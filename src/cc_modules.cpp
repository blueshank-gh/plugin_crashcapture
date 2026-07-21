// Crash Capture - module & memory probing
// Windows: PEB loader-list walk (no allocations, no dbghelp, no psapi).
// Linux: /proc/self/maps parsed with raw syscalls into static tables.

#include "crashcapture.h"

#include <stdio.h>
#include <string.h>

#if defined(CC_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <windows.h>
    #include <winternl.h>
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/mman.h>
#endif

namespace CrashCapture {
    static const int kMaxModules = 1024;
    static CCModule g_modules[kMaxModules];
    static int g_moduleCount = 0;

    static void BaseName(const char* path, char* out, size_t outsz)
    {
        const char* base = path;
        for (const char* p = path; *p; ++p)
            if (*p == '/' || *p == '\\') base = p + 1;
        snprintf(out, outsz, "%s", base);
    }

    #if defined(CC_WINDOWS)
        // winternl.h's LDR_DATA_TABLE_ENTRY hides the fields we need
        typedef struct CC_LDR_DATA_TABLE_ENTRY {
            LIST_ENTRY     InLoadOrderLinks;
            LIST_ENTRY     InMemoryOrderLinks;
            LIST_ENTRY     InInitializationOrderLinks;
            PVOID          DllBase;
            PVOID          EntryPoint;
            ULONG          SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
        } CC_LDR_DATA_TABLE_ENTRY;

        static void WideToUtf8(const wchar_t* w, int wlen, char* out, size_t outsz)
        {
            if (!w || wlen <= 0) { out[0] = 0; return; }
            int n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, out, (int)outsz - 1, NULL, NULL);
            if (n < 0) n = 0;
            if ((size_t)n >= outsz) n = (int)outsz - 1;
            out[n] = 0;
        }

        int Modules::Refresh()
        {
            g_moduleCount = 0;

            #if defined(CC_X64)
                PPEB peb = (PPEB)__readgsqword(0x60);
            #else
                PPEB peb = (PPEB)__readfsdword(0x30);
            #endif
            if (!peb || !peb->Ldr) return 0;

            PEB_LDR_DATA* ldr = peb->Ldr;
            LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
            for (LIST_ENTRY* cur = head->Flink; cur && cur != head && g_moduleCount < kMaxModules; cur = cur->Flink) {
                // InMemoryOrderLinks is the 2nd LIST_ENTRY in the struct.
                CC_LDR_DATA_TABLE_ENTRY* e =
                    (CC_LDR_DATA_TABLE_ENTRY*)((char*)cur - sizeof(LIST_ENTRY));
                if (!e->DllBase || !e->SizeOfImage) continue;

                CCModule& m = g_modules[g_moduleCount++];
                m.base = (uintptr_t)e->DllBase;
                m.size = (size_t)e->SizeOfImage;
                WideToUtf8(e->BaseDllName.Buffer,
                        e->BaseDllName.Length / (int)sizeof(wchar_t),
                        m.name, sizeof(m.name));
                if (!m.name[0]) snprintf(m.name, sizeof(m.name), "0x%p", e->DllBase);
            }
            return g_moduleCount;
        }

        bool Mem::IsReadable(const void* p, size_t n)
        {
            if (!p) return false;
            MEMORY_BASIC_INFORMATION mbi;
            const char* a = (const char*)p;
            const char* end = a + n;
            while (a < end) {
                if (!VirtualQuery(a, &mbi, sizeof(mbi))) return false;
                if (mbi.State != MEM_COMMIT) return false;
                DWORD prot = mbi.Protect & 0xff;
                if (prot == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) return false;
                a = (const char*)mbi.BaseAddress + mbi.RegionSize;
            }
            return true;
        }

        bool Mem::IsExecutable(uintptr_t addr)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT) return false;
            DWORD prot = mbi.Protect & 0xff;
            return prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
                prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
        }
    #else // CC_LINUX
        // Tiny async-safe reader for /proc/self/maps.
        static unsigned long ParseHex(const char*& s)
        {
            unsigned long v = 0;
            while (*s) {
                char c = *s;
                int d;
                if (c >= '0' && c <= '9') d = c - '0';
                else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                else break;
                v = (v << 4) | (unsigned)d;
                ++s;
            }
            return v;
        }

        int Modules::Refresh()
        {
            g_moduleCount = 0;

            int fd = open("/proc/self/maps", O_RDONLY);
            if (fd < 0) return 0;

            static char buf[256 * 1024];
            size_t total = 0;
            for (;;) {
                if (total >= sizeof(buf) - 1) break;
                ssize_t r = read(fd, buf + total, sizeof(buf) - 1 - total);
                if (r <= 0) break;
                total += (size_t)r;
            }
            close(fd);
            buf[total] = 0;

            // One CCModule per executable, file-backed mapping with a path
            char* line = buf;
            while (line && *line && g_moduleCount < kMaxModules) {
                char* nl = strchr(line, '\n');
                if (nl) *nl = 0;

                const char* s = line;
                unsigned long start = ParseHex(s);
                if (*s == '-') { ++s; }
                unsigned long end = ParseHex(s);
                while (*s == ' ') ++s;
                char perms[5] = {0};
                for (int i = 0; i < 4 && *s && *s != ' '; ++i) perms[i] = *s++;

                int fields = 0;
                while (*s && fields < 3) {
                    while (*s == ' ') ++s;
                    while (*s && *s != ' ') ++s;
                    ++fields;
                }
                while (*s == ' ') ++s;
                const char* path = s; // may be empty, [heap], [stack], anon

                bool exec = perms[2] == 'x';
                bool filebacked = path && path[0] == '/';

                if (exec && filebacked) {
                    char base[96];
                    BaseName(path, base, sizeof(base));
                    // merge with an existing entry of the same basename
                    CCModule* found = NULL;
                    for (int i = 0; i < g_moduleCount; ++i)
                        if (strcmp(g_modules[i].name, base) == 0) { found = &g_modules[i]; break; }
                    if (found) {
                        if ((uintptr_t)start < found->base) {
                            found->size += found->base - (uintptr_t)start;
                            found->base = (uintptr_t)start;
                        }
                        uintptr_t fend = found->base + found->size;
                        if ((uintptr_t)end > fend) found->size += (uintptr_t)end - fend;
                    } else {
                        CCModule& m = g_modules[g_moduleCount++];
                        m.base = (uintptr_t)start;
                        m.size = (size_t)(end - start);
                        snprintf(m.name, sizeof(m.name), "%s", base);
                    }
                } else if (exec && g_moduleCount < kMaxModules) {
                    // Anonymous executable mapping (LuaJIT mcode etc.)
                    CCModule& m = g_modules[g_moduleCount++];
                    m.base = (uintptr_t)start;
                    m.size = (size_t)(end - start);
                    snprintf(m.name, sizeof(m.name), "[anon-exec]");
                }

                line = nl ? nl + 1 : NULL;
            }
            return g_moduleCount;
        }

        bool Mem::IsReadable(const void* p, size_t n)
        {
            if (!p) return false;
            // msync on the containing page(s) returns ENOMEM for unmapped memory and is
            // async-signal-safe. Round down to page, walk pages spanning [p, p+n).
            long pg = sysconf(_SC_PAGESIZE);
            if (pg <= 0) pg = 4096;
            uintptr_t a = (uintptr_t)p & ~(uintptr_t)(pg - 1);
            uintptr_t end = (uintptr_t)p + n;
            for (; a < end; a += (uintptr_t)pg) {
                if (msync((void*)a, (size_t)pg, MS_ASYNC) != 0)
                    return false;
            }
            return true;
        }

        bool Mem::IsExecutable(uintptr_t addr)
        {
            const CCModule* m = Modules::Find(addr);
            return m != NULL; // file-backed exec ranges only enter the table
        }
    #endif

    bool Modules::HasLua()
    {
        Modules::Refresh();
        for (int i = 0; i < g_moduleCount; ++i) {
            for (const char* p = g_modules[i].name; p[0] && p[1] && p[2]; ++p) {
                if ((p[0] == 'l' || p[0] == 'L') &&
                    (p[1] == 'u' || p[1] == 'U') &&
                    (p[2] == 'a' || p[2] == 'A'))
                    return true;
            }
        }
        return false;
    }

    const CCModule* Modules::Find(uintptr_t addr)
    {
        for (int i = 0; i < g_moduleCount; ++i) {
            const CCModule& m = g_modules[i];
            if (addr >= m.base && addr < m.base + m.size) return &m;
        }
        return NULL;
    }

    const CCModule* Modules::FindByName(const char* needle)
    {
        if (!needle || !*needle) return NULL;
        for (int i = 0; i < g_moduleCount; ++i) {
            const char* hay = g_modules[i].name;
            // case-insensitive substring match
            for (const char* h = hay; *h; ++h) {
                const char* a = h; const char* b = needle;
                while (*a && *b) {
                    char ca = *a, cb = *b;
                    if (ca >= 'A' && ca <= 'Z') ca += 32;
                    if (cb >= 'A' && cb <= 'Z') cb += 32;
                    if (ca != cb) break;
                    ++a; ++b;
                }
                if (!*b) return &g_modules[i];
            }
        }
        return NULL;
    }

    int Modules::Snapshot(const CCModule** out)
    {
        if (out) *out = g_modules;
        return g_moduleCount;
    }

    void FormatAddress(uintptr_t addr, char* out, size_t outsz)
    {
        const CCModule* m = Modules::Find(addr);
        int w;
        if (m)
            w = snprintf(out, outsz, "%s+0x%llx (0x%llx)",
                        m->name, (unsigned long long)(addr - m->base), (unsigned long long)addr);
        else if (addr && Mem::IsExecutable(addr)) // exec but no module: likely JIT mcode
            w = snprintf(out, outsz, "0x%llx <JIT mcode? (anon exec)>", (unsigned long long)addr);
        else
            w = snprintf(out, outsz, "0x%llx <unmapped>", (unsigned long long)addr);

        // Append symbol/file:line when resolvable (only modules carry symbols)
        if (m && w > 0 && (size_t)w < outsz) {
            char sym[400];
            if (Sym::Resolve(addr, sym, sizeof(sym)))
                snprintf(out + w, outsz - (size_t)w, "  %s", sym);
        }
    }

    void Modules::Dump()
    {
        Log::F("loaded modules: %d\n\n", g_moduleCount);
        Log::Str("| base | end | size | name |\n");
        Log::Str("|---|---|---|---|\n");
        for (int i = 0; i < g_moduleCount; ++i) {
            const CCModule& m = g_modules[i];
            Log::F("| `0x%llx` | `0x%llx` | %llu KB | `%s` |\n",
                (unsigned long long)m.base,
                (unsigned long long)(m.base + m.size),
                (unsigned long long)(m.size / 1024), m.name);
        }
    }
}