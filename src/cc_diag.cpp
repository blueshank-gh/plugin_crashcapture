// Crash Capture - live memory diagnostics
// On a crash, spins up a FRESH lua_State for live debugging

#include "crashcapture.h"
#include "tools/cc_signature.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(CC_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <windows.h>
#else
    #include <fcntl.h>
    #include <unistd.h>
    #include <ucontext.h>
#endif

struct lua_State;

namespace CrashCapture {
    typedef int (*lua_CFunction)(lua_State*);
    enum { LUA_TNIL = 0, LUA_TBOOL = 1, LUA_TLIGHTUD = 2, LUA_TNUM = 3, LUA_TSTR = 4, LUA_TUD = 7 };
    static const int LUA_GLOBALSINDEX = -10002;

    // LuaJIT C API for the fresh state, resolved from lua_shared.
    struct DiagApi {
        lua_State* (*newstate)(void);
        void (*openlibs)(lua_State*);
        void (*close)(lua_State*);
        int (*loadstring)(lua_State*, const char*);
        int (*pcall)(lua_State*, int, int, int);
        void (*createtable)(lua_State*, int, int);
        int (*gettop)(lua_State*);
        void (*settop)(lua_State*, int);
        int (*type)(lua_State*, int);
        const char* (*tolstring)(lua_State*, int, size_t*);
        double (*tonumber)(lua_State*, int);
        int (*toboolean)(lua_State*, int);
        void* (*touserdata)(lua_State*, int);
        void (*pushnil)(lua_State*);
        void (*pushnumber)(lua_State*, double);
        void (*pushboolean)(lua_State*, int);
        void (*pushlstring)(lua_State*, const char*, size_t);
        void (*pushstring)(lua_State*, const char*);
        void (*pushlightuserdata)(lua_State*, void*);
        void (*pushcclosure)(lua_State*, lua_CFunction, int);
        void (*setfield)(lua_State*, int, const char*);
        void (*rawseti)(lua_State*, int, int);
        bool ok;
    };
    static DiagApi A = {0};
    static const char* g_diagDiag = "not attempted";

    static bool ResolveDiagApi()
    {
        if (A.ok) return true;
        void* m = Lua::SharedHandle();
        if (!m) { g_diagDiag = "lua_shared handle not found"; return false; }
        struct Sym { const char* name; void** slot; };
        Sym syms[] = {
            {"luaL_newstate", (void**)&A.newstate},
            {"luaL_openlibs", (void**)&A.openlibs},
            {"lua_close", (void**)&A.close},
            {"luaL_loadstring", (void**)&A.loadstring},
            {"lua_pcall", (void**)&A.pcall},
            {"lua_createtable", (void**)&A.createtable},
            {"lua_gettop", (void**)&A.gettop},
            {"lua_settop", (void**)&A.settop},
            {"lua_type", (void**)&A.type},
            {"lua_tolstring", (void**)&A.tolstring},
            {"lua_tonumber", (void**)&A.tonumber},
            {"lua_toboolean", (void**)&A.toboolean},
            {"lua_touserdata", (void**)&A.touserdata},
            {"lua_pushnil", (void**)&A.pushnil},
            {"lua_pushnumber", (void**)&A.pushnumber},
            {"lua_pushboolean", (void**)&A.pushboolean},
            {"lua_pushlstring", (void**)&A.pushlstring},
            {"lua_pushstring", (void**)&A.pushstring},
            {"lua_pushlightuserdata",(void**)&A.pushlightuserdata},
            {"lua_pushcclosure", (void**)&A.pushcclosure},
            {"lua_setfield", (void**)&A.setfield},
            {"lua_rawseti", (void**)&A.rawseti},
        };
        bool all = true;
        for (size_t i = 0; i < sizeof(syms)/sizeof(syms[0]); ++i) {
            *syms[i].slot = Lua::Sym(m, syms[i].name);
            if (!*syms[i].slot && all) { g_diagDiag = syms[i].name; all = false; }
        }
        A.ok = all;
        if (all) g_diagDiag = "ok";
        return all;
    }

    // --------- diagnostics.helpers ------
    static uintptr_t ArgAddr(lua_State* L, int idx)
    {
        int t = A.type(L, idx);
        if (t == LUA_TLIGHTUD || t == LUA_TUD) return (uintptr_t)A.touserdata(L, idx);
        return (uintptr_t)(long long)A.tonumber(L, idx);
    }

    static void SetFn(lua_State* L, const char* name, lua_CFunction fn)
    {
        A.pushcclosure(L, fn, 0);
        A.setfield(L, -2, name);
    }

    // --------- diagnostics.mem.* --------
    static int mem_read(lua_State* L)
    {
        uintptr_t a = ArgAddr(L, 1);
        const char* ty = A.tolstring(L, 2, NULL);
        if (!ty || !a) { A.pushnil(L); return 1; }

        #define RD_NUM(T) do { if (!Mem::IsReadable((void*)a, sizeof(T))) { A.pushnil(L); return 1; } \
            T v; memcpy(&v, (void*)a, sizeof(T)); A.pushnumber(L, (double)v); return 1; } while (0)
        if (!strcmp(ty, "int8")) RD_NUM(signed char);
        else if (!strcmp(ty, "uint8")) RD_NUM(unsigned char);
        else if (!strcmp(ty, "int16")) RD_NUM(short);
        else if (!strcmp(ty, "uint16")) RD_NUM(unsigned short);
        else if (!strcmp(ty, "int32")) RD_NUM(int);
        else if (!strcmp(ty, "uint32")) RD_NUM(unsigned int);
        else if (!strcmp(ty, "int64")) RD_NUM(long long);
        else if (!strcmp(ty, "uint64")) RD_NUM(unsigned long long);
        else if (!strcmp(ty, "float")) RD_NUM(float);
        else if (!strcmp(ty, "double")) RD_NUM(double);
        else if (!strcmp(ty, "ptr")) {
            if (!Mem::IsReadable((void*)a, sizeof(void*))) {
                A.pushnil(L);
                return 1;
            }
            void* p;
            memcpy(&p, (void*)a, sizeof(void*));
            A.pushlightuserdata(L, p); return 1;
        }
        #undef RD_NUM
        A.pushnil(L);
        return 1;
    }

    static int mem_string(lua_State* L)
    {
        uintptr_t a = ArgAddr(L, 1);
        int maxlen = A.type(L, 2) == LUA_TNUM ? (int)A.tonumber(L, 2) : 256;
        if (maxlen < 0 || maxlen > 4096) maxlen = 4096;
        static char buf[4096];
        int n = 0;
        for (; n < maxlen; ++n) {
            if (!Mem::IsReadable((void*)(a + n), 1)) break;
            char c = *(char*)(a + n);
            if (!c) break;
            buf[n] = c;
        }
        A.pushlstring(L, buf, (size_t)n);
        return 1;
    }

    static int mem_sym(lua_State* L)
    {
        char out[400];
        FormatAddress(ArgAddr(L, 1), out, sizeof(out));
        A.pushstring(L, out);
        return 1;
    }

    static int mem_deref(lua_State* L)
    {
        uintptr_t a = ArgAddr(L, 1);
        if (!Mem::IsReadable((void*)a, sizeof(void*))) { A.pushnil(L); return 1; }
        void* p; memcpy(&p, (void*)a, sizeof(void*));
        A.pushlightuserdata(L, p);
        return 1;
    }

    static int mem_offset(lua_State* L)
    {
        A.pushlightuserdata(L, (void*)(ArgAddr(L, 1) + (uintptr_t)(long long)A.tonumber(L, 2)));
        return 1;
    }

    static int mem_readable(lua_State* L)
    {
        size_t n = A.type(L, 2) == LUA_TNUM ? (size_t)A.tonumber(L, 2) : 1;
        A.pushboolean(L, Mem::IsReadable((void*)ArgAddr(L, 1), n) ? 1 : 0);
        return 1;
    }

    static int mem_executable(lua_State* L)
    {
        A.pushboolean(L, Mem::IsExecutable(ArgAddr(L, 1)) ? 1 : 0);
        return 1;
    }

    static int mem_find(lua_State* L)
    {
        const char* name = A.tolstring(L, 1, NULL);
        const CCModule* m = name ? Modules::FindByName(name) : NULL;
        if (!m) { A.pushnil(L); return 1; }
        A.pushlightuserdata(L, (void*)m->base);
        A.pushnumber(L, (double)m->size);
        return 2; // base, size
    }

    static int mem_modules(lua_State* L)
    {
        const CCModule* mods = NULL;
        int count = Modules::Snapshot(&mods);
        A.createtable(L, count, 0);
        for (int i = 0; i < count; ++i) {
            A.createtable(L, 0, 3);
            A.pushstring(L, mods[i].name); A.setfield(L, -2, "name");
            A.pushlightuserdata(L, (void*)mods[i].base); A.setfield(L, -2, "base");
            A.pushnumber(L, (double)mods[i].size);A.setfield(L, -2, "size");
            A.rawseti(L, -2, i + 1);
        }
        return 1;
    }

    // mem.scan("server", "48 8B ?? C3") -> address in that module, or nil
    static int mem_scan(lua_State* L)
    {
        const char* name = A.tolstring(L, 1, NULL);
        const char* pat  = A.tolstring(L, 2, NULL);
        if (!name || !pat) { A.pushnil(L); return 1; }
        uintptr_t hit = Sig::Scan(name, pat);
        if (hit) A.pushlightuserdata(L, (void*)hit);
        else A.pushnil(L);
        return 1;
    }

    static int mem_region(lua_State* L)
    {
        uintptr_t a = ArgAddr(L, 1);
        A.createtable(L, 0, 5);
        #if defined(CC_WINDOWS)
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery((void*)a, &mbi, sizeof(mbi))) { A.settop(L, -1); A.pushnil(L); return 1; }
            DWORD pr = mbi.Protect & 0xff;
            bool r = pr == PAGE_READONLY || pr == PAGE_READWRITE || pr == PAGE_EXECUTE_READ || pr == PAGE_EXECUTE_READWRITE;
            bool w = pr == PAGE_READWRITE || pr == PAGE_EXECUTE_READWRITE;
            bool x = pr == PAGE_EXECUTE || pr == PAGE_EXECUTE_READ || pr == PAGE_EXECUTE_READWRITE;
            A.pushlightuserdata(L, mbi.BaseAddress);
            A.setfield(L, -2, "base");
            A.pushnumber(L, (double)mbi.RegionSize);
            A.setfield(L, -2, "size");
            A.pushboolean(L, r);
            A.setfield(L, -2, "read");
            A.pushboolean(L, w);
            A.setfield(L, -2, "write");
            A.pushboolean(L, x);
            A.setfield(L, -2, "execute");
        #else
            const CCModule* m = Modules::Find(a);
            A.pushlightuserdata(L, (void*)(m ? m->base : (a & ~(uintptr_t)0xFFF)));
            A.setfield(L, -2, "base");
            A.pushnumber(L, (double)(m ? m->size : 0x1000));
            A.setfield(L, -2, "size");
            A.pushboolean(L, Mem::IsReadable((void*)a, 1) ? 1 : 0);
            A.setfield(L, -2, "read");
            A.pushboolean(L, 0); A.setfield(L, -2, "write");
            A.pushboolean(L, Mem::IsExecutable(a) ? 1 : 0);
            A.setfield(L, -2, "execute");
        #endif
        return 1;
    }

    static int mem_dump(lua_State* L)
    {
        uintptr_t a = ArgAddr(L, 1);
        size_t want = A.type(L, 2) == LUA_TNUM ? (size_t)A.tonumber(L, 2) : 64;
        if (want > 512) want = 512;
        if (!a) { A.pushnumber(L, 0); return 1; }
        size_t avail = 0;
        while (avail < want && Mem::IsReadable((void*)(a + avail), 1)) ++avail;
        if (avail) Log::HexDump((void*)a, avail, a);
        A.pushnumber(L, (double)avail);
        return 1;
    }

    static int mem_symbol(lua_State* L)
    {
        const char* s1 = A.type(L, 1) == LUA_TSTR ? A.tolstring(L, 1, NULL) : NULL;
        const char* s2 = A.type(L, 2) == LUA_TSTR ? A.tolstring(L, 2, NULL) : NULL;
        const char* module = s2 ? s1 : NULL;
        const char* name = s2 ? s2 : s1;
        if (!name) { A.pushnil(L); return 1; }
        uintptr_t addr = Sym::Lookup(module, name);
        if (!addr) { A.pushnil(L); return 1; }
        A.pushlightuserdata(L, (void*)addr);
        return 1;
    }

    static int mem_threads(lua_State* L)
    {
        static CCThread th[256];
        int n = Platform::EnumThreads(th, 256);
        A.createtable(L, n, 0);
        for (int i = 0; i < n; ++i) {
            A.createtable(L, 0, 5);
            A.pushnumber(L, (double)th[i].id);
            A.setfield(L, -2, "id");
            if (th[i].pc) {
                A.pushlightuserdata(L, (void*)th[i].pc);
                A.setfield(L, -2, "pc");
                char s[400]; FormatAddress(th[i].pc, s, sizeof(s));
                A.pushstring(L, s);
                A.setfield(L, -2, "sym");
            }
            if (th[i].name[0]) { A.pushstring(L, th[i].name); A.setfield(L, -2, "name"); }
            A.pushboolean(L, th[i].current ? 1 : 0); A.setfield(L, -2, "current");
            A.rawseti(L, -2, i + 1);
        }
        return 1;
    }

    // pointer chain walk
    static int mem_chain(lua_State* L)
    {
        int top = A.gettop(L);
        if (top < 1) { A.pushnil(L); return 1; }
        uintptr_t a = ArgAddr(L, 1);
        for (int i = 2; i <= top; ++i) {
            a += (uintptr_t)(long long)A.tonumber(L, i);
            if (i < top) { // intermediate hop: follow the pointer stored here
                if (!a || !Mem::IsReadable((void*)a, sizeof(void*))) { A.pushnil(L); return 1; }
                void* p; memcpy(&p, (void*)a, sizeof(void*));
                a = (uintptr_t)p;
            }
        }
        A.pushlightuserdata(L, (void*)a);
        return 1;
    }

    static int mem_bytes(lua_State* L)
    {
        uintptr_t a = ArgAddr(L, 1);
        int want = A.type(L, 2) == LUA_TNUM ? (int)A.tonumber(L, 2) : 64;
        if (want < 0) want = 0;
        if (want > 4096) want = 4096;
        static char buf[4096];
        int n = 0;
        for (; n < want; ++n) {
            if (!Mem::IsReadable((void*)(a + n), 1)) break;
            buf[n] = *(char*)(a + n);
        }
        A.pushlstring(L, buf, (size_t)n);
        return 1;
    }

    static int NeedleSize(const char* ty)
    {
        if (!ty || !strcmp(ty, "ptr")) return (int)sizeof(void*);
        if (!strcmp(ty, "int8")  || !strcmp(ty, "uint8"))  return 1;
        if (!strcmp(ty, "int16") || !strcmp(ty, "uint16")) return 2;
        if (!strcmp(ty, "int32") || !strcmp(ty, "uint32") || !strcmp(ty, "float"))  return 4;
        if (!strcmp(ty, "int64") || !strcmp(ty, "uint64") || !strcmp(ty, "double")) return 8;
        return 0;
    }

    static int BuildNeedle(lua_State* L, int valIdx, const char* ty, unsigned char* out)
    {
        int sz = NeedleSize(ty);
        if (sz <= 0) return 0;
        if (ty && !strcmp(ty, "float"))  { float f = (float)A.tonumber(L, valIdx); memcpy(out, &f, 4); return 4; }
        if (ty && !strcmp(ty, "double")) { double d = A.tonumber(L, valIdx);       memcpy(out, &d, 8); return 8; }
        uint64_t v = (uint64_t)ArgAddr(L, valIdx);
        memcpy(out, &v, sz);
        return sz;
    }

    static void ScanModuleForBytes(lua_State* L, const CCModule* m, const unsigned char* needle, int nlen, int* count, int cap)
    {
        if (nlen <= 0 || nlen > kSigMaxLen) return;
        int room = cap - *count;
        if (room <= 0) return;

        CCPattern pat;
        for (int i = 0; i < nlen; ++i) { pat.bytes[i] = needle[i]; pat.mask[i] = 1; }
        pat.len = nlen;

        uintptr_t hits[256];
        if (room > (int)(sizeof(hits) / sizeof(hits[0]))) room = (int)(sizeof(hits) / sizeof(hits[0]));
        int n = Sig::FindAll(m, &pat, hits, room);
        for (int i = 0; i < n; ++i) {
            A.pushlightuserdata(L, (void*)hits[i]);
            A.rawseti(L, -2, ++(*count));
        }
    }

    static int mem_search(lua_State* L)
    {
        const char* mod = A.type(L, 1) == LUA_TSTR ? A.tolstring(L, 1, NULL) : NULL;
        const CCModule* m = mod ? Modules::FindByName(mod) : NULL;
        if (!m) { A.pushnil(L); return 1; }
        const char* ty = A.type(L, 3) == LUA_TSTR ? A.tolstring(L, 3, NULL) : "ptr";
        unsigned char needle[8];
        int nlen = BuildNeedle(L, 2, ty, needle);
        if (!nlen) { A.pushnil(L); return 1; }
        A.createtable(L, 0, 0);
        int count = 0;
        ScanModuleForBytes(L, m, needle, nlen, &count, 256);
        return 1;
    }

    static int mem_refs(lua_State* L)
    {
        uintptr_t target = ArgAddr(L, 1);
        if (!target) { A.pushnil(L); return 1; }
        unsigned char needle[sizeof(void*)];
        memcpy(needle, &target, sizeof(void*));
        A.createtable(L, 0, 0);
        int count = 0;
        const CCModule* mods = NULL;
        int c = Modules::Snapshot(&mods);
        for (int i = 0; i < c && count < 256; ++i)
            ScanModuleForBytes(L, &mods[i], needle, (int)sizeof(void*), &count, 256);
        return 1;
    }

    static int diag_print(lua_State* L)
    {
        int top = A.gettop(L);
        for (int i = 1; i <= top; ++i) {
            if (i > 1) Log::Str("\t");
            switch (A.type(L, i)) {
                case LUA_TNIL: Log::Str("nil"); break;
                case LUA_TBOOL: Log::Str(A.toboolean(L, i) ? "true" : "false"); break;
                case LUA_TNUM: Log::F("%.14g", A.tonumber(L, i)); break;
                case LUA_TLIGHTUD:
                case LUA_TUD: Log::F("0x%llx", (unsigned long long)(uintptr_t)A.touserdata(L, i)); break;
                case LUA_TSTR: {
                    size_t n = 0; const char* s = A.tolstring(L, i, &n);
                    if (s) Log::Raw(s, n);
                    break;
                }
                default: {
                    const char* s = A.tolstring(L, i, NULL);
                    Log::Str(s ? s : "?");
                    break;
                }
            }
        }
        Log::Str("\n");
        return 0;
    }

    static void Register(lua_State* L, void* nativeCtx)
    {
        // mem.*
        A.createtable(L, 0, 18);
        SetFn(L, "read", mem_read);
        SetFn(L, "string", mem_string);
        SetFn(L, "bytes", mem_bytes);
        SetFn(L, "sym", mem_sym);
        SetFn(L, "deref", mem_deref);
        SetFn(L, "offset", mem_offset);
        SetFn(L, "chain", mem_chain);
        SetFn(L, "readable", mem_readable);
        SetFn(L, "executable", mem_executable);
        SetFn(L, "find", mem_find);
        SetFn(L, "modules", mem_modules);
        SetFn(L, "scan", mem_scan);
        SetFn(L, "search", mem_search);
        SetFn(L, "refs", mem_refs);
        SetFn(L, "region", mem_region);
        SetFn(L, "dump", mem_dump);
        SetFn(L, "symbol", mem_symbol);
        SetFn(L, "threads", mem_threads);
        A.setfield(L, LUA_GLOBALSINDEX, "mem");

        A.pushcclosure(L, diag_print, 0);
        A.setfield(L, LUA_GLOBALSINDEX, "print");

        A.createtable(L, 0, 10);
        A.pushstring(L, Report::Kind());
        A.setfield(L, -2, "kind");
        A.pushstring(L, Report::Reason());
        A.setfield(L, -2, "reason");
        {
            uintptr_t f = Report::Fault();
            if (f) A.pushlightuserdata(L, (void*)f); else A.pushnil(L);
            A.setfield(L, -2, "fault");
        }
        A.pushnumber(L, (double)Report::Uptime());
        A.setfield(L, -2, "uptime");
        if (g_lastPulseMs) A.pushnumber(L, (double)(MonotonicMs() - g_lastPulseMs));
        else A.pushnil(L);
        A.setfield(L, -2, "pulse");

        A.createtable(L, 0, 20);
        #define CCREG(nm, v) do { A.pushlightuserdata(L, (void*)(uintptr_t)(v)); A.setfield(L, -2, nm); } while (0)
        uintptr_t pc = 0, sp = 0;
        #if defined(CC_WINDOWS)
            CONTEXT* c = (CONTEXT*)nativeCtx;
            if (c) {
                #if defined(CC_X64)
                    pc = (uintptr_t)c->Rip; sp = (uintptr_t)c->Rsp;
                    CCREG("rax", c->Rax); CCREG("rbx", c->Rbx); CCREG("rcx", c->Rcx); CCREG("rdx", c->Rdx);
                    CCREG("rsi", c->Rsi); CCREG("rdi", c->Rdi); CCREG("rbp", c->Rbp); CCREG("rsp", c->Rsp);
                    CCREG("r8", c->R8); CCREG("r9", c->R9); CCREG("r10", c->R10); CCREG("r11", c->R11);
                    CCREG("r12", c->R12); CCREG("r13", c->R13); CCREG("r14", c->R14); CCREG("r15", c->R15);
                    CCREG("rip", c->Rip);
                #else
                    pc = (uintptr_t)c->Eip; sp = (uintptr_t)c->Esp;
                    CCREG("eax", c->Eax); CCREG("ebx", c->Ebx); CCREG("ecx", c->Ecx); CCREG("edx", c->Edx);
                    CCREG("esi", c->Esi); CCREG("edi", c->Edi); CCREG("ebp", c->Ebp); CCREG("esp", c->Esp);
                    CCREG("eip", c->Eip);
                #endif
            }
        #else
            ucontext_t* uc = (ucontext_t*)nativeCtx;
            if (uc) {
                greg_t* g = uc->uc_mcontext.gregs;
                #if defined(CC_X64)
                    pc = (uintptr_t)g[REG_RIP]; sp = (uintptr_t)g[REG_RSP];
                    CCREG("rax", g[REG_RAX]); CCREG("rbx", g[REG_RBX]); CCREG("rcx", g[REG_RCX]); CCREG("rdx", g[REG_RDX]);
                    CCREG("rsi", g[REG_RSI]); CCREG("rdi", g[REG_RDI]); CCREG("rbp", g[REG_RBP]); CCREG("rsp", g[REG_RSP]);
                    CCREG("r8", g[REG_R8]); CCREG("r9", g[REG_R9]); CCREG("r10", g[REG_R10]); CCREG("r11", g[REG_R11]);
                    CCREG("r12", g[REG_R12]); CCREG("r13", g[REG_R13]); CCREG("r14", g[REG_R14]); CCREG("r15", g[REG_R15]);
                    CCREG("rip", g[REG_RIP]);
                #else
                    pc = (uintptr_t)g[REG_EIP]; sp = (uintptr_t)g[REG_ESP];
                    CCREG("eax", g[REG_EAX]); CCREG("ebx", g[REG_EBX]); CCREG("ecx", g[REG_ECX]); CCREG("edx", g[REG_EDX]);
                    CCREG("esi", g[REG_ESI]); CCREG("edi", g[REG_EDI]); CCREG("ebp", g[REG_EBP]); CCREG("esp", g[REG_ESP]);
                    CCREG("eip", g[REG_EIP]);
                #endif
            }
        #endif
        #undef CCREG
        A.setfield(L, -2, "regs");

        A.pushlightuserdata(L, (void*)pc);
        A.setfield(L, -2, "pc");
        A.pushlightuserdata(L, (void*)sp);
        A.setfield(L, -2, "sp");

        {
            static uintptr_t pcs[64];
            int nf = Platform::Backtrace(nativeCtx, pcs, 64);
            A.createtable(L, nf, 0);
            for (int i = 0; i < nf; ++i) {
                A.createtable(L, 0, 2);
                A.pushlightuserdata(L, (void*)pcs[i]);
                A.setfield(L, -2, "pc");
                char s[400]; FormatAddress(pcs[i], s, sizeof(s));
                A.pushstring(L, s);
                A.setfield(L, -2, "sym");
                A.rawseti(L, -2, i + 1);
            }
            A.setfield(L, -2, "stack");
        }

        {
            static CCLuaTrace traces[3];
            int nr = Lua::CaptureTraces(traces, 3);
            if (nr <= 0) {
                A.pushnil(L);
            } else {
                A.createtable(L, nr, 0);
                for (int i = 0; i < nr; ++i) {
                    CCLuaTrace* t = &traces[i];
                    A.createtable(L, 0, 3);
                    A.pushstring(L, t->realm);
                    A.setfield(L, -2, "realm");
                    A.pushnumber(L, (double)t->top);
                    A.setfield(L, -2, "top");
                    A.createtable(L, t->frameCount, 0);
                    for (int fi = 0; fi < t->frameCount; ++fi) {
                        CCLuaFrame* f = &t->frames[fi];
                        A.createtable(L, 0, 6);
                        A.pushnumber(L, (double)f->level);
                        A.setfield(L, -2, "level");
                        A.pushstring(L, f->source);
                        A.setfield(L, -2, "source");
                        A.pushnumber(L, (double)f->currentline);
                        A.setfield(L, -2, "line");
                        A.pushstring(L, f->name);
                        A.setfield(L, -2, "name");
                        A.pushstring(L, f->what);
                        A.setfield(L, -2, "what");
                        if (f->locals[0]) {
                            A.pushstring(L, f->locals);
                            A.setfield(L, -2, "locals");
                        }
                        A.rawseti(L, -2, fi + 1);
                    }
                    A.setfield(L, -2, "frames");
                    A.rawseti(L, -2, i + 1);
                }
            }
            A.setfield(L, -2, "lua");
        }

        A.setfield(L, LUA_GLOBALSINDEX, "crash");
    }

    static bool ReadScript(const char* path, char* buf, size_t cap)
    {
        size_t n = 0;
        #if defined(CC_WINDOWS)
            HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (h == INVALID_HANDLE_VALUE) return false;
            DWORD r = 0;
            while (n < cap - 1 && ReadFile(h, buf + n, (DWORD)(cap - 1 - n), &r, NULL) && r > 0) n += r;
            CloseHandle(h);
        #else
            int fd = open(path, O_RDONLY);
            if (fd < 0) return false;
            ssize_t r;
            while (n < cap - 1 && (r = read(fd, buf + n, cap - 1 - n)) > 0) n += (size_t)r;
            close(fd);
        #endif
        buf[n] = 0;
        return n > 0;
    }

    void Diag::Section(void* nativeCtx)
    {
        if (!Cfg().script[0]) { Log::Str("_no CRASHCAPTURE_SCRIPT set; skipped._\n"); return; }
        if (!ResolveDiagApi()) { Log::F("_diag Lua API not resolved (%s)._\n", g_diagDiag); return; }

        static char script[64 * 1024];
        if (!ReadScript(Cfg().script, script, sizeof(script))) {
            Log::F("_could not read script: %s_\n", Cfg().script);
            return;
        }

        lua_State* L = A.newstate();
        if (!L) { Log::Str("_luaL_newstate failed._\n"); return; }
        A.openlibs(L);

        // do not use JIT in this state.
        if (A.loadstring(L, "if jit then jit.off(true, true) end") == 0) A.pcall(L, 0, 0, 0);
        A.settop(L, 0);

        Register(L, nativeCtx);

        Log::F("running `%s`:\n\n", Cfg().script);
        if (A.loadstring(L, script) != 0) {
            const char* e = A.tolstring(L, -1, NULL);
            Log::F("\nscript load error: %s\n", e ? e : "?");
        } else if (A.pcall(L, 0, 0, 0) != 0) {
            const char* e = A.tolstring(L, -1, NULL);
            Log::F("\nscript error: %s\n", e ? e : "?");
        }

        A.close(L);
    }
}
