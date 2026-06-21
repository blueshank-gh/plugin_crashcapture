// Crash Capture - Linux crash & hang capture
// Traps the fatal signals on a private alt-stack, walks the native stack with the
// libgcc unwinder (names from the ELF .symtab, demangled), and dumps a stalled
// thread by signalling it (SIGUSR2) so it writes its own context.

#include "crashcapture.h"

#if defined(CC_LINUX)

#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <dlfcn.h>
#include <ucontext.h>
#include <unwind.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>
#include <cxxabi.h>
#include <dirent.h>

namespace CrashCapture {
    unsigned long g_gameThreadPthread = 0;
    int g_gameThreadTid = 0;

    static const int kFatal[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, 0 };
    static struct sigaction g_old[64];
    static stack_t g_altstack;
    static volatile sig_atomic_t g_inReport = 0;

    // cross-thread dump handshake (SIGUSR2)
    static const char* volatile g_pendKind = NULL;
    static const char* volatile g_pendReason = NULL;
    static volatile sig_atomic_t g_dumpDone = 0;

    // RunProtected state (single report path, guarded by g_inReport)
    static sigjmp_buf g_jb;
    static volatile sig_atomic_t g_protArmed = 0;

    static int gettid_() { return (int)syscall(SYS_gettid); }

    // --------- linux-symbols ---

    struct ElfMod {
        const void* fbase; // dladdr load base = cache key
        void* map;
        size_t maplen;
        const ElfW(Sym)* syms;
        size_t nsyms;
        const char* strs;
        size_t strsz;
        bool used;
    };
    static ElfMod g_elf[40];

    static bool ParseElf(ElfMod* m, const char* path)
    {
        int fd = open(path, O_RDONLY);
        if (fd < 0) return false;
        off_t sz = lseek(fd, 0, SEEK_END);
        if (sz < (off_t)sizeof(ElfW(Ehdr))) { close(fd); return false; }
        void* map = mmap(NULL, (size_t)sz, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (map == MAP_FAILED) return false;

        const unsigned char* b = (const unsigned char*)map;
        const ElfW(Ehdr)* eh = (const ElfW(Ehdr)*)b;
        if (memcmp(b, ELFMAG, SELFMAG) != 0 ||
            eh->e_shoff == 0 || eh->e_shentsize != sizeof(ElfW(Shdr)) ||
            eh->e_shoff + (off_t)eh->e_shnum * eh->e_shentsize > sz) {
            munmap(map, sz); return false;
        }
        const ElfW(Shdr)* sh = (const ElfW(Shdr)*)(b + eh->e_shoff);

        // Prefer .symtab (has LOCAL symbols); fall back to .dynsym.
        const ElfW(Shdr)* sym = NULL; const ElfW(Shdr)* str = NULL;
        const ElfW(Shdr)* dsym = NULL; const ElfW(Shdr)* dstr = NULL;
        for (int i = 0; i < eh->e_shnum; ++i) {
            if (sh[i].sh_type == SHT_SYMTAB && sh[i].sh_link < eh->e_shnum) {
                sym = &sh[i]; str = &sh[sh[i].sh_link];
            } else if (sh[i].sh_type == SHT_DYNSYM && sh[i].sh_link < eh->e_shnum) {
                dsym = &sh[i]; dstr = &sh[sh[i].sh_link];
            }
        }
        if (!sym) { sym = dsym; str = dstr; }
        if (!sym || !str ||
            sym->sh_offset + sym->sh_size > (ElfW(Off))sz ||
            str->sh_offset + str->sh_size > (ElfW(Off))sz ||
            sym->sh_entsize == 0) {
            munmap(map, sz); return false;
        }

        m->map = map; m->maplen = (size_t)sz;
        m->syms = (const ElfW(Sym)*)(b + sym->sh_offset);
        m->nsyms = (size_t)(sym->sh_size / sym->sh_entsize);
        m->strs = (const char*)(b + str->sh_offset);
        m->strsz = (size_t)str->sh_size;
        return true;
    }

    // get (or build) the parsed ELF for the module at load base `fbase`.
    static ElfMod* GetElf(const void* fbase, const char* path)
    {
        for (size_t i = 0; i < sizeof(g_elf)/sizeof(g_elf[0]); ++i)
            if (g_elf[i].used && g_elf[i].fbase == fbase) return g_elf[i].syms ? &g_elf[i] : NULL;
        for (size_t i = 0; i < sizeof(g_elf)/sizeof(g_elf[0]); ++i) {
            if (g_elf[i].used) continue;
            g_elf[i].used = true;
            g_elf[i].fbase = fbase;
            if (!path || !ParseElf(&g_elf[i], path)) { g_elf[i].syms = NULL; return NULL; }
            return &g_elf[i];
        }
        return NULL; // cache full
    }

    void Sym_Init() {}

    void Sym_Cleanup()
    {
        for (size_t i = 0; i < sizeof(g_elf)/sizeof(g_elf[0]); ++i)
            if (g_elf[i].map) { munmap(g_elf[i].map, g_elf[i].maplen); g_elf[i].map = NULL; }
    }

    bool Sym_Resolve(uintptr_t addr, char* out, size_t outsz)
    {
        if (!Cfg().symbols || !addr || !out || outsz == 0) return false;
        Dl_info di;
        if (!dladdr((void*)addr, &di) || !di.dli_fbase) return false;

        const char*   mangled = NULL;
        unsigned long off = 0;

        ElfMod* m = GetElf(di.dli_fbase, di.dli_fname);
        if (m && m->syms) {
            ElfW(Addr) rva = (ElfW(Addr))(addr - (uintptr_t)di.dli_fbase);
            const ElfW(Sym)* best = NULL; // nearest FUNC with st_value <= rva
            for (size_t i = 0; i < m->nsyms; ++i) {
                const ElfW(Sym)* s = &m->syms[i];
                if ((s->st_info & 0xf) != STT_FUNC || s->st_shndx == SHN_UNDEF || !s->st_value)
                    continue;
                if (s->st_value > rva) continue;
                if (s->st_size && rva < s->st_value + s->st_size) { best = s; break; } // exact
                if (!best || s->st_value > best->st_value) best = s;
            }
            if (best && best->st_name < m->strsz) {
                mangled = m->strs + best->st_name;
                off = (unsigned long)(rva - best->st_value);
            }
        }
        if (!mangled && di.dli_sname) { // dladdr global fallback
            mangled = di.dli_sname;
            off = di.dli_saddr ? (unsigned long)(addr - (uintptr_t)di.dli_saddr) : 0;
        }
        if (!mangled || !*mangled) return false;

        // demangle C++ names (uses malloc, fine for the hang case).
        const char* name = mangled;
        char* dem = NULL;
        if (mangled[0] == '_' && mangled[1] == 'Z') {
            int status = 0;
            dem = abi::__cxa_demangle(mangled, NULL, NULL, &status);
            if (status == 0 && dem) name = dem;
        }
        snprintf(out, outsz, "%s+0x%lx", name, off);
        if (dem) free(dem);
        return true;
    }

    static uintptr_t ElfLookup(const CCModule* mod, const char* name)
    {
        Dl_info di;
        if (!dladdr((void*)mod->base, &di) || !di.dli_fbase) return 0;
        ElfMod* m = GetElf(di.dli_fbase, di.dli_fname);
        if (!m || !m->syms) return 0;
        for (size_t k = 0; k < m->nsyms; ++k) {
            const ElfW(Sym)* s = &m->syms[k];
            int tp = s->st_info & 0xf;
            if ((tp != STT_FUNC && tp != STT_OBJECT) || s->st_shndx == SHN_UNDEF || !s->st_value) continue;
            if (s->st_name >= m->strsz) continue;
            if (strcmp(m->strs + s->st_name, name) == 0)
                return (uintptr_t)di.dli_fbase + s->st_value;
        }
        return 0;
    }

    uintptr_t Sym_Lookup(const char* module, const char* name)
    {
        if (!name || !*name) return 0;
        if (module) {
            const CCModule* m = Modules_FindByName(module);
            return m ? ElfLookup(m, name) : 0;
        }
        const CCModule* mods = NULL;
        int c = Modules_Snapshot(&mods);
        for (int i = 0; i < c; ++i) {
            uintptr_t a = ElfLookup(&mods[i], name);
            if (a) return a;
        }
        return 0;
    }

    int Platform_EnumThreads(CCThread* out, int max)
    {
        if (!out || max <= 0) return 0;
        int self = gettid_();
        DIR* d = opendir("/proc/self/task");
        if (!d) return 0;

        int n = 0;
        struct dirent* e;
        while ((e = readdir(d)) != NULL && n < max) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            int tid = atoi(e->d_name);
            CCThread& t = out[n];
            t.id = (unsigned)tid;
            t.pc = 0;
            t.current = (tid == self);
            t.name[0] = 0;

            char path[64];
            snprintf(path, sizeof(path), "/proc/self/task/%d/comm", tid);
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                ssize_t r = read(fd, t.name, sizeof(t.name) - 1);
                close(fd);
                if (r > 0) {
                    t.name[r] = 0;
                    if (t.name[r - 1] == '\n') t.name[r - 1] = 0;
                }
            }
            ++n;
        }
        closedir(d);
        return n;
    }

    bool RunProtectedQuiet(SectionFn fn, void* arg)
    {
        sigjmp_buf prev;
        memcpy(prev, g_jb, sizeof(g_jb));
        sig_atomic_t prevArmed = g_protArmed;

        bool ok;
        g_protArmed = 1;
        if (sigsetjmp(g_jb, 1) == 0) {
            fn(arg);
            ok = true;
        } else {
            ok = false;
        }

        g_protArmed = prevArmed;
        memcpy(g_jb, prev, sizeof(g_jb));
        return ok;
    }

    bool RunProtected(SectionFn fn, void* arg)
    {
        if (RunProtectedQuiet(fn, arg)) return true;
        Log::Str("    <section faulted; skipped>\n");
        return false;
    }

    // --------- linux-registers ---

    void Report_Registers(void* vctx)
    {
        ucontext_t* uc = (ucontext_t*)vctx;
        if (!uc) { Log::Str("  <no context>\n"); return; }
        greg_t* g = uc->uc_mcontext.gregs;

        #if defined(CC_X64)
            Log::F("  rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx\n",
                   (unsigned long long)g[REG_RAX], (unsigned long long)g[REG_RBX],
                   (unsigned long long)g[REG_RCX], (unsigned long long)g[REG_RDX]);
            Log::F("  rsi=%016llx rdi=%016llx rbp=%016llx rsp=%016llx\n",
                   (unsigned long long)g[REG_RSI], (unsigned long long)g[REG_RDI],
                   (unsigned long long)g[REG_RBP], (unsigned long long)g[REG_RSP]);
            Log::F("  r8 =%016llx r9 =%016llx r10=%016llx r11=%016llx\n",
                   (unsigned long long)g[REG_R8], (unsigned long long)g[REG_R9],
                   (unsigned long long)g[REG_R10], (unsigned long long)g[REG_R11]);
            Log::F("  r12=%016llx r13=%016llx r14=%016llx r15=%016llx\n",
                   (unsigned long long)g[REG_R12], (unsigned long long)g[REG_R13],
                   (unsigned long long)g[REG_R14], (unsigned long long)g[REG_R15]);
            uintptr_t pc = (uintptr_t)g[REG_RIP];
            char rip[512]; FormatAddress(pc, rip, sizeof(rip));
            Log::F("  rip=%016llx  %s\n", (unsigned long long)pc, rip);
            Log::F("  eflags=%08llx\n", (unsigned long long)g[REG_EFL]);
            uintptr_t sp = (uintptr_t)g[REG_RSP];
        #else
            Log::F("  eax=%08x ebx=%08x ecx=%08x edx=%08x\n",
                   (unsigned)g[REG_EAX], (unsigned)g[REG_EBX], (unsigned)g[REG_ECX], (unsigned)g[REG_EDX]);
            Log::F("  esi=%08x edi=%08x ebp=%08x esp=%08x\n",
                   (unsigned)g[REG_ESI], (unsigned)g[REG_EDI], (unsigned)g[REG_EBP], (unsigned)g[REG_ESP]);
            uintptr_t pc = (uintptr_t)g[REG_EIP];
            char eip[512]; FormatAddress(pc, eip, sizeof(eip));
            Log::F("  eip=%08x  %s\n", (unsigned)pc, eip);
            Log::F("  eflags=%08x\n", (unsigned)g[REG_EFL]);
            uintptr_t sp = (uintptr_t)g[REG_ESP];
        #endif
        if (Mem_IsReadable((void*)pc, 16)) {
            Log::Str("  code bytes at instruction pointer:\n");
            Log::HexDump((void*)pc, 16, pc);
        }
        (void)sp;
    }

    // --------- linux-stack-walker ---

    struct BtState { int n; };
    static _Unwind_Reason_Code BtCb(struct _Unwind_Context* ctx, void* arg)
    {
        BtState* s = (BtState*)arg;
        uintptr_t pc = (uintptr_t)_Unwind_GetIP(ctx);
        if (pc) {
            char buf[512];
            FormatAddress(pc, buf, sizeof(buf));
            Log::F("  #%-2d %s\n", s->n, buf);
        }
        if (++s->n > 96) return _URC_END_OF_STACK;
        return _URC_NO_REASON;
    }

    // silent warm-up of libgcc/dladdr at arm time, cause we don't want this printing immediately...
    static _Unwind_Reason_Code BtWarmCb(struct _Unwind_Context*, void* arg)
    {
        int* n = (int*)arg;
        return (++*n > 8) ? _URC_END_OF_STACK : _URC_NO_REASON;
    }

    void Report_StackScan(void* vctx)
    {
        if (!vctx) { Log::Str("  <no context>\n"); return; }
        ucontext_t* uc = (ucontext_t*)vctx;
        #if defined(CC_X64)
            uintptr_t sp = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
        #else
            uintptr_t sp = (uintptr_t)uc->uc_mcontext.gregs[REG_ESP];
        #endif
        int found = 0;
        for (uintptr_t a = sp; a < sp + 0x4000 && found < 64; a += sizeof(uintptr_t)) {
            if (!Mem_IsReadable((void*)a, sizeof(uintptr_t))) break;
            uintptr_t v = *(uintptr_t*)a;
            if (Modules_Find(v) && Mem_IsExecutable(v)) {
                char buf[512]; FormatAddress(v, buf, sizeof(buf));
                Log::F("  [sp+0x%llx] %s\n", (unsigned long long)(a - sp), buf);
                ++found;
            }
        }
        if (!found) Log::Str("  <none>\n");
    }

    void Report_NativeStack(void* vctx)
    {
        // PC in no file-backed module (anon-exec or unmapped) is typically LuaJIT mcode
        if (vctx) {
            ucontext_t* uc = (ucontext_t*)vctx;
            #if defined(CC_X64)
                uintptr_t pc0 = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
            #else
                uintptr_t pc0 = (uintptr_t)uc->uc_mcontext.gregs[REG_EIP];
            #endif
            const CCModule* m0 = pc0 ? Modules_Find(pc0) : NULL;
            if (pc0 && (!m0 || strcmp(m0->name, "[anon-exec]") == 0))
                Log::Str("  note: instruction pointer is in anonymous executable memory "
                    "(likely LuaJIT mcode); see the Lua section for the Lua frame.\n");
        }

        Log::Str("  (libgcc unwind; the top frames are the signal handler)\n");
        BtState s = { 0 };
        _Unwind_Backtrace(BtCb, &s);
    }

    // --------- linux-section-adapters ---

    static void* g_curCtx = NULL;
    static void Sec_Registers(void*) { Report_Registers(g_curCtx); }
    static void Sec_Stack(void*) { Report_NativeStack(g_curCtx); }
    static void Sec_StackScan(void*) { Report_StackScan(g_curCtx); }
    static void Sec_Lua(void*) { Lua_Dump(); }
    static void Sec_Modules(void*) { Modules_Dump(); }

    static const char* SignalName(int s)
    {
        switch (s) {
            case SIGSEGV: return "SIGSEGV";
            case SIGBUS: return "SIGBUS";
            case SIGILL: return "SIGILL";
            case SIGFPE: return "SIGFPE";
            case SIGABRT: return "SIGABRT";
            default: return "signal";
        }
    }

    static void WriteReport(const char* kind, const char* reason, void* uctx, uintptr_t fault = 0)
    {
        Modules_Refresh();
        Log::Open(kind);
        Report_SetContext(kind, reason, fault);
        Report_Header(kind, reason);
        g_curCtx = uctx;
        Report_Section("Registers", Sec_Registers, NULL, true);
        Report_Section("Native stack", Sec_Stack, NULL, true);
        Report_Section("Stack scan (code pointers)", Sec_StackScan, NULL, true);
        Report_Section("Lua", Sec_Lua, NULL, false);
        Report_Section("Modules", Sec_Modules, NULL, false);
        Report_Section("Diagnostics", Diag_Section, uctx, false);
        Report_Footer();
        Log::Close();
    }

    struct FmtCtx { uintptr_t addr; char* out; size_t sz; };
    static void Sec_FormatAddr(void* p) { FmtCtx* f = (FmtCtx*)p; FormatAddress(f->addr, f->out, f->sz); }

    // --------- linux-signal-entry ---
    static void FatalHandler(int sig, siginfo_t* info, void* ucontext)
    {
        // fault while inside a protected section? bail back to it.
        if (g_protArmed) { g_protArmed = 0; siglongjmp(g_jb, 1); }

        if (g_inReport) { // recursive crash while reporting
            for (int i = 0; kFatal[i]; ++i) signal(kFatal[i], SIG_DFL);
            return;
        }
        g_inReport = 1;

        char reason[256];
        char at[512];
        uintptr_t faultAddr = (uintptr_t)(info ? info->si_addr : 0);
        snprintf(at, sizeof(at), "0x%llx", (unsigned long long)faultAddr); // raw fallback
        FmtCtx fc = { faultAddr, at, sizeof(at) };
        RunProtectedQuiet(Sec_FormatAddr, &fc); // symbolize, but never recurse-kill
        int tid = gettid_();
        snprintf(reason, sizeof(reason), "%s (code %d) fault addr %s%s",
                 SignalName(sig), info ? info->si_code : 0, at,
                 (g_gameThreadTid && tid != g_gameThreadTid) ? " [NOT the game thread]" : "");

        WriteReport("crash", reason, ucontext, faultAddr);

        // chain to whatever was installed before us (core dumps, valve handlers).
        struct sigaction* old = (sig >= 0 && sig < 64) ? &g_old[sig] : NULL;
        g_inReport = 0;
        if (old) {
            if (old->sa_flags & SA_SIGINFO) {
                if (old->sa_sigaction) { old->sa_sigaction(sig, info, ucontext); return; }
            } else if (old->sa_handler && old->sa_handler != SIG_IGN && old->sa_handler != SIG_DFL) {
                old->sa_handler(sig); return;
            }
        }
        signal(sig, SIG_DFL); // re-fault into the default action
    }

    // SIGUSR2 = "dump where you are right now" (watchdog hang inspection)
    static void DumpRequestHandler(int /*sig*/, siginfo_t* /*info*/, void* ucontext)
    {
        if (g_inReport) { g_dumpDone = 1; return; }
        g_inReport = 1;
        const char* kind = g_pendKind ? g_pendKind : "dump";
        const char* reason = g_pendReason ? g_pendReason : "thread inspection";
        WriteReport(kind, reason, ucontext);
        g_inReport = 0;
        g_dumpDone = 1;
    }

    void Platform_DumpThread(const char* kind, const char* reason)
    {
        int self = gettid_();
        if (g_gameThreadTid && g_gameThreadTid != self) {
            g_pendKind = kind;
            g_pendReason = reason;
            g_dumpDone = 0;
            if (syscall(SYS_tgkill, getpid(), g_gameThreadTid, SIGUSR2) == 0) {
                for (int i = 0; i < 2000 && !g_dumpDone; ++i) {
                    struct timespec ts = { 0, 1000000 }; // 1ms
                    nanosleep(&ts, NULL);
                }
                if (g_dumpDone) return;
                Log::Str("[CrashCapture] hang: target thread did not respond to dump signal; "
                         "writing from watchdog thread.\n");
            }
        }
        // fall back scenario: dump from the calling (watchdog) thread without a context.
        if (g_inReport) return;
        g_inReport = 1;
        WriteReport(kind, reason, NULL);
        g_inReport = 0;
    }

    // --------- linux-install ---
    void Platform_Install()
    {
        static char altbuf[64 * 1024];
        g_altstack.ss_sp = altbuf;
        g_altstack.ss_size = sizeof(altbuf);
        g_altstack.ss_flags = 0;
        sigaltstack(&g_altstack, NULL);

        // warm up the unwinder/dladdr once.
        int warm = 0;
        _Unwind_Backtrace(BtWarmCb, &warm);

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = FatalHandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESTART;
        for (int i = 0; kFatal[i]; ++i)
            sigaction(kFatal[i], &sa, &g_old[kFatal[i]]);

        struct sigaction su;
        memset(&su, 0, sizeof(su));
        su.sa_sigaction = DumpRequestHandler;
        sigemptyset(&su.sa_mask);
        su.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
        sigaction(SIGUSR2, &su, NULL);

        Sym_Init();
    }

    void Platform_Uninstall()
    {
        for (int i = 0; kFatal[i]; ++i)
            sigaction(kFatal[i], &g_old[kFatal[i]], NULL);
        signal(SIGUSR2, SIG_DFL);
        Sym_Cleanup();
    }
}

#endif // CC_LINUX
