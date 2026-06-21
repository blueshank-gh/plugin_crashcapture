// Crash Capture - Windows crash & hang capture
// Catches fatal exceptions (SEH + VEH) and CRT aborts, walks the native stack
// (x64 via .pdata, x86 via the EBP chain), and dumps a stalled thread on demand.

#include "crashcapture.h"

#if defined(CC_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <eh.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#pragma comment(lib, "dbghelp.lib")

namespace CrashCapture {
    void* g_gameThreadHandle = NULL;   // see crashcapture.h
    unsigned g_gameThreadId = 0;

    static PVOID    g_veh = NULL;
    static LPTOP_LEVEL_EXCEPTION_FILTER g_prevFilter = NULL;
    static volatile LONG g_inReport = 0;
    static uintptr_t g_lastPc = 0;
    static uint64_t  g_lastMs = 0;

    // __try/__except can't share a frame with C++ unwinding, so this just calls through the pointer.
    bool RunProtectedQuiet(SectionFn fn, void* arg)
    {
        __try {
            fn(arg);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool RunProtected(SectionFn fn, void* arg)
    {
        if (RunProtectedQuiet(fn, arg)) return true;
        Log::Str("    <section faulted; skipped>\n");
        return false;
    }

    // --------- windows-registers ---

    void Report_Registers(void* vctx)
    {
        CONTEXT local;
        CONTEXT* c = (CONTEXT*)vctx;
        if (!c) { RtlCaptureContext(&local); c = &local; }

        #if defined(CC_X64)
            Log::F("  rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx\n", c->Rax, c->Rbx, c->Rcx, c->Rdx);
            Log::F("  rsi=%016llx rdi=%016llx rbp=%016llx rsp=%016llx\n", c->Rsi, c->Rdi, c->Rbp, c->Rsp);
            Log::F("  r8 =%016llx r9 =%016llx r10=%016llx r11=%016llx\n", c->R8,  c->R9,  c->R10, c->R11);
            Log::F("  r12=%016llx r13=%016llx r14=%016llx r15=%016llx\n", c->R12, c->R13, c->R14, c->R15);
            char rip[512]; FormatAddress((uintptr_t)c->Rip, rip, sizeof(rip));
            Log::F("  rip=%016llx  %s\n", c->Rip, rip);
            Log::F("  eflags=%08lx\n", (unsigned long)c->EFlags);
        #else
            Log::F("  eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx\n", c->Eax, c->Ebx, c->Ecx, c->Edx);
            Log::F("  esi=%08lx edi=%08lx ebp=%08lx esp=%08lx\n", c->Esi, c->Edi, c->Ebp, c->Esp);
            char eip[512]; FormatAddress((uintptr_t)c->Eip, eip, sizeof(eip));
            Log::F("  eip=%08lx  %s\n", c->Eip, eip);
            Log::F("  eflags=%08lx cs=%04lx ds=%04lx ss=%04lx\n", c->EFlags, c->SegCs, c->SegDs, c->SegSs);
        #endif

        #if defined(CC_X64)
            uintptr_t pc = (uintptr_t)c->Rip;
        #else
            uintptr_t pc = (uintptr_t)c->Eip;
        #endif
        if (Mem_IsReadable((void*)pc, 16)) {
            Log::Str("  code bytes at instruction pointer:\n");
            Log::HexDump((void*)pc, 16, pc);
        }
    }

    // --------- windows-stack-walk ---

    void Report_StackScan(void* vctx)
    {
        CONTEXT local;
        CONTEXT* base = (CONTEXT*)vctx;
        if (!base) { RtlCaptureContext(&local); base = &local; }
        #if defined(CC_X64)
            uintptr_t sp = (uintptr_t)base->Rsp;
        #else
            uintptr_t sp = (uintptr_t)base->Esp;
        #endif
        uintptr_t spLimit = sp + 0x4000;

        int found = 0;
        for (uintptr_t a = sp; a < spLimit && found < 64; a += sizeof(uintptr_t)) {
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
        CONTEXT local;
        CONTEXT* base = (CONTEXT*)vctx;
        if (!base) { RtlCaptureContext(&local); base = &local; }

        // executable PC in no module = likely LuaJIT mcode... the Lua section locates it.
        #if defined(CC_X64)
            uintptr_t pc0 = (uintptr_t)base->Rip;
        #else
            uintptr_t pc0 = (uintptr_t)base->Eip;
        #endif
        if (pc0 && !Modules_Find(pc0) && Mem_IsExecutable(pc0))
            Log::Str("  note: instruction pointer is in anonymous executable memory "
                     "(likely LuaJIT mcode); see the Lua section for the Lua frame.\n");

        #if defined(CC_X64)
            CONTEXT c = *base;
            for (int frame = 0; frame < 64; ++frame) {
                char buf[512]; FormatAddress((uintptr_t)c.Rip, buf, sizeof(buf));
                Log::F("  #%-2d 0x%016llx  %s\n", frame, c.Rip, buf);

                // Only a real executable PC has .pdata; for a null/garbage/mcode PC,
                // recover the return address off the stack top and keep walking.
                DWORD64 imageBase = 0;
                PRUNTIME_FUNCTION rf = NULL;
                if (c.Rip && Mem_IsExecutable((uintptr_t)c.Rip))
                    rf = RtlLookupFunctionEntry(c.Rip, &imageBase, NULL);

                if (rf) {
                    PVOID handlerData = NULL;
                    DWORD64 establisher = 0;
                    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, c.Rip, rf, &c,
                                     &handlerData, &establisher, NULL);
                    if (c.Rip == 0) break; // bottom of a real chain
                } else {
                    if (!Mem_IsReadable((void*)c.Rsp, sizeof(DWORD64))) break;
                    c.Rip = *(DWORD64*)c.Rsp;
                    c.Rsp += sizeof(DWORD64);
                }
            }
        #else
            char buf[512]; FormatAddress((uintptr_t)base->Eip, buf, sizeof(buf));
            Log::F("  #0  0x%08lx  %s  (eip)\n", base->Eip, buf);
            uintptr_t ebp = base->Ebp;
            for (int frame = 1; frame < 64; ++frame) {
                if (!Mem_IsReadable((void*)ebp, 2 * sizeof(uintptr_t))) break;
                uintptr_t ret     = ((uintptr_t*)ebp)[1];
                uintptr_t nextEbp = ((uintptr_t*)ebp)[0];
                if (!ret) break;
                FormatAddress(ret, buf, sizeof(buf));
                Log::F("  #%-2d 0x%08lx  %s\n", frame, (unsigned long)ret, buf);
                if (nextEbp <= ebp) break; // chain must climb
                ebp = nextEbp;
            }
        #endif
    }

    // --------- windows-section-adapters ---

    static void* g_curCtx = NULL;
    static void Sec_Registers(void*)   { Report_Registers(g_curCtx); }
    static void Sec_Stack(void*)       { Report_NativeStack(g_curCtx); }
    static void Sec_StackScan(void*)   { Report_StackScan(g_curCtx); }
    static void Sec_Lua(void*)         { Lua_Dump(); }
    static void Sec_Modules(void*)     { Modules_Dump(); }

    static void EmitSections()
    {
        Report_Section("Registers",   Sec_Registers, NULL, true);
        Report_Section("Native stack", Sec_Stack,    NULL, true);
        Report_Section("Stack scan (code pointers)", Sec_StackScan, NULL, true);
        Report_Section("Lua",         Sec_Lua,       NULL, false);
        Report_Section("Modules",     Sec_Modules,   NULL, false);
        Report_Section("Diagnostics", Diag_Section,  g_curCtx, false);
    }

    static const char* ExceptionName(DWORD code)
    {
        switch (code) {
            case EXCEPTION_ACCESS_VIOLATION:      return "ACCESS_VIOLATION";
            case EXCEPTION_ILLEGAL_INSTRUCTION:   return "ILLEGAL_INSTRUCTION";
            case EXCEPTION_STACK_OVERFLOW:        return "STACK_OVERFLOW";
            case EXCEPTION_INT_DIVIDE_BY_ZERO:    return "INT_DIVIDE_BY_ZERO";
            case EXCEPTION_PRIV_INSTRUCTION:      return "PRIV_INSTRUCTION";
            case EXCEPTION_IN_PAGE_ERROR:         return "IN_PAGE_ERROR";
            case EXCEPTION_DATATYPE_MISALIGNMENT: return "DATATYPE_MISALIGNMENT";
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:    return "FLT_DIVIDE_BY_ZERO";
            case EXCEPTION_BREAKPOINT:            return "BREAKPOINT";
            case 0xE06D7363:                      return "C++ exception (msvc)";
            default:                              return "unknown";
        }
    }

    static bool IsFatalCode(DWORD code)
    {
        switch (code) {
            case EXCEPTION_ACCESS_VIOLATION:
            case EXCEPTION_ILLEGAL_INSTRUCTION:
            case EXCEPTION_STACK_OVERFLOW:
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
            case EXCEPTION_PRIV_INSTRUCTION:
            case EXCEPTION_IN_PAGE_ERROR:
            case EXCEPTION_DATATYPE_MISALIGNMENT:
                return true;
            default:
                return false;
        }
    }

    static void WriteCrashReport(const char* kind, EXCEPTION_POINTERS* ep)
    {
        EXCEPTION_RECORD* rec = ep ? ep->ExceptionRecord : NULL;
        CONTEXT* ctx = ep ? ep->ContextRecord : NULL;

        Modules_Refresh();
        Log::Open(rec && rec->ExceptionCode == EXCEPTION_STACK_OVERFLOW ? "stackoverflow" : "crash");

        char reason[256];
        uintptr_t fault = 0;
        if (rec) {
            if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2) {
                const char* op = rec->ExceptionInformation[0] == 1 ? "write" :
                                 rec->ExceptionInformation[0] == 8 ? "execute" : "read";
                fault = (uintptr_t)rec->ExceptionInformation[1];
                char faultAddr[512];
                FormatAddress(fault, faultAddr, sizeof(faultAddr));
                snprintf(reason, sizeof(reason), "%s (0x%08lx) %s fault at %s",
                         ExceptionName(rec->ExceptionCode), rec->ExceptionCode, op, faultAddr);
            } else {
                char at[512];
                FormatAddress((uintptr_t)rec->ExceptionAddress, at, sizeof(at));
                snprintf(reason, sizeof(reason), "%s (0x%08lx) at %s",
                         ExceptionName(rec->ExceptionCode), rec->ExceptionCode, at);
            }
        } else {
            snprintf(reason, sizeof(reason), "(no exception record)");
        }

        Report_SetContext(kind, reason, fault);
        Report_Header(kind, reason);

        g_curCtx = ctx;
        EmitSections();

        Report_Footer();
        Log::Close();
    }

    static LONG HandleException(const char* kind, EXCEPTION_POINTERS* ep)
    {
        if (InterlockedCompareExchange(&g_inReport, 1, 0) != 0)
            return EXCEPTION_CONTINUE_SEARCH;

        uintptr_t pc = ep && ep->ExceptionRecord ? (uintptr_t)ep->ExceptionRecord->ExceptionAddress : 0;
        uint64_t now = MonotonicMs();
        bool dup = (pc && pc == g_lastPc && (now - g_lastMs) < 3000);
        if (!dup) {
            WriteCrashReport(kind, ep);
            g_lastPc = pc;
            g_lastMs = now;
        }
        InterlockedExchange(&g_inReport, 0);
        return EXCEPTION_CONTINUE_SEARCH; // let WER / the runtime finish the crash
    }

    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* ep)
    {
        if (!Cfg().firstchance) return EXCEPTION_CONTINUE_SEARCH;
        if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
        if (!IsFatalCode(ep->ExceptionRecord->ExceptionCode)) return EXCEPTION_CONTINUE_SEARCH;
        return HandleException("first-chance fatal exception", ep);
    }

    static LONG WINAPI UnhandledFilter(EXCEPTION_POINTERS* ep)
    {
        HandleException("unhandled exception", ep);
        if (g_prevFilter) return g_prevFilter(ep);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // --------- windows-thread-dumper ---
    
    void Platform_DumpThread(const char* kind, const char* reason)
    {
        if (InterlockedCompareExchange(&g_inReport, 1, 0) != 0) return;

        Modules_Refresh();
        Log::Open(kind);
        Report_SetContext(kind, reason, 0);
        Report_Header(kind, reason);

        HANDLE th = (HANDLE)g_gameThreadHandle;
        if (th && g_gameThreadId != GetCurrentThreadId()) {
            SuspendThread(th);
            CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(th, &ctx)) {
                Log::F("\n> target thread id=%u suspended for inspection\n", g_gameThreadId);
                g_curCtx = &ctx;
            } else {
                Log::Str("\n> GetThreadContext failed; reporting calling thread instead.\n");
                g_curCtx = NULL;
            }
            Report_Section("Registers", Sec_Registers, NULL, true);
            Report_Section("Native stack", Sec_Stack, NULL, true);
            Report_Section("Stack scan (code pointers)", Sec_StackScan, NULL, true);
            ResumeThread(th);
        } else {
            g_curCtx = NULL;
            Report_Section("Registers", Sec_Registers, NULL, true);
            Report_Section("Native stack", Sec_Stack, NULL, true);
            Report_Section("Stack scan (code pointers)", Sec_StackScan, NULL, true);
        }

        Report_Section("Lua", Sec_Lua, NULL, false);
        Report_Section("Modules", Sec_Modules, NULL, false);
        Report_Section("Diagnostics", Diag_Section, g_curCtx, false);

        Report_Footer();
        Log::Close();
        InterlockedExchange(&g_inReport, 0);
    }

    // --------- windows-symbols (dbghelp) ---
    
    static bool g_symReady = false;
    void Sym_Init()
    {
        if (g_symReady || !Cfg().symbols) return;
        SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
        __try {
            if (SymInitialize(GetCurrentProcess(), NULL, TRUE)) g_symReady = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) { g_symReady = false; }
    }

    void Sym_Cleanup()
    {
        if (!g_symReady) return;
        __try { SymCleanup(GetCurrentProcess()); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        g_symReady = false;
    }

    bool Sym_Resolve(uintptr_t addr, char* out, size_t outsz)
    {
        if (!g_symReady || !addr || !out || outsz == 0) return false;
        __try {
            HANDLE proc = GetCurrentProcess();
            char b[sizeof(SYMBOL_INFO) + 512];
            SYMBOL_INFO* si = (SYMBOL_INFO*)b;
            memset(si, 0, sizeof(SYMBOL_INFO));
            si->SizeOfStruct = sizeof(SYMBOL_INFO);
            si->MaxNameLen = 511;
            DWORD64 disp = 0;
            if (!SymFromAddr(proc, addr, &disp, si)) return false;

            IMAGEHLP_LINE64 line; memset(&line, 0, sizeof(line));
            line.SizeOfStruct = sizeof(line);
            DWORD ldisp = 0;
            if (SymGetLineFromAddr64(proc, addr, &ldisp, &line) && line.FileName)
                snprintf(out, outsz, "%s+0x%llx (%s:%lu)", si->Name,
                         (unsigned long long)disp, line.FileName, (unsigned long)line.LineNumber);
            else
                snprintf(out, outsz, "%s+0x%llx", si->Name, (unsigned long long)disp);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    uintptr_t Sym_Lookup(const char* module, const char* name)
    {
        if (!name || !*name) return 0;

        if (g_symReady && Cfg().symbols) {
            __try {
                char b[sizeof(SYMBOL_INFO) + 512];
                SYMBOL_INFO* si = (SYMBOL_INFO*)b;
                memset(si, 0, sizeof(SYMBOL_INFO));
                si->SizeOfStruct = sizeof(SYMBOL_INFO);
                si->MaxNameLen = 511;
                if (SymFromName(GetCurrentProcess(), name, si) && si->Address) {
                    if (!module) return (uintptr_t)si->Address;
                    const CCModule* m = Modules_FindByName(module);
                    if (m && (uintptr_t)si->Address >= m->base && (uintptr_t)si->Address < m->base + m->size)
                        return (uintptr_t)si->Address;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        if (module) {
            const CCModule* m = Modules_FindByName(module);
            if (!m) return 0;
            void* p = (void*)GetProcAddress((HMODULE)m->base, name);
            return (uintptr_t)p;
        }

        const CCModule* mods = NULL;
        int c = Modules_Snapshot(&mods);
        for (int i = 0; i < c; ++i) {
            void* p = (void*)GetProcAddress((HMODULE)mods[i].base, name);
            if (p) return (uintptr_t)p;
        }
        return 0;
    }

    int Platform_EnumThreads(CCThread* out, int max)
    {
        if (!out || max <= 0) return 0;
        DWORD pid = GetCurrentProcessId();
        DWORD self = GetCurrentThreadId();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;

        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        int n = 0;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                if (n >= max) break;
                CCThread& t = out[n];
                t.id = te.th32ThreadID;
                t.pc = 0;
                t.current = (te.th32ThreadID == self);
                t.name[0] = 0;
                if (!t.current) {
                    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (th) {
                        if (SuspendThread(th) != (DWORD)-1) {
                            CONTEXT c;
                            memset(&c, 0, sizeof(c));
                            c.ContextFlags = CONTEXT_CONTROL;
                            if (GetThreadContext(th, &c))
                                #if defined(CC_X64)
                                    t.pc = (uintptr_t)c.Rip;
                                #else
                                    t.pc = (uintptr_t)c.Eip;
                                #endif
                            ResumeThread(th);
                        }
                        CloseHandle(th);
                    }
                }
                ++n;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        return n;
    }

    // --------- windows-asserts-aborts ---
    
    static void WriteSyntheticReport(const char* kind, const char* reason)
    {
        if (InterlockedCompareExchange(&g_inReport, 1, 0) != 0)
            return;
        Modules_Refresh();
        Log::Open(kind);
        Report_SetContext(kind, reason, 0);
        Report_Header(kind, reason);
        g_curCtx = NULL; // sections capture the live context via RtlCaptureContext
        EmitSections();
        Report_Footer();
        Log::Close();
        InterlockedExchange(&g_inReport, 0);
    }

    static void AbortHandler(int)
    {
        // catches abort(), which is also where assert()/_wassert() end up.
        WriteSyntheticReport("abort", "abort() / assert (SIGABRT)");
    }

    static void TerminateHandler()
    {
        WriteSyntheticReport("terminate", "std::terminate (unhandled C++ exception)");
    }

    static void PureCallHandler()
    {
        WriteSyntheticReport("purecall", "pure virtual function call");
    }

    static void InvalidParameterHandler(const wchar_t* expr, const wchar_t* func,
        const wchar_t* file, unsigned int line,
        uintptr_t /*reserved*/)
    {
        char e[200] = {0}, f[200] = {0}, fl[260] = {0};
        if (expr) WideCharToMultiByte(CP_UTF8, 0, expr, -1, e,  sizeof(e) - 1,  NULL, NULL);
        if (func) WideCharToMultiByte(CP_UTF8, 0, func, -1, f,  sizeof(f) - 1,  NULL, NULL);
        if (file) WideCharToMultiByte(CP_UTF8, 0, file, -1, fl, sizeof(fl) - 1, NULL, NULL);
        char reason[700];
        snprintf(reason, sizeof(reason), "CRT invalid parameter: %s in %s (%s:%u)",
                 e[0] ? e : "<expr>", f[0] ? f : "<func>", fl[0] ? fl : "<file>", line);
        WriteSyntheticReport("invalid-parameter", reason);
    }

    static void InstallCrtHandlers()
    {
        signal(SIGABRT, AbortHandler);
        set_terminate(TerminateHandler);
        _set_purecall_handler(PureCallHandler);
        _set_invalid_parameter_handler(InvalidParameterHandler);
        // no abort message box / WER, a headless server must not block on it.
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    }

    // ------------------------------------------------------------- install -----
    void Platform_Install()
    {
        g_prevFilter = SetUnhandledExceptionFilter(UnhandledFilter);
        g_veh = AddVectoredExceptionHandler(0 /*call last*/, VectoredHandler);
        // make sure our last-chance filter is actually reached.
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        InstallCrtHandlers();
        Sym_Init(); // enumerate modules now, in a safe (non-crash) context
    }

    void Platform_Uninstall()
    {
        if (g_veh) { RemoveVectoredExceptionHandler(g_veh); g_veh = NULL; }
        SetUnhandledExceptionFilter(g_prevFilter);
        g_prevFilter = NULL;
        signal(SIGABRT, SIG_DFL);
        Sym_Cleanup();
    }
}

#endif // CC_WINDOWS
