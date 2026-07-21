// Crash Capture - Windows crash & hang capture
// Catches fatal exceptions (SEH + VEH) and CRT aborts, walks the native stack
// (x64 via .pdata, x86 via the EBP chain), and dumps a stalled thread on demand.

#include "crashcapture.h"
#include "features/index.hpp"

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
    static const int kRecentPc = 16;
    static const uint64_t kDupWindowMs = 30000;
    static const int kMaxFirstChanceReports = 12;
    static uintptr_t g_recentPc[kRecentPc] = {0};
    static uint64_t  g_recentMs[kRecentPc] = {0};
    static int g_recentIdx = 0;
    static int g_firstChanceReports = 0;

    static bool SeenRecently(uintptr_t pc, uint64_t now)
    {
        if (!pc) return false;
        for (int i = 0; i < kRecentPc; ++i)
            if (g_recentPc[i] == pc && (now - g_recentMs[i]) < kDupWindowMs) return true;
        return false;
    }
    static void RememberPc(uintptr_t pc, uint64_t now)
    {
        g_recentPc[g_recentIdx] = pc;
        g_recentMs[g_recentIdx] = now;
        g_recentIdx = (g_recentIdx + 1) % kRecentPc;
    }

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

    void Report::Registers(void* vctx)
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
        if (Mem::IsReadable((void*)pc, 16)) {
            Log::Str("  code bytes at instruction pointer:\n");
            Log::HexDump((void*)pc, 16, pc);
        }
    }

    // --------- windows-stack-walk ---

    void Report::StackScan(void* vctx)
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
            if (!Mem::IsReadable((void*)a, sizeof(uintptr_t))) break;
            uintptr_t v = *(uintptr_t*)a;
            if (Modules::Find(v) && Mem::IsExecutable(v)) {
                char buf[512]; FormatAddress(v, buf, sizeof(buf));
                Log::F("  [sp+0x%llx] %s\n", (unsigned long long)(a - sp), buf);
                ++found;
            }
        }
        if (!found) Log::Str("  <none>\n");
    }

    void Report::NativeStack(void* vctx)
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
        if (pc0 && !Modules::Find(pc0) && Mem::IsExecutable(pc0))
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
                if (c.Rip && Mem::IsExecutable((uintptr_t)c.Rip))
                    rf = RtlLookupFunctionEntry(c.Rip, &imageBase, NULL);

                if (rf) {
                    PVOID handlerData = NULL;
                    DWORD64 establisher = 0;
                    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, c.Rip, rf, &c,
                                     &handlerData, &establisher, NULL);
                    if (c.Rip == 0) break; // bottom of a real chain
                } else {
                    if (!Mem::IsReadable((void*)c.Rsp, sizeof(DWORD64))) break;
                    c.Rip = *(DWORD64*)c.Rsp;
                    c.Rsp += sizeof(DWORD64);
                }
            }
        #else
            char buf[512]; FormatAddress((uintptr_t)base->Eip, buf, sizeof(buf));
            Log::F("  #0  0x%08lx  %s  (eip)\n", base->Eip, buf);
            uintptr_t ebp = base->Ebp;
            for (int frame = 1; frame < 64; ++frame) {
                if (!Mem::IsReadable((void*)ebp, 2 * sizeof(uintptr_t))) break;
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

    int Platform::Backtrace(void* vctx, uintptr_t* out, int max)
    {
        if (!out || max <= 0) return 0;
        CONTEXT local;
        CONTEXT* base = (CONTEXT*)vctx;
        if (!base) { RtlCaptureContext(&local); base = &local; }
        int n = 0;
        #if defined(CC_X64)
            CONTEXT c = *base;
            while (n < max && n < 64) {
                out[n++] = (uintptr_t)c.Rip;
                DWORD64 imageBase = 0;
                PRUNTIME_FUNCTION rf = NULL;
                if (c.Rip && Mem::IsExecutable((uintptr_t)c.Rip))
                    rf = RtlLookupFunctionEntry(c.Rip, &imageBase, NULL);
                if (rf) {
                    PVOID handlerData = NULL; DWORD64 establisher = 0;
                    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, c.Rip, rf, &c,
                                     &handlerData, &establisher, NULL);
                    if (c.Rip == 0) break;
                } else {
                    if (!Mem::IsReadable((void*)c.Rsp, sizeof(DWORD64))) break;
                    c.Rip = *(DWORD64*)c.Rsp;
                    c.Rsp += sizeof(DWORD64);
                }
            }
        #else
            out[n++] = (uintptr_t)base->Eip;
            uintptr_t ebp = base->Ebp;
            while (n < max && n < 64) {
                if (!Mem::IsReadable((void*)ebp, 2 * sizeof(uintptr_t))) break;
                uintptr_t ret     = ((uintptr_t*)ebp)[1];
                uintptr_t nextEbp = ((uintptr_t*)ebp)[0];
                if (!ret) break;
                out[n++] = ret;
                if (nextEbp <= ebp) break;
                ebp = nextEbp;
            }
        #endif
        return n;
    }

    // --------- windows-section-adapters ---

    static void* g_curCtx = NULL;
    static void Sec_Registers(void*)   { Report::Registers(g_curCtx); }
    static void Sec_Stack(void*)       { Report::NativeStack(g_curCtx); }
    static void Sec_StackScan(void*)   { Report::StackScan(g_curCtx); }
    static void Sec_Lua(void*)         { Lua::Dump(); }
    static void Sec_Modules(void*)     { Modules::Dump(); }
    static void Sec_EngineFrame(void*) { Engine::ReportFrameProfile(); }

    static void EmitSections()
    {
        { EngineFrameStats efs; if (Engine::FrameStats(&efs)) Report::Section("Profiling", Sec_EngineFrame, NULL, false); }
        Report::Section("Registers",   Sec_Registers, NULL, true);
        Report::Section("Native stack", Sec_Stack,    NULL, true);
        Report::Section("Stack scan (code pointers)", Sec_StackScan, NULL, true);
        Report::Section("Lua",         Sec_Lua,       NULL, false);
        Report::Section("Modules",     Sec_Modules,   NULL, false);
        Report::Section("Diagnostics", Diag::Section,  g_curCtx, false);
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

        Modules::Refresh();
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

        Report::SetContext(kind, reason, fault);
        Report::Header(kind, reason);

        g_curCtx = ctx;
        EmitSections();

        Report::Footer();
        Log::Close();
    }

    static LONG HandleException(const char* kind, EXCEPTION_POINTERS* ep, bool firstChance)
    {
        if (InterlockedCompareExchange(&g_inReport, 1, 0) != 0)
            return EXCEPTION_CONTINUE_SEARCH;
        Log::Panic();

        uintptr_t pc = ep && ep->ExceptionRecord ? (uintptr_t)ep->ExceptionRecord->ExceptionAddress : 0;
        uint64_t now = MonotonicMs();

        bool write = true;
        if (firstChance) {
            if (g_firstChanceReports >= kMaxFirstChanceReports || SeenRecently(pc, now))
                write = false;
        }

        if (write) {
            WriteCrashReport(kind, ep);
            RememberPc(pc, now);
            if (firstChance && ++g_firstChanceReports == kMaxFirstChanceReports)
                Log::Notice("[Crash Capture] first-chance report cap reached (%d); "
                            "further first-chance exceptions are suppressed this session.\n",
                            kMaxFirstChanceReports);
        }
        
        // TODO: windows needs physics-fault resume but this is a low priority.
        if (firstChance) Log::ClearPanic();
        InterlockedExchange(&g_inReport, 0);
        return EXCEPTION_CONTINUE_SEARCH; // let WER / the runtime finish the crash
    }

    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* ep)
    {
        if (!Cfg().firstchance) return EXCEPTION_CONTINUE_SEARCH;
        if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
        if (!IsFatalCode(ep->ExceptionRecord->ExceptionCode)) return EXCEPTION_CONTINUE_SEARCH;
        return HandleException("first-chance fatal exception", ep, true);
    }

    static LONG WINAPI UnhandledFilter(EXCEPTION_POINTERS* ep)
    {
        HandleException("unhandled exception", ep, false);
        if (g_prevFilter) return g_prevFilter(ep);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // --------- windows-thread-dumper ---

    bool Platform::IsGameThread()
    {
        return g_gameThreadId != 0 && GetCurrentThreadId() == g_gameThreadId;
    }

    void Platform::DumpThread(const char* kind, const char* reason)
    {
        if (InterlockedCompareExchange(&g_inReport, 1, 0) != 0) return;

        Modules::Refresh();
        Log::Open(kind);

        const char* dispKind = kind;
        char dk[96];
        {
            char stall[128] = "unknown (no thread context)";
            int sc = STALL_UNKNOWN;
            HANDLE th0 = (HANDLE)g_gameThreadHandle;
            if (th0 && g_gameThreadId != GetCurrentThreadId()) {
                SuspendThread(th0);
                CONTEXT cc; memset(&cc, 0, sizeof(cc));
                cc.ContextFlags = CONTEXT_FULL;
                if (GetThreadContext(th0, &cc)) sc = Report::ClassifyStall(&cc, stall, sizeof(stall));
                ResumeThread(th0);
            }
            g_lastStallClass = sc;
            snprintf(dk, sizeof(dk), "%s - %s", kind, stall);
            dispKind = dk;
        }

        Report::SetContext(dispKind, reason, 0);
        Report::Header(dispKind, reason);

        CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
        HANDLE th = (HANDLE)g_gameThreadHandle;
        bool suspended = false;
        g_curCtx = NULL;
        if (th && g_gameThreadId != GetCurrentThreadId()) {
            ctx.ContextFlags = CONTEXT_FULL;
            if (SuspendThread(th) == (DWORD)-1) {
                Log::Str("\n> SuspendThread failed; reporting calling thread instead.\n");
            } else {
                suspended = true;
                if (GetThreadContext(th, &ctx)) {
                    Log::F("\n> target thread id=%u suspended for inspection\n", g_gameThreadId);
                    g_curCtx = &ctx;
                } else {
                    Log::Str("\n> GetThreadContext failed; reporting calling thread instead.\n");
                }
            }
        }

        { EngineFrameStats efs; if (Engine::FrameStats(&efs)) Report::Section("Profiling", Sec_EngineFrame, NULL, false); }
        Report::Section("Registers", Sec_Registers, NULL, true);
        Report::Section("Native stack", Sec_Stack, NULL, true);
        Report::Section("Stack scan (code pointers)", Sec_StackScan, NULL, true);
        Report::Section("Lua", Sec_Lua, NULL, false);
        
        if (suspended) ResumeThread(th);

        Report::Section("Modules", Sec_Modules, NULL, false);
        Report::Section("Diagnostics", Diag::Section, g_curCtx, false);

        Report::Footer();
        Log::Close();
        InterlockedExchange(&g_inReport, 0);
    }

    int Platform::RequestLuaBreak()
    {
        if (g_gameThreadId == GetCurrentThreadId())
            return -1;

        HANDLE th = (HANDLE)g_gameThreadHandle;
        if (!th) return 0;
        if (SuspendThread(th) == (DWORD)-1) return 0;

        CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(th, &ctx);

        int armed = Lua::ArmBreakHook();

        ResumeThread(th);
        return armed;
    }
    int Platform::SetPhysPaused(int) { return 0; }
    int Platform::PhysPaused() { return -1; }

    uintptr_t Platform::ContextPC(void* vctx)
    {
        if (!vctx) return 0;
        CONTEXT* c = (CONTEXT*)vctx;
        #if defined(CC_X64)
            return (uintptr_t)c->Rip;
        #else
            return (uintptr_t)c->Eip;
        #endif
    }

    // --------- windows-symbols (dbghelp) ---
    
    static bool g_symReady = false;
    void Sym::Init()
    {
        if (g_symReady || !Cfg().symbols) return;
        SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
        __try {
            if (SymInitialize(GetCurrentProcess(), NULL, TRUE)) g_symReady = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) { g_symReady = false; }
    }

    void Sym::Cleanup()
    {
        if (!g_symReady) return;
        __try { SymCleanup(GetCurrentProcess()); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        g_symReady = false;
    }

    bool Sym::Resolve(uintptr_t addr, char* out, size_t outsz)
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

    uintptr_t Sym::Lookup(const char* module, const char* name)
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
                    const CCModule* m = Modules::FindByName(module);
                    if (m && (uintptr_t)si->Address >= m->base && (uintptr_t)si->Address < m->base + m->size)
                        return (uintptr_t)si->Address;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        if (module) {
            const CCModule* m = Modules::FindByName(module);
            if (!m) return 0;
            void* p = (void*)GetProcAddress((HMODULE)m->base, name);
            return (uintptr_t)p;
        }

        const CCModule* mods = NULL;
        int c = Modules::Snapshot(&mods);
        for (int i = 0; i < c; ++i) {
            void* p = (void*)GetProcAddress((HMODULE)mods[i].base, name);
            if (p) return (uintptr_t)p;
        }
        return 0;
    }

    int Platform::EnumThreads(CCThread* out, int max)
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
        Modules::Refresh();
        Log::Open(kind);
        Report::SetContext(kind, reason, 0);
        Report::Header(kind, reason);
        g_curCtx = NULL; // sections capture the live context via RtlCaptureContext
        EmitSections();
        Report::Footer();
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

    static HANDLE g_dumpEvent = NULL; // external SetEvent -> request a dump
    static HANDLE g_dumpStop = NULL; // signalled at teardown to unblock the waiter
    static HANDLE g_dumpWaiter = NULL;

    static DWORD WINAPI DumpWaiterThread(LPVOID)
    {
        HANDLE h[2] = { g_dumpEvent, g_dumpStop };
        for (;;) {
            DWORD w = WaitForMultipleObjects(2, h, FALSE, INFINITE);
            if (w != WAIT_OBJECT_0) break;
            DumpNow("manual dump requested (event)");
        }
        return 0;
    }

    static void StartDumpWaiter()
    {
        if (g_dumpWaiter) return;
        char name[64];
        snprintf(name, sizeof(name), "Local\\CrashCapture_Dump_%lu",
                 (unsigned long)GetCurrentProcessId());
        g_dumpEvent = CreateEventA(NULL, FALSE, FALSE, name);
        g_dumpStop = CreateEventA(NULL, FALSE, FALSE, NULL);
        if (!g_dumpEvent || !g_dumpStop) return;
        g_dumpWaiter = CreateThread(NULL, 0, DumpWaiterThread, NULL, 0, NULL);
        if (g_dumpWaiter)
            Log::F("[Crash Capture] manual dump armed: signal event \"%s\" to capture.\n", name);
    }

    static void StopDumpWaiter()
    {
        if (g_dumpWaiter) {
            if (g_dumpStop) SetEvent(g_dumpStop);
            WaitForSingleObject(g_dumpWaiter, 2000);
            CloseHandle(g_dumpWaiter); g_dumpWaiter = NULL;
        }
        if (g_dumpStop) { CloseHandle(g_dumpStop); g_dumpStop = NULL; }
        if (g_dumpEvent) { CloseHandle(g_dumpEvent); g_dumpEvent = NULL; }
    }

    // ------------------------------------------------------------- install -----
    void Platform::Install()
    {
        g_prevFilter = SetUnhandledExceptionFilter(UnhandledFilter);
        g_veh = AddVectoredExceptionHandler(0 /*call last*/, VectoredHandler);
        // make sure our last-chance filter is actually reached.
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        InstallCrtHandlers();
        if (Cfg().manual_dump) StartDumpWaiter();
        Sym::Init(); // enumerate modules now, in a safe (non-crash) context
        Features::Init();
    }

    void Platform::Uninstall()
    {
        Features::Shutdown();
        StopDumpWaiter();
        if (g_veh) { RemoveVectoredExceptionHandler(g_veh); g_veh = NULL; }
        SetUnhandledExceptionFilter(g_prevFilter);
        g_prevFilter = NULL;
        signal(SIGABRT, SIG_DFL);
        Sym::Cleanup();
    }
}

#endif // CC_WINDOWS
