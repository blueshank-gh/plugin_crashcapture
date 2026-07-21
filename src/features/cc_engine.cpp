// cc_engine - see cc_engine.h. Linux + Windows, x86 + x64.

#include "crashcapture.h"
#include "features/cc_engine.h"
#include "tools/cc_hooking.h"
#include "tools/cc_signature.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

#if defined(CC_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#else
    #include <time.h>
#endif

namespace CrashCapture {
    static const CCTarget kEngineTargets[] = {
        #if defined(CC_LINUX) && defined(CC_X86)
            // Sys_Error(const char*, ...)
            {"engine.sys_error", "engine", "_Z9Sys_ErrorPKcz",
                "55 89 E5 83 EC 18 8D 45 0C C7 04 24 01 00 00 00 89 44 24 08 8B 45 08 89 44 24 04 E8 ?? ?? ?? ?? C9 C3",
                {{CC_STEP_END, 0, 0}}},
            // Host_RunFrame(float)
            {"engine.host_runframe", "engine", "_Z13Host_RunFramef",
                "55 89 E5 57 56 53 83 EC 3C C6 05 ?? ?? ?? ?? 00 8B 15 ?? ?? ?? ?? F3 0F 10 5D 08 66 0F 7E DF 85 D2",
                {{CC_STEP_END, 0, 0}}},
        #elif defined(CC_LINUX) && defined(CC_X64)
            // sig runs through `mov edi, 1` (BF 01..): the non-fatal twin is identical up to 0x59.
            {"engine.sys_error", "engine", NULL,
                "55 48 89 E5 48 81 EC D0 00 00 00 84 C0 48 89 B5 58 FF FF FF 48 89 95 60 FF FF FF 48 89 8D 68 FF FF FF 4C 89 85 70 FF FF FF 4C 89 8D 78 FF FF FF 74 20 0F 29 45 80 0F 29 4D 90 0F 29 55 A0 0F 29 5D B0 0F 29 65 C0 0F 29 6D D0 0F 29 75 E0 0F 29 7D F0 48 8D 45 10 48 89 FE BF 01 00 00 00",
                {{CC_STEP_END, 0, 0}}},
            {"engine.host_runframe", "engine", NULL,
                "55 48 89 E5 41 56 66 41 0F 7E C6 41 55 41 54 53 48 83 EC 20 4C 8B 25 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 41 8B 94 24 0C 10 00 00 C6 00 00 85 D2 41 0F 95 C5 0F 85 ?? ?? ?? ??",
                {{CC_STEP_END, 0, 0}}},
        #elif defined(CC_WINDOWS) && defined(CC_X86)
            // __cdecl; sig ends past `push 1` (6A 01) to skip the non-fatal twin.
            {"engine.sys_error", "engine", NULL,
                "55 8B EC 8D 45 0C 50 FF 75 08 6A 01 E8 ?? ?? ?? ?? 83 C4 0C 5D C3",
                {{CC_STEP_END, 0, 0}}},
            {"engine.host_runframe", "engine", NULL,
                "55 8B EC 83 EC 10 80 3D ?? ?? ?? ?? 00 75 6A 83 3D ?? ?? ?? ?? 02 7C 61 83 3D ?? ?? ?? ?? 06",
                {{CC_STEP_END, 0, 0}}},
            // &scr_drawloading - cmp scr_drawloading, 0 / jz / call OnLevelLoadingFinished / mov 0 / jmp / mov 1
            {"engine.loading_byte", "engine", NULL,
                "80 3D ?? ?? ?? ?? 00 74 15 E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 00 EB 07 C6 05 ?? ?? ?? ?? 01",
                {{CC_STEP_ABS32, 2, 0}, {CC_STEP_END, 0, 0}}},
            // CBaseClientState::SetSignonState Range-guard cmp edi, 7 + cmp edi,[esi+13Ch]
            {"client.setsignon", "engine", NULL,
                "55 8B EC 56 57 8B 7D 08 8B F1 83 FF 07 0F 87 ?? ?? ?? ?? 83 FF 02 7E ?? 3B BE 3C 01 00 00",
                {{CC_STEP_END, 0, 0}}},
        #elif defined(CC_WINDOWS) && defined(CC_X64)
            // sig ends past `mov cl, 1` (B1 01) to skip the non-fatal twin.
            {"engine.sys_error", "engine", NULL,
                "48 89 4C 24 08 48 89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 8B D1 4C 8D 44 24 38 B1 01 E8 ?? ?? ?? ??",
                {{CC_STEP_END, 0, 0}}},
            {"engine.host_runframe", "engine", NULL,
                "48 83 EC 48 80 3D ?? ?? ?? ?? 00 0F 29 7C 24 20 0F 28 F8 48 89 5C 24 40 75 6D 83 3D ?? ?? ?? ?? 02",
                {{CC_STEP_END, 0, 0}}},
            // &scr_drawloading
            {"engine.loading_byte", "engine", NULL,
                "40 38 35 ?? ?? ?? ?? 74 15 E8 ?? ?? ?? ?? 40 88 35 ?? ?? ?? ?? EB 07 C6 05 ?? ?? ?? ?? 01",
                {{CC_STEP_REL, 3, 7}, {CC_STEP_END, 0, 0}}},
            // CBaseClientState::SetSignonState cmp edx,7 range-guard + cmp edx,[rcx+15Ch]
            {"client.setsignon", "engine", NULL,
                "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 41 8B F0 8B FA 48 8B D9 83 FA 07 0F 87 ?? ?? ?? ?? 83 FA 02 7E ?? 3B 91 5C 01 00 00",
                {{CC_STEP_END, 0, 0}}},
        #endif
    };

    void Engine::Init()
    {
        Sig::Register(kEngineTargets, (int)(sizeof(kEngineTargets) / sizeof(kEngineTargets[0])));
    }

    static inline uint64_t NowNs()
    {
        #if defined(CC_WINDOWS)
            static LARGE_INTEGER f = {0};
            if (!f.QuadPart) QueryPerformanceFrequency(&f);
            LARGE_INTEGER c; QueryPerformanceCounter(&c);
            uint64_t q = (uint64_t)c.QuadPart, hz = (uint64_t)f.QuadPart;
            return hz ? (q / hz) * 1000000000ull + (q % hz) * 1000000000ull / hz : 0;
        #else
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
        #endif
    }

    // --- Sys_Error: capture, then let it die ---

    typedef void (*Fn_syserror)(const char*, ...);
    static Fn_syserror o_syserror = 0;
    static void* g_sysErrorTarget = 0;
    static bool g_sysErrHooked = false;

    static void h_syserror(const char* fmt, ...)
    {
        char text[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(text, sizeof(text), fmt ? fmt : "Sys_Error", ap);
        va_end(ap);

        Log::Panic();
        Platform::DumpThread("engine error", text);

        if (o_syserror) o_syserror("%s", text);
    }

    // --- Host_RunFrame: time work vs sleep ---

    typedef void (*Fn_hostframe)(float);
    static Fn_hostframe o_hostframe = 0;
    static void* g_hostFrameTarget = 0;
    static bool g_frameHooked = false;

    static uint64_t g_lastExitNs = 0;
    static double g_workMs = 0, g_sleepMs = 0, g_totalMs = 0, g_loadPct = 0;
    static double g_avgWork = 0, g_avgTotal = 0;
    static uint64_t g_frames = 0;

    static void h_hostframe(float time)
    {
        uint64_t entry = NowNs();
        double sleep = g_lastExitNs ? (double)(entry - g_lastExitNs) / 1e6 : 0.0; // idle before this frame

        o_hostframe(time);

        uint64_t exit = NowNs();
        g_lastExitNs = exit;
        double work = (double)(exit - entry) / 1e6;
        double total = sleep + work;

        g_workMs = work;
        g_sleepMs = sleep;
        g_totalMs = total;
        g_loadPct = total > 0 ? work / total * 100.0 : 0.0;
        g_avgWork  = g_frames ? g_avgWork  * 0.95 + work  * 0.05 : work;
        g_avgTotal = g_frames ? g_avgTotal * 0.95 + total * 0.05 : total;
        ++g_frames;
    }

    bool Engine::FrameStats(EngineFrameStats* out)
    {
        if (!out || !g_frames) return false;
        out->work_ms = g_workMs;
        out->sleep_ms = g_sleepMs;
        out->total_ms = g_totalMs;
        out->load_pct = g_loadPct;
        out->avg_work_ms = g_avgWork;
        out->avg_total_ms = g_avgTotal;
        out->frames = g_frames;
        return true;
    }

    void Engine::ReportFrameProfile()
    {
        EngineFrameStats s;
        if (!Engine::FrameStats(&s)) {
            Log::Str("_no engine frame samples (Host_RunFrame not hooked)._\n");
            return;
        }
        Log::Str("**Last Frame**\n");
        Log::F("- **work** : %.3f ms\n", s.work_ms);
        Log::F("- **sleep** : %.3f ms\n", s.sleep_ms);
        Log::F("- **total** : %.3f ms\n", s.total_ms);
        Log::F("- **load** : %.1f%%\n", s.load_pct);
        Log::Str("\n**Rolling Average**\n");
        Log::F("- **work** : %.3f ms\n", s.avg_work_ms);
        Log::F("- **total** : %.3f ms\n", s.avg_total_ms);
        Log::F("- **fps** : ~%.1f\n", s.avg_total_ms > 0 ? 1000.0 / s.avg_total_ms : 0.0);
        Log::F("- **frames sampled** : %llu\n", (unsigned long long)s.frames);
    }

    // --- loading state ---

    #if defined(CC_WINDOWS)
        enum { SIGNON_NONE = 0, SIGNON_FULL = 6 };
        #if defined(CC_X64)
            static const int kSignonOff = 0x15C;
            typedef char (*Fn_setsignon)(void* self, int64_t state, uint32_t spawn);
        #else
            static const int kSignonOff = 0x13C;
            typedef char (__fastcall *Fn_setsignon)(void* self, void* edx, int state, int spawn);
        #endif
        static Fn_setsignon o_setsignon = 0;
        static void* g_setsignonTarget = 0;
        static bool g_signonHooked = false;
        static volatile int g_signonState = -1; // -1 = no transition seen yet

        static void NoteSignon(void* self)
        {
            uintptr_t p = (uintptr_t)self + kSignonOff;
            if (self && Mem::IsReadable((void*)p, sizeof(int))) {
                int s = *(int*)p;
                if (s >= 0 && s <= 7) g_signonState = s;
            }
        }

        #if defined(CC_X64)
            static char h_setsignon(void* self, int64_t state, uint32_t spawn)
            {
                char r = o_setsignon(self, state, spawn);
                NoteSignon(self);
                return r;
            }
        #else
            static char __fastcall h_setsignon(void* self, void* edx, int state, int spawn)
            {
                char r = o_setsignon(self, edx, state, spawn);
                NoteSignon(self);
                return r;
            }
        #endif
    #endif

    int Engine::IsLoading()
    {
        #if defined(CC_WINDOWS)
            if (g_signonHooked) {
                int s = g_signonState;
                if (s >= 0 && s != SIGNON_NONE && s != SIGNON_FULL) return 1;
            }
        #endif
        uintptr_t a = Sig::Get("engine.loading_byte");
        if (a && Mem::IsReadable((void*)a, 1))
            return *(volatile unsigned char*)a ? 1 : 0;
        #if defined(CC_WINDOWS)
            if (g_signonHooked) return 0;
        #endif
        return -1;
    }

    // --- install / uninstall ---

    bool Engine::InstallHooks()
    {
        bool any = false;
        if (Cfg().engine_error && !g_sysErrHooked) {
            uintptr_t a = Sig::Get("engine.sys_error");
            bool ok = a && Hook::Install((void*)a, (void*)h_syserror, (void**)&o_syserror);
            if (ok) { g_sysErrorTarget = (void*)a; g_sysErrHooked = true; any = true; }
            Log::Debug("[CC-ENGINE] sys_error: sig=%p hooked=%d\n", (void*)a, (int)ok);
        }
        if (Cfg().frame_profile && !g_frameHooked) {
            uintptr_t a = Sig::Get("engine.host_runframe");
            bool ok = a && Hook::Install((void*)a, (void*)h_hostframe, (void**)&o_hostframe);
            if (ok) { g_hostFrameTarget = (void*)a; g_frameHooked = true; any = true; }
            Log::Debug("[CC-ENGINE] host_runframe: sig=%p hooked=%d\n", (void*)a, (int)ok);
        }
        #if defined(CC_WINDOWS) && !defined(INTERFACE_PLUGIN)
            if (!g_signonHooked) {
                uintptr_t a = Sig::Get("client.setsignon");
                bool ok = a && Hook::Install((void*)a, (void*)h_setsignon, (void**)&o_setsignon);
                if (ok) { g_setsignonTarget = (void*)a; g_signonHooked = true; any = true; }
                Log::Debug("[CC-ENGINE] setsignon: sig=%p hooked=%d\n", (void*)a, (int)ok);
            }
        #endif
        return any;
    }

    void Engine::Uninstall()
    {
        if (g_sysErrHooked && g_sysErrorTarget) Hook::Uninstall(g_sysErrorTarget);
        if (g_frameHooked && g_hostFrameTarget) Hook::Uninstall(g_hostFrameTarget);
        #if defined(CC_WINDOWS)
            if (g_signonHooked && g_setsignonTarget) Hook::Uninstall(g_setsignonTarget);
            o_setsignon = 0; g_setsignonTarget = 0; g_signonHooked = false;
        #endif
        o_syserror = 0; o_hostframe = 0;
        g_sysErrorTarget = 0; g_hostFrameTarget = 0;
        g_sysErrHooked = false; g_frameHooked = false;
    }
}
