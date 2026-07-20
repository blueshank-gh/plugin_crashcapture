// cc_physhook - detour IVP's mindist pipeline to PREVENT physics hangs at their source.
// Linux x86 + x64. No windows.

#include "crashcapture.h"

#if defined(CC_LINUX)

#include "cc_hooking.h"
#include "cc_signature.h"
#include "cc_physrecover.h"
#include <time.h>
#include <stdint.h>

namespace CrashCapture {
    static const CCTarget kHookTargets[] = {
    #if defined(CC_X86)
        {"hook.update_exact", "vphysics", NULL,
            "55 66 0F EF C0 66 0F EF C9 89 E5 57 56 53 83 EC 6C 8B 5D 08 0F B6 43 15",
            {{CC_STEP_END, 0, 0}}},
        {"hook.do_impact", "vphysics", NULL,
            "55 89 E5 57 56 53 83 EC 28 8B 7D 08 8B 77 28 8B",
            {{CC_STEP_END, 0, 0}}},
        {"hook.simulate_time_events", "vphysics", NULL,
            "55 89 E5 57 56 53 83 EC 1C F2 0F 10 5D 14 8B 75",
            {{CC_STEP_END, 0, 0}}},
        {"hook.simulate_time_event", "vphysics", NULL,
            "55 89 E5 56 8B 75 0C 53 8B 5D 08 83 EC 08 8B 46",
            {{CC_STEP_END, 0, 0}}},
    #elif defined(CC_X64)
        {"hook.update_exact", "vphysics", NULL,
            "55 48 89 E5 41 56 41 55 41 54 53 48 89 FB 48 83 EC 20 44 0F B6 77",
            {{CC_STEP_END, 0, 0}}},
        {"hook.do_impact", "vphysics", NULL,
            "55 48 89 E5 41 56 41 55 49 89 FD 41 54 53 4C 8B 67",
            {{CC_STEP_END, 0, 0}}},
        {"hook.simulate_time_events", "vphysics", NULL,
            "55 48 89 E5 41 56 66 49 0F 7E C6",
            {{CC_STEP_END, 0, 0}}},
        {"hook.simulate_time_event", "vphysics", NULL,
            "55 48 89 E5 41 54 49 89 F4 53 48 89 FB 48 8B 7E",
            {{CC_STEP_END, 0, 0}}},
    #endif
    };

    void PhysHook_Init()
    {
        Sig_Register(kHookTargets, (int)(sizeof(kHookTargets) / sizeof(kHookTargets[0])));
    }

    // trampolines to the originals
    typedef void (*Fn_ste)(void*, void*, void*, double); // simulate_time_events(em,tm,env,time)
    typedef void (*Fn_ue)(void*, int, int); // update_exact_mindist_events(mindist,a2,a3)
    typedef void (*Fn_di)(void*); // do_impact(mindist)
    typedef void (*Fn_stev)(void*, void*); // simulate_time_event(mindist,env)
    static Fn_ste o_ste = 0;
    static Fn_ue o_ue = 0;
    static Fn_di o_di = 0;
    static Fn_stev o_stev = 0;

    static bool g_installed = false;

    static thread_local uint64_t g_tickStartNs = 0;
    static thread_local bool g_skip = false;
    static thread_local bool g_noted = false;

    static uint64_t g_lagEpisodes = 0; // diagnostics lifetime

    static inline uint64_t NowNs()
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    }
    static inline uint64_t ElapsedMs()
    {
        return g_tickStartNs ? (NowNs() - g_tickStartNs) / 1000000ull : 0;
    }
    static uint64_t ThresholdMs()
    {
        int ms = Cfg().phys_hook_ms;
        return ms > 0 ? (uint64_t)ms : 250;
    }

    // --- the detours, oh no ---

    // simulate_time_events: the outer boundary of a drain.
    static void h_ste(void* em, void* tm, void* env, double time)
    {
        g_tickStartNs = NowNs();
        g_skip = false;
        g_noted = false;
        o_ste(em, tm, env, time);
        g_skip = false;
    }

    // update_exact_mindist_events: the source of the painful runaway rescheduling.
    static void h_ue(void* mindist, int a2, int a3)
    {
        if (!g_skip && ElapsedMs() > ThresholdMs()) {
            g_skip = true;
            if (!g_noted) {
                g_noted = true;
                ++g_lagEpisodes;
                PhysRecover_NoteHookLag((uintptr_t)mindist); // -> offenders + one debounced report
            }
        }
        if (g_skip) return;
        o_ue(mindist, a2, a3);
    }

    // do_impact / simulate_time_event: while skipping, don't resolve/reschedule either, this will break vphysics into garbage states
    static void h_di(void* mindist)
    {
        if (g_skip) { PhysRecover_NoteHookLag((uintptr_t)mindist); return; }
        o_di(mindist);
    }
    static void h_stev(void* mindist, void* env)
    {
        if (g_skip) { PhysRecover_NoteHookLag((uintptr_t)mindist); return; }
        o_stev(mindist, env);
    }

    bool PhysHook_Install()
    {
        if (g_installed) return true;
        if (!Cfg().phys_hook) return false;

        uintptr_t a_ste = Sig_Get("hook.simulate_time_events");
        uintptr_t a_ue = Sig_Get("hook.update_exact");
        uintptr_t a_di = Sig_Get("hook.do_impact");
        uintptr_t a_stev = Sig_Get("hook.simulate_time_event");
        if (!a_ste || !a_ue) {
            return false; // this... shouldn't happen, vphysics didn't load yet.
        }

        bool okSte = Hook_Install((void*)a_ste, (void*)h_ste, (void**)&o_ste);
        bool okUe = Hook_Install((void*)a_ue, (void*)h_ue, (void**)&o_ue);
        if (!okSte || !okUe) {
            Log::F("[CrashCapture] phys hook: FAILED to install core hooks (ste=%d ue=%d) -- "
                   "removing any partial hooks.\n", (int)okSte, (int)okUe);
            Hook_RemoveAll();
            return false;
        }
        if (a_di) Hook_Install((void*)a_di, (void*)h_di, (void**)&o_di);
        if (a_stev) Hook_Install((void*)a_stev, (void*)h_stev, (void**)&o_stev);

        g_installed = true;
        return true;
    }

    void PhysHook_Uninstall()
    {
        if (!g_installed) return;
        Hook_RemoveAll();
        o_ste = 0; o_ue = 0; o_di = 0; o_stev = 0;
        g_installed = false;
        Log::Debug("[CC-HOOK] removed all IVP detours (%llu lag episode(s) this run).\n",
                    (unsigned long long)g_lagEpisodes);
    }

    uint64_t PhysHook_LagEpisodes() { return g_lagEpisodes; }
}

#else

namespace CrashCapture {
    void PhysHook_Init() {}
    bool PhysHook_Install() { return false; }
    void PhysHook_Uninstall() {}
    uint64_t PhysHook_LagEpisodes() { return 0; }
}

#endif
