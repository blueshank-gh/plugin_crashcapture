// cc_engine - hook engine internals: fatal path (Sys_Error) + per-frame work/sleep timing.

#pragma once
#include "crashcapture.h"

namespace CrashCapture {
    struct EngineFrameStats {
        double work_ms, sleep_ms, total_ms, load_pct;
        double avg_work_ms, avg_total_ms;
        double phys_ms, avg_phys_ms;
        uint64_t frames;
        uint64_t phys_ticks;
        uint64_t phys_calls;
        int phys_paused;
    };

    namespace Engine {
        void Init();
        bool InstallHooks();
        void Uninstall();
        bool FrameStats(EngineFrameStats* out);
        void ReportFrameProfile();
        int IsLoading();
    }
}
