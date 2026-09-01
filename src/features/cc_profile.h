// cc_profile - name-attributed profiler for C->Lua transitions (gamemode hooks, timers, concommands).

#pragma once
#include "crashcapture.h"

namespace CrashCapture {
    enum ProfileKind { PROF_OTHER = 0, PROF_HOOK, PROF_TIMER, PROF_LUA, PROF_NET, PROF_CONCMD };

    struct ProfileBucket {
        char name[72];
        char source[160];
        int kind;
        uint64_t calls;
        uint64_t selfTicks;
        uint64_t totalTicks;
        uint64_t maxTicks;
        double selfMs;
        double totalMs;
        double maxMs;
        double p50Ms;
        double p99Ms;
    };

    struct ProfileView {
        int count;
        bool previous;
        double windowMs;
        uint64_t dropped;
        int buckets;
    };

    namespace Profile {
        void Init();
        bool Install();
        void Uninstall();
        void Poll();

        bool Enabled();
        void SetEnabled(bool on);
        void Reset();
        void Rotate();
        void FrameBoundary();

        bool HasSamples();
        ProfileView Snapshot(ProfileBucket* out, int max);
        double TicksToMs(uint64_t ticks);
        double WindowMs();
        uint64_t Dropped();
        int BucketCount();
        int BucketMax();

        const char* KindName(int kind);
        int Depth();
        const char* NameAt(int level);
        double ElapsedMsAt(int level);

        void ReportSection();
    }
}
