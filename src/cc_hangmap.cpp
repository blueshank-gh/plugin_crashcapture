// cc_hangmap - burst-interrupt sampling of a stuck thread.

#include "crashcapture.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

namespace CrashCapture {
    static const int kMaxSamples = 64;
    static const int kMaxFrames = 12;

    struct HangSample {
        uintptr_t pc;
        uintptr_t frames[kMaxFrames];
        int nframes;
        uint32_t ms;
    };
    static HangSample g_map[kMaxSamples];
    static volatile int g_mapCount = 0;
    static volatile uint64_t g_mapStartMs = 0;

    // the crashcapture module itself, so we can skip our own frames.
    static const CCModule* g_selfMod = NULL;
    static void ResolveSelf()
    {
        if (g_selfMod) return;
        g_selfMod = Modules::Find((uintptr_t)(void*)&HangMap::Capture);
    }

    static bool IsSelf(uintptr_t a)
    {
        ResolveSelf();
        return g_selfMod && Modules::Find(a) == g_selfMod;
    }

    void HangMap::Reset()
    {
        g_mapCount = 0;
        g_mapStartMs = MonotonicMs();
        ResolveSelf();
    }

    void HangMap::Capture(uintptr_t pc, const uintptr_t* frames, int nframes)
    {
        int n = g_mapCount;
        if (n >= kMaxSamples) return;
        HangSample& s = g_map[n];
        s.pc = pc;
        s.nframes = nframes > kMaxFrames ? kMaxFrames : nframes;
        for (int i = 0; i < s.nframes; ++i)
            s.frames[i] = frames ? frames[i] : 0;
        s.ms = (uint32_t)(MonotonicMs() - g_mapStartMs);
        ++g_mapCount;
    }

    int HangMap::Count() { return g_mapCount; }

    // resolve one probe to the code site it actually represents
    static uintptr_t SiteOf(const HangSample& s)
    {
        int i = 0;
        while (i < s.nframes && IsSelf(s.frames[i])) ++i;
        #if defined(CC_LINUX)
            if (i + 1 < s.nframes) {
                const CCModule* m0 = Modules::Find(s.frames[i]);
                if (!m0 || strcmp(m0->name, "[anon-exec]") == 0) ++i;
            }
        #endif
        for (; i < s.nframes; ++i) {
            uintptr_t a = s.frames[i];
            if (!a || IsSelf(a)) continue;
            return a;
        }
        return IsSelf(s.pc) ? 0 : s.pc;
    }

    // ---- report section ---

    struct MapSite { uintptr_t pc; int hits; };
    static int SiteCmpDesc(const void* a, const void* b)
    {
        const MapSite* sa = (const MapSite*)a;
        const MapSite* sb = (const MapSite*)b;
        if (sb->hits != sa->hits) return sb->hits - sa->hits;
        return sa->pc < sb->pc ? -1 : (sa->pc > sb->pc ? 1 : 0);
    }

    void HangMap::Section(void*)
    {
        int n = g_mapCount;
        if (n <= 0) { Log::Str("  <no probes captured>\n"); return; }

        uintptr_t sites[kMaxSamples];
        int nsites = 0;
        int mapped = 0;

        for (int i = 0; i < n; ++i) {
            uintptr_t site = SiteOf(g_map[i]);
            if (site == 0) site = g_map[i].pc;
            if (site != g_map[i].pc) ++mapped;
            int j = 0;
            for (; j < nsites; ++j) if (sites[j] == site) break;
            if (j < nsites) continue;
            if (nsites < kMaxSamples) sites[nsites++] = site;
        }

        MapSite heat[kMaxSamples];
        int nhit = 0;
        for (int i = 0; i < n; ++i) {
            uintptr_t site = SiteOf(g_map[i]);
            if (site == 0) site = g_map[i].pc;
            int j = 0;
            for (; j < nhit; ++j) if (heat[j].pc == site) break;
            if (j < nhit) { ++heat[j].hits; continue; }
            if (nhit < kMaxSamples) { heat[nhit].pc = site; heat[nhit].hits = 1; ++nhit; }
        }
        qsort(heat, (size_t)nhit, sizeof(MapSite), SiteCmpDesc);

        uint32_t window = g_map[n - 1].ms;
        Log::F("  %d probe(s) over %u ms (interval %d ms)\n", n, window, Cfg().hang_map_interval_ms);
        Log::F("  %d distinct site(s)\n", nsites);
        if (mapped)
            Log::F("  > %d probe(s) landed in crashcapture's own detour code and were resolved to their caller\n", mapped);

        if (nhit == 1) {
            Log::Str("  > tight loop: all probes landed on a single site\n");
        } else if (heat[0].hits * 2 >= n) {
            Log::F("  > %d/%d probes on one site, likely a tight loop with periodic escape\n", heat[0].hits, n);
        } else {
            Log::Str("  > execution is cycling across multiple sites\n");
        }

        Log::Str("\n  site heat (most-hit first):\n");
        for (int i = 0; i < nhit; ++i) {
            char buf[512];
            FormatAddress(heat[i].pc, buf, sizeof(buf));
            Log::F("  %3dx  %s\n", heat[i].hits, buf);
        }

        Log::Str("\n  probe timeline:\n");
        for (int i = 0; i < n; ++i) {
            uintptr_t site = SiteOf(g_map[i]);
            if (site == 0) site = g_map[i].pc;
            char buf[512];
            FormatAddress(site, buf, sizeof(buf));
            Log::F("  #%-2d +%-4u ms  %s\n", i, g_map[i].ms, buf);
        }
    }
}
