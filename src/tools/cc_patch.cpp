// cc_patch - see cc_patch.h.

#include "tools/cc_patch.h"
#include "tools/cc_hooking.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(CC_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <windows.h>
#endif

namespace CrashCapture {
    const char* PatchStateName(CCPatchState state)
    {
        switch (state) {
            case CC_PATCH_APPLIED: return "applied";
            case CC_PATCH_DISABLED: return "disabled";
            case CC_PATCH_UNRESOLVED: return "unresolved";
            case CC_PATCH_DRIFTED: return "drifted";
            case CC_PATCH_FAILED: return "failed";
            case CC_PATCH_UNSUPPORTED: return "unsupported";
        }
        return "unknown";
    }

    const char* PatchToggleName(CCPatchToggle result)
    {
        switch (result) {
            case CC_TOGGLE_UNKNOWN: return "unknown";
            case CC_TOGGLE_BLOCKED: return "blocked";
            case CC_TOGGLE_QUEUED: return "queued";
            case CC_TOGGLE_RESTART: return "restart";
        }
        return "unknown";
    }

    #if defined(INTERFACE_PLUGIN)

    static const int kMaxPatches = 32;
    static const int kMaxQueue = kMaxPatches;
    static const char* kStateFileName = "patches.txt";

    struct PatchRec {
        CCPatchState  state;
        uintptr_t addr;
        bool enabled;
        int override; // -1 not set, 0 off, 1 on
        bool retry_module; // unresolved because the module was absent; retry when it maps
        unsigned char orig[24];
    };

    struct PatchQueueEntry { const char* id; bool on; };

    static const CCPatch* g_patches[kMaxPatches];
    static PatchRec g_recs[kMaxPatches];
    static int g_nPatches = 0;
    static bool g_inited = false;

    static PatchQueueEntry g_queue[kMaxQueue];
    static int g_nQueue = 0;

    static int FindIndex(const char* id);

    void Patch::Register(const CCPatch* patches, int count)
    {
        for (int i = 0; i < count && g_nPatches < kMaxPatches; ++i) {
            const CCPatch* p = &patches[i];
            if (!p->id || !p->id[0]) continue;
            if (FindIndex(p->id) >= 0) {
                Log::Debug("[CC-PATCH] duplicate id '%s' ignored\n", p->id);
                continue;
            }
            g_patches[g_nPatches] = p;
            PatchRec* r = &g_recs[g_nPatches];
            r->state = CC_PATCH_DISABLED;
            r->addr = 0;
            r->enabled = false;
            r->override = -1;
            r->retry_module = false;
            ++g_nPatches;
        }
    }

    static int FindIndex(const char* id)
    {
        if (!id) return -1;
        for (int i = 0; i < g_nPatches; ++i)
            if (strcmp(g_patches[i]->id, id) == 0) return i;
        return -1;
    }

    static bool MaskedMatch(const unsigned char* at, const CCPatch* p)
    {
        for (int i = 0; i < p->len; ++i)
            if (p->mask[i] && at[i] != p->expect[i]) return false;
        return true;
    }

    static bool UnlockSite(const CCPatch* p, uintptr_t addr)
    {
        return Mem::Protect((void*)addr, (size_t)p->len, true, p->kind != CC_PATCH_DATA);
    }

    static void RelockSite(const CCPatch* p, uintptr_t addr)
    {
        // a data page is writable in its normal state; re-locking one faults the engine's own writes.
        if (p->kind == CC_PATCH_DATA) return;
        Mem::Protect((void*)addr, (size_t)p->len, false, true);
    }

    static void WriteSite(const CCPatch* p, uintptr_t addr)
    {
        if (!p->keep_wildcards) {
            memcpy((void*)addr, p->bytes, (size_t)p->len);
            return;
        }
        unsigned char* dst = (unsigned char*)addr;
        for (int i = 0; i < p->len; ++i)
            if (p->mask[i]) dst[i] = p->bytes[i];
    }

    // a site whose module has not mapped yet is retried at the frame boundary.
    // a module that is present but unmatched stays unresolved (drifted codegen).
    static CCPatchState MarkUnresolved(const CCPatch* p, PatchRec* r)
    {
        r->retry_module = p->site.module && !Modules::FindByName(p->site.module);
        return CC_PATCH_UNRESOLVED;
    }

    static CCPatchState ApplyDetour(const CCPatch* p, PatchRec* r)
    {
        if (p->len <= 0 || p->len > (int)sizeof(p->expect)) return CC_PATCH_FAILED;
        uintptr_t base = Sig::Resolve(&p->site);
        if (!base) return MarkUnresolved(p, r);
        if (!Mem::IsReadable((void*)base, (size_t)p->len)) return CC_PATCH_UNRESOLVED;
        if (!MaskedMatch((const unsigned char*)base, p)) return CC_PATCH_DRIFTED;
        if (!p->detour || !p->trampoline) return CC_PATCH_FAILED;
        if (Hook::Install((void*)base, p->detour, p->trampoline)) {
            r->addr = base;
            r->retry_module = false;
            return CC_PATCH_APPLIED;
        }
        return CC_PATCH_FAILED;
    }

    static CCPatchState ApplyOne(const CCPatch* p, PatchRec* r)
    {
        if (p->kind == CC_PATCH_DETOUR) return ApplyDetour(p, r);
        if (p->kind != CC_PATCH_BYTES && p->kind != CC_PATCH_DATA) {
            Log::Debug("[CC-PATCH] %s: kind %d not supported yet\n", p->id, (int)p->kind);
            return CC_PATCH_UNSUPPORTED;
        }
        if (p->len <= 0 || p->len > (int)sizeof(p->expect)) return CC_PATCH_FAILED;

        uintptr_t addr = r->addr;
        if (!addr) {
            uintptr_t base = Sig::Resolve(&p->site);
            if (!base) return MarkUnresolved(p, r);
            addr = base + (uintptr_t)p->offset;
            r->addr = addr;
        }
        if (!Mem::IsReadable((void*)addr, (size_t)p->len)) return CC_PATCH_UNRESOLVED;
        if (!MaskedMatch((const unsigned char*)addr, p)) return CC_PATCH_DRIFTED;
        if (!UnlockSite(p, addr)) return CC_PATCH_FAILED;
        if (r->state != CC_PATCH_APPLIED)
            memcpy(r->orig, (void*)addr, (size_t)p->len);
        WriteSite(p, addr);
        RelockSite(p, addr);
        return CC_PATCH_APPLIED;
    }

    static void RevertOne(const CCPatch* p, PatchRec* r)
    {
        if (r->state != CC_PATCH_APPLIED || !r->addr) return;
        if (p->kind == CC_PATCH_DETOUR) {
            Hook::Uninstall((void*)r->addr);
        } else if (UnlockSite(p, r->addr)) {
            memcpy((void*)r->addr, r->orig, (size_t)p->len);
            RelockSite(p, r->addr);
        }
        r->state = CC_PATCH_DISABLED;
        r->enabled = false;
    }

    static bool EffectiveEnabled(const CCPatch* p, PatchRec* r)
    {
        if (!Cfg().patches) return false; // CRASHCAPTURE_PATCHES=0 panic switch
        if (r->override >= 0) return r->override != 0;
        return p->default_on;
    }

    void Patch::LoadStateFile()
    {
        char path[600];
        snprintf(path, sizeof(path), "%s/%s", Cfg().dir, kStateFileName);
        FILE* f = fopen(path, "r");
        if (!f) return;

        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char* p = line;
            while (*p == ' ' || *p == '\t') ++p;
            if (*p == '#' || *p == '\n' || !*p) continue;
            char* eq = strchr(p, '=');
            if (!eq) continue;
            char* idEnd = eq;
            while (idEnd > p && (idEnd[-1] == ' ' || idEnd[-1] == '\t')) --idEnd;
            int idLen = (int)(idEnd - p);
            if (idLen <= 0 || idLen >= 96) continue;
            int on = atoi(eq + 1) != 0;
            for (int i = 0; i < g_nPatches; ++i) {
                if ((int)strlen(g_patches[i]->id) == idLen &&
                    memcmp(g_patches[i]->id, p, (size_t)idLen) == 0) {
                    g_recs[i].override = on ? 1 : 0;
                    break;
                }
            }
        }
        fclose(f);
    }

    bool Patch::WriteStateFile()
    {
        char path[600];
        char tmp[600];
        snprintf(path, sizeof(path), "%s/%s", Cfg().dir, kStateFileName);
        snprintf(tmp, sizeof(tmp), "%s/%s.tmp", Cfg().dir, kStateFileName);

        FILE* f = fopen(tmp, "w");
        if (!f) return false;
        for (int i = 0; i < g_nPatches; ++i)
            if (g_recs[i].override >= 0)
                fprintf(f, "%s = %d\n", g_patches[i]->id, g_recs[i].override);
        bool ok = fclose(f) == 0;
        if (ok) {
        #if defined(CC_WINDOWS)
            ok = MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING) != 0;
        #else
            ok = rename(tmp, path) == 0;
        #endif
        }
        if (!ok) remove(tmp);
        return ok;
    }

    void Patch::Init()
    {
        if (g_inited) return;
        g_inited = true;

        Patch::LoadStateFile();

        for (int i = 0; i < g_nPatches; ++i) {
            const CCPatch* p = g_patches[i];
            PatchRec* r = &g_recs[i];
            r->enabled = EffectiveEnabled(p, r);
            if (!r->enabled) { r->state = CC_PATCH_DISABLED; continue; }
            r->state = ApplyOne(p, r);
        }

        for (int i = 0; i < g_nPatches; ++i)
            if (g_recs[i].enabled)
                Log::Debug("[CC-PATCH] enabled: %s (%s)\n",
                           g_patches[i]->id, PatchStateName(g_recs[i].state));

        for (int i = 0; i < g_nPatches; ++i)
            if (g_recs[i].state == CC_PATCH_DRIFTED)
                Log::Notice("[Crash Capture] patch %s no longer applies (site changed) - "
                            "possibly fixed upstream, see %s\n",
                            g_patches[i]->id,
                            g_patches[i]->upstream ? g_patches[i]->upstream : "?");
    }

    void Patch::Shutdown()
    {
        for (int i = 0; i < g_nPatches; ++i) {
            RevertOne(g_patches[i], &g_recs[i]);
            g_recs[i].addr = 0;
        }
        g_nQueue = 0;
        g_inited = false;
    }

    CCPatchToggle Patch::Queue(const char* id, bool on, bool* persisted)
    {
        if (persisted) *persisted = false;
        int idx = FindIndex(id);
        if (idx < 0) return CC_TOGGLE_UNKNOWN;
        if (!Cfg().patches) return CC_TOGGLE_BLOCKED;

        const CCPatch* p = g_patches[idx];
        g_recs[idx].override = on ? 1 : 0;

        bool ok = Patch::WriteStateFile();
        if (persisted) *persisted = ok;
        if (!ok)
            Log::Notice("[Crash Capture] patch %s: could not persist state to %s/%s "
                        "(toggle applies this session only)\n",
                        p->id, Cfg().dir, kStateFileName);

        // writing a live site that another thread may be executing tears the instruction stream.
        if (!p->hot_safe) return CC_TOGGLE_RESTART;

        for (int i = 0; i < g_nQueue; ++i)
            if (g_queue[i].id == p->id) { g_queue[i].on = on; return CC_TOGGLE_QUEUED; }
        if (g_nQueue >= kMaxQueue) return CC_TOGGLE_RESTART;

        g_queue[g_nQueue].id = p->id;
        g_queue[g_nQueue].on = on;
        ++g_nQueue;
        return CC_TOGGLE_QUEUED;
    }

    void Patch::DrainQueue()
    {
        for (int i = 0; i < g_nQueue; ++i) {
            int idx = FindIndex(g_queue[i].id);
            if (idx < 0) continue;
            const CCPatch* p = g_patches[idx];
            PatchRec* r = &g_recs[idx];
            if (g_queue[i].on) {
                if (r->state == CC_PATCH_APPLIED) continue;
                r->enabled = true;
                r->state = ApplyOne(p, r);
                if (r->state == CC_PATCH_APPLIED)
                    Log::F("[Crash Capture] patch %s applied\n", p->id);
                else
                    Log::Debug("[CC-PATCH] %s enable failed: %s\n", p->id, PatchStateName(r->state));
            } else {
                CCPatchState prev = r->state;
                RevertOne(p, r);
                r->enabled = false;
                r->state = CC_PATCH_DISABLED;
                if (prev == CC_PATCH_APPLIED)
                    Log::F("[Crash Capture] patch %s reverted\n", p->id);
                else
                    Log::Debug("[CC-PATCH] %s disabled (was %s)\n", p->id, PatchStateName(prev));
            }
        }
        g_nQueue = 0;

        // a site whose module was absent at Init maps in later (vphysics can load after the server plugin's Load)
        for (int i = 0; i < g_nPatches; ++i) {
            PatchRec* r = &g_recs[i];
            if (!r->enabled || r->state != CC_PATCH_UNRESOLVED || !r->retry_module) continue;
            const CCPatch* p = g_patches[i];
            if (p->site.module && !Modules::FindByName(p->site.module)) continue;
            r->retry_module = false;
            CCPatchState s = ApplyOne(p, r);
            if (s == CC_PATCH_APPLIED)
                Log::F("[Crash Capture] patch %s applied\n", p->id);
            else
                Log::Debug("[CC-PATCH] %s still %s\n", p->id, PatchStateName(s));
        }
    }

    int Patch::Count() { return g_nPatches; }

    bool Patch::GetInfo(int index, CCPatchInfo* out)
    {
        if (index < 0 || index >= g_nPatches || !out) return false;
        const CCPatch* p = g_patches[index];
        const PatchRec* r = &g_recs[index];
        out->id = p->id;
        out->upstream = p->upstream;
        out->state = r->state;
        out->enabled = r->enabled;
        out->addr = r->addr;
        return true;
    }

    bool Patch::Enabled(const char* id)
    {
        if (!id) return false;
        for (int i = 0; i < g_nPatches; ++i)
            if (strcmp(g_patches[i]->id, id) == 0)
                return g_recs[i].enabled && g_recs[i].state == CC_PATCH_APPLIED;
        return false;
    }

    void Patch::ReportHeader()
    {
        if (!g_nPatches) return;
        int applied = 0, drifted = 0, failed = 0, unresolved = 0, unsupported = 0;
        for (int i = 0; i < g_nPatches; ++i) {
            switch (g_recs[i].state) {
                case CC_PATCH_APPLIED:     ++applied; break;
                case CC_PATCH_DRIFTED:     ++drifted; break;
                case CC_PATCH_FAILED:      ++failed; break;
                case CC_PATCH_UNRESOLVED:  ++unresolved; break;
                case CC_PATCH_UNSUPPORTED: ++unsupported; break;
                default: break;
            }
        }
        Log::F("- **patches** : %d applied, %d drifted", applied, drifted);
        if (unresolved) Log::F(", %d unresolved", unresolved);
        if (failed) Log::F(", %d failed", failed);
        if (unsupported) Log::F(", %d unsupported", unsupported);
        Log::Str("\n");
    }

    static void Sec_PatchList(void*)
    {
        for (int i = 0; i < g_nPatches; ++i) {
            const CCPatch* p = g_patches[i];
            const PatchRec* r = &g_recs[i];
            Log::F("- **%s** : %s", p->id, PatchStateName(r->state));
            if (r->addr) {
                char at[512];
                FormatAddress(r->addr, at, sizeof(at));
                Log::F(" @ `%s`", at);
            }
            if (p->upstream && p->upstream[0]) Log::F(" - %s", p->upstream);
            if (p->note && p->note[0]) Log::F(" (%s)", p->note);
            Log::Str("\n");
        }
    }

    void Patch::ReportSection(void*)
    {
        if (!g_nPatches) return;
        Sec_PatchList(NULL);
    }

    #else
        void Patch::Register(const CCPatch*, int) {}
        void Patch::Init() {}
        void Patch::Shutdown() {}
        void Patch::DrainQueue() {}
        CCPatchToggle Patch::Queue(const char*, bool, bool* persisted) { if (persisted) *persisted = false; return CC_TOGGLE_UNKNOWN; }
        int Patch::Count() { return 0; }
        bool Patch::GetInfo(int, CCPatchInfo*) { return false; }
        bool Patch::Enabled(const char*) { return false; }
        void Patch::ReportHeader() {}
        void Patch::ReportSection(void*) {}
        void Patch::LoadStateFile() {}
        bool Patch::WriteStateFile() { return false; }
    #endif
}
