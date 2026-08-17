// cc_patch - compiled-in engine patch registry with byte-verify + drift tracking.
// see docs/patcher-design.md for the design.

#pragma once
#include "crashcapture.h"
#include "tools/cc_signature.h"

namespace CrashCapture {
    enum CCPatchKind {
        CC_PATCH_BYTES = 0,
        CC_PATCH_DATA,
        CC_PATCH_DETOUR,
        CC_PATCH_VFUNC,
    };

    enum CCPatchState {
        CC_PATCH_DISABLED = 0, // off via config/state file/default_on, or reverted
        CC_PATCH_UNRESOLVED, // site signature/symbol found nothing
        CC_PATCH_DRIFTED, // site found, expected bytes differ (probably fixed upstream)
        CC_PATCH_FAILED, // mprotect or the write was refused
        CC_PATCH_UNSUPPORTED, // kind not implemented in this build
        CC_PATCH_APPLIED, // resolved, verified, written
    };

    // result of a runtime toggle request
    enum CCPatchToggle {
        CC_TOGGLE_UNKNOWN = 0, // no patch with that id
        CC_TOGGLE_BLOCKED, // CRASHCAPTURE_PATCHES=0
        CC_TOGGLE_QUEUED, // applies at the next frame boundary
        CC_TOGGLE_RESTART, // recorded, but this patch is not safe to write live
    };

    const char* PatchStateName(CCPatchState state);
    const char* PatchToggleName(CCPatchToggle result);

    struct CCPatch {
        const char* id; // stable, namespaced: "gm.phys.mindist_reschedule"
        const char* upstream; // tracking link for when this gets fixed upstream
        const char* note;
        CCPatchKind kind;
        CCTarget site; // symbol-first, IDA pattern fallback, resolve steps
        int offset; // site + offset = the patched window
        unsigned char expect[24];
        unsigned char mask[24]; // 1 = must match expect, 0 = wildcard
        unsigned char bytes[24]; // the replacement bytes
        int len;
        void* detour; // PATCH_DETOUR: C++ handler
        void** trampoline;// PATCH_DETOUR: original-address out
        bool default_on;
        bool hot_safe; // site is unreachable from the non-game threads, so a live toggle cannot tear it
        bool keep_wildcards; // leave mask==0 positions holding their original byte
    };

    struct CCPatchInfo {
        const char*   id;
        const char*   upstream;
        CCPatchState  state;
        bool          enabled;
        uintptr_t     addr;
    };

    namespace Patch {
        void Register(const CCPatch* patches, int count);
        void Init();
        void Shutdown();
        void DrainQueue();
        CCPatchToggle Queue(const char* id, bool on, bool* persisted);
        int Count();
        bool GetInfo(int index, CCPatchInfo* out);
        bool Enabled(const char* id);
        void ReportHeader();
        void ReportSection(void*);
        void LoadStateFile();
        bool WriteStateFile();
    }
}
