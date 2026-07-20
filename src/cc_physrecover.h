// cc_physrecover - targeted physics hang/fault recovery.
// Linux only, i am not doing windows.

#pragma once
#include "crashcapture.h"

namespace CrashCapture {
    void PhysRecover_Init();
    bool PhysRecover_Available();

    // pause physics + resume the game thread out of the faulting tick.
    bool PhysRecover_ResumeFromFault(int sig, void* ucontext);

    // mark an offender, set event_manager->mode=1 so the drain loop exits, and pause physics.
    enum { PHYS_NORESUME = 0, PHYS_RESUMED = 1, PHYS_DEFERRED = 2 };
    int PhysRecover_ResumeFromHang(void* ucontext, bool forceResume);

    bool PhysRecover_MarkOffender(uintptr_t spLo, uintptr_t spHi);
    int PhysRecover_PendingCount();
    int PhysRecover_FreezeQueued();
    void PhysRecover_PollGameThread();
    int PhysRecover_FrozenEntities(int* out, int max);
    void PhysRecover_Reset();
    void PhysRecover_NoteHookLag(uintptr_t mindist);
}
