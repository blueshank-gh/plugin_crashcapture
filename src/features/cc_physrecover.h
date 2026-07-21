// cc_physrecover - targeted physics hang/fault recovery.
// Linux only, i am not doing windows.

#pragma once
#include "crashcapture.h"

namespace CrashCapture {
    enum { PHYS_NORESUME = 0, PHYS_RESUMED = 1, PHYS_DEFERRED = 2 };

    namespace Phys {
        namespace Recover {
            void Init();
            bool Available();

            // pause physics + resume the game thread out of the faulting tick.
            bool ResumeFromFault(int sig, void* ucontext);

            // mark an offender, set event_manager->mode=1 so the drain loop exits, and pause physics.
            int ResumeFromHang(void* ucontext, bool forceResume);

            bool MarkOffender(uintptr_t spLo, uintptr_t spHi);
            int PendingCount();
            int FreezeQueued();
            void PollGameThread();
            int FrozenEntities(int* out, int max);
            void Reset();
            void NoteHookLag(uintptr_t mindist);
        }
    }
}
