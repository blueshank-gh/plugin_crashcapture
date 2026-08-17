// cc_physpatch - compiled-in physics patches for vphysics/IVP.
// Linux x86 + x64. No windows.

#pragma once
#include "crashcapture.h"

namespace CrashCapture {
    namespace Phys {
        namespace Patch {
            void Init();
            void RefreshToggles();
            void DeferEpsilonRefire(void* mindist, void* env);
        }
    }
}
