// features/index.hpp - one include to register and drive every optional feature.

#pragma once
#include "crashcapture.h"
#include "tools/cc_signature.h"
#include "tools/cc_patch.h"
#include "features/cc_physrecover.h"
#include "features/cc_engine.h"
#include "features/cc_profile.h"

namespace CrashCapture {
    namespace Features {
        inline void Init()
        {
            #if defined(CC_LINUX)
                Phys::Recover::Init();
                Phys::Bind::Init();
            #endif
            Engine::Init();
            Profile::Init();
            Sig::Init();
            Patch::Init();
            Engine::InstallHooks();
        }

        inline void Shutdown()
        {
            Patch::Shutdown();
            Profile::Uninstall();
            Engine::Uninstall();
            #if defined(CC_LINUX)
                Phys::Bind::Uninstall();
            #endif
        }
    }
}
