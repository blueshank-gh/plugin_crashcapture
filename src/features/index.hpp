// features/index.hpp - one include to register and drive every optional feature.

#pragma once
#include "crashcapture.h"
#include "tools/cc_signature.h"
#include "features/cc_physrecover.h"
#include "features/cc_engine.h"

namespace CrashCapture {
    namespace Features {
        inline void Init()
        {
            #if defined(CC_LINUX)
                Phys::Recover::Init();
                Phys::Bind::Init();
            #endif
            Engine::Init();
            Sig::Init();
            Engine::InstallHooks();
        }

        inline void Shutdown()
        {
            Engine::Uninstall();
            #if defined(CC_LINUX)
                Phys::Bind::Uninstall();
            #endif
        }
    }
}
