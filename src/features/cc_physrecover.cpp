// cc_physrecover - all physics crash/hang recovery.
// Linux only, no we are not doing windows.

#include "features/cc_physrecover.h"
#include "tools/cc_signature.h"

#if defined(CC_LINUX)

#include <string.h>
#include <stdio.h>
#include <ucontext.h>
#include <unwind.h>
#include <signal.h>
#include <stdint.h>

namespace CrashCapture {
    // --------- object model ---
    // data offsets for kIvpCore/kCore*
    #if defined(CC_X86)
        static const int kIvpToObj = 160; // IVP_Real_Object -> CPhysicsObject*
        static const int kMindistObj0 = 40, kMindistObj1 = 68; // IVP_Mindist -> two IVP_Real_Object*
        static const int kObjGameData = 4; // CPhysicsObject.m_pGameData (CBaseEntity*)
        static const int kObjIvp = 8; // CPhysicsObject.m_pObject   (IVP_Real_Object*)
        static const int kObjShadow = 0x10;// CPhysicsObject.m_pShadow (GetShadowController: *(this+0x10))
        static const int kEntHandle = 832; // CBaseEntity.m_RefEHandle
        static const int kIvpCore = 0x94; // IVP_Real_Object -> IVP_Core*
        static const int kCoreSpeed = 0x100; // IVP_Core.speed     {x,y,z} (0x10c skipped)
        static const int kCoreRotSpeed = 0x110; // IVP_Core.rot_speed {x,y,z}
        static const int kCoreSpeedChange = 0xe0; // {x,y,z} (0xec skipped)
        static const int kCoreRotChange = 0xf0; // {x,y,z} (0xfc skipped)
        static const int kCoreVec30 = 0x30; // 16B block set_pinned clears (movaps)
        static const int kEnvInSim = 121; // CPhysicsEnvironment.m_inSimulation (byte)
    #elif defined(CC_X64)
        static const int kIvpToObj = 256;
        static const int kMindistObj0 = 0x40, kMindistObj1 = 0x70; // per-synapse stride 48 (vs x86 28)
        static const int kObjGameData = 8;
        static const int kObjIvp = 16;
        static const int kObjShadow = 0x20;  // m_pShadow (raw member; getter returns +8)
        static const int kEntHandle = 1060;
        static const int kIvpCore = 0xE8;  // IVP_Real_Object -> IVP_Core*
        static const int kCoreSpeed = 0x100;
        static const int kCoreRotSpeed = 0xF0;
        static const int kCoreSpeedChange = 0xE0;
        static const int kCoreRotChange = 0xD0;
        static const int kCoreVec30 = 0x40; // inv_rot_inertia 16B block (name is the x86 offset)
        static const int kEnvInSim = 0x10D; // inert until phys.env_slot is registered for x64
    #endif
    static const unsigned char kCoreStatic = 0x02; // IVP_Core flags: already immovable
    static const unsigned char kCorePinned = 0x10; // IVP_Core flags: pinned (motion off)
    static const uint32_t kEntEntryMask    = 0xFFF; // Source ENT_ENTRY_MASK (confirm at test)

    // --------- cc_signature targets ---
    // phase-1 physics pause byte and phase-2 CPhysicsObject vptr
    // vptr = the value a live CPhysicsObject stores at *(obj)+0

    // PhysFrame's paused-byte guard is byte-identical on both arches:
    //   80 3D <disp/abs32> 00   cmpb $0,&g_PhysicsHook.m_bPaused
    //   0F B6 05 <disp/abs32>   movzbl <other flag>,eax
    //   0F 85 <rel32>           jne  <skip physics if paused>

    static const CCTarget kPhysTargets[] = {
    #if defined(CC_X86)
        {"phys.paused_byte", "server", NULL, "80 3D ?? ?? ?? ?? 00 0F B6 05 ?? ?? ?? ?? 0F 85",
            {{CC_STEP_ABS32, 2, 0}, {CC_STEP_END, 0, 0}}}, // &g_PhysicsHook.m_bPaused (== +91)
        {"phys.frame_code", "server", NULL, "80 3D ?? ?? ?? ?? 00 0F B6 05 ?? ?? ?? ?? 0F 85",
            {{CC_STEP_END, 0, 0}}}, // the guard instruction, i.e. a code addr inside PhysFrame
        {"physobj.vptr", "vphysics", "_ZTV14CPhysicsObject", NULL, {{CC_STEP_ADD, 8, 0}, {CC_STEP_END, 0, 0}}},
        {"phys.env_slot", "server", NULL, // &physenv (mov edx,physenv right after the guard)
            "80 3D ?? ?? ?? ?? 00 0F B6 05 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 85 D2",
            {{CC_STEP_ABS32, 22, 0}, {CC_STEP_END, 0, 0}}},
        {"phys.remove_sem", "server", NULL, // &s_RemoveImmediateSemaphore (via the call target)
            "80 3D ?? ?? ?? ?? 00 0F B6 05 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 85 D2 "
            "0F 84 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? F3 0F 11 45 D0 E8 ?? ?? ?? ??",
            {{CC_STEP_REL, 48, 52}, {CC_STEP_ABS32, 2, 0}, {CC_STEP_END, 0, 0}}},
        {"phys.minlist_add", "vphysics", NULL, // interior of IVP_U_Min_List::add
            "83 40 14 01 0F B7 40 02 66 83 F8 FF 0F 84 ?? ?? ?? ??",
            {{CC_STEP_END, 0, 0}}},
    #elif defined(CC_X64)
        {"phys.paused_byte", "server", NULL, "80 3D ?? ?? ?? ?? 00 0F B6 05 ?? ?? ?? ?? 0F 85",
            {{CC_STEP_REL, 2, 7}, {CC_STEP_END, 0, 0}}},
        {"phys.frame_code", "server", NULL, "80 3D ?? ?? ?? ?? 00 0F B6 05 ?? ?? ?? ?? 0F 85",
            {{CC_STEP_END, 0, 0}}}, // the guard instruction, i.e. a code addr inside PhysFrame
        {"physobj.vptr", "vphysics", NULL, "48 8D 05 ?? ?? ?? ?? 55 48 89 FA 48 8D 77 08 48 89 07",
            {{CC_STEP_REL, 3, 7}, {CC_STEP_END, 0, 0}}},
    #endif
    };

    void Phys::Recover::Init()
    {
        Sig::Register(kPhysTargets, (int)(sizeof(kPhysTargets) / sizeof(kPhysTargets[0])));
    }

    static uintptr_t Vptr() { return Sig::Get("physobj.vptr"); }

    bool Phys::Recover::Available() { return Vptr() != 0; }

    static void* PhysFrameStart(); // resolves server.so PhysFrame start
    static void RestorePhysEnvState(); // un-defers deletes after an abandoned Simulate

    // --------- phase 1: full physics pause ---
    // first line of defense is to just fully pause physics itself.

    static unsigned g_physResumeCount = 0;
    static bool g_pluginPaused = false; // physics paused by hang-recovery (auto-unpause), not the user
    static volatile bool g_modeForced = false; // we set event_manager->mode=1; PollGameThread resets it
    static volatile bool g_hookLagged = false; // cc_physhook flagged a runaway tick -> report offenders
    static const unsigned kMaxPhysResume = 100; // bail to a real crash if it keeps re-faulting

    static bool* PhysPausedSlot()
    {
        bool* m_bPaused = (bool*)Sig::Get("phys.paused_byte");
        return (m_bPaused && Mem::IsReadable(m_bPaused, sizeof(bool))) ? m_bPaused : NULL;
    }

    int Platform::SetPhysPaused(int paused)
    {
        bool* slot = PhysPausedSlot();
        if (!slot) return 0;
        *slot = paused != 0;
        return 1;
    }

    int Platform::PhysPaused()
    {
        bool* slot = PhysPausedSlot();
        return slot ? (*slot ? 1 : 0) : -1;
    }

    // &IVP_Event_Manager::mode drain loop (simulate_time_events)
    static int* EventLoopMode()
    {
    #if defined(CC_X86)
        uintptr_t slot = Sig::Get("phys.env_slot"); // &physenv
        if (!slot || !Mem::IsReadable((void*)slot, sizeof(void*))) return NULL;
        uintptr_t env = *(uintptr_t*)slot; // CPhysicsEnvironment*
        if (!env || !Mem::IsReadable((void*)(env + 4), sizeof(void*))) return NULL;
        uintptr_t ivpEnv = *(uintptr_t*)(env + 4); // IVP_Environment* CPhysEnv[1]
        if (!ivpEnv || !Mem::IsReadable((void*)(ivpEnv + 4), sizeof(void*))) return NULL;
        uintptr_t tmgr = *(uintptr_t*)(ivpEnv + 4); // IVP_Time_Manager* IVP_Env[1]
        if (!tmgr || !Mem::IsReadable((void*)(tmgr + 4), sizeof(void*))) return NULL;
        uintptr_t emgr = *(uintptr_t*)(tmgr + 4); // IVP_Event_Manager* time_mgr[1]
        if (!emgr || !Mem::IsReadable((void*)(emgr + 4), sizeof(int))) return NULL;
        return (int*)(emgr + 4); // &mode event_mgr[1]
    #else
        return NULL;
    #endif
    }

    // read IVP's time-event queue (min_hash = time_mgr+8) live load
    static bool MinListStats(uint32_t* countOut, uint32_t* capOut, uintptr_t* listOut)
    {
        #if defined(CC_X86)
            uintptr_t slot = Sig::Get("phys.env_slot");
            if (!slot || !Mem::IsReadable((void*)slot, 4)) return false;
            uintptr_t env = *(uintptr_t*)slot;
            if (!env || !Mem::IsReadable((void*)(env + 4), 4)) return false;
            uintptr_t ivpEnv = *(uintptr_t*)(env + 4);
            if (!ivpEnv || !Mem::IsReadable((void*)(ivpEnv + 4), 4)) return false;
            uintptr_t tmgr = *(uintptr_t*)(ivpEnv + 4);
            if (!tmgr || !Mem::IsReadable((void*)(tmgr + 8), 4)) return false;
            uintptr_t mh = *(uintptr_t*)(tmgr + 8);            // min_hash (the IVP_U_Min_List)
            if (!mh || !Mem::IsReadable((void*)mh, 24)) return false;
            if (countOut) *countOut = *(uint32_t*)(mh + 20);
            if (capOut)   *capOut   = *(uint16_t*)(mh + 0);
            if (listOut)  *listOut  = mh;
            return true;
        #else
            (void)countOut; (void)capOut; (void)listOut; return false;
        #endif
    }

    // exploding set IVP_Real_Object* pulled from the saturated queue's mindist
    static uintptr_t g_rawIvp[64]; static int g_nRawIvp = 0;
    static void RawIvpAdd(uintptr_t p)
    {
        if (!p || (p & (sizeof(void*) - 1))) return;
        if (g_nRawIvp >= (int)(sizeof(g_rawIvp) / sizeof(g_rawIvp[0]))) return;
        for (int i = 0; i < g_nRawIvp; ++i) if (g_rawIvp[i] == p) return;
        g_rawIvp[g_nRawIvp++] = p;
    }

    // cc_physhook bridge for mid-tick on the game thread when the hook skips a runaway mindist
    void Phys::Recover::NoteHookLag(uintptr_t mindist)
    {
        if (!mindist || (mindist & (sizeof(void*) - 1))) return;
        RawIvpAdd(*(uintptr_t*)(mindist + kMindistObj0));
        RawIvpAdd(*(uintptr_t*)(mindist + kMindistObj1));
        g_hookLagged = true;
    }

    // reset a saturated/corrupt IVP_U_Min_List back to empty, this causes garbage to hit the next tick.
    struct ResetArgs { uintptr_t mh; };
    static void ResetMinListInner(void* arg)
    {
        #if defined(CC_X86)
            uintptr_t mh = ((ResetArgs*)arg)->mh;
            if (!mh || !Mem::IsReadable((void*)mh, 24)) return;
            uint32_t cap = *(uint16_t*)(mh + 0); // malloced_size (capacity)
            uintptr_t elems = *(uintptr_t*)(mh + 4); // slot array
            uint32_t before = *(uint32_t*)(mh + 20); // live count (may exceed cap)
            if (!cap || !elems || !Mem::IsReadable((void*)elems, (size_t)cap * 16))
                return;

            // clear each in-use slot's mindist back-link
            int cleared = 0;
            for (uint32_t i = 0; i < cap; ++i) {
                uintptr_t mindist = *(uintptr_t*)(elems + (uintptr_t)i * 16 + 12);
                if (mindist && *(uint32_t*)(mindist + 4) == i) {
                    *(uint32_t*)(mindist + 4) = 0xFFFF; // "no time-event slot"
                    ++cleared;
                    RawIvpAdd(*(uintptr_t*)(mindist + kMindistObj0)); // collect the exploding objects
                    RawIvpAdd(*(uintptr_t*)(mindist + kMindistObj1));
                }
            }

            // empty every slot's links + rebuild the free-list
            for (uint32_t i = 0; i < cap; ++i) {
                *(uint16_t*)(elems + (uintptr_t)i * 16 + 0) = 0xFFFF;                                     // long_next
                *(uint16_t*)(elems + (uintptr_t)i * 16 + 4) = (i + 1 < cap) ? (uint16_t)(i + 1) : 0xFFFF; // free-next
            }
            *(uint16_t*)(mh + 2) = 0; // free_list head = slot 0
            *(uint32_t*)(mh + 8) = 0x501802B9; // min_value = empty sentinel (as remove sets it)
            *(uint32_t*)(mh + 12) = 0xFFFF; // first_long = none
            *(uint32_t*)(mh + 16) = 0xFFFF; // first_element = none
            *(uint32_t*)(mh + 20) = 0; // live count = 0
            Log::F("[Crash Capture] phys recover: reset saturated event queue "
                "(mh=0x%lx cap=%u, was count=%u, cleared %d mindist back-links).\n",
                (unsigned long)mh, cap, before, cleared);
        #else
            (void)arg;
        #endif
    }

    // --------- phase 2: targeted freeze ---
    static const int kMaxPhys = 32;
    static uintptr_t g_pending[kMaxPhys]; static int g_nPending = 0; // offender CPhysicsObject*
    static uintptr_t g_frozen[kMaxPhys];  static int g_nFrozen = 0;
    static int       g_frozenEnt[kMaxPhys]; static int g_nFrozenEnt = 0;

    // --------- non-convergence detection ---
    // pinning stops motion but not collision detection, so a pile can keep hanging...
    static const int kMaxRepins = 3;
    struct RepinEnt { int ent; int count; };
    static RepinEnt g_repin[kMaxPhys]; static int g_nRepin = 0;
    static bool g_giveUp = false;
    static int  g_giveUpEnt = -1;

    // rate-based backstop since frozen objects still generate collision events...
    static const uint64_t kRecWindowMs = 70000; // ~7 back-to-back 10s hangs
    static const int kRecWindowMax = 5;
    static uint64_t g_recWindowStart = 0;
    static int g_recWindowCount = 0;

    // count a pin of ent, returns true once it has repeated too often.
    static bool NoteRepin(int ent)
    {
        if (ent < 0) return false;
        for (int i = 0; i < g_nRepin; ++i) {
            if (g_repin[i].ent != ent) continue;
            if (++g_repin[i].count >= kMaxRepins) { g_giveUp = true; g_giveUpEnt = ent; }
            return g_giveUp;
        }
        if (g_nRepin < kMaxPhys) { g_repin[g_nRepin].ent = ent; g_repin[g_nRepin].count = 1; ++g_nRepin; }
        return false;
    }

    static bool PtrOk(uintptr_t p)
    {
        return p && !(p & (sizeof(void*) - 1)) && Mem::IsReadable((void*)p, sizeof(void*));
    }

    static uintptr_t AsPhysObject(uintptr_t p)
    {
        uintptr_t vptr = Vptr();
        if (!vptr || !PtrOk(p)) return 0;
        if (*(uintptr_t*)p == vptr) return p; // direct CPhysicsObject

        uintptr_t slot = p + kIvpToObj;
        if (!Mem::IsReadable((void*)slot, sizeof(void*))) return 0;
        uintptr_t obj = *(uintptr_t*)slot;
        if (!PtrOk(obj) || *(uintptr_t*)obj != vptr) return 0;
        uintptr_t back = obj + kObjIvp; // back-link must agree
        if (!Mem::IsReadable((void*)back, sizeof(void*)) || *(uintptr_t*)back != p) return 0;
        return obj;
    }

    static bool Known(uintptr_t obj)
    {
        for (int i = 0; i < g_nPending; ++i) if (g_pending[i] == obj) return true;
        for (int i = 0; i < g_nFrozen; ++i)  if (g_frozen[i] == obj) return true;
        return false;
    }

    // scan [spLo, spHi) for validated offenders and queue every new one (up to kMaxPhys).
    struct ScanArgs { uintptr_t lo, hi; int queued; };
    static void ScanForOffenders(void* arg)
    {
        ScanArgs* sa = (ScanArgs*)arg;
        uintptr_t a = sa->lo & ~(uintptr_t)(sizeof(void*) - 1);
        for (; a + sizeof(void*) <= sa->hi; a += sizeof(void*)) {
            if (!Mem::IsReadable((void*)a, sizeof(void*))) {
                a = (a & ~(uintptr_t)0xFFF) + 0x1000 - sizeof(void*); // skip to next page
                continue;
            }
            uintptr_t v = *(uintptr_t*)a;
            uintptr_t obj = AsPhysObject(v);
            if (!obj || Known(obj)) continue;
            if (g_nPending >= kMaxPhys) break;
            g_pending[g_nPending++] = obj;
            ++sa->queued;
        }
    }

    bool Phys::Recover::MarkOffender(uintptr_t spLo, uintptr_t spHi)
    {
        if (!Vptr()) return false;
        ScanArgs sa = {spLo, spHi, 0};
        RunProtectedQuiet(ScanForOffenders, &sa); // a bad deref must not kill the server
        return sa.queued > 0;
    }

    int Phys::Recover::PendingCount() { return g_nPending; }

    static int ObjEntIndex(uintptr_t obj)
    {
        uintptr_t gd = obj + kObjGameData;
        if (!Mem::IsReadable((void*)gd, sizeof(void*))) return -1;
        uintptr_t ent = *(uintptr_t*)gd;
        if (!ent) return -1;
        uintptr_t h = ent + kEntHandle;
        if (!Mem::IsReadable((void*)h, sizeof(uint32_t))) return -1;
        return (int)(*(uint32_t*)h & kEntEntryMask);
    }

    // shadow-controlled objects (players, NPCs, physgun-held props) should be ignored in processing
    static bool IsShadowControlled(uintptr_t obj)
    {
        if (!kObjShadow) return false;
        uintptr_t shSlot = obj + kObjShadow;
        if (!Mem::IsReadable((void*)shSlot, sizeof(void*))) return true; // unreadable -> don't touch
        return *(uintptr_t*)shSlot != 0;
    }

    // replication of EnableMotion's set_pinned, this is to stop objects from moving.
    // calling the actual enable motion will cause collision checks, we can't have that.
    static bool FreezeObject(uintptr_t obj)
    {
        if (!kIvpCore) return false; // object model not reversed for this arch

        uintptr_t ivpSlot = obj + kObjIvp;
        if (!Mem::IsReadable((void*)ivpSlot, sizeof(void*))) return false;
        uintptr_t ivp = *(uintptr_t*)ivpSlot;
        if (!PtrOk(ivp)) return false;

        uintptr_t coreSlot = ivp + kIvpCore;
        if (!Mem::IsReadable((void*)coreSlot, sizeof(void*))) return false;
        uintptr_t core = *(uintptr_t*)coreSlot;

        // must cover the highest field we store (speed vs rot_speed swap order by arch)
        const int hi = (kCoreSpeed > kCoreRotSpeed ? kCoreSpeed : kCoreRotSpeed) + 3 * (int)sizeof(uint32_t);
        if (!PtrOk(core) || !Mem::IsReadable((void*)core, (size_t)hi))
            return false;

        unsigned char* flags = (unsigned char*)core;
        if (*flags & kCoreStatic) return false; // already immovable

        for (int i = 0; i < 3; ++i) {
            const int o = i * (int)sizeof(uint32_t);
            *(uint32_t*)(core + kCoreSpeed + o) = 0;
            *(uint32_t*)(core + kCoreRotSpeed + o) = 0;
            *(uint32_t*)(core + kCoreSpeedChange + o) = 0;
            *(uint32_t*)(core + kCoreRotChange + o) = 0;
        }
        for (int i = 0; i < 4; ++i) // 16B movaps block
            *(uint32_t*)(core + kCoreVec30 + i * (int)sizeof(uint32_t)) = 0;

        *flags |= kCorePinned;
        return true;
    }

    struct FreezeArgs { int frozen; };

    static void FreezeQueuedInner(void* arg)
    {
        FreezeArgs* fa = (FreezeArgs*)arg;
        uintptr_t vptr = Vptr();
        for (int i = 0; i < g_nPending; ++i) {
            uintptr_t obj = g_pending[i];
            if (!PtrOk(obj) || *(uintptr_t*)obj != vptr) continue;
            if (IsShadowControlled(obj)) continue;
            int ent = ObjEntIndex(obj);
            if (Cfg().phys_pin && !FreezeObject(obj)) continue;
            if (g_nFrozen < kMaxPhys) g_frozen[g_nFrozen++] = obj;
            if (ent >= 0 && g_nFrozenEnt < kMaxPhys) g_frozenEnt[g_nFrozenEnt++] = ent;
            NoteRepin(ent); // watch for "same offender every episode" -> not converging
            ++fa->frozen;
        }
    }

    int Phys::Recover::FreezeQueued()
    {
        FreezeArgs fa = {0};
        RunProtectedQuiet(FreezeQueuedInner, &fa);
        g_nPending = 0;
        return fa.frozen;
    }

    int Phys::Recover::FrozenEntities(int* out, int max)
    {
        int n = g_nFrozenEnt < max ? g_nFrozenEnt : max;
        for (int i = 0; i < n; ++i) out[i] = g_frozenEnt[i];
        return n;
    }

    static bool BannerDebounce()
    {
        static uint64_t s_lastMs = 0;
        uint64_t now = MonotonicMs();
        int deb = Cfg().report_debounce_sec;
        if (deb <= 0 || s_lastMs == 0 || (now - s_lastMs) >= (uint64_t)deb * 1000ull) {
            s_lastMs = now;
            return true;
        }
        return false;
    }

    void Phys::Recover::PollGameThread()
    {
        PhysFrameStart();
        if (Cfg().phys_hook) Phys::Bind::Install();

        // undo the drain-loop escape from mode=1
        if (g_modeForced) {
            int* mode = EventLoopMode();
            if (mode) *mode = 0;
            g_modeForced = false;
        }

        // cc_physhook prevented a hang and collected the offenders.
        if (g_hookLagged) {
            g_hookLagged = false;
            for (int i = 0; i < g_nRawIvp; ++i) {
                uintptr_t obj = AsPhysObject(g_rawIvp[i]);
                if (obj && !Known(obj) && g_nPending < kMaxPhys) g_pending[g_nPending++] = obj;
            }

            bool b_BannerDebounce = BannerDebounce();
            g_nRawIvp = 0;
            int frozen = 0;
            if (g_nPending > 0) {
                frozen = Phys::Recover::FreezeQueued();
                if (frozen > 0) {
                    int ents[kMaxPhys];
                    int nEnt = Phys::Recover::FrozenEntities(ents, kMaxPhys);
                    if (nEnt > 0) Recovery::NotePhysResolve(ents, nEnt, NULL);
                    if (!b_BannerDebounce)
                        Log::F("[Crash Capture] phys hook: runaway physics tick prevented, %d offender(s).\n", frozen);
                }
            }
            
            if (b_BannerDebounce) {
                char reason[176];
                snprintf(reason, sizeof(reason), "vphysics mindist tick overran %dms, %d offender(s)", Cfg().phys_hook_ms, frozen);
                Report::Banner("hang - physics (vphysics)", reason, NULL);
            }
        }

        // signal-path exploding set (gathered by the reset): queue every new offender.
        if (g_nRawIvp > 0) {
            int added = 0;
            for (int i = 0; i < g_nRawIvp; ++i) {
                uintptr_t obj = AsPhysObject(g_rawIvp[i]);
                if (obj && !Known(obj) && g_nPending < kMaxPhys) { g_pending[g_nPending++] = obj; ++added; }
            }
            g_nRawIvp = 0;
            if (added)
                Log::F("[Crash Capture] phys recover: queued %d exploding object(s) from the saturated queue's mindists (total pending=%d).\n", added, g_nPending);
        }

        if (g_nPending > 0) {
            if (Phys::Recover::FreezeQueued() == 0 && g_pluginPaused) {
                g_pluginPaused = false; // pause stays ON, simply stop managing it
                Log::F("[Crash Capture] phys recover: no offender to act on, leaving physics paused.\n");
                return;
            }
        }

        if (g_giveUp) {
            g_nPending = 0;
            if (g_pluginPaused) {
                Platform::SetPhysPaused(1);
                g_pluginPaused = false; // pause is now permanent, stop managing it, physenv.SetPhysicsPaused can undo this.
                if (g_giveUpEnt == -2)
                    Log::Notice("[Crash Capture] phys recover: still re-saturating after %d recoveries "
                                "in %llums, giving up targeted recovery, physics left paused.\n",
                                kRecWindowMax, (unsigned long long)kRecWindowMs);
                else
                    Log::Notice("[Crash Capture] phys recover: entity %d still hanging after %d recovery "
                                "attempts, giving up targeted recovery, physics left paused.\n",
                                g_giveUpEnt, kMaxRepins);
            }
            return;
        }

        if (g_pluginPaused && g_nPending == 0) {
            Platform::SetPhysPaused(0);
            g_pluginPaused = false;
            Log::F("[Crash Capture] phys recover: physics unpaused%s.\n", Cfg().phys_pin ? " (offenders frozen)" : "");
        }
    }

    void Phys::Recover::Reset()
    {
        g_nPending = g_nFrozen = g_nFrozenEnt = 0;
        g_physResumeCount = 0;
    }

    // --------- resume out of the stuck/faulting tick ---
    struct ResumeTarget {
        bool foundPhys;
        bool have;
        uintptr_t ip, sp;
    #if defined(CC_X64)
        uintptr_t rbx, rbp, r12, r13, r14, r15;
    #else
        uintptr_t ebx, ebp, esi, edi;
    #endif
    };

    // PhysFrame's start + its module bounds, so the resume can skip a PhysFrame detour
    static void* g_physFrameStart = NULL;
    static uintptr_t g_physModBase = 0, g_physModEnd = 0;
    static void* PhysFrameStart()
    {
        if (!g_physFrameStart) {
            uintptr_t code = Sig::Get("phys.frame_code");
            if (code) {
                g_physFrameStart = _Unwind_FindEnclosingFunction((void*)code);
                Modules::Refresh();
                const CCModule* m = g_physFrameStart ? Modules::Find((uintptr_t)g_physFrameStart) : NULL;
                if (m) { g_physModBase = m->base; g_physModEnd = m->base + m->size; }
            }
        }
        return g_physFrameStart;
    }

    // walk up to the first frame back in PhysFrame's module and capture it -- resume
    // returns "as if PhysFrame returned", skipping any detour. Bounds-matched via
    // .eh_frame (works stripped/x64). Physics is paused first, so a later call early-outs.
    static _Unwind_Reason_Code ResumeCb(struct _Unwind_Context* ctx, void* arg)
    {
        ResumeTarget* t = (ResumeTarget*)arg;
        uintptr_t pc = (uintptr_t)_Unwind_GetIP(ctx);
        if (!pc) return _URC_NO_REASON;

        if (t->foundPhys) {
            if (pc < g_physModBase || pc >= g_physModEnd) return _URC_NO_REASON; // still in the hook/vphysics
            t->ip = pc;
            t->sp = (uintptr_t)_Unwind_GetCFA(ctx);
            #if defined(CC_X64)
                t->rbx = (uintptr_t)_Unwind_GetGR(ctx, 3);
                t->rbp = (uintptr_t)_Unwind_GetGR(ctx, 6);
                t->r12 = (uintptr_t)_Unwind_GetGR(ctx, 12);
                t->r13 = (uintptr_t)_Unwind_GetGR(ctx, 13);
                t->r14 = (uintptr_t)_Unwind_GetGR(ctx, 14);
                t->r15 = (uintptr_t)_Unwind_GetGR(ctx, 15);
            #else
                t->ebx = (uintptr_t)_Unwind_GetGR(ctx, 3);
                t->ebp = (uintptr_t)_Unwind_GetGR(ctx, 5);
                t->esi = (uintptr_t)_Unwind_GetGR(ctx, 6);
                t->edi = (uintptr_t)_Unwind_GetGR(ctx, 7);
            #endif
            t->have = true;
            return _URC_END_OF_STACK;
        }
        if (g_physFrameStart && _Unwind_FindEnclosingFunction((void*)pc) == g_physFrameStart)
            t->foundPhys = true;
        return _URC_NO_REASON;
    }

    static void DoResumeWalk(void* arg) { _Unwind_Backtrace(ResumeCb, arg); }

    static void ResumeOut(void* ucontext, const ResumeTarget* t)
    {
        ucontext_t* uc = (ucontext_t*)ucontext;
        greg_t* g = uc->uc_mcontext.gregs;
        #if defined(CC_X64)
            g[REG_RIP] = (greg_t)t->ip;  g[REG_RSP] = (greg_t)t->sp;
            g[REG_RBX] = (greg_t)t->rbx; g[REG_RBP] = (greg_t)t->rbp;
            g[REG_R12] = (greg_t)t->r12; g[REG_R13] = (greg_t)t->r13;
            g[REG_R14] = (greg_t)t->r14; g[REG_R15] = (greg_t)t->r15;
            g[REG_RAX] = 0; // physics call "return value" - unknown
        #else
            g[REG_EIP] = (greg_t)t->ip;  g[REG_ESP] = (greg_t)t->sp;
            g[REG_EBX] = (greg_t)t->ebx; g[REG_EBP] = (greg_t)t->ebp;
            g[REG_ESI] = (greg_t)t->esi; g[REG_EDI] = (greg_t)t->edi;
            g[REG_EAX] = 0;
        #endif
    }

    // undo the two mid-tick states the resume-out skips.
    static void RestorePhysEnvState()
    {
        if (kEnvInSim) {
            uintptr_t slot = Sig::Get("phys.env_slot"); // &physenv
            if (slot && Mem::IsReadable((void*)slot, sizeof(void*))) {
                uintptr_t env = *(uintptr_t*)slot;
                if (env && Mem::IsReadable((void*)(env + kEnvInSim), 1))
                    *(unsigned char*)(env + kEnvInSim) = 0; // clear m_inSimulation
            }
        }
        uintptr_t sem = Sig::Get("phys.remove_sem"); // &s_RemoveImmediateSemaphore
        if (sem && Mem::IsReadable((void*)sem, sizeof(int))) {
            int* s = (int*)sem;
            if (*s > 0) --*s; // balance PhysFrame's unmatched UTIL_DisableRemoveImmediate
        }
    }

    bool Phys::Recover::ResumeFromFault(int sig, void* ucontext)
    {
        if (sig != SIGSEGV && sig != SIGBUS && sig != SIGFPE && sig != SIGILL) return false;
        if (!ucontext) return false;

        if (!Cfg().phys_resume) {
            Log::Debug("[CC-PHYS] physics fault, but phys_resume=0 -- not resuming "
                        "(set CRASHCAPTURE_PHYS_RESUME=1 to recover these).\n");
            return false;
        }
        if (g_physResumeCount >= kMaxPhysResume) return false;

        PhysFrameStart(); // ensure the resume anchor is resolved
        ResumeTarget t;
        memset(&t, 0, sizeof(t));
        RunProtectedQuiet(DoResumeWalk, &t); // never let the walk recursive-kill us
        if (!t.have) return false;

        // physics off so the next tick doesn't re-fault on the same garbage.
        Platform::SetPhysPaused(1);
        RestorePhysEnvState(); // we bailed out of Simulate mid-tick -> un-defer deletes
        ResumeOut(ucontext, &t);

        ++g_physResumeCount;
        Log::F("[Crash Capture] physics fault recovered: resumed Host_RunFrame (resume #%u; physics paused).\n", g_physResumeCount);
        Log::Flush();
        Recovery::NotePhysResume("physics", Log::Path());
        return true;
    }

    int Phys::Recover::ResumeFromHang(void* ucontext, bool forceResume)
    {
        (void)forceResume; // legacy gate arg -- the mode-write escape needs no safe PC
        if (!Cfg().phys_recover || !ucontext) return PHYS_NORESUME;
        if (g_physResumeCount >= kMaxPhysResume) return PHYS_NORESUME;

        // rate-based backstop
        {
            uint64_t now = MonotonicMs();
            if (now - g_recWindowStart > kRecWindowMs) { g_recWindowStart = now; g_recWindowCount = 1; }
            else if (++g_recWindowCount >= kRecWindowMax) { g_giveUp = true; g_giveUpEnt = -2; }
        }

        // mark an offender from the stuck stack (interrupt context: reads only).
        ucontext_t* uc = (ucontext_t*)ucontext;
        greg_t* g = uc->uc_mcontext.gregs;
        #if defined(CC_X64)
            uintptr_t sp = (uintptr_t)g[REG_RSP];
            uintptr_t pc = (uintptr_t)g[REG_RIP];
        #else
            uintptr_t sp = (uintptr_t)g[REG_ESP];
            uintptr_t pc = (uintptr_t)g[REG_EIP];
        #endif
        static const uintptr_t kStackWindow = 0x20000; // 128 KiB above SP
        Phys::Recover::MarkOffender(sp, sp + kStackWindow);

        // log where the thread is stuck (module+offset, maps to IDA via +0x2A000) so a new hang variant is diagnosable.
        {
            void* fn = _Unwind_FindEnclosingFunction((void*)pc);
            const CCModule* pm = Modules::Find(pc);
            const CCModule* fm = fn ? Modules::Find((uintptr_t)fn) : NULL;
            Log::Debug("[CC-PHYS]   stuck PC=0x%lx (%s+0x%lx), enclosing fn=%s+0x%lx\n",
                        (unsigned long)pc,
                        pm ? pm->name : "?", (unsigned long)(pm ? pc - pm->base : 0UL),
                        fm ? fm->name : "?", (unsigned long)((fm && fn) ? (uintptr_t)fn - fm->base : 0UL));
        }

        // resolve physenv's time-event queue (its min_hash) so we can reset it below.
        uintptr_t mh = 0;
        bool haveMh = MinListStats(NULL, NULL, &mh);


        if (!haveMh || !mh) {
            Log::Debug("[CC-PHYS] ResumeFromHang: could not resolve min_hash -- cannot reset/escape.\n");
            return PHYS_NORESUME;
        }

        g_nRawIvp = 0; // ResetMinListInner refills this with the exploding set from the mindists
        ResetArgs ra; ra.mh = mh;
        RunProtectedQuiet(ResetMinListInner, &ra); // reset the queue in place, fault-guarded

        int* mode = EventLoopMode();
        if (mode) { *mode = 1; g_modeForced = true; } // drain loop exits after the cascade

        // pause the next PhysFrame until offenders are frozen.
        Platform::SetPhysPaused(1);
        g_pluginPaused = true;

        ++g_physResumeCount;
        Log::Debug("[CC-PHYS] ResumeFromHang: reset queue + mode=1, returning to finish the tick "
                    "(escape #%u; %d offender(s) queued; mh=0x%lx; mode@%p).\n",
                    g_physResumeCount, g_nPending, (unsigned long)mh, (void*)mode);
        return PHYS_RESUMED;
    }
}

#endif
