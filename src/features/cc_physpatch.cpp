// cc_physpatch - compiled-in physics patches for vphysics/IVP.

#include "crashcapture.h"
#include "features/cc_physpatch.h"

#if defined(CC_LINUX)

#include "tools/cc_patch.h"
#include "tools/cc_signature.h"
#include "features/cc_physrecover.h"
#include <string.h>
#include <stdint.h>

namespace CrashCapture {
    static const CCTarget kPatchTargets[] = {
        #if defined(CC_X86)
            {"patch.vhash_find", "vphysics", "_ZNK9IVP_VHash9find_elemEPKvj",
                "55 89 E5 57 56 53 83 EC 0C 8B 7D 08 8B 5D 10 8B 4F 0C",
                {{CC_STEP_END, 0, 0}}},
            {"patch.minlist_add_entry", "vphysics", NULL,
                "55 89 E5 57 56 53 83 EC 2C 8B 45 E8 F3 0F 10 45 48 83 40 14 01",
                {{CC_STEP_END, 0, 0}}},
            {"patch.p_malloc", "vphysics", "_Z8p_mallocj", NULL,
                {{CC_STEP_END, 0, 0}}},
            {"patch.p_free", "vphysics", "_Z6p_freePv", NULL,
                {{CC_STEP_END, 0, 0}}},
            {"patch.remove_minlist_elem", "vphysics",
                "_ZN14IVP_U_Min_List19remove_minlist_elemEj", NULL,
                {{CC_STEP_END, 0, 0}}},
            {"patch.vhash_store_find", "vphysics",
                "_ZN15IVP_VHash_Store9find_elemEPvj", NULL,
                {{CC_STEP_END, 0, 0}}},
        #elif defined(CC_X64)
            {"patch.vhash_find", "vphysics", NULL,
                "5D C3 49 8B 44 24 08",
                {{CC_STEP_ADD, -143, 0}, {CC_STEP_END, 0, 0}}},
            {"patch.minlist_add_entry", "vphysics", NULL,
                "55 48 89 E5 41 57 41 56 49 89 F6 41 55 41 54 53 48 89 FB 48 83 EC 28 0F B7 57 02",
                {{CC_STEP_END, 0, 0}}},
            {"patch.p_malloc", "vphysics", NULL,
                "48 8B 05 ?? ?? ?? ?? 55 89 FE 48 89 E5 5D 48 8B 00",
                {{CC_STEP_END, 0, 0}}},
            {"patch.p_free", "vphysics", NULL,
                "48 8B 05 ?? ?? ?? ?? 55 48 89 FE 48 89 E5 5D 48 8B 38 48 8B 07 48 8B 40 10",
                {{CC_STEP_END, 0, 0}}},
            {"patch.remove_minlist_elem", "vphysics", NULL,
                "4C 8B 47 08 89 F0 55 48 8D 04 40 48 89 E5 49 8D 04 C0 0F B7 50 06",
                {{CC_STEP_END, 0, 0}}},
        #endif
    };

    // --- shared detour handlers (identical on x86 and x64) ---
    typedef void (*Fn_rfc)(void*);
    static Fn_rfc o_rfc = 0;
    typedef int (*Fn_pk)(void*, void*, void*, void*, void*);
    static Fn_pk o_pk = 0;
    typedef void (*Fn_remove_elem)(void*, const void*, unsigned);
    typedef int  (*Fn_find_elem)(void*, const void*, unsigned);
    static Fn_remove_elem o_remove_elem = 0;
    static Fn_find_elem o_find_elem = 0;

    #if defined(CC_X86)
        static const int kRfcEnvOffset = 0xC; // IVP_Core->environment
        static const int kRfcEnvRead = 0x114; // env readable to current_time (+0x110)
        static const int kRfcCoreRead = 0x10;
    #elif defined(CC_X64)
        static const int kRfcEnvOffset = 0x10;
        static const int kRfcEnvRead = 0x178; // env->current_time at +0x170
        static const int kRfcCoreRead = 0x18;
    #else
        static const int kRfcEnvOffset = 0;
        static const int kRfcEnvRead = 0;
        static const int kRfcCoreRead = 0;
    #endif

    // --- gm.phys.contact_stale_core (PATCH_DETOUR) ---
    static void h_rfc(void* core)
    {
        if (core && Mem::IsReadable(core, kRfcCoreRead)) {
            void* env = *(void**)((char*)core + kRfcEnvOffset);
            if (env && Mem::IsReadable(env, kRfcEnvRead)) {
                o_rfc(core);
                return;
            }
        }
        Log::Debug("[CC-PATCH] reset_freeze_check_values skipped (stale core 0x%lx)\n",
                (unsigned long)(uintptr_t)core);
    }

    // --- gm.phys.mindist_null_edge (PATCH_DETOUR) ---
    static int h_pk(void* mms, void* e1, void* e2, void* cA, void* cB)
    {
        if (e1 && e2)
            return o_pk(mms, e1, e2, cA, cB);
        Log::Debug("[CC-PATCH] p_minimize_PK skipped: null edge (mindist 0x%lx)\n",
                (unsigned long)(uintptr_t)mms);
        return 1; // converged, the retained mindist is stale
    }

    // --- gm.phys.mindist_stale_ff (PATCH_DETOUR) ---
    typedef int (*Fn_ff)(void*, void*, void*, void*, void*);
    static Fn_ff o_ff = 0;

    static int h_ff(void* mms, void* e1, void* e2, void* cA, void* cB)
    {
        if (mms && Mem::IsReadable(mms, sizeof(void*))) {
            void* mindist = *(void**)mms;
            if (mindist && !Phys::Recover::MindistObjectsLive(mindist)) {
                Log::Debug("[CC-PATCH] p_minimize_FF skipped: retained mindist 0x%lx "
                           "references a stale object\n",
                           (unsigned long)(uintptr_t)mindist);
                return 1; // converged, the retained mindist is stale
            }
        }
        if (e1 && e2)
            return o_ff(mms, e1, e2, cA, cB);
        Log::Debug("[CC-PATCH] p_minimize_FF skipped: null edge (mindist 0x%lx)\n",
                (unsigned long)(uintptr_t)mms);
        return 1; // converged, the retained mindist is stale
    }

    // --- gm.phys.ovtree_hash_remove (PATCH_DETOUR) ---
    struct VHashArgs { void* hash; const void* elem; unsigned idx; bool present; };
    static void VHashFindInner(void* arg)
    {
        VHashArgs* a = (VHashArgs*)arg;
        if (o_find_elem)
            a->present = o_find_elem(a->hash, a->elem, a->idx) != 0;
    }

    static void h_remove_elem(void* hash, const void* elem, unsigned idx)
    {
        if (hash && elem) {
            if (!o_find_elem)
                o_find_elem = (Fn_find_elem)Sig::Get("patch.vhash_find");
            if (o_find_elem) {
                VHashArgs a = { hash, elem, idx, false };
                RunProtectedQuiet(VHashFindInner, &a);
                if (!a.present) {
                    Log::Debug("[CC-PATCH] IVP_VHash::remove_elem skipped: elem not in hash\n");
                    return;
                }
            }
        }
        o_remove_elem(hash, elem, idx);
    }

    // --- IVP_U_Min_List::add replacement (gm.phys.minlist_replace) ---
    typedef uint32_t (*Fn_minlist_add)(void* self, void* elem, float value);
    static Fn_minlist_add o_minlist_add = 0;
    static uint32_t h_minlist_add(void* self, void* elem, float value);

    typedef void (*Fn_remove_coc)(void*, void*, void*);
    static Fn_remove_coc o_remove_coc = 0;

    #if defined(CC_X86)
        static const int kCocCount = 0x1E;
        static const int kCocElems = 0x20;
        static const int kCocSimRead = 0x24;
        static const int kCocWrapRead = 0x14;
    #elif defined(CC_X64)
        static const int kCocCount = 0x3A;
        static const int kCocElems = 0x40;
        static const int kCocSimRead = 0x48;
        static const int kCocWrapRead = 0x28;
    #else
        static const int kCocCount = 0, kCocElems = 0, kCocSimRead = 0, kCocWrapRead = 0;
    #endif

    struct CocArgs { void* sim; void* ctrl; bool found; };
    static void CocScanInner(void* arg)
    {
        CocArgs* a = (CocArgs*)arg;
        unsigned short n = *(unsigned short*)((char*)a->sim + kCocCount);
        if (!n) return;
        void** elems = *(void***)((char*)a->sim + kCocElems);
        if (!elems) return;
        for (unsigned short i = 0; i < n; ++i) {
            void* w = elems[i];
            if (!w) continue;
            if (!Mem::IsReadable(w, kCocWrapRead)) continue;
            if (*(void**)w == a->ctrl) { a->found = true; return; }
        }
    }

    static void h_remove_coc(void* sim, void* core, void* ctrl)
    {
        if (sim && ctrl && Mem::IsReadable(sim, kCocSimRead)) {
            CocArgs a = { sim, ctrl, false };
            RunProtectedQuiet(CocScanInner, &a);
            if (a.found) {
                o_remove_coc(sim, core, ctrl);
                return;
            }
            Log::Debug("[CC-PATCH] remove_controller_of_core skipped: controller 0x%lx not in sim-unit 0x%lx\n",
                    (unsigned long)(uintptr_t)ctrl, (unsigned long)(uintptr_t)sim);
            return;
        }
        Log::Debug("[CC-PATCH] remove_controller_of_core skipped: unreadable sim-unit 0x%lx\n",
                (unsigned long)(uintptr_t)sim);
    }

    // --- gm.phys.vhash_store_remove_bound (PATCH_DETOUR) ---
    typedef void* (*Fn_store_find)(void*, void*, unsigned);
    typedef void* (*Fn_store_remove)(void*, void*, unsigned);
    static Fn_store_find o_store_find = 0;
    static Fn_store_remove o_store_remove = 0;

    struct StoreFindArgs { void* hash; void* key; unsigned idx; void* found; };
    static void StoreFindInner(void* arg)
    {
        StoreFindArgs* a = (StoreFindArgs*)arg;
        if (o_store_find)
            a->found = o_store_find(a->hash, a->key, a->idx);
    }

    static void* h_store_remove(void* hash, void* key, unsigned idx)
    {
        if (hash && key) {
            if (!o_store_find)
                o_store_find = (Fn_store_find)Sig::Get("patch.vhash_store_find");
            if (o_store_find) {
                StoreFindArgs a = { hash, key, idx, NULL };
                RunProtectedQuiet(StoreFindInner, &a);
                if (!a.found) {
                    Log::Debug("[CC-PATCH] IVP_VHash_Store::remove_elem skipped: key not in hash\n");
                    return NULL;
                }
            }
        }
        return o_store_remove(hash, key, idx);
    }

    #if defined(CC_X86)
        // --- gm.phys.watcher_stale_mindist (PATCH_DETOUR, x86 only) ---
        typedef void (*Fn_oow)(void*, void*);
        static Fn_oow o_oow_remove = 0;

        struct OowArgs { void* watcher; void* c; bool present; };
        static void OowCheckInner(void* arg)
        {
            OowArgs* a = (OowArgs*)arg;
            unsigned int n = *(unsigned short*)((char*)a->watcher + 0x3A); // mindists.n_elems
            void** elems = *(void***)((char*)a->watcher + 0x3C);
            if (!elems) return;
            int i0 = *(int*)((char*)a->c + 0x0C); // fvector_index[0]
            int i1 = *(int*)((char*)a->c + 0x10); // fvector_index[1]
            int index = -1;
            if (i0 >= 0 && i0 < (int)n && elems[i0] == a->c) index = i0;
            else if (i1 >= 0 && i1 < (int)n && elems[i1] == a->c) index = i1;
            if (index < 0) return;
            if (n > 0 && (n - 1) > (unsigned int)index && !elems[n - 1])
                return; // the resort would move a null slot
            a->present = true;
        }

        static void h_oow_remove(void* watcher, void* c)
        {
            if (watcher && c) {
                OowArgs a = { watcher, c, false };
                RunProtectedQuiet(OowCheckInner, &a);
                if (!a.present) {
                    Log::Debug("[CC-PATCH] watcher remove skipped: mindist 0x%lx not in vector\n",
                            (unsigned long)(uintptr_t)c);
                    return;
                }
            }
            o_oow_remove(watcher, c);
        }
    #endif

    // --- IVP_U_Min_List::add replacement (gm.phys.minlist_replace) ---

    #if defined(CC_X86)
        static const int kMinListCap = 0, kMinListFree = 2, kMinListElems = 4;
        static const int kMinListMinVal = 8, kMinListFirstLong = 12;
        static const int kMinListFirstElement = 16, kMinListCounter = 20;
        static const int kMinListElemSize = 16;
        static const int kMinListElemLongNext = 0, kMinListElemLongPrev = 2;
        static const int kMinListElemNext = 4, kMinListElemPrev = 6;
        static const int kMinListElemValue = 8, kMinListElemElement = 12;
    #else
        static const int kMinListCap = 0, kMinListFree = 2, kMinListElems = 8;
        static const int kMinListMinVal = 16, kMinListFirstLong = 20;
        static const int kMinListFirstElement = 24, kMinListCounter = 28;
        static const int kMinListElemSize = 24;
        static const int kMinListElemLongNext = 0, kMinListElemLongPrev = 2;
        static const int kMinListElemNext = 4, kMinListElemPrev = 6;
        static const int kMinListElemValue = 8, kMinListElemElement = 16;
    #endif
    static const uint16_t kMinListUnused = 0xFFFF;
    static const uint16_t kMinListLongUnused = 0xFFFE;
    static const uint32_t kMinListMaxAlloc = 0xFFFC;

    static bool g_minlistSkipList = false; // gm.phys.minlist_skip_list (linear walk)
    static bool g_minlistBoundA = true; // gm.phys.minlist_walk_bound_a (long-walk bound)
    static bool g_minlistBoundB = true; // gm.phys.minlist_walk_bound_b (short-walk bound)
    static uintptr_t g_minListMalloc = 0, g_minListFree = 0;

    static inline char* MinListSlot(uintptr_t elems, uint32_t idx)
    {
        return (char*)elems + (uintptr_t)idx * kMinListElemSize;
    }

    static uint32_t h_minlist_add(void* selfPtr, void* elem, float value)
    {
        if (!g_minListMalloc || !g_minListFree) {
            g_minListMalloc = Sig::Get("patch.p_malloc");
            g_minListFree = Sig::Get("patch.p_free");
            if (!g_minListMalloc || !g_minListFree || !o_minlist_add)
                return o_minlist_add ? o_minlist_add(selfPtr, elem, value) : 0;
        }

        char* self = (char*)selfPtr;
        *(uint32_t*)(self + kMinListCounter) += 1;

        uint16_t returnIndex;
        char* e;
        uintptr_t elems;

        uint16_t freeList = *(uint16_t*)(self + kMinListFree);
        if (freeList != kMinListUnused) {
            returnIndex = freeList;
            elems = *(uintptr_t*)(self + kMinListElems);
            e = MinListSlot(elems, returnIndex);
            *(uint16_t*)(self + kMinListFree) = *(uint16_t*)(e + kMinListElemNext);
        } else {
            uint16_t cap = *(uint16_t*)(self + kMinListCap);
            uint32_t newCap = (uint32_t)cap * 2 + 1;
            if (newCap > kMinListMaxAlloc) newCap = kMinListMaxAlloc;
            char* newElems = (char*)((void* (*)(size_t))g_minListMalloc)(
                (size_t)kMinListElemSize * (newCap + 1));
            elems = *(uintptr_t*)(self + kMinListElems);
            if (cap && elems)
                memcpy(newElems, (void*)elems, (size_t)kMinListElemSize * cap);
            if (elems)
                ((void (*)(void*))g_minListFree)((void*)elems);
            *(uint16_t*)(self + kMinListCap) = (uint16_t)newCap;
            *(uintptr_t*)(self + kMinListElems) = (uintptr_t)newElems;
            returnIndex = cap;
            e = MinListSlot((uintptr_t)newElems, returnIndex);
            elems = (uintptr_t)newElems;
            for (uint32_t i = (uint32_t)cap + 1; i < newCap; ++i)
                *(uint16_t*)(MinListSlot(elems, i) + kMinListElemNext) = (uint16_t)(i + 1);
            *(uint16_t*)(MinListSlot(elems, newCap - 1) + kMinListElemNext) = kMinListUnused;
            *(uint16_t*)(self + kMinListFree) = (uint16_t)(cap + 1);
        }

        *(void**)(e + kMinListElemElement) = elem;
        *(float*)(e + kMinListElemValue) = value;
        *(uint16_t*)(e + kMinListElemLongNext) = kMinListLongUnused;

        if (value <= *(float*)(self + kMinListMinVal)) {
            // quick insert first element
            *(float*)(self + kMinListMinVal) = value;
            uint32_t firstElement = *(uint32_t*)(self + kMinListFirstElement);
            *(uint16_t*)(e + kMinListElemNext) = (uint16_t)firstElement;
            if (firstElement != kMinListUnused)
                *(uint16_t*)(MinListSlot(elems, firstElement) + kMinListElemPrev) = returnIndex;
            *(uint32_t*)(self + kMinListFirstElement) = returnIndex;
            *(uint16_t*)(e + kMinListElemPrev) = kMinListUnused;
            return returnIndex;
        }

        // find place to insert (at least one element exists here)
        uint32_t lastj = *(uint32_t*)(self + kMinListFirstElement);
        uint32_t maxCmpLen = 3;

        // long walk over the skip-list (skipped when the skip-list is disabled)
        uint32_t lo = g_minlistSkipList ? kMinListUnused : *(uint32_t*)(self + kMinListFirstLong);
        uint32_t longEnd = g_minlistBoundA ? 0xFFFD : 0xFFFF;
        while (lo < longEnd) {
            char* flong = MinListSlot(elems, lo);
            if (*(float*)(flong + kMinListElemValue) >= value) break;
            ++maxCmpLen;
            lastj = lo;
            lo = *(uint16_t*)(flong + kMinListElemLongNext);
        }
        uint32_t firstjAfter = lastj;

        // short walk
        uint32_t countCmp = 0;
        char* f = MinListSlot(elems, lastj);
        uint32_t j = *(uint16_t*)(f + kMinListElemNext);
        uint32_t shortEnd = g_minlistBoundB ? 0xFFFD : 0xFFFF;
        uint32_t promotePos = kMinListUnused;
        for (; j < shortEnd; j = *(uint16_t*)(f + kMinListElemNext)) {
            f = MinListSlot(elems, j);
            ++countCmp;
            if (countCmp == maxCmpLen - 2) promotePos = j;
            if (value > *(float*)(f + kMinListElemValue)) { lastj = j; continue; }
            // insert before j (after lastj)
            char* l = MinListSlot(elems, lastj);
            *(uint16_t*)(e + kMinListElemNext) = *(uint16_t*)(l + kMinListElemNext);
            *(uint16_t*)(f + kMinListElemPrev) = returnIndex;
            *(uint16_t*)(e + kMinListElemPrev) = (uint16_t)lastj;
            *(uint16_t*)(l + kMinListElemNext) = returnIndex;
            goto linked;
        }
        // insert after the last element
        {
            char* l = MinListSlot(elems, lastj);
            *(uint16_t*)(e + kMinListElemNext) = (uint16_t)j; // end-of-chain
            *(uint16_t*)(e + kMinListElemPrev) = (uint16_t)lastj;
            *(uint16_t*)(l + kMinListElemNext) = returnIndex;
        }

        linked:
        // skip-list creation, corrected: never promote an element that is already a long node.
        if (!g_minlistSkipList && countCmp > maxCmpLen) {
            uint32_t newLongPos = promotePos;
            char* nl = MinListSlot(elems, newLongPos);
            if (*(uint16_t*)(nl + kMinListElemLongNext) == kMinListLongUnused) {
                uint16_t nextOfFirst =
                    *(uint16_t*)(MinListSlot(elems, firstjAfter) + kMinListElemLongNext);
                if (nextOfFirst != kMinListLongUnused) {
                    // real long as first element
                    *(uint16_t*)(nl + kMinListElemLongNext) = nextOfFirst;
                    *(uint16_t*)(nl + kMinListElemLongPrev) = (uint16_t)firstjAfter;
                    if (nextOfFirst != kMinListUnused)
                        *(uint16_t*)(MinListSlot(elems, nextOfFirst) + kMinListElemLongPrev) =
                            (uint16_t)newLongPos;
                    *(uint16_t*)(MinListSlot(elems, firstjAfter) + kMinListElemLongNext) =
                        (uint16_t)newLongPos;
                } else {
                    // insert long as first long
                    uint32_t firstLong = *(uint32_t*)(self + kMinListFirstLong);
                    *(uint16_t*)(nl + kMinListElemLongNext) = (uint16_t)firstLong;
                    *(uint16_t*)(nl + kMinListElemLongPrev) = kMinListUnused;
                    if (firstLong != kMinListUnused)
                        *(uint16_t*)(MinListSlot(elems, firstLong) + kMinListElemLongPrev) =
                            (uint16_t)newLongPos;
                    *(uint32_t*)(self + kMinListFirstLong) = newLongPos;
                }
            }
        }

        return returnIndex;
    }

    static const CCPatch kPhysPatches[] = {
        #if defined(CC_X86)
            {
                "gm.phys.contact_stale_core",
                "gmod IVP teardown UAF",
                "skip reset_freeze_check_values when core->environment is null during teardown",
                CC_PATCH_DETOUR,
                {"patch.rfc", "vphysics", NULL,
                    "55 89 E5 8B 45 08 8B 50 0C F2 0F 10 82",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x89,0xE5,0x8B,0x45,0x08,0x8B,0x50,0x0C,0xF2,0x0F,0x10,0x82},
                {1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                13,
                (void*)h_rfc,
                (void**)&o_rfc,
                true,   // default_on: proven crash fix
                false,  // hot_safe: reachable from the physics threads, no live toggle
                false,  // keep_wildcards: n/a for a detour
            },
            {
                "gm.phys.mindist_null_edge",
                "gmod IVP retained-mindist UAF",
                "skip p_minimize_PK when handed a null edge (stale hull geometry)",
                CC_PATCH_DETOUR,
                {"patch.p_minimize_pk", "vphysics",
                    "_ZN27IVP_Mindist_Minimize_Solver13p_minimize_PKEPK16IVP_Compact_EdgeS2_P21IVP_Cache_Ledge_PointS4_",
                    "55 89 E5 57 56 8D 7D C8 53 83 EC 3C 8B 5D 18 8B 75 10",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x89,0xE5,0x57,0x56,0x8D,0x7D,0xC8,0x53,0x83,0xEC,0x3C,0x8B,0x5D,0x18,0x8B,0x75,0x10},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                18,
                (void*)h_pk,
                (void**)&o_pk,
                true, false, false,
            },
            {
                "gm.phys.mindist_stale_ff",
                "gmod IVP retained-mindist UAF",
                "skip p_minimize_FF when the retained mindist references a stale object",
                CC_PATCH_DETOUR,
                {"patch.p_minimize_ff", "vphysics",
                    "_ZN27IVP_Mindist_Minimize_Solver13p_minimize_FFEPK16IVP_Compact_EdgeS2_P21IVP_Cache_Ledge_PointS4_",
                    "55 89 E5 57 56 53 81 EC 9C 02 00 00 8B 45 08",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x89,0xE5,0x57,0x56,0x53,0x81,0xEC,0x9C,0x02,0x00,0x00,0x8B,0x45,0x08,0xC7,0x85,0x80,0xFD,0xFF,0xFF,0x03,0x00,0x00},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                24,
                (void*)h_ff,
                (void**)&o_ff,
                true, false, false,
            },
            {
                "gm.phys.oo_collision_hash_index",
                "gmod IVP OO-watcher collision-hash sign-extension",
                "read the 16-bit collision-hash slot with movzx, not movsx (an index >= 0x8000 went negative)",
                CC_PATCH_BYTES,
                {"patch.oo_hash_index", "vphysics", NULL,
                    "0F BF 38 89 FE 66 83 FF FF",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x0F,0xBF,0x38,0x89,0xFE,0x66,0x83,0xFF,0xFF},
                {1,1,1,1,1,1,1,1,1},
                {0x0F,0xB7,0x38,0x89,0xFE,0x66,0x83,0xFF,0xFF},
                9,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.oo_collision_hash_swap",
                "gmod IVP OO-watcher collision-hash sign-extension",
                "second movsx->movzx site on the hash swap-path probe",
                CC_PATCH_BYTES,
                {"patch.oo_hash_swap", "vphysics", NULL,
                    "0F BF 0A 39 8D 88 ED FF FF",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x0F,0xBF,0x0A,0x39,0x8D,0x88,0xED,0xFF,0xFF},
                {1,1,1,1,1,1,1,1,1},
                {0x0F,0xB7,0x0A,0x39,0x8D,0x88,0xED,0xFF,0xFF},
                9,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.watcher_stale_mindist",
                "gmod IVP teardown UAF - stale mindist double-removal",
                "skip remove_allow_resort when the mindist is no longer in the OO_Watcher mindists vector",
                CC_PATCH_DETOUR,
                {"patch.oow_remove", "vphysics",
                    "_ZN14IVP_OO_Watcher38collision_is_going_to_be_deleted_eventEP13IVP_Collision",
                    "55 89 E5 56 8B 4D 0C 53 8B 5D 08 8B 51 0C 0F B7 73 3A",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x89,0xE5,0x56,0x8B,0x4D,0x0C,0x53,0x8B,0x5D,0x08,0x8B,0x51,0x0C,0x0F,0xB7,0x73,0x3A},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                18,
                (void*)h_oow_remove,
                (void**)&o_oow_remove,
                true, false, false,
            },
            {
                "gm.phys.ovtree_hash_remove",
                "gmod IVP teardown UAF",
                "skip IVP_VHash::remove_elem when the element is already absent (fatal not-found assert)",
                CC_PATCH_DETOUR,
                {"patch.vhash_remove", "vphysics",
                    "_ZN9IVP_VHash11remove_elemEPKvj",
                    "55 89 E5 57 56 53 83 EC 1C 8B 75 08 8B 5D 10 23 5E 04",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x89,0xE5,0x57,0x56,0x53,0x83,0xEC,0x1C,0x8B,0x75,0x08,0x8B,0x5D,0x10,0x23,0x5E,0x04},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                18,
                (void*)h_remove_elem,
                (void**)&o_remove_elem,
                true, false, false,
            },
            {
                "gm.phys.vhash_remove_null",
                "gmod IVP VHash absent-key fatal",
                "IVP_VHash::remove_elem returns early on an absent key instead of the not-found fatal",
                CC_PATCH_BYTES,
                {"patch.vhash_remove_null", "vphysics", NULL,
                    "8B 47 04 85 C0 75 BF",
                    {{CC_STEP_END, 0, 0}}},
                0x7, // anchor(0x11a892, scan-loop tail) -> not-found fatal entry (0x11a899)
                {0x83,0xEC,0x04,0x89,0x4D,0xE4},
                {1,1,1,1,1,1},
                {0xE9,0x0E,0x01,0x00,0x00},
                5,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.minlist_walk_bound_a",
                "gmod IVP min-list walk bound",
                "treat an out-of-range add() chain link (>= 0xFFFD) as end-of-chain instead of walking past the slot array",
                CC_PATCH_BYTES,
                {"patch.minlist_add", "vphysics", NULL,
                    "83 40 14 01 0F B7 40 02 66 83 F8 FF 0F 84",
                    {{CC_STEP_END, 0, 0}}},
                0x7F, // anchor(0x117bc1) -> first insertion-walk link check (0x117c40)
                {0x81,0xFB,0xFF,0xFF,0x00,0x00,0x0F,0x84,0xA4,0x01,0x00,0x00},
                {1,1,1,1,1,1,1,1,1,1,1,1},
                {0x81,0xFB,0xFD,0xFF,0x00,0x00,0x0F,0x83,0xA4,0x01,0x00,0x00},
                12,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.minlist_walk_bound_b",
                "gmod IVP min-list walk bound",
                "treat an out-of-range add() chain link (>= 0xFFFD) as end-of-chain instead of walking past the slot array",
                CC_PATCH_BYTES,
                {"patch.minlist_add", "vphysics", NULL,
                    "83 40 14 01 0F B7 40 02 66 83 F8 FF 0F 84",
                    {{CC_STEP_END, 0, 0}}},
                0xE6, // anchor(0x117bc1) -> second insertion-walk link check (0x117ca7)
                {0x81,0xFB,0xFF,0xFF,0x00,0x00,0x0F,0x84,0x1B,0x03,0x00,0x00},
                {1,1,1,1,1,1,1,1,1,1,1,1},
                {0x81,0xFB,0xFD,0xFF,0x00,0x00,0x0F,0x83,0x1B,0x03,0x00,0x00},
                12,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.minlist_skip_list",
                "gmod IVP min-list skip-list (long-jump) corruption",
                "disable IVP_U_Min_List's skip-list (long-jump) optimization",
                CC_PATCH_BYTES,
                {"patch.minlist_add", "vphysics", NULL,
                    "83 40 14 01 0F B7 40 02 66 83 F8 FF 0F 84",
                    {{CC_STEP_END, 0, 0}}},
                0x147, // anchor(0x117bc1) -> long-node creation guard (0x117d08)
                {0x39,0xD6}, // cmp esi, edx (count_cmp vs max_cmp_len)
                {1,1},
                {0x39,0xF6}, // cmp esi, esi (always equal -> never insert a skip-list node)
                2,
                NULL, NULL,
                false, false, false,
            },
            {
                "gm.phys.minlist_replace",
                "gmod IVP min-list add() replacement (skip-list corruption fix)",
                "replaces IVP_U_Min_List::add with a corrected implementation",
                CC_PATCH_DETOUR,
                {"patch.minlist_add_entry", "vphysics", NULL,
                    "55 89 E5 57 56 53 83 EC 2C 8B 45 08 F3 0F 10 45 10 83 40 14 01",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x89,0xE5,0x57,0x56,0x53,0x83,0xEC,0x2C,0x8B,0x45,0x08,0xF3,0x0F,0x10,0x45,0x10,0x83,0x40,0x14,0x01},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                21,
                (void*)h_minlist_add,
                (void**)&o_minlist_add,
                true, false, false,
            },
            {
                "gm.phys.ctrl_remove_absent",
                "gmod IVP teardown UAF",
                "skip remove_controller_of_core when the controller is absent from the sim unit's controller list",
                CC_PATCH_DETOUR,
                {"patch.remove_coc", "vphysics",
                    "_ZN19IVP_Simulation_Unit25remove_controller_of_coreEP8IVP_CoreP14IVP_Controller",
                    "55 89 E5 57 56 53 83 EC 1C 8B 45 08 8B 55 0C 8B 4D 10 0F B7 70 1E",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x89,0xE5,0x57,0x56,0x53,0x83,0xEC,0x1C,0x8B,0x45,0x08,0x8B,0x55,0x0C,0x8B,0x4D,0x10,0x0F,0xB7,0x70,0x1E},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                22,
                (void*)h_remove_coc,
                (void**)&o_remove_coc,
                true, false, false,
            },
            {
                "gm.phys.coc_absent_bail",
                "gmod IVP controller-list UAF",
                "remove_controller_of_core returns when the controller is absent from the sim unit's list",
                CC_PATCH_BYTES,
                {"patch.remove_coc", "vphysics", NULL,
                    "83 EE 01 66 89 70 1E 8D 65 F4 5B 5E 5F 5D C3",
                    {{CC_STEP_END, 0, 0}}},
                0xF, // anchor(0x101621, epilogue) -> not-found fallthrough (0x101630)
                {0x8B,0x70,0xFC,0xE9,0x30,0xFF,0xFF,0xFF},
                {1,1,1,1,1,1,1,1},
                {0xE9,0xF3,0xFF,0xFF,0xFF,0x90,0x90,0x90},
                8,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.vhash_store_remove_bound",
                "gmod IVP friction-hash unbounded scan",
                "skip IVP_VHash_Store::remove_elem when the key is absent (its find loop has no null break and walks off the array)",
                CC_PATCH_DETOUR,
                {"patch.vhash_store_remove", "vphysics",
                    "_ZN15IVP_VHash_Store11remove_elemEPvj",
                    "55 89 E5 57 56 53 83 EC 10 8B 45 08 8B 75 08",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x89,0xE5,0x57,0x56,0x53,0x83,0xEC,0x10,0x8B,0x45,0x08,0x8B,0x75,0x08},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                15,
                (void*)h_store_remove,
                (void**)&o_store_remove,
                false, false, false,
            },
        #elif defined(CC_X64)
            {
                "gm.phys.contact_stale_core",
                "gmod IVP teardown UAF",
                "skip reset_freeze_check_values when core->environment is null during teardown",
                CC_PATCH_DETOUR,
                {"patch.rfc", "vphysics", NULL,
                    "48 8B 47 10 55 48 89 E5 5D F2 0F 10 80 70 01 00 00",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x48,0x8B,0x47,0x10,0x55,0x48,0x89,0xE5,0x5D,0xF2,0x0F,0x10,0x80,0x70,0x01,0x00,0x00},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                17,
                (void*)h_rfc,
                (void**)&o_rfc,
                true,   // default_on: proven crash fix
                false,  // hot_safe: reachable from the physics threads, no live toggle
                false,  // keep_wildcards: n/a for a detour
            },
            {
                "gm.phys.mindist_null_edge",
                "gmod IVP retained-mindist UAF",
                "skip p_minimize_PK when handed a null edge (stale hull geometry)",
                CC_PATCH_DETOUR,
                {"patch.p_minimize_pk", "vphysics", NULL,
                    "55 48 89 E5 41 57 49 89 CF 41 56 49 89 F6 4C 89 FE 41 55 4C 8D 6D C0 41 54 4C 89 E9 49 89 D4 53 4C 89 C2 4C 89 C3 48 83",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x48,0x89,0xE5,0x41,0x57,0x49,0x89,0xCF,0x41,0x56,0x49,0x89,0xF6,0x4C,0x89,0xFE,0x41,0x55,0x4C,0x8D,0x6D,0xC0,0x41},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                24,
                (void*)h_pk,
                (void**)&o_pk,
                true, false, false,
            },
            {
                "gm.phys.mindist_stale_ff",
                "gmod IVP retained-mindist UAF",
                "skip p_minimize_FF when the retained mindist references a stale object",
                CC_PATCH_DETOUR,
                {"patch.p_minimize_ff", "vphysics", NULL,
                    "55 48 89 E5 41 57 4D 89 C7 41 56 41 BE 03 00 00 00 41 55 41 54 49 89 F4 53 48 81 EC 78 03 00 00",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x48,0x89,0xE5,0x41,0x57,0x4D,0x89,0xC7,0x41,0x56,0x41,0xBE,0x03,0x00,0x00,0x00,0x41,0x55,0x41,0x54,0x49,0x89,0xF4},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                24,
                (void*)h_ff,
                (void**)&o_ff,
                true, false, false,
            },
            {
                "gm.phys.oo_collision_hash_index",
                "gmod IVP OO-watcher collision-hash sign-extension",
                "read the 16-bit collision-hash slot with movzx, not movsx (an index >= 0x8000 went negative)",
                CC_PATCH_BYTES,
                {"patch.oo_hash_index", "vphysics", NULL,
                    "0F BF 0A 44 39 C1 75 EC 8B BD",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x0F,0xBF,0x0A,0x44,0x39,0xC1,0x75,0xEC,0x8B,0xBD},
                {1,1,1,1,1,1,1,1,1,1},
                {0x0F,0xB7,0x0A,0x44,0x39,0xC1,0x75,0xEC,0x8B,0xBD},
                10,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.oo_collision_hash_swap",
                "gmod IVP OO-watcher collision-hash sign-extension",
                "second movsx->movzx site on the hash swap-path probe",
                CC_PATCH_BYTES,
                {"patch.oo_hash_swap", "vphysics", NULL,
                    "0F BF 0A 39 8D ?? ?? ?? ??",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x0F,0xBF,0x0A,0x39,0x8D,0x60,0xE3,0xFF,0xFF},
                {1,1,1,1,1,1,1,1,1},
                {0x0F,0xB7,0x0A,0x39,0x8D,0x60,0xE3,0xFF,0xFF},
                9,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.ovtree_hash_remove",
                "gmod IVP teardown UAF",
                "skip IVP_VHash::remove_elem when the element is already absent (fatal not-found assert)",
                CC_PATCH_DETOUR,
                {"patch.vhash_remove", "vphysics", NULL,
                    "55 41 89 D0 48 89 E5 41 57 41 56 41 55 49 89 FD 41 54 53 48 83 EC 18",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x41,0x89,0xD0,0x48,0x89,0xE5,0x41,0x57,0x41,0x56,0x41,0x55,0x49,0x89,0xFD,0x41,0x54,0x53,0x48,0x83,0xEC,0x18},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                23,
                (void*)h_remove_elem,
                (void**)&o_remove_elem,
                true, false, false,
            },
            {
                "gm.phys.vhash_remove_null",
                "gmod IVP VHash absent-key fatal",
                "IVP_VHash::remove_elem returns early on an absent key instead of the not-found fatal",
                CC_PATCH_BYTES,
                {"patch.vhash_remove_null", "vphysics", NULL,
                    "49 83 7C 24 08 00 0F 84 ?? ?? ?? ??",
                    {{CC_STEP_END, 0, 0}}},
                0x0, // anchor(0x1233f0) = the null-elem probe itself (disp wildcarded; entry is detoured)
                {0x49,0x83,0x7C,0x24,0x08,0x00,0x0F,0x84,0x04,0x01,0x00,0x00},
                {1,1,1,1,1,1,1,1,0,0,0,0},
                {0x49,0x83,0x7C,0x24,0x08,0x00,0x0F,0x84,0x50,0x01,0x00,0x00},
                12,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.minlist_walk_bound_a",
                "gmod IVP min-list walk bound",
                "treat an out-of-range add() chain link (>= 0xFFFD) as end-of-chain instead of walking past the slot array",
                CC_PATCH_BYTES,
                {"patch.minlist_add", "vphysics", NULL,
                    "0F B7 57 02 83 47 1C 01 66 83 FA FF 0F 84 ?? ?? ?? ??",
                    {{CC_STEP_END, 0, 0}}},
                0xDB, // anchor(0x120877) -> first insertion-walk link check (0x120952)
                {0x81,0xF9,0xFF,0xFF,0x00,0x00,0x75,0xDE},
                {1,1,1,1,1,1,1,1},
                {0x81,0xF9,0xFD,0xFF,0x00,0x00,0x72,0xDE},
                8,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.minlist_walk_bound_b",
                "gmod IVP min-list walk bound",
                "treat an out-of-range add() chain link (>= 0xFFFD) as end-of-chain instead of walking past the slot array",
                CC_PATCH_BYTES,
                {"patch.minlist_add", "vphysics", NULL,
                    "0F B7 57 02 83 47 1C 01 66 83 FA FF 0F 84 ?? ?? ?? ??",
                    {{CC_STEP_END, 0, 0}}},
                0x14D, // anchor(0x120877) -> second insertion-walk link check (0x1209C4)
                {0x81,0xFE,0xFF,0xFF,0x00,0x00,0x75,0xD4},
                {1,1,1,1,1,1,1,1},
                {0x81,0xFE,0xFD,0xFF,0x00,0x00,0x72,0xD4},
                8,
                NULL, NULL,
                true, false, false,
            },
            {
                "gm.phys.minlist_skip_list",
                "gmod IVP min-list skip-list (long-jump) corruption",
                "disable IVP_U_Min_List's skip-list (long-jump) optimization",
                CC_PATCH_BYTES,
                {"patch.minlist_add", "vphysics", NULL,
                    "0F B7 57 02 83 47 1C 01 66 83 FA FF 0F 84 ?? ?? ?? ??",
                    {{CC_STEP_END, 0, 0}}},
                0x169, // anchor(0x120877) -> long-node creation guard (0x1209e0)
                {0x41,0x39,0xFB}, // cmp r11d, edi (count_cmp vs max_cmp_len)
                {1,1,1},
                {0x45,0x39,0xDB}, // cmp r11d, r11d (always equal -> never insert a skip-list node)
                3,
                NULL, NULL,
                false, false, false,
            },
            {
                "gm.phys.minlist_replace",
                "gmod IVP min-list add() replacement (skip-list corruption fix)",
                "replaces IVP_U_Min_List::add with a corrected implementation",
                CC_PATCH_DETOUR,
                {"patch.minlist_add_entry", "vphysics", NULL,
                    "55 48 89 E5 41 57 41 56 49 89 F6 41 55 41 54 53 48 89 FB 48 83 EC 28 0F B7 57 02",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x48,0x89,0xE5,0x41,0x57,0x41,0x56,0x49,0x89,0xF6,0x41,0x55,0x41,0x54,0x53,0x48,0x89,0xFB,0x48,0x83,0xEC,0x28},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                23,
                (void*)h_minlist_add,
                (void**)&o_minlist_add,
                true, false, false,
            },
            {
                "gm.phys.ctrl_remove_absent",
                "gmod IVP teardown UAF",
                "skip remove_controller_of_core when the controller is absent from the sim unit's controller list",
                CC_PATCH_DETOUR,
                {"patch.remove_coc", "vphysics", NULL,
                    "55 48 89 E5 41 55 49 89 FD 41 54 53 48 83 EC 08 0F B7 5F 3A 48 8B 4F 40",
                    {{CC_STEP_END, 0, 0}}},
                0,
                {0x55,0x48,0x89,0xE5,0x41,0x55,0x49,0x89,0xFD,0x41,0x54,0x53,0x48,0x83,0xEC,0x08,0x0F,0xB7,0x5F,0x3A,0x48,0x8B,0x4F,0x40},
                {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
                {0},
                24,
                (void*)h_remove_coc,
                (void**)&o_remove_coc,
                true, false, false,
            },
            {
                "gm.phys.coc_absent_bail",
                "gmod IVP controller-list UAF",
                "remove_controller_of_core returns when the controller is absent from the sim unit's list",
                CC_PATCH_BYTES,
                {"patch.remove_coc", "vphysics", NULL,
                    "83 EB 01 83 FB FF 75 EB",
                    {{CC_STEP_END, 0, 0}}},
                0x8, // anchor(0x10f5ed, scan-loop tail) -> not-found fallthrough (0x10f5f5)
                {0x4C,0x8B,0x61,0xF8,0xBB,0xFF,0xFF,0xFF,0xFF},
                {1,1,1,1,1,1,1,1,1},
                {0xE9,0x3C,0x01,0x00,0x00,0x90,0x90,0x90,0x90},
                9,
                NULL, NULL,
                true, false, false,
            },
        #endif
    };

    static const CCPatch kPerfPatches[] = {
        #if defined(CC_X86)
            {
                "gm.phys.friction_hash_init_size",
                "gmod IVP friction-hash warmup",
                "create the per-core friction hash with 16 initial slots instead of 2",
                CC_PATCH_BYTES,
                {"patch.friction_hash_init", "vphysics",
                    "_ZN8IVP_Core17add_friction_infoEP26IVP_Friction_Info_For_Core",
                    NULL,
                    {{CC_STEP_END, 0, 0}}},
                0x60, // entry -> push 2 (the IVP_VHash_Store(size) arg)
                {0x6A,0x02},
                {1,1},
                {0x6A,0x10},
                2,
                NULL, NULL,
                true, false, false,
            },
        #endif
    };

    // --- ue_defer (phys_defer_eps_us) ---

    #if defined(CC_X86)
        static const int kMindistIndex = 4; // IVP_Mindist (IVP_Time_Event) -> min-list slot index
        static const int kIvpTm = 4; // IVP_Environment -> time manager
        static const int kTmmHash = 8; // IVP_Time_Manager -> min_hash
        static const int kTmLmTime = 0x10; // IVP_Time_Manager -> last_time (double)
    #else
        static const int kMindistIndex = 8;
        static const int kIvpTm = 8;
        static const int kTmmHash = 0x10;
        static const int kTmLmTime = 0x20; // IVP_Time_Manager -> last_time (float)
    #endif
    static const uint16_t kDeferUnused = 0xFFFF;

    typedef void (*Fn_remove_minlist)(void*, unsigned);
    static Fn_remove_minlist o_remove_minlist = 0;

    static inline float DeferLastTime(uintptr_t tm)
    {
        #if defined(CC_X86)
            return (float)(*(double*)(tm + kTmLmTime));
        #else
            return *(float*)(tm + kTmLmTime);
        #endif
    }

    void Phys::Patch::DeferEpsilonRefire(void* mindist, void* env)
    {
        int epsUs = Cfg().phys_defer_eps_us;
        if (!epsUs || !mindist || !env) return;
        if (!o_remove_minlist)
            o_remove_minlist = (Fn_remove_minlist)Sig::Get("patch.remove_minlist_elem");
        if (!o_remove_minlist) return;

        uintptr_t m = (uintptr_t)mindist;
        uint16_t idx = *(uint16_t*)(m + kMindistIndex);
        if (idx == kDeferUnused) return;

        uintptr_t tm = *(uintptr_t*)((char*)env + kIvpTm);
        if (!tm) return;
        uintptr_t mh = *(uintptr_t*)(tm + kTmmHash);
        if (!mh) return;
        uint16_t cap = *(uint16_t*)(mh + kMinListCap);
        if (idx >= cap) return;
        uintptr_t elems = *(uintptr_t*)(mh + kMinListElems);
        if (!elems) return;

        uintptr_t slot = elems + (uintptr_t)idx * kMinListElemSize;
        if (*(uintptr_t*)(slot + kMinListElemElement) != m) return;

        float value = *(float*)(slot + kMinListElemValue);
        float lastTime = DeferLastTime(tm);
        if ((double)(value - lastTime) >= (double)epsUs * 1e-6) return;

        o_remove_minlist((void*)mh, idx);
        *(uint16_t*)(m + kMindistIndex) = kDeferUnused;
        Log::Debug("[CC-PATCH] deferred epsilon refire (mindist 0x%lx, delta %.3fus)\n",
                   (unsigned long)m, (double)(value - lastTime) * 1000000.0);
    }

    void Phys::Patch::Init()
    {
        #if defined(CC_X86) || defined(CC_X64)
            Sig::Register(kPatchTargets, (int)(sizeof(kPatchTargets) / sizeof(kPatchTargets[0])));
            CrashCapture::Patch::Register(kPhysPatches, (int)(sizeof(kPhysPatches) / sizeof(kPhysPatches[0])));
        #endif
        #if defined(CC_X86)
            CrashCapture::Patch::Register(kPerfPatches, (int)(sizeof(kPerfPatches) / sizeof(kPerfPatches[0])));
        #endif
    }

    void Phys::Patch::RefreshToggles()
    {
        g_minlistSkipList = CrashCapture::Patch::Enabled("gm.phys.minlist_skip_list");
        g_minlistBoundA = CrashCapture::Patch::Enabled("gm.phys.minlist_walk_bound_a");
        g_minlistBoundB = CrashCapture::Patch::Enabled("gm.phys.minlist_walk_bound_b");
        g_minListMalloc = Sig::Get("patch.p_malloc");
        g_minListFree = Sig::Get("patch.p_free");
    }
}

#else

namespace CrashCapture {
    void Phys::Patch::Init() {}
    void Phys::Patch::RefreshToggles() {}
    void Phys::Patch::DeferEpsilonRefire(void*, void*) {}
}

#endif
