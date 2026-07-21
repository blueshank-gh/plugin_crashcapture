// cc_hooking - see cc_hooking.h.

#include "tools/cc_hooking.h"
#include "crashcapture.h" // CC_X86 / CC_X64 / CC_WINDOWS
#include <stdint.h>
#include <string.h>

#if defined(CC_WINDOWS)
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
#endif

namespace CrashCapture {
    #if defined(CC_X64)
        static const bool kX64 = true;
        static const int kJmpLen = 14; // FF 25 00000000 <abs64>
    #else
        static const bool kX64 = false;
        static const int kJmpLen = 5; // E9 rel32
    #endif

    struct HookRec {
        unsigned char* target;
        unsigned char orig[32];
        int len; // bytes of prologue we saved/patched (0 == slot free)
        unsigned char* tramp;
    };
    static const int kMaxHooks = 64;
    static HookRec g_hooks[kMaxHooks];
    static int     g_nHooks = 0;

    // decode one instruction at p, returns its length, or 0 if we can't safely relocate it
    static int DecodeInsn(const unsigned char* p, int* ripDisp)
    { // this is unironically, painful, as hell.
        if (ripDisp) *ripDisp = -1;
        int i = 0;
        bool opsize = false;
        for (;;) { // yes I know this looks cursed.
            unsigned char b = p[i];
            if (b == 0x66) { opsize = true; ++i; continue; }
            if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { ++i; continue; }
            break;
        }
        if (kX64 && p[i] >= 0x40 && p[i] <= 0x4F) ++i; // REX prefix

        unsigned char op = p[i++];

        if (!kX64 && op >= 0x40 && op <= 0x4F) return i; // x86 inc/dec reg (REX range on x64)
        if (op >= 0x50 && op <= 0x5F) return i; // push/pop reg
        if (op == 0x90 || op == 0xC9 || op == 0xC3) return i; // nop / leave / ret
        if (op == 0x68) return i + (opsize ? 2 : 4); // push imm
        if (op == 0x6A) return i + 1; // push imm8

        bool hasModRM = false;
        int  imm = 0;
        if (op == 0x0F) {
            unsigned char op2 = p[i++];
            switch (op2) {
                case 0xEF: case 0x28: case 0x29: case 0x10: case 0x11:
                case 0x54: case 0x55: case 0x56: case 0x57:
                case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x17:
                case 0x6E: case 0x7E: case 0xD6: case 0x6F: case 0x7F:
                case 0x1E: case 0x1F: // endbr64 (F3 0F 1E FA) / multi-byte nop
                    hasModRM = true; break;
                default: return 0; // unknown two-byte opcode -> bail
            }
        } else {
            switch (op) {
                case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8D: case 0x63:
                case 0x00: case 0x01: case 0x02: case 0x03:
                case 0x08: case 0x09: case 0x0A: case 0x0B:
                case 0x20: case 0x21: case 0x22: case 0x23:
                case 0x28: case 0x29: case 0x2A: case 0x2B:
                case 0x30: case 0x31: case 0x32: case 0x33:
                case 0x38: case 0x39: case 0x3A: case 0x3B:
                case 0x84: case 0x85:
                    hasModRM = true; break;
                case 0x80: hasModRM = true; imm = 1; break;
                case 0x81: hasModRM = true; imm = opsize ? 2 : 4; break;
                case 0x83: hasModRM = true; imm = 1; break;
                case 0xC6: hasModRM = true; imm = 1; break;
                case 0xC7: hasModRM = true; imm = opsize ? 2 : 4; break;
                default: return 0; // unknown/relative -> bail
            }
        }
        if (hasModRM) {
            unsigned char m = p[i++];
            int mod = m >> 6, rm = m & 7;
            if (mod != 3) {
                if (rm == 4) { // SIB
                    unsigned char sib = p[i++];
                    if (mod == 0 && (sib & 7) == 5) i += 4;
                } else if (mod == 0 && rm == 5) {
                    if (kX64 && ripDisp) *ripDisp = i; // [rip+disp32] on x64 (abs on x86)
                    i += 4;
                }
                if (mod == 1) i += 1;
                else if (mod == 2) i += 4;
            }
        }
        return i + imm;
    }

    static bool Protect(void* addr, size_t len, bool writable)
    {
    #if defined(CC_WINDOWS)
        DWORD old;
        return VirtualProtect(addr, len, writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ, &old) != 0;
    #else
        long ps = sysconf(_SC_PAGESIZE);
        uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
        size_t span = ((uintptr_t)addr + len) - page;
        int prot = writable ? (PROT_READ | PROT_WRITE | PROT_EXEC) : (PROT_READ | PROT_EXEC);
        return mprotect((void*)page, span, prot) == 0;
    #endif
    }

    // allocate executable trampoline memory.
    // on x64 we try to place it near `nearTo` so any relocated RIP-relative disp32 stays in range.
    static unsigned char* AllocTramp(size_t len, void* nearTo)
    {
        #if defined(CC_WINDOWS)
            if (kX64 && nearTo) {
                SYSTEM_INFO si; GetSystemInfo(&si);
                uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
                uintptr_t target = (uintptr_t)nearTo;
                for (uintptr_t off = gran; off < 0x78000000; off += gran) {
                    uintptr_t cands[2] = { target - off, target + off };
                    for (int i = 0; i < 2; ++i) {
                        uintptr_t a = cands[i] & ~(uintptr_t)(gran - 1);
                        if (!a) continue;
                        MEMORY_BASIC_INFORMATION mbi;
                        if (VirtualQuery((void*)a, &mbi, sizeof(mbi)) && mbi.State == MEM_FREE) {
                            void* p = VirtualAlloc((void*)a, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                            if (p) return (unsigned char*)p;
                        }
                    }
                }
            }
            return (unsigned char*)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        #else
            void* hint = NULL;
            if (kX64 && nearTo)
                hint = (void*)(((uintptr_t)nearTo & ~(uintptr_t)0xFFFFF) - 0x200000); // ~2MB below, page-aligned
            void* p = mmap(hint, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED)
                p = mmap(NULL, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            return p == MAP_FAILED ? NULL : (unsigned char*)p;
        #endif
    }

    // write a jump to `dest` at `at`.
    // x86: rel32. x64: absolute via [rip+0].
    static void WriteJmp(unsigned char* at, const void* dest)
    {
    #if defined(CC_X64)
        at[0] = 0xFF; at[1] = 0x25;
        *(int32_t*)(at + 2) = 0;
        *(uint64_t*)(at + 6) = (uint64_t)dest;
    #else
        at[0] = 0xE9;
        *(int32_t*)(at + 1) = (int32_t)((const unsigned char*)dest - (at + 5));
    #endif
    }

    bool Hook::Install(void* target, void* detour, void** trampoline)
    {
        if (!target || !detour) return false;
        int slot = -1;
        for (int i = 0; i < g_nHooks; ++i) if (g_hooks[i].len == 0) { slot = i; break; }
        if (slot < 0) { if (g_nHooks >= kMaxHooks) return false; slot = g_nHooks; }

        unsigned char* t = (unsigned char*)target;

        // measure whole instructions until we cover the patch jump.
        int total = 0;
        int ripOff[8]; int nRip = 0;
        while (total < kJmpLen) {
            int rd = -1;
            int l = DecodeInsn(t + total, &rd);
            if (l <= 0) return false; // un-relocatable prologue -> refuse
            if (rd >= 0 && nRip < 8) ripOff[nRip++] = total + rd;
            total += l;
        }
        if (total > (int)sizeof(g_hooks[0].orig)) return false;

        unsigned char* tramp = AllocTramp((size_t)total + kJmpLen, target);
        if (!tramp) return false;

        memcpy(tramp, t, (size_t)total); // relocated prologue
        #if defined(CC_X64)
            // fix each RIP-relative disp32: new_disp = old_disp + (target - tramp).
            for (int i = 0; i < nRip; ++i) {
                int off = ripOff[i];
                int64_t delta = (int64_t)((uintptr_t)t - (uintptr_t)tramp);
                int64_t nd = (int64_t)(*(int32_t*)(tramp + off)) + delta;
                if (nd < INT32_MIN || nd > INT32_MAX) return false; // trampoline too far -> bail
                *(int32_t*)(tramp + off) = (int32_t)nd;
            }
        #else
            (void)ripOff; (void)nRip;
        #endif
        WriteJmp(tramp + total, t + total); // jump back to target+total

        if (!Protect(t, (size_t)total, true)) return false; // trampoline leaks here.
        HookRec* h = &g_hooks[slot];
        h->target = t; h->len = total; h->tramp = tramp;
        memcpy(h->orig, t, (size_t)total);

        WriteJmp(t, detour);
        for (int i = kJmpLen; i < total; ++i) t[i] = 0x90; // NOP-pad the tail of the last insn
        Protect(t, (size_t)total, false);

        if (slot == g_nHooks) ++g_nHooks;
        if (trampoline) *trampoline = tramp;
        return true;
    }

    static void RestoreRec(HookRec* h)
    {
        if (!h->len) return;
        if (Protect(h->target, (size_t)h->len, true)) {
            memcpy(h->target, h->orig, (size_t)h->len);
            Protect(h->target, (size_t)h->len, false);
        }
        h->len = 0;
    }

    bool Hook::Uninstall(void* target)
    {
        for (int i = 0; i < g_nHooks; ++i) {
            if (g_hooks[i].len && g_hooks[i].target == (unsigned char*)target) {
                RestoreRec(&g_hooks[i]);
                return true;
            }
        }
        return false;
    }

    void Hook::RemoveAll()
    {
        for (int i = 0; i < g_nHooks; ++i) RestoreRec(&g_hooks[i]);
        g_nHooks = 0;
    }

    int Hook::Count()
    {
        int n = 0;
        for (int i = 0; i < g_nHooks; ++i) if (g_hooks[i].len) ++n;
        return n;
    }

    #if defined(CC_WINDOWS)
        // TODO: DllMain DETACH hook...?
    #else
        __attribute__((destructor))
        static void AutoCleanupHooks() { Hook::RemoveAll(); }
    #endif
}