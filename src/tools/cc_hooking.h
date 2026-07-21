// cc_hooking - minimal, dependency-free cross-platform inline hooks (x86 + x64).
// x86 -> 5-byte jmp rel32
// x64 -> 14-byte jmp [rip+0]+abs64

/*
// always make sure to have the right signature
typedef void (*target_func)(void* self, int a);

// this will store the original via trampoline
static target_func original_func = 0;
static void detour_func(void* self, int a) {
    // do what you want here.
    original_func(self, a);
}

// this will attempt to create the hook, returns false if it couldn't.
Hook::Install(target_ptr, (void*)detour_func, (void**)&original_func);

// this will remove the hook, restoring the function.
Hook::Uninstall(target_ptr);
*/

#pragma once
namespace CrashCapture {
    namespace Hook {
        bool Install(void* target, void* detour, void** trampoline);
        bool Uninstall(void* target);
        void RemoveAll();
        int  Count();
    }
}
