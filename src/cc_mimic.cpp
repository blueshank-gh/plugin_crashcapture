// Crash Capture - preloader mimic patches
// pass-through exports for the Windows client preload. the same binary can be
// renamed to version.dll, winmm.dll, winhttp.dll or wininet.dll: every export
// of all four System32 DLLs is present and forwards to the real one lazily.
// stubs beat PE forwarders, which the loader cannot resolve to a device path
// and which broke imports such as d3d9.

#include "crashcapture.h"

#if defined(INTERFACE_PRELOAD) && defined(CC_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#pragma section(".ccpx", read, execute)
#pragma comment(linker, "/SECTION:.ccpx,RWE")

extern "C" IMAGE_DOS_HEADER __ImageBase;

enum {
    PX_VERSION = 1,
    PX_WINMM   = 2,
    PX_WINHTTP = 4,
    PX_WININET = 8
};

static const char* const kPxDll[4] = { "version.dll", "winmm.dll", "winhttp.dll", "wininet.dll" };
static const unsigned kPxMask[4] = { PX_VERSION, PX_WINMM, PX_WINHTTP, PX_WININET };

#pragma pack(push, 1)
struct PxThunk {
#ifdef _WIN64
    unsigned char head[7];
    unsigned char pad0[3];
    unsigned char jump[6];
    void* target;
    const char* name;
    unsigned int mask;
    unsigned char pad1[12];
#else
    unsigned char head[5];
    unsigned char popEdx;
    unsigned char subEdx[3];
    unsigned char nop;
    unsigned char jump[6];
    void* target;
    const char* name;
    unsigned int mask;
    unsigned char pad1[4];
#endif
};

struct PxResolve {
#ifdef _WIN64
    unsigned char head[40];
    unsigned char jump[2];
    void* fn;
    unsigned char call[6];
    unsigned char tail[39];
    unsigned char pad[1];
#else
    unsigned char head[5];
    unsigned char movEax;
    void* fn;
    unsigned char tail[11];
    unsigned char pad[11];
#endif
};
#pragma pack(pop)

extern "C" void* PxResolveC(PxThunk* thunk);

extern "C" void* PxNull()
{
    return NULL;
}

#ifdef _WIN64
extern "C" __declspec(allocate(".ccpx")) __declspec(align(16)) PxResolve g_pxResolve = {
    { 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x48, 0x81, 0xEC, 0x68, 0, 0, 0,
      0xF3, 0x0F, 0x7F, 0x44, 0x24, 0x20, 0xF3, 0x0F, 0x7F, 0x4C, 0x24, 0x30,
      0xF3, 0x0F, 0x7F, 0x54, 0x24, 0x40, 0xF3, 0x0F, 0x7F, 0x5C, 0x24, 0x50,
      0x4C, 0x89, 0xD1 },
    { 0xEB, 0x08 },
    (void*)&PxResolveC,
    { 0xFF, 0x15, 0xF2, 0xFF, 0xFF, 0xFF },
    { 0xF3, 0x0F, 0x6F, 0x44, 0x24, 0x20, 0xF3, 0x0F, 0x6F, 0x4C, 0x24, 0x30,
      0xF3, 0x0F, 0x6F, 0x54, 0x24, 0x40, 0xF3, 0x0F, 0x6F, 0x5C, 0x24, 0x50,
      0x48, 0x81, 0xC4, 0x68, 0, 0, 0, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0xFF, 0xE0 },
    { 0xCC }
};
#else
extern "C" __declspec(allocate(".ccpx")) __declspec(align(16)) PxResolve g_pxResolve = {
    { 0x50, 0x51, 0x8B, 0xC2, 0x50 }, 0xB8, (void*)&PxResolveC,
    { 0xFF, 0xD0, 0x83, 0xC4, 0x04, 0x8B, 0xD0, 0x59, 0x58, 0xFF, 0xE2 },
    { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC }
};
#endif

static int PxOwnIndex()
{
    char path[MAX_PATH];
    if (!GetModuleFileNameA((HMODULE)&__ImageBase, path, MAX_PATH))
        return -1;

    const char* base = path;
    for (const char* p = path; *p; ++p) {
        if (*p == '\\' || *p == '/')
            base = p + 1;
    }

    for (int i = 0; i < 4; ++i) {
        if (lstrcmpiA(base, kPxDll[i]) == 0)
            return i;
    }
    return -1;
}

static HMODULE PxRealDll(unsigned int mask)
{
    static PVOID volatile loaded[4] = { NULL, NULL, NULL, NULL };

    int own = PxOwnIndex();
    int pick = -1;
    for (int i = 0; i < 4; ++i) {
        if ((mask & kPxMask[i]) == 0)
            continue;
        if (pick < 0)
            pick = i;
        if (i == own) {
            pick = i;
            break;
        }
    }
    if (pick < 0)
        return NULL;

    HMODULE h = (HMODULE)loaded[pick];
    if (h)
        return h;

    char path[MAX_PATH];
    UINT n = GetSystemDirectoryA(path, MAX_PATH);
    if (!n || n >= MAX_PATH - 16)
        return NULL;
    lstrcatA(path, "\\");
    lstrcatA(path, kPxDll[pick]);

    HMODULE real = LoadLibraryA(path);
    if (!real)
        return NULL;
    PVOID prev = InterlockedCompareExchangePointer(&loaded[pick], real, NULL);
    if (prev) {
        FreeLibrary(real);
        return (HMODULE)prev;
    }
    return real;
}

extern "C" void* PxResolveC(PxThunk* thunk)
{
    HMODULE h = PxRealDll(thunk->mask);
    FARPROC proc = h ? GetProcAddress(h, thunk->name) : NULL;
    void* target = proc ? (void*)proc : (void*)&PxNull;
    InterlockedExchangePointer((PVOID volatile*)&thunk->target, target);
    return target;
}

#ifdef _WIN64
#define PX_SYMBOL(name) "cc_px_" #name
#else
#define PX_SYMBOL(name) "_cc_px_" #name
#endif

#define PX_EXPORT(name) \
    __pragma(comment(linker, "/EXPORT:" #name "=" PX_SYMBOL(name) ",PRIVATE"))

#ifdef _WIN64
#define PX_INIT(name, mask) \
    { { 0x4C, 0x8D, 0x15, 0xF9, 0xFF, 0xFF, 0xFF }, { 0x90, 0x90, 0x90 }, \
      { 0xFF, 0x25, 0, 0, 0, 0 }, (void*)&g_pxResolve, name, mask, { 0 } }
#else
#define PX_INIT(name, mask) \
    { { 0xE8, 0, 0, 0, 0 }, 0x5A, { 0x83, 0xEA, 0x05 }, 0x90, \
      { 0xFF, 0xA2, 0x10, 0, 0, 0 }, (void*)&g_pxResolve, name, mask, { 0 } }
#endif

#define PX_THUNK(name, mask)                                                   \
    extern "C" __declspec(allocate(".ccpx")) __declspec(align(16)) PxThunk     \
        cc_px_##name = PX_INIT(#name, mask);                                   \
    PX_EXPORT(name)

#include "cc_mimic_exports.h"
CC_MIMIC_EXPORTS(PX_THUNK)

#ifndef _WIN64
// x86 link.exe drops one leading underscore from an export name
#pragma comment(linker, "/EXPORT:__GetFileExtensionFromUrl=_cc_px__GetFileExtensionFromUrl,PRIVATE")
#endif

#endif // INTERFACE_PRELOAD && CC_WINDOWS
