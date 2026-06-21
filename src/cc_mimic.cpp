// Crash Capture - preloader mimic patches
// version.dll proxy for the Windows client preload.
// better than forwarders as it breaks loading of some binaries like d3d9.

#include "crashcapture.h"

#if defined(INTERFACE_PRELOAD) && defined(CC_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// resolve a function from the genuine System32 (SysWOW64 for a 32-bit process)
static FARPROC RealVer(const char* name)
{
    static HMODULE h = NULL;
    if (!h) {
        char path[MAX_PATH];
        UINT n = GetSystemDirectoryA(path, MAX_PATH);
        if (n && n < MAX_PATH - 16) {
            lstrcatA(path, "\\version.dll"); // full path => the real one, not us
            h = LoadLibraryA(path);
        }
    }
    FARPROC p = h ? GetProcAddress(h, name) : NULL;
    if (!p) {
        HMODULE k = GetModuleHandleA("kernel32.dll");
        if (k) p = GetProcAddress(k, name);
    }
    return p;
}

// export cc_ver_<name> under the real <name>. On x86 WINAPI is __stdcall, so the
// internal symbol is decorated _cc_ver_<name>@<bytes>; x64 has no decoration
#ifdef _WIN64
    #define VER_EXPORT(name, bytes) \
        __pragma(comment(linker, "/EXPORT:" #name "=cc_ver_" #name))
#else
    #define VER_EXPORT(name, bytes) \
        __pragma(comment(linker, "/EXPORT:" #name "=_cc_ver_" #name "@" #bytes))
#endif

// one pass-through stub: cache the real proc on first call, then tail-call it
#define VER_STUB(ret, name, params, args, fail)                         \
    extern "C" ret WINAPI cc_ver_##name params {                        \
        typedef ret (WINAPI* Fn) params;                                \
        static Fn fn = (Fn)RealVer(#name);                              \
        return fn ? fn args : (ret)(fail);                              \
    }

VER_STUB(BOOL,  GetFileVersionInfoA,       (LPCSTR a, DWORD b, DWORD c, LPVOID d),            (a,b,c,d),     FALSE)
VER_STUB(BOOL,  GetFileVersionInfoW,       (LPCWSTR a, DWORD b, DWORD c, LPVOID d),           (a,b,c,d),     FALSE)
VER_STUB(BOOL,  GetFileVersionInfoByHandle,(DWORD a, HANDLE b, DWORD c, LPVOID d),            (a,b,c,d),     FALSE)
VER_STUB(BOOL,  GetFileVersionInfoExA,     (DWORD a, LPCSTR b, DWORD c, DWORD d, LPVOID e),   (a,b,c,d,e),   FALSE)
VER_STUB(BOOL,  GetFileVersionInfoExW,     (DWORD a, LPCWSTR b, DWORD c, DWORD d, LPVOID e),  (a,b,c,d,e),   FALSE)
VER_STUB(DWORD, GetFileVersionInfoSizeA,   (LPCSTR a, LPDWORD b),                             (a,b),         0)
VER_STUB(DWORD, GetFileVersionInfoSizeW,   (LPCWSTR a, LPDWORD b),                            (a,b),         0)
VER_STUB(DWORD, GetFileVersionInfoSizeExA, (DWORD a, LPCSTR b, LPDWORD c),                    (a,b,c),       0)
VER_STUB(DWORD, GetFileVersionInfoSizeExW, (DWORD a, LPCWSTR b, LPDWORD c),                   (a,b,c),       0)
VER_STUB(BOOL,  VerQueryValueA,            (LPCVOID a, LPCSTR b, LPVOID* c, PUINT d),         (a,b,c,d),     FALSE)
VER_STUB(BOOL,  VerQueryValueW,            (LPCVOID a, LPCWSTR b, LPVOID* c, PUINT d),        (a,b,c,d),     FALSE)
VER_STUB(DWORD, VerFindFileA,              (DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPSTR e, PUINT f, LPSTR g, PUINT h),       (a,b,c,d,e,f,g,h), 0)
VER_STUB(DWORD, VerFindFileW,              (DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPWSTR e, PUINT f, LPWSTR g, PUINT h),   (a,b,c,d,e,f,g,h), 0)
VER_STUB(DWORD, VerInstallFileA,           (DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e, LPCSTR f, LPSTR g, PUINT h),      (a,b,c,d,e,f,g,h), 0)
VER_STUB(DWORD, VerInstallFileW,           (DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e, LPCWSTR f, LPWSTR g, PUINT h),(a,b,c,d,e,f,g,h), 0)

// match the real System32 version.dll export set exactly
VER_EXPORT(GetFileVersionInfoA,        16)
VER_EXPORT(GetFileVersionInfoW,        16)
VER_EXPORT(GetFileVersionInfoByHandle, 16)
VER_EXPORT(GetFileVersionInfoExA,      20)
VER_EXPORT(GetFileVersionInfoExW,      20)
VER_EXPORT(GetFileVersionInfoSizeA,     8)
VER_EXPORT(GetFileVersionInfoSizeW,     8)
VER_EXPORT(GetFileVersionInfoSizeExA,  12)
VER_EXPORT(GetFileVersionInfoSizeExW,  12)
VER_EXPORT(VerQueryValueA,             16)
VER_EXPORT(VerQueryValueW,             16)
VER_EXPORT(VerFindFileA,               32)
VER_EXPORT(VerFindFileW,               32)
VER_EXPORT(VerInstallFileA,            32)
VER_EXPORT(VerInstallFileW,            32)

#endif // INTERFACE_PRELOAD && CC_WINDOWS
