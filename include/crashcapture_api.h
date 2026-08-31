// plugin_crashcapture - public C API for third-party binaries

#ifndef CRASHCAPTURE_API_H
#define CRASHCAPTURE_API_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRASHCAPTURE_INTERFACE "CRASHCAPTURE001"
#define CC_API_VER 1

// Passed to add_section callbacks at report-write time.
typedef struct CCSectionCtx {
    void* impl;

    // append one or more lines of text (include your own \n)
    void (*print)(struct CCSectionCtx* ctx, const char* text);
    
    // printf-style append; output is truncated to ~1024 chars per call
    void (*format)(struct CCSectionCtx* ctx, const char* fmt, ...);
} CCSectionCtx;

typedef void (*CCSectionFn)(void* user, CCSectionCtx* w);

typedef struct CCAPI {
    unsigned size;
    unsigned version;

    // static strings, any thread
    const char* (*version_str)(void);
    const char* (*build_str)(void);
    const char* (*side_str)(void);
    const char* (*os_str)(void);
    const char* (*arch_str)(void);

    // 1 while the watchdog is handling a freeze (both the heartbeat and the Windows window-probe detector).
    // 0 otherwise, 0 before init.
    // SAFETY: Any thread
    int (*is_hung)(void);

    // milliseconds since the watchdog declared the current freeze, 0 if not hung.
    // SAFETY: Any thread
    unsigned long long (*hung_since_ms)(void);

    // STALL_UNKNOWN=0 STALL_NATIVE=1 STALL_PHYSICS=2 STALL_LUA_INTERP=3 STALL_LUA_JIT=4
    // SAFETY: Any thread
    int (*stall_class)(void);

    // "unknown"/"native"/"physics"/"lua"/"lua-jit" for a class number.
    // SAFETY: Any thread
    const char* (*stall_class_name)(int cls);

    // milliseconds since the last heartbeat pulse; 0 if none has happened yet.
    // Build your own liveness logic on this if is_hung is too unstable.
    // SAFETY: Any thread
    unsigned long long (*ms_since_pulse)(void);

    // read-only lookup of launch/runtime settings (CRASHCAPTURE_* names, with or without the prefix), NULL for unknown keys.
    // SAFETY: Any thread
    const char* (*config_get)(const char* name);

    // report folder as configured (may be relative).
    // SAFETY: Any thread
    const char* (*report_dir)(void);

    // path of the report/session file currently open, else NULL.
    // The buffer is only valid until the next report opens, copy it if you keep it.
    // SAFETY: Any thread
    const char* (*log_path)(void);

    // milliseconds since crashcapture initialized.
    // SAFETY: Any thread
    unsigned long long (*uptime_ms)(void);

    // current map name, NULL when unknown.
    // SAFETY: Any thread
    const char* (*map_name)(void);

    // Returns 1 written, 0 skipped (not initialized, or another dump/report already in flight - fail-fast, never blocks).
    // Reason is truncated to 256 chars. Any live thread, never a crash context.
    // SAFETY: Any live thread, never a crash context
    int (*dump)(const char* reason);

    // feed the heartbeat (only useful if crashcapture is not already pulsing via the plugin GameFrame or the lua timer).
    // SAFETY: Game thread
    void (*pulse)(void);

    // suppress freeze detection for the next N seconds (planned heavy work, map loads).
    // Clamped to 0 < seconds <= 86400.
    // SAFETY: Any thread
    void (*grace)(int seconds);

    // register a key/value line shown in a "Third-party data" report section.
    // Both strings are copied (key <= 47 chars, value <= 255 chars) and stay until overwritten or cleared.
    // Returns 1 stored, 0 table full.
    // SAFETY: Game thread
    int (*set_data)(const char* key, const char* value);

    // remove a key previously set with set_data.
    // SAFETY: Game thread
    void (*clear_data)(const char* key);

    // register a report section that runs at report-write time.
    // The callback runs wrapped in crashcapture's crash protection.
    // If it faults, the section is skipped so the report survives.
    // See CCSectionCtx for more details.
    // SAFETY: Game thread
    int (*add_section)(const char* name, CCSectionFn fn, void* user);

    // unregister a section added with add_section.
    // Call before your module unloads or its callback pointer dangles.
    // !!! Not calling this can lead to crashes if the callback pointer is freed or moved !!!
    // SAFETY: Game thread
    void (*remove_section)(const char* name);

    // walk the calling thread's native stack (return addresses).
    // Returns the number of addresses written, capped at 64.
    // SAFETY: Live threads only, not from crash/signal context.
    int (*backtrace)(unsigned long long* out, int max);

    // symbolize one address ("name+0xoff (file:line)" when debug info allows).
    // Returns 1 wrote a name, 0 failed or the symbol engine is busy (it is shared with the report path and fail-fast, never blocks).
    // SAFETY: Live threads only
    int (*resolve)(unsigned long long addr, char* out, unsigned outsz);
} CCAPI;

// true when api is non-NULL, is at least version 1, and is big enough to
// contain the first minSize bytes (pass sizeof of a trailing-subset struct you
// actually use, or sizeof(CCAPI) for everything).
#define CC_API_OK(api, minSize) \
    ((api) != 0 && (api)->version >= CC_API_VER && (api)->size >= (unsigned)(minSize))

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <windows.h>
    #include <tlhelp32.h>

    static CCAPI* CC_FIND_API(void)
    {
        typedef void* (*CCCreateInterfaceFn)(const char* name, int* returncode);
        static const wchar_t* kNames[] = {
            L"version.dll",
            L"plugin_crashcapture86_sv.dll", L"plugin_crashcapture64_sv.dll",
            L"plugin_crashcapture86_cl.dll", L"plugin_crashcapture64_cl.dll",
            L"gmsv_crashcapture_win32.dll", L"gmsv_crashcapture_win64.dll",
            L"gmcl_crashcapture_win32.dll", L"gmcl_crashcapture_win64.dll",
        };
        int tryCount = (int)(sizeof(kNames) / sizeof(kNames[0]));

        for (int i = 0; i < tryCount; ++i) {
            HMODULE h = GetModuleHandleW(kNames[i]);
            if (!h) continue;
            CCCreateInterfaceFn f = (CCCreateInterfaceFn)GetProcAddress(h, "CreateInterface");
            if (!f) continue;
            int rc = 1;
            CCAPI* api = (CCAPI*)f(CRASHCAPTURE_INTERFACE, &rc);
            if (rc == 0 && api && api->version >= CC_API_VER &&
                api->size >= 64 && api->size <= 4096)
                return api;
        }

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (snap == INVALID_HANDLE_VALUE) return NULL;
        MODULEENTRY32W me;
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                wchar_t low[MAX_MODULE_NAME32 + 1];
                int n = 0;
                for (; me.szModule[n] && n < MAX_MODULE_NAME32; ++n) {
                    wchar_t c = me.szModule[n];
                    low[n] = (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;
                }
                low[n] = 0;
                if (!wcsstr(low, L"crashcapture")) continue;
                CCCreateInterfaceFn f = (CCCreateInterfaceFn)GetProcAddress(me.hModule, "CreateInterface");
                if (!f) continue;
                int rc = 1;
                CCAPI* api = (CCAPI*)f(CRASHCAPTURE_INTERFACE, &rc);
                if (rc == 0 && api && api->version >= CC_API_VER &&
                    api->size >= 64 && api->size <= 4096)
                    return api;
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return NULL;
    }

#else
    #include <dlfcn.h>
    #include <link.h>
    #include <string.h>
    #include <stdio.h>

    struct CCPhdrNames001 { char names[4][512]; int count; };

    static int CCPhdrCb001(struct dl_phdr_info* info, size_t size, void* arg)
    {
        struct CCPhdrNames001* p = (struct CCPhdrNames001*)arg;
        (void)size;
        const char* name = info->dlpi_name;
        if (!name || !*name || p->count >= 4) return 0;
        if (!strstr(name, "crashcapture")) return 0;
        snprintf(p->names[p->count], sizeof(p->names[0]), "%s", name);
        p->count++;
        return 0;
    }

    static CCAPI* CC_FIND_API(void)
    {
        typedef void* (*CCCreateInterfaceFn)(const char* name, int* returncode);
        struct CCPhdrNames001 p;
        memset(&p, 0, sizeof(p));
        dl_iterate_phdr(CCPhdrCb001, &p);

        for (int i = 0; i < p.count; ++i) {
            void* h = dlopen(p.names[i], RTLD_NOW | RTLD_NOLOAD);
            if (!h) continue;
            CCCreateInterfaceFn f = (CCCreateInterfaceFn)dlsym(h, "CreateInterface");
            int rc = 1;
            CCAPI* api = f ? (CCAPI*)f(CRASHCAPTURE_INTERFACE, &rc) : NULL;
            dlclose(h);
            if (f && rc == 0 && api && api->version >= CC_API_VER &&
                api->size >= 64 && api->size <= 4096)
                return api;
        }
        return NULL;
    }
#endif

// Simple wrapper to ensure the API is valid.
static CCAPI* CC_ENSURE_API()
{
    CCAPI* api = CC_FIND_API();
    return CC_API_OK(api, sizeof(CCAPI)) ? api : NULL;
}

#ifdef __cplusplus
}
#endif

#endif
