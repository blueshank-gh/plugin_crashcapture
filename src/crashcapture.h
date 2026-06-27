// plugin_crashcapture - verbose crash + hang (watchdog) capture for Garry's Mod

#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
    #define CC_WINDOWS 1
#elif defined(__linux__)
    #define CC_LINUX 1
#endif

#if defined(__x86_64__) || defined(_M_X64)
    #define CC_X64 1
    #define CC_ARCH "x64"
#elif defined(__i386__) || defined(_M_IX86)
    #define CC_X86 1
    #define CC_ARCH "x86"
#endif

#if defined(CC_WINDOWS)
    #define CC_OS "windows"
#else
    #define CC_OS "linux"
#endif

// INTERFACE_PLUGIN -> server plugin (IGMODSERVERPLUGINCALLBACKS004), gets GameFrame.
// INTERFACE_PRELOAD -> client preload (version.dll mimic / .so), crash-only.
#ifdef INTERFACE_PLUGIN
    #define CC_SIDE "server"
#else
    #define CC_SIDE "client"
#endif

#define CC_VERSION "1.0"

namespace CrashCapture {
    // --------- cc-config ---
    struct Config {
        int timeout_sec;      // CRASHCAPTURE_TIMEOUT
        int hang_kill_sec;    // CRASHCAPTURE_HANG_KILL
        int max_age_days;     // CRASHCAPTURE_MAX_AGE_DAYS
        bool loopbreak;       // CRASHCAPTURE_LOOPBREAK
        bool phys_resume;     // CRASHCAPTURE_PHYS_RESUME (Linux only, sad)
        bool firstchance;     // CRASHCAPTURE_FIRSTCHANCE
        bool window_watchdog; // CRASHCAPTURE_WINDOW_WATCHDOG
        bool lua_heartbeat;   // CRASHCAPTURE_LUA_HEARTBEAT
        bool console;         // CRASHCAPTURE_CONSOLE
        bool symbols;         // CRASHCAPTURE_SYMBOLS
        char dir[512];        // CRASHCAPTURE_DIR
        char script[512];     // CRASHCAPTURE_SCRIPT
    };
    Config& Cfg();

    // --------- cc-lifecycle ---
    void Init();
    void InstallHandlers();
    void Shutdown();
    void Pulse();
    void Grace(int seconds);
    void DumpNow(const char* reason);

    // --------- cc-log ---
    namespace Log {
        bool Open(const char* kind);
        void Close();
        bool IsOpen();
        const char* Path();
        void Raw(const char* s, size_t len);
        void Str(const char* s);
        void F(const char* fmt, ...);
        void Notice(const char* fmt, ...);
        void OpenFence();
        void CloseFence();
        void Flush();
        void HexDump(const void* p, size_t n, uintptr_t labelBase);
        void EnableConsole();
        void AppendNote(const char* path, const char* text); // append to an already-closed report
    }

    // --------- cc-modules ---
    struct CCModule {
        uintptr_t base;
        size_t size;
        char name[96]; // basename only
    };
    int  Modules_Refresh();
    bool Modules_HasLua();
    const CCModule* Modules_Find(uintptr_t addr);
    const CCModule* Modules_FindByName(const char* needle);
    int  Modules_Snapshot(const CCModule** out);
    void Modules_Dump();
    bool Mem_IsReadable(const void* p, size_t n);
    bool Mem_IsExecutable(uintptr_t addr);
    void FormatAddress(uintptr_t addr, char* out, size_t outsz);

    void Sym_Init();
    void Sym_Cleanup();
    bool Sym_Resolve(uintptr_t addr, char* out, size_t outsz); // true if it wrote a name
    uintptr_t Sym_Lookup(const char* module, const char* name); // name -> address; module optional (NULL = search all)

    struct CCThread {
        unsigned id;
        uintptr_t pc;   // 0 if not obtainable
        bool current;
        char name[32];  // empty if unknown
    };
    int Platform_EnumThreads(CCThread* out, int max);

    // --------- cc-lua ---
    void Lua_OnInit(void* iface);
    void Lua_OnShutdown(void* iface);
    bool Lua_HasBoundRealms();
    void Lua_RefreshStates();
    void Lua_Dump();
    bool Lua_BreakLoop(const char* msg);
    int  Lua_ArmBreakHook();
    void Lua_InstallHeartbeat(void* iface);
    void Lua_InstallHeartbeatAll();
    void Lua_InstallApi(void* iface);
    bool Lua_EnsureApi();
    void* Lua_SharedHandle();
    void* Lua_Sym(void* mod, const char* name);

    struct CCLuaFrame {
        int level;
        int currentline;
        char source[80];
        char name[64];
        char what[24];
        char locals[256];
    };
    struct CCLuaTrace {
        char realm[16];
        int top;
        int frameCount;
        CCLuaFrame frames[24];
    };
    int Lua_CaptureTraces(CCLuaTrace* out, int maxRealms);

    // --------- cc-diag ---
    void Diag_Section(void* nativeCtx);

    // --------- cc-platform-handlers ---
    void Platform_Install();
    void Platform_Uninstall();
    void Platform_DumpThread(const char* kind, const char* reason);
    int Platform_Backtrace(void* ctx, uintptr_t* out, int max);
    uintptr_t Platform_ContextPC(void* ctx);

    // there are different kinds of classified stalls/hangs now.
    enum StallClass { STALL_UNKNOWN = 0, STALL_NATIVE, STALL_PHYSICS, STALL_LUA_INTERP, STALL_LUA_JIT };
    extern volatile int g_lastStallClass;
    int Report_ClassifyStall(void* ctx, char* out, size_t outsz);
    int Platform_RequestLuaBreak();

    typedef void (*SectionFn)(void* arg);
    bool RunProtected(SectionFn fn, void* arg);
    bool RunProtectedQuiet(SectionFn fn, void* arg);

    void Report_Registers(void* ctx);
    void Report_NativeStack(void* ctx);
    void Report_StackScan(void* ctx);

    // --------- cc-shared ---
    void Report_Header(const char* kind, const char* reason);
    void Report_Footer();
    void Report_SetContext(const char* kind, const char* reason, uintptr_t fault);
    const char* Report_Kind();
    const char* Report_Reason();
    uintptr_t Report_Fault();
    uint64_t Report_Uptime();
    void Report_Section(const char* title, SectionFn fn, void* arg, bool fenced);
    uint64_t MonotonicMs();
    void UtcStamp(char* out, size_t outsz);

    void Watchdog_Start(bool deferredArm);
    void Watchdog_Stop();
    void Watchdog_Pulse();
    extern volatile uint64_t g_lastPulseMs;
    extern volatile uint64_t g_graceUntilMs;

    #if defined(CC_WINDOWS)
        extern void* g_gameThreadHandle;
        extern unsigned g_gameThreadId;
    #else
        extern unsigned long g_gameThreadPthread; // pthread_t of pulsing thread
        extern int g_gameThreadTid; // gettid() of pulsing thread
    #endif
}
