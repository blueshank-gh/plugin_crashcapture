// plugin_crashcapture - verbose crash + hang (watchdog) capture for Garry's Mod

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <atomic>

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

#if defined(DEBUG) || defined(_DEBUG)
    #define CC_CONFIG "debug"
#else
    #define CC_CONFIG "release"
#endif

// INTERFACE_PLUGIN -> server plugin (IGMODSERVERPLUGINCALLBACKS004), gets GameFrame.
// INTERFACE_PRELOAD -> client preload (version.dll mimic / .so), crash-only.
#ifdef INTERFACE_PLUGIN
    #define CC_SERVER 1
    #define CC_SIDE "server"
#else
    #define CC_CLIENT 1
    #define CC_SIDE "client"
#endif

#define CC_VERSION "1.5.0"
#define CC_BUILD __DATE__ " " __TIME__

namespace CrashCapture {
    // --------- cc-config ---
    struct Config {
        int timeout_sec;      // CRASHCAPTURE_TIMEOUT
        int hang_kill_sec;    // CRASHCAPTURE_HANG_KILL
        int max_age_days;     // CRASHCAPTURE_MAX_AGE_DAYS
        bool loopbreak;       // CRASHCAPTURE_LOOPBREAK
        bool phys_resume;     // CRASHCAPTURE_PHYS_RESUME
        bool phys_recover;    // CRASHCAPTURE_PHYS_RECOVER
        bool phys_pin;        // CRASHCAPTURE_PHYS_PIN
        bool debug;           // CRASHCAPTURE_DEBUG - enable Log::Debug traces
        bool phys_hook;       // CRASHCAPTURE_PHYS_HOOK
        int phys_hook_ms;     // CRASHCAPTURE_PHYS_HOOK_MS
        int report_debounce_sec; // CRASHCAPTURE_REPORT_DEBOUNCE
        bool hang_map;         // CRASHCAPTURE_HANG_MAP
        int hang_map_samples;  // CRASHCAPTURE_HANG_MAP_SAMPLES
        int hang_map_interval_ms; // CRASHCAPTURE_HANG_MAP_INTERVAL_MS
        int phys_resolve_delay; // CRASHCAPTURE_PHYS_RESOLVE_DELAY
        int phys_defer_eps_us; // CRASHCAPTURE_PHYS_DEFER_EPS_US (0 = off)
        bool firstchance;     // CRASHCAPTURE_FIRSTCHANCE
        bool window_watchdog; // CRASHCAPTURE_WINDOW_WATCHDOG
        bool lua_heartbeat;   // CRASHCAPTURE_LUA_HEARTBEAT
        bool manual_dump;     // CRASHCAPTURE_MANUAL_DUMP (SIGUSR1 / named event)
        bool console;         // CRASHCAPTURE_CONSOLE
        bool symbols;         // CRASHCAPTURE_SYMBOLS
        bool engine_error;    // CRASHCAPTURE_ENGINE_ERROR
        bool frame_profile;   // CRASHCAPTURE_FRAME_PROFILE
        bool profile;         // CRASHCAPTURE_PROFILE
        int profile_window;   // CRASHCAPTURE_PROFILE_WINDOW
        bool memapi;          // CRASHCAPTURE_MEMAPI
        bool patches;         // CRASHCAPTURE_PATCHES
        char dir[512];        // CRASHCAPTURE_DIR
        char script[512];     // CRASHCAPTURE_SCRIPT
    };
    Config& Cfg();
    const char* CfgRaw(const char* name);

    // --------- cc-lifecycle ---
    void Init();
    void InstallHandlers();
    void Shutdown();
    bool Ready();
    void Pulse();
    void Grace(int seconds);
    void DumpNow(const char* reason);
    const char* StallClassName(int cls);
    uint64_t MonotonicMs();
    void UtcStamp(char* out, size_t outsz);
    void UtcStampReadable(char* out, size_t outsz);

    typedef void (*SectionFn)(void* arg);
    bool RunProtected(SectionFn fn, void* arg);
    bool RunProtectedQuiet(SectionFn fn, void* arg);

    // --------- cc-log ---
    namespace Log {
        bool Open(const char* kind);
        void Close();
        bool OpenSession();
        void CloseSession();
        bool IsOpen();
        const char* Path();
        void Raw(const char* s, size_t len);
        void Str(const char* s);
        void F(const char* fmt, ...);
        void Notice(const char* fmt, ...);
        void Debug(const char* fmt, ...);
        void SetDebug(bool on);
        void OpenFence();
        void CloseFence();
        void Flush();
        void HexDump(const void* p, size_t n, uintptr_t labelBase);
        void Watermark();
        void PumpConsole();
        void Panic();
        void ClearPanic();
        void AppendNote(const char* path, const char* text); // append to an already-closed report
    }

    // --------- cc-modules ---
    struct CCModule {
        uintptr_t base;
        uintptr_t loadbase;
        size_t size;
        uintptr_t fileend;
        char name[96]; // basename only
    };
    struct CCThread {
        unsigned id;
        uintptr_t pc;   // 0 if not obtainable
        bool current;
        char name[32];  // empty if unknown
    };
    void FormatAddress(uintptr_t addr, char* out, size_t outsz);

    namespace Modules {
        int  Refresh();
        bool HasLua();
        uintptr_t Extent(const CCModule* m, size_t* sizeOut);
        uintptr_t FileExtent(const CCModule* m, size_t* sizeOut);
        const CCModule* Find(uintptr_t addr);
        const CCModule* FindByName(const char* needle);
        bool IsExactName(const CCModule* m, const char* needle);
        int  Snapshot(const CCModule** out);
        void Dump();
    }
    namespace Mem {
        bool IsReadable(const void* p, size_t n);
        bool IsExecutable(uintptr_t addr);
        bool Protect(void* addr, size_t len, bool writable, bool exec);
    }
    namespace Sym {
        void Init();
        void Cleanup();
        bool Resolve(uintptr_t addr, char* out, size_t outsz);    // true if it wrote a name
        bool ResolveRaw(uintptr_t addr, char* out, size_t outsz); // no demangling
        uintptr_t Lookup(const char* module, const char* name);   // name -> address; module optional (NULL = search all)
    }

    // --------- cc-lua ---
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

    namespace Lua {
        void OnInit(void* iface);
        void OnShutdown(void* iface);
        void MarkModuleLoad();
        bool HasBoundRealms();
        bool IfaceLive(void* iface);
        void RefreshStates();
        void Dump();
        bool BreakLoop(const char* msg);
        int  ArmBreakHook();
        void InstallHeartbeat(void* iface);
        void InstallHeartbeatAll();
        void InstallApi(void* iface);
        bool EnsureApi();
        bool InstallSideloadBootstrap();
        void* SharedHandle();
        void* Iface(int realm);
        void* Sym(void* mod, const char* name);
        void PollRecovery();
        void PollReady();
        int  CaptureTraces(CCLuaTrace* out, int maxRealms);
    }

    // --------- cc-recovery ---
    namespace Recovery {
        void NotePhysResume(const char* stall, const char* report);
        void NotePhysResolve(const int* ents, int n, const char* report, uint64_t downtimeMs);
        void NoteRecovered(const char* method, uint64_t downtimeMs, const char* stall, const char* reason, const char* report);
    }

    // --------- cc-hangmap ---
    namespace HangMap {
        void Reset();
        void Capture(uintptr_t pc, const uintptr_t* frames, int nframes);
        int Count();
        void Section(void* arg);
    }

    // --------- cc-physhook (Linux: detour IVP to prevent physics hangs) ---
    namespace Phys {
        namespace Bind { // IVP detour install/remove (named Bind so it doesn't shadow tools Hook::)
            void Init();
            bool Install();
            void Uninstall();
            uint64_t LagEpisodes();
            uint64_t LastLagTickMs();
        }
    }

    // --------- cc-diag ---
    namespace Diag { void Section(void* nativeCtx); }

    // --------- cc-api ---
    namespace Api {
        void* V1();
        void EmitReportSections();
    }

    // --------- cc-platform-handlers ---
    // there are different kinds of classified stalls/hangs now.
    enum StallClass { STALL_UNKNOWN = 0, STALL_NATIVE, STALL_PHYSICS, STALL_LUA_INTERP, STALL_LUA_JIT };
    extern volatile int g_lastStallClass;

    namespace Platform {
        void Install();
        void Uninstall();
        void DumpThread(const char* kind, const char* reason);
        int  Backtrace(void* ctx, uintptr_t* out, int max);
        uintptr_t ContextPC(void* ctx);
        bool IsGameThread();
        int  EnumThreads(CCThread* out, int max);
        int  RequestLuaBreak();
        int  RequestPhysResolve(const char* kind, const char* reason, bool writeReport); // classify(+dump if writeReport)+resume-if-physics (1 resumed, 0 handled-no-resume, <0 failed)
        int  HangMapBurst(int samples, int intervalMs); // sample the stuck game thread repeatedly
        int  SetPhysPaused(int paused);
        int  PhysPaused();
        void SuppressFurtherReports();
    }

    // --------- cc-report ---
    namespace Report {
        int  ClassifyStall(void* ctx, char* out, size_t outsz);
        void Registers(void* ctx);
        void NativeStack(void* ctx);
        void StackScan(void* ctx);
        const char* Meme();
        void Header(const char* kind, const char* reason);
        void Banner(const char* kind, const char* reason, const char* reportPath); // console-only banner; NULL path = no "report :" line
        void Footer();
        void SetContext(const char* kind, const char* reason, uintptr_t fault);
        void SetMapName(const char* name);
        const char* MapName();
        const char* Kind();
        const char* Reason();
        uintptr_t Fault();
        uint64_t Uptime();
        void Section(const char* title, SectionFn fn, void* arg, bool fenced);
    }

    // --------- cc-watchdog ---
    namespace Watchdog {
        void Start(bool deferredArm);
        void Stop();
        void Pulse();
        bool HangState(uint64_t* sinceMs);
    }
    extern std::atomic<uint64_t> g_lastPulseMs;
    extern std::atomic<uint64_t> g_graceUntilMs;
    extern std::atomic<uint64_t> g_graceAnchorPulse;

    #if defined(CC_WINDOWS)
        extern void* g_gameThreadHandle;
        extern unsigned g_gameThreadId;
    #else
        extern unsigned long g_gameThreadPthread; // pthread_t of pulsing thread
        extern int g_gameThreadTid; // gettid() of pulsing thread
    #endif
}
