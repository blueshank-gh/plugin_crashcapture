// Lifecycle, configuration and shared report sections.

#include "crashcapture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(CC_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <dirent.h>
#endif

namespace CrashCapture {
    static bool g_initialized = false;
    static uint64_t g_startMs = 0;

    Config& Cfg()
    {
        static Config cfg;
        return cfg;
    }

    uint64_t MonotonicMs()
    {
    #if defined(CC_WINDOWS)
        return (uint64_t)GetTickCount64();
    #else
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
    #endif
    }

    // Async-safe UTC breakdown (civil_from_days); localtime_r locks, unsafe in a handler.
    void UtcStamp(char* out, size_t outsz)
    {
        long long t = (long long)time(NULL);
        int sec = (int)(((t % 86400) + 86400) % 86400);
        long long days = (t - sec) / 86400;

        long long z = days + 719468;
        long long era = (z >= 0 ? z : z - 146096) / 146097;
        unsigned doe = (unsigned)(z - era * 146097);
        unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        long long y = (long long)yoe + era * 400;
        unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        unsigned mp = (5 * doy + 2) / 153;
        unsigned d = doy - (153 * mp + 2) / 5 + 1;
        unsigned m = mp + (mp < 10 ? 3 : -9);
        y += (m <= 2);

        snprintf(out, outsz, "%04lld%02u%02u_%02d%02d%02d",
                y, m, d, sec / 3600, (sec / 60) % 60, sec % 60);
    }

    static int EnvInt(const char* name, int def)
    {
        const char* v = getenv(name);
        if (!v || !*v) return def;
        return atoi(v);
    }

    static void LoadConfig()
    {
        Config& c = Cfg();
        c.timeout_sec = EnvInt("CRASHCAPTURE_TIMEOUT", 10);
        c.hang_kill_sec = EnvInt("CRASHCAPTURE_HANG_KILL", 0);
        c.max_age_days = EnvInt("CRASHCAPTURE_MAX_AGE_DAYS", 0);
        c.loopbreak = EnvInt("CRASHCAPTURE_LOOPBREAK", 1) != 0;
        
        // First-chance VEH off on the client: the D3D/ShaderAPI bring-up uses SEH as control flow and intercepting it can break startup.
        #ifdef INTERFACE_PLUGIN
            c.firstchance = EnvInt("CRASHCAPTURE_FIRSTCHANCE", 1) != 0;
        #else
            c.firstchance = EnvInt("CRASHCAPTURE_FIRSTCHANCE", 0) != 0;
        #endif
        
        c.window_watchdog = EnvInt("CRASHCAPTURE_WINDOW_WATCHDOG", 1) != 0;
        c.lua_heartbeat = EnvInt("CRASHCAPTURE_LUA_HEARTBEAT", 1) != 0;
        c.console = EnvInt("CRASHCAPTURE_CONSOLE", 0) != 0;
        c.symbols = EnvInt("CRASHCAPTURE_SYMBOLS", 1) != 0;

        // store crashes in <gmod-root>/crashes
        const char* dir = getenv("CRASHCAPTURE_DIR");
        if (!dir || !*dir) dir = "crashes";
        snprintf(c.dir, sizeof(c.dir), "%s", dir);

        // optional Lua script for live memory diagnostics on a crash
        const char* script = getenv("CRASHCAPTURE_SCRIPT");
        snprintf(c.script, sizeof(c.script), "%s", script ? script : "");

        #if defined(CC_WINDOWS)
            CreateDirectoryA(c.dir, NULL);
        #else
            mkdir(c.dir, 0777);
        #endif
    }

    static int PruneOldReports()
    {
        int days = Cfg().max_age_days;
        if (days <= 0) return 0;
        const char* dir = Cfg().dir;
        int deleted = 0;

        #if defined(CC_WINDOWS)
            char pattern[1100];
            snprintf(pattern, sizeof(pattern), "%s\\*.md", dir);
            WIN32_FIND_DATAA fd;
            HANDLE h = FindFirstFileA(pattern, &fd);
            if (h == INVALID_HANDLE_VALUE) return 0;

            FILETIME nowft;
            GetSystemTimeAsFileTime(&nowft);
            ULARGE_INTEGER now;
            now.LowPart = nowft.dwLowDateTime;
            now.HighPart = nowft.dwHighDateTime;
            ULONGLONG maxAge = (ULONGLONG)days * 24ull * 3600ull * 10000000ull; // 100ns units

            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                ULARGE_INTEGER w;
                w.LowPart = fd.ftLastWriteTime.dwLowDateTime;
                w.HighPart = fd.ftLastWriteTime.dwHighDateTime;
                if (now.QuadPart > w.QuadPart && (now.QuadPart - w.QuadPart) > maxAge) {
                    char full[1200];
                    snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
                    if (DeleteFileA(full)) ++deleted;
                }
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        #else
            DIR* d = opendir(dir);
            if (!d) return 0;
            time_t now = time(NULL);
            time_t maxAge = (time_t)days * 24 * 3600;
            struct dirent* e;
            while ((e = readdir(d)) != NULL) {
                const char* nm = e->d_name;
                size_t len = strlen(nm);
                if (len < 4 || strcmp(nm + len - 3, ".md") != 0) continue;
                char full[1200];
                snprintf(full, sizeof(full), "%s/%s", dir, nm);
                struct stat st;
                if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;
                if (now > st.st_mtime && (now - st.st_mtime) > maxAge) {
                    if (unlink(full) == 0) ++deleted;
                }
            }
            closedir(d);
        #endif

        if (deleted > 0)
            Log::F("[CrashCapture] pruned %d old report(s) (older than %d day(s)) from %s\n",
                   deleted, days, dir);
        return deleted;
    }

    void Init()
    {
        if (g_initialized) return;

        {
            const char* dis = getenv("CRASHCAPTURE_DISABLE");
            if (dis && atoi(dis) != 0) { g_initialized = true; return; }
        }

        g_initialized = true;
        g_startMs = MonotonicMs();

        LoadConfig();
        PruneOldReports();

        // client preloading can cause issues of loading into telemetry, this fixes that.
        bool deferArm = false;
        #if defined(CC_WINDOWS) && defined(INTERFACE_PRELOAD)
            deferArm = Cfg().window_watchdog && Cfg().timeout_sec > 0;
            if (deferArm && !getenv("CRASHCAPTURE_FIRSTCHANCE"))
                Cfg().firstchance = true;
        #endif
        if (deferArm) {
            Watchdog_Start(true); // gate thread installs handlers once lua appears
            return;
        }

        InstallHandlers();
        if (Cfg().timeout_sec > 0)
            Watchdog_Start(false);
    }

    // Resolve modules + Lua, install handlers, print the armed banner.
    void InstallHandlers()
    {
        if (Cfg().console) Log::EnableConsole();

        Modules_Refresh();
        Lua_RefreshStates();
        Platform_Install();

        // Armed banner with the absolute report dir (resolves cwd ambiguity).
        #if defined(CC_WINDOWS)
            char abdir[1024] = {0};
            if (!GetFullPathNameA(Cfg().dir, sizeof(abdir), abdir, NULL))
                snprintf(abdir, sizeof(abdir), "%s", Cfg().dir);
        #else
            char abdir[1024] = {0};
            {
                char cwd[1024] = {0};
                if (getcwd(cwd, sizeof(cwd))) snprintf(abdir, sizeof(abdir), "%s/%s", cwd, Cfg().dir);
                else snprintf(abdir, sizeof(abdir), "%s", Cfg().dir);
            }
        #endif
        Log::F("CrashCapture - v" CC_VERSION " " CC_OS "/" CC_ARCH "/" CC_SIDE " - " __TIME__ " " __DATE__
            "\nreports -> %s\n", abdir);
    }

    void Shutdown()
    {
        if (!g_initialized) return;
        Watchdog_Stop();
        Platform_Uninstall();
        g_initialized = false;
        Log::Str("[CrashCapture] disarmed.\n");
    }

    void Pulse()
    {
        Watchdog_Pulse();
    }

    void Grace(int seconds)
    {
        uint64_t until = MonotonicMs() + (uint64_t)seconds * 1000ull;
        if (until > g_graceUntilMs) g_graceUntilMs = until;
    }

    void DumpNow(const char* reason)
    {
        Platform_DumpThread("dump", reason ? reason : "manual dump_now");
    }

    // --------- core-report ---

    static char g_ctxKind[64] = {0};
    static char g_ctxReason[256] = {0};
    static uintptr_t g_ctxFault = 0;

    void Report_SetContext(const char* kind, const char* reason, uintptr_t fault)
    {
        snprintf(g_ctxKind, sizeof(g_ctxKind), "%s", kind ? kind : "");
        snprintf(g_ctxReason, sizeof(g_ctxReason), "%s", reason ? reason : "");
        g_ctxFault = fault;
    }
    const char* Report_Kind() { return g_ctxKind; }
    const char* Report_Reason() { return g_ctxReason; }
    uintptr_t Report_Fault() { return g_ctxFault; }
    uint64_t Report_Uptime() { return MonotonicMs() - g_startMs; }

    void Report_Header(const char* kind, const char* reason)
    {
        char stamp[32];
        UtcStamp(stamp, sizeof(stamp));

        Log::F("# Crash Capture\n\n");
        Log::F("- **type** : `%s`\n", kind);
        Log::F("- **reason** : `%s`\n", reason ? reason : "-");
        Log::F("- **build** : v" CC_VERSION " " CC_OS "/" CC_ARCH "/" CC_SIDE " (" __DATE__ " " __TIME__ ")\n");
        Log::F("- **time** : %s UTC (epoch %lld)\n", stamp, (long long)time(NULL));
        Log::F("- **uptime** : %llu ms since init\n", (unsigned long long)(MonotonicMs() - g_startMs));
        #if defined(CC_WINDOWS)
            Log::F("- **process** : pid=%u\n", (unsigned)GetCurrentProcessId());
        #else
            Log::F("- **process** : pid=%u\n", (unsigned)getpid());
        #endif
        if (g_lastPulseMs)
            Log::F("- **pulse** : last heartbeat %llu ms ago\n",
                (unsigned long long)(MonotonicMs() - g_lastPulseMs));
        else Log::Str("- **pulse** : never (no heartbeat source in this configuration)\n");
        Log::Flush();

        Log::Notice("\n======================= CrashCapture =======================\n");
        Log::Notice("  %s detected\n", kind ? kind : "event");
        Log::Notice("  reason : %s\n", reason ? reason : "-");
        Log::Notice("  report : %s\n", Log::Path());
        Log::Notice("============================================================\n\n");
    }

    void Report_Footer()
    {
        Log::F("\n---\n\n_END OF REPORT (%s)_\n\n", Log::Path());
        Log::Flush();
    }

    void Report_Section(const char* title, SectionFn fn, void* arg, bool fenced)
    {
        Log::F("\n## %s\n\n", title);
        if (fenced) Log::OpenFence();
        RunProtected(fn, arg);
        Log::CloseFence();
        Log::Flush();
    }
}
