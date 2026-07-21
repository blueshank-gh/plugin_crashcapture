// Lifecycle, configuration and shared report sections.

#include "crashcapture.h"
#include "features/cc_physrecover.h"

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
    #include <fcntl.h>
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

    static const char* CmdlineLookup(const char* name)
    {
        static char buf[8192];
        static char val[512];
        char* toks[256];
        int nt = 0;

        #if defined(CC_WINDOWS)
            const char* cl = GetCommandLineA();
            if (!cl) return NULL;
            snprintf(buf, sizeof(buf), "%s", cl);
            char* p = buf; // tokenize in place, honoring double quotes
            while (*p && nt < 256) {
                while (*p == ' ' || *p == '\t') ++p;
                if (!*p) break;
                char* start;
                if (*p == '"') { ++p; start = p; while (*p && *p != '"') ++p; }
                else           { start = p; while (*p && *p != ' ' && *p != '\t') ++p; }
                if (*p) *p++ = 0;
                toks[nt++] = start;
            }
        #else
            int fd = open("/proc/self/cmdline", O_RDONLY);
            if (fd < 0) return NULL;
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n <= 0) return NULL;
            buf[n] = 0;
            char* p = buf; char* end = buf + n; // argv are NUL-separated
            while (p < end && nt < 256) { toks[nt++] = p; p += strlen(p) + 1; }
        #endif

        for (int i = 0; i < nt; ++i) {
            const char* t = toks[i];
            if ((t[0] == '-' || t[0] == '+') && strcmp(t + 1, name) == 0) {
                if (i + 1 < nt && toks[i + 1][0] != '-' && toks[i + 1][0] != '+') {
                    snprintf(val, sizeof(val), "%s", toks[i + 1]);
                    return val;
                }
                return "1";
            }
        }
        return NULL;
    }

    static const char* CfgRaw(const char* name)
    {
        const char* v = getenv(name);
        if (v && *v) return v;
        return CmdlineLookup(name);
    }

    static int EnvInt(const char* name, int def)
    {
        const char* v = CfgRaw(name);
        if (!v || !*v) return def;
        return atoi(v);
    }

    static void LoadConfig()
    {
        Config& c = Cfg();
        c.timeout_sec = EnvInt("CRASHCAPTURE_TIMEOUT", 10);
        c.hang_kill_sec = EnvInt("CRASHCAPTURE_HANG_KILL", 0);
        c.max_age_days = EnvInt("CRASHCAPTURE_MAX_AGE_DAYS", 14);
        c.loopbreak = EnvInt("CRASHCAPTURE_LOOPBREAK", 1) != 0;
        c.phys_resume = EnvInt("CRASHCAPTURE_PHYS_RESUME", 1) != 0;
        c.phys_recover = EnvInt("CRASHCAPTURE_PHYS_RECOVER", 1) != 0;
        c.phys_pin = EnvInt("CRASHCAPTURE_PHYS_PIN", 0) != 0;
        c.debug = EnvInt("CRASHCAPTURE_DEBUG", 0) != 0;
        Log::SetDebug(c.debug);
        c.phys_hook = EnvInt("CRASHCAPTURE_PHYS_HOOK", 1) != 0;
        c.phys_hook_ms = EnvInt("CRASHCAPTURE_PHYS_HOOK_MS", 250);
        if (c.phys_hook_ms < 20) c.phys_hook_ms = 20;
        c.report_debounce_sec = EnvInt("CRASHCAPTURE_REPORT_DEBOUNCE", 15);
        if (c.report_debounce_sec < 0) c.report_debounce_sec = 0;
        c.phys_resolve_delay = EnvInt("CRASHCAPTURE_PHYS_RESOLVE_DELAY", 3);
        if (c.phys_resolve_delay < 0) c.phys_resolve_delay = 0;

        // First-chance VEH off on the client: the D3D/ShaderAPI bring-up uses SEH as control flow and intercepting it can break startup.
        #ifdef INTERFACE_PLUGIN
            c.firstchance = EnvInt("CRASHCAPTURE_FIRSTCHANCE", 1) != 0;
        #else
            c.firstchance = EnvInt("CRASHCAPTURE_FIRSTCHANCE", 0) != 0;
        #endif
        
        c.window_watchdog = EnvInt("CRASHCAPTURE_WINDOW_WATCHDOG", 1) != 0;
        c.lua_heartbeat = EnvInt("CRASHCAPTURE_LUA_HEARTBEAT", 1) != 0;
        c.manual_dump = EnvInt("CRASHCAPTURE_MANUAL_DUMP", 1) != 0;
        c.console = EnvInt("CRASHCAPTURE_CONSOLE", 0) != 0;
        c.symbols = EnvInt("CRASHCAPTURE_SYMBOLS", 1) != 0;
        c.engine_error = EnvInt("CRASHCAPTURE_ENGINE_ERROR", 1) != 0;
        c.frame_profile = EnvInt("CRASHCAPTURE_FRAME_PROFILE", 1) != 0;

        // store crashes in <gmod-root>/crashes
        const char* dir = CfgRaw("CRASHCAPTURE_DIR");
        if (!dir || !*dir) dir = "crashes";
        snprintf(c.dir, sizeof(c.dir), "%s", dir);

        // optional Lua script for live memory diagnostics on a crash
        const char* script = CfgRaw("CRASHCAPTURE_SCRIPT");
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
            Log::F("[Crash Capture] pruned %d old report(s) (older than %d day(s)) from %s\n",
                   deleted, days, dir);
        return deleted;
    }

    void Init()
    {
        if (g_initialized) return;

        {
            const char* dis = CfgRaw("CRASHCAPTURE_DISABLE");
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
            if (deferArm && !CfgRaw("CRASHCAPTURE_FIRSTCHANCE"))
                Cfg().firstchance = true;
        #endif
        if (deferArm) {
            Watchdog::Start(true); // gate thread installs handlers once lua appears
            return;
        }

        InstallHandlers();
        if (Cfg().timeout_sec > 0)
            Watchdog::Start(false);
    }

    // Resolve modules + Lua, install handlers, print the armed banner.
    void InstallHandlers()
    {
        Modules::Refresh();
        Lua::RefreshStates();
        Platform::Install();
        
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

        #if defined(CC_SERVER)
            Log::F("CrashCapture - v" CC_VERSION " " CC_OS "/" CC_ARCH "/" CC_SIDE " - " __TIME__ " " __DATE__
                "\nreports -> %s\n", abdir);
        #endif

        #ifndef INTERFACE_PLUGIN
            Lua::InstallSideloadBootstrap();
        #endif
    }

    void Shutdown()
    {
        if (!g_initialized) return;
        Watchdog::Stop();
        Platform::Uninstall();
        g_initialized = false;
        Log::Str("[Crash Capture] disarmed.\n");
    }

    void Pulse()
    {
        Watchdog::Pulse();
        Log::PumpConsole();
        #if defined(CC_LINUX) // TODO: windows at some point.
            Phys::Recover::PollGameThread();
        #endif
        Lua::PollRecovery();
        Lua::PollReady();
    }

    const char* StallClassName(int cls)
    {
        switch (cls) {
            case STALL_PHYSICS:    return "physics";
            case STALL_NATIVE:     return "native";
            case STALL_LUA_INTERP: return "lua";
            case STALL_LUA_JIT:    return "lua-jit";
            default:               return "unknown";
        }
    }

    void Grace(int seconds)
    {
        uint64_t until = MonotonicMs() + (uint64_t)seconds * 1000ull;
        if (until > g_graceUntilMs) g_graceUntilMs = until;
        g_graceAnchorPulse = g_lastPulseMs;
    }

    void DumpNow(const char* reason)
    {
        Platform::DumpThread("dump", reason ? reason : "manual dump_now");
    }

    // --------- core-report ---

    static char g_ctxKind[64] = {0};
    static char g_ctxReason[256] = {0};
    static uintptr_t g_ctxFault = 0;

    void Report::SetContext(const char* kind, const char* reason, uintptr_t fault)
    {
        snprintf(g_ctxKind, sizeof(g_ctxKind), "%s", kind ? kind : "");
        snprintf(g_ctxReason, sizeof(g_ctxReason), "%s", reason ? reason : "");
        g_ctxFault = fault;
    }
    const char* Report::Kind() { return g_ctxKind; }
    const char* Report::Reason() { return g_ctxReason; }
    uintptr_t Report::Fault() { return g_ctxFault; }
    uint64_t Report::Uptime() { return MonotonicMs() - g_startMs; }

    // I had to do this, please.
    const char* Report::Meme()
    {
        static const char* const DehMemes[] = {
            "i think something has happened.",
            "there appears to be a problem...",
            "shiver me timbers, the game's shitting itself.",
            "ah jezz rick we broke it...",
            "freeman, stop fucking with the microwave!!!",
            "ah shit, here we go again.",
            "blueshank everything is broken.",
            "dude this code is ass.",
            "well fuck, wanna sprite cranberry?",
            "man i'm going to bed fuck this shit.",
            "dafug you mean its not working?",
            "attempting shutdown, it's not.. it- it's not- it's not shutting down.",
            "can you sign my petition please?",
            "hey, you, you're finally awake. fix it.",
            "the crash is a lie.",
            "all we had to do was follow the damn report!",
            "what do the crashes mean, Mason? MASON.",
            "the right crash, in the wrong place, can make all the difference in the world.",
            "what did I do to deserve this...",
            "sometimes, I dream about crashes.",
            "remember, no crashes.",
            "harry, yerr are a crash report.",
            "ITS PEANUT BUTTER CRASHING TIME",
            "maybe don't press that button.",
            "@rubat @rubat @rubat @rubat, can u fix it?" // rubat: no.
        };
        const size_t MemeCount = sizeof(DehMemes) / sizeof(DehMemes[0]);
        return DehMemes[(size_t)(MonotonicMs() + time(NULL)) % MemeCount];
    }

    void Report::Header(const char* kind, const char* reason)
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

        Report::Banner(kind, reason, Log::Path());
    }

    void Report::Banner(const char* kind, const char* reason, const char* reportPath)
    {
        Log::Notice("\n======================= Crash Capture =======================\n");
        Log::Notice("  %s\n", Report::Meme());
        Log::Notice("  %s detected\n", kind ? kind : "event");
        Log::Notice("  reason : %s\n", reason ? reason : "-");
        if (reportPath && *reportPath) Log::Notice("  report : %s\n", reportPath);
        Log::Notice("=============================================================\n\n");
    }

    void Report::Footer()
    {
        Log::F("\n---\n\n_END OF REPORT (%s)_\n\n", Log::Path());
        Log::Flush();
    }

    volatile int g_lastStallClass = STALL_UNKNOWN;

    struct PhysScan { void* ctx; const CCModule* pcMod; bool hit; };
    static void PhysScanFn(void* p)
    {
        PhysScan* s = (PhysScan*)p;
        if (s->pcMod && strstr(s->pcMod->name, "vphysics")) { s->hit = true; return; }

        uintptr_t pcs[48];
        int n = Platform::Backtrace(s->ctx, pcs, 48);
        for (int i = 0; i < n; ++i) {
            const CCModule* fm = Modules::Find(pcs[i]);
            if (fm && strstr(fm->name, "vphysics")) { s->hit = true; return; }
            char sym[256];
            if (Sym::Resolve(pcs[i], sym, sizeof(sym)) &&
                (strstr(sym, "PhysFrame") || strstr(sym, "CPhysicsHook") ||
                 strstr(sym, "PhysicsSimulate"))) { s->hit = true; return; }
        }
    }

    int Report::ClassifyStall(void* ctx, char* out, size_t outsz)
    {
        uintptr_t pc = Platform::ContextPC(ctx);
        if (!pc) { snprintf(out, outsz, "unknown (no thread context)"); return STALL_UNKNOWN; }

        const CCModule* m = Modules::Find(pc);
        if (m && strstr(m->name, "lua_shared")) {
            snprintf(out, outsz, "lua (interpreter)");
            return STALL_LUA_INTERP;
        }
        if ((!m || strcmp(m->name, "[anon-exec]") == 0) && Mem::IsExecutable(pc)) {
            snprintf(out, outsz, "lua (JIT trace / mcode)");
            return STALL_LUA_JIT;
        }
        if (m) {
            PhysScan ps = { ctx, m, false };
            RunProtectedQuiet(PhysScanFn, &ps);
            if (ps.hit) { snprintf(out, outsz, "physics (%s)", m->name); return STALL_PHYSICS; }
            snprintf(out, outsz, "native (%s)", m->name);
            return STALL_NATIVE;
        }
        snprintf(out, outsz, "unknown (pc 0x%llx unmapped)", (unsigned long long)pc);
        return STALL_UNKNOWN;
    }

    void Report::Section(const char* title, SectionFn fn, void* arg, bool fenced)
    {
        Log::F("\n## %s\n\n", title);
        if (fenced) Log::OpenFence();
        RunProtected(fn, arg);
        Log::CloseFence();
        Log::Flush();
    }
}
