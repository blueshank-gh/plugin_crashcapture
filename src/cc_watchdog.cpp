// Crash Capture - hang watchdog
// A side thread watches the game thread's "pulse".
// If the pulse stops advancing for longer than the timeout, the game thread is considered stuck.

#include "crashcapture.h"

#include <stdio.h>
#include <string.h>

#if defined(CC_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <windows.h>
#else
    #include <pthread.h>
    #include <unistd.h>
    #include <time.h>
    #include <sys/syscall.h>
#endif

namespace CrashCapture {
    volatile uint64_t g_lastPulseMs = 0;
    volatile uint64_t g_graceUntilMs = 0;

    static volatile bool g_running = false;
    static volatile bool g_stop = false;
    static volatile bool g_deferredArm = false; // wait for a lua module, then InstallHandlers()
    static uint64_t g_firedAtPulse = (uint64_t)-1; // lastPulse value when we last fired
    static uint64_t g_hangStartMs = 0;
    static bool g_hangPending = false;
    static char g_hangReportPath[768] = {0};
    static char g_hangReason[256] = {0};
    static char g_hangMethod[16] = {0};

    #if defined(CC_WINDOWS)
        static HANDLE g_thread = NULL;
    #else
        static pthread_t g_thread;
        static bool g_threadValid = false;
    #endif

    static void SleepMs(int ms)
    {
        #if defined(CC_WINDOWS)
            Sleep(ms);
        #else
            struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
            nanosleep(&ts, NULL);
        #endif
    }

    void Watchdog_Pulse()
    {
        if (g_lastPulseMs == 0) {
            // first pulse: remember which thread the heartbeat comes from...
            #if defined(CC_WINDOWS)
                g_gameThreadId = GetCurrentThreadId();
                DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                                GetCurrentProcess(), (HANDLE*)&g_gameThreadHandle,
                                0, FALSE, DUPLICATE_SAME_ACCESS);
            #else
                g_gameThreadPthread = (unsigned long)pthread_self();
                g_gameThreadTid = (int)syscall(SYS_gettid);
            #endif
            Log::F("[CrashCapture] heartbeat bound to game thread (id=%llu)\n",
            #if defined(CC_WINDOWS)
                   (unsigned long long)g_gameThreadId);
            #else
                   (unsigned long long)g_gameThreadTid);
            #endif
        }
        g_lastPulseMs = MonotonicMs();
    }

    // dump the stuck game thread and (best effort) ask Lua to break the loop.
    static void FireHangDump(uint64_t now, const char* reason)
    {
        g_hangStartMs = now;
        Platform_DumpThread("hang", reason);
        snprintf(g_hangReportPath, sizeof(g_hangReportPath), "%s", Log::Path());
        snprintf(g_hangReason, sizeof(g_hangReason), "%s", reason ? reason : "");
        g_hangMethod[0] = 0;
        g_hangPending = true;

        // only worth arming the Lua loop-break when the stall is actually in Lua...
        if (Cfg().loopbreak) {
            if (g_lastStallClass == STALL_NATIVE || g_lastStallClass == STALL_PHYSICS) {
                Log::Str("[CrashCapture] hang: stall is not in Lua, loop-break skipped.\n");
            } else if (Lua_BreakLoop("CrashCapture: breaking suspected infinite loop")) {
                snprintf(g_hangMethod, sizeof(g_hangMethod), "loopbreak");
                Log::Str("[CrashCapture] hang: requested Lua loop-break.\n");
            }
        }
    }

    static void NoteRecovery(uint64_t now)
    {
        if (!g_hangPending) return;
        g_hangPending = false;
        uint64_t dur = now - g_hangStartMs;
        Log::Notice("[CrashCapture] game thread recovered after %llu ms\n", (unsigned long long)dur);
        char note[512];
        snprintf(note, sizeof(note),
                 "\n---\n\n> **RECOVERY**: the game thread resumed %llu ms after this "
                 "report was written.",
                 (unsigned long long)dur);
        Log::AppendNote(g_hangReportPath, note);
        Recovery_NoteRecovered(g_hangMethod, dur, StallClassName(g_lastStallClass), g_hangReason, g_hangReportPath);
    }

    // after a dump, optionally kill the process once the grace window passes
    static void MaybeHardKill(uint64_t now)
    {
        if (Cfg().hang_kill_sec > 0 &&
            now - g_hangStartMs > (uint64_t)Cfg().hang_kill_sec * 1000ull) {
            Log::F("[CrashCapture] hang persisted %ds past first dump; terminating process.\n",
                   Cfg().hang_kill_sec);
            Log::Flush();
            #if defined(CC_WINDOWS)
                TerminateProcess(GetCurrentProcess(), 0xDEAD);
            #else
                _exit(0xDE);
            #endif
        }
    }

    // --------- watchdog-heartbeat-detector ---

    static void HeartbeatTick(int timeout, uint64_t now)
    {
        uint64_t pulse = g_lastPulseMs;

        // fresh pulse since we last fired re-arms the watchdog
        if (pulse != g_firedAtPulse) {
            NoteRecovery(now);
            if (now - pulse > (uint64_t)timeout * 1000ull) {
                g_firedAtPulse = pulse;
                char reason[160];
                snprintf(reason, sizeof(reason),
                         "no heartbeat for %llu ms (timeout %ds) - game thread stalled",
                         (unsigned long long)(now - pulse), timeout);
                FireHangDump(now, reason);
            }
            return;
        }

        // still hanging...
        MaybeHardKill(now);
    }

    // --------- windows-pump-detector ---

    #if defined(CC_WINDOWS)
        static HWND g_gameWnd = NULL;
        static bool g_winHung = false;
        static bool g_winSawAlive = false; // engine reached a responsive state once
        static uint64_t g_winHungSinceMs = 0; // when the window first looked hung

        typedef BOOL (WINAPI* PFN_EnumWindows)(WNDENUMPROC, LPARAM);
        typedef DWORD (WINAPI* PFN_GetWindowThreadProcessId)(HWND, LPDWORD);
        typedef BOOL (WINAPI* PFN_IsWindowVisible)(HWND);
        typedef HWND (WINAPI* PFN_GetWindow)(HWND, UINT);
        typedef int (WINAPI* PFN_GetClassNameA)(HWND, LPSTR, int);
        typedef BOOL (WINAPI* PFN_IsWindow)(HWND);
        typedef BOOL (WINAPI* PFN_IsHungAppWindow)(HWND);

        static struct {
            HMODULE lib;
            PFN_EnumWindows EnumWindows;
            PFN_GetWindowThreadProcessId GetWindowThreadProcessId;
            PFN_IsWindowVisible IsWindowVisible;
            PFN_GetWindow GetWindow;
            PFN_GetClassNameA GetClassNameA;
            PFN_IsWindow IsWindow;
            PFN_IsHungAppWindow IsHungAppWindow;
        } U = {0};

        static bool ResolveUser32()
        {
            if (U.lib) return true;
            HMODULE h = GetModuleHandleA("user32.dll"); // the engine already pulled it in
            if (!h) h = LoadLibraryA("user32.dll");
            if (!h) return false;
            U.EnumWindows = (PFN_EnumWindows) GetProcAddress(h, "EnumWindows");
            U.GetWindowThreadProcessId = (PFN_GetWindowThreadProcessId) GetProcAddress(h, "GetWindowThreadProcessId");
            U.IsWindowVisible = (PFN_IsWindowVisible) GetProcAddress(h, "IsWindowVisible");
            U.GetWindow = (PFN_GetWindow) GetProcAddress(h, "GetWindow");
            U.GetClassNameA = (PFN_GetClassNameA) GetProcAddress(h, "GetClassNameA");
            U.IsWindow = (PFN_IsWindow) GetProcAddress(h, "IsWindow");
            U.IsHungAppWindow = (PFN_IsHungAppWindow) GetProcAddress(h, "IsHungAppWindow");
            if (!U.EnumWindows || !U.GetWindowThreadProcessId || !U.IsWindowVisible ||
                !U.GetWindow || !U.GetClassNameA || !U.IsWindow || !U.IsHungAppWindow)
                return false;
            U.lib = h;
            return true;
        }

        static BOOL CALLBACK FindWndProc(HWND hwnd, LPARAM lp)
        {
            DWORD pid = 0;
            U.GetWindowThreadProcessId(hwnd, &pid);
            if (pid != GetCurrentProcessId()) return TRUE;
            if (!U.IsWindowVisible(hwnd)) return TRUE;
            if (U.GetWindow(hwnd, GW_OWNER)) return TRUE; // top-level only

            // match ONLY the Source engine window ("Valve001"). 
            char cls[64] = {0};
            U.GetClassNameA(hwnd, cls, sizeof(cls));
            if (strncmp(cls, "Valve", 5) == 0) { *(HWND*)lp = hwnd; return FALSE; }
            return TRUE;
        }

        static HWND FindGameWindow()
        {
            if (!ResolveUser32()) return NULL;
            if (g_gameWnd && U.IsWindow(g_gameWnd)) return g_gameWnd;
            g_gameWnd = NULL;
            U.EnumWindows(FindWndProc, (LPARAM)&g_gameWnd);
            return g_gameWnd;
        }

        static void BindThread(DWORD tid)
        {
            if (g_gameThreadId == tid && g_gameThreadHandle) return;
            if (g_gameThreadHandle) CloseHandle((HANDLE)g_gameThreadHandle);
            g_gameThreadHandle = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                FALSE, tid);
            g_gameThreadId = tid;
        }

        static void WindowProbeTick(int timeout, uint64_t now)
        {
            HWND hwnd = FindGameWindow();
            if (!hwnd) return;

            if (!U.IsHungAppWindow(hwnd)) {
                if (!g_winSawAlive) { // first time the engine window is responsive
                    g_winSawAlive = true;
                    Log::F("[CrashCapture] watching game window %p (class Valve*) for hangs.\n",
                           (void*)hwnd);
                }
                if (g_winHung) NoteRecovery(now);
                g_winHung = false;
                g_winHungSinceMs = 0;
                return;
            }

            if (!g_winSawAlive) return;

            if (g_winHungSinceMs == 0) g_winHungSinceMs = now;
            if (now - g_winHungSinceMs < (uint64_t)timeout * 1000ull) return; // not long enough

            if (!g_winHung) { // first detection: bind the owner thread and dump.
                g_winHung = true;
                DWORD tid = U.GetWindowThreadProcessId(hwnd, NULL);
                BindThread(tid);
                char reason[200];
                snprintf(reason, sizeof(reason),
                         "window unresponsive >=%ds (hwnd=%p tid=%lu) - "
                         "main thread stalled (infinite loop?)",
                         timeout, (void*)hwnd, (unsigned long)tid);
                FireHangDump(now, reason);
            } else {
                MaybeHardKill(now);
            }
        }
    #endif // CC_WINDOWS

    static void WatchdogLoop()
    {
        // deferred arm for client preload, stay inert until a "lua" module is mapped.
        if (g_deferredArm) {
            while (!g_stop) {
                if (Modules_HasLua()) break;
                SleepMs(250);
            }
            if (g_stop) { g_running = false; return; }
            InstallHandlers();
        }

        while (!g_stop) {
            SleepMs(500);
            if (g_stop) break;

            int timeout = Cfg().timeout_sec;
            if (timeout <= 0) continue;

            uint64_t now = MonotonicMs();
            if (now < g_graceUntilMs) continue; // inside a known stall (map change)

            if (g_lastPulseMs != 0) {
                HeartbeatTick(timeout, now); // GameFrame or lua-timer pulse source
            }
            #if defined(CC_WINDOWS)
                else if (Cfg().window_watchdog) {
                    WindowProbeTick(timeout, now); // no pulse, watch the message pump
                }
            #endif
        }
        g_running = false;
    }

    #if defined(CC_WINDOWS)
        static DWORD WINAPI ThreadEntry(LPVOID) { WatchdogLoop(); return 0; }
    #else
        static void* ThreadEntry(void*) { WatchdogLoop(); return NULL; }
    #endif

    void Watchdog_Start(bool deferredArm)
    {
        if (g_running) return;
        g_stop = false;
        g_running = true;
        g_deferredArm = deferredArm;
        #if defined(CC_WINDOWS)
            g_thread = CreateThread(NULL, 0, ThreadEntry, NULL, 0, NULL);
            if (!g_thread) g_running = false;
        #else
            if (pthread_create(&g_thread, NULL, ThreadEntry, NULL) == 0)
                g_threadValid = true;
            else
                g_running = false;
        #endif
    }

    void Watchdog_Stop()
    {
        if (!g_running && !g_stop) return;
        g_stop = true;
        #if defined(CC_WINDOWS)
            if (g_thread) {
                WaitForSingleObject(g_thread, 2000);
                CloseHandle(g_thread);
                g_thread = NULL;
            }
        #else
            if (g_threadValid) {
                pthread_join(g_thread, NULL);
                g_threadValid = false;
            }
        #endif
    }
}
