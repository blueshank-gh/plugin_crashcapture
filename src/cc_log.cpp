// Async-signal-safe-ish... report logger
// raw file descriptor + stderr echo, static buffers only.
// vsnprintf is technically not async-signal-safe... but it accepts those pramatic choices in crash handlers.

#include "crashcapture.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#if defined(CC_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <windows.h>
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <errno.h>
#endif

namespace CrashCapture::Log {
    #if defined(CC_WINDOWS)
        static HANDLE g_file = INVALID_HANDLE_VALUE;
    #else
        static int g_file = -1;
    #endif
    static char g_path[768];

    bool IsOpen()
    {
        #if defined(CC_WINDOWS)
            return g_file != INVALID_HANDLE_VALUE;
        #else
            return g_file >= 0;
        #endif
    }

    const char* Path() { return g_path; }

    static void WriteStderr(const char* s, size_t len)
    {
        #if defined(CC_WINDOWS)
            HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
            if (err && err != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                WriteFile(err, s, (DWORD)len, &written, NULL);
            }
        #else
            ssize_t r = write(2, s, len);
            (void)r;
        #endif
    }

    void Raw(const char* s, size_t len)
    {
        if (!s || !len) return;
        #if defined(CC_WINDOWS)
            // Mirror to the debugger stream (DebugView/WinDbg), visible with no console.
            {
                char dbg[1024];
                size_t k = len < sizeof(dbg) - 1 ? len : sizeof(dbg) - 1;
                memcpy(dbg, s, k);
                dbg[k] = 0;
                OutputDebugStringA(dbg);
            }
            if (g_file != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                WriteFile(g_file, s, (DWORD)len, &written, NULL);
            }
        #else
            if (g_file >= 0) {
                ssize_t r = write(g_file, s, len);
                (void)r;
            }
        #endif
        if (!IsOpen() || Cfg().console)
            WriteStderr(s, len);
    }

    // just a concise console banner, never written to the .md
    void Notice(const char* fmt, ...)
    {
        char buf[1024];
        va_list args;
        va_start(args, fmt);
        int len = vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        if (len <= 0) return;
        if ((size_t)len >= sizeof(buf)) len = sizeof(buf) - 1;
        #if defined(CC_WINDOWS)
            OutputDebugStringA(buf);
        #endif
        WriteStderr(buf, (size_t)len);
    }

    static bool g_debug = false;
    void SetDebug(bool on) { g_debug = on; }

    void Debug(const char* fmt, ...)
    {
        if (!g_debug) return;
        char buf[1024];
        va_list args;
        va_start(args, fmt);
        int len = vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        if (len <= 0) return;
        if ((size_t)len >= sizeof(buf)) len = sizeof(buf) - 1;
        #if defined(CC_WINDOWS)
            OutputDebugStringA(buf);
        #endif
        WriteStderr(buf, (size_t)len);
    }

    void Str(const char* s)
    {
        if (s) Raw(s, strlen(s));
    }

    void F(const char* fmt, ...)
    {
        char buf[1024];
        va_list args;
        va_start(args, fmt);
        int len = vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        if (len <= 0) return;
        if ((size_t)len >= sizeof(buf)) len = sizeof(buf) - 1;
        Raw(buf, (size_t)len);
    }

    static int g_fence = 0; // 1 while inside a ```text block

    void OpenFence()
    {
        if (g_fence) return;
        g_fence = 1;
        Str("```text\n");
    }

    void CloseFence()
    {
        if (!g_fence) return;
        g_fence = 0;
        Str("```\n");
    }

    void Flush()
    {
    #if defined(CC_WINDOWS)
        if (g_file != INVALID_HANDLE_VALUE) FlushFileBuffers(g_file);
    #else
        if (g_file >= 0) fsync(g_file);
    #endif
    }

    void EnableConsole()
    {
        #if defined(CC_WINDOWS)
            static bool done = false;
            if (done) return;
            done = true;
            if (AllocConsole()) {
                SetConsoleTitleA("plugin_crashcapture");
                FILE* f = NULL;
                freopen_s(&f, "CONOUT$", "w", stdout);
                freopen_s(&f, "CONOUT$", "w", stderr);
            }
        #endif
    }

    // 16 bytes/line "base+off  hex  ascii".
    void HexDump(const void* p, size_t n, uintptr_t labelBase)
    {
        const unsigned char* b = (const unsigned char*)p;
        if (!b) { Str("    <null>\n"); return; }
        if (n > 512) n = 512;

        char line[128];
        for (size_t i = 0; i < n; i += 16) {
            int w = snprintf(line, sizeof(line), "    %p  ", (void*)(labelBase + i));
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < n) w += snprintf(line + w, sizeof(line) - w, "%02x ", b[i + j]);
                else           w += snprintf(line + w, sizeof(line) - w, "   ");
            }
            w += snprintf(line + w, sizeof(line) - w, " ");
            for (size_t j = 0; j < 16 && i + j < n; ++j) {
                unsigned char c = b[i + j];
                line[w++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
            }
            line[w++] = '\n';
            Raw(line, (size_t)w);
        }
    }

    void AppendNote(const char* path, const char* text)
    {
        if (!path || !*path || !text || !*text) return;
        #if defined(CC_WINDOWS)
            HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return;
            SetFilePointer(h, 0, NULL, FILE_END);
            DWORD w = 0;
            WriteFile(h, text, (DWORD)strlen(text), &w, NULL);
            CloseHandle(h);
        #else
            int fd = open(path, O_WRONLY | O_APPEND);
            if (fd < 0) return;
            ssize_t r = write(fd, text, strlen(text));
            (void)r;
            close(fd);
        #endif
    }

    bool Open(const char* kind)
    {
        if (IsOpen()) Close();

        char stamp[32];
        UtcStamp(stamp, sizeof(stamp));

        #if defined(CC_WINDOWS)
            unsigned pid = (unsigned)GetCurrentProcessId();
        #else
            unsigned pid = (unsigned)getpid();
        #endif

        snprintf(g_path, sizeof(g_path), "%s/%s_%s_%u.md", Cfg().dir, kind, stamp, pid);

        #if defined(CC_WINDOWS)
            g_file = CreateFileA(g_path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (g_file == INVALID_HANDLE_VALUE) {
                // last resort: drop the directory, write next to the exe cwd
                snprintf(g_path, sizeof(g_path), "crashcapture_%s_%s_%u.md", kind, stamp, pid);
                g_file = CreateFileA(g_path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            }
            return g_file != INVALID_HANDLE_VALUE;
        #else
            g_file = open(g_path, O_TRUNC | O_WRONLY | O_CREAT, 0666);
            if (g_file < 0) {
                snprintf(g_path, sizeof(g_path), "crashcapture_%s_%s_%u.md", kind, stamp, pid);
                g_file = open(g_path, O_TRUNC | O_WRONLY | O_CREAT, 0666);
            }
            return g_file >= 0;
        #endif
    }

    void Close()
    {
        Flush();
        #if defined(CC_WINDOWS)
            if (g_file != INVALID_HANDLE_VALUE) {
                CloseHandle(g_file);
                g_file = INVALID_HANDLE_VALUE;
            }
        #else
            if (g_file >= 0) {
                close(g_file);
                g_file = -1;
            }
        #endif
    }
}
