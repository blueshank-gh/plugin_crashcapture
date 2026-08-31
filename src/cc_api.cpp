// Crash Capture - external binary API (CCAPI, see include/crashcapture_api.h)

#include "crashcapture.h"
#include "crashcapture_api.h"
#include <atomic>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

namespace CrashCapture {
    static void SanitizeCopy(char* dst, size_t dstsz, const char* src)
    {
        size_t j = 0;
        if (src) {
            for (size_t i = 0; src[i] && j + 1 < dstsz; ++i) {
                unsigned char c = (unsigned char)src[i];
                dst[j++] = (c < 0x20 || c == 0x7f) ? ' ' : (char)c;
            }
        }
        while (j > 0 && dst[j - 1] == ' ') --j;
        dst[j] = 0;
    }

    // --------- third-party report data ---

    static const int EXT_DATA_MAX = 16;
    static const int EXT_SECTION_MAX = 8;

    struct ExtData { bool used; char key[48]; char value[256]; };
    struct ExtSection { bool used; char name[64]; CCSectionFn fn; void* user; };

    static ExtData g_extData[EXT_DATA_MAX];
    static ExtSection g_extSections[EXT_SECTION_MAX];

    static bool AnyExtData()
    {
        for (int i = 0; i < EXT_DATA_MAX; ++i)
            if (g_extData[i].used && g_extData[i].key[0]) return true;
        return false;
    }

    static void Sec_ThirdPartyData(void*)
    {
        Log::F("| Key | Value |\n| --- | --- |\n");
        bool any = false;
        for (int i = 0; i < EXT_DATA_MAX; ++i) {
            if (!g_extData[i].used || !g_extData[i].key[0]) continue;
            Log::F("| %s | %s |\n", g_extData[i].key, g_extData[i].value);
            any = true;
        }
        if (!any) Log::Str("_(none)_\n");
    }

    static void ApiWriterPrint(CCSectionCtx* ctx, const char* text)
    {
        (void)ctx;
        if (text) Log::Str(text);
    }

    static void ApiWriterFormat(CCSectionCtx* ctx, const char* fmt, ...)
    {
        (void)ctx;
        if (!fmt) return;
        char buf[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        Log::Str(buf);
    }

    static CCSectionCtx g_apiWriter = { NULL, ApiWriterPrint, ApiWriterFormat };

    static void Sec_ExtSectionAdapter(void* p)
    {
        ExtSection* s = (ExtSection*)p;
        s->fn(s->user, &g_apiWriter);
    }

    void Api::EmitReportSections()
    {
        if (!Ready()) return;
        if (AnyExtData())
            Report::Section("Third-party data", Sec_ThirdPartyData, NULL, false);
        for (int i = 0; i < EXT_SECTION_MAX; ++i) {
            if (!g_extSections[i].used || !g_extSections[i].fn) continue;
            Log::F("\n## %s\n\n", g_extSections[i].name);
            Log::OpenFence();
            RunProtected(Sec_ExtSectionAdapter, &g_extSections[i]);
            Log::CloseFence();
            Log::Flush();
        }
    }

    // --------- CCAPI wrappers ---

    static const char* ApiVersionStr() { return CC_VERSION; }
    static const char* ApiBuildStr() { return CC_BUILD; }
    static const char* ApiSideStr() { return CC_SIDE; }
    static const char* ApiOsStr() { return CC_OS; }
    static const char* ApiArchStr() { return CC_ARCH; }

    static int ApiIsHung()
    {
        return Watchdog::HangState(NULL) ? 1 : 0;
    }

    static unsigned long long ApiHungSinceMs()
    {
        uint64_t since = 0;
        Watchdog::HangState(&since);
        if (!since) return 0;
        uint64_t now = MonotonicMs();
        return now > since ? (unsigned long long)(now - since) : 0;
    }

    static int ApiStallClass() { return g_lastStallClass; }
    static const char* ApiStallClassName(int cls) { return StallClassName(cls); }

    static unsigned long long ApiMsSincePulse()
    {
        uint64_t p = g_lastPulseMs.load();
        if (!p) return 0;
        uint64_t now = MonotonicMs();
        return now > p ? (unsigned long long)(now - p) : 0;
    }

    static const char* ApiConfigGet(const char* name) { return name ? CfgRaw(name) : NULL; }
    static const char* ApiReportDir() { return Cfg().dir; }
    static const char* ApiLogPath()   { return Log::IsOpen() ? Log::Path() : NULL; }
    static unsigned long long ApiUptimeMs() { return (unsigned long long)Report::Uptime(); }
    static const char* ApiMapName()   { return Report::MapName(); }

    static int ApiDump(const char* reason)
    {
        if (!Ready()) return 0;
        static std::atomic<int> gate(0);
        int expected = 0;
        if (!gate.compare_exchange_strong(expected, 1)) return 0;
        char buf[256];
        SanitizeCopy(buf, sizeof(buf), reason);
        if (!buf[0]) snprintf(buf, sizeof(buf), "external dump");
        DumpNow(buf);
        gate.store(0);
        return 1;
    }

    static void ApiPulse() { Pulse(); }

    static void ApiGrace(int seconds)
    {
        if (seconds <= 0) return;
        if (seconds > 86400) seconds = 86400;
        Grace(seconds);
    }

    static int ApiSetData(const char* key, const char* value)
    {
        if (!Ready() || !key || !key[0]) return 0;
        char k[48];
        char v[256];
        SanitizeCopy(k, sizeof(k), key);
        SanitizeCopy(v, sizeof(v), value);
        if (!k[0]) return 0;

        int freeSlot = -1;
        for (int i = 0; i < EXT_DATA_MAX; ++i) {
            if (g_extData[i].used && strcmp(g_extData[i].key, k) == 0) {
                g_extData[i].value[0] = 0;
                if (v[0]) SanitizeCopy(g_extData[i].value, sizeof(g_extData[i].value), v);
                return 1;
            }
            if (!g_extData[i].used && freeSlot < 0) freeSlot = i;
        }
        if (freeSlot < 0 || !v[0]) return 0;
        g_extData[freeSlot].used = true;
        snprintf(g_extData[freeSlot].key, sizeof(g_extData[freeSlot].key), "%s", k);
        snprintf(g_extData[freeSlot].value, sizeof(g_extData[freeSlot].value), "%s", v);
        return 1;
    }

    static void ApiClearData(const char* key)
    {
        if (!key || !key[0]) return;
        char k[48];
        SanitizeCopy(k, sizeof(k), key);
        for (int i = 0; i < EXT_DATA_MAX; ++i) {
            if (g_extData[i].used && strcmp(g_extData[i].key, k) == 0) {
                g_extData[i].used = false;
                g_extData[i].key[0] = 0;
                g_extData[i].value[0] = 0;
            }
        }
    }

    static int ApiAddSection(const char* name, CCSectionFn fn, void* user)
    {
        if (!Ready() || !name || !name[0] || !fn) return 0;
        char n[64];
        SanitizeCopy(n, sizeof(n), name);
        if (!n[0]) return 0;

        int freeSlot = -1;
        for (int i = 0; i < EXT_SECTION_MAX; ++i) {
            if (g_extSections[i].used && strcmp(g_extSections[i].name, n) == 0) {
                g_extSections[i].fn = fn;
                g_extSections[i].user = user;
                return 1;
            }
            if (!g_extSections[i].used && freeSlot < 0) freeSlot = i;
        }
        if (freeSlot < 0) return 0;
        g_extSections[freeSlot].used = true;
        snprintf(g_extSections[freeSlot].name, sizeof(g_extSections[freeSlot].name), "%s", n);
        g_extSections[freeSlot].fn = fn;
        g_extSections[freeSlot].user = user;
        return 1;
    }

    static void ApiRemoveSection(const char* name)
    {
        if (!name || !name[0]) return;
        char n[64];
        SanitizeCopy(n, sizeof(n), name);
        for (int i = 0; i < EXT_SECTION_MAX; ++i) {
            if (g_extSections[i].used && strcmp(g_extSections[i].name, n) == 0) {
                g_extSections[i].used = false;
                g_extSections[i].name[0] = 0;
                g_extSections[i].fn = NULL;
                g_extSections[i].user = NULL;
            }
        }
    }

    static int ApiBacktrace(unsigned long long* out, int max)
    {
        if (!Ready() || !out || max <= 0) return 0;
        if (max > 64) max = 64;
        uintptr_t tmp[64];
        int n = Platform::Backtrace(NULL, tmp, max);
        for (int i = 0; i < n; ++i) out[i] = (unsigned long long)tmp[i];
        return n;
    }

    static int ApiResolve(unsigned long long addr, char* out, unsigned outsz)
    {
        if (!Ready() || !out || outsz == 0) return 0;
        out[0] = 0;
        return Sym::Resolve((uintptr_t)addr, out, (size_t)outsz) ? 1 : 0;
    }

    // --------- the vtable ---

    static const CCAPI g_api001 = {
        sizeof(CCAPI),
        CC_API_VER,
        ApiVersionStr,
        ApiBuildStr,
        ApiSideStr,
        ApiOsStr,
        ApiArchStr,
        ApiIsHung,
        ApiHungSinceMs,
        ApiStallClass,
        ApiStallClassName,
        ApiMsSincePulse,
        ApiConfigGet,
        ApiReportDir,
        ApiLogPath,
        ApiUptimeMs,
        ApiMapName,
        ApiDump,
        ApiPulse,
        ApiGrace,
        ApiSetData,
        ApiClearData,
        ApiAddSection,
        ApiRemoveSection,
        ApiBacktrace,
        ApiResolve
    };

    void* Api::V1() { return (void*)&g_api001; }
}
