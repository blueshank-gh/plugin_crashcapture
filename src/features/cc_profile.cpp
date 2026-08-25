// cc_profile - see cc_profile.h.

#include "crashcapture.h"
#include "features/cc_profile.h"
#include "tools/cc_hooking.h"
#include "tools/cc_signature.h"
#include "glua/LuaInterface.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#if defined(CC_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <intrin.h>
#else
    #include <time.h>
    #include <cpuid.h>
    #include <x86intrin.h>
#endif

// MSVC x86 passes `this` in ecx for member functions, every other target we build takes it as a normal leading argument.
#if defined(CC_WINDOWS) && defined(CC_X86)
    #define CC_MEMBER __fastcall
    #define CC_EDX void* edx,
    #define CC_EDXARG NULL,
#else
    #define CC_MEMBER
    #define CC_EDX
    #define CC_EDXARG
#endif

namespace CrashCapture {
    using GarrysMod::Lua::ILuaInterface;

    static const int kMaxBuckets = 1024;
    static const int kMaxDepth = 48;
    static const int kKeySlots = 4096;
    static const int kMaxSnapshot = 64;
    static const int kPooledCache = 4096;
    static const int kHistBins = 40;

    static ProfileBucket g_buckets[kMaxBuckets];
    static uint32_t g_hist[kMaxBuckets][kHistBins];
    static int g_nBuckets = 0;
    static int g_unattributed = -1;

    struct KeySlot { uintptr_t key; int bucket; };
    static KeySlot g_keys[kKeySlots];

    static int16_t g_pooled[kPooledCache];
    static bool g_pooledReady = false;

    static ProfileBucket g_prev[kMaxSnapshot];
    static int g_prevCount = 0;
    static double g_prevWindowMs = 0;
    static uint64_t g_prevDropped = 0;
    static int g_prevBuckets = 0;
    static uint64_t g_rotations = 0;

    static volatile bool g_enabled = false;
    static bool g_installed = false;
    static bool g_disarmPending = false;
    static uintptr_t g_triedBase = 0;
    static uint64_t g_dropped = 0;

    // --------- profile-clock ---

    static bool g_useTsc = false;
    static uint64_t g_anchorNs = 0;
    static uint64_t g_anchorTicks = 0;

    static inline uint64_t NowNs()
    {
        #if defined(CC_WINDOWS)
            static LARGE_INTEGER f = {0};
            if (!f.QuadPart) QueryPerformanceFrequency(&f);
            LARGE_INTEGER c; QueryPerformanceCounter(&c);
            uint64_t q = (uint64_t)c.QuadPart, hz = (uint64_t)f.QuadPart;
            return hz ? (q / hz) * 1000000000ull + (q % hz) * 1000000000ull / hz : 0;
        #else
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
        #endif
    }

    static inline uint64_t Ticks()
    {
        return g_useTsc ? (uint64_t)__rdtsc() : NowNs();
    }

    static bool HasInvariantTsc()
    {
        #if defined(CC_WINDOWS)
            int r[4] = {0};
            __cpuid(r, 0x80000000);
            if ((unsigned)r[0] < 0x80000007u) return false;
            __cpuid(r, 0x80000007);
            return (r[3] & (1 << 8)) != 0;
        #else
            unsigned a = 0, b = 0, c = 0, d = 0;
            if (!__get_cpuid(0x80000007u, &a, &b, &c, &d)) return false;
            return (d & (1 << 8)) != 0;
        #endif
    }

    double Profile::TicksToMs(uint64_t ticks)
    {
        if (!ticks || !g_anchorNs) return 0.0;
        uint64_t nowNs = NowNs(), nowTicks = Ticks();
        if (nowNs <= g_anchorNs || nowTicks <= g_anchorTicks) return 0.0;
        uint64_t dn = nowNs - g_anchorNs;
        uint64_t dc = nowTicks - g_anchorTicks;
        if (dn < 1000000ull || !dc) return 0.0; // under 1 ms of anchor span, rate is noise
        return (double)ticks * ((double)dn / (double)dc) / 1e6;
    }

    double Profile::WindowMs()
    {
        return g_anchorNs ? (double)(NowNs() - g_anchorNs) / 1e6 : 0.0;
    }

    uint64_t Profile::Dropped() { return g_dropped; }
    int Profile::BucketCount() { return g_nBuckets; }
    int Profile::BucketMax() { return kMaxBuckets; }

    // --------- profile-buckets ---

    static void CopyField(char* dst, size_t cap, const char* src)
    {
        if (!src) { dst[0] = 0; return; }
        size_t i = 0;
        for (; i + 1 < cap && src[i]; ++i) dst[i] = src[i];
        dst[i] = 0;
    }

    static int NewBucket(const char* prefix, const char* name, const char* source, int kind)
    {
        if (g_nBuckets >= kMaxBuckets) { ++g_dropped; return -1; }
        int idx = g_nBuckets++;
        ProfileBucket& b = g_buckets[idx];
        snprintf(b.name, sizeof(b.name), "%s%s", prefix ? prefix : "", name ? name : "?");
        CopyField(b.source, sizeof(b.source), source);
        b.kind = kind;
        b.calls = 0;
        b.selfTicks = 0;
        b.totalTicks = 0;
        b.maxTicks = 0;
        memset(g_hist[idx], 0, sizeof(g_hist[idx]));
        return idx;
    }

    static inline int Log2Bin(uint64_t v)
    {
        int n = 0;
        if (v >> 32) { n += 32; v >>= 32; }
        if (v >> 16) { n += 16; v >>= 16; }
        if (v >> 8)  { n += 8;  v >>= 8;  }
        if (v >> 4)  { n += 4;  v >>= 4;  }
        if (v >> 2)  { n += 2;  v >>= 2;  }
        if (v >> 1)  { n += 1; }
        return n < kHistBins ? n : kHistBins - 1;
    }

    static inline int BucketFor(uintptr_t key, const char* prefix, const char* name, const char* source, int kind)
    {
        unsigned h = (unsigned)((key >> 4) * 2654435761u) & (kKeySlots - 1);
        for (int probe = 0; probe < 16; ++probe) {
            KeySlot& s = g_keys[(h + probe) & (kKeySlots - 1)];
            if (s.key == key) return s.bucket;
            if (!s.key) {
                int idx = NewBucket(prefix, name, source, kind);
                if (idx < 0) return -1;
                s.key = key;
                s.bucket = idx;
                return idx;
            }
        }
        ++g_dropped;
        return -1;
    }

    // --------- profile-stack ---

    struct StackFrame { int bucket; uint64_t start; uint64_t child; };
    static StackFrame g_stack[kMaxDepth];
    static volatile int g_depth = 0;
    static int g_skipped = 0;

    enum { PEND_NONE = 0, PEND_GAMEMODE, PEND_TIMER, PEND_NET, PEND_CONCMD };
    static int g_pending = -1;
    static int g_pendKind = PEND_NONE;
    static int g_gmPending[kMaxDepth];

    static inline void Enter(int bucket)
    {
        if (g_depth >= kMaxDepth) { ++g_skipped; return; }
        StackFrame& f = g_stack[g_depth++];
        f.bucket = bucket;
        f.child = 0;
        f.start = Ticks();
    }

    static inline void Exit()
    {
        if (g_skipped) { --g_skipped; return; }
        if (g_depth <= 0) return;
        StackFrame& f = g_stack[--g_depth];
        uint64_t now = Ticks();
        uint64_t elapsed = now > f.start ? now - f.start : 0;

        if (f.bucket >= 0) {
            ProfileBucket& b = g_buckets[f.bucket];
            ++b.calls;
            b.totalTicks += elapsed;
            b.selfTicks += elapsed > f.child ? elapsed - f.child : 0;
            if (elapsed > b.maxTicks) b.maxTicks = elapsed;
            ++g_hist[f.bucket][Log2Bin(elapsed)];
        }

        if (g_depth > 0) g_stack[g_depth - 1].child += elapsed;
    }

    static inline void SetPending(int bucket, int kind)
    {
        g_pending = bucket;
        g_pendKind = kind;
    }

    static inline int TakePending(int kind)
    {
        if (g_pendKind != kind) return -1;
        int p = g_pending;
        g_pending = -1;
        g_pendKind = PEND_NONE;
        return p;
    }

    int Profile::Depth() { return g_depth; }

    const char* Profile::NameAt(int level)
    {
        if (level < 0 || level >= g_depth) return NULL;
        int b = g_stack[level].bucket;
        if (b < 0 || b >= g_nBuckets) return NULL;
        return g_buckets[b].name;
    }

    double Profile::ElapsedMsAt(int level)
    {
        if (level < 0 || level >= g_depth) return 0.0;
        uint64_t now = Ticks();
        uint64_t start = g_stack[level].start;
        return now > start ? Profile::TicksToMs(now - start) : 0.0;
    }

    // --------- profile-names ---

    static const char* StdStringData(const void* s)
    {
        #if defined(CC_WINDOWS)
            if (!s || !Mem::IsReadable(s, 4 * sizeof(void*))) return NULL;
            size_t cap = ((const size_t*)s)[3];
            const char* p = cap >= 16 ? *(const char* const*)s : (const char*)s;
        #else
            if (!s || !Mem::IsReadable(s, sizeof(void*))) return NULL;
            const char* p = *(const char* const*)s;
        #endif
        return (p && Mem::IsReadable(p, 1)) ? p : NULL;
    }

    static ILuaInterface* GamemodeIface()
    {
        #ifdef INTERFACE_PLUGIN
            return (ILuaInterface*)Lua::Iface(1);
        #else
            return (ILuaInterface*)Lua::Iface(0);
        #endif
    }

    static ILuaInterface* g_pooledIface = NULL;

    static int BucketForPooled(unsigned idx)
    {
        ILuaInterface* l = GamemodeIface();
        if (!g_pooledReady || (l && l != g_pooledIface)) {
            for (int i = 0; i < kPooledCache; ++i) g_pooled[i] = -1;
            g_pooledReady = true;
            if (l) g_pooledIface = l;
        }
        if (idx < (unsigned)kPooledCache && g_pooled[idx] >= 0) return g_pooled[idx];

        const char* name = NULL;
        if (l && Lua::IfaceLive(l)) {
            const char* s = l->GetPooledString((int)idx);
            if (s && Mem::IsReadable(s, 1)) name = s;
        }

        char fallback[32];
        if (!name) {
            snprintf(fallback, sizeof(fallback), "#%u", idx); // prefixed to "hook:#N"
            name = fallback;
        }

        int b = BucketFor((uintptr_t)0x1000000 + idx, "hook:", name, NULL, PROF_HOOK);
        if (idx < (unsigned)kPooledCache && b >= 0) g_pooled[idx] = (int16_t)b;
        return b;
    }

    static inline int BucketForName(const char* name)
    {
        if (!name || !Mem::IsReadable(name, 1)) return g_unattributed;
        return BucketFor((uintptr_t)name, "hook:", name, NULL, PROF_HOOK);
    }

    static uintptr_t HashStr(const char* s)
    {
        uint64_t h = 1469598103934665603ull;
        for (; *s; ++s) { h ^= (unsigned char)*s; h *= 1099511628211ull; }
        if (sizeof(uintptr_t) < 8) h ^= h >> 32;
        return (uintptr_t)h | 1;
    }

    static const char* ShortSource(const char* p)
    {
        if (!p) return "?";
        if (*p == '@') ++p;
        const char* b = p;
        for (const char* s = p; *s; ++s) if (*s == '/' || *s == '\\') b = s + 1;
        return *b ? b : p;
    }

    // --------- profile-luaname ---
    
    static const int CC_LUA_TFUNCTION = 6;
    struct prof_lua_Debug {
        int event;
        const char* name;
        const char* namewhat;
        const char* what;
        const char* source;
        int currentline;
        int nups;
        int linedefined;
        int lastlinedefined;
        char short_src[128];
        int i_ci;
        int nparams;
        int isvararg;
    };

    union ProfDebugBuf {
        prof_lua_Debug d;
        char raw[512];
    };

    struct ProfLua {
        int (*gettop)(void*);
        void (*settop)(void*, int);
        int (*type)(void*, int);
        void (*pushvalue)(void*, int);
        int (*getinfo)(void*, const char*, prof_lua_Debug*);
        const void* (*topointer)(void*, int);
        bool ok;
        bool tried;
    };
    static ProfLua g_lua = {0};

    static void ResolveLuaApi()
    {
        g_lua.tried = true;
        void* m = Lua::SharedHandle();
        if (!m) return;
        g_lua.gettop = (int (*)(void*))Lua::Sym(m, "lua_gettop");
        g_lua.settop = (void (*)(void*, int))Lua::Sym(m, "lua_settop");
        g_lua.type = (int (*)(void*, int))Lua::Sym(m, "lua_type");
        g_lua.pushvalue = (void (*)(void*, int))Lua::Sym(m, "lua_pushvalue");
        g_lua.getinfo = (int (*)(void*, const char*, prof_lua_Debug*))Lua::Sym(m, "lua_getinfo");
        g_lua.topointer = (const void* (*)(void*, int))Lua::Sym(m, "lua_topointer");
        g_lua.ok = g_lua.gettop && g_lua.settop && g_lua.type &&
                   g_lua.pushvalue && g_lua.getinfo && g_lua.topointer;
        Log::Debug("[CC-PROF] lua name api resolved=%d\n", (int)g_lua.ok);
    }

    static const int kFnSlots = 2048;
    struct FnSlot { uintptr_t fn; int bucket; };
    static FnSlot g_fnCache[kFnSlots];
    static inline unsigned FnHash(uintptr_t fn)
    {
        return (unsigned)((fn >> 4) * 2654435761u) & (kFnSlots - 1);
    }

    static inline int FnCacheFind(uintptr_t fn)
    {
        unsigned h = FnHash(fn);
        for (int p = 0; p < 8; ++p) {
            const FnSlot& s = g_fnCache[(h + p) & (kFnSlots - 1)];
            if (s.fn == fn) return s.bucket;
            if (!s.fn) break;
        }
        return -1;
    }

    static void FnCacheStore(uintptr_t fn, int bucket)
    {
        unsigned h = FnHash(fn);
        for (int p = 0; p < 8; ++p) {
            FnSlot& s = g_fnCache[(h + p) & (kFnSlots - 1)];
            if (!s.fn || s.fn == fn) { s.fn = fn; s.bucket = bucket; return; }
        }
        g_fnCache[h].fn = fn;
        g_fnCache[h].bucket = bucket;
    }

    static int BucketForLuaFunc(void* iface, int args)
    {
        if (!g_lua.tried) ResolveLuaApi();
        if (!g_lua.ok || !iface || !Mem::IsReadable(iface, 2 * sizeof(void*))) return g_unattributed;

        void* L = ((void**)iface)[1];
        if (!L || !Mem::IsReadable(L, sizeof(void*))) return g_unattributed;

        int top = g_lua.gettop(L);
        int idx = top - args;
        if (idx < 1 || idx > top) return g_unattributed;
        if (g_lua.type(L, idx) != CC_LUA_TFUNCTION) return g_unattributed;

        const void* fn = g_lua.topointer(L, idx);
        if (!fn) return g_unattributed;

        int hit = FnCacheFind((uintptr_t)fn);
        if (hit >= 0) return hit;

        ProfDebugBuf buf;
        memset(&buf, 0, sizeof(buf));
        prof_lua_Debug& ar = buf.d;
        g_lua.pushvalue(L, idx);
        int got = g_lua.getinfo(L, ">S", &ar);
        g_lua.settop(L, top);
        if (!got) return g_unattributed;

        char label[72];
        snprintf(label, sizeof(label), "lua:%s:%d", ShortSource(ar.short_src), ar.linedefined);

        const char* full = (ar.source && Mem::IsReadable(ar.source, 1)) ? ar.source : ar.short_src;
        int b = BucketFor(HashStr(label), NULL, label, full, PROF_LUA);
        if (b >= 0) FnCacheStore((uintptr_t)fn, b);
        return b;
    }

    // --------- profile-net ---

    #ifdef INTERFACE_PLUGIN
        static const char* kStringTableIface = "VEngineServerStringTable001";
    #else
        static const char* kStringTableIface = "VEngineClientStringTable001";
    #endif

    #if defined(CC_WINDOWS)
        static const int kSlotFindTable = 3;
        static const int kSlotGetString = 9;
    #else
        static const int kSlotFindTable = 4;
        static const int kSlotGetString = 10;
    #endif

    typedef void* (*Fn_createiface)(const char*, int*);
    typedef void* (CC_MEMBER *Fn_findtable)(void*, CC_EDX const char*);
    typedef const char* (CC_MEMBER *Fn_getstring)(void*, CC_EDX int);

    static const int kNetIdCache = 4096;
    static int16_t g_netIds[kNetIdCache];
    static void* g_netTable = NULL;

    static void* VSlot(void* obj, int slot)
    {
        if (!obj || !Mem::IsReadable(obj, sizeof(void*))) return NULL;
        void** vt = *(void***)obj;
        if (!vt || !Mem::IsReadable(vt, (size_t)(slot + 1) * sizeof(void*))) return NULL;
        return vt[slot];
    }

    static void* NetStringTable()
    {
        static Fn_createiface factory = NULL;
        static void* container = NULL;
        if (!container) {
            if (!factory) factory = (Fn_createiface)Sym::Lookup("engine", "CreateInterface");
            if (!factory) return NULL;
            container = factory(kStringTableIface, NULL);
            if (!container) return NULL;
        }
        Fn_findtable find = (Fn_findtable)VSlot(container, kSlotFindTable);
        return find ? find(container, CC_EDXARG "networkstring") : NULL;
    }

    static const char* NetStringForId(void* table, unsigned id)
    {
        Fn_getstring get = (Fn_getstring)VSlot(table, kSlotGetString);
        if (!get) return NULL;
        const char* s = get(table, CC_EDXARG (int)id);
        return (s && Mem::IsReadable(s, 1) && *s) ? s : NULL;
    }

    struct NetPeek { const unsigned char* base; int bit; int bits; };

    static inline unsigned PeekBits(const unsigned char* p, int at, int n)
    {
        unsigned v = 0;
        for (int i = 0; i < n; ++i) v |= (unsigned)((p[(at + i) >> 3] >> ((at + i) & 7)) & 1) << i;
        return v;
    }

    static bool PeekValid(const NetPeek& p)
    {
        if (!p.base || p.bits <= 0 || p.bits > (1 << 28)) return false;
        if (p.bit < 0 || p.bit + 24 > p.bits) return false;
        if (!Mem::IsReadable(p.base + (p.bit >> 3), 4)) return false;
        return PeekBits(p.base, p.bit, 8) <= 5; // gmod's packet type, 0..5
    }

    static bool PeekNew(const void* b, NetPeek* out)
    {
        #if defined(CC_X64)
            const int oBits = 12, oBytes = 16, oAvail = 28, oIn = 32, oData = 48;
        #else
            const int oBits = 8, oBytes = 12, oAvail = 20, oIn = 24, oData = 32;
        #endif
        if (!Mem::IsReadable(b, oData + sizeof(void*))) return false;
        const char* s = (const char*)b;
        const unsigned char* data = *(const unsigned char* const*)(s + oData);
        const unsigned char* in = *(const unsigned char* const*)(s + oIn);
        if (!data || in < data) return false;

        long long pos = (long long)((in - data) / 4) * 32
                      + 8 * (*(const int*)(s + oBytes) & 3)
                      - *(const int*)(s + oAvail);
        if (pos < 0 || pos > 0x7fffffff) return false;

        out->base = data;
        out->bit = (int)pos;
        out->bits = *(const int*)(s + oBits);
        return PeekValid(*out);
    }

    static bool PeekOld(const void* b, NetPeek* out)
    {
        const int oBits = (int)sizeof(void*) + 4;
        const int oCur = (int)sizeof(void*) + 8;
        if (!Mem::IsReadable(b, oCur + 4)) return false;
        const char* s = (const char*)b;
        out->base = *(const unsigned char* const*)s;
        out->bits = *(const int*)(s + oBits);
        out->bit = *(const int*)(s + oCur);
        return PeekValid(*out);
    }

    static int g_bufLayout = 0;
    static bool PeekNetBuf(const void* b, NetPeek* out)
    {
        if (!b) return false;
        int was = g_bufLayout;
        if (g_bufLayout != 2 && PeekNew(b, out)) g_bufLayout = 1;
        else if (g_bufLayout != 1 && PeekOld(b, out)) g_bufLayout = 2;
        else return false;
        if (!was) Log::Debug("[CC-PROF] bf_read layout = %s\n", g_bufLayout == 1 ? "word-cached" : "classic");
        return true;
    }

    static int BucketForNetId(unsigned id)
    {
        if (id < (unsigned)kNetIdCache && g_netIds[id] >= 0) return g_netIds[id];

        void* table = NetStringTable();
        const char* name = table ? NetStringForId(table, id) : NULL;
        if (!name) return -1;

        char label[72];
        snprintf(label, sizeof(label), "net:%s", name);
        int b = BucketFor(HashStr(label), NULL, label, NULL, PROF_NET);
        if (id < (unsigned)kNetIdCache && b >= 0) g_netIds[id] = (int16_t)b;
        return b;
    }

    static void NoteNetMessage(void* buf)
    {
        NetPeek p;
        if (!PeekNetBuf(buf, &p)) return;
        if (PeekBits(p.base, p.bit, 8) != 0) return;
        int b = BucketForNetId(PeekBits(p.base, p.bit + 8, 16));
        if (b >= 0) SetPending(b, PEND_NET);
    }

    // --------- profile-detours ---

    typedef int (CC_MEMBER *Fn_call)(void*, CC_EDX uintptr_t);
    typedef char (CC_MEMBER *Fn_args)(void*, CC_EDX uintptr_t);
    typedef int (CC_MEMBER *Fn_finish)(void*, CC_EDX int);
    typedef char (CC_MEMBER *Fn_finishbool)(void*, CC_EDX int, char);
    typedef int (CC_MEMBER *Fn_returns)(void*, CC_EDX int, int);
    typedef char (CC_MEMBER *Fn_protected)(void*, CC_EDX int, int, char);
    typedef char (*Fn_timercb)(unsigned, const void*, const void*);

    static Fn_call o_call_a = 0;
    static Fn_call o_call_b = 0;
    static Fn_args o_args_a = 0;
    static Fn_args o_args_b = 0;
    static Fn_finish o_finish = 0;
    static Fn_finishbool o_finishbool = 0;
    static Fn_returns o_returns = 0;
    static Fn_protected o_protected = 0;
    static Fn_timercb o_timercb = 0;

    static inline int BucketForCallArg(uintptr_t arg)
    {
        if (arg < 0x10000) return BucketForPooled((unsigned)arg);
        const char* s = (const char*)arg;
        return Mem::IsReadable(s, 1) ? BucketForName(s) : g_unattributed;
    }

    static inline int CallBody(void* self, uintptr_t arg, Fn_call orig)
    {
        if (g_enabled) SetPending(BucketForCallArg(arg), PEND_GAMEMODE);
        return orig(self, CC_EDXARG arg);
    }

    static inline char ArgsBody(void* self, uintptr_t arg, Fn_args orig)
    {
        char r = orig(self, CC_EDXARG arg);
        if (g_enabled && r) SetPending(BucketForCallArg(arg), PEND_GAMEMODE);
        return r;
    }

    static int CC_MEMBER h_call_a(void* self, CC_EDX uintptr_t arg) { return CallBody(self, arg, o_call_a); }
    static int CC_MEMBER h_call_b(void* self, CC_EDX uintptr_t arg) { return CallBody(self, arg, o_call_b); }
    static char CC_MEMBER h_args_a(void* self, CC_EDX uintptr_t arg) { return ArgsBody(self, arg, o_args_a); }
    static char CC_MEMBER h_args_b(void* self, CC_EDX uintptr_t arg) { return ArgsBody(self, arg, o_args_b); }

    static inline int GmScopeBegin(int bucket)
    {
        int frame = g_depth;
        Enter(-1);
        if (g_depth > frame && bucket >= 0) g_gmPending[frame] = bucket;
        return frame;
    }

    static inline void GmScopeEnd(int frame)
    {
        if (g_depth > frame) g_gmPending[frame] = -1;
        Exit();
    }

    static inline int GmScopePick()
    {
        for (int i = g_depth - 1; i >= 0; --i)
            if (g_gmPending[i] >= 0) return g_gmPending[i];
        return -1;
    }

    static int CC_MEMBER h_finish(void* self, CC_EDX int nargs)
    {
        if (!g_enabled) return o_finish(self, CC_EDXARG nargs);
        int frame = GmScopeBegin(TakePending(PEND_GAMEMODE));
        int r = o_finish(self, CC_EDXARG nargs);
        GmScopeEnd(frame);
        return r;
    }

    static char CC_MEMBER h_finishbool(void* self, CC_EDX int nargs, char showErrors)
    {
        if (!g_enabled) return o_finishbool(self, CC_EDXARG nargs, showErrors);
        int frame = GmScopeBegin(TakePending(PEND_GAMEMODE));
        char r = o_finishbool(self, CC_EDXARG nargs, showErrors);
        GmScopeEnd(frame);
        return r;
    }

    static int CC_MEMBER h_returns(void* self, CC_EDX int nargs, int nrets)
    {
        if (!g_enabled) return o_returns(self, CC_EDXARG nargs, nrets);
        int frame = GmScopeBegin(TakePending(PEND_GAMEMODE));
        int r = o_returns(self, CC_EDXARG nargs, nrets);
        GmScopeEnd(frame);
        return r;
    }

    static char CC_MEMBER h_protected(void* self, CC_EDX int args, int rets, char showErrors)
    {
        if (!g_enabled) return o_protected(self, CC_EDXARG args, rets, showErrors);
        int b = TakePending(PEND_CONCMD);
        if (b < 0) b = TakePending(PEND_TIMER);
        if (b < 0) b = TakePending(PEND_NET);
        if (b < 0) b = TakePending(PEND_GAMEMODE);
        if (b < 0) b = GmScopePick();
        if (b < 0) b = BucketForLuaFunc(self, args);
        Enter(b);
        char r = o_protected(self, CC_EDXARG args, rets, showErrors);
        Exit();
        return r;
    }

    static char h_timercb(unsigned ref, const void* identifier, const void* location)
    {
        if (!g_enabled) return o_timercb(ref, identifier, location);

        const char* id = StdStringData(identifier);
        const char* loc = StdStringData(location);

        bool anonymous = !id || strcmp(id, "Simple") == 0;
        const char* key = anonymous ? loc : id;
        if (key) {
            char label[72];
            if (anonymous) snprintf(label, sizeof(label), "timer.simple:%s", ShortSource(loc));
            else snprintf(label, sizeof(label), "timer:%s", id);
            SetPending(BucketFor(HashStr(key), NULL, label, loc, PROF_TIMER), PEND_TIMER);
        }

        return o_timercb(ref, identifier, location);
    }

    // --------- profile-concommand ---

    static void NoteConCommand(const void* cmd)
    {
        if (!cmd || !Mem::IsReadable(cmd, 1032 + sizeof(void*))) return;
        const int argc = *(const int*)cmd;
        const char* name = *(const char* const*)((const char*)cmd + 1032);
        if (argc <= 0 || !name || !Mem::IsReadable(name, 1) || !*name) return;

        char label[72];
        snprintf(label, sizeof(label), "command:%s", name);
        SetPending(BucketFor(HashStr(name), NULL, label, NULL, PROF_CONCMD), PEND_CONCMD);
    }

    typedef void (*Fn_concmd)(const void*);
    static Fn_concmd o_concmd = 0;

    static void h_concmd(const void* cmd)
    {
        if (g_enabled) NoteConCommand(cmd);
        o_concmd(cmd);
    }

    #ifdef INTERFACE_PLUGIN
        typedef void (CC_MEMBER *Fn_netmsg)(void*, CC_EDX int, void*, void*, int);
        static Fn_netmsg o_netmsg = 0;

        static void CC_MEMBER h_netmsg(void* self, CC_EDX int client, void* edict, void* buf, int bits)
        {
            if (g_enabled) NoteNetMessage(buf);
            o_netmsg(self, CC_EDXARG client, edict, buf, bits);
        }
    #else
        typedef void (CC_MEMBER *Fn_netmsg)(void*, CC_EDX void*, int);
        static Fn_netmsg o_netmsg = 0;

        static void CC_MEMBER h_netmsg(void* self, CC_EDX void* buf, int bits)
        {
            if (g_enabled) NoteNetMessage(buf);
            o_netmsg(self, CC_EDXARG buf, bits);
        }
    #endif

    // --------- profile-install ---

    struct Anchor {
        const char* module;
        const char* symbol;
        const char* literal;
        const char* sig;
        void* detour;
        void** tramp;
        void* target;
    };

    static const char* kConcmdSig =
        #if defined(CC_LINUX) && defined(CC_X86)
            "55 89 E5 57 56 53 83 EC 5C A1 ?? ?? ?? ?? 8B 75 ?? 85 C0";
        #elif defined(CC_LINUX) && defined(CC_X64)
            #ifdef INTERFACE_PLUGIN
                "55 48 89 E5 41 57 41 56 49 89 FE 41 55 41 54 53 48 83 EC 78 4C 8B 25";
            #else
                "55 48 89 E5 41 57 41 56 41 55 49 89 FD 41 54 53 48 83 EC 78 48 8B 05";
            #endif
        #elif defined(CC_WINDOWS) && defined(CC_X86)
            "55 8B EC 8B 0D ?? ?? ?? ?? 83 EC 3C 85 C9 0F 84 ?? ?? ?? ?? 8B 01 FF 90 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 56";
        #else
            "40 57 48 83 EC 70 48 8B F9 48 8B 0D ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ??";
        #endif

    #ifdef INTERFACE_PLUGIN
        static const char* kGameModule = "server";
        #define CC_NET_SYMBOL "_ZN18CServerGameClients25GMOD_ReceiveClientMessageEiP7edict_tP7bf_readi"
        #define CC_NET_MARKER "NetMessage(read_sv)"
    #else
        static const char* kGameModule = "client";
        #define CC_NET_SYMBOL NULL
        #define CC_NET_MARKER "NetMessage(read_cl)"
    #endif

    static Anchor g_anchors[] = {
        { NULL, "_ZN12CLuaGamemode4CallEPKc", "CLuaGamemode::Call", NULL, (void*)h_call_a, (void**)&o_call_a, 0 },
        { NULL, "_ZN12CLuaGamemode4CallEi", "CLuaGamemode::Call", NULL, (void*)h_call_b, (void**)&o_call_b, 0 },
        { NULL, "_ZN12CLuaGamemode12CallWithArgsEPKc","CLuaGamemode::CallWithArgs", NULL, (void*)h_args_a, (void**)&o_args_a, 0 },
        { NULL, "_ZN12CLuaGamemode12CallWithArgsEi", "CLuaGamemode::CallWithArgs", NULL, (void*)h_args_b, (void**)&o_args_b, 0 },
        { NULL, "_ZN12CLuaGamemode10CallFinishEi", "CLuaGamemode::CallFinish", NULL, (void*)h_finish, (void**)&o_finish, 0 },
        { NULL, "_ZN12CLuaGamemode14CallFinishBoolEib","CLuaGamemode::CallFinishBool",NULL, (void*)h_finishbool, (void**)&o_finishbool, 0 },
        { NULL, "_ZN12CLuaGamemode11CallReturnsEii",  "CLuaGamemode::CallReturns", NULL, (void*)h_returns, (void**)&o_returns, 0 },
        { NULL, "_ZN9GarrysMod3Lua9Libraries5Timer17CallTimerFunctionEiRKSsS4_", "Timer Failed! [%s][%s]\n", NULL, (void*)h_timercb, (void**)&o_timercb, 0 },
        { "lua_shared", "_ZN13CLuaInterface21CallFunctionProtectedEiib", "CLuaInterface::CallFunctionProtected", NULL, (void*)h_protected, (void**)&o_protected, 0 },
        { NULL, CC_NET_SYMBOL, CC_NET_MARKER, NULL, (void*)h_netmsg, (void**)&o_netmsg, 0 },
        { NULL, "_Z13LuaConCommandRK8CCommand", "Warning: Player issued command but is now vanished (Command was \"%s\")\n", kConcmdSig, (void*)h_concmd, (void**)&o_concmd, 0 },
    };
    static const int kAnchorCount = (int)(sizeof(g_anchors) / sizeof(g_anchors[0]));

    void Profile::Init()
    {
        for (int i = 0; i < kAnchorCount; ++i)
            if (!g_anchors[i].module) g_anchors[i].module = kGameModule;
    }

    void Profile::Poll()
    {
        if (g_disarmPending) {
            g_disarmPending = false;
            Profile::Uninstall();
            Profile::Reset();
            Log::Debug("[CC-PROF] disarmed, detours removed.\n");
            return;
        }
        uint64_t now = MonotonicMs();
        static uint64_t nextTry = 0;
        if (now < nextTry) return;
        nextTry = now + 1000;

        if (g_installed && g_enabled) {
            int secs = Cfg().profile_window;
            if (secs > 0 && Profile::WindowMs() >= (double)secs * 1000.0) Profile::Rotate();
            else if (g_nBuckets >= kMaxBuckets) Profile::Rotate();
            void* t = NetStringTable();
            if (t != g_netTable) {
                g_netTable = t;
                for (int i = 0; i < kNetIdCache; ++i) g_netIds[i] = -1;
            }
        }

        if (!Cfg().profile || g_installed) return;
        if (Profile::Install()) g_enabled = true;
    }

    static bool ModulesPresent()
    {
        return Modules::IsExactName(Modules::FindByName(kGameModule), kGameModule) &&
               Modules::IsExactName(Modules::FindByName("lua_shared"), "lua_shared");
    }

    bool Profile::Install()
    {
        if (g_installed) return true;

        if (!ModulesPresent()) {
            Modules::Refresh();
            if (!ModulesPresent()) {
                static bool waited = false;
                if (!waited) {
                    waited = true;
                    Log::Debug("[CC-PROF] waiting for %s + lua_shared to load.\n", kGameModule);
                }
                return false;
            }
        }

        const CCModule* gm = Modules::FindByName(kGameModule);
        uintptr_t base = gm ? gm->base : 0;
        if (base && base == g_triedBase) return false;
        g_triedBase = base;

        g_useTsc = HasInvariantTsc();
        int hooked = 0;
        int gameHooked = 0;

        if (gm) Log::Debug("[CC-PROF] %s -> %s @ %p (%u KiB)\n", kGameModule, gm->name,
                           (void*)gm->base, (unsigned)(gm->size >> 10));

        #if defined(CC_LINUX)
            for (int i = 0; i < kAnchorCount; ++i) {
                Anchor& a = g_anchors[i];
                if (a.target || !a.symbol) continue;
                uintptr_t addr = Sym::Lookup(a.module, a.symbol);
                if (addr && Hook::Install((void*)addr, a.detour, a.tramp)) {
                    a.target = (void*)addr;
                    ++hooked;
                }
                if (addr) Log::Debug("[CC-PROF] sym %s -> %p hooked=%d\n", a.symbol, (void*)addr, (int)(a.target != 0));
            }
        #endif

        for (int i = 0; i < kAnchorCount; ++i) {
            Anchor& a = g_anchors[i];
            Anchor* b = (i == 0 || i == 2) ? &g_anchors[i + 1] : NULL;
            if (a.target && (!b || b->target)) continue;

            uintptr_t addr = 0;
            if (b) {
                uintptr_t fns[4];
                int n = Sig::AnchorAll(a.module, a.literal, fns, 4);
                for (int x = 0; x < n; ++x) // ascending only for determinism; the two detours are interchangeable
                    for (int y = x + 1; y < n; ++y)
                        if (fns[y] < fns[x]) { uintptr_t t = fns[x]; fns[x] = fns[y]; fns[y] = t; }
                if (n >= 1) addr = fns[0];
                if (n >= 2 && !b->target && Hook::Install((void*)fns[1], b->detour, b->tramp)) {
                    b->target = (void*)fns[1];
                    ++hooked;
                    Log::Debug("[CC-PROF] %s (overload 2) -> %p\n", a.literal, (void*)fns[1]);
                }
                if (a.target) continue;
            } else {
                addr = Sig::Anchor(a.module, a.literal);
                if (!addr && a.sig) addr = Sig::Scan(a.module ? a.module : kGameModule, a.sig);
            }

            for (int j = 0; addr && j < kAnchorCount; ++j)
                if (g_anchors[j].target == (void*)addr) addr = 0;

            if (addr && Hook::Install((void*)addr, a.detour, a.tramp)) {
                a.target = (void*)addr;
                ++hooked;
            }
            Log::Debug("[CC-PROF] %s -> %p hooked=%d\n", a.literal, (void*)addr, (int)(a.target != 0));
        }

        for (int i = 0; i < kAnchorCount; ++i)
            if (g_anchors[i].target && g_anchors[i].module == kGameModule) ++gameHooked;

        if (!gameHooked) {
            for (int i = 0; i < kAnchorCount; ++i) {
                if (g_anchors[i].target) Hook::Uninstall(g_anchors[i].target);
                g_anchors[i].target = 0;
                *g_anchors[i].tramp = 0;
            }
            Log::F("[Crash Capture] profiler: no anchors resolved in %s (%d elsewhere); not arming.\n",
                   kGameModule, hooked);
            return false;
        }

        Profile::Reset();
        g_installed = true;
        Log::Debug("[CC-PROF] installed %d/%d anchors (tsc=%d)\n", hooked, kAnchorCount, (int)g_useTsc);
        return true;
    }

    void Profile::Uninstall()
    {
        g_enabled = false;
        g_disarmPending = false;
        if (!g_installed) return;
        for (int i = 0; i < kAnchorCount; ++i) {
            if (g_anchors[i].target) Hook::Uninstall(g_anchors[i].target);
            g_anchors[i].target = 0;
            *g_anchors[i].tramp = 0;
        }
        g_installed = false;
        g_triedBase = 0;
        g_prevCount = 0;
        g_prevWindowMs = 0;
        g_prevDropped = 0;
        g_prevBuckets = 0;
    }

    bool Profile::Enabled() { return g_enabled && g_installed; }

    void Profile::SetEnabled(bool on)
    {
        if (on) {
            g_disarmPending = false;
            if (!g_installed && !Profile::Install()) return;
            Profile::Reset();
            g_enabled = true;
            return;
        }
        g_enabled = false;
        if (g_installed) g_disarmPending = true;
    }

    void Profile::Reset()
    {
        g_depth = 0;
        g_skipped = 0;
        g_pending = -1;
        g_pendKind = PEND_NONE;
        for (int i = 0; i < kMaxDepth; ++i) g_gmPending[i] = -1;

        memset(g_keys, 0, sizeof(g_keys));
        memset(g_fnCache, 0, sizeof(g_fnCache));
        for (int i = 0; i < kNetIdCache; ++i) g_netIds[i] = -1;
        for (int i = 0; i < kPooledCache; ++i) g_pooled[i] = -1;
        g_pooledReady = true;
        g_nBuckets = 0;
        g_unattributed = NewBucket(NULL, "<unattributed>", NULL, PROF_OTHER);

        g_dropped = 0;
        g_anchorNs = NowNs();
        g_anchorTicks = Ticks();
    }

    void Profile::FrameBoundary()
    {
        g_depth = 0;
        g_skipped = 0;
        g_pending = -1;
        g_pendKind = PEND_NONE;
        for (int i = 0; i < kMaxDepth; ++i) g_gmPending[i] = -1;
    }

    bool Profile::HasSamples()
    {
        for (int i = 0; i < g_nBuckets; ++i) if (g_buckets[i].calls) return true;
        return false;
    }

    static uint64_t PercentileTicks(const uint32_t* h, uint64_t calls, double frac)
    {
        if (!calls) return 0;
        uint64_t want = (uint64_t)((double)calls * frac);
        if (want >= calls) want = calls - 1;
        uint64_t seen = 0;
        for (int i = 0; i < kHistBins; ++i) {
            seen += h[i];
            if (seen > want) return (3ull << i) / 2;
        }
        return 0;
    }

    static int SnapshotLive(ProfileBucket* out, int max)
    {
        int n = 0;
        for (int i = 0; i < g_nBuckets; ++i) {
            const ProfileBucket& src = g_buckets[i];
            if (!src.calls) continue;
            if (n == max && src.selfTicks <= out[max - 1].selfTicks) continue;

            int at = n < max ? n++ : max - 1;
            out[at] = src;
            out[at].p50Ms = Profile::TicksToMs(PercentileTicks(g_hist[i], src.calls, 0.50));
            out[at].p99Ms = Profile::TicksToMs(PercentileTicks(g_hist[i], src.calls, 0.99));
            while (at > 0 && out[at - 1].selfTicks < out[at].selfTicks) {
                ProfileBucket t = out[at - 1]; out[at - 1] = out[at]; out[at] = t;
                --at;
            }
        }

        for (int i = 0; i < n; ++i) {
            out[i].selfMs = Profile::TicksToMs(out[i].selfTicks);
            out[i].totalMs = Profile::TicksToMs(out[i].totalTicks);
            out[i].maxMs = Profile::TicksToMs(out[i].maxTicks);
            if (out[i].p99Ms > out[i].maxMs) out[i].p99Ms = out[i].maxMs;
            if (out[i].p50Ms > out[i].p99Ms) out[i].p50Ms = out[i].p99Ms;
        }
        return n;
    }

    void Profile::Rotate()
    {
        g_prevCount = SnapshotLive(g_prev, kMaxSnapshot);
        g_prevWindowMs = Profile::WindowMs();
        g_prevDropped = g_dropped;
        g_prevBuckets = g_nBuckets;
        ++g_rotations;
        Profile::Reset();
    }

    ProfileView Profile::Snapshot(ProfileBucket* out, int max)
    {
        ProfileView v = { 0, false, 0.0, 0, 0 };
        if (!out || max <= 0) return v;

        double live = Profile::WindowMs();
        if (g_prevCount > 0 && live < 5000.0) {
            int n = g_prevCount < max ? g_prevCount : max;
            for (int i = 0; i < n; ++i) out[i] = g_prev[i];
            v.count = n;
            v.previous = true;
            v.windowMs = g_prevWindowMs;
            v.dropped = g_prevDropped;
            v.buckets = g_prevBuckets;
            return v;
        }

        v.count = SnapshotLive(out, max);
        v.windowMs = live;
        v.dropped = g_dropped;
        v.buckets = g_nBuckets;
        return v;
    }

    const char* Profile::KindName(int kind)
    {
        switch (kind) {
            case PROF_HOOK: return "hook";
            case PROF_TIMER: return "timer";
            case PROF_LUA: return "lua";
            case PROF_NET: return "net";
            case PROF_CONCMD: return "command";
            default: return "other";
        }
    }

    void Profile::ReportSection()
    {
        if (!g_installed) return;

        int depth = g_depth;
        if (depth > 0) {
            Log::Str("\n**In flight**\n");
            for (int i = 0; i < depth && i < kMaxDepth; ++i) {
                const char* nm = Profile::NameAt(i);
                Log::F("- `%s` (%.1f ms so far)\n", nm ? nm : "?", Profile::ElapsedMsAt(i));
            }
        }

        static ProfileBucket snap[32];
        ProfileView v = Profile::Snapshot(snap, 32);
        if (!v.count) {
            if (g_enabled) Log::Str("\n_profiler armed, no samples yet._\n");
            return;
        }

        Log::F("\n**Lua call profile** (%.0f ms %s window, %s)\n\n", v.windowMs,
               v.previous ? "completed" : "live", g_enabled ? "sampling" : "stopped");
        Log::Str("| kind | name | calls | self ms | total ms | p50 ms | p99 ms | worst ms |\n");
        Log::Str("|---|---|---:|---:|---:|---:|---:|---:|\n");
        for (int i = 0; i < v.count; ++i) {
            const ProfileBucket& b = snap[i];
            Log::F("| %s | `%s` | %llu | %.2f | %.2f | %.2f | %.2f | %.2f |\n",
                   Profile::KindName(b.kind), b.name, (unsigned long long)b.calls,
                   b.selfMs, b.totalMs, b.p50Ms, b.p99Ms, b.maxMs);
        }
        if (v.dropped)
            Log::F("\n_%llu call(s) dropped: bucket table full._\n", (unsigned long long)v.dropped);
    }
}
