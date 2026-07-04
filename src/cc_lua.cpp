// Crash Capture - Lua
// Per-realm call stack + locals + value stack via the public LuaJIT C API

#include "crashcapture.h"

#include "glua/LuaShared.h"
#include "glua/LuaInterface.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#if defined(CC_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <windows.h>
#else
    #include <dlfcn.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

using GarrysMod::Lua::ILuaShared;
using GarrysMod::Lua::ILuaInterface;
namespace LuaState = GarrysMod::Lua::State;

namespace CrashCapture {
    typedef void* (*CreateInterfaceFn)(const char* name, int* returncode);
    static ILuaShared* g_shared = NULL;
    static ILuaInterface* g_realm[3] = { NULL, NULL, NULL }; // CLIENT, SERVER, MENU
    static bool g_apiInstalled[3] = { false, false, false }; // crashcapture table installed
    static bool g_hbInstalled[3] = { false, false, false }; // heartbeat timer/hook installed
    static bool g_readyPending[3] = { false, false, false }; // crashcapture.ready hook owed to this realm
    static bool g_readyFired[3] = { false, false, false }; // crashcapture.ready hook already fired for this realm
    static void* g_apiState[3] = { NULL, NULL, NULL }; // lua_State each was installed on

    // lua_Debug must match LuaJIT's layout byte-for-byte
    // this better not change... ever...
    #define CC_LUA_IDSIZE 60
    struct cc_lua_Debug {
        int         event;
        const char* name;
        const char* namewhat;
        const char* what;
        const char* source;
        int         currentline;
        int         nups;
        int         linedefined;
        int         lastlinedefined;
        char        short_src[CC_LUA_IDSIZE];
        int         i_ci;
    };

    typedef void (*cc_lua_Hook)(lua_State*, cc_lua_Debug*);
    #define CC_LUA_MASKCOUNT (1 << 3)
    enum {
        CC_LT_NIL = 0, CC_LT_BOOL = 1, CC_LT_LIGHTUD = 2, CC_LT_NUM = 3,
        CC_LT_STR = 4, CC_LT_TAB = 5, CC_LT_FUNC = 6, CC_LT_UD = 7, CC_LT_THREAD = 8
    };

    struct LuaApi {
        int         (*gettop)(lua_State*);
        void        (*settop)(lua_State*, int);
        int         (*type)(lua_State*, int);
        const char* (*typenm)(lua_State*, int);
        const char* (*tolstring)(lua_State*, int, size_t*);
        double      (*tonumber)(lua_State*, int);
        int         (*toboolean)(lua_State*, int);
        const void* (*topointer)(lua_State*, int);
        void*       (*touserdata)(lua_State*, int);
        int         (*getstack)(lua_State*, int, cc_lua_Debug*);
        int         (*getinfo)(lua_State*, const char*, cc_lua_Debug*);
        const char* (*getlocal)(lua_State*, const cc_lua_Debug*, int);
        void        (*pushnil)(lua_State*);
        void        (*pushnumber)(lua_State*, double);
        void        (*pushboolean)(lua_State*, int);
        void        (*pushstring)(lua_State*, const char*);
        int         (*sethook)(lua_State*, cc_lua_Hook, int, int);
        int         (*error)(lua_State*);
        bool        ok; // stack-walk API resolved
        bool        push_ok; // push API resolved
        bool        hook_ok; // loop-break resolved
    };

    static const char* kGmodTypeName[] = {
        "nil", "bool", "lightuserdata", "number", "string", "table", "function",
        "userdata", "thread", "Entity", "Vector", "Angle", "PhysObj", "Save",
        "Restore", "DamageInfo", "EffectData", "MoveData", "RecipientFilter",
        "UserCmd", "Vehicle", "Material", "Panel", "Particle", "ParticleEmitter",
        "Texture", "UserMsg", "ConVar", "IMesh", "Matrix", "Sound", "PixelVisHandle",
        "DLight", "Video", "File", "Locomotion", "Path", "NavArea", "SoundHandle",
        "NavLadder", "ParticleSystem", "ProjectedTexture", "PhysCollide", "SurfaceInfo",
    };
    static LuaApi g_api = {0};
    static const char* g_apiDiag = "not attempted"; // why resolution failed (for the report)

    #if !defined(CC_WINDOWS)
        // Some branches of this game doesn't really always turn out to be the correct lua_shared naming.
        static bool FindLuaSharedPath(char* out, size_t outsz)
        {
            int fd = open("/proc/self/maps", O_RDONLY);
            if (fd < 0) return false;
            static char buf[256 * 1024];
            size_t total = 0; ssize_t r;
            while (total < sizeof(buf) - 1 && (r = read(fd, buf + total, sizeof(buf) - 1 - total)) > 0)
                total += (size_t)r;
            close(fd);
            buf[total] = 0;

            for (char* line = buf; line && *line; ) {
                char* nl = strchr(line, '\n');
                if (nl) *nl = 0;
                const char* slash = strrchr(line, '/');
                if (slash && strstr(slash, "lua_shared") && strstr(slash, ".so")) {
                    const char* path = line;
                    for (const char* p = line; *p; ++p) if (*p == '/') { path = p; break; }
                    snprintf(out, outsz, "%s", path);
                    return true;
                }
                line = nl ? nl + 1 : NULL;
            }
            return false;
        }
    #endif

    // Handle to the loaded lua_shared for symbol lookup. Resolved at arm time.
    void* Lua_SharedHandle()
    {
    #if defined(CC_WINDOWS)
        HMODULE h = GetModuleHandleA("lua_shared.dll");
        if (!h) h = GetModuleHandleA("lua_shared_srv.dll");
        return (void*)h;
    #else
        const char* names[] = { "lua_shared.so", "lua_shared_srv.so", "lua_shared_client.so", NULL };
        for (int i = 0; names[i]; ++i) {
            void* h = dlopen(names[i], RTLD_NOW | RTLD_NOLOAD);
            if (h) return h;
        }
        char path[512];
        if (FindLuaSharedPath(path, sizeof(path))) {
            void* h = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
            if (h) return h;
        }
        return NULL;
    #endif
    }

    void* Lua_Sym(void* mod, const char* n)
    {
    #if defined(CC_WINDOWS)
        return mod ? (void*)GetProcAddress((HMODULE)mod, n) : NULL;
    #else
        return mod ? dlsym(mod, n) : NULL;
    #endif
    }

    static void Lua_ResolveApi()
    {
        if (g_api.ok) return;
        void* m = Lua_SharedHandle();
        if (!m) { g_apiDiag = "lua_shared handle not found"; return; }

        // Resolve each symbol, on the first miss, record its name for the report.
        struct Sym { const char* name; void** slot; };
        Sym syms[] = {
            {"lua_gettop", (void**)&g_api.gettop},
            {"lua_settop", (void**)&g_api.settop},
            {"lua_type", (void**)&g_api.type},
            {"lua_typename", (void**)&g_api.typenm},
            {"lua_tolstring", (void**)&g_api.tolstring},
            {"lua_tonumber", (void**)&g_api.tonumber},
            {"lua_toboolean", (void**)&g_api.toboolean},
            {"lua_topointer", (void**)&g_api.topointer},
            {"lua_touserdata", (void**)&g_api.touserdata},
            {"lua_getstack", (void**)&g_api.getstack},
            {"lua_getinfo", (void**)&g_api.getinfo},
            {"lua_getlocal", (void**)&g_api.getlocal},
        };
        bool all = true;
        for (size_t i = 0; i < sizeof(syms)/sizeof(syms[0]); ++i) {
            *syms[i].slot = Lua_Sym(m, syms[i].name);
            if (!*syms[i].slot && all) { g_apiDiag = syms[i].name; all = false; }
        }
        g_api.ok = all;
        if (all) g_apiDiag = "ok";

        // specific for the crash capture API
        g_api.pushnil = (void(*)(lua_State*)) Lua_Sym(m, "lua_pushnil");
        g_api.pushnumber = (void(*)(lua_State*, double)) Lua_Sym(m, "lua_pushnumber");
        g_api.pushboolean = (void(*)(lua_State*, int)) Lua_Sym(m, "lua_pushboolean");
        g_api.pushstring = (void(*)(lua_State*, const char*)) Lua_Sym(m, "lua_pushstring");
        g_api.push_ok = g_api.pushnil && g_api.pushnumber && g_api.pushboolean && g_api.pushstring;

        // loop-break: set a count hook that raises an error out of the running VM.
        g_api.sethook = (int(*)(lua_State*, cc_lua_Hook, int, int)) Lua_Sym(m, "lua_sethook");
        g_api.error = (int(*)(lua_State*)) Lua_Sym(m, "lua_error");
        g_api.hook_ok = g_api.sethook && g_api.error && g_api.pushstring;
    }

    static const char* RealmName(int r)
    {
        return (r >= 0 && r < 3 && LuaState::Name[r]) ? LuaState::Name[r] : "?";
    }

    static int RealmOf(ILuaInterface* iface)
    {
        if (!iface) return -1;
        // IsServer/IsClient/IsMenu are trivial getters; safe to call at bind time.
        if (iface->IsMenu()) return LuaState::MENU;
        if (iface->IsServer()) return LuaState::SERVER;
        if (iface->IsClient()) return LuaState::CLIENT;
        return -1;
    }

    void Lua_OnInit(void* iface)
    {
        ILuaInterface* l = (ILuaInterface*)iface;
        int r = RealmOf(l);
        if (r >= 0) g_realm[r] = l;
        Lua_InstallApi(iface);
        Lua_InstallHeartbeat(iface);
    }

    void Lua_OnShutdown(void* iface)
    {
        for (int i = 0; i < 3; ++i)
            if (g_realm[i] == iface) {
                g_realm[i] = NULL;
                g_apiState[i] = NULL;
                g_apiInstalled[i] = false;
                g_hbInstalled[i] = false;
                g_readyPending[i] = false;
                g_readyFired[i] = false;
            }
    }

    bool Lua_HasBoundRealms()
    {
        for (int i = 0; i < 3; ++i) if (g_realm[i]) return true;
        return false;
    }

    static CreateInterfaceFn ResolveLuaSharedFactory()
    {
        void* h = Lua_SharedHandle();
        return h ? (CreateInterfaceFn)Lua_Sym(h, "CreateInterface") : NULL;
    }

    void Lua_RefreshStates()
    {
        Lua_ResolveApi();
        if (!g_shared) {
            CreateInterfaceFn ci = ResolveLuaSharedFactory();
            if (ci) g_shared = (ILuaShared*)ci(GMOD_LUASHARED_INTERFACE, NULL);
        }
        if (g_shared) {
            for (int r = 0; r < 3; ++r)
                if (!g_realm[r]) g_realm[r] = g_shared->GetLuaInterface((unsigned char)r);
        }
    }

    // --------- lua-reporter ---

    static int GmodTypeByte(lua_State* L, int idx)
    {
        if (!g_api.touserdata) return -1;
        unsigned char* ud = (unsigned char*)g_api.touserdata(L, idx);
        if (!ud || !Mem_IsReadable(ud, sizeof(void*) + 1)) return -1;
        return ud[sizeof(void*)];
    }

    static void FormatValue(lua_State* L, int idx, char* out, size_t outsz)
    {
        int t = g_api.type(L, idx);
        switch (t) {
            case CC_LT_NIL:  snprintf(out, outsz, "nil"); break;
            case CC_LT_BOOL: snprintf(out, outsz, g_api.toboolean(L, idx) ? "true" : "false"); break;
            case CC_LT_NUM:  snprintf(out, outsz, "%.14g", g_api.tonumber(L, idx)); break;
            case CC_LT_STR: {
                size_t n = 0;
                const char* s = g_api.tolstring(L, idx, &n);
                if (!s) { snprintf(out, outsz, "string <?>"); break; }
                // truncate long strings so one value can't blow the line.
                int w = snprintf(out, outsz, "\"");
                size_t cap = (n < 60) ? n : 60;
                for (size_t i = 0; i < cap && (size_t)w < outsz - 8; ++i) {
                    unsigned char c = (unsigned char)s[i];
                    out[w++] = (c >= 0x20 && c < 0x7f && c != '"') ? (char)c : '.';
                }
                snprintf(out + w, outsz - w, "%s\"", n > cap ? "..." : "");
                break;
            }
            case CC_LT_UD: {
                const void* p = g_api.topointer(L, idx);
                int gt = GmodTypeByte(L, idx);
                if (gt >= 9 && gt < (int)(sizeof(kGmodTypeName) / sizeof(kGmodTypeName[0])))
                    snprintf(out, outsz, "%s: %p", kGmodTypeName[gt], p);
                else if (gt >= (int)(sizeof(kGmodTypeName) / sizeof(kGmodTypeName[0])))
                    snprintf(out, outsz, "userdata<%d>: %p", gt, p); // custom usertype
                else
                    snprintf(out, outsz, "userdata: %p", p);
                break;
            }
            default: {
                const char* tn = g_api.typenm(L, t);
                snprintf(out, outsz, "%s: %p", tn ? tn : "?", g_api.topointer(L, idx));
                break;
            }
        }
    }

    struct FrameCtx { lua_State* L; int level; bool more; };
    static void Sec_Frame(void* p)
    {
        FrameCtx* c = (FrameCtx*)p;
        lua_State* L = c->L;
        cc_lua_Debug ar;
        memset(&ar, 0, sizeof(ar));
        if (!g_api.getstack(L, c->level, &ar)) { c->more = false; return; }
        c->more = true;
        g_api.getinfo(L, "nSl", &ar);

        const char* what = ar.namewhat && *ar.namewhat ? ar.namewhat : "";
        const char* nm   = ar.name ? ar.name : (ar.what ? ar.what : "?");
        Log::F("#%-2d %s:%d  %s %s\n", c->level,
            ar.short_src[0] ? ar.short_src : "?", ar.currentline, what, nm);

        // C-frame locals are read off the C stack.
        bool luaFrame = ar.what && (ar.what[0] == 'L' || ar.what[0] == 'm');
        if (!luaFrame) return;

        int saved = g_api.gettop(L);
        for (int n = 1; n < 200; ++n) {
            const char* lname = g_api.getlocal(L, &ar, n);
            if (!lname) break;
            char val[128];
            FormatValue(L, -1, val, sizeof(val));
            Log::F("      %s = %s\n", lname, val);
            g_api.settop(L, saved);
        }
    }

    static void Sec_ValueStack(void* p)
    {
        lua_State* L = (lua_State*)p;
        int top = g_api.gettop(L);
        // top < 0 (below base) or > LuaJIT's max => transient mid-call state, can't read it.
        if (top <= 0 || top > 65536) {
            Log::F("<unavailable: VM in transient state (reported top=%d)>\n", top);
            return;
        }
        Log::F("(%d slot%s)\n", top, top == 1 ? "" : "s");
        int lo = top > 64 ? top - 64 + 1 : 1; // cap to last 64 slots
        if (lo > 1) Log::F("... %d lower slots omitted ...\n", lo - 1);
        for (int i = lo; i <= top; ++i) {
            const char* tn = g_api.typenm(L, g_api.type(L, i));
            char val[128];
            FormatValue(L, i, val, sizeof(val));
            Log::F("[%d] %-9s %s\n", i, tn ? tn : "?", val);
        }
    }

    static void DumpRealm(int r, ILuaInterface* l)
    {
        Log::F("\n### %s realm\n\n", RealmName(r));
        Log::F("- interface: `%p`\n", (void*)l);

        if (!g_api.ok) {
            Log::F("\n_LuaJIT C API not resolved from lua_shared (%s); no stack walk._\n",
                g_apiDiag ? g_apiDiag : "?");
            return;
        }
        if (!Mem_IsReadable(l, 2 * sizeof(void*))) {
            Log::Str("\n_interface not readable; skipping stack walk._\n");
            return;
        }
        lua_State* L = l->GetState();
        if (!L || !Mem_IsReadable(L, sizeof(void*))) {
            Log::Str("\n_lua_State not readable; skipping stack walk._\n");
            return;
        }
        int top0 = g_api.gettop(L);
        Log::F("- stack top: %d%s\n", top0,
            top0 < 0 ? " (VM caught mid-call; transient state)" : "");

        Log::Str("\n**call stack** (frame -- source:line -- name -- locals)\n\n");
        Log::OpenFence();
        int frames = 0, faults = 0;
        bool stoppedByFault = false;
        for (int level = 0; level < 64; ++level) {
            FrameCtx fc = { L, level, false };
            if (!RunProtectedQuiet(Sec_Frame, &fc)) { // VM in a mid-mcode can fault per-frame, this fixes that, shouldn't cause the rest to fail.
                if (++faults >= 2) { stoppedByFault = true; break; }
                continue;
            }
            faults = 0;
            if (!fc.more) break; // no more frames
            ++frames;
        }
        if (!frames) Log::Str("<no readable Lua frames>\n");
        else if (stoppedByFault)
            Log::Str("...deeper frames unreadable (VM in transient state)\n");
        Log::CloseFence();

        Log::Str("\n**value stack**\n\n");
        Log::OpenFence();
        RunProtected(Sec_ValueStack, L);
        Log::CloseFence();
    }

    void Lua_Dump()
    {
        Lua_RefreshStates();

        bool any = false;
        for (int r = 0; r < 3; ++r) {
            ILuaInterface* l = g_realm[r];
            if (!l) continue;
            if (!Mem_IsReadable(l, sizeof(void*))) continue;
            any = true;
            DumpRealm(r, l);
        }

        if (!any)
            Log::Str("\n_no bound Lua interfaces (lua_shared not resolved or no realms up)._\n");
    }

    struct CapCtx { lua_State* L; int level; CCLuaFrame* f; bool more; };
    static void Sec_CapFrame(void* p)
    {
        CapCtx* c = (CapCtx*)p;
        lua_State* L = c->L;
        cc_lua_Debug ar;
        memset(&ar, 0, sizeof(ar));
        if (!g_api.getstack(L, c->level, &ar)) { c->more = false; return; }
        c->more = true;
        g_api.getinfo(L, "nSl", &ar);

        CCLuaFrame* f = c->f;
        f->level = c->level;
        f->currentline = ar.currentline;
        snprintf(f->source, sizeof(f->source), "%s", ar.short_src[0] ? ar.short_src : "?");
        snprintf(f->name, sizeof(f->name), "%s", ar.name ? ar.name : (ar.what ? ar.what : "?"));
        snprintf(f->what, sizeof(f->what), "%s", ar.what ? ar.what : "?");
        f->locals[0] = 0;

        bool luaFrame = ar.what && (ar.what[0] == 'L' || ar.what[0] == 'm');
        if (!luaFrame) return;

        int saved = g_api.gettop(L);
        int w = 0;
        for (int n = 1; n < 50; ++n) {
            const char* lname = g_api.getlocal(L, &ar, n);
            if (!lname) break;
            char val[96];
            FormatValue(L, -1, val, sizeof(val));
            g_api.settop(L, saved);
            if (lname[0] == '(') continue;
            w += snprintf(f->locals + w, sizeof(f->locals) - w, "%s%s=%s", w ? "; " : "", lname, val);
            if ((size_t)w >= sizeof(f->locals) - 1) break;
        }
    }

    int Lua_CaptureTraces(CCLuaTrace* out, int maxRealms)
    {
        if (!out || maxRealms <= 0) return 0;
        Lua_RefreshStates();
        if (!g_api.ok) return 0;

        int rc = 0;
        const int maxFrames = (int)(sizeof(out[0].frames) / sizeof(out[0].frames[0]));
        for (int r = 0; r < 3 && rc < maxRealms; ++r) {
            ILuaInterface* l = g_realm[r];
            if (!l || !Mem_IsReadable(l, 2 * sizeof(void*))) continue;
            lua_State* L = l->GetState();
            if (!L || !Mem_IsReadable(L, sizeof(void*))) continue;

            CCLuaTrace* t = &out[rc];
            memset(t, 0, sizeof(*t));
            snprintf(t->realm, sizeof(t->realm), "%s", RealmName(r));
            t->top = g_api.gettop(L);

            int faults = 0;
            for (int level = 0; level < maxFrames; ++level) {
                CapCtx cc = { L, level, &t->frames[t->frameCount], false };
                if (!RunProtectedQuiet(Sec_CapFrame, &cc)) { if (++faults >= 2) break; continue; }
                faults = 0;
                if (!cc.more) break;
                ++t->frameCount;
            }
            ++rc;
        }
        return rc;
    }

    // --------- recovery-hooks ---
    
    enum { CC_REC_STACK_MAX = 16 };
    struct RecoveryInfo {
        char method[16];
        char stall[32];
        char reason[176];
        char report[768];
        uint64_t downtime;
        int  stackCount;
        char stack[CC_REC_STACK_MAX][192];
    };
    static RecoveryInfo g_recInfo;
    static volatile sig_atomic_t g_recLoopbreak = 0;
    static volatile sig_atomic_t g_recPhysresume = 0;
    static volatile sig_atomic_t g_recRecovery = 0;

    static void RecStr(char* dst, size_t cap, const char* s) { snprintf(dst, cap, "%s", s ? s : ""); }

    void Recovery_NotePhysResume(const char* stall, const char* report)
    {
        RecStr(g_recInfo.method, sizeof(g_recInfo.method), "physresume");
        RecStr(g_recInfo.stall,  sizeof(g_recInfo.stall),  stall ? stall : "physics");
        RecStr(g_recInfo.reason, sizeof(g_recInfo.reason), "");
        RecStr(g_recInfo.report, sizeof(g_recInfo.report), report);
        g_recInfo.downtime = 0;
        g_recInfo.stackCount = 0;
        g_recPhysresume = 1;
        g_recRecovery = 1;
    }

    void Recovery_NoteRecovered(const char* method, uint64_t downtimeMs, const char* stall, const char* reason, const char* report)
    {
        RecStr(g_recInfo.method, sizeof(g_recInfo.method), method);
        RecStr(g_recInfo.stall,  sizeof(g_recInfo.stall),  stall);
        RecStr(g_recInfo.reason, sizeof(g_recInfo.reason), reason);
        RecStr(g_recInfo.report, sizeof(g_recInfo.report), report);
        g_recInfo.downtime = downtimeMs;
        g_recInfo.stackCount = 0;
        g_recRecovery = 1;
    }

    static void FireRecoveryHook(ILuaInterface* L, const char* event, const RecoveryInfo& info)
    {
        namespace G = GarrysMod::Lua;
        L->PushSpecial(G::SPECIAL_GLOB);
        L->GetField(-1, "hook");
        if (!L->IsType(-1, G::Type::Table)) { L->Pop(2); return; }
        L->GetField(-1, "Run");
        if (!L->IsType(-1, G::Type::Function)) { L->Pop(3); return; }
        L->PushString(event);

        L->CreateTable();
        if (info.method[0]) { L->PushString(info.method); L->SetField(-2, "method"); }
        if (info.stall[0])  { L->PushString(info.stall); L->SetField(-2, "stall"); }
        if (info.reason[0]) { L->PushString(info.reason); L->SetField(-2, "reason"); }
        if (info.report[0]) { L->PushString(info.report); L->SetField(-2, "report"); }
        if (info.downtime)  { L->PushNumber((double)info.downtime); L->SetField(-2, "downtime"); }
        if (info.stackCount > 0) {
            L->CreateTable();
            for (int i = 0; i < info.stackCount; ++i) {
                L->PushNumber((double)(i + 1));
                L->PushString(info.stack[i]);
                L->SetTable(-3);
            }
            L->SetField(-2, "stack");
        }
        if (L->PCall(2, 0, 0) != 0) L->Pop(1);
        L->Pop(2);
    }

    void Lua_PollRecovery()
    {
        int lb = g_recLoopbreak, pr = g_recPhysresume, rc = g_recRecovery;
        if (!lb && !pr && !rc) return;
        g_recLoopbreak = g_recPhysresume = g_recRecovery = 0;

        RecoveryInfo info = g_recInfo;
        Lua_RefreshStates();
        for (int r = 0; r < 3; ++r) {
            ILuaInterface* l = g_realm[r];
            if (!l || !Mem_IsReadable(l, 2 * sizeof(void*))) continue;
            void* L = (void*)l->GetState();
            if (!L || !Mem_IsReadable(L, sizeof(void*))) continue;
            if (lb) FireRecoveryHook(l, "crashcapture.loopbreak", info);
            if (pr) FireRecoveryHook(l, "crashcapture.physresume", info);
            if (rc) FireRecoveryHook(l, "crashcapture.recovery", info);
        }
    }

    // --------- lua-ready ---

    static bool FireReadyHook(ILuaInterface* L, int r)
    {
        namespace G = GarrysMod::Lua;
        L->PushSpecial(G::SPECIAL_GLOB);
        L->GetField(-1, "hook");
        if (!L->IsType(-1, G::Type::Table)) { L->Pop(2); return false; }
        L->GetField(-1, "Run");
        if (!L->IsType(-1, G::Type::Function)) { L->Pop(3); return false; }
        L->PushString("crashcapture.ready");

        L->CreateTable();
        L->PushString(RealmName(r)); L->SetField(-2, "realm");
        L->PushString(CC_SIDE); L->SetField(-2, "side");
        L->PushString(CC_VERSION); L->SetField(-2, "version");
        L->PushString(CC_OS); L->SetField(-2, "os");
        L->PushString(CC_ARCH); L->SetField(-2, "arch");

        if (L->PCall(2, 0, 0) != 0) L->Pop(1);
        L->Pop(2);
        return true;
    }

    void Lua_PollReady()
    {
        bool pending = false;
        for (int r = 0; r < 3; ++r) if (g_readyPending[r]) { pending = true; break; }
        if (!pending) return;

        Lua_RefreshStates();
        for (int r = 0; r < 3; ++r) {
            if (!g_readyPending[r]) continue;
            ILuaInterface* l = g_realm[r];
            if (!l || !Mem_IsReadable(l, 2 * sizeof(void*))) continue;
            void* L = (void*)l->GetState();
            if (!L || !Mem_IsReadable(L, sizeof(void*))) continue;
            if (FireReadyHook(l, r)) {
                g_readyPending[r] = false;
                g_readyFired[r] = true;
            }
        }
    }

    static void Lua_DisarmBreakHook()
    {
        if (!g_api.sethook) return;
        for (int r = 0; r < 3; ++r) {
            ILuaInterface* l = g_realm[r];
            if (!l || !Mem_IsReadable(l, 2 * sizeof(void*))) continue;
            lua_State* L = l->GetState();
            if (!L || !Mem_IsReadable(L, sizeof(void*))) continue;
            g_api.sethook(L, NULL, 0, 0);
        }
    }

    static const char* g_breakMsg = "CrashCapture: interrupting a suspected infinite loop";
    static void cc_break_hook(lua_State* L, cc_lua_Debug* /*ar*/)
    {
        if (!Mem_IsReadable(L, sizeof(void*))) { Lua_DisarmBreakHook(); return; }
        if (g_api.sethook) g_api.sethook(L, NULL, 0, 0);

        RecStr(g_recInfo.method, sizeof(g_recInfo.method), "loopbreak");
        RecStr(g_recInfo.stall,  sizeof(g_recInfo.stall),  StallClassName(g_lastStallClass));
        RecStr(g_recInfo.reason, sizeof(g_recInfo.reason), "");
        RecStr(g_recInfo.report, sizeof(g_recInfo.report), "");
        g_recInfo.downtime = 0;
        g_recInfo.stackCount = 0;
        g_recLoopbreak = 1;

        if (!Mem_IsReadable(L, sizeof(void*))) return;
        if (g_api.pushstring) g_api.pushstring(L, g_breakMsg);
        if (g_api.error) g_api.error(L);
    }

    int Lua_ArmBreakHook()
    {
        if (!g_api.hook_ok) return 0;
        int armed = 0;
        for (int r = 0; r < 3; ++r) {
            if (r == LuaState::MENU) continue;
            ILuaInterface* l = g_realm[r];
            if (!l || !Mem_IsReadable(l, 2 * sizeof(void*))) continue;
            lua_State* L = l->GetState();
            if (!L || !Mem_IsReadable(L, sizeof(void*))) continue;
            g_api.sethook(L, cc_break_hook, CC_LUA_MASKCOUNT, 1);
            ++armed;
        }
        return armed;
    }

    bool Lua_BreakLoop(const char* msg)
    {
        Lua_RefreshStates();
        if (msg && *msg) g_breakMsg = msg;
        if (!g_api.hook_ok) {
            Log::Str("[CrashCapture] loop-break unavailable (lua_sethook/lua_error not resolved from lua_shared).\n");
            return false;
        }

        int routed = Platform_RequestLuaBreak();
        if (routed >= 0) {
            if (routed)
                Log::F("[CrashCapture] loop-break: armed count hook on %d realm(s) on the game thread.\n", routed);
            else
                Log::Str("[CrashCapture] loop-break: game thread had no readable Lua realms.\n");
            return routed > 0;
        }

        // fallback if request break doesn't work...
        int armed = Lua_ArmBreakHook();
        if (armed)
            Log::F("[CrashCapture] loop-break: armed count hook on %d realm(s).\n", armed);
        else
            Log::Str("[CrashCapture] loop-break: no readable Lua realms to hook.\n");
        return armed > 0;
    }

    // --------- lua-heartbeat ---

    static int cc_lua_pulse(lua_State*)
    {
        Watchdog_Pulse();
        Lua_PollRecovery();
        Lua_PollReady();
        return 0;
    }

    void Lua_InstallHeartbeat(void* iface)
    {
        if (!Cfg().lua_heartbeat) return;

        ILuaInterface* L = (ILuaInterface*)iface;
        if (!L) return;

        int r = RealmOf(L);
        if (r >= 0) {
            if (g_hbInstalled[r]) return;
            g_realm[r] = L;
        }

        // call this function to pulse crashcapture to keep alive
        L->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
        L->PushCFunction(cc_lua_pulse);
        L->SetField(-2, "CrashCapture_Pulse");
        L->Pop();

        static const char* kInstall =
            "if timer and timer.Create then "
            "timer.Create('CrashCapture_Heartbeat', 0.1, 0, CrashCapture_Pulse) end "
            "if hook and hook.Add then "
            "hook.Add('GetGameDescription', 'CrashCapture_Heartbeat', CrashCapture_Pulse) end "
            "CrashCapture_Pulse()";
        L->RunStringEx("crashcapture", "", kInstall, true, false, true, true);

        if (r >= 0) g_hbInstalled[r] = true;
    }

    void Lua_InstallHeartbeatAll()
    {
        Lua_RefreshStates();
        for (int r = 0; r < 3; ++r)
            if (g_realm[r]) { Lua_InstallApi(g_realm[r]); Lua_InstallHeartbeat(g_realm[r]); }
    }

    // --------- lua-api ---

    enum CfgKind { CK_INT, CK_BOOL, CK_STR };
    struct CfgEntry { const char* key; int kind; void* ptr; size_t cap; };

    static int BuildCfgTable(CfgEntry* t)
    {
        Config& c = Cfg();
        int n = 0;
        t[n++] = {"timeout", CK_INT, &c.timeout_sec, 0};
        t[n++] = {"hang_kill", CK_INT, &c.hang_kill_sec, 0};
        t[n++] = {"max_age_days", CK_INT, &c.max_age_days, 0};
        t[n++] = {"loopbreak", CK_BOOL, &c.loopbreak, 0};
        t[n++] = {"phys_resume", CK_BOOL, &c.phys_resume, 0};
        t[n++] = {"firstchance", CK_BOOL, &c.firstchance, 0};
        t[n++] = {"window_watchdog", CK_BOOL, &c.window_watchdog, 0};
        t[n++] = {"lua_heartbeat", CK_BOOL, &c.lua_heartbeat, 0};
        t[n++] = {"manual_dump", CK_BOOL, &c.manual_dump, 0};
        t[n++] = {"symbols", CK_BOOL, &c.symbols, 0};
        t[n++] = {"dir", CK_STR,  c.dir, sizeof(c.dir)};
        t[n++] = {"script", CK_STR,  c.script, sizeof(c.script)};
        return n;
    }

    static const CfgEntry* FindCfg(const char* key, CfgEntry* buf)
    {
        int n = BuildCfgTable(buf);
        for (int i = 0; i < n; ++i)
            if (strcmp(buf[i].key, key) == 0) return &buf[i];
        return NULL;
    }

    // "disable" isn't a Config field, it's a lifecycle state we drive directly.
    static bool g_luaDisabled = false;

    static void ApplyDisable(bool disable)
    {
        if (disable == g_luaDisabled) return;
        g_luaDisabled = disable;
        if (disable) {
            Shutdown();
        } else {
            InstallHandlers();
            if (Cfg().timeout_sec > 0) Watchdog_Start(false);
        }
    }

    static int cc_lua_set(lua_State* L)
    {
        if (!g_api.ok) return 0;
        if (g_api.gettop(L) < 2 || g_api.type(L, 1) != CC_LT_STR) return 0;
        const char* key = g_api.tolstring(L, 1, NULL);
        if (!key) return 0;

        if (strcmp(key, "disable") == 0) {
            ApplyDisable(g_api.toboolean(L, 2) != 0);
            return 0;
        }

        CfgEntry buf[16];
        const CfgEntry* e = FindCfg(key, buf);
        if (!e) return 0;

        switch (e->kind) {
            case CK_INT: *(int*)e->ptr = (int)g_api.tonumber(L, 2); break;
            case CK_BOOL: *(bool*)e->ptr = g_api.toboolean(L, 2) != 0; break;
            case CK_STR: {
                const char* s = g_api.tolstring(L, 2, NULL);
                snprintf((char*)e->ptr, e->cap, "%s", s ? s : "");
                break;
            }
        }

        if (strcmp(key, "timeout") == 0) {
            if (Cfg().timeout_sec > 0) Watchdog_Start(false);
        } else if (strcmp(key, "lua_heartbeat") == 0) {
            if (Cfg().lua_heartbeat) Lua_InstallHeartbeatAll();
        }

        return 0;
    }

    static int cc_lua_get(lua_State* L)
    {
        if (!g_api.ok || !g_api.push_ok) return 0;
        if (g_api.gettop(L) < 1 || g_api.type(L, 1) != CC_LT_STR) return 0;
        const char* key = g_api.tolstring(L, 1, NULL);
        if (!key) return 0;

        if (strcmp(key, "disable") == 0) { g_api.pushboolean(L, g_luaDisabled); return 1; }

        if (strcmp(key, "ready") == 0) {
            bool ready = false, matched = false;
            for (int r = 0; r < 3; ++r)
                if (g_apiState[r] && g_apiState[r] == (void*)L) { ready = g_readyFired[r]; matched = true; break; }
            if (!matched)
                for (int r = 0; r < 3; ++r) if (g_readyFired[r]) { ready = true; break; }
            g_api.pushboolean(L, ready ? 1 : 0);
            return 1;
        }

        CfgEntry buf[16];
        const CfgEntry* e = FindCfg(key, buf);
        if (!e) { g_api.pushnil(L); return 1; }

        switch (e->kind) {
            case CK_INT: g_api.pushnumber(L, (double)*(int*)e->ptr); break;
            case CK_BOOL: g_api.pushboolean(L, *(bool*)e->ptr ? 1 : 0); break;
            case CK_STR: g_api.pushstring(L, (const char*)e->ptr); break;
        }
        return 1;
    }

    static int cc_lua_physpause(lua_State* L)
    {
        if (!g_api.ok || !g_api.push_ok) return 0;

        int paused;
        if (g_api.gettop(L) < 1 || g_api.type(L, 1) == CC_LT_NIL) {
            int cur = Platform_PhysPaused();
            paused = (cur == 1) ? 0 : 1;
        } else {
            paused = g_api.toboolean(L, 1) != 0;
        }

        int applied = Platform_SetPhysPaused(paused);
        g_api.pushboolean(L, applied ? 1 : 0);

        int state = Platform_PhysPaused();
        if (state < 0) g_api.pushnil(L); else g_api.pushboolean(L, state);
        return 2;
    }

    void Lua_InstallApi(void* iface)
    {
        ILuaInterface* L = (ILuaInterface*)iface;
        if (!L) return;

        int r = RealmOf(L);
        if (r >= 0) {
            if (g_apiInstalled[r]) return;
            g_realm[r] = L;
        }

        {
            const char* dis = getenv("CRASHCAPTURE_DISABLE");
            if (dis && atoi(dis) != 0) g_luaDisabled = true;
        }

        L->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
        L->CreateTable();
            L->PushCFunction(cc_lua_set); L->SetField(-2, "set");
            L->PushCFunction(cc_lua_get); L->SetField(-2, "get");
            L->PushCFunction(cc_lua_pulse); L->SetField(-2, "pulse");
            L->PushCFunction(cc_lua_physpause); L->SetField(-2, "phys_pause");
        L->SetField(-2, "crashcapture");
        L->Pop();

        if (r >= 0) {
            g_apiInstalled[r] = true;
            g_apiState[r] = (void*)L->GetState();
            if (!g_readyFired[r]) g_readyPending[r] = true;
        }
    }

    bool Lua_EnsureApi()
    {
        Lua_RefreshStates();
        if (!g_shared) return false;

        bool serverReady = false;
        for (int r = 0; r < 3; ++r) {
            ILuaInterface* l = g_shared->GetLuaInterface((unsigned char)r);
            if (!l || !Mem_IsReadable(l, 2 * sizeof(void*))) {
                g_realm[r] = NULL;
                g_apiState[r] = NULL;
                g_apiInstalled[r] = false;
                g_hbInstalled[r] = false;
                g_readyPending[r] = false;
                g_readyFired[r] = false;
                continue;
            }

            void* st = (void*)l->GetState();
            if (st && (l != g_realm[r] || st != g_apiState[r])) {
                g_realm[r] = l;
                g_apiState[r] = st;
                g_apiInstalled[r] = false;
                g_hbInstalled[r] = false;
                g_readyFired[r] = false;
                Lua_InstallApi(l);
                Lua_InstallHeartbeat(l);
            }

            if (r == LuaState::SERVER && g_apiInstalled[r]) serverReady = true;
        }
        return serverReady;
    }
}
