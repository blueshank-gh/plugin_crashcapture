// Crash Capture - Entry Points
// INTERFACE_PLUGIN -> GMod server plugin
// INTERFACE_PRELOAD -> Windows version.dll shim (see mimic.h)

#include "crashcapture.h"
#include "glua/Interface.h"
#include <stddef.h>
#include <string.h>

#if defined(CC_WINDOWS)
    #define CC_EXPORT extern "C" __declspec(dllexport)
#else
    #define CC_EXPORT extern "C" __attribute__((visibility("default")))
#endif

// For arming features of crash capture
CC_EXPORT void CrashCapture_Arm() { CrashCapture::Init(); }
CC_EXPORT void CrashCapture_Disarm() { CrashCapture::Shutdown(); }
CC_EXPORT void CrashCapture_Pulse() { CrashCapture::Pulse(); }
CC_EXPORT void CrashCapture_InstallLuaHeartbeat() { CrashCapture::Lua_InstallHeartbeatAll(); }

// This is what allows us to attach to gmod over lua
CC_EXPORT int gmod13_open(GarrysMod::lua_State* L)
{
    CrashCapture::Init();
    if (L && L->luabase) {
        L->luabase->SetState(L);
        CrashCapture::Lua_OnInit(L->luabase);
    }
    return 0;
}

CC_EXPORT int gmod13_close(GarrysMod::lua_State* L)
{
    if (L && L->luabase) CrashCapture::Lua_OnShutdown(L->luabase);
    return 0;
}

// ---------------------------------------------------------------- server ---
#if defined(INTERFACE_PLUGIN)

namespace GarrysMod { namespace Lua { class ILuaInterface; } }

namespace {

typedef void* (*CreateInterfaceFn)(const char* name, int* returncode);

// Opaque stand-ins for engine types we never dereference.
struct edict_t;
class  CCommand;
typedef int QueryCvarCookie_t;
enum  EQueryCvarValueStatus { eQueryCvarValueStatus_ValueIntact = 0 };
enum  PLUGIN_RESULT { PLUGIN_CONTINUE = 0, PLUGIN_OVERRIDE, PLUGIN_STOP };

#define CC_PLUGIN_INTERFACE_VERSION "IGMODSERVERPLUGINCALLBACKS004"

// Based on engine/iserverplugin.h IGMODSERVERPLUGINCALLBACKS004
class IServerPluginCallbacks {
public:
    virtual bool          Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory) = 0;
    virtual void          Unload(void) = 0;
    virtual void          Pause(void) = 0;
    virtual void          UnPause(void) = 0;
    virtual const char*   GetPluginDescription(void) = 0;
    virtual void          LevelInit(const char* pMapName) = 0;
    virtual void          ServerActivate(edict_t* pEdictList, int edictCount, int clientMax) = 0;
    virtual void          GameFrame(bool simulating) = 0;
    virtual void          LevelShutdown(void) = 0;
    virtual void          ClientActive(edict_t* pEntity) = 0;
    virtual void          ClientFullyConnect(edict_t* pEntity) = 0;
    virtual void          ClientDisconnect(edict_t* pEntity) = 0;
    virtual void          ClientPutInServer(edict_t* pEntity, const char* playername) = 0;
    virtual void          SetCommandClient(int index) = 0;
    virtual void          ClientSettingsChanged(edict_t* pEdict) = 0;
    virtual PLUGIN_RESULT ClientConnect(bool* bAllowConnect, edict_t* pEntity, const char* pszName, const char* pszAddress, char* reject, int maxrejectlen) = 0;
    virtual PLUGIN_RESULT ClientCommand(edict_t* pEntity, const CCommand& args) = 0;
    virtual PLUGIN_RESULT NetworkIDValidated(const char* pszUserName, const char* pszNetworkID) = 0;
    virtual void          OnQueryCvarValueFinished(QueryCvarCookie_t iCookie, edict_t* pPlayerEntity, EQueryCvarValueStatus eStatus, const char* pCvarName, const char* pCvarValue) = 0;
    virtual void          OnEdictAllocated(edict_t* edict) = 0;
    virtual void          OnEdictFreed(const edict_t* edict) = 0;
    virtual void          OnLuaInit(GarrysMod::Lua::ILuaInterface* LUA) = 0;
    virtual void          OnLuaShutdown(GarrysMod::Lua::ILuaInterface* LUA) = 0;
};

class CrashCapturePlugin : public IServerPluginCallbacks {
    unsigned m_frame = 0;
public:
    bool          Load(CreateInterfaceFn, CreateInterfaceFn) override { CrashCapture::Init(); return true; }
    void          Unload(void) override { CrashCapture::Shutdown(); }
    void          Pause(void) override {}
    void          UnPause(void) override {}
    const char*   GetPluginDescription(void) override { return "plugin_crashcapture v" CC_VERSION; }
    void          LevelInit(const char*) override { CrashCapture::Grace(60); }
    void          ServerActivate(edict_t*, int, int) override {}
    void          GameFrame(bool) override {
        CrashCapture::Pulse();
        // TODO: we need to switch off of this for plugins, its unreliable.
        if ((++m_frame & 15) == 0) CrashCapture::Lua_EnsureApi();
    }
    void          LevelShutdown(void) override { CrashCapture::Grace(30); }
    void          ClientActive(edict_t*) override {}
    void          ClientFullyConnect(edict_t*) override {}
    void          ClientDisconnect(edict_t*) override {}
    void          ClientPutInServer(edict_t*, const char*) override {}
    void          SetCommandClient(int) override {}
    void          ClientSettingsChanged(edict_t*) override {}
    PLUGIN_RESULT ClientConnect(bool*, edict_t*, const char*, const char*, char*, int) override { return PLUGIN_CONTINUE; }
    PLUGIN_RESULT ClientCommand(edict_t*, const CCommand&) override { return PLUGIN_CONTINUE; }
    PLUGIN_RESULT NetworkIDValidated(const char*, const char*) override { return PLUGIN_CONTINUE; }
    void          OnQueryCvarValueFinished(QueryCvarCookie_t, edict_t*, EQueryCvarValueStatus, const char*, const char*) override {}
    void          OnEdictAllocated(edict_t*) override {}
    void          OnEdictFreed(const edict_t*) override {}
    void          OnLuaInit(GarrysMod::Lua::ILuaInterface* LUA) override { CrashCapture::Lua_OnInit((void*)LUA); }
    void          OnLuaShutdown(GarrysMod::Lua::ILuaInterface* LUA) override { CrashCapture::Lua_OnShutdown((void*)LUA); }
};

CrashCapturePlugin g_plugin;

}

// Used for interface creation from source engine itself
CC_EXPORT void* CreateInterface(const char* name, int* returncode)
{
    if (name && (strcmp(name, CC_PLUGIN_INTERFACE_VERSION) == 0 ||
                 strcmp(name, "ISERVERPLUGINCALLBACKS003") == 0 ||
                 strcmp(name, "ISERVERPLUGINCALLBACKS002") == 0 ||
                 strcmp(name, "ISERVERPLUGINCALLBACKS001") == 0)) {
        if (returncode) *returncode = 0; // IFACE_OK
        return (void*)static_cast<IServerPluginCallbacks*>(&g_plugin);
    }
    if (returncode) *returncode = 1;      // IFACE_FAILED
    return NULL;
}

#endif // INTERFACE_PLUGIN

// ---------------------------------------------------------------- client ---
#if defined(INTERFACE_PRELOAD)

#if defined(CC_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// version.dll export proxying lives in cc_mimic.cpp
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        CrashCapture::Init();
        break;
    case DLL_PROCESS_DETACH:
        CrashCapture::Shutdown();
        break;
    default:
        break;
    }
    return TRUE;
}

#else // Linux preload (.so constructor)

__attribute__((constructor)) static void cc_preload_init() { CrashCapture::Init(); }
__attribute__((destructor))  static void cc_preload_fini() { CrashCapture::Shutdown(); }

#endif

#endif // INTERFACE_PRELOAD
