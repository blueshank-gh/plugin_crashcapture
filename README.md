# plugin_crashcapture

A crash and freeze logger for Garry's Mod servers.\
Thanks to **Buildstruct** for infrastructure testing.\
Based on https://github.com/Python1320/gmsv_segfault

> Warning: do not share crash captures to others unless you have sanitized them, they can contain private/sensitive information about your server!

## What it does

When your server crashes or freezes, you normally get nothing useful... the process just dies.\
This plugin catches those failures and writes a readable report explaining what happened and where, so you can actually track down the problem.

It handles two kinds of failures:

- **Crashes** - the game hits a fatal error and would otherwise close silently.
- **Freezes (hangs)** - the server stops responding (for example, a stuck script looping forever).

Either way, you get a report file describing the failure.

## Where the reports go

Reports are saved as Markdown files in a `crashes/` folder at your GMod root (next to the game's own crash dumps).\
Each one is named for what happened and when, so they're easy to find and read.

## How to use it

The easiest and recommended way is to load it as a binary module:

1. Put the matching `.dll` for your server in `garrysmod/lua/bin/`.
2. Add `require("crashcapture")` to a server autorun script.

That's it, once loaded, it watches for crashes and freezes on its own.

We do support other ways of attaching, via either injection, plugins or sideloading, either way is fine.\
For early crashes during game startup, we recommend source plugin for servers, and for client, use sideloading by mimic'ing `version.dll` (just rename it to it and place it near the executable for windows).

## Settings

It works out of the box, but you can tweak its behavior with these environment
variables.\
The defaults are sensible, so you only need these if you want to change something.

| Variable | Default | What it does |
|---|---|---|
| `CRASHCAPTURE_TIMEOUT` | `10` | How many seconds the server can be unresponsive before it's treated as frozen. `0` turns freeze detection off. |
| `CRASHCAPTURE_HANG_KILL` | `0` | After a freeze report, force-close the process this many seconds later. `0` means never. |
| `CRASHCAPTURE_LOOPBREAK` | `1` | On a freeze, if the stalled thread is in Lua, arms a Lua debug hook on every realm that raises an error to break out of a stuck loop. |
| `CRASHCAPTURE_PHYS_RESUME` | `1` | Linux only, when a fatal fault happens inside the physics tick (`PhysFrame`, under `Host_RunFrame`), pause physics and resume the game thread as if the physics call returned. |
| `CRASHCAPTURE_WINDOW_WATCHDOG` | `1` | On Windows clients with no other heartbeat, detect a frozen game by watching its window. |
| `CRASHCAPTURE_LUA_HEARTBEAT` | `1` | Use a lightweight in-game timer as the freeze heartbeat. |
| `CRASHCAPTURE_FIRSTCHANCE` | auto | Windows: also catch certain early/internal errors. Auto-managed; usually leave alone. |
| `CRASHCAPTURE_CONSOLE` | `0` | Print the full report to the console too. Off by default, only a short notice and the file path are printed. |
| `CRASHCAPTURE_SYMBOLS` | `1` | Add function names and source lines to reports when debug info is available. No effect when it isn't. |
| `CRASHCAPTURE_DISABLE` | `0` | Set to `1` to make the plugin do nothing at all. Handy for ruling it out when troubleshooting. |
| `CRASHCAPTURE_DIR` | `crashes` | Folder to write reports into (relative to the GMod root). |
| `CRASHCAPTURE_MAX_AGE_DAYS` | `14` | At startup, delete reports in the crash folder older than this many days, so they don't pile up. `0` keeps them forever. |
| `CRASHCAPTURE_SCRIPT` | _(none)_ | Path to a Lua script run in a fresh, isolated state on each crash for live memory diagnostics (see below). Off when unset. |

### Lua Settings

Some servers need to configure the plugin from Lua rather than the process
environment.\
Once a realm is up, a global `crashcapture` table is available:

```lua
crashcapture.set("timeout", 30) -- seconds before a freeze is declared
crashcapture.set("hang_kill", 15) -- force-close 15s after a freeze report
crashcapture.set("loopbreak", false)
print(crashcapture.get("timeout")) -- 30
crashcapture.pulse() -- manual heartbeat
```

> In plugin mode the Lua table appears a little after the realm comes up (it's
> attached on the next game frame, not synchronously like `require`). Don't guess
> when it's ready, listen for the `crashcapture.ready` hook or poll
> `crashcapture.get("ready")` (see [Knowing when it's ready](#knowing-when-its-ready)).

Keys mirror the settings above, lower-cased and without the `CRASHCAPTURE_`
prefix: `timeout`, `hang_kill`, `max_age_days`, `loopbreak`, `phys_resume`, `firstchance`, `window_watchdog`, `lua_heartbeat`, `symbols`, `dir`, `script`, and `disable`.

There's also a Linux-only diagnostic for the physics-resume feature:

```lua
local applied, state = crashcapture.phys_pause(true) -- pause physics
print(applied, state) --> true   true
crashcapture.phys_pause(false) -- resume
```

- Raising `timeout` from `0` starts the watchdog, enabling `lua_heartbeat`
  installs the heartbeat timer; `set("disable", true)` disarms the plugin and
  `false` re-arms it.
- `max_age_days`, `dir`, and `script` only matter at the next startup / next
  crash respectively, so set them early.

## Knowing when it's ready

Loading as a binary module (`require`) installs the `crashcapture` table synchronously, so it's there the moment `require` returns.\
In plugin mode it's attached a little later, on the first game frame after the realm comes up.\
Rather than guessing or polling for the table, use either of these:

**`crashcapture.ready` hook** - fired once per realm, on the game thread at a safe
tick, as soon as the table is installed and usable:

```lua
hook.Add("crashcapture.ready", "configure_crashcapture", function(info)
    print("[CrashCapture] ready in", info.realm) -- "server" / "client" / "menu"
    crashcapture.set("timeout", 30)
end)
```

The `info` table carries `realm`, `side` (`"server"`/`"client"`), `version`, `os`,
and `arch`.

**`crashcapture.get("ready")`** - a boolean for code that may load *after* the hook
already fired (the hook is one-shot, so a late listener would miss it):

```lua
if crashcapture and crashcapture.get("ready") then
    crashcapture.set("timeout", 30)
end
```

## Recovery hooks

Some freezes are recoverable, for example a stuck Lua loop can be broken (`loopbreak`).\
When that happens, the plugin fires standard Garry's Mod hooks so your addons can react, for example notify staff, log to a database, or clean up the offending entity.

The hooks run **on the game thread at the next safe tick**, so it's safe to do normal Lua work in them.

| Hook | Fires when |
|---|---|
| `crashcapture.loopbreak` | A suspected infinite Lua loop was interrupted. |
| `crashcapture.physresume` | A physics fault was resumed. |
| `crashcapture.recovery` | Any time the game thread recovers from a freeze. |

Each hook receives a single `info` table.\
Fields are present only when known:

- `info.method` - `"loopbreak"`, `"physresume"`, or `nil` (self-recovered).
- `info.stall` - where the stall was: `"physics"`, `"native"`, `"lua"`, `"lua-jit"`.
- `info.reason` - the one-line freeze reason (same text as the report).
- `info.report` - path to the full report file.
- `info.downtime` - milliseconds the game thread was stalled (recovery only).
- `info.stack?` - array of `"source:line in name"` strings captured from the stuck Lua call stack.

```lua
hook.Add("crashcapture.recovery", "notify_staff", function(info)
    print(("[CrashCapture] recovered via %s after %dms (%s)")
        :format(info.method or "self", info.downtime or 0, info.stall or "?"))
    if info.report then print("  report:", info.report) end
end)

hook.Add("crashcapture.loopbreak", "log_loop", function(info)
    for _, frame in ipairs(info.stack or {}) do print("  ", frame) end
end)
```

## Live memory diagnostics (`CRASHCAPTURE_SCRIPT`)

Point `CRASHCAPTURE_SCRIPT` at a `.lua` file and it runs on every crash/hang in a **brand-new, throwaway LuaJIT state**, never the game's, which is unreliable mid-crash.\
Its `print()` output goes into the report's **Diagnostics** section.
The whole thing is fault-isolated, so a mistake in the script just loses that section.\
Everything is read-only and bounds-checked.

Addresses are opaque light pointers, pass them straight back into `mem.*`.\
An `address` argument also accepts a plain number. Reads that fail return `nil`.

**Crash context** (`crash` table)

- `crash.kind: string`\
    What happened, e.g. `unhandled exception`, `hang`, `abort`, `dump`.

- `crash.reason: string`\
    The one-line summary (same text as the report's **reason**).

- `crash.fault: address`\
    The faulting data address (e.g. the bad pointer in an access violation).\
    `nil` for freezes and faults with no address.

- `crash.pc: address`\
    Faulting instruction pointer.

- `crash.sp: address`\
    Faulting stack pointer.

- `crash.regs: table`\
    The register file as `address` values (`rax`...`rip` on x64, `eax`...`eip` on x86).\
    Empty if no context was available.\
    Pass any into `mem.*`.

- `crash.uptime: number`\
    Milliseconds since the plugin armed.

- `crash.pulse: number`\
    Milliseconds since the last heartbeat.\
    `nil` if there was never a heartbeat.

- `crash.lua: table[]`\
    The crashing game's Lua state(s), one entry per bound realm.\
    Each entry is `{realm: string, top: number, frames: table[]}`, where every frame is `{level, source, line, name, what, locals}`.\
    `locals` is a `"a=1; self=Entity: 0x..."` summary, present only for Lua frames.\
    `nil` if no realm was readable or the LuaJIT API didn't resolve.

- `crash.stack: table[]`\
    The native call stack from the faulting context, as `{pc: address, sym: string}` entries (outermost frame first).\
    On Linux the first few frames may be the report handler itself (it unwinds from there).

**`mem` library**

- `mem.read(addr: address, type: string): number`\
    Reads the following possible types:\
    `int8`/`uint8`/`int16`/`uint16`/`int32`/`uint32`/`int64`/`uint64`/`float`/`double`/`ptr`.\
    `ptr` returns an `address`; `nil` if unreadable.

- `mem.string(addr: address, max: number): string`\
    Reads a NUL-terminated string (up to `max` bytes, default 256).

- `mem.bytes(addr: address, n: number): string`\
    Up to `n` raw bytes (default 64, capped at 4096) as a Lua string, stopping at the first unreadable byte.\
    For decoding structs with `string.byte` / `string.unpack`.

- `mem.deref(addr: address): address`\
    Reads the pointer stored.

- `mem.offset(addr: address, n: number): address`\
    Returns `addr + n`.

- `mem.chain(start: address, ...: number): address`\
    Walks a pointer chain.\
    Each intermediate offset is "add then dereference"; the final offset is "add" only, so the result is the **address** of the last field (read it with `mem.read`/`mem.deref`).\
    `nil` if any hop is unreadable. E.g. `mem.chain(crash.regs.rdi, 0x10, 0x28)` -> `*(rdi+0x10) + 0x28`.

- `mem.sym(addr: address): string`\
    Returns `module+RVA` plus a symbol name when debug info is available.

- `mem.find(name: string): address, number`\
    Locates a loaded module by name, returning its `base` and `size`; `nil` if not found.

- `mem.modules(): table[]`\
    Array of `{name, base, size}` for every loaded module.

- `mem.scan(module: string, pattern: string): address`\
    IDA-style signature scan within `module` (e.g. `"48 8B ?? C3"`); `nil` if no match.

- `mem.search(module: string, value: address|number, type: string): address[]`\
    Addresses in `module` whose memory equals `value` interpreted as `type` (default `ptr`; same type names as `mem.read`).\
    Returns a table of hits (possibly empty), capped at 256; `nil` on bad args.

- `mem.refs(addr: address): address[]`\
    Pointer-sized references to `addr` across all loaded modules - i.e. *what points here?*\
    Returns a table of hits, capped at 256.\
    Handy for tracking down a dangling/stale pointer.

- `mem.region(addr: address): table`\
    Returns `{base, size, read, write, execute}` for the page containing `addr`.

- `mem.readable(addr: address, n: number): boolean`\
    True if `n` bytes (default 1) at `addr` can be read.

- `mem.executable(addr: address): boolean`\
    True if `addr` is in executable memory.

- `mem.dump(addr: address, n: number): number`\
    Hexdumps up to `n` bytes (default 64, capped at 512) into the report, stopping at the first unreadable byte.\
    Returns the number of bytes dumped.

- `mem.symbol(name: string): address`\
    `mem.symbol(module: string, name: string): address`\
    Reverse symbol lookup (name -> address) using PE exports / dbghelp on Windows and the ELF symbol table on Linux. Optionally scoped to one `module`.\
    `nil` if the name isn't found.

- `mem.threads(): table[]`\
    Array of `{id, pc, sym, name, current}` for every thread in the process.\
    Mainly useful on a hang to see which thread is stuck and where.\
    `pc`/`sym` are present only when the thread's instruction pointer is obtainable (always on Windows; Linux reports `id`/`name` only).

Example:

```lua
print("fault at", mem.sym(crash.pc))
local base, size = mem.find("server_srv")
if base then print("server_srv", mem.sym(base), size) end
print("dword at rip:", mem.read(crash.pc, "uint32"))

-- native call stack
for _, f in ipairs(crash.stack or {}) do print(f.sym) end

-- what still references the faulting pointer?
for _, a in ipairs(mem.refs(crash.fault) or {}) do print("referenced by", mem.sym(a)) end

-- walk a struct: health at *(ent+0x10)+0x4
local hp = mem.chain(crash.regs.rdi, 0x10, 0x4)
if hp then print("hp =", mem.read(hp, "float")) end
```
