<div align="center">
  <picture>
  <img width="590" height="79" src="./logo.png">
  </picture>


</div>

---

The sole goal of the project is to report, mitigate and recover severe crashes/hangs.\
This is targeting baseline garry's mod, not custom implementations/overrides to the game.\
However this can work on heavily modified versions of the game.

Thanks to **Buildstruct** for infrastructure testing.\
Based on https://github.com/Python1320/gmsv_segfault

> [!WARNING]
> Do not share crash captures to others unless you have sanitized them, they can contain private/sensitive information about your server!

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

There is also included a `session.txt`, which is a running log of what the plugin itself did.\
This gets wiped on every boot, you can use this to debug what went wrong with crash capture itself or for more information, this pairs with `CRASHCAPTURE_DEBUG`.

## How to use it

The easiest and recommended way is to load it as a binary module:

1. Put the matching `.dll` for your server in `garrysmod/lua/bin/`.
2. Add `require("crashcapture")` to a server autorun script.

That's it, once loaded, it watches for crashes and freezes on its own.

We do support other ways of attaching, via either injection, plugins or sideloading, either way is fine.\
For early crashes during game startup, we recommend source plugin for servers, and for client, use sideloading by mimic'ing `version.dll` (just rename it to it and place it near the executable for windows, **not near the launcher**).

## Settings

It works out of the box, but you can tweak its behavior with these environment variables, process arguments, or a [configuration file](#configuration-file).\
The defaults are sensible, so you only need these if you want to change something.

| Variable | Default | What it does |
|---|---|---|
| `CRASHCAPTURE_TIMEOUT` | `10` | How many seconds the server can be unresponsive before it's treated as frozen. `0` turns freeze detection off. |
| `CRASHCAPTURE_HANG_KILL` | `30` | After a freeze report, force-close the process this many seconds later. `0` means never. |
| `CRASHCAPTURE_LOOPBREAK` | `1` | On a freeze, if the stalled thread is in Lua, arms a Lua debug hook on every realm that raises an error to break out of a stuck loop. |
| `CRASHCAPTURE_PHYS_RESUME` | `1` | Linux only, when a fatal fault happens inside the physics tick (`PhysFrame`, under `Host_RunFrame`), pause physics and resume the game thread as if the physics call returned. |
| `CRASHCAPTURE_PHYS_HOOK` | `1` | Linux only, prevents runaway physics hangs at the source instead of just reporting them. |
| `CRASHCAPTURE_PHYS_HOOK_MS` | `250` | per-tick budget, in milliseconds, before the hook above steps in. Clamped to a minimum of `20`. |
| `CRASHCAPTURE_PHYS_RECOVER` | `1` | Linux only, after a physics stall, freeze the offending objects so the tick can finish instead of stalling again. |
| `CRASHCAPTURE_PHYS_PIN` | `0` | Linux only, also pin the offending objects in place (motion disabled) rather than only reporting them. |
| `CRASHCAPTURE_PHYS_RESOLVE_DELAY` | `3` | Linux only, frames to wait after a physics recovery before firing the `crashcapture.physresolve` hook, so physics has settled. |
| `CRASHCAPTURE_PHYS_DEFER_EPS_US` | `0` | Linux only, defer retained-mindist events whose next refire lands within this many microseconds of the current drain position. Experimental. |
| `CRASHCAPTURE_REPORT_DEBOUNCE` | `15` | Minimum seconds between repeat reports for the same recurring condition. `0` disables the debounce. |
| `CRASHCAPTURE_HANG_MAP` | `1` | When a hang is detected, burst-probe the stuck thread a few times and include a `Hang map` report section showing the PC sites it kept landing on (see below). |
| `CRASHCAPTURE_HANG_MAP_SAMPLES` | `16` | How many probes the hang map takes. Clamped to `1..64`. |
| `CRASHCAPTURE_HANG_MAP_INTERVAL_MS` | `10` | Milliseconds between hang-map probes. Clamped to `1..5000`. |
| `CRASHCAPTURE_ENGINE_ERROR` | `1` | Capture engine-side fatal errors (`Sys_Error` and friends) instead of letting them exit silently. |
| `CRASHCAPTURE_FRAME_PROFILE` | `1` | Collect per-frame timing metrics (what `crashcapture.frametime()` returns). On Linux this also times the server physics tick (`PhysFrame`). |
| `CRASHCAPTURE_PROFILE` | `0` | Arm the Lua call profiler. |
| `CRASHCAPTURE_PROFILE_WINDOW` | `300` | Seconds before the profiler retires the current window and starts a fresh one, so it can be left armed indefinitely, `0` never rotates. |
| `CRASHCAPTURE_DEBUG` | `0` | Verbose internal tracing. Noisy, for troubleshooting the plugin itself. |
| `CRASHCAPTURE_MEMAPI` | `0` | Expose the `mem.*` API to Lua. Unsafe, see the warning below. |
| `CRASHCAPTURE_PATCHES` | `1` | Master switch for the compiled-in engine patches. |
| `CRASHCAPTURE_WINDOW_WATCHDOG` | `1` | On Windows clients with no other heartbeat, detect a frozen game by watching its window. |
| `CRASHCAPTURE_LUA_HEARTBEAT` | `1` | Use a lightweight in-game timer as the freeze heartbeat. |
| `CRASHCAPTURE_MANUAL_DUMP` | `1` | Let an external process force a report on demand. |
| `CRASHCAPTURE_FIRSTCHANCE` | auto | Windows: also catch certain early/internal errors. Auto-managed; usually leave alone. |
| `CRASHCAPTURE_CONSOLE` | `0` | Print the full report to the console too. Off by default, only a short notice and the file path are printed. |
| `CRASHCAPTURE_SYMBOLS` | `1` | Add function names and source lines to reports when debug info is available. No effect when it isn't. |
| `CRASHCAPTURE_DISABLE` | `0` | Set to `1` to make the plugin do nothing at all. Handy for ruling it out when troubleshooting. |
| `CRASHCAPTURE_DIR` | `crashes` | Folder to write reports into (relative to the GMod root). |
| `CRASHCAPTURE_MAX_AGE_DAYS` | `14` | At startup, delete reports in the crash folder older than this many days, so they don't pile up. `0` keeps them forever. |
| `CRASHCAPTURE_SCRIPT` | _(none)_ | Path to a Lua script run in a fresh, isolated state on each crash for live memory diagnostics (see below). Off when unset. |

> [!WARNING]
> We recommend not having CRASHCAPTURE_MEMAPI enabled, as this exposes the same API layer of mem.* from to one or multiple lua_State's\
> Proceed with caution when this is enabled, as this is inherently unsafe.

### Configuration file

Hosts that cannot set environment variables or process arguments can drop a `crashcapture.cfg` into the crash folder instead.\
Settings are resolved in this order:

1. Environment variables, if set.
2. Process arguments (`-CRASHCAPTURE_TIMEOUT 30`, and so on).
3. `crashcapture.cfg` in the crash folder.
4. Runtime `crashcapture.set()` from Lua, which always wins once a realm is up.

Each line is a `key = value` pair using the setting names above, with or without the `CRASHCAPTURE_` prefix (case-insensitive).\
Lines starting with `#` or `//` are comments inline comments must be preceded by whitespace.\
A repeated key keeps the last value.

```ini
# crashes/crashcapture.cfg
timeout = 30
debug = 1 # verify signatures are not drifting
CRASHCAPTURE_DIR = my reports
phys_hook_ms = 500
```

The file is read from the crash folder resolved by environment variables and process arguments (default `crashes/`).\
A `dir` line in the file redirects where reports are written, but the file itself is always read from that resolved folder.\
All settings work here, including the launch-only ones (`dir`, `script`, `memapi`, `phys_hook`, `console`) and `disable = 1`.

### Lua Settings

Some servers need to configure the plugin from Lua rather than the process
environment.\
Once a realm is up, a global `crashcapture` table is available:

```lua
crashcapture.set("timeout", 30) -- seconds before a freeze is declared
crashcapture.set("loopbreak", false)
print(crashcapture.get("timeout")) -- 30
crashcapture.pulse() -- manual heartbeat
crashcapture.frametime() -- returns a table of timing metrics
crashcapture.set("profile", true) -- start the Lua call profiler
crashcapture.profile(10) -- top 10 hooks/timers by self time
crashcapture.profile_reset() -- zero the counters, start a fresh window
crashcapture.patches() -- list the compiled-in engine patches and their state
crashcapture.patch("gm.phys.mindist_reschedule", false) -- disable one
crashcapture.patch("gm.phys.mindist_reschedule") -- re-enable it
```

> In plugin mode the Lua table appears a little after the realm comes up (it's
> attached on the next game frame, not synchronously like `require`). Don't guess
> when it's ready, listen for the `crashcapture.ready` hook or poll
> `crashcapture.get("ready")` (see [Knowing when it's ready](#knowing-when-its-ready)).

Keys mirror the settings above, lower-cased and without the `CRASHCAPTURE_`
prefix: `timeout`, `hang_kill`, `max_age_days`, `loopbreak`, `phys_resume`, `phys_recover`, `phys_pin`, `phys_hook_ms`, `phys_resolve_delay`, `debug`, `engine_error`, `frame_profile`, `profile`, `profile_window`, `report_debounce`, `hang_map`, `hang_map_samples`, `hang_map_interval_ms`, `firstchance`, `window_watchdog`, `lua_heartbeat`, `manual_dump`, `symbols`, and `disable`.

`dir`, `script`, `memapi` and `phys_hook` are launch-config only: `get` reads them, `set` is refused (they're decided before Lua exists, and `memapi` would be a way to grant itself the unsafe `mem.*` API).\
`console` is not exposed to Lua at all.

There's also a Linux-only diagnostic for the physics-resume feature:
> This is deprecate due to the existing `physenv.SetPhysicsPaused( boolean pause )`

```lua
local applied, state = crashcapture.phys_pause(true) -- pause physics
print(applied, state) --> true   true
crashcapture.phys_pause(false) -- resume
```

- Raising `timeout` from `0` starts the watchdog, enabling `lua_heartbeat`
  installs the heartbeat timer; `set("disable", true)` disarms the plugin and
  `false` re-arms it.
- `max_age_days` is only read at startup, so setting it from Lua only affects the next run, `dir` and `script` are launch-config only for the same reason.
- `phys_hook_ms` applies to the next physics tick and is clamped to `20` minimum, the same as the environment variable.

## Lua call profiler

GMod's own `vprof` can tell you that gamemode hooks cost 8 ms, but not *which* hook, and profiling from Lua with `debug.sethook` breaks Starfall while detouring `hook.Call` costs more than it measures.\
This does it from C++, above LuaJIT, so an armed profiler costs a couple of nanoseconds per call.

It is off by default.\
Arm it with `CRASHCAPTURE_PROFILE=1` at launch, or from Lua
at any time:

```lua
crashcapture.set("profile", true)

timer.Simple(30, function()
    for _, e in ipairs(crashcapture.profile(10)) do
        print(("%-40s %8.2f ms self  %6d calls"):format(e.name, e.self_ms, e.calls))
    end
    crashcapture.set("profile", false)
end)
```

`crashcapture.profile([limit])` returns a table sorted by self time, highest first, capped at `limit` entries (default 20, max 64):

| field | meaning |
| --- | --- |
| `name` | `hook:Think`, `timer:MyAddon_Tick`, `timer.simple:x.lua:42`, `lua:sh_thing.lua:120`, `net:my_message`, or `<unattributed>` |
| `kind` | `hook`, `timer`, `lua`, `net` or `other` |
| `source` | full path: timer creation site, or the Lua file for `lua` entries |
| `calls` | times entered during the window |
| `self_ms` | time in this entry, excluding nested Lua calls it made |
| `total_ms` | time including everything it called |
| `p50_ms` | median call |
| `p99_ms` | 99th percentile call |
| `max_ms` | the single worst call |

The table itself also carries `enabled`, `window_ms`, `completed`, `depth` (Lua
calls in flight right now), `buckets` / `bucket_max`, and `dropped`.

### What it can and cannot see

- Attribution is **per hook name, not per addon**.
  - `hook:Think` still aggregates every `hook.Add("Think", ...)` on the server.
  - It tells you which hook is expensive, not whose code.
- `timer.Simple` callbacks on Windows are named by the closure (`lua:...`) rather than as `timer.simple:...`
  - Because MSVC inlines the callback runner into the simple-timer drain and removes the hook point that supplies the timer's creation site.

## Engine patches

Garry's Mod has a few known bugs in its physics code that can crash or freeze the server.
The plugin ships with small fixes for these and applies them automatically when it loads, so there's nothing to set up.

They're compiled for both Linux x86 and x64 servers (the one exception is `gm.phys.watcher_stale_mindist`, which is x86-only because its x64 prologue can't be safely detoured):

- `gm.phys.contact_stale_core` - stops a crash when physics objects are destroyed while still in use.
- `gm.phys.mindist_null_edge` - stops a crash when a physics contact record points at removed geometry or a NaN-position object.
- `gm.phys.watcher_stale_mindist` - stops a crash when a physics record is removed twice. (x86 only)
- `gm.phys.ovtree_hash_remove` - stops a crash when an object is removed from a physics list twice.
- `gm.phys.oo_collision_hash_index` / `gm.phys.oo_collision_hash_swap` - stop a crash from a lookup bug in the collision system.
- `gm.phys.minlist_walk_bound_a` / `gm.phys.minlist_walk_bound_b` - stop a freeze where physics scheduling gets stuck in a loop.
- `gm.phys.minlist_replace` - replaces `IVP_U_Min_List::add` with a corrected copy of the stock algorithm.
- `gm.phys.minlist_skip_list` - disables the physics min-list skip-list (long-jump) optimization outright.
- `gm.phys.ctrl_remove_absent` - stops a crash when a constraint is removed from a physics object that has already been torn down.
- `gm.phys.vhash_remove_null` - `IVP_VHash::remove_elem` returns early on an absent key instead of raising the not-found fatal.
- `gm.phys.coc_absent_bail` - `ctrl_remove_absent` controller removal returns when the controller is absent from the sim unit's list instead of reading before the list array.
- `gm.phys.friction_hash_init_size` - creates the per-core friction hash with 16 initial slots instead of 2, cutting rehash+re-add churn as contacts accumulate. (x86)
- `gm.phys.vhash_store_remove_bound` - bounds `IVP_VHash_Store::remove_elem`: its find loop has no null-slot break, so an absent key walks off the array. (x86, opt-in)

Every fix is tied to the exact game code it repairs.\
If a Garry's Mod update changes that code, the fix simply doesn't apply, the plugin never writes over code it doesn't recognize, so a fix that's no longer valid can't cause new problems.\
When that happens you'll get a notice in the console, and every crash report shows how many fixes were applied versus skipped, so you always know what's actually running.

You can check and control the fixes from Lua:

```lua
crashcapture.patches() -- list every fix and its state
crashcapture.patch("gm.phys.contact_stale_core", false) -- turn one off
crashcapture.patch("gm.phys.contact_stale_core") -- turn it back on
```

Your choice is saved to `crashes/patches.txt` and remembered on the next start.\
`CRASHCAPTURE_PATCHES=0` turns every fix off, regardless of the file.\
These fixes only exist in server builds, never the client.

`crashcapture.patch()` returns three values:

- `ok` - whether the change was accepted.
- `status` - what happens next: `"queued"` takes effect shortly, `"restart"` applies on the next server start (most fixes, because rewriting code while it's running is unsafe), `"unknown"` is an invalid id, and `"blocked"` means patches are turned off.
- `saved` - whether your choice was written to disk. `false` means it only lasts this session, usually because the reports folder isn't writable.

## Knowing when it's ready

Loading as a binary module (`require`) installs the `crashcapture` table synchronously, so it's there the moment `require` returns.\
In plugin mode it's attached a little later, on the first game frame after the realm comes up.\
Rather than guessing or polling for the table, use either of these:

**`crashcapture.ready` hook** - fired once per realm, on the game thread at a safe
tick, as soon as the table is installed and usable:

```lua
hook.Add("crashcapture.ready", "configure_crashcapture", function(info)
    print("[Crash Capture] ready in", info.realm) -- "server" / "client" / "menu"
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

## Manual dump (on demand)

Sometimes you want a report *right now* without waiting for a crash or freeze, for example the server feels sluggish and you want to see what the game thread is doing.\
An external process can force a capture without touching the game.\
The report is written just like a freeze report (game-thread stack, Lua traces, modules, diagnostics) and lands in the crash folder with a `dump` type.

**Linux** - send `SIGUSR1` to the server process:

```sh
kill -USR1 <pid>
# or, if it's the only srcds_linux on the box:
pkill -USR1 srcds_linux
```

**Windows** - signal the per-pid named event `Local\CrashCapture_Dump_<pid>`:

```c
HANDLE h = OpenEventA(EVENT_MODIFY_STATE, FALSE, "Local\\CrashCapture_Dump_1234");
SetEvent(h);
CloseHandle(h);
```
Note that on Linux this claims `SIGUSR1`, if another component in your process already uses that signal, the plugin chains to it after capturing, but you can still turn it off here.

If you require to dump via lua, simply call `crashcapture.dump()`, this will generate in-place of where this was called from.

## Recovery hooks

Some freezes are recoverable, for example a stuck Lua loop can be broken (`loopbreak`).\
When that happens, the plugin fires standard Garry's Mod hooks so your addons can react, for example notify staff, log to a database, or clean up the offending entity.

The hooks run **on the game thread at the next safe tick**, so it's safe to do normal Lua work in them.

| Hook | Fires when |
|---|---|
| `crashcapture.loopbreak` | A suspected infinite Lua loop was interrupted. |
| `crashcapture.physresume` | A physics fault was resumed. |
| `crashcapture.physresolve` | A physics hang was mitigated. |
| `crashcapture.recovery` | Any time the game thread recovers from a freeze. |

Each hook receives a single `info` table.\
Fields are present only when known:

- `info.method` - `"loopbreak"`, `"physresume"`, or `nil` (self-recovered).
- `info.stall` - where the stall was: `"physics"`, `"native"`, `"lua"`, `"lua-jit"`.
- `info.reason` - the one-line freeze reason (same text as the report).
- `info.report` - path to the full report file.
- `info.downtime` - milliseconds the game thread was stalled (recovery only).
- `info.stack?` - array of `"source:line in name"` strings captured from the stuck Lua call stack.
- `info.entities?` - **`physresolve` only**: array of entity indices the plugin flagged as the offending physics objects (see below).

```lua
hook.Add("crashcapture.recovery", "notify_recovery", function(info)
    print(("[Crash Capture] recovered via %s after %dms (%s)")
        :format(info.method or "self", info.downtime or 0, info.stall or "?"))
    if info.report then print("  report:", info.report) end
end)

hook.Add("crashcapture.loopbreak", "log_loop", function(info)
    for _, frame in ipairs(info.stack or {}) do print("  ", frame) end
end)

hook.Add("crashcapture.physresolve", "remove_offenders", function(info)
    for _, idx in ipairs(info.entities or {}) do
        local ent = Entity(idx)
        if IsValid(ent) then
            print("[Crash Capture] run away entity #" .. idx)
        end
    end
end)
```

A few things worth knowing about physresolve:

- It fires a few frames **after** the hang is caught (tunable via the `phys_resolve_delay` setting), so physics has settled before your handler runs.
- Players, NPCs and physgun-held props are **never** reported, so you won't be handed something you shouldn't delete.
- If a contraption keeps re-triggering, the same entity can show up across repeated episodes (deduped within one window, not forever), so keep your handler idempotent, the `IsValid` check above is enough.
- `phys_pin` is for if you need crash capture to handle freezing, this tends to be unstable and we recommend handling it in lua itself.

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

- `crash.map: string`\
    The current map name (e.g. `gm_construct`).\
    `nil` if no map was known when the plugin captured it (no heartbeat source or still loading).

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
