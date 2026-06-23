# plugin_crashcapture

A crash and freeze logger for Garry's Mod servers.\
Thanks to **Buildstruct** for infrastructure testing.\
Based on https://github.com/Python1320/gmsv_segfault

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
| `CRASHCAPTURE_LOOPBREAK` | `1` | Try to break out of a stuck Lua loop on a freeze (currently best-effort, the report still pinpoints the loop). |
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

> Do note that plugin-mode doesn't initialize the lua counterparts early, this is being worked on.

Keys mirror the settings above, lower-cased and without the `CRASHCAPTURE_`
prefix: `timeout`, `hang_kill`, `max_age_days`, `loopbreak`, `firstchance`,
`window_watchdog`, `lua_heartbeat`, `symbols`, `dir`, `script`, and `disable`.

- Raising `timeout` from `0` starts the watchdog, enabling `lua_heartbeat`
  installs the heartbeat timer; `set("disable", true)` disarms the plugin and
  `false` re-arms it.
- `max_age_days`, `dir`, and `script` only matter at the next startup / next
  crash respectively, so set them early.

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

**`mem` library**

- `mem.read(addr: address, type: string): number`\
    Reads the following possible types:\
    `int8`/`uint8`/`int16`/`uint16`/`int32`/`uint32`/`int64`/`uint64`/`float`/`double`/`ptr`.\
    `ptr` returns an `address`; `nil` if unreadable.

- `mem.string(addr: address, max: number): string`\
    Reads a NUL-terminated string (up to `max` bytes, default 256).

- `mem.deref(addr: address): address`\
    Reads the pointer stored.

- `mem.offset(addr: address, n: number): address`\
    Returns `addr + n`.

- `mem.sym(addr: address): string`\
    Returns `module+RVA` plus a symbol name when debug info is available.

- `mem.find(name: string): address, number`\
    Locates a loaded module by name, returning its `base` and `size`; `nil` if not found.

- `mem.modules(): table[]`\
    Array of `{name, base, size}` for every loaded module.

- `mem.scan(module: string, pattern: string): address`\
    IDA-style signature scan within `module` (e.g. `"48 8B ?? C3"`); `nil` if no match.

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
```
