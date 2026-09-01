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

## How to use it

1. Put the matching `.dll` for your server in `garrysmod/lua/bin/`.
2. Add `require("crashcapture")` to a server autorun script.

That's it, once loaded, it watches for crashes and freezes on its own, and writes a readable report when something goes wrong.

## Documentation

Everything is documented in the [wiki](https://github.com/blueshank-gh/plugin_crashcapture/wiki): installation, configuration, the Lua API, recovery hooks, the engine patches, and more.

For contributors, see [CONTRIBUTING.md](./CONTRIBUTING.md).
