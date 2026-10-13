# Roadmap

Ideas that were scoped out on purpose, with the reason. Nothing here is promised.

## Package digests for `npx` / `uvx` launchers

The command `pin` hashes the launcher (`npx`, `uvx`, `node`...) and the script it runs when there is one. For a server started with `npx -y some-package`, it does not cover the code that the launcher downloads. Pinning that code would mean recording the npm integrity (`dist.integrity`) or the PyPI file digest of the resolved version, and checking it at start. That is out of scope for v0.8. It needs registry or cache access, and the proxy must never wait on the network before forwarding traffic.

## `proxy --enforce`

v0.8 is fail-open by design: the proxy prevents nothing, it makes changes visible. A blocking mode would hold back a `tools/list` answer that differs from the lock, or would refuse to start a server whose pin changed. It would need its own design: what the client sees instead, how to avoid breaking sessions on a legitimate upgrade, and how to approve a change. Until then, `--enforce` does not exist.

## Proxy hardening left for later

- **Hash every file argument.** The pin hashes the first argument that is an existing file. With `node --require ./hook.js server.js`, that is the hook, not the server.
- **Stop the whole process tree.** Use a process group on POSIX and a job object on Windows, with a grace period before a kill, so that the children of `npx` stop with the proxy.
- **Cap the size of `--record-bodies` journals.**

## Proxy over Streamable HTTP

The proxy speaks stdio only. Under the 2026-07-28 revision, `list_changed` arrives on HTTP through `subscriptions/listen`. The session logic (`runtime/inspector.py`) does not depend on the transport, so it can be reused.
