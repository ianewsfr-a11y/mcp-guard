"""Runtime side of mcp-guard: `mcp-guard proxy` sits between an MCP client and
a stdio server, copies every byte unchanged, and reports on stderr what the
server declares that differs from the lock or from earlier in the session.

The proxy prevents nothing; it makes things visible. It is fail-open: no
error of its own (missing lock, unwritable journal, unparsable message)
ever stops or alters the traffic.
"""
