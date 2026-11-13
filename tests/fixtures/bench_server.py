"""A stdio MCP server that serves one benchmark set: `python bench_server.py SET [SERVER]`.

Used to check that the in-process benchmark measures what `inspect --live`
reports. Tools have no effect: every call answers "no-op".
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))
import bench

corpus = bench.load("historical")

WANTED = sys.argv[1]
SERVER = sys.argv[2] if len(sys.argv) > 2 else None
TOOLS = [bench.raw_tool(t) for t in bench.set_tools(corpus.TOOLS, WANTED)
         if SERVER is None or bench.server_of(t, WANTED) == SERVER]


def reply(msg_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    method, msg_id = msg.get("method"), msg.get("id")
    if msg_id is None:
        continue
    if method == "initialize":
        reply(msg_id, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                       "serverInfo": {"name": f"bench-{WANTED}", "version": "1.0.0"}})
    elif method == "tools/list":
        reply(msg_id, {"tools": TOOLS})
    elif method == "tools/call":
        reply(msg_id, {"content": [{"type": "text", "text": "no-op"}]})
    else:
        reply(msg_id, {})
