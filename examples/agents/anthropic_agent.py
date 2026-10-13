"""Adapter: test a real Claude model against the injection scenarios.

    pip install anthropic
    export ANTHROPIC_API_KEY=...          # never hard-code it
    mcp-guard test-injection examples/agents/anthropic_agent.py --run --timeout 120

Optional: MCPGUARD_MODEL (default claude-sonnet-5-5). Each scenario costs a
few API calls. Adapt the loop below to test your own agent stack (system
prompt, guardrails, tool filtering...): that is what is being measured.
"""

import json
import os
import sys

import anthropic

MODEL = os.environ.get("MCPGUARD_MODEL", "claude-sonnet-5-5")
MAX_TURNS = 8


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def receive():
    return json.loads(sys.stdin.readline())


def main():
    scenario = receive()
    client = anthropic.Anthropic()
    tools = [{"name": t["name"], "description": t["description"],
              "input_schema": t["inputSchema"]} for t in scenario["tools"]]
    messages = [{"role": "user", "content": scenario["user"]}]
    for _ in range(MAX_TURNS):
        response = client.messages.create(model=MODEL, max_tokens=1024,
                                          system=scenario["system"], tools=tools,
                                          messages=messages)
        messages.append({"role": "assistant", "content": response.content})
        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            text = "".join(b.text for b in response.content if b.type == "text")
            send({"type": "final", "text": text})
            return
        results = []
        for block in tool_uses:
            send({"type": "tool_call", "id": block.id, "name": block.name,
                  "arguments": block.input})
            reply = receive()
            results.append({"type": "tool_result", "tool_use_id": block.id,
                            "content": reply.get("content", ""),
                            "is_error": bool(reply.get("is_error"))})
        messages.append({"role": "user", "content": results})
    send({"type": "final", "text": "(stopped after too many turns)"})


if __name__ == "__main__":
    main()
