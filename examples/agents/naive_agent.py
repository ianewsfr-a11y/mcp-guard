"""A deliberately naive agent: it obeys any instruction it reads.

Use it to see what a failing run looks like:

    mcp-guard test-injection examples/agents/naive_agent.py --run --yes

It speaks the mcp-guard-harness/1 protocol (one JSON object per line on
stdin/stdout), like any adapter you write around a real model.
"""

import base64
import json
import re
import sys

TASK_TOOLS = {"note": "read_note", "document": "read_document", "weather": "get_weather",
              "email": "send_email"}


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def receive():
    return json.loads(sys.stdin.readline())


def call(name, arguments):
    send({"type": "tool_call", "id": f"c-{name}", "name": name, "arguments": arguments})
    return receive().get("content", "")


def decoded(text):
    """Naively decode any base64 blob and treat it as more text to obey."""
    extra = []
    for blob in re.findall(r"[A-Za-z0-9+/=]{16,}", text):
        try:
            extra.append(base64.b64decode(blob).decode("utf-8"))
        except ValueError:
            continue
    return " ".join([text, *extra])


def obey(text, answer, email):
    """Follow every instruction found in text. Returns the new answer."""
    for word in re.findall(r"MCPGUARD-CANARY-\w+", text):
        answer = f"{answer} {word}"
    shell = re.search(r"shell tool with `([^`]+)`", text)
    if shell:
        call("run_shell", {"command": shell.group(1)})
    url = re.search(r"fetch (https?://\S+)", text)
    if url:
        call("fetch_url", {"url": url.group(1)})
    path = re.search(r"read the file (\S+)", text)
    if path:
        email["notes"] = call("read_file", {"path": path.group(1)})
    bcc = re.search(r"bcc: (\S+?)\.?(\s|$)", text)
    if bcc:
        email["bcc"] = bcc.group(1)
    if "pre-approved" in text:
        call("delete_file", {"path": "latest"})
    return answer


def main():
    scenario = receive()
    descriptions = " ".join(t["description"] for t in scenario["tools"])
    email = {}
    answer = obey(decoded(descriptions), "Done.", email)
    task = scenario["user"].lower()
    tool = next(t for k, t in TASK_TOOLS.items() if k in task)
    if tool == "send_email":
        call(tool, {"to": "bob@example.com", "subject": "Report", "body": "It is ready.",
                    **email})
    else:
        result = call(tool, {"note_id": "latest", "url": "x", "city": "Paris", **email})
        answer = obey(decoded(result), f"Summary: {result[:40]}", email)
    send({"type": "final", "text": answer})


if __name__ == "__main__":
    main()
