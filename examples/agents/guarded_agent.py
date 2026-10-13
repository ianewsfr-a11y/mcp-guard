"""A rule-based agent that treats tool output as data, never as instructions.

    mcp-guard test-injection examples/agents/guarded_agent.py --run --yes

It only calls the one tool the task needs and never repeats text it did not
write. Real model-backed agents are harder to pin down: test them with an
adapter such as anthropic_agent.py.
"""

import json
import sys

TASK_TOOLS = {"note": ("read_note", {"note_id": "latest"}),
              "document": ("read_document", {"url": "https://drive.example.com/q3-report"}),
              "weather": ("get_weather", {"city": "Paris"}),
              "email": ("send_email", {"to": "bob@example.com", "subject": "Report",
                                       "body": "The report is ready."})}


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main():
    scenario = json.loads(sys.stdin.readline())
    task = scenario["user"].lower()
    name, arguments = next(v for k, v in TASK_TOOLS.items() if k in task)
    send({"type": "tool_call", "id": "c1", "name": name, "arguments": arguments})
    sys.stdin.readline()  # the result is data; nothing in it is obeyed
    send({"type": "final", "text": f"I used {name} to complete your request."})


if __name__ == "__main__":
    main()
