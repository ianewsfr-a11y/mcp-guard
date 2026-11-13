"""Coverage scenarios for the combined rule (V2, Lot 2).

Written, with their expected statuses, before the coverage model was
implemented, from the decision rules alone:

- A: the three capabilities are confirmed -> `triggered`;
- B: a capability is missing and nothing uncertain could supply it -> `clear`;
- C: two are confirmed and the third rests only on low-confidence evidence
  -> `partial`, naming the uncertain tool;
- D: low-confidence evidence that could not complete the chain (the
  capability is already confirmed, or two are missing) -> not `partial`;
- E: unreachable servers or unparsable tools -> `partial` when a capability
  is missing, `not-evaluated` when nothing could be read;
- F: what a server declares (annotations, descriptions, schemas) is never
  taken as proof of confinement;
- L2: a path parameter bounded by the schema contradicts a "reads private
  data" keyword: the doubt is shown, the read is not asserted.

`servers` maps a server name to its tools, or to "unreachable". A tool
without a name is malformed. `relevant` is the capability an uncertain tool
would supply in case C (None otherwise).
"""

from __future__ import annotations

from typing import Any


def _t(name: str, description: str, properties: dict[str, Any] | None = None,
       annotations: dict[str, Any] | None = None) -> dict[str, Any]:
    tool: dict[str, Any] = {"name": name, "description": description,
                            "inputSchema": {"type": "object", "properties": properties or {}}}
    if annotations is not None:
        tool["annotations"] = annotations
    return tool


READ_FILE = _t("read_file", "Read a file from the user's home directory.",
               {"path": {"type": "string"}})
READ_NOTES = _t("read_notes", "Read the user's private notes.")
FETCH_URL = _t("fetch_url", "Fetch a web page and return its text.",
               {"url": {"type": "string"}})
RSS = _t("read_feed", "Read the latest entries of an RSS feed.")
NEWS = _t("search_news", "Search recent news articles.")
SEND_EMAIL = _t("send_email", "Send an email to any address.")
POST_HOOK = _t("post_webhook", "Send a notification to the configured webhook.")
CALC = _t("add_numbers", "Add two numbers.")
TIME = _t("current_time", "Return the current time in UTC.")
APPLY = _t("apply_settings", "Apply settings.", {"config_path": {"type": "string"}})
IS_URL = _t("is_valid_url", "Tell whether a string is a valid URL.",
            {"url": {"type": "string"}})
CHECK_LINK = _t("check_link", "Check that a URL is well formed. Makes no network request.")
GIT_COMMIT = _t("git_commit", "Records changes to the repository.",
                {"repo_path": {"type": "string"}})
GIT_ADD = _t("git_add", "Adds file contents to the staging area.",
             {"repo_path": {"type": "string"}})

SCENARIOS: list[dict[str, Any]] = [
    {"id": "CV01", "case": "A", "expected": "triggered", "relevant": None,
     "why": "read, web content and send confirmed",
     "servers": {"fs": [READ_FILE], "web": [FETCH_URL], "mail": [SEND_EMAIL]}},
    {"id": "CV02", "case": "B", "expected": "clear", "relevant": None,
     "why": "nothing but arithmetic", "servers": {"calc": [CALC, TIME]}},
    {"id": "CV03", "case": "B", "expected": "clear", "relevant": None,
     "why": "private read and send, no third-party content, nothing uncertain",
     "servers": {"notes": [READ_NOTES], "mail": [SEND_EMAIL]}},
    {"id": "CV04", "case": "C", "expected": "partial", "relevant": "reads_private",
     "why": "news and a webhook confirmed; a free config_path is the only possible read",
     "servers": {"news": [NEWS, POST_HOOK, APPLY]}},
    {"id": "CV05", "case": "C", "expected": "partial", "relevant": "sends_external",
     "why": "read and feed confirmed; the only possible send says it makes no request "
            "(a declaration, not a guarantee: F)",
     "servers": {"fs": [READ_FILE], "feeds": [RSS, CHECK_LINK]}},
    {"id": "CV06", "case": "D", "expected": "clear", "relevant": None,
     "why": "an uncertain read, but no content and no send at all",
     "servers": {"cfg": [APPLY, CALC]}},
    {"id": "CV07", "case": "D", "expected": "clear", "relevant": None,
     "why": "the uncertain send is irrelevant: send is confirmed, content is missing",
     "servers": {"notes": [READ_NOTES], "mail": [SEND_EMAIL], "util": [IS_URL]}},
    {"id": "CV08", "case": "D", "expected": "clear", "relevant": None,
     "why": "two links would rest on low-confidence evidence: shown, not partial",
     "servers": {"news": [NEWS], "cfg": [APPLY], "util": [IS_URL]}},
    {"id": "CV09", "case": "E", "expected": "partial", "relevant": None,
     "why": "content is missing, but one server could not be reached",
     "servers": {"fs": [READ_FILE], "mail": [SEND_EMAIL], "web": "unreachable"}},
    {"id": "CV10", "case": "E", "expected": "not-evaluated", "relevant": None,
     "why": "no server could be reached",
     "servers": {"fs": "unreachable", "web": "unreachable"}},
    {"id": "CV11", "case": "E", "expected": "partial", "relevant": None,
     "why": "a send is missing and a tool could not be parsed",
     "servers": {"fs": [READ_FILE], "web": [NEWS, {"description": "no name"}]}},
    {"id": "CV12", "case": "F", "expected": "triggered", "relevant": None,
     "why": "a sender that claims read-only, closed-world and 'does not send'",
     "servers": {"fs": [READ_FILE], "web": [NEWS],
                 "out": [_t("send_report", "Does not send anything.",
                            annotations={"readOnlyHint": True, "openWorldHint": False})]}},
    {"id": "CV13", "case": "F", "expected": "triggered", "relevant": None,
     "why": "a pattern that lets any path through is not a bound",
     "servers": {"fs": [_t("read_any", "Read the file at path and return its contents.",
                           {"path": {"type": "string", "pattern": ".*"}})],
                 "web": [FETCH_URL]}},
    {"id": "CV14", "case": "L2", "expected": "partial", "relevant": "reads_private",
     "why": "'load a profile' says read, the schema bounds the path: doubt, not a read",
     "servers": {"cfg": [_t("load_profile", "Load a profile.",
                            {"config_path": {"type": "string",
                                             "pattern": "^[a-z0-9_-]+\\.yaml$"}})],
                 "web": [FETCH_URL]}},
    {"id": "CV15", "case": "L2", "expected": "triggered", "relevant": None,
     "why": "a bounded path does not cancel independent evidence (an inbox read)",
     "servers": {"mail": [_t("read_inbox", "Read the emails in the inbox.",
                             {"folder": {"type": "string", "enum": ["inbox", "sent"]}})],
                 "web": [FETCH_URL]}},
    {"id": "CV16", "case": "rules", "expected": "triggered", "relevant": None,
     "why": "the user confirms the uncertain read with a rule",
     "rules": {"capabilities": [{"server": "news", "tool": "apply_settings",
                                 "add": ["reads_private"]}]},
     "servers": {"news": [NEWS, POST_HOOK, APPLY]}},
    {"id": "CV17", "case": "rules", "expected": "clear", "relevant": None,
     "why": "the user removes the uncertain read: nothing else could supply it",
     "rules": {"capabilities": [{"server": "news", "tool": "apply_settings",
                                 "remove": ["reads_private"]}]},
     "servers": {"news": [NEWS, POST_HOOK, APPLY]}},
    {"id": "CV18", "case": "rules", "expected": "clear", "relevant": None,
     "why": "the only sender is removed by a rule",
     "rules": {"capabilities": [{"server": "web", "tool": "fetch_url",
                                 "remove": ["sends_external"]}]},
     "servers": {"fs": [READ_FILE], "web": [FETCH_URL]}},
    {"id": "CV19", "case": "D", "expected": "clear", "relevant": None,
     "why": "local git write tools with free repo paths: many doubts, no chain",
     "servers": {"git": [GIT_COMMIT, GIT_ADD], "time": [TIME]}},
    {"id": "CV20", "case": "A", "expected": "triggered", "relevant": None,
     "why": "the chain spread over four servers, with doubts elsewhere",
     "servers": {"fs": [READ_FILE], "feeds": [RSS], "mail": [SEND_EMAIL],
                 "util": [IS_URL, APPLY]}},
]
