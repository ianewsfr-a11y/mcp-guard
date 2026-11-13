"""Held-out cases: written before the Lot 1 capability rules, never tuned for them.

Two parts, both with ground truth fixed before the rules were changed:

- synthetic tools that do not appear in `corpus.py`, including the five
  `config_path` situations of decision L1-a and phrasings of negation;
- the 38 tools of the official MCP reference servers
  (`tests/fixtures/official_tools.json`, real descriptions, schemas and
  annotations), annotated here by what each tool does.

A capability is `yes`, `no` or `ambiguous`. Ambiguous cases are not counted
in precision and recall: they are reported apart, and a tool should then be
left untagged or tagged with low confidence, never asserted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_OFFICIAL = json.loads((Path(__file__).resolve().parents[1] / "fixtures" /
                        "official_tools.json").read_text(encoding="utf-8"))["servers"]


def _schema(params: dict[str, Any]) -> dict[str, Any]:
    properties = {}
    for name, spec in params.items():
        properties[name] = ({"type": "string", "description": spec} if isinstance(spec, str)
                            else {"type": "string", **spec})
    return {"type": "object", "properties": properties}


def _tool(tid: str, sets: list[str], server: str, name: str, description: str,
          params: dict[str, Any] | None = None, technique: str = "",
          **caps: str) -> dict[str, Any]:
    truth = {"reads_private": "no", "ingests_untrusted": "no", "sends_external": "no", **caps}
    return {"id": tid, "sets": sets, "server": server, "name": name, "technique": technique,
            "truth": truth, "raw": {"name": name, "description": description,
                                    "inputSchema": _schema(params or {})}}


TOOLS: list[dict[str, Any]] = [
    # --- decision L1-a: a path parameter is evidence, not proof ---------------------
    _tool("L1", ["paths"], "configs", "read_config",
          "Read the configuration file at config_path and return its contents.",
          {"config_path": "Path to the file."}, "free path, content returned",
          reads_private="yes"),
    _tool("L2", ["paths"], "configs", "load_profile", "Load a profile.",
          {"config_path": {"description": "Name of a YAML file in the server's profiles "
                                          "folder; other paths are rejected.",
                           "pattern": "^[a-z0-9_-]+\\.yaml$"}},
          "path bounded by a schema pattern"),
    _tool("L3", ["paths"], "configs", "select_profile", "Select the active profile.",
          {"profile_path": "Logical profile name such as 'team/default'; nothing is read "
                           "from disk."}, "path used as an identifier"),
    _tool("L4", ["paths"], "configs", "check_config",
          "Check that config_path points to a readable file. Returns true or false only.",
          {"config_path": "Path to check."}, "path validated, no data returned"),
    _tool("L5", ["paths"], "configs", "apply_settings", "Apply settings.",
          {"config_path": "Optional configuration."}, "ambiguous",
          reads_private="ambiguous"),
    _tool("L6", ["paths"], "configs", "export_settings",
          "Write the current settings to the file at output_path.",
          {"output_path": "Destination file."}, "free path, write only"),
    # --- URLs: validate, read, send ------------------------------------------------------
    _tool("U1", ["web"], "web", "fetch_page", "Download a web page and return its text.",
          {"url": {"description": "Address of the page.", "format": "uri"}},
          "reads a URL the model chooses", ingests_untrusted="yes", sends_external="yes"),
    _tool("U2", ["web"], "web", "is_valid_url",
          "Tell whether a string is a syntactically valid URL. No network access.",
          {"url": "Candidate URL."}, "validates a URL locally"),
    _tool("U3", ["web"], "web", "post_webhook", "POST a JSON payload to a webhook URL.",
          {"webhook_url": "Target URL.", "payload": "JSON body."}, "sends to a chosen URL",
          sends_external="yes"),
    _tool("U4", ["web"], "web", "shorten_link", "Create a short link for a URL.",
          {"url": "Long URL."}, "third-party shortener", sends_external="ambiguous"),
    _tool("U5", ["web"], "web", "check_links",
          "Request each URL and report its HTTP status code.", {"urls": "URLs to check."},
          "contacts chosen hosts, returns status only", sends_external="yes"),
    _tool("U6", ["web"], "web", "screenshot_page",
          "Open the given URL in a headless browser and return a screenshot and the visible "
          "text.", {"url": "Page URL."}, "browser", ingests_untrusted="yes",
          sends_external="yes"),
    _tool("U7", ["web"], "web", "parse_url", "Split a URL into scheme, host, path and query.",
          {"url": "URL to parse."}, "string operation"),
    # --- negations: claims, not guarantees ---------------------------------------------
    _tool("G1", ["negation"], "sync", "upload_backup",
          "Upload the backup to the configured bucket. Does not send data anywhere else.",
          {"name": "Backup name."}, "negation next to a real send", sends_external="yes"),
    _tool("G2", ["negation"], "sync", "validate_email",
          "Read-only validation of an email address format; no email is sent.",
          {"address": "Email address."}, "negated send"),
    _tool("G3", ["negation"], "sync", "export_notes",
          "Cannot write files. Exports notes to the sync server.", {"notes": "Note ids."},
          "negation of another effect", sends_external="yes", reads_private="yes"),
    _tool("G4", ["negation"], "sync", "render_preview",
          "Render a markdown preview locally. Never makes network requests.",
          {"markdown": "Text."}, "negated request"),
    # --- a mailbox, a news reader, a chat: content and private data ---------------------
    _tool("M1", ["mail_web", "mail"], "mailbox", "list_messages", "List messages in the inbox.",
          {"folder": "Folder name."}, "inbox", reads_private="yes", ingests_untrusted="yes"),
    _tool("M2", ["mail_web", "mail"], "mailbox", "get_message", "Get one message by id.",
          {"id": "Message id."}, "inbox item", reads_private="yes",
          ingests_untrusted="yes"),
    _tool("M3", ["mail"], "mailbox", "send_message", "Send a message to a recipient.",
          {"to": "Recipient.", "body": "Text."}, "send", sends_external="yes"),
    _tool("W1", ["mail_web"], "browser", "browse", "Open a website and return its content.",
          {"url": "Website address."}, "web read", ingests_untrusted="yes",
          sends_external="yes"),
    _tool("S1", ["news_chat"], "news", "search_news", "Search recent news articles.",
          {"query": "Search terms."}, "news search", ingests_untrusted="yes"),
    _tool("S2", ["news_chat"], "news", "get_article", "Get the full text of an article by id.",
          {"id": "Article id."}, "stored third-party article", ingests_untrusted="yes"),
    _tool("S3", ["news_chat"], "news", "count_articles", "Count the stored articles.",
          {}, "counter on the same server"),
    _tool("S4", ["news_chat"], "chat", "post_to_channel", "Post a message to a chat channel.",
          {"channel": "Channel.", "text": "Message."}, "chat send", sends_external="yes"),
    # --- private stores without third-party content ---------------------------------------
    _tool("K1", ["kv_translate"], "store", "kv_get", "Return the value stored under a key.",
          {"key": "Key."}, "user's key-value store", reads_private="yes"),
    _tool("K2", ["kv_translate"], "store", "list_items", "List the items on the user's list.",
          {"list": "List name."}, "items without a fetch on the server",
          reads_private="yes"),
    _tool("K3", ["kv_translate"], "translate", "translate_text",
          "Translate text with the provider's API.", {"text": "Text.", "target": "Language."},
          "text sent to a fixed provider", sends_external="ambiguous"),
    # --- no capability ------------------------------------------------------------------
    _tool("Z1", ["todo_calc"], "calc", "multiply", "Multiply two numbers.",
          {"a": "First.", "b": "Second."}, "arithmetic"),
    _tool("Z2", ["todo_calc"], "calc", "format_json", "Pretty-print a JSON string.",
          {"json": "JSON text."}, "string operation"),
    _tool("Z3", ["todo_calc"], "notes_ui", "draft_reply",
          "Draft a reply for the user to review; nothing is sent.", {"context": "Thread."},
          "draft only"),
]

# --- official reference servers: ground truth by tool name -------------------------------
_YES_PRIVATE = {
    "read_graph", "search_nodes", "open_nodes", "read_file", "read_text_file",
    "read_media_file", "read_multiple_files", "list_directory", "list_directory_with_sizes",
    "directory_tree", "search_files", "get_file_info", "git_status", "git_diff_unstaged",
    "git_diff_staged", "git_diff", "git_log", "git_show", "git_branch"}
_AMBIGUOUS_PRIVATE = {"list_allowed_directories", "edit_file"}
_GIT_READS = {"git_diff_unstaged", "git_diff_staged", "git_diff", "git_log", "git_show"}

for server, raw_tools in _OFFICIAL.items():
    for raw in raw_tools:
        name = raw["name"]
        truth = {"reads_private": ("yes" if name in _YES_PRIVATE else
                                   "ambiguous" if name in _AMBIGUOUS_PRIVATE else "no"),
                 # git content may come from other authors: not decidable from the tool
                 "ingests_untrusted": ("yes" if name == "fetch" else
                                       "ambiguous" if name in _GIT_READS else "no"),
                 "sends_external": "yes" if name == "fetch" else "no"}
        sets = ["official_all"] + ([] if server == "fetch" else ["official_local"])
        TOOLS.append({"id": f"O-{server}-{name}", "sets": sets, "server": f"official-{server}",
                      "name": name, "technique": "official reference server", "truth": truth,
                      "raw": raw})

SETS: dict[str, dict[str, Any]] = {
    "paths": {"expected_alert": None, "why": "decision L1-a cases"},
    "web": {"expected_alert": None, "why": "URL cases"},
    "negation": {"expected_alert": None, "why": "negation cases"},
    "mail": {"expected_alert": True, "why": "an inbox (private, third-party) and a send tool"},
    "mail_web": {"expected_alert": True, "why": "inbox (private, third-party) and a browser"},
    "news_chat": {"expected_alert": False, "why": "no private read"},
    "kv_translate": {"expected_alert": False, "why": "no third-party content"},
    "todo_calc": {"expected_alert": False, "why": "no capability"},
    "official_all": {"expected_alert": True,
                     "why": "filesystem/git/memory reads, fetch reads and sends"},
    "official_local": {"expected_alert": False, "why": "no fetch: nothing goes out"},
}

RESULTS: list[dict[str, Any]] = []
