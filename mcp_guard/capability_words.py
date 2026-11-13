"""Verb families shared by the capability keyword clauses and the schema
analysis (`capability_schema`)."""

READ_VERBS = frozenset(
    {"read", "get", "list", "search", "find", "open", "view", "load", "retrieve", "query",
     "select", "lookup", "browse", "export", "show", "fetch", "download"})
# reading a page brings its content in; a "request" alone only sends (see the
# sends_external clauses): "the request body", "request each URL for its status"
FETCH_VERBS = frozenset({"fetch", "download", "retrieve", "browse", "scrape", "crawl", "open",
                         "visit", "load"})
SEND_VERBS = frozenset({"send", "upload", "publish", "reply", "tweet", "webhook", "smtp",
                        "transfer", "deliver", "notify", "dispatch", "forward", "broadcast"})
