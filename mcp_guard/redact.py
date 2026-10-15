"""Recognizing secrets and keeping them out of reports, locks and snapshots.

Shared by the rules (hardcoded-secret), the lock file, the TUI and the
serialized snapshot, so that every output redacts the same way.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import ServerSpec
from .rules import tokenize

REDACTED = "<redacted>"
_SECRET_KEY_TOKENS = frozenset(
    {"token", "key", "apikey", "secret", "password", "passwd", "pwd",
     "credential", "credentials", "auth", "authorization"}
)
# ${VAR}, ${env:VAR}, ${input:id}, ${file:/path} (VS Code, Windsurf),
# ${{ secrets.X }} (Continue), $VAR, %VAR%.
_VARIABLE_REFERENCE = re.compile(r"\$\{\{[^}]*\}\}|\$\{[^}]+\}|^\$\w+$|^%\w+%$")
_SECRET_FLAG = re.compile(
    r"^(?P<flag>--?[\w-]*(key|token|secret|password)[\w-]*)=(?P<value>.+)$", re.IGNORECASE)
_SECRET_BARE_FLAG = re.compile(r"^--?[\w-]*(key|token|secret|password)[\w-]*$",
                               re.IGNORECASE)
_NOT_A_SECRET_FLAG = re.compile(r"(file|path|dir|name|id)$", re.IGNORECASE)
_ASSIGNMENT = re.compile(r"^(?P<key>[A-Za-z_][\w.-]*)=(?P<value>.+)$")
_URL_CREDENTIALS = re.compile(r"(\w+://[^/\s:@]+:)[^@\s/]+@")


def redact_value(value: str) -> str:
    """Evidence for a secret: its length, never its content."""
    return f"<redacted, {len(value)} chars>"


def is_secret_key(key: str) -> bool:
    """Whether an env/header/query name looks like it holds a credential."""
    return bool(tokenize(key) & _SECRET_KEY_TOKENS)


def is_literal(value: str) -> bool:
    """A value written in the config, not a reference such as `${env:KEY}`."""
    return bool(value) and not _VARIABLE_REFERENCE.search(value)


def has_url_credentials(value: str) -> bool:
    return bool(_URL_CREDENTIALS.search(value))


def strip_url_credentials(value: str) -> str:
    return _URL_CREDENTIALS.sub(lambda m: m.group(1) + f"{REDACTED}@", value)


def secret_arg(arg: str, previous: str | None) -> tuple[str, str] | None:
    """(evidence, redacted arg) when a launch argument holds a literal secret:
    `--api-key=X`, `--api-key X`, `API_KEY=X` (e.g. `docker -e`) or a URL
    with a password such as `postgres://user:pw@host/db`."""
    flag = _SECRET_FLAG.match(arg)
    if flag and is_literal(flag["value"]) and not _NOT_A_SECRET_FLAG.search(flag["flag"]):
        return f"arg {flag['flag']}={redact_value(flag['value'])}", f"{flag['flag']}={REDACTED}"
    assignment = _ASSIGNMENT.match(arg)
    if (assignment and is_secret_key(assignment["key"])
            and is_literal(assignment["value"])):
        key = assignment["key"]
        return f"arg {key}={redact_value(assignment['value'])}", f"{key}={REDACTED}"
    if has_url_credentials(arg):
        return "arg url credentials in userinfo", strip_url_credentials(arg)
    if (previous and _SECRET_BARE_FLAG.match(previous)
            and not _NOT_A_SECRET_FLAG.search(previous)
            and not arg.startswith("-") and is_literal(arg)):
        return f"arg {previous} {redact_value(arg)}", REDACTED
    return None


# Shapes of a secret inside an argument that `secret_arg` cannot name: the
# command pin masks them, `secret-in-args` reports them.
URL_ORIGIN = re.compile(r"(\w+://[^/\s?#]*)\S*")  # group 1: scheme and host
TOKEN = re.compile(r"(?=[\w+=-]*\d)(?=[\w+=-]*[A-Za-z])[\w+=-]{24,}")
SECRET_WORDS = re.compile(r"bearer\s|password=|passwd=|pwd=|secret=|token=", re.IGNORECASE)
_DIGEST = re.compile(r"sha(1|224|256|384|512)[:=-]$", re.IGNORECASE)


def _token(arg: str) -> bool:
    """A long random-looking word outside URLs, not a pinned digest."""
    text = URL_ORIGIN.sub(" ", arg)
    return any(not _DIGEST.search(text[:m.start()]) for m in TOKEN.finditer(text))


def secret_args(args: list[str]) -> list[str]:
    """Evidence for the arguments that look secret but that `hardcoded-secret`
    does not report (it covers `--api-key X`, `KEY=X` and URL passwords):
    credential words (`Bearer x`, `password=`) and token-like words."""
    return [evidence for _, evidence in secret_args_at(args)]


def secret_args_at(args: list[str]) -> list[tuple[int, str]]:
    """`secret_args` with the index of each argument."""
    found: list[tuple[int, str]] = []
    previous = None
    for index, arg in enumerate(args):
        if secret_arg(arg, previous) is None:
            reason = ("credential word" if SECRET_WORDS.search(arg)
                      else "token-like word" if _token(arg) else None)
            if reason:
                found.append((index, f"arg {index}: {reason} (<redacted, {len(arg)} chars>)"))
        previous = arg
    return found


def redact_args(args: list[str]) -> list[str]:
    """Launch arguments with every literal secret replaced, for display."""
    redacted, previous = [], None
    for arg in args:
        found = secret_arg(arg, previous)
        redacted.append(found[1] if found else arg)
        previous = arg
    return redacted


def safe_url(url: str) -> str:
    """Drop userinfo, query and fragment so credentials never reach the output."""
    parts = urlsplit(url)
    try:
        port = f":{parts.port}" if parts.port else ""
    except ValueError:  # non-numeric port
        port = ""
    return f"{parts.scheme}://{parts.hostname or ''}{port}{parts.path}"


# --- storage form ---------------------------------------------------------------
#
# Stricter than detection: over-redacting a stored snapshot costs nothing,
# leaking costs a credential. Env and header values are all redacted (the
# lock file already tracks their changes with a salted HMAC); a key that
# looks secret redacts its whole subtree, whatever the value type; every
# string holding a URL loses its userinfo and its secret-looking parameters.

_STORAGE_SECRET_TOKENS = _SECRET_KEY_TOKENS | frozenset(
    {"tokens", "keys", "apikeys", "secrets", "passwords", "pass", "cookie", "cookies",
     "jwt", "bearer", "session", "sessionid", "sid", "signature", "sig", "pat",
     "privatekey", "clientsecret"})
_PURE_REFERENCE = re.compile(r"\$\{\{[^}]*\}\}|\$\{[^}]+\}|%\w+%")
_HAS_URL = re.compile(r"\w+://")


def _storage_secret_key(key: str) -> bool:
    return bool(tokenize(key) & _STORAGE_SECRET_TOKENS)


def _is_reference(value: str) -> bool:
    """Exactly one reference such as `${env:API_KEY}`, nothing else around it."""
    return bool(_PURE_REFERENCE.fullmatch(value.strip()))


def _stored_url(url: str) -> str:
    """The URL without userinfo, with secret-looking query values redacted.
    Anything that does not parse is redacted whole."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        netloc = f"{host}:{parts.port}" if parts.port else host
        pairs = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return REDACTED
    if "@" in parts.path:  # userinfo with a "/" in it spills into the path
        return REDACTED
    # a bare `?abc123` parameter can itself be the token: redact the key
    query = urlencode([(REDACTED, "") if not v else
                       (k, REDACTED if _storage_secret_key(k) else v) for k, v in pairs])
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def stored_text(value: str) -> str:
    """Free text as stored: every URL in it loses userinfo and secret values."""
    return _stored_text(value)


def _stored_text(value: str) -> str:
    if not _HAS_URL.search(value):
        return value
    return " ".join(_stored_url(word) if _HAS_URL.search(word) else word
                    for word in value.split(" "))


def _stored_value(key: str, value: Any) -> Any:
    if _storage_secret_key(key):
        return value if isinstance(value, str) and _is_reference(value) else REDACTED
    if isinstance(value, dict):
        return {str(k): _stored_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [_stored_value(key, item) for item in value]
    return _stored_text(value) if isinstance(value, str) else value


def _stored_mapping(mapping: dict[str, Any]) -> dict[str, str]:
    return {str(k): v if isinstance(v, str) and _is_reference(v) else REDACTED
            for k, v in mapping.items()}


def stored_spec(spec: ServerSpec) -> dict[str, Any]:
    """A server spec safe to write to disk. Env and header values are
    redacted unless they are references such as `${env:API_KEY}`; secrets in
    arguments, URLs and extra settings are redacted too."""
    extra = {str(k): _stored_value(str(k), v) for k, v in (spec.model_extra or {}).items()}
    return {
        **extra,
        "command": _stored_text(spec.command),
        "args": [_stored_text(a) for a in redact_args([str(a) for a in spec.args])],
        "env": _stored_mapping(spec.env),
        "headers": _stored_mapping(spec.headers),
        "url": _stored_url(spec.url) if spec.url else "",
    }
