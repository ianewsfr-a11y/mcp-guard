"""`mcp-guard journal`: work with a proxy journal (`proxy --record`)."""

from __future__ import annotations

import json
import os
import secrets
import stat
import tempfile
from pathlib import Path

import click
from rich.console import Console

from .markup import escape
from .runtime.journal import Export, Options, bounded_lines, read_journal
from .runtime.otlp import to_otlp

stderr = Console(stderr=True)


class JournalError(click.ClickException):
    """Unreadable journal or unwritable output: exit code 2, as other input errors."""

    exit_code = 2


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _read(path: Path, options: Options) -> Export:
    try:
        if not stat.S_ISREG(path.stat().st_mode):  # a FIFO or a device may never end
            raise JournalError(f"{path} is not a regular file")
        with path.open(encoding="utf-8", errors="replace", newline="\n") as handle:
            return read_journal(bounded_lines(handle), options)
    except OSError as exc:
        raise JournalError(f"cannot read {path}: {exc.strerror or exc}") from exc


def write_private(path: Path, text: str) -> None:
    """Write through a temporary file in the same folder, readable by its owner
    only, then replace: a symbolic link at `path` is replaced, not followed,
    and a failed write leaves the former file whole."""
    try:
        fd, temporary = tempfile.mkstemp(prefix=".mcp-guard-", dir=path.parent or Path("."))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text + "\n")
            os.replace(temporary, path)
        except BaseException:
            try:
                os.close(fd)  # still open when fdopen itself failed
            except OSError:
                pass
            Path(temporary).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise JournalError(f"cannot write {path}: {exc.strerror or exc}") from exc


def _same_file(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve() or (b.exists() and os.path.samefile(a, b))
    except OSError:
        return False


def _summary(result: Export) -> str:
    linked = sum(1 for s in result.spans if s.parent_id)
    text = (f"{_plural(len(result.spans), 'span')}, {linked} from an incoming trace, "
            f"{len(result.spans) - linked} local; {_plural(result.skipped, 'line')} skipped, "
            f"{result.unmatched} answer(s) or cancellation(s) with no open request")
    if result.dropped:
        text += f"; {_plural(result.dropped, 'request')} not exported (limits reached)"
    if result.lost:
        text += (f"; the proxy could not record {_plural(result.lost, 'message')}, "
                 "so some calls may show no response")
    return text


@click.group()
def journal() -> None:
    """Work with a proxy journal (`proxy --record`)."""


@journal.command("export")
@click.argument("journal_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--otlp", is_flag=True, default=True,
              help="OTLP/JSON traces, for an OpenTelemetry collector (the only format so far).")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path),
              help="Write the traces to this file (readable by you only) instead of stdout.")
@click.option("--local-traces", is_flag=True,
              help="Ignore incoming traceparents: every request is a local root.")
@click.option("--id-salt", metavar="TEXT",
              help="Derive span ids from this text: the same salt gives the same export. "
                   "Random by default.")
def export(journal_file: Path, otlp: bool, output: Path | None, local_traces: bool,
           id_salt: str | None) -> None:
    """Export a journal as OpenTelemetry traces: one span per request, with
    its outcome, linked to the caller's trace when the request carried a
    W3C traceparent. Message bodies are never exported, even when the
    journal was recorded with --record-bodies. Nothing is sent anywhere:
    give the file to your collector. It reveals the caller's trace ids:
    load it into the backend those traces belong to."""
    if output is not None and _same_file(journal_file, output):
        raise JournalError("the output is the journal itself: choose another file")
    salt = id_salt if id_salt is not None else secrets.token_hex(16)
    result = _read(journal_file, Options(salt=salt, propagate=not local_traces))
    text = json.dumps(to_otlp(result.spans))
    if output is None:
        click.echo(text)
    else:
        write_private(output, text)
        stderr.print(f"Traces written to {escape(str(output))}")
    stderr.print(_summary(result))
