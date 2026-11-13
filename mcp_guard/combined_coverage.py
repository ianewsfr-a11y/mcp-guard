"""What the combined rule could see, and why it concludes what it does.

The rule needs three capabilities. Its verdict depends on what is confirmed
(medium or high confidence), what is missing, and how much of the config it
could read:

- the three are confirmed: `triggered`;
- one is missing, and only low-confidence evidence could supply it (a free
  `config_path` with no sign its content is returned, a "makes no network
  request" sender): `partial`, naming those uncertain links. They are never
  counted as confirmed, and they never raise a finding;
- a capability is missing and some servers or tools could not be read:
  `partial`;
- otherwise `clear`. Low-confidence evidence that could not complete the
  chain (its capability is already confirmed, or another link is missing as
  well) is reported, but does not turn the verdict into `partial`.

Every verdict is the scanner's conclusion from what the servers declare
(names, descriptions, schemas, annotations). A server can misdescribe its
tools: no status certifies that a config is safe.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from .capabilities import CAPABILITIES, Capability, TaggedTool

LIMITS = ("drawn from what the servers declare (names, descriptions, schemas, annotations); "
          "a server can misdescribe its tools, so no status certifies a config as safe")


class UncertainLink(BaseModel):
    """A low-confidence tag that would complete the chain if confirmed."""

    model_config = ConfigDict(frozen=True)

    server: str | None
    tool: str
    capability: Capability
    source: str
    trigger: str

    @property
    def label(self) -> str:
        return f"{self.server} > {self.tool}" if self.server else self.tool


class Coverage(BaseModel):
    model_config = ConfigDict(frozen=True)

    confirmed: tuple[Capability, ...] = ()
    missing: tuple[Capability, ...] = ()
    relevant_uncertain: tuple[UncertainLink, ...] = ()  # would complete the chain
    other_uncertain: int = 0  # low-confidence tags that could not complete it
    unevaluated: tuple[str, ...] = ()  # active servers without a tool list
    malformed: int = 0  # tools that could not be parsed
    reasons: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        """Every active server was read and every tool could be tagged."""
        return not self.unevaluated and not self.malformed


def _links(tagged: list[TaggedTool]) -> list[UncertainLink]:
    return [UncertainLink(server=t.server, tool=t.name, capability=tag.capability,
                          source=tag.source, trigger=tag.trigger)
            for t in tagged for tag in t.uncertain]


def _count(tools: tuple[TaggedTool, ...]) -> str:
    return f"{len(tools)} tool(s)"


def coverage(surface: dict[Capability, tuple[TaggedTool, ...]], tagged: list[TaggedTool],
             unevaluated: list[str], malformed: int) -> Coverage:
    """Confirmed and missing capabilities, the uncertain links that matter,
    and the reasons, in order, for whatever verdict follows."""
    confirmed = tuple(c for c in CAPABILITIES if surface[c])
    missing = tuple(c for c in CAPABILITIES if not surface[c])
    links = _links(tagged)
    # only a single missing link can be "completed": two speculative links
    # make a chain too weak to report as partial
    relevant = tuple(link for link in links
                     if len(missing) == 1 and link.capability == missing[0])
    reasons = []
    if confirmed:
        reasons.append("confirmed: " + ", ".join(f"{c} ({_count(surface[c])})"
                                                  for c in confirmed))
    if missing:
        reasons.append("missing: " + ", ".join(missing))
    if relevant:
        reasons.append("uncertain, would complete the chain: " + ", ".join(
            f"{link.label} ({link.trigger})" for link in relevant[:5])
            + (f" and {len(relevant) - 5} more" if len(relevant) > 5 else ""))
    other = len(links) - len(relevant)
    if other:
        reasons.append(f"uncertain, not counted: {other} low-confidence tag(s) that could "
                       "not complete the chain")
    return Coverage(confirmed=confirmed, missing=missing, relevant_uncertain=relevant,
                    other_uncertain=other, unevaluated=tuple(unevaluated),
                    malformed=malformed, reasons=tuple(reasons))


def relevant_reason(cov: Coverage) -> str:
    """The `reason` clause for a `partial` that rests on uncertain links."""
    names = ", ".join(link.label for link in cov.relevant_uncertain[:5])
    more = len(cov.relevant_uncertain) - 5
    return (f"uncertain: {names}{f' and {more} more' if more > 0 else ''} could provide "
            f"{cov.missing[0]} (low confidence, not counted)")


def coverage_dict(cov: Coverage) -> dict[str, Any]:
    """JSON and SARIF form (additive since v0.14)."""
    return {"complete": cov.complete, "confirmed": list(cov.confirmed),
            "missing": list(cov.missing),
            "relevant_uncertain": [{"server": link.server, "tool": link.tool,
                                    "capability": link.capability, "source": link.source,
                                    "trigger": link.trigger}
                                   for link in cov.relevant_uncertain],
            "other_uncertain": cov.other_uncertain, "unevaluated": list(cov.unevaluated),
            "malformed": cov.malformed, "reasons": list(cov.reasons), "limits": LIMITS}
