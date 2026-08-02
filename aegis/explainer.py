"""Human-readable receipts. Optional, read-only, and strictly after the fact.

explain() is called with a Decision that is already final and already written to
the chain. It cannot change an outcome, and nothing depends on it: delete this
file and Aegis works identically. That is the property the spec asks for in
section 2, and keeping it true is why the receipt is computed on demand and
never stored inside a hashed structure.

This is templated string formatting — no model is involved at all, which is the
safest possible version of the explainer the spec permits.
"""

from __future__ import annotations

from typing import Any

from aegis.models import LogEntry

_TEMPLATES: dict[str, str] = {
    "internal_recipient_ok": "Allowed: {to} is an internal corp address.",
    "external_recipient_stepup": (
        "Held for human approval: {to} is outside corp, and this agent may not "
        "email external recipients unattended."
    ),
    "data_path_ok": "Allowed: {path} is inside the permitted /data/ directory.",
    "secrets_path_blocked": (
        "Blocked: {path} is inside /secrets/, which this agent may never read."
    ),
    "amount_within_limit": "Allowed: EUR {amount_eur} is within this agent's EUR 50 limit.",
    "amount_exceeds_limit": (
        "Blocked: EUR {amount_eur} exceeds this agent's EUR 50 payment limit."
    ),
    "no_rule_matched": "Blocked: no policy rule permits {tool} with these arguments.",
}

_FALLBACK = "{outcome}: {reason_code}."


class _Missing(dict[str, Any]):
    """Renders absent arguments as '?' instead of raising.

    A receipt is cosmetic. A malformed action still produces a log entry, and a
    KeyError here must never be able to break the request that produced it.
    """

    def __missing__(self, key: str) -> str:
        return "?"


def explain(entry: LogEntry) -> str:
    """One sentence of prose for a decision that has already been made."""
    decision = entry.decision
    template = _TEMPLATES.get(decision.reason_code, _FALLBACK)
    fields: dict[str, Any] = {
        **entry.request.args,
        "tool": entry.request.tool,
        "outcome": decision.outcome,
        "reason_code": decision.reason_code,
    }
    return template.format_map(_Missing(fields))
