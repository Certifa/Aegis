"""Deterministic policy evaluation.

evaluate() is a pure synchronous function of (action, policy) -> Decision. No
I/O, no network, and above all no language model: the threat this project
defends against is an LLM being manipulated, so the enforcement boundary
contains no LLM. Spec: aegis-build-spec.pdf section 4.
"""

from __future__ import annotations

import posixpath
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml

from aegis.models import ActionRequest, Condition, Decision, Policy, Rule

NO_RULE_MATCHED = "no_rule_matched"


def load_policy(path: Path) -> Policy:
    """Read and validate a policy file.

    All policy I/O happens here, at startup, and never inside evaluate().
    safe_load, not load: a policy file is untrusted input to a security
    component, and yaml.load can construct arbitrary Python objects.
    """
    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: policy file must be a YAML mapping")
    return Policy.model_validate(raw)


def _domain_of(value: object) -> str | None:
    """The domain part of an email address, or None if it isn't one.

    Fails closed. If we cannot determine a domain we cannot honestly say a
    to_domain rule matched, so the action falls through to deny-by-default.
    """
    if not isinstance(value, str):
        return None
    local, sep, domain = value.rpartition("@")
    if not sep or not local or not domain:
        return None
    return domain


def _matches_path_prefix(value: object, prefix: str) -> bool:
    if not isinstance(value, str):
        return False
    # Normalise BEFORE comparing. '/data/../secrets/creds.env' carries the
    # prefix '/data/' as a raw string but resolves into /secrets/ — comparing
    # the raw string is a traversal bypass of the rule.
    return posixpath.normpath(value).startswith(prefix)


def _matches_max_eur(value: object, ceiling: Decimal) -> bool:
    # bool is a subclass of int, so True would otherwise compare as 1 <= 50.
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    amount = Decimal(str(value))
    # A negative amount is not "within the limit" in any meaningful sense, so
    # it fails closed and falls through to the catch-all deny.
    return Decimal(0) <= amount <= ceiling


def matches(when: Condition, args: Mapping[str, Any]) -> bool:
    """True if a rule's condition holds for these args. Pure.

    Condition guarantees exactly one kind is set. Every kind fails closed on a
    missing or wrong-typed argument, so a malformed action is denied and
    logged rather than slipping through.
    """
    if when.always:
        return True
    if when.to_domain is not None:
        domain = _domain_of(args.get("to"))
        if domain is None:
            return False
        return when.to_domain == "*" or domain == when.to_domain
    if when.path_prefix is not None:
        return _matches_path_prefix(args.get("path"), when.path_prefix)
    if when.max_eur is not None:
        return _matches_max_eur(args.get("amount_eur"), when.max_eur)
    raise AssertionError("unreachable: Condition guarantees one kind is set")


def _reason_code(rule: Rule) -> str:
    return rule.reason_code or rule.id


def evaluate(action: ActionRequest, policy: Policy) -> Decision:
    """Evaluate one action. Pure, synchronous, no I/O.

    First match wins, so rule order in the policy file is significant. An
    action matching no rule is refused, never allowed.
    """
    for rule in policy.rules:
        if rule.tool != action.tool:
            continue
        if matches(rule.when, action.args):
            return Decision(
                request_id=action.request_id,
                outcome=rule.outcome,
                reason_code=_reason_code(rule),
                matched_rule=rule.id,
            )
    return Decision(
        request_id=action.request_id,
        outcome=policy.default,
        reason_code=NO_RULE_MATCHED,
        matched_rule=None,
    )
