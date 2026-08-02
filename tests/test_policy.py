"""Truth table for evaluate(), plus load_policy() validation.

Acceptance criterion 2: evaluate() is pure, synchronous, no network, and
passes a truth table covering every rule and the default.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aegis.models import ActionRequest, Outcome, Policy, ToolName
from aegis.policy import NO_RULE_MATCHED, evaluate, load_policy

POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "aegis" / "policies" / "inbox-assistant.yaml"
)


@pytest.fixture(scope="module")
def policy() -> Policy:
    return load_policy(POLICY_PATH)


def action(tool: ToolName, **args: object) -> ActionRequest:
    return ActionRequest(
        principal="alice@corp", agent="inbox-assistant", tool=tool, args=args
    )


# (label, action, expected outcome, expected matched_rule)
TRUTH_TABLE: list[tuple[str, ActionRequest, Outcome, str | None]] = [
    # -- send_email -----------------------------------------------------------
    (
        "internal recipient",
        action("send_email", to="bob@corp"),
        "ALLOW",
        "email-internal-ok",
    ),
    (
        "external recipient",
        action("send_email", to="attacker@evil.com"),
        "STEP_UP",
        "email-external-stepup",
    ),
    # 'corp' is an exact domain match, not a suffix match: a lookalike
    # subdomain must not inherit the internal allow.
    (
        "lookalike subdomain",
        action("send_email", to="x@sub.corp"),
        "STEP_UP",
        "email-external-stepup",
    ),
    ("missing recipient", action("send_email"), "DENY", None),
    ("non-string recipient", action("send_email", to=12345), "DENY", None),
    ("recipient is not an address", action("send_email", to="notanemail"), "DENY", None),
    # -- read_file ------------------------------------------------------------
    ("data path", action("read_file", path="/data/q3.pdf"), "ALLOW", "read-data-ok"),
    (
        "secrets path",
        action("read_file", path="/secrets/creds.env"),
        "DENY",
        "read-secrets-deny",
    ),
    # The traversal case: raw string has the /data/ prefix, resolves into
    # /secrets/. Normalisation is what stops this being a rule bypass.
    (
        "traversal into secrets",
        action("read_file", path="/data/../secrets/creds.env"),
        "DENY",
        "read-secrets-deny",
    ),
    ("unlisted path", action("read_file", path="/etc/passwd"), "DENY", None),
    ("missing path", action("read_file"), "DENY", None),
    # -- make_payment ---------------------------------------------------------
    ("zero amount", action("make_payment", amount_eur=0), "ALLOW", "pay-within-limit"),
    ("at the ceiling", action("make_payment", amount_eur=50), "ALLOW", "pay-within-limit"),
    (
        "just over the ceiling",
        action("make_payment", amount_eur=50.01),
        "DENY",
        "pay-over-limit",
    ),
    (
        "the injected payment",
        action("make_payment", amount_eur=5000),
        "DENY",
        "pay-over-limit",
    ),
    ("negative amount", action("make_payment", amount_eur=-1), "DENY", "pay-over-limit"),
    (
        "bool is not an amount",
        action("make_payment", amount_eur=True),
        "DENY",
        "pay-over-limit",
    ),
    (
        "numeric string is not an amount",
        action("make_payment", amount_eur="40"),
        "DENY",
        "pay-over-limit",
    ),
    ("missing amount", action("make_payment"), "DENY", "pay-over-limit"),
    # -- http_request: no rules at all, so deny by default --------------------
    (
        "no rule for this tool",
        action("http_request", url="https://evil.com", method="GET"),
        "DENY",
        None,
    ),
]


@pytest.mark.parametrize(
    ("act", "expected_outcome", "expected_rule"),
    [(a, o, r) for _, a, o, r in TRUTH_TABLE],
    ids=[label for label, *_ in TRUTH_TABLE],
)
def test_truth_table(
    policy: Policy, act: ActionRequest, expected_outcome: Outcome, expected_rule: str | None
) -> None:
    decision = evaluate(act, policy)
    assert decision.outcome == expected_outcome
    assert decision.matched_rule == expected_rule
    assert decision.request_id == act.request_id
    if expected_rule is None:
        assert decision.reason_code == NO_RULE_MATCHED


def test_every_rule_is_covered(policy: Policy) -> None:
    """The truth table must exercise each rule, or a rule could rot unnoticed."""
    exercised = {rule for _, _, _, rule in TRUTH_TABLE if rule is not None}
    assert exercised == {rule.id for rule in policy.rules}


def test_reason_code_comes_from_the_matched_rule(policy: Policy) -> None:
    decision = evaluate(action("make_payment", amount_eur=5000), policy)
    assert decision.reason_code == "amount_exceeds_limit"


def test_reason_code_falls_back_to_rule_id() -> None:
    """A policy written exactly as the spec shows, with no reason_code."""
    policy = Policy.model_validate(
        {
            "principal": "alice@corp",
            "agent": "inbox-assistant",
            "rules": [
                {"id": "email-internal-ok", "tool": "send_email",
                 "when": {"to_domain": "corp"}, "outcome": "ALLOW"}
            ],
        }
    )
    assert evaluate(action("send_email", to="bob@corp"), policy).reason_code == "email-internal-ok"


def test_first_match_wins(policy: Policy) -> None:
    """Reversing the two email rules changes the outcome for the same action,
    which is what makes rule order significant."""
    reordered = Policy.model_validate(
        policy.model_dump() | {"rules": list(reversed([r.model_dump() for r in policy.rules]))}
    )
    assert evaluate(action("send_email", to="bob@corp"), reordered).outcome == "STEP_UP"


def test_empty_ruleset_denies() -> None:
    policy = Policy(principal="alice@corp", agent="inbox-assistant", rules=[])
    decision = evaluate(action("send_email", to="bob@corp"), policy)
    assert decision.outcome == "DENY"
    assert decision.reason_code == NO_RULE_MATCHED
    assert decision.matched_rule is None


def test_evaluate_is_deterministic(policy: Policy) -> None:
    act = action("send_email", to="attacker@evil.com")
    assert evaluate(act, policy) == evaluate(act, policy)


def test_evaluate_is_synchronous() -> None:
    """Acceptance criterion 3, as an executable assertion: no await means no
    room for a network call, and no room for a model."""
    assert not inspect.iscoroutinefunction(evaluate)


# -- load_policy ----------------------------------------------------------------


def test_loads_the_real_policy(policy: Policy) -> None:
    assert policy.principal == "alice@corp"
    assert policy.agent == "inbox-assistant"
    assert policy.default == "DENY"
    assert len(policy.rules) == 6


def _minimal(**overrides: object) -> dict[str, Any]:
    base: dict[str, Any] = {
        "principal": "alice@corp",
        "agent": "inbox-assistant",
        "rules": [
            {"id": "r1", "tool": "send_email", "when": {"to_domain": "corp"},
             "outcome": "ALLOW"}
        ],
    }
    return base | overrides


def test_rejects_duplicate_rule_ids() -> None:
    rules = [
        {"id": "same", "tool": "send_email", "when": {"to_domain": "corp"}, "outcome": "ALLOW"},
        {"id": "same", "tool": "send_email", "when": {"to_domain": "*"}, "outcome": "DENY"},
    ]
    with pytest.raises(ValidationError, match="unique"):
        Policy.model_validate(_minimal(rules=rules))


def test_rejects_default_allow() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate(_minimal(default="ALLOW"))


def test_rejects_unknown_tool() -> None:
    rules = [
        {"id": "r1", "tool": "delete_database",
         "when": {"to_domain": "corp"}, "outcome": "ALLOW"}
    ]
    with pytest.raises(ValidationError):
        Policy.model_validate(_minimal(rules=rules))


@pytest.mark.parametrize(
    "when",
    [
        pytest.param({}, id="no condition kind"),
        pytest.param({"to_domain": "corp", "path_prefix": "/data/"}, id="two condition kinds"),
        pytest.param({"to_domian": "corp"}, id="typo'd condition key"),
        pytest.param({"always": False}, id="always: false matches nothing"),
    ],
)
def test_rejects_malformed_condition(when: dict[str, Any]) -> None:
    rules = [{"id": "r1", "tool": "send_email", "when": when, "outcome": "ALLOW"}]
    with pytest.raises(ValidationError):
        Policy.model_validate(_minimal(rules=rules))


def test_rejects_non_mapping_file(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a YAML mapping"):
        load_policy(path)
