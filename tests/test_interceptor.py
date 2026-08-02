"""The boundary itself.

The most important test in this file is that a blocked tool is never called.
Everything else Aegis does is bookkeeping around that one guarantee.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from aegis.interceptor import Interceptor
from aegis.keys import keypair_from_seed
from aegis.models import Policy, ToolName
from aegis.policy import load_policy
from aegis.provenance import ProvenanceLog
from aegis.tools import ToolResult

SEED = bytes(range(32))
POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "aegis" / "policies" / "inbox-assistant.yaml"
)


@pytest.fixture(scope="module")
def policy() -> Policy:
    return load_policy(POLICY_PATH)


@pytest.fixture
def log() -> ProvenanceLog:
    return ProvenanceLog(keypair_from_seed(SEED))  # no path: nothing touches disk


@pytest.fixture
def interceptor(policy: Policy, log: ProvenanceLog) -> Interceptor:
    return Interceptor(policy, log)


class ToolSpy:
    """Counts calls per tool and stands in for the real stubs."""

    def __init__(self) -> None:
        self.calls: list[tuple[ToolName, Mapping[str, Any]]] = []

    def table(self) -> dict[ToolName, Callable[[Mapping[str, Any]], ToolResult]]:
        def make(tool: ToolName) -> Callable[[Mapping[str, Any]], ToolResult]:
            def call(args: Mapping[str, Any]) -> ToolResult:
                self.calls.append((tool, args))
                return ToolResult(tool, True, "spy")

            return call

        return {
            "send_email": make("send_email"),
            "read_file": make("read_file"),
            "http_request": make("http_request"),
            "make_payment": make("make_payment"),
        }


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> ToolSpy:
    spy = ToolSpy()
    monkeypatch.setattr("aegis.interceptor.TOOLS", spy.table())
    return spy


# -- the guarantee --------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "expected_outcome"),
    [
        pytest.param(
            "send_email",
            {"to": "attacker@evil.com", "subject": "x", "body": "y"},
            "STEP_UP",
            id="STEP_UP does not execute",
        ),
        pytest.param(
            "read_file",
            {"path": "/secrets/creds.env"},
            "DENY",
            id="DENY does not execute",
        ),
        pytest.param(
            "make_payment",
            {"amount_eur": 5000, "iban": "DE89", "memo": "x"},
            "DENY",
            id="over-limit payment does not execute",
        ),
        pytest.param(
            "http_request",
            {"url": "https://evil.com", "method": "GET"},
            "DENY",
            id="unmatched tool does not execute",
        ),
    ],
)
async def test_a_blocked_tool_is_never_called(
    interceptor: Interceptor,
    spy: ToolSpy,
    tool: ToolName,
    args: dict[str, Any],
    expected_outcome: str,
) -> None:
    interception = await interceptor.attempt(tool, args)

    assert interception.decision.outcome == expected_outcome
    assert spy.calls == [], f"{tool} executed despite a {expected_outcome}"
    assert interception.result is None


async def test_allow_executes_exactly_once(
    interceptor: Interceptor, spy: ToolSpy
) -> None:
    interception = await interceptor.attempt(
        "send_email", {"to": "bob@corp", "subject": "Q3", "body": "attached"}
    )

    assert interception.decision.outcome == "ALLOW"
    assert len(spy.calls) == 1
    assert spy.calls[0][0] == "send_email"
    assert interception.result is not None
    assert interception.result.ok


# -- everything is logged, blocked or not ---------------------------------------


async def test_a_blocked_attempt_is_still_logged(
    interceptor: Interceptor, log: ProvenanceLog, spy: ToolSpy
) -> None:
    """An attack that leaves no trace would be the wrong failure mode."""
    await interceptor.attempt("make_payment", {"amount_eur": 5000, "iban": "DE89"})

    assert len(log.entries) == 1
    entry = log.entries[0]
    assert entry.decision.outcome == "DENY"
    assert entry.decision.reason_code == "amount_exceeds_limit"
    assert entry.request.args["amount_eur"] == 5000


async def test_the_entry_is_written_before_the_tool_runs(
    interceptor: Interceptor, log: ProvenanceLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If logging happened after execution, a crash in between would leave a
    real side effect with no record of it."""

    def explode(args: Mapping[str, Any]) -> ToolResult:
        raise RuntimeError("tool blew up mid-send")

    monkeypatch.setattr("aegis.interceptor.TOOLS", {"send_email": explode})

    with pytest.raises(RuntimeError, match="blew up"):
        await interceptor.attempt(
            "send_email", {"to": "bob@corp", "subject": "Q3", "body": "x"}
        )

    assert len(log.entries) == 1
    assert log.entries[0].decision.outcome == "ALLOW"


async def test_each_attempt_appends_one_entry(
    interceptor: Interceptor, log: ProvenanceLog, spy: ToolSpy
) -> None:
    await interceptor.attempt("send_email", {"to": "bob@corp"})
    await interceptor.attempt("send_email", {"to": "attacker@evil.com"})
    await interceptor.attempt("make_payment", {"amount_eur": 5000})

    assert [e.seq for e in log.entries] == [0, 1, 2]
    assert [e.decision.outcome for e in log.entries] == ["ALLOW", "STEP_UP", "DENY"]
    assert log.verify().ok


async def test_principal_and_agent_default_to_the_policy(
    interceptor: Interceptor, policy: Policy, spy: ToolSpy
) -> None:
    interception = await interceptor.attempt("send_email", {"to": "bob@corp"})
    assert interception.request.principal == policy.principal
    assert interception.request.agent == policy.agent


async def test_the_decision_matches_the_request(
    interceptor: Interceptor, spy: ToolSpy
) -> None:
    interception = await interceptor.attempt("send_email", {"to": "bob@corp"})
    assert interception.decision.request_id == interception.request.request_id
    assert interception.entry.request == interception.request
