"""The two scenarios, end to end.

Acceptance criterion 7: the benign scenario yields exactly one ALLOW entry, and
the injected scenario yields two blocks. Acceptance criterion 10: the injection
scenario is covered as an integration test.

These run the deterministic scripts through the real interceptor, real policy
engine, and real provenance log. Only the agent's *intent* is scripted —
replacing the model must not replace the boundary, or the test proves nothing.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from aegis.demo import BENIGN_SCRIPT, INJECTED_SCRIPT, replay
from aegis.interceptor import Interceptor
from aegis.keys import keypair_from_seed
from aegis.models import Policy, ToolName, VerifyResult
from aegis.policy import load_policy
from aegis.provenance import ProvenanceLog
from aegis.tools import TOOLS, ToolResult

SEED = bytes(range(32))
POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "aegis" / "policies" / "inbox-assistant.yaml"
)


@pytest.fixture(scope="module")
def policy() -> Policy:
    return load_policy(POLICY_PATH)


@pytest.fixture
def log() -> ProvenanceLog:
    return ProvenanceLog(keypair_from_seed(SEED))


@pytest.fixture
def interceptor(policy: Policy, log: ProvenanceLog) -> Interceptor:
    return Interceptor(policy, log)


# -- benign ---------------------------------------------------------------------


async def test_benign_scenario_yields_exactly_one_allow(
    interceptor: Interceptor, log: ProvenanceLog
) -> None:
    interceptions = await replay(BENIGN_SCRIPT, interceptor)

    assert len(interceptions) == 1
    only = interceptions[0]
    assert only.decision.outcome == "ALLOW"
    assert only.decision.reason_code == "internal_recipient_ok"
    assert only.decision.matched_rule == "email-internal-ok"
    assert only.result is not None and only.result.ok

    assert len(log.entries) == 1
    assert log.verify() == VerifyResult(ok=True, count=1, broken_at=None, why=None)


# -- injected -------------------------------------------------------------------


async def test_injected_scenario_blocks_both_attacks(
    interceptor: Interceptor, log: ProvenanceLog
) -> None:
    read, exfiltrate, pay = await replay(INJECTED_SCRIPT, interceptor)

    # Reading the document is legitimate. The injection arrives in its content.
    assert read.decision.outcome == "ALLOW"
    assert read.result is not None
    assert "ignore previous instructions" in read.result.detail

    assert exfiltrate.decision.outcome == "STEP_UP"
    assert exfiltrate.decision.reason_code == "external_recipient_stepup"
    assert exfiltrate.decision.matched_rule == "email-external-stepup"

    assert pay.decision.outcome == "DENY"
    assert pay.decision.reason_code == "amount_exceeds_limit"
    assert pay.decision.matched_rule == "pay-over-limit"

    assert len(log.entries) == 3
    assert log.verify() == VerifyResult(ok=True, count=3, broken_at=None, why=None)


async def test_neither_attack_actually_executed(
    interceptor: Interceptor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the whole project: the model was fooled and nothing
    happened."""
    executed: list[ToolName] = []

    def wrap(name: ToolName) -> Callable[[Mapping[str, Any]], ToolResult]:
        real = TOOLS[name]

        def call(args: Mapping[str, Any]) -> ToolResult:
            executed.append(name)
            return real(args)

        return call

    monkeypatch.setattr("aegis.interceptor.TOOLS", {n: wrap(n) for n in TOOLS})

    await replay(INJECTED_SCRIPT, interceptor)

    assert executed == ["read_file"]
    assert "send_email" not in executed
    assert "make_payment" not in executed


async def test_the_injected_run_is_deterministic(
    policy: Policy,
) -> None:
    """The scripted path must produce the same decisions every time, or it is
    not a fallback."""

    async def run() -> list[tuple[str, str, str | None]]:
        log = ProvenanceLog(keypair_from_seed(SEED))
        interceptions = await replay(INJECTED_SCRIPT, Interceptor(policy, log))
        return [
            (i.decision.outcome, i.decision.reason_code, i.decision.matched_rule)
            for i in interceptions
        ]

    assert await run() == await run()


# -- the climax -----------------------------------------------------------------


async def test_tampering_with_a_past_entry_is_caught(
    interceptor: Interceptor, log: ProvenanceLog
) -> None:
    """The demo's closing beat: edit a past record, re-run verify()."""
    await replay(INJECTED_SCRIPT, interceptor)
    assert log.verify().ok

    log.tamper_at(2, "content")

    assert log.verify() == VerifyResult(
        ok=False, count=3, broken_at=2, why="content_altered"
    )


async def test_the_chain_survives_a_restart(
    policy: Policy, tmp_path: Path
) -> None:
    """A chain written by one process verifies in the next, because the
    identity is pinned by the seed rather than minted per boot."""
    path = tmp_path / "chain.jsonl"
    first = ProvenanceLog(keypair_from_seed(SEED), path)
    await replay(INJECTED_SCRIPT, Interceptor(policy, first))

    second = ProvenanceLog(keypair_from_seed(SEED), path)
    second.load()

    assert second.entries == first.entries
    assert second.verify() == VerifyResult(ok=True, count=3, broken_at=None, why=None)
