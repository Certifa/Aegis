"""The gate. Every tool call the agent attempts passes through attempt().

Order matters and is the whole design:

    build request -> evaluate (pure) -> LOG -> execute only if ALLOW

Logging happens BEFORE execution. If it happened after, a crash in between
would leave a real side effect with no record of it — and a log that can miss
the one action that mattered is not an audit log.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aegis.models import ActionRequest, Decision, LogEntry, Policy, ToolName
from aegis.policy import evaluate
from aegis.provenance import ProvenanceLog
from aegis.tools import TOOLS, ToolResult


@dataclass(frozen=True)
class Interception:
    request: ActionRequest
    decision: Decision
    entry: LogEntry
    result: ToolResult | None  # None whenever the action was not executed


class Interceptor:
    def __init__(self, policy: Policy, log: ProvenanceLog) -> None:
        self._policy = policy
        self._log = log

    async def attempt(
        self,
        tool: ToolName,
        args: Mapping[str, Any],
        *,
        principal: str | None = None,
        agent: str | None = None,
    ) -> Interception:
        request = ActionRequest(
            principal=principal or self._policy.principal,
            agent=agent or self._policy.agent,
            tool=tool,
            args=dict(args),
        )
        # Deterministic code. No await, no model, nothing that can be talked to.
        decision = evaluate(request, self._policy)
        entry = await self._log.record(request, decision)

        # ALLOW is the only outcome that executes. STEP_UP blocks and records,
        # exactly like DENY, and waits on a human this build has no workflow for
        # yet — so it must not fall through to the tool.
        result = TOOLS[tool](request.args) if decision.outcome == "ALLOW" else None
        return Interception(request=request, decision=decision, entry=entry, result=result)
