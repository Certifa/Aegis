"""Frozen data contracts for Aegis.

Every other module imports these shapes and none redefines them. Changing a
field name or type here silently breaks the console built against it, so treat
this module as a published API: additive changes only, announced before they
land. Spec: aegis-build-spec.pdf section 3.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Literal, Self
from uuid import uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

CONTRACT_VERSION = "1.0.0"

ToolName = Literal["send_email", "read_file", "http_request", "make_payment"]
Outcome = Literal["ALLOW", "DENY", "STEP_UP"]
BreakReason = Literal["chain_link", "content_altered", "bad_signature"]

# frozen: a log entry that can be mutated in place is not evidence. /debug/tamper
# must build a new object via model_copy(), which keeps tampering explicit.
# extra="forbid": a typo'd field is a contract break, and should fail loudly here
# rather than silently evaluate to something harmless later.
_STRICT = ConfigDict(frozen=True, extra="forbid")


class Condition(BaseModel):
    """The `when:` clause of a rule. Exactly one kind per rule."""

    model_config = _STRICT

    to_domain: str | None = None      # exact match on the domain of args['to'], or '*'
    path_prefix: str | None = None    # args['path'] starts with this
    max_eur: Decimal | None = None    # passes if args['amount_eur'] <= this
    # Catch-all for a tool. `always: false` is a rule that matches nothing,
    # which is only ever a mistake, so the type forbids it.
    always: Literal[True] | None = None

    @model_validator(mode="after")
    def _exactly_one_kind(self) -> Self:
        kinds = (self.to_domain, self.path_prefix, self.max_eur, self.always)
        if sum(k is not None for k in kinds) != 1:
            raise ValueError(
                "a rule's `when:` must set exactly one of "
                "to_domain / path_prefix / max_eur / always"
            )
        return self


class Rule(BaseModel):
    model_config = _STRICT

    id: str
    tool: ToolName
    when: Condition
    outcome: Outcome
    # Optional caption for the log. Falls back to the rule id when absent, so
    # policy files written exactly as the spec shows still load unchanged.
    reason_code: str | None = None


class Policy(BaseModel):
    """A deterministic ruleset bound to one (principal, agent) pair."""

    model_config = _STRICT

    principal: str
    agent: str
    rules: list[Rule]
    # Literal['DENY'], not Outcome: deny-by-default is a property of the system,
    # so a policy file that defaults to ALLOW must be unrepresentable.
    default: Literal["DENY"] = "DENY"

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> Self:
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique; matched_rule would be ambiguous")
        return self


class ActionRequest(BaseModel):
    """A single attempted operation. The unit Aegis evaluates."""

    model_config = _STRICT

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    principal: str
    agent: str
    tool: ToolName
    # Deliberately permissive. A malformed action must reach the policy engine and
    # be DENIED AND LOGGED, not rejected at the edge with a 422 that leaves no
    # trace. matches() fails closed on missing or wrong-typed args.
    args: dict[str, Any] = Field(default_factory=dict)
    ts: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))


class Decision(BaseModel):
    """The output of policy evaluation. Contains no prose and no LLM output."""

    model_config = _STRICT

    request_id: str
    outcome: Outcome
    reason_code: str
    matched_rule: str | None


class LogEntry(BaseModel):
    """One immutable record in the chain."""

    model_config = _STRICT

    seq: int
    ts: AwareDatetime
    request: ActionRequest
    decision: Decision
    prev_hash: str      # sha256 hex of entry seq-1; '' at seq 0
    entry_hash: str     # sha256 hex over canonical JSON of all fields except
                        # entry_hash and signature
    signature: str      # ed25519 signature over entry_hash, hex


class VerifyResult(BaseModel):
    """Result of verify() over the whole chain.

    Flat by design: the console should not have to parse a union to render one
    row.
    """

    model_config = _STRICT

    ok: bool
    count: int
    broken_at: int | None = None
    why: BreakReason | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.ok != (self.broken_at is None and self.why is None):
            raise ValueError("ok must be true iff broken_at and why are both unset")
        return self

    @classmethod
    def intact(cls, count: int) -> VerifyResult:
        return cls(ok=True, count=count)

    @classmethod
    def broken(cls, *, at: int, why: BreakReason, count: int) -> VerifyResult:
        return cls(ok=False, count=count, broken_at=at, why=why)


class ActResponse(BaseModel):
    """POST /act — the decision plus where it landed in the chain."""

    model_config = _STRICT

    decision: Decision
    seq: int


__all__ = [
    "CONTRACT_VERSION",
    "ActResponse",
    "ActionRequest",
    "BreakReason",
    "Condition",
    "Decision",
    "LogEntry",
    "Outcome",
    "Policy",
    "Rule",
    "ToolName",
    "VerifyResult",
]
