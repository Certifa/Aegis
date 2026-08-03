"""FastAPI surface for Aegis.

Route paths and response shapes were fixed in Phase 1 so the console could be
built against them before the engine existed, and that promise held: the data
source moved from a mock fixture to the real hash-chained log without changing a
single response model. Every version bump since has added endpoints only, so
nothing built against 1.0.0 has ever needed touching.

Spec: aegis-build-spec.pdf section 7.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, cast

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from aegis.demo import (
    BENIGN_SCRIPT,
    INJECTED_SCRIPT,
    OVERREACH_SCRIPT,
    ScriptedStep,
    replay,
)
from aegis.explainer import explain
from aegis.interceptor import Interceptor
from aegis.keys import load_or_generate_keypair
from aegis.models import (
    CONTRACT_VERSION,
    ActionRequest,
    ActResponse,
    LogEntry,
    VerifyResult,
)
from aegis.policy import load_policy
from aegis.provenance import ProvenanceLog, TamperMode

_REPO_ROOT = Path(__file__).resolve().parent.parent
_POLICY_PATH = _REPO_ROOT / "aegis" / "policies" / "inbox-assistant.yaml"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Load the policy and the signing identity once, at startup.

    Nothing here happens per-request: evaluate() must never read a file, and a
    policy that could change under a running process would make the log's
    reason codes unreproducible.
    """
    demo_mode = os.getenv("AEGIS_DEMO_MODE") == "1"
    policy = load_policy(_POLICY_PATH)
    # Read once, here, alongside the policy the engine will actually use, so the
    # two cannot drift. See get_policy() for why that matters.
    policy_yaml = _POLICY_PATH.read_text(encoding="utf-8")
    keypair = load_or_generate_keypair(demo_mode=demo_mode)
    log = ProvenanceLog(keypair, Path(os.getenv("AEGIS_LOG_PATH", "aegis-log.jsonl")))
    log.load()  # a chain written before a restart is still ours

    app.state.policy = policy
    app.state.policy_yaml = policy_yaml
    app.state.log = log
    app.state.interceptor = Interceptor(policy, log)
    app.state.demo_mode = demo_mode
    yield


app = FastAPI(title="Aegis", version=CONTRACT_VERSION, lifespan=lifespan)

# The console is developed on its own dev server before it is served from
# templates/. Opt-in via env so a permissive origin policy can never ship.
if os.getenv("AEGIS_DEV_CORS") == "1":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

_STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@app.get("/")
def read_root() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")


# app.state is untyped, so each accessor casts once, here, rather than every
# route doing it inline.
def _log(request: Request) -> ProvenanceLog:
    return cast(ProvenanceLog, request.app.state.log)


def _interceptor(request: Request) -> Interceptor:
    return cast(Interceptor, request.app.state.interceptor)


def _demo_mode(request: Request) -> bool:
    return cast(bool, request.app.state.demo_mode)


def _policy_yaml(request: Request) -> str:
    return cast(str, request.app.state.policy_yaml)


LogDep = Annotated[ProvenanceLog, Depends(_log)]
InterceptorDep = Annotated[Interceptor, Depends(_interceptor)]
DemoModeDep = Annotated[bool, Depends(_demo_mode)]
PolicyYamlDep = Annotated[str, Depends(_policy_yaml)]


class TamperCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq: int
    mode: TamperMode


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/contract")
def contract() -> dict[str, str]:
    """Lets the console detect a contract change instead of discovering it
    visually. Bumped whenever models.py changes shape."""
    return {"version": CONTRACT_VERSION}


@app.get("/policy")
def get_policy(policy_yaml: PolicyYamlDep) -> dict[str, str]:
    """The policy text as loaded at startup: the one actually being enforced.

    Deliberately NOT a fresh read from disk. evaluate() uses the Policy parsed
    once in the lifespan handler, so re-reading the file here would let the
    console display a rule that is not in force. Editing the YAML on a running
    server made /policy report a EUR 100000 ceiling while the engine kept
    refusing at EUR 50, which for a policy viewer is the one bug that undoes
    the point of having one.
    """
    return {"policy_yaml": policy_yaml}


@app.get("/pubkey")
def get_pubkey(log: LogDep) -> dict[str, str]:
    """The Ed25519 public key, as hex.

    Without this the signatures are unverifiable by anyone but this process,
    which makes "cryptographically signed" a claim rather than a property.
    Publishing it is what lets a third party check the chain with verify_chain.py
    and no Aegis code at all.
    """
    return {"public_key": log.public_key_hex, "algorithm": "ed25519"}


@app.get("/log")
def get_log(log: LogDep) -> list[LogEntry]:
    """Full chain, newest first (spec section 7).

    Storage and verification are always oldest-first; the reversal here is
    presentation only, because the console renders a newest-at-top stream.
    """
    return list(reversed(log.entries))


@app.get("/log/verify")
def get_log_verify(log: LogDep) -> VerifyResult:
    return log.verify()


@app.get("/receipt/{seq}")
def get_receipt(seq: int, log: LogDep) -> dict[str, object]:
    """Human-readable prose for one entry.

    Computed on demand and never stored: the receipt is not part of the hashed
    entry, so an explainer can never influence — or invalidate — a decision.
    """
    entries = log.entries
    if not 0 <= seq < len(entries):
        raise HTTPException(status_code=404, detail=f"no entry at seq {seq}")
    return {"seq": seq, "text": explain(entries[seq])}


@app.post("/act")
async def act(action: ActionRequest, interceptor: InterceptorDep) -> ActResponse:
    """Evaluate and log one action.

    The decision is made by evaluate(), which is deterministic code. No model
    is consulted anywhere between this request and its outcome.
    """
    interception = await interceptor.attempt(
        action.tool,
        action.args,
        principal=action.principal,
        agent=action.agent,
    )
    return ActResponse(decision=interception.decision, seq=interception.entry.seq)


async def _run_script(
    script: tuple[ScriptedStep, ...], interceptor: Interceptor
) -> list[ActResponse]:
    return [
        ActResponse(decision=i.decision, seq=i.entry.seq)
        for i in await replay(script, interceptor)
    ]


@app.post("/demo/benign")
async def demo_benign(interceptor: InterceptorDep) -> list[ActResponse]:
    return await _run_script(BENIGN_SCRIPT, interceptor)


@app.post("/demo/injected")
async def demo_injected(interceptor: InterceptorDep) -> list[ActResponse]:
    return await _run_script(INJECTED_SCRIPT, interceptor)


@app.post("/demo/overreach")
async def demo_overreach(interceptor: InterceptorDep) -> list[ActResponse]:
    """An uncompromised agent, refused anyway.

    No injection anywhere in this path — the agent is asked to pay an invoice
    and does exactly that. It is blocked because it holds more payment authority
    than it should, which is the failure mode that does not require anyone to be
    fooled.
    """
    return await _run_script(OVERREACH_SCRIPT, interceptor)


@app.post("/debug/tamper")
def debug_tamper(
    command: TamperCommand, log: LogDep, demo_mode: DemoModeDep
) -> dict[str, bool]:
    """Corrupt one past entry so detection can be demonstrated live.

    DEMO ONLY. This is an attack on our own audit log and exists solely to
    prove the attack is caught. 404 rather than 403 when disabled: an endpoint
    that is switched off should not confirm that it exists.
    """
    if not demo_mode:
        raise HTTPException(status_code=404, detail="Not Found")
    try:
        log.tamper_at(command.seq, command.mode)
    except IndexError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"ok": True}
