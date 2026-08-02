"""FastAPI surface for Aegis.

Route paths and response shapes were fixed in Phase 1 so the console could be
built against them before the engine existed. Phase 4 swaps the data source
from a mock fixture to the real hash-chained log without changing a single
response model — CONTRACT_VERSION is still 1.0.0.

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

from aegis.demo import BENIGN_SCRIPT, INJECTED_SCRIPT, ScriptedStep, replay
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
    keypair = load_or_generate_keypair(demo_mode=demo_mode)
    log = ProvenanceLog(keypair, Path(os.getenv("AEGIS_LOG_PATH", "aegis-log.jsonl")))
    log.load()  # a chain written before a restart is still ours

    app.state.policy = policy
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


LogDep = Annotated[ProvenanceLog, Depends(_log)]
InterceptorDep = Annotated[Interceptor, Depends(_interceptor)]
DemoModeDep = Annotated[bool, Depends(_demo_mode)]


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
