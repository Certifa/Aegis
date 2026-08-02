"""FastAPI surface for Aegis.

Route paths and response shapes are FINAL from Phase 1 so the console can be
built against them immediately. Only the data *source* changes later: Phase 1
serves a static mock fixture, Phase 3 swaps in the real hash-chained log
without touching a single response model.

Spec: aegis-build-spec.pdf section 7.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis.models import CONTRACT_VERSION, LogEntry, VerifyResult

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MOCK_LOG_PATH = _REPO_ROOT / "tests" / "fixtures" / "mock_log.json"

app = FastAPI(title="Aegis", version=CONTRACT_VERSION)

# The console is developed on its own dev server before it is served from
# templates/. Opt-in via env so a permissive origin policy can never ship.
if os.getenv("AEGIS_DEV_CORS") == "1":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )


@lru_cache(maxsize=1)
def _mock_chain() -> tuple[LogEntry, ...]:
    """Load the mock chain, oldest first.

    PHASE 1 ONLY. entry_hash and signature in the fixture are placeholders, not
    real crypto — see the contract note. Phase 3 regenerates this file with the
    real algorithm; the field shapes do not change.
    """
    raw: Any = json.loads(_MOCK_LOG_PATH.read_text(encoding="utf-8"))
    return tuple(LogEntry.model_validate(entry) for entry in raw)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/contract")
def contract() -> dict[str, str]:
    """Lets the console detect a contract change instead of discovering it
    visually. Bumped whenever models.py changes shape."""
    return {"version": CONTRACT_VERSION}


@app.get("/log")
def get_log() -> list[LogEntry]:
    """Full chain, newest first (spec §7).

    Storage and verification are always oldest-first; the reversal here is
    presentation only, because the console renders a newest-at-top stream.
    """
    return list(reversed(_mock_chain()))


@app.get("/log/verify")
def get_log_verify() -> VerifyResult:
    """Run verify() over the whole chain.

    PHASE 1 ONLY: returns a hardcoded INTACT so the console's verify button is
    wired end to end. The fixture's hashes are placeholders and would not pass
    real verification. Phase 3 replaces this with the actual verify() call.
    """
    return VerifyResult.intact(count=len(_mock_chain()))
