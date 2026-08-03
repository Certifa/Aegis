"""The independent verifier must agree with the implementation.

verify_chain.py deliberately shares no code with Aegis: it restates the
canonical-JSON rule and re-derives every hash from the published entry alone.
That independence is only worth something if the two actually agree, and only
stays worth something if a drift in either one breaks a test.

So these run the real script as a subprocess against a real chain, rather than
importing its functions, which is also how a third party would use it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from aegis.demo import BENIGN_SCRIPT, INJECTED_SCRIPT, OVERREACH_SCRIPT, replay
from aegis.interceptor import Interceptor
from aegis.keys import keypair_from_seed
from aegis.policy import load_policy
from aegis.provenance import ProvenanceLog

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "verify_chain.py"
POLICY = REPO / "aegis" / "policies" / "inbox-assistant.yaml"
SEED = bytes(range(32))


@pytest.fixture
async def chain(tmp_path: Path) -> tuple[Path, str]:
    """A real chain on disk, plus the public key that signed it."""
    keypair = keypair_from_seed(SEED)
    path = tmp_path / "chain.jsonl"
    log = ProvenanceLog(keypair, path)
    interceptor = Interceptor(load_policy(POLICY), log)
    for script in (BENIGN_SCRIPT, INJECTED_SCRIPT, OVERREACH_SCRIPT):
        await replay(script, interceptor)
    assert log.verify().ok, "fixture chain should start intact"
    return path, keypair.public_hex


def run(path: Path, pubkey: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path), pubkey],
        capture_output=True, text=True, check=False,
    )


Mutation = Callable[[list[dict[str, Any]]], object]


def rewrite(path: Path, mutate: Mutation) -> Path:
    entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    mutate(entries)
    out = path.parent / "tampered.jsonl"
    out.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    return out


async def test_agrees_with_the_implementation_on_an_intact_chain(
    chain: tuple[Path, str],
) -> None:
    path, pubkey = chain
    result = run(path, pubkey)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "INTACT" in result.stdout


async def test_rejects_the_wrong_public_key(chain: tuple[Path, str]) -> None:
    path, _ = chain
    result = run(path, "11" * 32)
    assert result.returncode == 1
    assert "bad_signature" in result.stdout


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        pytest.param(
            lambda es: es[2]["request"]["args"].__setitem__("amount_eur", 999_999),
            "content_altered",
            id="content edit",
        ),
        pytest.param(
            lambda es: es[2].__setitem__("signature", "f" + es[2]["signature"][1:]),
            "bad_signature",
            id="forged signature",
        ),
        pytest.param(
            lambda es: es[2].__setitem__("prev_hash", "0" * 64),
            "chain_link",
            id="broken link",
        ),
        pytest.param(lambda es: es.pop(2), "not contiguous", id="deleted entry"),
    ],
)
async def test_detects_tampering_without_any_aegis_code(
    chain: tuple[Path, str], mutation: Mutation, expected: str
) -> None:
    """Each break is caught and named from the published data alone."""
    path, pubkey = chain
    result = run(rewrite(path, mutation), pubkey)

    assert result.returncode == 1, result.stdout
    assert "BROKEN" in result.stdout
    assert expected in result.stdout


async def test_the_verifier_imports_nothing_from_aegis() -> None:
    """The claim this whole file rests on. If someone imports a helper from the
    package to save a few lines, the verification stops being independent and
    starts being a tautology."""
    source = SCRIPT.read_text()
    assert "import aegis" not in source
    assert "from aegis" not in source
