"""Hash chain, signatures, and tamper detection.

Acceptance criteria 4, 5 and 6: append() produces a valid chain, verify()
returns INTACT on an untampered one, and a content edit, a bad signature and a
broken prev_hash are each detected independently with the correct seq.

Every assertion here compares the whole VerifyResult, never just `ok`. A test
that only checks "verification failed" would pass even if the log named the
wrong entry for the wrong reason, which is most of what makes the log useful.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.keys import Keypair, keypair_from_seed, load_or_generate_keypair
from aegis.models import ActionRequest, Decision, LogEntry, VerifyResult
from aegis.provenance import (
    GENESIS_PREV_HASH,
    ProvenanceLog,
    TamperMode,
    _signature_ok,
    append,
    compute_entry_hash,
    entry_body,
    sign_entry_hash,
    tamper,
    verify,
)

SEED_A = bytes(range(32))
SEED_B = bytes(range(32, 64))
FIXED_TS = datetime(2026, 8, 2, 14, 0, 0, tzinfo=UTC)


@pytest.fixture
def keypair() -> Keypair:
    return keypair_from_seed(SEED_A)


def make_request(n: int) -> ActionRequest:
    return ActionRequest(
        request_id=f"req-{n}",
        principal="alice@corp",
        agent="inbox-assistant",
        tool="make_payment",
        args={"amount_eur": n, "iban": "DE89370400440532013000", "memo": f"#{n}"},
        ts=FIXED_TS,
    )


def make_decision(n: int) -> Decision:
    return Decision(
        request_id=f"req-{n}",
        outcome="ALLOW",
        reason_code="amount_within_limit",
        matched_rule="pay-within-limit",
    )


def build_chain(keypair: Keypair, length: int = 4) -> list[LogEntry]:
    chain: list[LogEntry] = []
    for n in range(length):
        append(make_request(n), make_decision(n), keypair, chain, ts=FIXED_TS)
    return chain


# -- the chain itself -----------------------------------------------------------


def test_genesis_prev_hash_is_empty(keypair: Keypair) -> None:
    chain = build_chain(keypair, 1)
    assert chain[0].prev_hash == GENESIS_PREV_HASH


def test_seq_is_contiguous_from_zero(keypair: Keypair) -> None:
    chain = build_chain(keypair, 5)
    assert [e.seq for e in chain] == [0, 1, 2, 3, 4]


def test_each_entry_links_to_its_predecessor(keypair: Keypair) -> None:
    chain = build_chain(keypair)
    for i in range(1, len(chain)):
        assert chain[i].prev_hash == chain[i - 1].entry_hash


def test_hash_and_signature_are_the_documented_lengths(keypair: Keypair) -> None:
    entry = build_chain(keypair, 1)[0]
    assert len(entry.entry_hash) == 64
    assert len(entry.signature) == 128
    bytes.fromhex(entry.entry_hash)
    bytes.fromhex(entry.signature)


def test_entry_body_excludes_exactly_hash_and_signature(keypair: Keypair) -> None:
    """If entry_hash were inside its own preimage the hash could never be
    computed; if signature were, no entry could ever verify."""
    entry = build_chain(keypair, 1)[0]
    body = entry_body(entry)
    assert set(body) == {"seq", "ts", "request", "decision", "prev_hash"}


# -- INTACT ---------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 4])
def test_untampered_chain_is_intact(keypair: Keypair, length: int) -> None:
    chain = build_chain(keypair, length)
    assert verify(chain, keypair.public) == VerifyResult(
        ok=True, count=length, broken_at=None, why=None
    )


# -- the three tamper modes, each detected independently ------------------------
#
# Each test asserts that the OTHER two checks still pass at the tampered index
# before calling verify(). That is what makes the reported reason the real
# diagnosis rather than an artefact of the order verify() runs its checks in.


def link_ok(chain: list[LogEntry], i: int) -> bool:
    expected = chain[i - 1].entry_hash if i else GENESIS_PREV_HASH
    return chain[i].prev_hash == expected


def content_ok(chain: list[LogEntry], i: int) -> bool:
    return compute_entry_hash(chain[i]) == chain[i].entry_hash


def signature_ok(chain: list[LogEntry], i: int, keypair: Keypair) -> bool:
    return _signature_ok(keypair.public, chain[i].entry_hash, chain[i].signature)


def test_content_edit_is_content_altered(keypair: Keypair) -> None:
    chain = build_chain(keypair)
    chain[1] = tamper(chain[1], "content", keypair)

    assert link_ok(chain, 1), "the link must still be intact, or the reason is ambiguous"
    assert signature_ok(chain, 1, keypair), "the signature must still verify"
    assert not content_ok(chain, 1)

    assert verify(chain, keypair.public) == VerifyResult(
        ok=False, count=4, broken_at=1, why="content_altered"
    )


def test_bad_signature_is_bad_signature(keypair: Keypair) -> None:
    chain = build_chain(keypair)
    chain[2] = tamper(chain[2], "signature", keypair)

    assert link_ok(chain, 2), "the link must still be intact"
    assert content_ok(chain, 2), "the content must still hash correctly"
    assert not signature_ok(chain, 2, keypair)

    assert verify(chain, keypair.public) == VerifyResult(
        ok=False, count=4, broken_at=2, why="bad_signature"
    )


def test_broken_prev_hash_is_chain_link(keypair: Keypair) -> None:
    chain = build_chain(keypair)
    chain[3] = tamper(chain[3], "link", keypair)

    assert content_ok(chain, 3), "the entry must be re-hashed, or two checks fire"
    assert signature_ok(chain, 3, keypair), "the entry must be re-signed"
    assert not link_ok(chain, 3)

    assert verify(chain, keypair.public) == VerifyResult(
        ok=False, count=4, broken_at=3, why="chain_link"
    )


@pytest.mark.parametrize("mode", ["content", "signature", "link"])
def test_tamper_breaks_exactly_one_check(keypair: Keypair, mode: TamperMode) -> None:
    """The property the three tests above rely on, stated directly."""
    chain = build_chain(keypair)
    chain[1] = tamper(chain[1], mode, keypair)
    broken = [
        not link_ok(chain, 1),
        not content_ok(chain, 1),
        not signature_ok(chain, 1, keypair),
    ]
    assert sum(broken) == 1, f"{mode} broke {sum(broken)} checks, not 1"


# -- an attacker who holds the signing key --------------------------------------


def test_reseal_is_caught_by_the_next_entry(keypair: Keypair) -> None:
    """Edit entry 1, recompute its hash, re-sign it correctly.

    Entry 1 now passes all three of its own checks. The chain catches it one row
    later, because entry 2's prev_hash still points at the hash entry 1 used to
    have. This is the spec's claim in 5.2, as an executable test.
    """
    chain = build_chain(keypair)
    forged_request = chain[1].request.model_copy(
        update={"args": chain[1].request.args | {"amount_eur": 999_999}}
    )
    resealed = chain[1].model_copy(update={"request": forged_request})
    entry_hash = compute_entry_hash(resealed)
    chain[1] = resealed.model_copy(
        update={
            "entry_hash": entry_hash,
            "signature": sign_entry_hash(keypair, entry_hash),
        }
    )

    assert link_ok(chain, 1)
    assert content_ok(chain, 1)
    assert signature_ok(chain, 1, keypair)

    assert verify(chain, keypair.public) == VerifyResult(
        ok=False, count=4, broken_at=2, why="chain_link"
    )


# -- other ways to attack the chain ---------------------------------------------


def test_deleting_a_middle_entry_is_chain_link(keypair: Keypair) -> None:
    chain = build_chain(keypair)
    del chain[1]
    assert verify(chain, keypair.public) == VerifyResult(
        ok=False, count=3, broken_at=1, why="chain_link"
    )


def test_reordering_entries_is_chain_link(keypair: Keypair) -> None:
    chain = build_chain(keypair)
    chain[1], chain[2] = chain[2], chain[1]
    assert verify(chain, keypair.public) == VerifyResult(
        ok=False, count=4, broken_at=1, why="chain_link"
    )


def test_non_hex_signature_is_bad_signature_not_a_crash(keypair: Keypair) -> None:
    chain = build_chain(keypair)
    chain[0] = chain[0].model_copy(update={"signature": "not hex at all"})
    assert verify(chain, keypair.public) == VerifyResult(
        ok=False, count=4, broken_at=0, why="bad_signature"
    )


def test_wrong_public_key_fails_at_the_first_entry(keypair: Keypair) -> None:
    chain = build_chain(keypair)
    other = keypair_from_seed(SEED_B)
    assert verify(chain, other.public) == VerifyResult(
        ok=False, count=4, broken_at=0, why="bad_signature"
    )


# -- identity -------------------------------------------------------------------


def test_same_seed_yields_identical_signatures() -> None:
    """Ed25519 is deterministic, which is what makes AEGIS_SIGNING_SEED enough
    to survive a restart."""
    a = build_chain(keypair_from_seed(SEED_A))
    b = build_chain(keypair_from_seed(SEED_A))
    assert [e.signature for e in a] == [e.signature for e in b]
    assert [e.entry_hash for e in a] == [e.entry_hash for e in b]


def test_different_seeds_yield_different_identities() -> None:
    assert keypair_from_seed(SEED_A).public_hex != keypair_from_seed(SEED_B).public_hex


def test_seed_must_be_32_bytes() -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        keypair_from_seed(b"too short")


def test_seed_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_SIGNING_SEED", SEED_A.hex())
    assert load_or_generate_keypair().public_hex == keypair_from_seed(SEED_A).public_hex


def test_malformed_seed_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_SIGNING_SEED", "nonsense")
    with pytest.raises(ValueError, match="hex characters"):
        load_or_generate_keypair()


def test_generated_identity_is_random(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AEGIS_SIGNING_SEED", raising=False)
    assert load_or_generate_keypair().public_hex != load_or_generate_keypair().public_hex


# -- ProvenanceLog: persistence and concurrency ---------------------------------


async def test_record_persists_and_survives_a_restart(
    keypair: Keypair, tmp_path: Path
) -> None:
    """The restart beat: a chain written by one process verifies in the next,
    provided the identity is pinned by the seed."""
    path = tmp_path / "chain.jsonl"
    log = ProvenanceLog(keypair, path)
    for n in range(3):
        await log.record(make_request(n), make_decision(n))

    reloaded = ProvenanceLog(keypair_from_seed(SEED_A), path)
    reloaded.load()

    assert reloaded.entries == log.entries
    assert reloaded.verify() == VerifyResult(ok=True, count=3, broken_at=None, why=None)


async def test_loading_a_missing_file_is_not_an_error(
    keypair: Keypair, tmp_path: Path
) -> None:
    log = ProvenanceLog(keypair, tmp_path / "absent.jsonl")
    log.load()
    assert log.entries == ()


async def test_concurrent_records_keep_seq_contiguous(
    keypair: Keypair, tmp_path: Path
) -> None:
    """Without the lock, append() reads len(chain) and then writes, so
    concurrent callers mint duplicate seqs and split the chain."""
    log = ProvenanceLog(keypair, tmp_path / "chain.jsonl")
    await asyncio.gather(
        *(log.record(make_request(n), make_decision(n)) for n in range(50))
    )

    assert [e.seq for e in log.entries] == list(range(50))
    assert log.verify() == VerifyResult(ok=True, count=50, broken_at=None, why=None)


async def test_tamper_at_reports_the_right_seq_and_reason(
    keypair: Keypair, tmp_path: Path
) -> None:
    log = ProvenanceLog(keypair, tmp_path / "chain.jsonl")
    for n in range(4):
        await log.record(make_request(n), make_decision(n))

    log.tamper_at(2, "content")
    assert log.verify() == VerifyResult(
        ok=False, count=4, broken_at=2, why="content_altered"
    )


async def test_tamper_is_not_written_to_disk(keypair: Keypair, tmp_path: Path) -> None:
    """The file stays honest, so a restart restores integrity."""
    path = tmp_path / "chain.jsonl"
    log = ProvenanceLog(keypair, path)
    for n in range(3):
        await log.record(make_request(n), make_decision(n))
    log.tamper_at(1, "content")
    assert not log.verify().ok

    reloaded = ProvenanceLog(keypair, path)
    reloaded.load()
    assert reloaded.verify().ok


async def test_tamper_at_rejects_an_unknown_seq(keypair: Keypair) -> None:
    log = ProvenanceLog(keypair)
    with pytest.raises(IndexError, match="no entry at seq"):
        log.tamper_at(0, "content")
