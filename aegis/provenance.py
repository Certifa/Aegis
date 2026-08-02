"""The tamper-evident provenance log.

append() and verify() are pure and synchronous: they compute hashes and
signatures and touch nothing else. Persistence and concurrency live in
ProvenanceLog, so the crypto can be tested without a filesystem.

Spec: aegis-build-spec.pdf section 5.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis.canonical import canonical_json
from aegis.keys import Keypair
from aegis.models import ActionRequest, Decision, LogEntry, VerifyResult

TamperMode = Literal["content", "signature", "link"]

GENESIS_PREV_HASH = ""


def entry_body(entry: LogEntry) -> dict[str, Any]:
    """The exact fields that are hashed: everything except entry_hash and
    signature.

    Derived from the entry itself rather than from loose arguments, so append()
    and verify() cannot possibly disagree about what was hashed. mode='json'
    renders datetimes as isoformat, per the canonical rule.
    """
    return entry.model_dump(mode="json", exclude={"entry_hash", "signature"})


def compute_entry_hash(entry: LogEntry) -> str:
    return sha256(canonical_json(entry_body(entry))).hexdigest()


def sign_entry_hash(keypair: Keypair, entry_hash: str) -> str:
    """Sign the hex digest string, matching the spec's pseudocode, which passes
    hexdigest() straight to the signer. verify() must encode it identically."""
    return keypair.private.sign(entry_hash.encode("ascii")).hex()


def append(
    request: ActionRequest,
    decision: Decision,
    keypair: Keypair,
    chain: list[LogEntry],
    *,
    ts: datetime | None = None,
) -> LogEntry:
    """Hash, sign, and append one entry. Pure apart from extending `chain`.

    Deliberately does no file I/O: keeping the crypto free of the filesystem is
    what lets the tamper tests run without one. ProvenanceLog persists.
    """
    prev_hash = chain[-1].entry_hash if chain else GENESIS_PREV_HASH
    draft = LogEntry(
        seq=len(chain),
        ts=ts if ts is not None else datetime.now(UTC),
        request=request,
        decision=decision,
        prev_hash=prev_hash,
        entry_hash="",  # placeholders; entry_body excludes both from the hash
        signature="",
    )
    entry_hash = compute_entry_hash(draft)
    entry = draft.model_copy(
        update={
            "entry_hash": entry_hash,
            "signature": sign_entry_hash(keypair, entry_hash),
        }
    )
    chain.append(entry)
    return entry


def _signature_ok(
    public_key: Ed25519PublicKey, entry_hash: str, signature: str
) -> bool:
    try:
        raw = bytes.fromhex(signature)
    except ValueError:
        return False  # not even hex; treat as a bad signature, never as valid
    try:
        public_key.verify(raw, entry_hash.encode("ascii"))
    except InvalidSignature:
        return False
    return True


def verify(chain: Sequence[LogEntry], public_key: Ed25519PublicKey) -> VerifyResult:
    """Walk the chain oldest-first and report the first break, with its index.

    Check order follows the spec: link, then content, then signature. A content
    edit leaves entry_hash untouched, so the links still line up and the break
    is reported at exactly the altered seq rather than cascading to the entry
    after it.
    """
    count = len(chain)
    for i, entry in enumerate(chain):
        expected_prev = chain[i - 1].entry_hash if i else GENESIS_PREV_HASH
        if entry.prev_hash != expected_prev:
            return VerifyResult.broken(at=i, why="chain_link", count=count)
        if compute_entry_hash(entry) != entry.entry_hash:
            return VerifyResult.broken(at=i, why="content_altered", count=count)
        if not _signature_ok(public_key, entry.entry_hash, entry.signature):
            return VerifyResult.broken(at=i, why="bad_signature", count=count)
    return VerifyResult.intact(count)


def tamper(entry: LogEntry, mode: TamperMode, keypair: Keypair) -> LogEntry:
    """Return a corrupted copy of `entry`. DEMO ONLY.

    One mode per detectable failure, and each mode breaks exactly ONE of the
    three checks in verify() — so the reported reason is the real diagnosis and
    not an artefact of the order the checks happen to run in.
    """
    match mode:
        case "content":
            # Edit the payload, leave entry_hash and signature alone. prev_hash
            # is untouched so the link still matches, and the signature still
            # validly signs the stored entry_hash — only the content check can
            # fire.
            forged = entry.request.model_copy(
                update={"args": entry.request.args | {"amount_eur": 999_999}}
            )
            return entry.model_copy(update={"request": forged})
        case "signature":
            # Content and link both still verify; only the signature is wrong.
            flipped = f"{(int(entry.signature[0], 16) ^ 0xF):x}{entry.signature[1:]}"
            return entry.model_copy(update={"signature": flipped})
        case "link":
            # prev_hash is INSIDE the hashed body, so rewriting it naively would
            # break the content hash too, and 'chain_link' would only be
            # reported because that check runs first. Re-hash and re-sign, so
            # the content and signature checks both PASS and a broken link is
            # the only thing verify() can be reacting to.
            #
            # This is also the stronger adversary: someone holding the signing
            # key, who re-sealed the record perfectly, and is caught anyway.
            relinked = entry.model_copy(update={"prev_hash": "0" * 64})
            entry_hash = compute_entry_hash(relinked)
            return relinked.model_copy(
                update={
                    "entry_hash": entry_hash,
                    "signature": sign_entry_hash(keypair, entry_hash),
                }
            )


class ProvenanceLog:
    """In-memory chain, mirrored to an append-only JSONL file.

    The crypto lives in the module-level functions above. This class owns the
    two things they deliberately avoid: I/O and concurrency.
    """

    def __init__(self, keypair: Keypair, path: Path | None = None) -> None:
        self._keypair = keypair
        self._path = path
        self._chain: list[LogEntry] = []
        self._lock = asyncio.Lock()

    @property
    def entries(self) -> tuple[LogEntry, ...]:
        return tuple(self._chain)

    @property
    def public_key_hex(self) -> str:
        return self._keypair.public_hex

    async def record(self, request: ActionRequest, decision: Decision) -> LogEntry:
        """Append one entry and persist it.

        append() reads len(chain) and then writes. Two concurrent /act calls
        without this lock would mint the same seq and split the chain in half.
        """
        async with self._lock:
            entry = append(request, decision, self._keypair, self._chain)
            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(entry.model_dump_json() + "\n")
            return entry

    def load(self) -> None:
        """Rebuild the chain from disk, so it survives a restart."""
        if self._path is None or not self._path.exists():
            return
        entries: list[LogEntry] = []
        with self._path.open(encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    entries.append(LogEntry.model_validate_json(stripped))
        self._chain = entries

    def verify(self) -> VerifyResult:
        return verify(self._chain, self._keypair.public)

    def tamper_at(self, seq: int, mode: TamperMode) -> LogEntry:
        """DEMO ONLY. Corrupt one entry in memory.

        Not written back to disk: the file stays honest, so restarting restores
        integrity — which is its own demo beat.
        """
        if not 0 <= seq < len(self._chain):
            raise IndexError(f"no entry at seq {seq}")
        forged = tamper(self._chain[seq], mode, self._keypair)
        self._chain[seq] = forged
        return forged
