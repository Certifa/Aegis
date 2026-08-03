#!/usr/bin/env python3
"""Independent verifier for an Aegis provenance chain.

This file imports NOTHING from Aegis. That is the entire point of it.

`GET /log/verify` is the process that wrote the log checking its own work, which
is worth exactly as much as you trust that process. This script re-derives every
hash and checks every signature from the published data alone: the chain and the
public key. It shares no code, no constants and no canonical-JSON helper with the
implementation, so agreement between the two is evidence rather than tautology.

The only dependency is `cryptography`, for Ed25519. A third-party crypto library
is a feature here, not a compromise: the signature check does not come from us
either.

    # verify a file against a published key
    python verify_chain.py aegis-log.jsonl 4b4a012c...f6f14

    # or pull both from a running deployment and check it end to end
    python verify_chain.py --url https://aegis.certifa.net

Exit status is 0 when the chain is intact and 1 when it is not, so it can be
used in a pipeline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from typing import Any, cast

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - dependency guidance, not logic
    sys.exit("This script needs `cryptography`:  pip install cryptography")

GENESIS_PREV_HASH = ""
HASHED_FIELDS = ("seq", "ts", "request", "decision", "prev_hash")


def canonical(entry: dict[str, Any]) -> bytes:
    """Reproduce the bytes that were hashed, from the published entry alone.

    The rule, restated here rather than imported so that a drift in the
    implementation would show up as a verification failure instead of being
    silently mirrored: sort keys, no whitespace, ASCII-escaped, and every field
    except entry_hash and signature.
    """
    body = {k: entry[k] for k in HASHED_FIELDS}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def verify(chain: list[dict[str, Any]], public_key_hex: str) -> tuple[bool, str]:
    """Walk the chain oldest-first and report the first break.

    Checks in the same order the spec gives: link, then content, then signature.
    A content edit leaves entry_hash untouched, so the links still line up and
    the break is reported at the altered entry rather than its successor.
    """
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    except ValueError as exc:
        return False, f"public key is not valid hex or not 32 bytes: {exc}"

    for i, entry in enumerate(chain):
        seq = entry.get("seq")
        if seq != i:
            return False, f"entry {i}: seq is {seq}, expected {i} (chain is not contiguous)"

        expected_prev = chain[i - 1]["entry_hash"] if i else GENESIS_PREV_HASH
        if entry["prev_hash"] != expected_prev:
            return False, f"entry {i}: chain_link (prev_hash does not match entry {i - 1})"

        recomputed = hashlib.sha256(canonical(entry)).hexdigest()
        if recomputed != entry["entry_hash"]:
            return False, f"entry {i}: content_altered (recomputed hash differs)"

        try:
            pub.verify(bytes.fromhex(entry["signature"]), entry["entry_hash"].encode("ascii"))
        except (InvalidSignature, ValueError):
            return False, f"entry {i}: bad_signature"

    return True, f"{len(chain)} entries verified"


def load_from_file(path: str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _get_json(url: str) -> object:
    # A User-Agent is not optional in practice: urllib's default is blocked
    # outright by the CDN in front of the deployment, which surfaces as a 403
    # that looks like an auth problem rather than a bot filter.
    req = urllib.request.Request(url, headers={"User-Agent": "aegis-verify-chain/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def load_from_url(base: str) -> tuple[list[dict[str, Any]], str]:
    base = base.rstrip("/")
    entries = cast(list[dict[str, Any]], _get_json(f"{base}/log"))
    key = str(cast(dict[str, Any], _get_json(f"{base}/pubkey"))["public_key"])
    # /log is newest-first for the console. A chain only means anything in the
    # order it was written.
    entries.sort(key=lambda e: int(e["seq"]))
    return entries, key


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify an Aegis provenance chain without using any Aegis code."
    )
    ap.add_argument("chain", nargs="?", help="path to the JSONL chain")
    ap.add_argument("pubkey", nargs="?", help="Ed25519 public key, hex")
    ap.add_argument("--url", help="fetch /log and /pubkey from a running deployment")
    args = ap.parse_args()

    if args.url:
        try:
            chain, pubkey = load_from_url(args.url)
        except Exception as exc:  # any transport failure here is fatal
            print(f"FAILED to fetch from {args.url}: {exc}")
            return 1
        source = args.url
    elif args.chain and args.pubkey:
        chain, pubkey = load_from_file(args.chain), args.pubkey
        source = args.chain
    else:
        ap.print_usage()
        return 2

    print(f"source     {source}")
    print(f"public key {pubkey}")
    print(f"entries    {len(chain)}")

    if not chain:
        print("\nINTACT: empty chain, nothing to verify")
        return 0

    ok, detail = verify(chain, pubkey)
    print(f"\n{'INTACT' if ok else 'BROKEN'}: {detail}")
    if ok:
        print("\nEvery hash was recomputed and every signature checked by this script,")
        print("which shares no code with the system that produced the chain.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
