"""The Ed25519 identity that signs provenance entries.

Seeded from AEGIS_SIGNING_SEED when present, so a restarted process keeps the
same identity and a chain written before the restart still verifies. Without
that, every pre-restart entry fails verification with `bad_signature` — which
looks exactly like a tamper, and is the worst possible thing to happen while
recording.

Production would hold this key in a KMS and never let the process see it. This
is a demo, and the README says so.
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

logger = logging.getLogger(__name__)

SEED_ENV = "AEGIS_SIGNING_SEED"
_SEED_BYTES = 32


@dataclass(frozen=True)
class Keypair:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @property
    def public_hex(self) -> str:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()


def keypair_from_seed(seed: bytes) -> Keypair:
    """Deterministic: the same seed always yields the same identity."""
    if len(seed) != _SEED_BYTES:
        raise ValueError(f"seed must be exactly {_SEED_BYTES} bytes, got {len(seed)}")
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return Keypair(private=private, public=private.public_key())


def load_or_generate_keypair(*, demo_mode: bool = False) -> Keypair:
    """Read the seed from the environment, or mint a fresh one.

    The seed is a private key. It is echoed only in demo mode, and only so the
    operator can pin the identity across a restart.
    """
    raw = os.getenv(SEED_ENV)
    if raw:
        try:
            seed = bytes.fromhex(raw)
        except ValueError as exc:
            raise ValueError(
                f"{SEED_ENV} must be {_SEED_BYTES * 2} hex characters"
            ) from exc
        keypair = keypair_from_seed(seed)
        logger.info("signing identity loaded from %s: %s", SEED_ENV, keypair.public_hex)
        return keypair

    seed = secrets.token_bytes(_SEED_BYTES)
    keypair = keypair_from_seed(seed)
    logger.info("signing identity generated: %s", keypair.public_hex)
    if demo_mode:
        logger.warning(
            "DEMO MODE: export %s=%s to keep this identity across a restart",
            SEED_ENV,
            seed.hex(),
        )
    return keypair
