"""Canonical JSON — the one definition.

append() and verify() must serialise identically, byte for byte, or tamper
detection breaks. Two copies of this function that drifted apart would make
the chain silently unverifiable, so there is exactly one, with its own tests.

Rule (spec section 3): sort_keys=True, separators=(',',':'), datetimes as
isoformat().
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any


def _encode_unsupported(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(
        f"{type(value).__name__} is not canonically serialisable; "
        "convert it before hashing"
    )


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    """Deterministic bytes for `payload`.

    ensure_ascii stays at its default True, so the output is pure ASCII and
    cannot vary with anyone's locale or filesystem encoding. Unknown types
    raise rather than being coerced — a silent coercion here would change the
    hash and break verification for everyone downstream.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_encode_unsupported,
    ).encode("ascii")
