"""Canonical JSON must be byte-for-byte reproducible.

If these tests ever fail, every signature in every existing chain becomes
unverifiable — this is the foundation the whole provenance log stands on.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest

from aegis.canonical import canonical_json


def test_key_order_does_not_change_the_bytes() -> None:
    a = {"b": 1, "a": 2, "c": 3}
    b = {"c": 3, "a": 2, "b": 1}
    assert canonical_json(a) == canonical_json(b) == b'{"a":2,"b":1,"c":3}'


def test_nested_keys_are_sorted_too() -> None:
    assert canonical_json({"z": {"b": 1, "a": 2}}) == b'{"z":{"a":2,"b":1}}'


def test_separators_are_compact() -> None:
    """No whitespace: a stray space would change the hash."""
    out = canonical_json({"a": 1, "b": [1, 2]})
    assert b" " not in out
    assert out == b'{"a":1,"b":[1,2]}'


def test_datetime_is_isoformat() -> None:
    ts = datetime(2026, 8, 2, 14, 0, 0, tzinfo=UTC)
    assert canonical_json({"ts": ts}) == b'{"ts":"2026-08-02T14:00:00+00:00"}'


def test_datetime_matches_a_pre_serialised_string() -> None:
    """A caller passing model_dump(mode='json') and a caller passing raw
    datetimes must produce identical bytes, or append() and verify() disagree
    depending on how each happened to build its payload."""
    ts = datetime(2026, 8, 2, 14, 0, 0, tzinfo=UTC)
    assert canonical_json({"ts": ts}) == canonical_json({"ts": ts.isoformat()})


def test_output_is_pure_ascii() -> None:
    """Non-ASCII content is escaped, so the bytes cannot vary with locale."""
    out = canonical_json({"subject": "Q3 café — €5000"})
    assert out.decode("ascii")
    assert b"\\u" in out


def test_is_stable_across_calls() -> None:
    payload: dict[str, Any] = {"b": [3, 1], "a": {"y": None, "x": True}}
    assert canonical_json(payload) == canonical_json(payload)


def test_unknown_types_raise_rather_than_coerce() -> None:
    """A silent coercion here would change the hash and quietly break
    verification for everyone downstream."""
    with pytest.raises(TypeError, match="not canonically serialisable"):
        canonical_json({"amount": Decimal("50.00")})


def test_object_keys_are_stringified_consistently() -> None:
    assert canonical_json({"1": "a"}) == b'{"1":"a"}'
