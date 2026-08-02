"""The HTTP surface.

Uses `with TestClient(app)` throughout, because the policy, keypair and log are
built in the lifespan handler and none of them exist without it.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegis.main import app


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("AEGIS_LOG_PATH", str(tmp_path / "chain.jsonl"))
    monkeypatch.setenv("AEGIS_SIGNING_SEED", bytes(range(32)).hex())
    monkeypatch.delenv("AEGIS_DEMO_MODE", raising=False)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def demo_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("AEGIS_LOG_PATH", str(tmp_path / "chain.jsonl"))
    monkeypatch.setenv("AEGIS_SIGNING_SEED", bytes(range(32)).hex())
    monkeypatch.setenv("AEGIS_DEMO_MODE", "1")
    with TestClient(app) as client:
        yield client


def act(client: TestClient, tool: str, **args: object) -> dict[str, Any]:
    response = client.post(
        "/act",
        json={
            "principal": "alice@corp",
            "agent": "inbox-assistant",
            "tool": tool,
            "args": args,
        },
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


# -- liveness and contract ------------------------------------------------------


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_contract_version(client: TestClient) -> None:
    assert client.get("/contract").json() == {"version": "1.2.0"}


def test_root_serves_console_ui(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Aegis" in response.text
    assert "<!DOCTYPE html>" in response.text


def test_policy_endpoint(client: TestClient) -> None:
    response = client.get("/policy")
    assert response.status_code == 200
    assert "principal: alice@corp" in response.json()["policy_yaml"]


# -- /act -----------------------------------------------------------------------


def test_act_allows_an_internal_email(client: TestClient) -> None:
    body = act(client, "send_email", to="bob@corp", subject="Q3", body="attached")
    assert body["decision"] == {
        "request_id": body["decision"]["request_id"],  # server-generated
        "outcome": "ALLOW",
        "reason_code": "internal_recipient_ok",
        "matched_rule": "email-internal-ok",
    }
    assert body["seq"] == 0


def test_act_denies_an_over_limit_payment(client: TestClient) -> None:
    body = act(client, "make_payment", amount_eur=5000, iban="DE89", memo="x")
    assert body["decision"]["outcome"] == "DENY"
    assert body["decision"]["reason_code"] == "amount_exceeds_limit"


def test_act_steps_up_an_external_email(client: TestClient) -> None:
    body = act(client, "send_email", to="attacker@evil.com", subject="x", body="y")
    assert body["decision"]["outcome"] == "STEP_UP"
    assert body["decision"]["reason_code"] == "external_recipient_stepup"


def test_act_rejects_an_unknown_tool(client: TestClient) -> None:
    response = client.post(
        "/act",
        json={
            "principal": "alice@corp",
            "agent": "inbox-assistant",
            "tool": "delete_database",
            "args": {},
        },
    )
    assert response.status_code == 422


# -- /log and /log/verify -------------------------------------------------------


def test_log_starts_empty_and_verifies(client: TestClient) -> None:
    assert client.get("/log").json() == []
    assert client.get("/log/verify").json() == {
        "ok": True, "count": 0, "broken_at": None, "why": None
    }


def test_log_is_newest_first(client: TestClient) -> None:
    act(client, "send_email", to="bob@corp")
    act(client, "send_email", to="attacker@evil.com")
    act(client, "make_payment", amount_eur=5000)

    entries = client.get("/log").json()
    assert [e["seq"] for e in entries] == [2, 1, 0]
    assert [e["decision"]["outcome"] for e in entries] == ["DENY", "STEP_UP", "ALLOW"]


def test_log_verify_is_intact_after_real_appends(client: TestClient) -> None:
    act(client, "send_email", to="bob@corp")
    act(client, "make_payment", amount_eur=5000)
    assert client.get("/log/verify").json() == {
        "ok": True, "count": 2, "broken_at": None, "why": None
    }


# -- /demo/* --------------------------------------------------------------------


def test_demo_benign_yields_one_allow(client: TestClient) -> None:
    body = client.post("/demo/benign").json()
    assert [step["decision"]["outcome"] for step in body] == ["ALLOW"]
    assert client.get("/log/verify").json()["ok"]


def test_demo_injected_yields_two_blocks(client: TestClient) -> None:
    body = client.post("/demo/injected").json()
    assert [step["decision"]["outcome"] for step in body] == [
        "ALLOW", "STEP_UP", "DENY"
    ]
    assert client.get("/log/verify").json()["ok"]


def test_demo_overreach_blocks_the_payment(client: TestClient) -> None:
    body = client.post("/demo/overreach").json()
    assert [step["decision"]["outcome"] for step in body] == ["ALLOW", "DENY"]
    assert body[1]["decision"]["reason_code"] == "amount_exceeds_limit"
    assert client.get("/log/verify").json()["ok"]


# -- /debug/tamper --------------------------------------------------------------


def test_tamper_is_404_when_demo_mode_is_off(client: TestClient) -> None:
    """A disabled endpoint should not confirm that it exists."""
    act(client, "send_email", to="bob@corp")
    assert client.post("/debug/tamper", json={"seq": 0, "mode": "content"}).status_code == 404


@pytest.mark.parametrize(
    ("mode", "why"),
    [
        ("content", "content_altered"),
        ("signature", "bad_signature"),
        ("link", "chain_link"),
    ],
)
def test_tamper_breaks_verification_with_the_right_reason(
    demo_client: TestClient, mode: str, why: str
) -> None:
    demo_client.post("/demo/injected")

    response = demo_client.post("/debug/tamper", json={"seq": 1, "mode": mode})
    assert response.status_code == 200
    assert response.json() == {"ok": True}

    assert demo_client.get("/log/verify").json() == {
        "ok": False, "count": 3, "broken_at": 1, "why": why
    }


def test_tamper_rejects_an_unknown_seq(demo_client: TestClient) -> None:
    assert demo_client.post("/debug/tamper", json={"seq": 99, "mode": "content"}).status_code == 404


def test_tamper_rejects_an_unknown_mode(demo_client: TestClient) -> None:
    demo_client.post("/demo/benign")
    assert demo_client.post("/debug/tamper", json={"seq": 0, "mode": "wat"}).status_code == 422
