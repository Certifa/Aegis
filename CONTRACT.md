# Aegis data contract — `v1.0.0` (FROZEN)

The console is built against this document. Everything here is defined in
`aegis/models.py` and nowhere else — do not redefine these types locally.

`GET /contract` returns the version. If that number changes, a shape changed;
it will be announced first, and it will be additive.

## Running the API

```bash
pip install fastapi uvicorn pydantic pyyaml
AEGIS_DEV_CORS=1 uvicorn aegis.main:app --reload --port 8000
```

`AEGIS_DEV_CORS=1` is only needed while the console runs on its own dev server.

## Endpoints

| Method + path | Purpose | Returns |
|---|---|---|
| `GET /health` | liveness | `{"status": "ok"}` |
| `GET /contract` | contract version | `{"version": "1.0.0"}` |
| `GET /log` | full chain, **newest first** | `LogEntry[]` |
| `GET /log/verify` | verify the whole chain | `VerifyResult` |

Landing in Phase 4, shapes already fixed:

| Method + path | Purpose | Returns |
|---|---|---|
| `POST /act` | evaluate + log one action | `ActResponse` |
| `POST /demo/benign` | scripted benign scenario | `ActResponse[]` |
| `POST /demo/injected` | scripted injected scenario | `ActResponse[]` |
| `POST /debug/tamper` | edit a past entry — demo only, env-gated | `{"ok": true}` |

## `LogEntry`

```jsonc
{
  "seq": 0,                                    // int, contiguous from 0
  "ts": "2026-08-02T14:00:00+00:00",           // ISO 8601, always UTC-aware
  "request": {
    "request_id": "00000000-0000-4000-8000-000000000000",
    "principal": "alice@corp",
    "agent": "inbox-assistant",
    "tool": "send_email",
    "args": { "to": "bob@corp", "subject": "Q3 report", "body": "Attached." },
    "ts": "2026-08-02T14:00:00+00:00"
  },
  "decision": {
    "request_id": "00000000-0000-4000-8000-000000000000",  // matches request
    "outcome": "ALLOW",                        // ALLOW | DENY | STEP_UP
    "reason_code": "internal_recipient_ok",    // machine string
    "matched_rule": "email-internal-ok"        // string or null
  },
  "prev_hash": "",                             // 64 hex chars; "" only at seq 0
  "entry_hash": "0000…0000",                   // 64 hex chars
  "signature":  "0000…0000"                    // 128 hex chars
}
```

## `VerifyResult`

```jsonc
{ "ok": true,  "count": 4, "broken_at": null, "why": null }
{ "ok": false, "count": 4, "broken_at": 2,    "why": "content_altered" }
```

`ok` is true **iff** `broken_at` and `why` are both null — no other combination
can occur. When `ok` is false, highlight the row where `seq === broken_at`.

## `ActResponse`

```jsonc
{ "decision": { /* Decision, as nested in LogEntry */ }, "seq": 7 }
```

## Enums — exhaustive, will not grow

- `tool`: `send_email`, `read_file`, `http_request`, `make_payment`
- `outcome`: `ALLOW`, `DENY`, `STEP_UP`
- `why`: `chain_link`, `content_altered`, `bad_signature`

`reason_code` is the one open string. Treat unknown values as displayable text;
do not switch on it exhaustively.

## `args` shape per tool

| tool | args |
|---|---|
| `send_email` | `to`, `subject`, `body` |
| `read_file` | `path` |
| `http_request` | `url`, `method` |
| `make_payment` | `amount_eur`, `iban`, `memo` |

Render `args` defensively. A malformed action from an injected agent is
deliberately logged rather than rejected at the edge — an attack that leaves no
trace is the wrong failure mode for an audit log — so a key may be missing.
Those entries appear as `DENY` with `reason_code: no_rule_matched`.

## What is mock right now

`tests/fixtures/mock_log.json` carries **placeholder zeros** for `entry_hash`,
`prev_hash`, and `signature`, and `/log/verify` returns a hardcoded `INTACT` so
the verify button is wired end to end.

Phase 3 replaces both with the real SHA-256 chain and Ed25519 signatures.
**Field names, types, and lengths do not change** — only the values become
real. Nothing built against this fixture breaks.

The four fixture entries cover every visual state: `ALLOW`, `STEP_UP`,
`DENY` (secrets path), `DENY` (over-limit payment).
