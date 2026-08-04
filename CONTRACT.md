# Aegis data contract, `v1.3.0` (FROZEN)

The console is built against this document. Everything here is defined in
`aegis/models.py` and nowhere else. Do not redefine these types locally.

`GET /contract` returns the version. If that number changes, a shape changed;
it will be announced first, and it will be additive.

Every bump so far has added endpoints only. **No response shape has changed
since 1.0.0**, so nothing built against that first contract has ever needed
touching.

| Version | Added |
|---|---|
| 1.1.0 | `GET /receipt/{seq}` |
| 1.2.0 | `POST /demo/overreach` |
| 1.3.0 | `GET /policy`, `GET /pubkey` |

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
| `GET /contract` | contract version | `{"version": "1.3.0"}` |
| `GET /receipt/{seq}` | human-readable prose for one entry | `{"seq": int, "text": str}` |
| `GET /log` | full chain, **newest first** | `LogEntry[]` |
| `GET /log/verify` | verify the whole chain | `VerifyResult` |
| `GET /policy` | the policy as loaded at startup | `{"policy_yaml": str}` |
| `GET /pubkey` | Ed25519 public key, so anyone can verify | `{"public_key": str, "algorithm": "ed25519"}` |
| `GET /` | the console | HTML |

Also live:

| Method + path | Purpose | Returns |
|---|---|---|
| `POST /act` | evaluate + log one action | `ActResponse` |
| `POST /demo/benign` | scripted benign scenario | `ActResponse[]` |
| `POST /demo/injected` | scripted injected scenario | `ActResponse[]` |
| `POST /demo/overreach` | scripted over-reach scenario | `ActResponse[]` |
| `POST /debug/tamper` | edit a past entry (demo only, env-gated) | `{"ok": true}` |

### `GET /policy`

```jsonc
{ "policy_yaml": "principal: alice@corp\nagent: inbox-assistant\n..." }
```

The policy text **as loaded at startup**, which is the one being enforced. It is
deliberately not a fresh read from disk: `evaluate()` uses the policy parsed once
in the lifespan handler, so re-reading per request would let the console display
a rule that is not in force.

### `GET /pubkey`

```jsonc
{ "public_key": "03a107bff3ce…31b8", "algorithm": "ed25519" }
```

64 hex characters, 32 bytes. Published so the chain can be verified by anyone,
not only by the process that wrote it. `verify_chain.py` at the repo root does
exactly that and imports no Aegis code.

Note the key is generated per process unless `AEGIS_SIGNING_SEED` is set, so it
changes on restart. Fetch it alongside the log rather than caching it.

### `GET /receipt/{seq}`

```jsonc
{ "seq": 2, "text": "Blocked: EUR 5000 exceeds this agent's EUR 50 payment limit." }
```

One sentence of plain English for an entry, computed on demand. 404 if `seq`
does not exist. The receipt is **not** part of the hashed entry and never enters
the chain. That is what keeps `Decision` free of prose, and what makes it
impossible for an explainer to influence or invalidate a decision. Purely
cosmetic: render it or don't.

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

`ok` is true **iff** `broken_at` and `why` are both null. No other combination
can occur. When `ok` is false, highlight the row where `seq === broken_at`.

## `ActResponse`

```jsonc
{ "decision": { /* Decision, as nested in LogEntry */ }, "seq": 7 }
```

## Enums, exhaustive and will not grow

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
deliberately logged rather than rejected at the edge (an attack that leaves no
trace is the wrong failure mode for an audit log), so a key may be missing.
Those entries appear as `DENY` with `reason_code: no_rule_matched`.

## Nothing is mocked any more

`/log` and `/log/verify` serve the real hash-chained, Ed25519-signed log. The
Phase 1 fixture is gone from the request path. As promised, the field names,
types, and lengths never changed, only the values became real.

**One consequence:** a freshly started server has an empty chain, so `/log`
returns `[]` until something populates it. `POST /demo/injected` gives you three
rows covering every state you need to style (`ALLOW`, `STEP_UP`, and `DENY`),
`POST /demo/benign` gives you a single `ALLOW`, and `POST /demo/overreach` gives
you `ALLOW` then `DENY`.

`tests/fixtures/mock_log.json` is still in the repo as a shape reference if you
want to develop offline, but no endpoint reads it.
