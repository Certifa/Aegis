# Aegis

A policy-and-provenance gateway for AI agents. Orion Global Hackathon 2026.
Deadline: 4 days. Scope is small on purpose — do not grow it.

## The one inviolable rule

The enforcement decision (allow / deny / step-up) is made by DETERMINISTIC
CODE ONLY. No LLM is ever called in the path from an action to a decision.
An LLM appears in exactly two harmless places: inside the agent being
guarded, and as an optional read-only explainer that writes prose AFTER a
decision is already made. If you ever find yourself calling a model to
decide allow/deny, stop — that reintroduces the exact vulnerability this
product exists to stop.

## Scope — four tools, two scenarios, one chain. It does not grow.

Tools (all STUBBED — they record an attempt, they never really send/pay):
send_email, read_file, http_request, make_payment.
Scenarios: one benign task, one prompt-injected task.
Propose additions, don't build them.

## Build order — contracts first, UI last

1. models.py — ActionRequest, Decision, LogEntry (freeze before anything else)
2. policy.py — load YAML + evaluate(), pure and synchronous
3. provenance.py — append() + verify(), hash chain + Ed25519
4. interceptor.py, tools.py (stubs), agent.py
5. main.py — FastAPI routes
6. console UI (Jayden's half)

## Contracts are frozen

Once models.py exists, a second developer builds the console against it.
Do not change field names or shapes without announcing it first — a silent
change breaks their work invisibly.

## Conventions

- Python 3.13, FastAPI, asyncio, pytest
- evaluate() and the hash/verify functions are pure: no network, no I/O
- Full type hints, no bare excepts, structured logging
- Every function in policy.py and provenance.py has a test written alongside it
- Canonical JSON for hashing: sort_keys=True, separators=(',',':'),
  datetimes as isoformat() — byte-for-byte reproducible or tamper detection breaks

## Working style

Plan before building. Show diffs before applying. Pause before deleting or
overwriting files. Explain non-obvious decisions in a line — both teammates
must be able to defend every line on camera. Push back if I'm about to do
something wrong.
