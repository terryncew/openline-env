# openline-env

Environment integrity receipts for the OpenLine ecosystem.

Extends `openline.science.v1` receipts with a runtime fingerprint so that
**the same agent output under different dependency states produces a different
receipt hash**. That difference is the proof.

## What it adds to a receipt

```json
{
  "schema": "openline.science.v1",
  "timestamp_utc": "2026-03-24T...",
  "payload": { "...your claim..." },
  "env": {
    "fingerprint": {
      "python_version": "3.11.9 ...",
      "platform_summary": "Linux-...",
      "critical_packages": { "litellm": "1.82.9", "openai": "1.12.0" },
      "lockfile_hash": "a3f...",
      "fingerprint_hash": "7c2e..."
    },
    "denylist_hits": [],
    "env_clean": true
  },
  "receipt_hash": "9b4d..."
}
```

## Install

```bash
pip install openline-env
```

## Usage

```python
from openline_env import build, verify, collect

# Build a receipt — fingerprints the current environment automatically
r = build(payload={"agent_id": "my-agent", "result": "42"})
print(r["receipt_hash"])       # changes if deps change
print(r["env"]["env_clean"])   # False if litellm 1.82.7/1.82.8 (or other known-bad) is installed

# Strict mode: raises RuntimeError if a known-bad package is present
r = build(payload={...}, strict=True)

# Compare two runs
diff = verify(receipt_a, receipt_b)
print(diff["env_diverged"])        # True if dep state changed between runs
print(diff["payload_diverged"])    # True if output changed
```

## The discriminating test

> If two runs produce the same output but happened under different dependency
> states, can your receipt make that difference legible and verifiable?

```python
r1 = build(payload=same, fp=fp_with_litellm_1_82_6)
r2 = build(payload=same, fp=fp_with_litellm_1_82_8)

assert r1["receipt_hash"] != r2["receipt_hash"]  # passes
assert r2["env"]["env_clean"] is False            # passes
```

## Known-bad denylist

The package ships a `denylist.py` with confirmed compromised versions.
Currently flagged:

| Package | Version(s) | Severity | Incident |
|---------|-----------|----------|---------|
| litellm | 1.82.7, 1.82.8 | CRITICAL | Supply-chain: malicious `.pth` file targeting SSH keys, cloud creds, Kubernetes secrets, env vars, and persistence. ([SafeDep report](https://www.safedep.io/litellm-supply-chain-compromise)) |

Add future incidents directly in `denylist.py`.

## Tests

```bash
pytest tests/ -v
```

Expected: all tests pass.

## What this is not

This is not a SOC dashboard. It's a thin receipt layer that extends what
OpenLine already does — tamper-evident, SHA-256 hashed records — into the
environment dimension. The boundary is intentional.
