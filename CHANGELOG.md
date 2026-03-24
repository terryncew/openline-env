# Changelog

## [0.1.0] — 2026-03-24

Initial release.

### Added
- `fingerprint.collect()` — captures Python version, platform, critical package
  versions, lockfile SHA-256, and container digest into a deterministic
  `EnvFingerprint` with a single `fingerprint_hash`
- `denylist.check()` / `denylist.is_clean()` — checks installed packages against
  known-bad versions; ships with litellm 1.82.7 and 1.82.8 flagged at CRITICAL
  (SafeDep supply-chain compromise: malicious `.pth` file targeting credentials,
  Kubernetes secrets, env vars, and persistence)
- `receipt.build()` — extends openline.science.v1 receipts with an `env` block;
  `receipt_hash` covers payload + env together so same output + different deps =
  different hash
- `receipt.verify()` — diffs two receipts, reporting env divergence, payload
  divergence, and denylist hits per run
- `strict=True` mode on `receipt.build()` raises `RuntimeError` on any denylist hit
- 39 tests, 0 failures
