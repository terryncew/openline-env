"""
openline_env.receipt
--------------------
Attach an environment fingerprint to an OpenLine receipt.

The resulting receipt is a standard openline.science.v1 dict
with an added `env` block and a new top-level `receipt_hash`
that covers both the original payload and the env fingerprint.

Usage
-----
    from openline_env import receipt, fingerprint

    fp = fingerprint.collect()
    signed = receipt.build(
        payload={"claim": "agent ran", "result": "ok"},
        fp=fp,
    )
    # signed["receipt_hash"] changes if deps change — that's the point.
"""

import hashlib
import json
import time
from typing import Any, Optional

from .fingerprint import EnvFingerprint, collect as collect_fingerprint
from .denylist import check as denylist_check, DenylistHit


_SCHEMA_VERSION = "openline.science.v1"


def _sha256(obj: Any) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def build(
    payload: dict,
    fp: Optional[EnvFingerprint] = None,
    extra_packages: Optional[list] = None,
    lockfile_path: Optional[str] = None,
    strict: bool = False,
) -> dict:
    """
    Build a signed receipt attaching an environment fingerprint.

    Parameters
    ----------
    payload : dict
        The core claim / result data for this receipt.
    fp : EnvFingerprint, optional
        Pre-collected fingerprint. Collected fresh if omitted.
    extra_packages : list, optional
        Additional packages to track (passed to fingerprint.collect).
    lockfile_path : str, optional
        Explicit lockfile path (passed to fingerprint.collect).
    strict : bool
        If True, raises RuntimeError when denylist hits are found.

    Returns
    -------
    dict
        A complete openline.science.v1 receipt with env block.

    Raises
    ------
    RuntimeError
        If strict=True and a known-bad package is detected.
    """
    if fp is None:
        fp = collect_fingerprint(
            extra_packages=extra_packages,
            lockfile_path=lockfile_path,
        )

    denylist_hits: list[DenylistHit] = denylist_check(fp.critical_packages)

    if strict and denylist_hits:
        msgs = "\n".join(str(h) for h in denylist_hits)
        raise RuntimeError(
            f"Environment contains known-bad packages (strict mode):\n{msgs}"
        )

    env_block = {
        "schema": _SCHEMA_VERSION,
        "fingerprint": fp.to_dict(),
        "denylist_hits": [
            {
                "package": h.package,
                "version": h.version,
                "severity": h.severity,
                "incident": h.incident,
                "source": h.source,
                "cve": h.cve,
            }
            for h in denylist_hits
        ],
        "env_clean": len(denylist_hits) == 0,
    }

    receipt = {
        "schema": _SCHEMA_VERSION,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "payload": payload,
        "env": env_block,
    }

    # The receipt hash covers payload + env together.
    # Same output, different deps → different hash. That's the guarantee.
    receipt["receipt_hash"] = _sha256(
        {"payload": payload, "env": env_block}
    )

    return receipt


def verify(receipt_a: dict, receipt_b: dict) -> dict:
    """
    Compare two receipts and report whether env state diverged.

    Useful for "same claim, different run" audits.

    Returns a diff report dict with:
      - hashes_match: bool
      - env_hashes_match: bool
      - payload_hashes_match: bool
      - denylist_hits_a / denylist_hits_b
    """
    hash_a = receipt_a.get("receipt_hash")
    hash_b = receipt_b.get("receipt_hash")

    fp_hash_a = receipt_a.get("env", {}).get("fingerprint", {}).get("fingerprint_hash")
    fp_hash_b = receipt_b.get("env", {}).get("fingerprint", {}).get("fingerprint_hash")

    payload_hash_a = _sha256(receipt_a.get("payload", {}))
    payload_hash_b = _sha256(receipt_b.get("payload", {}))

    return {
        "hashes_match": hash_a == hash_b,
        "env_hashes_match": fp_hash_a == fp_hash_b,
        "payload_hashes_match": payload_hash_a == payload_hash_b,
        "env_diverged": fp_hash_a != fp_hash_b,
        "payload_diverged": payload_hash_a != payload_hash_b,
        "denylist_hits_a": receipt_a.get("env", {}).get("denylist_hits", []),
        "denylist_hits_b": receipt_b.get("env", {}).get("denylist_hits", []),
        "receipt_hash_a": hash_a,
        "receipt_hash_b": hash_b,
        "fingerprint_hash_a": fp_hash_a,
        "fingerprint_hash_b": fp_hash_b,
    }
