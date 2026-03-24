"""
openline_env.fingerprint
------------------------
Collect a deterministic runtime fingerprint for OpenLine receipts.

The fingerprint answers: "what was the environment when this agent ran?"
Two runs with identical outputs but different dependency states will
produce different receipt hashes — that's the guarantee.
"""

import hashlib
import json
import os
import platform
import sys
from dataclasses import dataclass, asdict, field
from importlib.metadata import version as pkg_version, PackageNotFoundError
from pathlib import Path
from typing import Optional


# Packages worth watching in AI-adjacent stacks
CRITICAL_PACKAGES = [
    "litellm",
    "openai",
    "anthropic",
    "langchain",
    "langchain-core",
    "langchain-community",
    "langgraph",
    "llama-index",
    "llama-index-core",
    "autogen",
    "crewai",
    "pydantic",
    "fastapi",
    "uvicorn",
    "httpx",
    "requests",
    "boto3",
    "google-cloud-storage",
    "kubernetes",
    "docker",
    # MCP / agent infra
    "mcp",
    "openline-agent-watchdog",
]


def _get_pkg_version(name: str) -> Optional[str]:
    try:
        return pkg_version(name)
    except PackageNotFoundError:
        return None


def _hash_lockfile(path: Optional[str]) -> Optional[str]:
    """SHA-256 of a lockfile if it exists."""
    if path is None:
        # Auto-detect common lockfiles from cwd
        for candidate in ["requirements.txt", "Pipfile.lock", "poetry.lock", "pdm.lock"]:
            p = Path(candidate)
            if p.exists():
                path = str(p)
                break
    if path and Path(path).exists():
        data = Path(path).read_bytes()
        return hashlib.sha256(data).hexdigest()
    return None


def _container_digest() -> Optional[str]:
    """Best-effort container / image digest from common env vars."""
    for var in ("DOCKER_IMAGE_DIGEST", "IMAGE_DIGEST", "CONTAINER_IMAGE"):
        val = os.environ.get(var)
        if val:
            return val
    # Kubernetes injects this in some setups
    return os.environ.get("HOSTNAME")  # fallback: pod name is better than nothing


@dataclass
class EnvFingerprint:
    python_version: str
    platform_summary: str
    os_release: str
    critical_packages: dict  # name -> version or None
    lockfile_hash: Optional[str]
    lockfile_source: Optional[str]
    container_hint: Optional[str]
    fingerprint_hash: str = field(init=False)

    def __post_init__(self):
        self.fingerprint_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Deterministic SHA-256 over all fields (excluding the hash itself)."""
        payload = {
            "python_version": self.python_version,
            "platform_summary": self.platform_summary,
            "os_release": self.os_release,
            "critical_packages": self.critical_packages,
            "lockfile_hash": self.lockfile_hash,
            "lockfile_source": self.lockfile_source,
            "container_hint": self.container_hint,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        """One-liner for logging."""
        return (
            f"py={self.python_version} "
            f"fp={self.fingerprint_hash[:12]}... "
            f"lockfile={'yes' if self.lockfile_hash else 'none'}"
        )


def collect(
    extra_packages: Optional[list] = None,
    lockfile_path: Optional[str] = None,
) -> EnvFingerprint:
    """
    Collect the current runtime environment into an EnvFingerprint.

    Parameters
    ----------
    extra_packages : list, optional
        Additional package names to include beyond CRITICAL_PACKAGES.
    lockfile_path : str, optional
        Explicit path to lockfile. Auto-detects if omitted.
    """
    packages_to_check = list(CRITICAL_PACKAGES)
    if extra_packages:
        packages_to_check.extend(extra_packages)

    pkg_versions = {name: _get_pkg_version(name) for name in packages_to_check}
    # Drop packages not installed to keep receipts clean
    pkg_versions = {k: v for k, v in pkg_versions.items() if v is not None}

    # Resolve lockfile
    resolved_lockfile_path = lockfile_path
    if resolved_lockfile_path is None:
        for candidate in ["requirements.txt", "Pipfile.lock", "poetry.lock", "pdm.lock"]:
            if Path(candidate).exists():
                resolved_lockfile_path = candidate
                break

    lf_hash = _hash_lockfile(resolved_lockfile_path)

    return EnvFingerprint(
        python_version=sys.version,
        platform_summary=platform.platform(),
        os_release=platform.version(),
        critical_packages=pkg_versions,
        lockfile_hash=lf_hash,
        lockfile_source=resolved_lockfile_path,
        container_hint=_container_digest(),
    )
