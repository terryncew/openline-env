"""
openline_env.denylist
---------------------
Check installed packages against a known-bad version registry.

This is intentionally minimal: it's a fast, local check,
not a subscription service. Update the list when incidents land.

Format:
    KNOWN_BAD = {
        "package-name": {
            "bad_versions": ["x.y.z", ...],
            "severity": "critical" | "high" | "medium",
            "cve": "CVE-...",          # optional
            "incident": "short label", # human note
            "source": "URL",           # report link
        }
    }
"""

from dataclasses import dataclass
from typing import Optional


KNOWN_BAD: dict = {
    "litellm": {
        "bad_versions": ["1.82.7", "1.82.8"],
        "severity": "critical",
        "cve": None,
        "incident": "Supply-chain compromise: malicious .pth file targeting SSH keys, "
                    "cloud creds, Kubernetes secrets, env vars, and persistence.",
        "source": "https://www.safedep.io/litellm-supply-chain-compromise",
    },
    # Add future incidents here — keep them dated in comments
    # "example-pkg": {
    #     "bad_versions": ["1.0.0"],
    #     "severity": "high",
    #     "incident": "...",
    #     "source": "...",
    # },
}


@dataclass
class DenylistHit:
    package: str
    version: str
    severity: str
    incident: str
    source: Optional[str]
    cve: Optional[str]

    def __str__(self) -> str:
        cve_note = f" [{self.cve}]" if self.cve else ""
        return (
            f"[{self.severity.upper()}]{cve_note} {self.package}=={self.version} — "
            f"{self.incident}"
        )


def check(installed_packages: dict) -> list[DenylistHit]:
    """
    Check a dict of {package_name: version_string} against KNOWN_BAD.

    Returns a (possibly empty) list of DenylistHit objects.
    """
    hits = []
    for pkg_name, installed_version in installed_packages.items():
        entry = KNOWN_BAD.get(pkg_name)
        if entry is None:
            continue
        if installed_version in entry["bad_versions"]:
            hits.append(
                DenylistHit(
                    package=pkg_name,
                    version=installed_version,
                    severity=entry["severity"],
                    incident=entry["incident"],
                    source=entry.get("source"),
                    cve=entry.get("cve"),
                )
            )
    return hits


def is_clean(installed_packages: dict) -> bool:
    """True if no known-bad packages are present."""
    return len(check(installed_packages)) == 0
