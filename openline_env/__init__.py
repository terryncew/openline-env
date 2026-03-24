## “””
openline-env

Environment integrity receipts for the OpenLine ecosystem.

Extends openline.science.v1 receipts with runtime fingerprints:
- Python version
- Dependency / lockfile hash
- Critical package versions
- Container / OS fingerprint
- Known-bad package denylist check

The core guarantee:
Same agent output + different dependency state = different receipt hash.

Quick start:

```
from openline_env import receipt

r = receipt.build(payload={"claim": "...", "result": "..."})
print(r["receipt_hash"])          # changes if deps change
print(r["env"]["env_clean"])      # False if denylist hit
```

“””

from .fingerprint import collect, EnvFingerprint, CRITICAL_PACKAGES
from .denylist import check as denylist_check, is_clean, KNOWN_BAD, DenylistHit
from .receipt import build, verify

**all** = [
“collect”,
“EnvFingerprint”,
“CRITICAL_PACKAGES”,
“denylist_check”,
“is_clean”,
“KNOWN_BAD”,
“DenylistHit”,
“build”,
“verify”,
]

**version** = “0.1.0”
