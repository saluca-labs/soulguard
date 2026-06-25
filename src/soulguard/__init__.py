"""SoulGuard — an open trust layer for agent memory and identity.

Tamper-evident memory, per-agent cryptographic identity, capability-scoped governance,
and OWASP-ASI06 memory-poisoning detection. Apache-2.0. By Saluca LLC.
"""
from .memory import TamperEvidentMemory, MemoryEntry, Finding
from .governance import issue_token, verify_token
from .detection import scan, ScanResult

__all__ = [
    "TamperEvidentMemory", "MemoryEntry", "Finding",
    "issue_token", "verify_token", "scan", "ScanResult",
]
__version__ = "0.1.0"

# identity (SoulKey) is imported lazily — it needs `cryptography`, which the core does not.
try:
    from .identity import SoulKey, SoulKeyVerifier  # noqa: F401
    __all__ += ["SoulKey", "SoulKeyVerifier"]
except Exception:
    pass

# Hybrid post-quantum SoulKeys are lazier still — they also need `quantcrypt`
# (pip install 'soulguard[pqc]'). Absent it, the classical SoulKey above still works.
try:
    from .identity import HybridSoulKey, HybridSoulKeyVerifier  # noqa: F401
    __all__ += ["HybridSoulKey", "HybridSoulKeyVerifier"]
except Exception:
    pass
