"""Per-agent cryptographic identity — "SoulKeys".

Each agent holds its own Ed25519 keypair. Memory writes and messages can be signed,
so identity is a continuously-verified property (catching impersonation and persona
hijack), not a one-time credential. Requires `cryptography` (pip install cryptography);
the memory + governance modules work without it, so the core demo runs dependency-free.
"""
from __future__ import annotations

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False


def _require():
    if not _HAVE_CRYPTO:
        raise ImportError("SoulKey identity needs `cryptography` — `pip install cryptography`.")


class SoulKey:
    """An agent's signing identity (private). Sign with .sign(); share .public()."""

    def __init__(self, _priv=None):
        _require()
        self._priv = _priv or Ed25519PrivateKey.generate()

    @property
    def agent_id(self) -> str:
        """A stable id derived from the public key (first 16 hex of the raw pubkey)."""
        return self.public_bytes().hex()[:16]

    def sign(self, message: bytes) -> bytes:
        return self._priv.sign(message)

    def public_bytes(self) -> bytes:
        return self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def public(self) -> "SoulKeyVerifier":
        return SoulKeyVerifier(self.public_bytes())

    def export_private(self) -> bytes:
        return self._priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())

    @classmethod
    def from_private(cls, raw: bytes) -> "SoulKey":
        _require()
        return cls(Ed25519PrivateKey.from_private_bytes(raw))


class SoulKeyVerifier:
    """The public half — verify signatures attributed to an agent."""

    def __init__(self, public_raw: bytes):
        _require()
        self._pub = Ed25519PublicKey.from_public_bytes(public_raw)
        self.public_raw = public_raw

    @property
    def agent_id(self) -> str:
        return self.public_raw.hex()[:16]

    def verify(self, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        try:
            self._pub.verify(signature, message)
            return True
        except InvalidSignature:
            return False
