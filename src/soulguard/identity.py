"""Per-agent cryptographic identity — "SoulKeys".

Each agent holds its own Ed25519 keypair. Memory writes and messages can be signed,
so identity is a continuously-verified property (catching impersonation and persona
hijack), not a one-time credential. Requires `cryptography` (pip install cryptography);
the memory + governance modules work without it, so the core demo runs dependency-free.

For a quantum-ready identity, `HybridSoulKey` / `HybridSoulKeyVerifier` sign with
Ed25519 AND ML-DSA-44 (FIPS 204) in parallel and verify both-or-reject — a break of
either algorithm alone cannot forge a signature. They share the classical SoulKey's
`.sign(msg)->bytes` / `.verify(msg,sig)->bool` interface, so they drop straight into the
tamper-evident memory chain. Needs `quantcrypt` (pip install 'soulguard[pqc]').
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


# ───────────────────────── Hybrid (post-quantum) SoulKeys ─────────────────────────
# A quantum-ready identity: every signature is Ed25519 AND ML-DSA-44 (FIPS 204),
# verified both-or-reject. A break of either algorithm alone cannot forge a
# signature — so the day a cryptographically-relevant quantum computer breaks
# Ed25519, an agent's signed history stays attributable. Drop-in: HybridSoulKey /
# HybridSoulKeyVerifier expose the same .sign(msg)->bytes / .verify(msg,sig)->bool
# duck-type the memory chain already uses, so `append(signer=...)` and
# `verify(verifier=...)` work unchanged. Needs `quantcrypt` (pip install
# 'soulguard[pqc]'); import fails cleanly otherwise, leaving the classical path intact.
import struct as _struct

try:
    from quantcrypt.dss import MLDSA_44 as _MLDSA_44  # type: ignore
    _HAVE_PQ = True
except Exception:  # pragma: no cover - optional extra
    _HAVE_PQ = False

_HYB_MAGIC = b"SGH1"  # SoulGuard Hybrid, format v1


def _require_pq():
    _require()
    if not _HAVE_PQ:
        raise ImportError(
            "Hybrid (post-quantum) SoulKeys need `quantcrypt` — `pip install 'soulguard[pqc]'`."
        )


def _hyb_pack(classical: bytes, pq: bytes) -> bytes:
    """Self-describing length-prefixed blob: magic | u16 len(ed) | ed | u32 len(pq) | pq."""
    return (_HYB_MAGIC + _struct.pack(">H", len(classical)) + bytes(classical)
            + _struct.pack(">I", len(pq)) + bytes(pq))


def _hyb_unpack(data: bytes) -> tuple[bytes, bytes]:
    data = bytes(data)
    if len(data) < 4 + 2 + 4 or data[:4] != _HYB_MAGIC:
        raise ValueError("not a SoulGuard hybrid blob")
    pos = 4
    (clen,) = _struct.unpack(">H", data[pos:pos + 2]); pos += 2
    classical = data[pos:pos + clen]; pos += clen
    (plen,) = _struct.unpack(">I", data[pos:pos + 4]); pos += 4
    pq = data[pos:pos + plen]; pos += plen
    if pos != len(data) or len(classical) != clen or len(pq) != plen:
        raise ValueError("malformed SoulGuard hybrid blob")
    return classical, pq


class HybridSoulKey:
    """A quantum-ready signing identity: parallel Ed25519 + ML-DSA-44 (both-or-reject)."""

    def __init__(self, _ed_priv=None, _mldsa_sk: bytes = None, _mldsa_pk: bytes = None):
        _require_pq()
        self._ed = _ed_priv or Ed25519PrivateKey.generate()
        if _mldsa_sk is None or _mldsa_pk is None:
            _mldsa_pk, _mldsa_sk = _MLDSA_44().keygen()
        self._sk = bytes(_mldsa_sk)
        self._pk = bytes(_mldsa_pk)

    def _ed_pub_raw(self) -> bytes:
        return self._ed.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def public_bytes(self) -> bytes:
        """Packed hybrid public key (Ed25519 raw + ML-DSA-44 pk)."""
        return _hyb_pack(self._ed_pub_raw(), self._pk)

    @property
    def agent_id(self) -> str:
        """Stable id derived from the packed hybrid public key (first 16 hex of its sha256)."""
        import hashlib
        return hashlib.sha256(self.public_bytes()).hexdigest()[:16]

    def sign(self, message: bytes) -> bytes:
        """Parallel signature: packed(Ed25519 sig || ML-DSA-44 sig)."""
        ed_sig = self._ed.sign(bytes(message))
        pq_sig = _MLDSA_44().sign(self._sk, bytes(message))
        return _hyb_pack(ed_sig, pq_sig)

    def public(self) -> "HybridSoulKeyVerifier":
        return HybridSoulKeyVerifier(self.public_bytes())

    def export_private(self) -> bytes:
        """Packed private material (Ed25519 raw || ML-DSA-44 sk||pk). Encrypt at rest yourself."""
        ed_raw = self._ed.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        return _hyb_pack(ed_raw, _hyb_pack(self._sk, self._pk))

    @classmethod
    def from_private(cls, raw: bytes) -> "HybridSoulKey":
        _require_pq()
        ed_raw, sk_pk = _hyb_unpack(raw)
        sk, pk = _hyb_unpack(sk_pk)
        ed_priv = Ed25519PrivateKey.from_private_bytes(ed_raw)
        return cls(_ed_priv=ed_priv, _mldsa_sk=sk, _mldsa_pk=pk)


class HybridSoulKeyVerifier:
    """The public half — verify hybrid signatures. BOTH halves must verify."""

    def __init__(self, public_raw: bytes):
        _require_pq()
        ed_raw, pq_pk = _hyb_unpack(public_raw)
        self._ed_pub = Ed25519PublicKey.from_public_bytes(ed_raw)
        self._pk = pq_pk
        self.public_raw = bytes(public_raw)

    @property
    def agent_id(self) -> str:
        import hashlib
        return hashlib.sha256(self.public_raw).hexdigest()[:16]

    def verify(self, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        try:
            ed_sig, pq_sig = _hyb_unpack(signature)
        except ValueError:
            return False
        # both-or-reject: do NOT short-circuit, so failure timing leaks less.
        classical_ok = True
        try:
            self._ed_pub.verify(ed_sig, bytes(message))
        except InvalidSignature:
            classical_ok = False
        except Exception:
            classical_ok = False
        pq_ok = False
        try:
            pq_ok = bool(_MLDSA_44().verify(self._pk, bytes(message), pq_sig))
        except Exception:
            pq_ok = False
        return classical_ok and pq_ok
