"""Hybrid (post-quantum) SoulKey tests — Ed25519 + ML-DSA-44, both-or-reject.

Run with: python -m pytest tests/test_hybrid_identity.py
Skips cleanly if the `pqc` extra (quantcrypt) is not installed.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest

from soulguard import TamperEvidentMemory

try:
    from soulguard import HybridSoulKey, HybridSoulKeyVerifier
    _HAVE = True
except Exception:
    _HAVE = False

pytestmark = pytest.mark.skipif(not _HAVE, reason="soulguard[pqc] (quantcrypt) not installed")


def test_sign_verify_roundtrip():
    k = HybridSoulKey()
    msg = b"the hash chain is sacred"
    sig = k.sign(msg)
    assert k.public().verify(msg, sig) is True


def test_tamper_rejected():
    k = HybridSoulKey()
    sig = k.sign(b"original")
    assert k.public().verify(b"forged", sig) is False


def test_wrong_key_rejected():
    a, b = HybridSoulKey(), HybridSoulKey()
    sig = a.sign(b"msg")
    assert b.public().verify(b"msg", sig) is False
    assert a.agent_id != b.agent_id


def test_both_or_reject_pq_half_corrupted():
    """Corrupting only the ML-DSA-44 half must still reject (no classical-only pass)."""
    k = HybridSoulKey()
    msg = b"msg"
    sig = bytearray(k.sign(msg))
    sig[-1] ^= 0xFF  # deep in the PQ component
    assert k.public().verify(msg, bytes(sig)) is False


def test_export_import_private_roundtrip():
    k = HybridSoulKey()
    raw = k.export_private()
    k2 = HybridSoulKey.from_private(raw)
    assert k2.agent_id == k.agent_id
    # A signature from the restored key verifies under the original public key.
    sig = k2.sign(b"continuity")
    assert k.public().verify(b"continuity", sig) is True


def test_drops_into_memory_chain():
    """The whole point: hybrid keys sign the tamper-evident memory unchanged."""
    k = HybridSoulKey()
    m = TamperEvidentMemory(agent_id=k.agent_id)
    m.append("first", signer=k)
    m.append("second", signer=k)
    v = k.public()
    assert m.is_intact(verifier=v) is True
    # Poison a memory: hash mismatch AND the signature no longer matches.
    m.entries[0].content = "POISONED"
    findings = m.verify(verifier=v)
    assert any(f.kind == "content_tampered" for f in findings)


def test_malformed_signature_is_false_not_raise():
    k = HybridSoulKey()
    assert k.public().verify(b"msg", b"not-a-hybrid-blob") is False
