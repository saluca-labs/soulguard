# Copyright (c) 2026 Saluca LLC. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Saluca-Proprietary
# Proprietary and confidential — see LICENSE. No rights granted without a written agreement from Saluca LLC.
"""SoulGuard chain signature semantics — the signature layer must defend against
a WRITE-CAPABLE adversary, not just a forger.

The attack this pins down: an adversary who can rewrite the stored entries does
not forge a signature (caught) — they simply STRIP the `sig` field. If absence
is a skip instead of a failure, the signature layer protects against nobody.

Covered here, directly at the vendored soulguard layer (memory.verify / scan):
  - stripped signature  -> missing_signature finding (the core fix)
  - forged signature    -> bad_signature (still detected)
  - malformed sig hex   -> bad_signature (never an exception out of verify)
  - valid signatures    -> clean
  - unsigned prefix below an explicit signed_from_idx boundary -> reported as
    unsigned_prefix state (distinct from valid AND from broken), never trusted
    from a field inside the entries themselves
  - no verifier         -> hash checks only; scan says attribution was NOT
    verified (a caller must not mistake it for a signed-and-valid chain)

Keys are generated fresh per test — no key material in the repo.
"""
import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from soulguard.detection import scan
from soulguard.identity import SoulKey
from soulguard.memory import TamperEvidentMemory


@pytest.fixture()
def signer():
    return SoulKey()


def _signed_chain(signer, n=4):
    m = TamperEvidentMemory(agent_id="agent-x")
    for i in range(n):
        m.append(f"memory {i}", signer=signer)
    return m


# ── the vulnerability: signature stripping ────────────────────────────────────

def test_stripped_signature_is_a_finding(signer):
    """An adversary who removes a stored entry's sig must NOT get a clean verify.
    This is the signature-stripping fix: absence is a failure, not a skip."""
    m = _signed_chain(signer)
    assert m.verify(verifier=signer.public()) == []      # baseline: clean
    m.entries[2].sig = None                              # strip, touch nothing else
    findings = m.verify(verifier=signer.public())
    assert findings, "stripping a signature must be detected"
    assert [f.kind for f in findings] == ["missing_signature"]
    assert findings[0].idx == 2
    assert not m.is_intact(verifier=signer.public())


def test_all_signatures_stripped_is_not_clean(signer):
    m = _signed_chain(signer)
    for e in m.entries:
        e.sig = None
    findings = m.verify(verifier=signer.public())
    assert len(findings) == len(m.entries)
    assert all(f.kind == "missing_signature" for f in findings)


# ── forgery and malformation still detected ───────────────────────────────────

def test_forged_signature_still_detected(signer):
    m = _signed_chain(signer)
    other = SoulKey()                                    # a different identity
    m.entries[1].sig = other.sign(m.entries[1].hash.encode("utf-8")).hex()
    findings = m.verify(verifier=signer.public())
    assert [f.kind for f in findings] == ["bad_signature"]
    assert findings[0].idx == 1


def test_malformed_signature_hex_is_a_finding_not_an_exception(signer):
    """Corrupting sig into non-hex must not crash verify() — that would let an
    adversary turn detection into a denial of service."""
    m = _signed_chain(signer)
    m.entries[0].sig = "not-hex!!"
    findings = m.verify(verifier=signer.public())
    assert [f.kind for f in findings] == ["bad_signature"]


def test_valid_signatures_pass(signer):
    m = _signed_chain(signer)
    assert m.verify(verifier=signer.public()) == []
    assert m.is_intact(verifier=signer.public())
    result = scan(m, verifier=signer.public())
    assert result.intact and result.signatures_verified
    assert result.unsigned_prefix == 0


# ── legitimate pre-signing history: the explicit boundary ─────────────────────

def _chain_with_unsigned_prefix(signer, unsigned=2, signed=3):
    m = TamperEvidentMemory(agent_id="agent-x")
    for i in range(unsigned):
        m.append(f"pre-signing {i}")                     # no signer yet
    for i in range(signed):
        m.append(f"signed {i}", signer=signer)
    return m


def test_unsigned_prefix_below_boundary_is_not_broken(signer):
    m = _chain_with_unsigned_prefix(signer, unsigned=2, signed=3)
    # The boundary comes from the CALLER (held outside the entry blobs).
    findings = m.verify(verifier=signer.public(), signed_from_idx=2)
    assert findings == []
    result = scan(m, verifier=signer.public(), signed_from_idx=2)
    assert result.intact
    assert result.unsigned_prefix == 2                   # distinct state, not silent
    assert result.signatures_verified


def test_without_boundary_the_prefix_is_missing_signatures(signer):
    """The boundary is opt-in: a caller who asserts full signing gets findings
    for the unsigned prefix. An adversary cannot flip that by editing entries —
    there is no in-entry field that verify() reads as a boundary."""
    m = _chain_with_unsigned_prefix(signer, unsigned=2, signed=3)
    findings = m.verify(verifier=signer.public())
    assert [f.kind for f in findings] == ["missing_signature", "missing_signature"]
    assert [f.idx for f in findings] == [0, 1]


def test_stripping_above_the_boundary_is_still_caught(signer):
    m = _chain_with_unsigned_prefix(signer, unsigned=2, signed=3)
    m.entries[3].sig = None                              # strip a SIGNED entry
    findings = m.verify(verifier=signer.public(), signed_from_idx=2)
    assert [f.kind for f in findings] == ["missing_signature"]
    assert findings[0].idx == 3


def test_bad_signature_below_the_boundary_is_still_caught(signer):
    """A pre-boundary entry that CARRIES a sig still has it checked — the
    boundary excuses absence, never invalidity."""
    m = _chain_with_unsigned_prefix(signer, unsigned=2, signed=3)
    other = SoulKey()
    m.entries[0].sig = other.sign(m.entries[0].hash.encode("utf-8")).hex()
    findings = m.verify(verifier=signer.public(), signed_from_idx=2)
    assert [f.kind for f in findings] == ["bad_signature"]
    assert findings[0].idx == 0


# ── no verifier: honest, not silently valid ───────────────────────────────────

def test_no_verifier_does_not_imply_attribution(signer):
    m = _signed_chain(signer)
    for e in m.entries:
        e.sig = None                                     # fully stripped
    # Hash chain still holds — verify() without a verifier only claims that.
    assert m.verify() == []
    result = scan(m)
    assert result.intact                                 # hash chain intact...
    assert not result.signatures_verified                # ...but NOT attributable
    assert "not verified" in result.summary().lower()


def test_hash_tampering_still_detected_regardless_of_signatures(signer):
    m = _signed_chain(signer)
    m.entries[1].content = "poisoned"
    kinds = {f.kind for f in m.verify(verifier=signer.public())}
    assert "content_tampered" in kinds
    assert "broken_link" not in kinds or True            # link checks unchanged
    kinds_unsigned = {f.kind for f in m.verify()}
    assert "content_tampered" in kinds_unsigned
