"""ASI06 memory-poisoning detection -turn silent corruption into a raised alarm.

Wraps the tamper-evident memory's integrity check into a simple scan() that classifies
findings the way OWASP ASI06 (Memory & Context Poisoning) cares about:
  - content_tampered  : a stored memory was edited after the fact (classic poisoning)
  - broken_link       : an entry was injected/reordered out-of-band
  - bad_signature     : an entry's authorship was forged (with SoulKey verification)
  - missing_signature : an entry on a signed chain carries no signature at all -
                        the signature-stripping attack a write-capable adversary
                        mounts instead of forging (absence is a failure, not a skip)

Signature semantics (mirrors TamperEvidentMemory.verify):
  - no verifier: hash checks only. The result reports `signatures_verified=False`
    so a caller can never mistake an unverified chain for an attributable one.
  - verifier supplied: every entry from `signed_from_idx` on must be validly
    signed. Entries BELOW that boundary without a sig are legitimate pre-signing
    history: counted in `unsigned_prefix` (a distinct, visible state - neither a
    finding nor silently valid). The boundary must come from the caller / be held
    outside the entry blobs, never from a field an adversary could edit.
"""
from __future__ import annotations
from dataclasses import dataclass
from .memory import TamperEvidentMemory, Finding


@dataclass
class ScanResult:
    intact: bool
    findings: list          # list[Finding]
    checked: int
    # True only when a verifier was supplied - i.e. signatures were actually
    # checked. intact=True with signatures_verified=False means "hash chain
    # holds, attribution NOT verified", never "signed and valid".
    signatures_verified: bool = False
    # Entries below the caller-supplied signed_from_idx boundary that carry no
    # signature (legitimate pre-signing history) - reported, not hidden.
    unsigned_prefix: int = 0

    @property
    def first_compromised_index(self):
        return min((f.idx for f in self.findings), default=None)

    def summary(self) -> str:
        if self.intact:
            if self.signatures_verified:
                attribution = "signatures verified"
                if self.unsigned_prefix:
                    attribution += (f" ({self.unsigned_prefix} pre-signing "
                                    "entries below the signed boundary)")
            else:
                attribution = "signatures NOT verified (no verifier supplied)"
            return (f"OK -{self.checked} memory entries verified, "
                    f"no poisoning detected; {attribution}.")
        by_kind = {}
        for f in self.findings:
            by_kind.setdefault(f.kind, []).append(f.idx)
        parts = "; ".join(f"{k} at {v}" for k, v in by_kind.items())
        return (f"ALERT -poisoning detected in {len({f.idx for f in self.findings})} of "
                f"{self.checked} entries (first at #{self.first_compromised_index}): {parts}")


def scan(memory: TamperEvidentMemory, verifier=None,
         signed_from_idx: int = 0) -> ScanResult:
    findings = memory.verify(verifier=verifier, signed_from_idx=signed_from_idx)
    unsigned_prefix = 0
    if verifier is not None:
        unsigned_prefix = sum(1 for e in memory.entries
                              if e.sig is None and e.idx < signed_from_idx)
    return ScanResult(intact=not findings, findings=findings,
                      checked=len(memory.entries),
                      signatures_verified=verifier is not None,
                      unsigned_prefix=unsigned_prefix)
