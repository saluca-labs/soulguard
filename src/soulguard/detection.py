"""ASI06 memory-poisoning detection -turn silent corruption into a raised alarm.

Wraps the tamper-evident memory's integrity check into a simple scan() that classifies
findings the way OWASP ASI06 (Memory & Context Poisoning) cares about:
  - content_tampered : a stored memory was edited after the fact (classic poisoning)
  - broken_link      : an entry was injected/reordered out-of-band
  - bad_signature    : an entry's authorship was forged (with SoulKey verification)
"""
from __future__ import annotations
from dataclasses import dataclass
from .memory import TamperEvidentMemory, Finding


@dataclass
class ScanResult:
    intact: bool
    findings: list          # list[Finding]
    checked: int

    @property
    def first_compromised_index(self):
        return min((f.idx for f in self.findings), default=None)

    def summary(self) -> str:
        if self.intact:
            return f"OK -{self.checked} memory entries verified, no poisoning detected."
        by_kind = {}
        for f in self.findings:
            by_kind.setdefault(f.kind, []).append(f.idx)
        parts = "; ".join(f"{k} at {v}" for k, v in by_kind.items())
        return (f"ALERT -poisoning detected in {len({f.idx for f in self.findings})} of "
                f"{self.checked} entries (first at #{self.first_compromised_index}): {parts}")


def scan(memory: TamperEvidentMemory, verifier=None) -> ScanResult:
    findings = memory.verify(verifier=verifier)
    return ScanResult(intact=not findings, findings=findings, checked=len(memory.entries))
