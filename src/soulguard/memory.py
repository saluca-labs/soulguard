"""Tamper-evident agent memory — a hash-chained store where corruption is detectable.

Each memory entry is hash-chained to its predecessor (like a per-agent ledger), so any
later alteration of a stored memory breaks the chain and is *detected*, not silent.
This is the core defense against OWASP ASI06 (Memory Poisoning): an attacker who edits
an agent's "trusted" history can no longer do so invisibly.

Adversary model of the two layers:
  - The hash chain alone defends against an adversary who edits stored CONTENT but
    cannot rewrite the whole store consistently. It does NOT defend against a fully
    write-capable adversary - hashes contain no secret, so a rebuilt chain verifies.
  - The signature layer (append with a signer, verify with a verifier) defends
    against that write-capable adversary: they can rebuild hashes but cannot re-sign
    without the private key. For that to hold, verify() treats a MISSING signature
    exactly like a forged one - otherwise stripping the sig field would launder a
    rebuilt chain. Neither layer defends against an adversary who holds the private
    signing key, or who can also swap the trusted public key: pin verifier keys
    out-of-band.

Pure standard library (hashlib/json) — runs anywhere, no dependencies.
"""
from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, asdict, field
from typing import Optional

GENESIS = "0" * 64


def _canonical(obj: dict) -> bytes:
    """Deterministic serialization for hashing (stable key order, no whitespace drift)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entry_hash(idx: int, ts: float, agent_id: str, content: str, prev_hash: str) -> str:
    payload = {"idx": idx, "ts": ts, "agent_id": agent_id, "content": content, "prev_hash": prev_hash}
    return hashlib.sha256(_canonical(payload)).hexdigest()


@dataclass
class MemoryEntry:
    idx: int
    ts: float
    agent_id: str
    content: str
    prev_hash: str
    hash: str = ""
    sig: Optional[str] = None  # optional Ed25519 signature (see identity.py)

    def recompute(self) -> str:
        return entry_hash(self.idx, self.ts, self.agent_id, self.content, self.prev_hash)


@dataclass
class Finding:
    idx: int
    kind: str          # "content_tampered" | "broken_link" | "bad_signature" | "missing_signature"
    detail: str


@dataclass
class TamperEvidentMemory:
    """Append-only, hash-chained memory for a single agent's history."""
    agent_id: str
    entries: list = field(default_factory=list)

    @property
    def head(self) -> str:
        return self.entries[-1].hash if self.entries else GENESIS

    def append(self, content: str, ts: Optional[float] = None, signer=None) -> MemoryEntry:
        # Next idx = the last entry's idx + 1 (not len): for a gap-free chain this
        # EQUALS len(entries), so every full chain (central + all existing) is
        # byte-for-byte unchanged; it also lets a chain rebuilt from a COMPACTED
        # prefix (an acked-anchor + tail — see cp_client.HttpAuditSink) resume at
        # the correct idx instead of resetting. idx is baked into entry_hash, so
        # this only changes the DERIVED value, never any stored hash/sig.
        idx = (self.entries[-1].idx + 1) if self.entries else 0
        ts = ts if ts is not None else time.time()
        prev = self.head
        h = entry_hash(idx, ts, self.agent_id, content, prev)
        e = MemoryEntry(idx=idx, ts=ts, agent_id=self.agent_id, content=content, prev_hash=prev, hash=h)
        if signer is not None:           # optional cryptographic attribution
            e.sig = signer.sign(h.encode("utf-8")).hex()
        self.entries.append(e)
        return e

    def verify(self, verifier=None, signed_from_idx: int = 0) -> list:
        """Return a list of Findings. Empty list == intact history.

        Always detects content tampering (hash mismatch) and chain breaks
        (prev_hash mismatch). The signature layer is controlled by `verifier`:

        - `verifier is None`: signatures are NOT checked at all. An empty result
          means only that the hash chain holds - it says NOTHING about who wrote
          the entries. A write-capable adversary can rebuild a hash chain (hashes
          contain no secret), so never treat an unverified chain as attributable;
          detection.scan() surfaces this honestly via `signatures_verified`.
        - `verifier` supplied: this IS the assertion that entries are signed.
          Every entry at idx >= `signed_from_idx` must carry a valid signature:
          a missing sig is a `missing_signature` finding (a write-capable
          adversary who strips the sig field is exactly who signatures defend
          against - absence is a failure, not a skip), and an invalid or
          malformed sig is `bad_signature`. Entries below `signed_from_idx`
          that carry a sig are still checked; the boundary excuses absence,
          never invalidity.

        `signed_from_idx` marks legitimate pre-signing history (a chain that
        began before signing was enabled). It MUST come from the caller or be
        held outside the entry blobs - never read it from a stored field, or an
        adversary who can edit the store can silently widen the unsigned window.
        """
        findings: list = []
        prev = GENESIS
        for e in self.entries:
            if e.recompute() != e.hash:
                findings.append(Finding(e.idx, "content_tampered",
                                        "stored content does not match its hash (ASI06 poisoning)"))
            if e.prev_hash != prev:
                findings.append(Finding(e.idx, "broken_link",
                                        "prev_hash does not reference the prior entry (injection/reorder)"))
            if verifier is not None:
                if e.sig is None:
                    if e.idx >= signed_from_idx:
                        findings.append(Finding(e.idx, "missing_signature",
                                                "entry has no signature on a signed chain (stripped/rebuilt)"))
                else:
                    try:
                        ok = verifier.verify(e.hash.encode("utf-8"), bytes.fromhex(e.sig))
                    except Exception:
                        ok = False  # malformed sig must be a finding, not a crash
                    if not ok:
                        findings.append(Finding(e.idx, "bad_signature",
                                                "signature invalid (forged/altered)"))
            prev = e.hash
        return findings

    def is_intact(self, verifier=None, signed_from_idx: int = 0) -> bool:
        return not self.verify(verifier, signed_from_idx=signed_from_idx)

    def to_json(self) -> str:
        return json.dumps({"agent_id": self.agent_id, "entries": [asdict(e) for e in self.entries]}, indent=2)

    @classmethod
    def from_json(cls, s: str) -> "TamperEvidentMemory":
        d = json.loads(s)
        m = cls(agent_id=d["agent_id"])
        m.entries = [MemoryEntry(**e) for e in d["entries"]]
        return m
