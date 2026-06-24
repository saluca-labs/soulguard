"""Tamper-evident agent memory — a hash-chained store where corruption is detectable.

Each memory entry is hash-chained to its predecessor (like a per-agent ledger), so any
later alteration of a stored memory breaks the chain and is *detected*, not silent.
This is the core defense against OWASP ASI06 (Memory Poisoning): an attacker who edits
an agent's "trusted" history can no longer do so invisibly.

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
    kind: str          # "content_tampered" | "broken_link" | "bad_signature"
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
        idx = len(self.entries)
        ts = ts if ts is not None else time.time()
        prev = self.head
        h = entry_hash(idx, ts, self.agent_id, content, prev)
        e = MemoryEntry(idx=idx, ts=ts, agent_id=self.agent_id, content=content, prev_hash=prev, hash=h)
        if signer is not None:           # optional cryptographic attribution
            e.sig = signer.sign(h.encode("utf-8")).hex()
        self.entries.append(e)
        return e

    def verify(self, verifier=None) -> list:
        """Return a list of Findings. Empty list == intact, attributable history.
        Detects: content tampering (hash mismatch), chain breaks (prev_hash mismatch),
        and — if a verifier is supplied — bad/forged signatures."""
        findings: list = []
        prev = GENESIS
        for e in self.entries:
            if e.recompute() != e.hash:
                findings.append(Finding(e.idx, "content_tampered",
                                        "stored content does not match its hash (ASI06 poisoning)"))
            if e.prev_hash != prev:
                findings.append(Finding(e.idx, "broken_link",
                                        "prev_hash does not reference the prior entry (injection/reorder)"))
            if verifier is not None and e.sig is not None:
                if not verifier.verify(e.hash.encode("utf-8"), bytes.fromhex(e.sig)):
                    findings.append(Finding(e.idx, "bad_signature", "signature invalid (forged/altered)"))
            prev = e.hash
        return findings

    def is_intact(self, verifier=None) -> bool:
        return not self.verify(verifier)

    def to_json(self) -> str:
        return json.dumps({"agent_id": self.agent_id, "entries": [asdict(e) for e in self.entries]}, indent=2)

    @classmethod
    def from_json(cls, s: str) -> "TamperEvidentMemory":
        d = json.loads(s)
        m = cls(agent_id=d["agent_id"])
        m.entries = [MemoryEntry(**e) for e in d["entries"]]
        return m
