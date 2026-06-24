# SoulGuard Threat Model — Agent Memory Poisoning (OWASP ASI06)

*v0, 2026-06-24. Scope: the integrity and attributability of a stateful AI agent's persistent memory and identity. Maps to OWASP Top 10 for Agentic Applications **ASI06 — Memory & Context Poisoning**.*

## Assets to protect
1. **Agent memory** — the persistent record an agent reads back and acts on.
2. **Agent identity** — which agent authored a memory or action (non-person-entity identity).
3. **Agent authority** — the set of tool actions an agent may take.

## Adversary
A party who can write to, or tamper with, an agent's memory store or message stream — via indirect prompt injection (the "lethal trifecta": private data + untrusted content + outbound action), a compromised tool/integration, a malicious co-agent, or storage-layer access. Goal: make the agent later act on a falsified "trusted" history, or act with an identity/authority it shouldn't have, **without detection**.

## Attack classes (and SoulGuard's response)
| # | Attack | Example | SoulGuard control | Detected as |
|---|---|---|---|---|
| A1 | **Content tampering** | Edit a stored memory after the fact ("no IOC was seen") | Hash-chained entries; stored content must match its hash | `content_tampered` |
| A2 | **Injection / reorder** | Splice a forged memory into history, or reorder entries | Each entry's `prev_hash` must reference the true prior entry | `broken_link` |
| A3 | **Impersonation / persona hijack** | Attribute a memory/action to another agent | Per-agent Ed25519 SoulKey signatures over entry hashes | `bad_signature` |
| A4 | **Authority over-reach** | A poisoned agent invokes tools beyond its role | Capability-scoped, short-TTL, signed tokens (least privilege) | token verification fails |
| A5 | **Stale / replayed authority** | Reuse an old capability token | TTL expiry on tokens | token verification fails |

## What SoulGuard does and does not do
**Does:** make A1–A3 *detectable* (silent corruption → raised alarm) and A4–A5 *preventable* (least-privilege, expiring authority); keep the substrate local-first and owned; provide a reproducible ASI06 detection benchmark.
**Does not (v0, residual risk):** prevent the *initial* injection at the input boundary (that's the prompt-firewall layer's job — SoulGuard is the integrity layer beneath it); distinguish *malicious* edits from *authorized* memory evolution at the semantic level (v0 treats the chain as append-only; authorized mutation = a new, signed entry, not an in-place edit); defend a fully-compromised host that holds the signing keys (key custody/HSM is out of scope for v0).

## Trust & key custody assumptions
- The signing secret (governance) and SoulKey private keys are held in the operator's control boundary (local-first). Compromise of the key store is out of scope; SoulGuard is designed so the *memory record itself* is verifiable independent of any single platform.
- Verification is offline-checkable: anyone with the public key + the chain can prove integrity without trusting a service.

## Benchmark protocol (ASI06 v0)
`benchmark/asi06_harness.py` injects A1/A2 attacks into otherwise-clean histories (fixed seed for reproducibility) and reports **detection rate**, **false-positive rate**, and **first-detection index**. The funded roadmap extends this to **adaptive adversaries** and authorized-evolution-vs-tampering precision/recall — the open, measurable benchmark the field currently lacks.

## Roadmap (funded deliverables)
Formal third-party security audit · adaptive-adversary benchmark · MCP-compatible reference adapters · authorized-evolution semantics (distinguishing benign drift from tampering) · key-custody integration (HSM/TPM).
