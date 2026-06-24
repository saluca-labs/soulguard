# SoulGuard

**An open trust layer for AI-agent memory and identity.** Tamper-evident memory, per-agent cryptographic identity, capability-scoped governance, and OWASP-**ASI06** memory-poisoning detection — so stateful agents can't be silently corrupted into acting on a falsified history.

Apache-2.0 · by [Saluca LLC](https://saluca.com) · extracted from the production stack that runs **Alfred**, a sovereign agentic operating partner.

---

## Why

AI agents became *stateful* — they carry persistent **memory**, a durable **identity**, and tool access. That state is also the new attack surface. In 2026 OWASP named **Memory Poisoning (ASI06)** a top-10 agentic risk: once memory is the substrate, an injected lie persists across sessions and the agent later acts on it with full authority — the machine equivalent of confabulation. Input-only guardrails don't see the corrupted state that already lives inside the agent.

SoulGuard makes agent memory and identity **first-class, verifiable, owned primitives**:

| Module | What it does |
|---|---|
| `memory` | **Hash-chained, tamper-evident memory** — any later edit breaks the chain and is *detected*, not silent. |
| `identity` | **Per-agent cryptographic identity (SoulKeys, Ed25519)** — sign memories/messages; catch impersonation & persona drift. |
| `governance` | **Capability-scoped, JIT, least-privilege tokens** — even a partially-compromised agent can't exceed its authority. |
| `detection` | **ASI06 scan** — turns silent poisoning into a classified alarm (content-tampered / injection / forged-signature). |

## Install / run (zero dependencies for the core)

```bash
# core (memory + governance + detection) is pure standard library
python examples/quickstart.py        # watch a poisoning attack get caught
python tests/test_soulguard.py       # run the tests
python benchmark/asi06_harness.py    # ASI06 detection benchmark v0

# identity (SoulKeys) needs cryptography:
pip install cryptography
```

## 30-second example

```python
from soulguard import TamperEvidentMemory, scan

mem = TamperEvidentMemory(agent_id="alfred")
mem.append("IOC 8.8.8.8 observed on 2026-06-20.")
mem.append("Playbook RB-17 applied; ticket closed.")

scan(mem).intact            # True — clean history

mem.entries[0].content = "No IOCs were ever observed."   # ASI06 poisoning
print(scan(mem).summary())  # ALERT — poisoning detected ... first at #0
```

Add cryptographic attribution:

```python
from soulguard import SoulKey, TamperEvidentMemory, scan
key = SoulKey()
mem = TamperEvidentMemory(agent_id=key.agent_id)
mem.append("signed memory", signer=key)
scan(mem, verifier=key.public()).intact   # True; a forged sig would flag bad_signature
```

## Status

v0.1 — a working core + a reproducible ASI06 benchmark protocol. Hardening, a formal third-party security audit, expanded reference implementations, MCP adapters, and a published adversarial benchmark are the funded roadmap (this library is open public-goods infrastructure; see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)).

## Design principles

- **Local-first / sovereign** — runs where *you* control it; no platform owns your agent's memory.
- **Verifiable, not trusted** — integrity is checkable, not asserted.
- **Dependency-light core** — the memory/governance/detection core is standard-library only.

## License

Apache-2.0. The patent grant covers the released SoulGuard code; Saluca's broader patent portfolio is separate.

---
*SoulGuard is part of Saluca's thesis: an AI partner for everyone — **and you own it**.*
