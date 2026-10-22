# AGENTS.md

Instructions for AI coding agents working in this repository.

## What this is

A small Python library: a SHA-256 hash-chained memory for one agent's history, Ed25519 and hybrid Ed25519 + ML-DSA-44 signing keys, HMAC capability tokens, and a `scan()` that classifies tampering. It is an integrity layer; it does not filter content, persist data, or enforce tokens for you.

## Read in this order

1. [README.md](README.md): the correction note at the top, then "How it works" and "Architecture".
2. [src/soulguard/memory.py](src/soulguard/memory.py): `entry_hash()`, `TamperEvidentMemory.append()` and `verify()`; the adversary model is in its module docstring.
3. [src/soulguard/detection.py](src/soulguard/detection.py): `scan()` and `ScanResult`, including `signatures_verified` and `unsigned_prefix`.
4. [src/soulguard/identity.py](src/soulguard/identity.py) and [governance.py](src/soulguard/governance.py): keys and tokens.
5. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what is and is not defended.

## What you can and cannot see

- You can see the whole library, its tests, the benchmark harness and the quickstart.
- You cannot see the production stack SoulGuard was extracted from; it is not public. A code comment in `memory.py` names a client module from it (`cp_client.HttpAuditSink`) that is not in this repo.
- There is no storage layer: a chain lives in memory and round-trips through `to_json()` and `from_json()`.
- Three source docstrings (`memory.py`, `identity.py`, `governance.py`) still carry the wording the README's 2026-10-22 correction withdrew. Trust the README and the code paths, not those docstrings.

## Using it as an agent

```bash
pip install "soulguard @ git+https://github.com/saluca-labs/soulguard@283d0192b29374859221e3d469182ff29c1ac16d"
```

```python
from soulguard import TamperEvidentMemory, scan
mem = TamperEvidentMemory(agent_id="agent-1")
mem.append("first fact")
head = mem.head                      # keep this outside the writer's reach to catch truncation
result = scan(mem)                   # pass verifier=key.public() to check signatures
print(result.intact, result.signatures_verified, result.summary())
```

Never install `soulguard` from PyPI: that project is not this one. Add `[pqc]` after `soulguard` for hybrid keys, which also need `cryptography` and `quantcrypt`.

## The only numbers to trust

| Number | Value | Source |
|---|---|---|
| Version | 0.1.0 | `__version__` in `src/soulguard/__init__.py`, `version` in `pyproject.toml` |
| Tests | 25 (7 + 2 + 11 + 5) | `def test_` in `tests/test_hybrid_identity.py`, `test_optional_imports.py`, `test_signature_absence.py`, `test_soulguard.py` |
| Entry hash | SHA-256, 64 hex characters; genesis is 64 zeros | `entry_hash()` and `GENESIS` in `memory.py` |
| Token default lifetime | 300 seconds | `ttl_seconds` default in `issue_token()`, `governance.py` |
| ASI06 benchmark v0 | 500 trials, length 20, seed 1337; detection 1.000, false positives 0.000 | `benchmark/asi06_harness.py`; output in `docs/img/asi06-benchmark-2026-10-22.txt`. A regression check of two attacks the chain catches by construction, not evidence against an adaptive adversary |
| Python | 3.9+ declared; CI on 3.10, 3.12, 3.13 | `pyproject.toml`, `.github/workflows/ci.yml` |

## Setup

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Test

```bash
python -m pytest -v                                         # full suite, needs the dev extras
PYTHONPATH=src python tests/test_soulguard.py               # core only, no dependencies
python examples/quickstart.py
python .github/scripts/check_install_docs.py soulguard     # no PyPI install instructions
```

Passing looks like: pytest reports every test passed (25 on 2026-10-22), `tests/test_soulguard.py`
ends with `5 tests passed.`, and `check_install_docs.py` prints nothing and exits 0. CI
(`.github/workflows/ci.yml`) runs the same three jobs.

## Conventions

- `memory.py`, `governance.py` and `detection.py` stay standard library only. Optional dependencies go
  in `[project.optional-dependencies]` and are imported lazily, catching `ImportError` only.
- Signature checks fail closed: a missing signature on a verified chain is a finding, never a skip.
  Do not add a code path that reads `signed_from_idx` from stored data.
- Install instructions in any doc are git installs from `github.com/saluca-labs/soulguard`, never a
  bare `pip install` of this package (CI enforces this).
- The README diagrams are Mermaid source traced from `memory.py`, `detection.py` and `__init__.py`.
  Change them when those paths change.
- No em-dashes in docs. Claims in the README must match the code on `main`.
- If you change README.md or docs/, regenerate `llms-full.txt` in the same change.

## Do not

- Publish to PyPI or add PyPI install instructions.
- Weaken `verify()` or `scan()` to pass a test.
- Commit secrets, hostnames, internal paths or personal emails.

## Done means

`python -m pytest` passes, the core-only run passes without optional packages installed, the
quickstart runs, and `check_install_docs.py soulguard` exits 0.
