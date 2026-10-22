# AGENTS.md

Instructions for AI coding agents working in this repository.

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
- No em-dashes in docs. Claims in the README must match the code on `main`.
- If you change README.md or docs/, regenerate `llms-full.txt` in the same change.

## Do not

- Publish to PyPI or add PyPI install instructions.
- Weaken `verify()` or `scan()` to pass a test.
- Commit secrets, hostnames, internal paths or personal emails.

## Done means

`python -m pytest` passes, the core-only run passes without optional packages installed, the
quickstart runs, and `check_install_docs.py soulguard` exits 0.
