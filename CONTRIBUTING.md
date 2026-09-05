# Contributing to SoulGuard

SoulGuard is open public-goods AI-security infrastructure. Contributions welcome.

## Principles
- **Sovereignty first.** Anything that makes the user *less* the owner of their agent's memory/identity is out of scope.
- **Verifiable, not trusted.** New controls must be externally checkable (an auditor with the public material can verify them offline).
- **Dependency-light core.** The `memory`, `governance`, and `detection` modules stay standard-library only. Optional crypto/integration deps go in `optional-dependencies`.

## Dev setup
```bash
pip install -e ".[dev]"
python -m pytest            # or: python tests/test_soulguard.py
python examples/quickstart.py
python benchmark/asi06_harness.py
```

## What's most valuable right now
- Adaptive-adversary attacks for the ASI06 benchmark.
- Authorized-evolution-vs-tampering semantics (distinguishing benign memory drift from poisoning).
- MCP-compatible adapters.
- Independent review of the crypto and the threat model (`docs/THREAT_MODEL.md`).

## License
By contributing you agree your contributions are licensed under **Apache-2.0** (see `LICENSE`). Please don't submit code encumbered by patents you can't license under Apache-2.0's grant.

## Security
Found a vulnerability? Email **info@saluca.com** rather than opening a public issue.
