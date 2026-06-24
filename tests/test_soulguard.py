"""SoulGuard tests — run with: python -m pytest  (or python tests/test_soulguard.py)"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from soulguard import TamperEvidentMemory, scan, issue_token, verify_token


def _mem():
    m = TamperEvidentMemory(agent_id="t")
    m.append("a"); m.append("b"); m.append("c")
    return m


def test_clean_chain_is_intact():
    assert scan(_mem()).intact is True


def test_content_tampering_is_detected():
    m = _mem()
    m.entries[1].content = "POISONED"
    r = scan(m)
    assert r.intact is False
    assert r.first_compromised_index == 1
    assert any(f.kind == "content_tampered" for f in r.findings)


def test_injection_breaks_the_chain():
    m = _mem()
    from soulguard.memory import MemoryEntry, entry_hash, GENESIS
    # inject a forged entry at the end with a bogus prev_hash
    bad = MemoryEntry(idx=3, ts=0.0, agent_id="t", content="inject", prev_hash=GENESIS)
    bad.hash = bad.recompute()
    m.entries.append(bad)
    assert any(f.kind == "broken_link" for f in scan(m).findings)


def test_roundtrip_json_preserves_integrity():
    m = _mem()
    m2 = TamperEvidentMemory.from_json(m.to_json())
    assert scan(m2).intact is True


def test_capability_token_scope_and_expiry():
    s = b"secret"
    tok = issue_token(s, "t", ["memory:read"], ttl_seconds=300, now=1000.0)
    assert verify_token(s, tok, "memory:read", now=1000.0) is True
    assert verify_token(s, tok, "tool:exec", now=1000.0) is False      # scope enforced
    assert verify_token(s, tok, "memory:read", now=2000.0) is False    # expired
    assert verify_token(b"wrong", tok, "memory:read", now=1000.0) is False  # forged


if __name__ == "__main__":
    fns = [v for k, v in dict(globals()).items() if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
