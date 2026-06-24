"""SoulGuard quickstart — watch a memory-poisoning attack get caught.

Runs with zero dependencies (the core is pure standard library).
    python examples/quickstart.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from soulguard import TamperEvidentMemory, scan, issue_token, verify_token

print("=== SoulGuard quickstart ===\n")

# 1. An agent records some memories into a tamper-evident, hash-chained store.
mem = TamperEvidentMemory(agent_id="alfred")
mem.append("User asked to monitor the SOC alert queue.")
mem.append("IOC 8.8.8.8 observed in the network on 2026-06-20.")
mem.append("Remediation playbook RB-17 applied; ticket closed.")

print("1) Clean history:")
print("   " + scan(mem).summary())

# 2. An attacker poisons a 'trusted' memory (OWASP ASI06) — edits a stored entry in place.
print("\n2) Attacker silently rewrites memory #1 (the IOC sighting)...")
mem.entries[1].content = "No indicators of compromise were ever observed."  # the poisoning

# 3. SoulGuard turns the silent corruption into an alarm.
result = scan(mem)
print("   " + result.summary())
print(f"   intact={result.intact}  first_compromised_index={result.first_compromised_index}")

# 4. Capability-scoped governance: a least-privilege, short-lived action token.
print("\n3) Capability-scoped governance:")
secret = b"per-deployment-signing-secret"
tok = issue_token(secret, agent_id="alfred", scopes=["memory:read"], ttl_seconds=300)
print("   token grants memory:read ->", verify_token(secret, tok, "memory:read"))
print("   token grants tool:exec   ->", verify_token(secret, tok, "tool:exec"), "(correctly denied)")

print("\nDone. Poisoning detected, authority scoped. That's the trust layer.")
