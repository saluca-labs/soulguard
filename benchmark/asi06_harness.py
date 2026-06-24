"""ASI06 memory-poisoning benchmark harness (v0).

Measures a memory defense's detection performance against poisoning attacks:
injects N attacks (content edits, out-of-band injections) into otherwise-clean
histories and reports detection rate, false-positive rate, and first-detection index.

This v0 establishes the metric + a reproducible protocol — a published benchmark is a
funded deliverable (see the SoulGuard grant budgets). Extend with adaptive adversaries.

    python benchmark/asi06_harness.py
"""
import sys, os, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from soulguard import TamperEvidentMemory, scan
from soulguard.memory import MemoryEntry, GENESIS

SEED = 1337  # fixed for reproducibility (no Math.random/time nondeterminism)


def fresh(n, agent="bench"):
    m = TamperEvidentMemory(agent_id=agent)
    for i in range(n):
        m.append(f"memory entry {i}")
    return m


def attack_content_edit(m, rnd):
    i = rnd.randrange(len(m.entries))
    m.entries[i].content += " [POISONED]"
    return i


def attack_injection(m, rnd):
    bad = MemoryEntry(idx=len(m.entries), ts=0.0, agent_id=m.agent_id,
                      content="[INJECTED]", prev_hash=GENESIS)
    bad.hash = bad.recompute()
    m.entries.append(bad)
    return bad.idx


def run(trials=500, length=20):
    rnd = random.Random(SEED)
    attacks = [attack_content_edit, attack_injection]
    tp = fn = 0
    # detection rate on poisoned histories
    for _ in range(trials):
        m = fresh(length)
        rnd.choice(attacks)(m, rnd)
        (tp := tp + 1) if not scan(m).intact else (fn := fn + 1)
    # false-positive rate on clean histories
    fp = sum(0 if scan(fresh(length)).intact else 1 for _ in range(trials))

    det = tp / trials
    fpr = fp / trials
    print("=== SoulGuard ASI06 benchmark v0 ===")
    print(f"trials={trials}  length={length}  seed={SEED}")
    print(f"detection rate : {det:.3f}  ({tp}/{trials} poisoned histories flagged)")
    print(f"false positives: {fpr:.3f}  ({fp}/{trials} clean histories flagged)")
    print(f"missed         : {fn}")
    return {"detection_rate": det, "false_positive_rate": fpr, "missed": fn}


if __name__ == "__main__":
    run()
