#!/usr/bin/env python3
"""What n escalate-positives can support (inventory A1, DEC-053) — arithmetic, not a proposal.

P7 (prompts/P7.md) reports recall(escalate) with 1,000 seeded bootstrap resamples over the
gold set and McNemar B4-vs-B1 on paired per-cluster correctness. This prints, for n escalate
positives in a 300-cluster gold set: the bootstrap 95 % CI width at several true recalls (with
Wilson for comparison), the exact-McNemar best case (all discordant pairs one way), the minimum
detectable recall difference at power 0.80 under the normal approximation (Connor 1987) for
several discordance rates, and the n required for a target difference. A simulation of the
exact test at the tabulated points shows where the approximation is optimistic for small n.

    python3 scripts/escalate_power.py [--seed 20260904] [--gold 300] [--resamples 1000]
"""

from __future__ import annotations

import argparse
import math
import random

Z_A = 1.959964  # two-sided 0.05
Z_B = 0.841621  # power 0.80


def wilson(k: int, n: int, z: float = Z_A) -> tuple[float, float]:
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - h) / d, (c + h) / d


def bootstrap_recall(
    rng: random.Random, gold: int, n_pos: int, recall: float, resamples: int
) -> tuple[float, float]:
    tp = round(recall * n_pos)
    labels = [1] * n_pos + [0] * (gold - n_pos)
    pred = [1] * tp + [0] * (n_pos - tp) + [0] * (gold - n_pos)
    recalls = []
    for _ in range(resamples):
        idx = [rng.randrange(gold) for _ in range(gold)]
        pos = sum(labels[i] for i in idx)
        if pos:
            recalls.append(sum(1 for i in idx if labels[i] and pred[i]) / pos)
    recalls.sort()
    return recalls[int(0.025 * len(recalls))], recalls[int(0.975 * len(recalls)) - 1]


def n_for_mcnemar(delta: float, psi: float) -> float:
    """Pairs needed to detect a paired-proportion difference delta at discordance psi."""
    return (Z_A * math.sqrt(psi) + Z_B * math.sqrt(psi - delta * delta)) ** 2 / (delta * delta)


def mdd(n: int, psi: float) -> float:
    lo, hi = 0.001, psi - 1e-6
    for _ in range(100):
        mid = (lo + hi) / 2
        if n_for_mcnemar(mid, psi) > n:
            lo = mid
        else:
            hi = mid
    return hi


def exact_power(rng: random.Random, n: int, pb: float, pc: float, reps: int = 4000) -> float:
    hits = 0
    for _ in range(reps):
        b = c = 0
        for _ in range(n):
            u = rng.random()
            if u < pb:
                b += 1
            elif u < pb + pc:
                c += 1
        m = b + c
        if m == 0:
            continue
        k = min(b, c)
        p = min(1.0, 2 * sum(math.comb(m, i) for i in range(k + 1)) * 0.5**m)
        hits += p < 0.05
    return hits / reps


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seed", type=int, default=20260904)  # EVAL_SEED, prompts/P6.md
    ap.add_argument("--gold", type=int, default=300)
    ap.add_argument("--resamples", type=int, default=1000)
    args = ap.parse_args(argv)
    rng = random.Random(args.seed)
    sizes = (15, 20, 30, 50, 100)

    print(
        f"## Bootstrap 95 % CI on recall(escalate) — {args.gold}-cluster gold set, {args.resamples:,} resamples, seed {args.seed}\n"
    )
    print(
        "| n_pos | true recall | bootstrap CI | width | Wilson CI | width |\n|---|---|---|---|---|---|"
    )
    for n in sizes:
        for p in (0.6, 0.8, 0.9):
            lo, hi = bootstrap_recall(rng, args.gold, n, p, args.resamples)
            wl, wh = wilson(round(p * n), n)
            print(
                f"| {n} | {p:.1f} | {lo:.2f}–{hi:.2f} | {hi - lo:.2f} | {wl:.2f}–{wh:.2f} | {wh - wl:.2f} |"
            )

    b_min = next(b for b in range(1, 20) if 2 * 0.5**b < 0.05)
    print(
        f"\n## Exact McNemar, best case: all discordant pairs favour B4 (c = 0) → b ≥ {b_min} (p = {2 * 0.5 ** b_min:.4f})\n"
    )
    print("| n_pos | minimum recall(escalate) gain B4 over B1 that can reach p < 0.05 |\n|---|---|")
    for n in sizes:
        print(f"| {n} | {b_min / n:.2f} |")

    print(
        "\n## McNemar minimum detectable difference, power 0.80, α 0.05 (normal approximation), by discordance rate ψ\n"
    )
    print("| n_pos | ψ = 0.2 | ψ = 0.3 | ψ = 0.5 |\n|---|---|---|---|")
    for n in sizes + (175, 300):
        print(f"| {n} | " + " | ".join(f"{mdd(n, psi):.2f}" for psi in (0.2, 0.3, 0.5)) + " |")

    print("\n## n_pos required (power 0.80)\n")
    print("| target difference | ψ = 0.2 | ψ = 0.3 | ψ = 0.5 |\n|---|---|---|---|")
    for delta in (0.10, 0.15, 0.20, 0.30):
        print(
            f"| {delta:.2f} | "
            + " | ".join(str(math.ceil(n_for_mcnemar(delta, psi))) for psi in (0.2, 0.3, 0.5))
            + " |"
        )

    print("\n## Simulated power of the exact test at the tabulated MDD (ψ = 0.3, 4,000 reps)\n")
    print("| n_pos | MDD | power |\n|---|---|---|")
    for n in (15, 20, 30, 50):
        d = mdd(n, 0.3)
        print(f"| {n} | {d:.2f} | {exact_power(rng, n, (0.3 + d) / 2, (0.3 - d) / 2):.2f} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
