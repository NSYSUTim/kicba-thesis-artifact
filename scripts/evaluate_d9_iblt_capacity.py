#!/usr/bin/env python3
"""Development-only capacity sweep for the D9 IBLT configuration."""

from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timezone
from pathlib import Path

from kicba.reconciliation import EntryToken, IBLT, MultisetFingerprint


D_TOTALS = (1, 2, 4, 8, 16, 32, 64, 128, 256, 512)
CELL_FACTORS = (1, 2, 4, 8)
MODES = ("missing", "substitution")


def _next_power_of_two(value: int) -> int:
    return 1 << (max(4, value) - 1).bit_length()


def _tokens(rng: random.Random, count: int, used: set[int]) -> list[EntryToken]:
    result = []
    while len(result) < count:
        key = rng.getrandbits(64)
        if key in used:
            continue
        used.add(key)
        result.append(EntryToken(key, rng.getrandbits(63) + 1, rng.randrange(16)))
    return result


def run_cell(mode: str, difference: int, factor: int, trials: int, seed: int):
    cell_count = _next_power_of_two(difference * factor)
    successes = 0
    incorrect_successes = 0
    fingerprint_false_equals = 0
    residuals = []
    for trial in range(trials):
        rng = random.Random(seed + trial * 104729)
        seed1 = rng.getrandbits(64)
        seed2 = rng.getrandbits(64)
        used: set[int] = set()
        if mode == "missing":
            upstream = _tokens(rng, difference, used)
            downstream = []
        else:
            upstream_count = (difference + 1) // 2
            downstream_count = difference // 2
            upstream = _tokens(rng, upstream_count, used)
            downstream = _tokens(rng, downstream_count, used)
        if (
            MultisetFingerprint.from_tokens(upstream).as_tuple()
            == MultisetFingerprint.from_tokens(downstream).as_tuple()
        ):
            fingerprint_false_equals += 1
        table = IBLT(cell_count, seed1, seed2)
        for token in upstream:
            table.add(token, 1)
        for token in downstream:
            table.add(token, -1)
        decoded = table.decode()
        exact = (
            set(decoded.upstream_only) == set(upstream)
            and set(decoded.downstream_only) == set(downstream)
        )
        if decoded.success and exact:
            successes += 1
        elif decoded.success:
            incorrect_successes += 1
        residuals.append(decoded.residual_cells)
    return {
        "mode": mode,
        "symmetric_difference": difference,
        "requested_cell_factor": factor,
        "cell_count": cell_count,
        "actual_cells_per_difference": cell_count / difference,
        "trials": trials,
        "decode_successes": successes,
        "decode_success_rate": successes / trials,
        "incorrect_successes": incorrect_successes,
        "fingerprint_false_equals": fingerprint_false_equals,
        "mean_residual_cells": sum(residuals) / trials,
        "max_residual_cells": max(residuals),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--trials", default=128, type=int)
    parser.add_argument("--seed", default=12009, type=int)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.mkdir(parents=True)
    rows = []
    for mode_index, mode in enumerate(MODES):
        for difference in D_TOTALS:
            for factor in CELL_FACTORS:
                rows.append(run_cell(
                    mode, difference, factor, args.trials,
                    args.seed + mode_index * 10_000_019 + difference * 1009 + factor,
                ))
    if any(row["incorrect_successes"] for row in rows):
        raise RuntimeError("IBLT produced an incorrect successful decode")
    record = {
        "schema_version": 1,
        "evidence_role": "development_capacity_sweep_not_confirmatory",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "trials_per_cell": args.trials,
        "rows": rows,
    }
    (args.output / "capacity.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    with (args.output / "capacity.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({
        "output": str(args.output),
        "cells": len(rows),
        "trials": len(rows) * args.trials,
        "incorrect_successes": 0,
    }, indent=2))


if __name__ == "__main__":
    main()
