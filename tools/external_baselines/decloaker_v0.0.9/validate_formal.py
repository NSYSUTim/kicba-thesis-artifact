#!/usr/bin/env python3
"""Independently validate and summarize the formal Decloaker comparison."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


STATES = ("unloaded", "filldir_pass", "filldir_active", "filldir_hiding")
EXPECTED_HASHES = {
    "runner": "06f0eee72ceae2d39cb715ab7a79111ca441a8ca0bfc91e6cb154d40bbfa371a",
    "decloaker_binary": "a275fea94173b48bb15bab215965cbf2cce76e12137f27248bb60696864428ca",
    "module_filldir_pass": "7689eb945c580a9889e727d310e791ba670852adc58b2355ea55f3c412f46949",
    "module_filldir_active": "c1c38de4ad476210b939b6c11a0f139475d68bb912b233e00a2740a58bee52e9",
    "module_filldir_hiding": "02f826eeade88af01c85f1c3098dee7bc4c3038f672fa69d4b5442184471e60c",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def describe_ns(values: list[int]) -> dict[str, float | int]:
    return {
        "count": len(values),
        "mean_ms": statistics.fmean(values) / 1_000_000,
        "median_ms": statistics.median(values) / 1_000_000,
        "min_ms": min(values) / 1_000_000,
        "max_ms": max(values) / 1_000_000,
        "sum_s": sum(values) / 1_000_000_000,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    errors: list[str] = []
    rows: list[dict] = []
    boot_ids: list[str] = []
    kernels: set[str] = set()
    file_hashes: dict[str, str] = {}

    for boot_index in range(1, 10):
        boot_dir = args.root / f"boot_{boot_index:02d}"
        payload = boot_dir / "campaign.json.gz"
        sidecar = boot_dir / "campaign.sha256"
        if not payload.is_file() or not sidecar.is_file():
            errors.append(f"boot_{boot_index:02d}: missing payload or sidecar")
            continue

        actual_hash = sha256(payload)
        file_hashes[f"boot_{boot_index:02d}"] = actual_hash
        expected_hash = sidecar.read_text(encoding="utf-8").split()[0]
        if actual_hash != expected_hash:
            errors.append(f"boot_{boot_index:02d}: sidecar hash mismatch")

        with gzip.open(payload, "rt", encoding="utf-8") as stream:
            record = json.load(stream)
        env = record.get("environment", {})
        if env.get("boot_index") != boot_index or env.get("boot_total") != 9:
            errors.append(f"boot_{boot_index:02d}: boot index/total mismatch")
        if env.get("filesystem") != "ext4":
            errors.append(f"boot_{boot_index:02d}: filesystem is not ext4")
        boot_ids.append(env.get("boot_id", ""))
        kernels.add(env.get("kernel", ""))
        if not record.get("success") or record.get("failures"):
            errors.append(f"boot_{boot_index:02d}: campaign failure recorded")
        if record.get("source_hashes") != EXPECTED_HASHES:
            errors.append(f"boot_{boot_index:02d}: source hash mismatch")

        boot_rows = record.get("rows", [])
        if len(boot_rows) != 80:
            errors.append(f"boot_{boot_index:02d}: expected 80 rows, got {len(boot_rows)}")
        counts = Counter(row.get("state") for row in boot_rows)
        if counts != Counter({state: 20 for state in STATES}):
            errors.append(f"boot_{boot_index:02d}: state counts mismatch: {dict(counts)}")
        for row in boot_rows:
            state = row.get("state")
            if row.get("expected_positive") != (state == "filldir_hiding"):
                errors.append(f"boot_{boot_index:02d}: label mismatch")
            if row.get("returncode") != 0:
                errors.append(f"boot_{boot_index:02d}: nonzero return code")
        rows.extend(boot_rows)

    if len(set(boot_ids)) != 9 or "" in boot_ids:
        errors.append(f"expected 9 unique nonempty boot IDs, got {len(set(boot_ids))}")
    if len(kernels) != 1 or "" in kernels:
        errors.append(f"expected one nonempty kernel, got {sorted(kernels)}")

    tp = sum(row["expected_positive"] and row["detected"] for row in rows)
    fn = sum(row["expected_positive"] and not row["detected"] for row in rows)
    fp = sum(not row["expected_positive"] and row["detected"] for row in rows)
    tn = sum(not row["expected_positive"] and not row["detected"] for row in rows)
    recall = tp / (tp + fn) if tp + fn else None
    precision = tp / (tp + fp) if tp + fp else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else None

    elapsed: dict[str, list[int]] = defaultdict(list)
    for row in rows:
        elapsed[row["state"]].append(row["elapsed_ns"])

    summary = {
        "status": "valid" if not errors else "invalid",
        "errors": errors,
        "root": str(args.root.resolve()),
        "boots": len(set(boot_ids)),
        "boot_ids": boot_ids,
        "kernels": sorted(kernels),
        "rows": len(rows),
        "state_counts": dict(Counter(row["state"] for row in rows)),
        "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "metrics": {
            "recall": recall,
            "precision": precision,
            "f1": f1,
            "false_positive_rate": fpr,
        },
        "timing_by_state": {
            state: describe_ns(elapsed[state]) for state in STATES if elapsed[state]
        },
        "file_sha256": file_hashes,
        "expected_source_hashes": EXPECTED_HASHES,
    }
    rendered = json.dumps(summary, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
