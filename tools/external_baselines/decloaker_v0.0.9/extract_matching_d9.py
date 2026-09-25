#!/usr/bin/env python3
"""Extract the D9 subset matching the formal Decloaker state matrix."""

from __future__ import annotations

import argparse
import gzip
import json
from collections import Counter
from pathlib import Path


STATES = ("unloaded", "filldir_pass", "filldir_active", "filldir_hiding")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    errors: list[str] = []
    rows: list[dict] = []
    boot_ids: list[str] = []
    source_hashes = None
    for boot_index in range(1, 10):
        path = args.root / f"boot_{boot_index:02d}" / "campaign.json.gz"
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            record = json.load(stream)
        parameters = record["parameters"]
        if (
            parameters["visible"] != 512
            or parameters["difference"] != 16
            or parameters["iterations_per_batch"] != 20
        ):
            errors.append(f"boot_{boot_index:02d}: fixture/iteration mismatch")
        if record["environment"]["boot_index"] != boot_index:
            errors.append(f"boot_{boot_index:02d}: boot index mismatch")
        boot_ids.append(record["environment"]["boot_id"])
        if source_hashes is None:
            source_hashes = record["source_hashes"]
        elif source_hashes != record["source_hashes"]:
            errors.append(f"boot_{boot_index:02d}: source hash mismatch")

        selected = [
            batch for batch in record["batches"]
            if batch["state"] in STATES
            and batch["condition"] == "baseline"
            and batch["buffer_size"] == 65536
        ]
        if Counter(batch["state"] for batch in selected) != Counter(STATES):
            errors.append(f"boot_{boot_index:02d}: selected state mismatch")
        for batch in selected:
            if not batch["treatment_valid"] or not batch["transaction_valid"]:
                errors.append(f"boot_{boot_index:02d}: invalid selected batch")
            for transaction in batch["transactions"]:
                rows.append({
                    "boot_index": boot_index,
                    "state": batch["state"],
                    "expected_positive": batch["state"] == "filldir_hiding",
                    "detected": transaction["difference_detected"],
                    "valid": transaction["measurement_valid"] and transaction["configuration_valid"],
                })

    state_counts = Counter(row["state"] for row in rows)
    if state_counts != Counter({state: 180 for state in STATES}):
        errors.append(f"state counts mismatch: {dict(state_counts)}")
    if len(set(boot_ids)) != 9:
        errors.append("boot IDs are not unique")
    if any(not row["valid"] for row in rows):
        errors.append("invalid transaction in selected subset")

    tp = sum(row["expected_positive"] and row["detected"] for row in rows)
    fn = sum(row["expected_positive"] and not row["detected"] for row in rows)
    fp = sum(not row["expected_positive"] and row["detected"] for row in rows)
    tn = sum(not row["expected_positive"] and not row["detected"] for row in rows)
    recall = tp / (tp + fn)
    fpr = fp / (fp + tn)
    precision = tp / (tp + fp) if tp + fp else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0

    output = {
        "status": "valid" if not errors else "invalid",
        "errors": errors,
        "selection": {
            "states": list(STATES),
            "condition": "baseline",
            "buffer_size": 65536,
            "visible": 512,
            "difference": 16,
        },
        "boots": len(set(boot_ids)),
        "boot_ids": boot_ids,
        "rows": len(rows),
        "state_counts": dict(state_counts),
        "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "metrics": {
            "recall": recall,
            "false_positive_rate": fpr,
            "precision": precision,
            "f1": f1,
        },
        "source_hashes": source_hashes,
    }
    rendered = json.dumps(output, ensure_ascii=False, indent=2)
    args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
