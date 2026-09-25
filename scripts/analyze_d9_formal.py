#!/usr/bin/env python3
"""Locked confirmatory analysis for D9 reconciliation campaigns."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path


PROTOCOL = "D9-reconciliation-campaign-r1-2026-09-24"
STATES = (
    "unloaded", "filldir_pass", "filldir_active", "filldir_hiding",
    "getdents_pass", "getdents_active", "getdents_hiding",
    "getdents_substitution", "policy_filter",
)
CONTROL_STATES = {
    "unloaded", "filldir_pass", "filldir_active",
    "getdents_pass", "getdents_active",
}
DIFFERENCE_STATES = set(STATES) - CONTROL_STATES
CONDITIONS = ("baseline", "cpu", "memory", "mixed")
BUFFERS = (128, 256, 4096, 65536)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float]:
    if total <= 0:
        return [float("nan"), float("nan")]
    p = successes / total
    denominator = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / denominator
    half = z * math.sqrt(
        p * (1.0 - p) / total + z * z / (4.0 * total * total)
    ) / denominator
    return [max(0.0, center - half), min(1.0, center + half)]


def _rate(successes: int, total: int) -> dict:
    return {
        "successes": successes,
        "total": total,
        "rate": successes / total if total else None,
        "wilson_95": _wilson(successes, total) if total else None,
    }


def _load_campaign(path: Path) -> dict:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def _timing_feature(batch: dict) -> float:
    values = [int(tx["userspace"]["scan_ns"]) for tx in batch["transactions"]]
    if len(values) != 20 or min(values) <= 0:
        raise ValueError("formal timing batch lacks 20 positive observations")
    return math.log(float(statistics.median(values)))


def _binary_metrics(predictions: list[dict], key: str) -> dict:
    tp = sum(row["positive"] and row[key] for row in predictions)
    fn = sum(row["positive"] and not row[key] for row in predictions)
    fp = sum(not row["positive"] and row[key] for row in predictions)
    tn = sum(not row["positive"] and not row[key] for row in predictions)
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "recall": recall, "recall_wilson_95": _wilson(tp, tp + fn),
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "fpr_wilson_95": _wilson(fp, fp + tn),
        "precision": precision, "f1": f1,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--timing-model", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    timing = json.loads(args.timing_model.read_text(encoding="utf-8"))
    failures: list[str] = []
    if _sha256(args.timing_model) != lock.get("files", {}).get("timing_model"):
        failures.append("timing model hash mismatch")
    if _sha256(Path(__file__)) != lock.get("files", {}).get("analysis_core"):
        failures.append("analysis core hash mismatch")
    expected_sources = lock.get("runtime_source_hashes", {})
    paths = sorted(args.input.glob("boot_*/campaign.json.gz"))
    if len(paths) != 9:
        failures.append(f"expected 9 campaign files, got {len(paths)}")

    campaigns = []
    predictions = []
    transaction_counts = Counter()
    boot_ids = set()
    for path in paths:
        record = _load_campaign(path)
        boot_index = int(record.get("environment", {}).get("boot_index", -1))
        if record.get("protocol_revision") != PROTOCOL:
            failures.append(f"boot {boot_index}: protocol mismatch")
        if record.get("role") != "formal" or not record.get("success"):
            failures.append(f"boot {boot_index}: unsuccessful/non-formal campaign")
        if record.get("source_hashes") != expected_sources:
            failures.append(f"boot {boot_index}: runtime source hashes mismatch")
        boot_id = record.get("environment", {}).get("boot_id")
        if not boot_id or boot_id in boot_ids:
            failures.append(f"boot {boot_index}: absent or duplicate boot id")
        boot_ids.add(boot_id)
        parameters = record.get("parameters", {})
        if record.get("environment", {}).get("boot_total") != 9:
            failures.append(f"boot {boot_index}: unexpected boot total")
        if (
            parameters.get("iterations_per_batch") != 20
            or parameters.get("repeats_per_cell") != 1
            or parameters.get("visible") != 512
            or parameters.get("difference") != 16
            or parameters.get("cells") != 256
            or tuple(parameters.get("buffers", ())) != BUFFERS
            or tuple(parameters.get("conditions", ())) != CONDITIONS
        ):
            failures.append(f"boot {boot_index}: design parameters mismatch")
        expected_order = STATES[(boot_index - 1) % len(STATES):] + STATES[:(boot_index - 1) % len(STATES)]
        if tuple(parameters.get("state_order", ())) != expected_order:
            failures.append(f"boot {boot_index}: state order mismatch")
        batches = record.get("batches", [])
        if len(batches) != len(STATES) * len(CONDITIONS) * len(BUFFERS):
            failures.append(f"boot {boot_index}: batch count mismatch")
        if [batch.get("position") for batch in batches] != list(range(len(batches))):
            failures.append(f"boot {boot_index}: positions incomplete")
        design_seen = Counter()
        for batch in batches:
            state = batch.get("state")
            condition = batch.get("condition")
            buffer_size = int(batch.get("buffer_size", -1))
            design_seen[(state, condition, buffer_size)] += 1
            transactions = batch.get("transactions", [])
            if (
                state not in STATES
                or condition not in CONDITIONS
                or buffer_size not in BUFFERS
                or len(transactions) != 20
                or not batch.get("treatment_valid")
                or not batch.get("transaction_valid")
                or batch.get("batch_failures")
            ):
                failures.append(
                    f"boot {boot_index} position {batch.get('position')}: invalid batch"
                )
            positive = state in DIFFERENCE_STATES
            for tx in transactions:
                expected = bool(tx.get("expected_difference"))
                if expected != positive:
                    failures.append(
                        f"boot {boot_index} position {batch.get('position')}: truth mismatch"
                    )
                transaction_counts["total"] += 1
                transaction_counts["positive" if positive else "control"] += 1
                transaction_counts["invalid"] += not bool(tx.get("measurement_valid"))
                transaction_counts["decode_success"] += bool(tx.get("decode_success"))
                transaction_counts["decoded_exact"] += bool(tx.get("decoded_exact"))
                transaction_counts["incorrect_success"] += bool(tx.get("incorrect_success"))
                if positive:
                    transaction_counts["positive_decode_success"] += bool(tx.get("decode_success"))
                    transaction_counts["positive_decoded_exact"] += bool(tx.get("decoded_exact"))
            key = f"{condition}|{buffer_size}"
            threshold_mad = timing.get("thresholds_mad", {}).get(key)
            threshold_envelope = timing.get("thresholds_envelope", {}).get(key)
            if threshold_mad is None or threshold_envelope is None:
                failures.append(f"missing timing thresholds {key}")
                threshold_mad = threshold_envelope = float("inf")
            feature = _timing_feature(batch)
            predictions.append({
                "boot_index": boot_index,
                "position": batch.get("position"),
                "state": state,
                "condition": condition,
                "buffer_size": buffer_size,
                "positive": positive,
                "d9_alert": any(bool(tx.get("difference_detected")) for tx in transactions),
                "d8_count_alert": any(bool(tx.get("d8_count_alert")) for tx in transactions),
                "timing_mad_alert": feature > float(threshold_mad),
                "timing_envelope_alert": feature > float(threshold_envelope),
                "timing_feature": feature,
                "timing_mad_threshold": float(threshold_mad),
                "timing_envelope_threshold": float(threshold_envelope),
            })
        if len(design_seen) != len(STATES) * len(CONDITIONS) * len(BUFFERS) or any(
            count != 1 for count in design_seen.values()
        ):
            failures.append(f"boot {boot_index}: factorial cells incomplete/duplicated")
        campaigns.append({
            "path": str(path), "boot_index": boot_index, "boot_id": boot_id,
            "hash_seed1": parameters.get("hash_seed1"),
            "hash_seed2": parameters.get("hash_seed2"),
            "sha256": _sha256(path),
        })

    if {row["boot_index"] for row in campaigns} != set(range(1, 10)):
        failures.append("boot indices are not exactly 1..9")
    if len({(row["hash_seed1"], row["hash_seed2"]) for row in campaigns}) != len(campaigns):
        failures.append("per-boot hash seed pairs are not unique")

    state_metrics = {}
    for state in STATES:
        rows = [row for row in predictions if row["state"] == state]
        state_metrics[state] = {
            method: _rate(sum(bool(row[method]) for row in rows), len(rows))
            for method in (
                "d9_alert", "d8_count_alert", "timing_mad_alert",
                "timing_envelope_alert",
            )
        }
    per_boot_control_fpr = {}
    for boot_index in range(1, 10):
        rows = [
            row for row in predictions
            if row["boot_index"] == boot_index and not row["positive"]
        ]
        per_boot_control_fpr[str(boot_index)] = _rate(
            sum(row["d9_alert"] for row in rows), len(rows)
        )
    method_metrics = {
        method: _binary_metrics(predictions, method)
        for method in (
            "d9_alert", "d8_count_alert", "timing_mad_alert",
            "timing_envelope_alert",
        )
    }
    positive_tx = transaction_counts["positive"]
    recovery = {
        "positive_decode_success": _rate(
            transaction_counts["positive_decode_success"], positive_tx
        ),
        "positive_exact_recovery": _rate(
            transaction_counts["positive_decoded_exact"], positive_tx
        ),
        "incorrect_success": _rate(
            transaction_counts["incorrect_success"], transaction_counts["total"]
        ),
        "measurement_invalid": _rate(
            transaction_counts["invalid"], transaction_counts["total"]
        ),
    }

    criteria = {
        "nine_unique_boots": len(campaigns) == 9 and len(boot_ids) == 9,
        "no_integrity_failures": not failures,
        "d9_difference_recall_ge_0_95": method_metrics["d9_alert"]["recall"] >= 0.95,
        "d9_control_fpr_le_0_05": method_metrics["d9_alert"]["false_positive_rate"] <= 0.05,
        "each_difference_state_recall_ge_0_95": all(
            state_metrics[state]["d9_alert"]["rate"] >= 0.95
            for state in DIFFERENCE_STATES
        ),
        "each_control_state_fpr_le_0_05": all(
            state_metrics[state]["d9_alert"]["rate"] <= 0.05
            for state in CONTROL_STATES
        ),
        "each_boot_control_fpr_le_0_10": all(
            item["rate"] <= 0.10 for item in per_boot_control_fpr.values()
        ),
        "exact_recovery_ge_0_95": recovery["positive_exact_recovery"]["rate"] >= 0.95,
        "zero_incorrect_success": transaction_counts["incorrect_success"] == 0,
        "zero_measurement_invalid": transaction_counts["invalid"] == 0,
        "substitution_advantage_over_count_ge_0_90": (
            state_metrics["getdents_substitution"]["d9_alert"]["rate"]
            - state_metrics["getdents_substitution"]["d8_count_alert"]["rate"]
            >= 0.90
        ),
        "authorized_policy_difference_visible_ge_0_95": (
            state_metrics["policy_filter"]["d9_alert"]["rate"] >= 0.95
        ),
    }
    output = {
        "analysis_protocol": "D9-confirmatory-analysis-r1-2026-09-24",
        "input_root": str(args.input),
        "lock_sha256": _sha256(args.lock),
        "timing_model_sha256": _sha256(args.timing_model),
        "campaigns": campaigns,
        "integrity_failures": failures,
        "batch_count": len(predictions),
        "transaction_counts": dict(transaction_counts),
        "methods": method_metrics,
        "states": state_metrics,
        "per_boot_control_fpr": per_boot_control_fpr,
        "recovery": recovery,
        "criteria": criteria,
        "passed": all(criteria.values()),
        "interpretation_limit": (
            "D9 observes identity-set discrepancy across the accepted-filldir64 "
            "to getdents64-output boundary; it does not infer malicious intent."
        ),
        "predictions": predictions,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(args.output), "passed": output["passed"],
        "batches": len(predictions), "integrity_failures": failures,
        "criteria": criteria,
    }, indent=2))
    if failures:
        raise RuntimeError("formal integrity audit failed")


if __name__ == "__main__":
    main()
