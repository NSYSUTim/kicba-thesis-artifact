#!/usr/bin/env python3
"""Freeze the D9 comparison-only timing rule from excluded calibration."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import statistics
from pathlib import Path


PROTOCOL = "D9-reconciliation-campaign-r1-2026-09-24"
CONTROL_STATES = {
    "unloaded", "filldir_pass", "filldir_active",
    "getdents_pass", "getdents_active",
}
CONDITIONS = ("baseline", "cpu", "memory", "mixed")
BUFFERS = (128, 256, 4096, 65536)
EXPECTED_REPEATS = 3


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _feature(batch: dict) -> float:
    """Natural log of the batch median complete-enumeration wall time."""

    values = [int(tx["userspace"]["scan_ns"]) for tx in batch["transactions"]]
    if len(values) != 20 or min(values) <= 0:
        raise ValueError("each calibration batch must have 20 positive scan_ns")
    return math.log(float(statistics.median(values)))


def _load(path: Path) -> tuple[dict, list[dict]]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        record = json.load(stream)
    if (
        record.get("protocol_revision") != PROTOCOL
        or record.get("role") != "calibration"
        or record.get("evidence_role")
        != "excluded_single_boot_timing_calibration"
        or not record.get("success")
    ):
        raise ValueError("input is not a successful excluded D9 calibration")
    parameters = record.get("parameters", {})
    if (
        parameters.get("iterations_per_batch") != 20
        or parameters.get("repeats_per_cell") != EXPECTED_REPEATS
        or tuple(parameters.get("buffers", ())) != BUFFERS
        or tuple(parameters.get("conditions", ())) != CONDITIONS
        or set(parameters.get("state_order", ())) != CONTROL_STATES
    ):
        raise ValueError("calibration design does not match the frozen fit design")
    rows = []
    for batch in record.get("batches", []):
        if (
            batch.get("state") not in CONTROL_STATES
            or not batch.get("treatment_valid")
            or not batch.get("transaction_valid")
            or batch.get("batch_failures")
        ):
            raise ValueError(f"invalid calibration batch {batch.get('position')}")
        rows.append({
            "state": batch["state"],
            "condition": batch["condition"],
            "buffer_size": int(batch["buffer_size"]),
            "feature": _feature(batch),
        })
    expected = len(CONTROL_STATES) * len(CONDITIONS) * len(BUFFERS) * EXPECTED_REPEATS
    if len(rows) != expected:
        raise ValueError(f"expected {expected} calibration batches, got {len(rows)}")
    return record, rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    record, rows = _load(args.input)
    thresholds_mad: dict[str, float] = {}
    thresholds_envelope: dict[str, float] = {}
    calibration: dict[str, dict] = {}
    for condition in CONDITIONS:
        for buffer_size in BUFFERS:
            key = f"{condition}|{buffer_size}"
            values = [
                row["feature"] for row in rows
                if row["condition"] == condition
                and row["buffer_size"] == buffer_size
            ]
            expected = len(CONTROL_STATES) * EXPECTED_REPEATS
            if len(values) != expected:
                raise ValueError(f"expected {expected} controls for {key}")
            center = float(statistics.median(values))
            mad = float(statistics.median(abs(value - center) for value in values))
            if mad <= 0:
                raise ValueError(f"degenerate timing dispersion for {key}")
            threshold_mad = center + 3.0 * 1.4826 * mad
            threshold_envelope = max(values) + 0.01
            thresholds_mad[key] = threshold_mad
            thresholds_envelope[key] = threshold_envelope
            calibration[key] = {
                "control_batches": len(values),
                "log_median_center": center,
                "log_median_mad": mad,
                "threshold_mad": threshold_mad,
                "threshold_envelope": threshold_envelope,
                "calibration_alerts_mad": sum(
                    value > threshold_mad for value in values
                ),
                "calibration_alerts_envelope": sum(
                    value > threshold_envelope for value in values
                ),
            }
    state_rates_mad = {}
    state_rates_envelope = {}
    for state in sorted(CONTROL_STATES):
        selected = [row for row in rows if row["state"] == state]
        alerts_mad = sum(
            row["feature"]
            > thresholds_mad[f"{row['condition']}|{row['buffer_size']}"]
            for row in selected
        )
        alerts_envelope = sum(
            row["feature"]
            > thresholds_envelope[f"{row['condition']}|{row['buffer_size']}"]
            for row in selected
        )
        state_rates_mad[state] = alerts_mad / len(selected)
        state_rates_envelope[state] = alerts_envelope / len(selected)
    model = {
        "role": "frozen_excluded_d9_timing_comparator",
        "not_primary_proposed_method": True,
        "fit_protocol": PROTOCOL,
        "fit_evidence_role": record["evidence_role"],
        "feature": "log(median userspace scan_ns over 20 transactions)",
        "strata": ["background condition", "getdents64 buffer size"],
        "threshold_rules": {
            "mad": (
            "median + 3 * 1.4826 * MAD among five non-suppression "
            "controls with three repeats per stratum"
            ),
            "envelope": (
                "maximum non-suppression calibration feature plus 0.01 "
                "log-unit in each stratum"
            ),
        },
        "direction": "alert_when_feature_above_corresponding_stratum_threshold",
        "fit_control_states": sorted(CONTROL_STATES),
        "thresholds_mad": thresholds_mad,
        "thresholds_envelope": thresholds_envelope,
        "calibration": calibration,
        "calibration_only_alert_rates": {
            "mad": state_rates_mad,
            "envelope": state_rates_envelope,
        },
        "input_sha256": _sha256(args.input),
        "input_source_hashes": record["source_hashes"],
        "script_sha256": _sha256(Path(__file__)),
        "warning": (
            "This is a simple comparison baseline, not a reproduction of all "
            "timing detectors. Formal labels and formal observations must not "
            "be used to tune these thresholds."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(model, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "strata": len(thresholds_mad),
        "calibration_batches": len(rows),
        "calibration_only_alert_rates": {
            "mad": state_rates_mad,
            "envelope": state_rates_envelope,
        },
    }, indent=2))


if __name__ == "__main__":
    main()
