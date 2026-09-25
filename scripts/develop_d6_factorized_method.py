#!/usr/bin/env python3
"""D6 method development on D5 data; never a confirmatory analysis.

This script evaluates two *predefined* benign-only security gates and a
factorized three-state interpretation:

    security alert                 -> attack; reject update
    no security + operational alert -> drift candidate; accept update
    neither                        -> normal; accept update

The operational reference is a single W20 per measured CPU-context stratum.
No attack observation is used to fit a threshold or choose a feature.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _extract, _write_csv
from d4_context_axis import fit_context_axis, score_context_axis


WINDOW = 20
RATIO_FEATURE = "first_div_last_raw_median"
LOG_MARGIN = 0.01


def _load_boot(root: Path):
    manifests = list(root.glob("campaign_*.json"))
    if len(manifests) != 1:
        raise ValueError(f"expected one manifest below {root}")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    if manifest.get("protocol_revision") != "D5-r1-2026-09-19":
        raise ValueError(f"not D5-r1: {root}")
    rows = [_extract(path) for path in sorted(root.glob("batch_*.json.gz"))]
    by_position = {row["campaign_position"]: row for row in rows}
    if len(rows) != len(manifest["schedule"]):
        raise ValueError(f"batch/schedule mismatch: {root}")
    clean, sham, test = [], [], []
    for item in manifest["schedule"]:
        row = by_position[item["position"]]
        if item["phase"] == "calibration":
            (clean if item["state"] == "unloaded" else sham).append(row)
        else:
            test.append((item, row))
    return manifest, clean, sham, test


def _fit_ratio_envelope(clean: list[dict], sham: list[dict], split: float) -> dict:
    model = {"context_split": split, "strata": {}}
    for stratum, predicate in (
        ("low", lambda value: value < split),
        ("high", lambda value: value >= split),
    ):
        values = np.log(np.asarray([
            row[RATIO_FEATURE] for row in clean + sham
            if predicate(row["cpu_busy_fraction"])
        ], dtype=float))
        if len(values) < 8:
            raise ValueError(f"insufficient ratio calibration in {stratum}")
        model["strata"][stratum] = {
            "low": float(np.min(values) - LOG_MARGIN),
            "high": float(np.max(values) + LOG_MARGIN),
            "n": len(values),
        }
    return model


def _score_ratio_envelope(model: dict, row: dict):
    stratum = (
        "low" if row["cpu_busy_fraction"] < model["context_split"] else "high"
    )
    value = float(np.log(row[RATIO_FEATURE]))
    limits = model["strata"][stratum]
    alert = value < limits["low"] or value > limits["high"]
    return stratum, value, limits, alert


def _fit_operational(clean: list[dict], split: float) -> dict:
    model = {"context_split": split, "strata": {}}
    for stratum, predicate in (
        ("low", lambda value: value < split),
        ("high", lambda value: value >= split),
    ):
        rows = [row for row in clean if predicate(row["cpu_busy_fraction"])]
        if len(rows) < 4:
            raise ValueError(f"insufficient clean calibration in {stratum}")
        values = [float(row["first_raw_median"]) for row in rows]
        anchor = float(np.median(values))
        model["strata"][stratum] = {
            "anchor": anchor,
            "threshold": float(max(value / anchor for value in values) * 1.01),
            "initial": values[-WINDOW:],
        }
    return model


def _bootstrap_ci(differences: np.ndarray, seed: int = 20260920):
    rng = np.random.default_rng(seed)
    draws = rng.choice(
        differences, size=(10_000, len(differences)), replace=True
    ).mean(axis=1)
    return [float(np.quantile(draws, 0.025)), float(np.quantile(draws, 0.975))]


def _replay_gate(manifest, clean, sham, test, gate_name: str):
    axis_model = fit_context_axis(clean, sham)
    ratio_model = _fit_ratio_envelope(
        clean, sham, float(axis_model["context_split"])
    )
    operational = _fit_operational(clean, float(axis_model["context_split"]))
    references = {
        stratum: [(value, "unloaded") for value in params["initial"]]
        for stratum, params in operational["strata"].items()
    }
    predictions = []
    for item, row in test:
        if gate_name == "clean_to_sham_axis":
            stratum, security_score, security_threshold, security_alert = (
                score_context_axis(axis_model, row)
            )
            security_detail = json.dumps({"threshold": security_threshold})
        elif gate_name == "role_ratio_envelope":
            stratum, security_score, limits, security_alert = (
                _score_ratio_envelope(ratio_model, row)
            )
            security_detail = json.dumps(limits, sort_keys=True)
        else:
            raise ValueError(gate_name)

        reference = references[stratum]
        adaptive_anchor = float(np.median([value for value, _ in reference]))
        operational_score = float(row["first_raw_median"] / adaptive_anchor)
        operational_threshold = operational["strata"][stratum]["threshold"]
        operational_alert = operational_score > operational_threshold

        if security_alert:
            decision = "attack"
            accepted_update = False
        elif operational_alert:
            decision = "drift"
            accepted_update = True
        else:
            decision = "normal"
            accepted_update = True

        if accepted_update:
            references[stratum] = (
                reference + [(float(row["first_raw_median"]), item["state"])]
            )[-WINDOW:]
        max_attack_fraction = max(
            sum(state == "hiding" for _, state in values) / len(values)
            for values in references.values()
        )
        predictions.append({
            "boot_id": manifest["boot_id"],
            "gate": gate_name,
            "position": item["position"],
            "segment": item["segment"],
            "segment_offset": item["segment_offset"],
            "truth_state": item["state"],
            "condition": item["condition"],
            "context_stratum": stratum,
            "security_score": security_score,
            "security_detail": security_detail,
            "security_alert": security_alert,
            "operational_score": operational_score,
            "operational_threshold": operational_threshold,
            "operational_alert": operational_alert,
            "decision": decision,
            "accepted_update": accepted_update,
            "max_window_attack_fraction": max_attack_fraction,
        })
    return predictions


def _metrics(predictions: list[dict]) -> list[dict]:
    output = []
    keys = sorted({(row["boot_id"], row["gate"]) for row in predictions})
    for boot_id, gate in keys:
        rows = [row for row in predictions
                if row["boot_id"] == boot_id and row["gate"] == gate]
        attack = [row for row in rows if row["truth_state"] == "hiding"]
        normal = [row for row in rows if row["truth_state"] != "hiding"]
        sham = [row for row in rows if row["truth_state"] == "sham"]
        unloaded = [row for row in rows if row["truth_state"] == "unloaded"]
        output.append({
            "boot_id": boot_id,
            "gate": gate,
            "attack_n": len(attack),
            "attack_recall": np.mean([row["decision"] == "attack" for row in attack]),
            "normal_n": len(normal),
            "normal_fpr": np.mean([row["decision"] == "attack" for row in normal]),
            "sham_n": len(sham),
            "sham_fpr": np.mean([row["decision"] == "attack" for row in sham]),
            "unloaded_fpr": np.mean([
                row["decision"] == "attack" for row in unloaded
            ]),
            "drift_decision_rate_normal": np.mean([
                row["decision"] == "drift" for row in normal
            ]),
            "attack_update_rate": np.mean([
                row["accepted_update"] for row in attack
            ]),
            "normal_update_rate": np.mean([
                row["accepted_update"] for row in normal
            ]),
            "max_window_attack_fraction": max(
                row["max_window_attack_fraction"] for row in rows
            ),
        })
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    boots = sorted(
        path for path in args.input.iterdir()
        if path.is_dir() and path.name.startswith("boot_")
        and path.name[5:].isdigit()
    )
    if len(boots) != 5:
        raise ValueError(f"expected five boot directories, got {len(boots)}")

    predictions = []
    for root in boots:
        manifest, clean, sham, test = _load_boot(root)
        for gate_name in ("clean_to_sham_axis", "role_ratio_envelope"):
            predictions.extend(_replay_gate(
                manifest, clean, sham, test, gate_name
            ))
    per_boot = _metrics(predictions)
    overall = []
    for gate in sorted({row["gate"] for row in predictions}):
        rows = [row for row in predictions if row["gate"] == gate]
        attack = [row for row in rows if row["truth_state"] == "hiding"]
        normal = [row for row in rows if row["truth_state"] != "hiding"]
        sham = [row for row in rows if row["truth_state"] == "sham"]
        unloaded = [row for row in rows if row["truth_state"] == "unloaded"]
        boot_fprs = np.asarray([
            row["normal_fpr"] for row in per_boot if row["gate"] == gate
        ], dtype=float)
        overall.append({
            "gate": gate,
            "attack_n": len(attack),
            "attack_recall": float(np.mean([
                row["decision"] == "attack" for row in attack
            ])),
            "min_boot_attack_recall": float(min(
                row["attack_recall"] for row in per_boot if row["gate"] == gate
            )),
            "normal_n": len(normal),
            "normal_fpr": float(np.mean([
                row["decision"] == "attack" for row in normal
            ])),
            "max_boot_normal_fpr": float(np.max(boot_fprs)),
            "sham_fpr": float(np.mean([
                row["decision"] == "attack" for row in sham
            ])),
            "max_boot_sham_fpr": float(max(
                row["sham_fpr"] for row in per_boot if row["gate"] == gate
            )),
            "unloaded_fpr": float(np.mean([
                row["decision"] == "attack" for row in unloaded
            ])),
            "drift_decision_rate_normal": float(np.mean([
                row["decision"] == "drift" for row in normal
            ])),
            "attack_update_rate": float(np.mean([
                row["accepted_update"] for row in attack
            ])),
            "normal_update_rate": float(np.mean([
                row["accepted_update"] for row in normal
            ])),
            "max_window_attack_fraction": float(max(
                row["max_window_attack_fraction"] for row in rows
            )),
        })

    # Paired boot uncertainty for the development comparison only.
    axis = {row["boot_id"]: row for row in per_boot
            if row["gate"] == "clean_to_sham_axis"}
    ratio = {row["boot_id"]: row for row in per_boot
             if row["gate"] == "role_ratio_envelope"}
    paired = {}
    for metric in ("attack_recall", "normal_fpr", "sham_fpr"):
        differences = np.asarray([
            ratio[boot][metric] - axis[boot][metric] for boot in sorted(axis)
        ], dtype=float)
        paired[metric] = {
            "ratio_minus_axis_mean": float(np.mean(differences)),
            "boot_bootstrap_95_ci": _bootstrap_ci(differences),
        }

    args.output.mkdir(parents=True)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "per_boot_metrics.csv", per_boot)
    _write_csv(args.output / "overall_metrics.csv", overall)
    report = {
        "status": "D6_post_D5_method_development_only",
        "warning": (
            "D5 outcomes motivated this factorization. These results are not "
            "confirmatory and must not be reported as an independent test."
        ),
        "method": {
            "classification_priority": "security -> attack; else operational -> drift; else normal",
            "update_rule": "accept iff security gate is negative",
            "operational_reference": "one W20 per measured CPU-context stratum",
            "attack_labels_used_for_fit_or_threshold": False,
            "gates_compared": ["clean_to_sham_axis", "role_ratio_envelope"],
            "ratio_envelope": "two-sided benign clean+sham log-ratio range plus/minus 0.01",
        },
        "overall": overall,
        "paired_ratio_minus_axis": paired,
    }
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
