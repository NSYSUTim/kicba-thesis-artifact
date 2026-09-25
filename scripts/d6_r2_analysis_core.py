"""Frozen D6-r2 loading, replay, and metric definitions."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _extract
from d4_context_axis import fit_context_axis, score_context_axis
from kicba.detector import ShiftDetector


PROTOCOL = "D6-r2-2026-09-20"
WINDOW = 50
QUANTILES = np.arange(0.1, 1.0, 0.1)
PUBLIC_METHODS = (
    "fixed_public_empirical",
    "blind_public_empirical_w50",
    "fixed_public_oas",
    "blind_public_oas_w50",
)
BASELINE_THRESHOLDS = {
    "fixed_public_empirical": 28.17319410417818,
    "blind_public_empirical_w50": 2.6102339930684484,
    "fixed_public_oas": 20.146773583634662,
    "blind_public_oas_w50": 0.8825466351416513,
}
PROPOSED = "proposed_factorized_guard_w50"


def batch_values(record: dict) -> np.ndarray:
    transactions = record["transaction_durations"]
    first = np.asarray([
        item["first_raw_wall_ns"] for item in transactions
    ], dtype=float)
    last = np.asarray([
        item["last_raw_wall_ns"] for item in transactions
    ], dtype=float)
    if len(first) < len(QUANTILES) or len(last) < len(QUANTILES):
        raise ValueError("not enough transaction durations for q9")
    return np.stack((
        np.quantile(first, QUANTILES),
        np.quantile(last, QUANTILES),
    ))


def load_boot(root: Path):
    manifests = list(root.glob("campaign_*.json"))
    if len(manifests) != 1:
        raise ValueError(f"manifest count in {root}")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    if manifest.get("protocol_revision") != PROTOCOL:
        raise ValueError(f"not D6-r2: {root}")
    raw_by_position = {}
    extracted_by_position = {}
    for path in root.glob("batch_*.json.gz"):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        position = int(record["collection"]["campaign_position"])
        if position in raw_by_position:
            raise ValueError(f"duplicate campaign position {position} in {root}")
        raw_by_position[position] = batch_values(record)
        extracted_by_position[position] = _extract(path)
    if len(raw_by_position) != len(manifest["schedule"]):
        raise ValueError(f"batch/schedule mismatch in {root}")
    initial, clean, sham, test = [], [], [], []
    for item in manifest["schedule"]:
        position = int(item["position"])
        if item.get("status") != "complete":
            raise ValueError(f"incomplete item {position} in {root}")
        if item["phase"] == "calibration":
            if item["state"] == "unloaded":
                initial.append(raw_by_position[position])
                clean.append(extracted_by_position[position])
            else:
                sham.append(extracted_by_position[position])
        else:
            test.append((
                item, raw_by_position[position], extracted_by_position[position]
            ))
    if len(initial) != 50 or len(clean) != 50 or len(sham) != 50 or len(test) != 360:
        raise ValueError(f"unexpected D6-r2 split sizes in {root}")
    return manifest, np.stack(initial), clean, sham, test


def replay_public(manifest: dict, initial: np.ndarray,
                  test: list) -> list[dict]:
    predictions = []
    for method in PUBLIC_METHODS:
        covariance = "oas" if "_oas" in method else "empirical"
        blind = method.startswith("blind_")
        fixed = ShiftDetector(covariance=covariance).fit(initial)
        window = [row.copy() for row in initial[-WINDOW:]]
        labels = ["unloaded"] * len(window)
        for item, values, _ in test:
            model = (
                ShiftDetector(covariance=covariance).fit(np.stack(window))
                if blind else fixed
            )
            score = model.max_distance_squared(values)
            threshold = BASELINE_THRESHOLDS[method]
            alert = not np.isfinite(score) or score > threshold
            if blind:
                window = (window + [values.copy()])[-WINDOW:]
                labels = (labels + [item["state"]])[-WINDOW:]
            predictions.append({
                "boot_id": manifest["boot_id"],
                "method": method,
                "position": item["position"],
                "episode": item["episode"],
                "episode_ordinal": item["episode_ordinal"],
                "segment": item["segment"],
                "truth_state": item["state"],
                "condition": item["condition"],
                "security_score": score,
                "security_threshold": threshold,
                "security_alert": alert,
                "operational_score": float("nan"),
                "operational_threshold": float("nan"),
                "operational_alert": False,
                "decision": "attack" if alert else "normal",
                "updated": blind,
                "window_attack_fraction": (
                    sum(value == "hiding" for value in labels) / len(labels)
                ),
            })
    return predictions


def _fit_operational(clean: list[dict], context_split: float) -> dict:
    model = {"context_split": context_split, "strata": {}}
    for stratum, predicate in (
        ("low", lambda value: value < context_split),
        ("high", lambda value: value >= context_split),
    ):
        rows = [row for row in clean if predicate(row["cpu_busy_fraction"])]
        if len(rows) < 4:
            raise ValueError(f"insufficient clean operational calibration: {stratum}")
        values = [float(row["first_raw_median"]) for row in rows]
        anchor = float(np.median(values))
        model["strata"][stratum] = {
            "threshold": float(max(value / anchor for value in values) * 1.01),
            "initial": values[-WINDOW:],
        }
    return model


def replay_proposed(manifest: dict, clean: list[dict], sham: list[dict],
                    test: list) -> list[dict]:
    security = fit_context_axis(clean, sham)
    operational = _fit_operational(clean, float(security["context_split"]))
    references = {
        stratum: [(value, "unloaded") for value in params["initial"]]
        for stratum, params in operational["strata"].items()
    }
    predictions = []
    for item, _, row in test:
        stratum, security_score, security_threshold, security_alert = (
            score_context_axis(security, row)
        )
        reference = references[stratum]
        adaptive_anchor = float(np.median([value for value, _ in reference]))
        operational_score = float(row["first_raw_median"] / adaptive_anchor)
        operational_threshold = float(
            operational["strata"][stratum]["threshold"]
        )
        operational_alert = operational_score > operational_threshold

        if security_alert:
            decision = "attack"
            accepted = False
        elif operational_alert:
            decision = "drift"
            accepted = True
        else:
            decision = "normal"
            accepted = True
        # Prequential order: prediction above is recorded before this update.
        if accepted:
            references[stratum] = (
                reference + [(float(row["first_raw_median"]), item["state"])]
            )[-WINDOW:]
        max_attack_fraction = max(
            sum(state == "hiding" for _, state in values) / len(values)
            for values in references.values()
        )
        predictions.append({
            "boot_id": manifest["boot_id"],
            "method": PROPOSED,
            "position": item["position"],
            "episode": item["episode"],
            "episode_ordinal": item["episode_ordinal"],
            "segment": item["segment"],
            "truth_state": item["state"],
            "condition": item["condition"],
            "context_stratum": stratum,
            "security_score": security_score,
            "security_threshold": security_threshold,
            "security_alert": security_alert,
            "operational_score": operational_score,
            "operational_threshold": operational_threshold,
            "operational_alert": operational_alert,
            "decision": decision,
            "updated": accepted,
            "window_attack_fraction": max_attack_fraction,
        })
    return predictions


def f1_score(rows: list[dict]) -> float:
    truth = np.asarray([
        row["truth_state"] == "hiding" for row in rows
    ], dtype=bool)
    predicted = np.asarray([row["security_alert"] for row in rows], dtype=bool)
    tp = int(np.sum(truth & predicted))
    fp = int(np.sum(~truth & predicted))
    fn = int(np.sum(truth & ~predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )


def metric_row(rows: list[dict], boot_id: str, method: str) -> dict:
    attack = [row for row in rows if row["truth_state"] == "hiding"]
    unloaded = [row for row in rows if row["truth_state"] == "unloaded"]
    sham = [row for row in rows if row["truth_state"] == "sham"]
    non_attack = unloaded + sham
    workload_drift = [
        row for row in unloaded if row["condition"] != "baseline"
    ]
    baseline_normal = [
        row for row in unloaded if row["condition"] == "baseline"
    ]
    result = {
        "boot_id": boot_id,
        "method": method,
        "attack_n": len(attack),
        "attack_recall": float(np.mean([
            row["security_alert"] for row in attack
        ])),
        "unloaded_n": len(unloaded),
        "unloaded_normal_fpr": float(np.mean([
            row["security_alert"] for row in unloaded
        ])),
        "sham_n": len(sham),
        "sham_fpr": float(np.mean([
            row["security_alert"] for row in sham
        ])),
        "non_attack_n": len(non_attack),
        "non_attack_fpr": float(np.mean([
            row["security_alert"] for row in non_attack
        ])),
        "f1": f1_score(rows),
        "attack_update_rate": float(np.mean([row["updated"] for row in attack])),
        "unloaded_update_rate": float(np.mean([
            row["updated"] for row in unloaded
        ])),
        "sham_update_rate": float(np.mean([row["updated"] for row in sham])),
        "benign_update_rate": float(np.mean([
            row["updated"] for row in non_attack
        ])),
        "max_window_attack_fraction": float(max(
            row["window_attack_fraction"] for row in rows
        )),
        "unknown_rate": 0.0,
        "operational_workload_drift_recall": float("nan"),
        "operational_baseline_drift_fpr": float("nan"),
    }
    if method == PROPOSED:
        result["operational_workload_drift_recall"] = float(np.mean([
            row["decision"] == "drift" for row in workload_drift
        ]))
        result["operational_baseline_drift_fpr"] = float(np.mean([
            row["decision"] == "drift" for row in baseline_normal
        ]))
    return result


def per_boot_metrics(predictions: list[dict]) -> list[dict]:
    output = []
    for boot_id, method in sorted({
        (row["boot_id"], row["method"]) for row in predictions
    }):
        rows = [row for row in predictions
                if row["boot_id"] == boot_id and row["method"] == method]
        output.append(metric_row(rows, boot_id, method))
    return output


def overall_metrics(predictions: list[dict]) -> list[dict]:
    output = []
    for method in sorted({row["method"] for row in predictions}):
        rows = [row for row in predictions if row["method"] == method]
        output.append(metric_row(rows, "ALL", method))
    return output
