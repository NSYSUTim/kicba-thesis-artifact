"""Normal-only context strata and clean-to-sham projection guard."""

from __future__ import annotations

import numpy as np


AXIS_FEATURES = ("first_raw_median", "first_div_last_raw_median")


def fit_context_axis(clean: list[dict], sham: list[dict]) -> dict:
    if len(clean) < 4 or len(sham) < 4:
        raise ValueError("insufficient clean/sham calibration")
    contexts = np.sort(np.asarray(
        [row["cpu_busy_fraction"] for row in clean + sham], dtype=float
    ))
    gaps = np.diff(contexts)
    split_index = int(np.argmax(gaps))
    if gaps[split_index] < 0.20:
        raise ValueError("CPU context has no stable low/high separation")
    context_split = float((contexts[split_index] + contexts[split_index + 1]) / 2)
    model = {"context_split": context_split, "strata": {}}
    for stratum, predicate in (
        ("low", lambda value: value < context_split),
        ("high", lambda value: value >= context_split),
    ):
        clean_rows = [row for row in clean if predicate(row["cpu_busy_fraction"])]
        sham_rows = [row for row in sham if predicate(row["cpu_busy_fraction"])]
        if len(clean_rows) < 4 or len(sham_rows) < 4:
            raise ValueError(f"insufficient calibration in {stratum} stratum")
        clean_x = np.log(np.asarray(
            [[row[name] for name in AXIS_FEATURES] for row in clean_rows], dtype=float
        ))
        sham_x = np.log(np.asarray(
            [[row[name] for name in AXIS_FEATURES] for row in sham_rows], dtype=float
        ))
        origin = np.mean(clean_x, axis=0)
        axis = np.mean(sham_x, axis=0) - origin
        norm = float(np.linalg.norm(axis))
        if norm <= 1e-9:
            raise ValueError(f"degenerate clean-to-sham axis in {stratum}")
        axis /= norm
        benign = np.vstack((clean_x, sham_x))
        projections = (benign - origin) @ axis
        model["strata"][stratum] = {
            "origin": origin.tolist(),
            "axis": axis.tolist(),
            # Fixed D4 rule: max observed benign projection plus 0.01 log-unit.
            "threshold": float(np.max(projections) + 0.01),
            "clean_n": len(clean_rows),
            "sham_n": len(sham_rows),
        }
    return model


def score_context_axis(model: dict, row: dict) -> tuple[str, float, float, bool]:
    stratum = "low" if row["cpu_busy_fraction"] < model["context_split"] else "high"
    parameters = model["strata"][stratum]
    value = np.log(np.asarray([row[name] for name in AXIS_FEATURES], dtype=float))
    score = float(
        (value - np.asarray(parameters["origin"])) @ np.asarray(parameters["axis"])
    )
    threshold = float(parameters["threshold"])
    return stratum, score, threshold, score > threshold
