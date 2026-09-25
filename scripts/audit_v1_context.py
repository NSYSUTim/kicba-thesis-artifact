from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from kicba.context import ContextBatchDataset
from kicba.v1_features import V1BatchContextDataset


def _finite_or_none(value: float) -> float | None:
    return float(value) if np.isfinite(value) else None


def _smd(normal: np.ndarray, rootkit: np.ndarray) -> float:
    if len(normal) < 2 or len(rootkit) < 2:
        return float("nan")
    pooled = np.sqrt((np.var(normal, ddof=1) + np.var(rootkit, ddof=1)) / 2.0)
    if pooled == 0:
        return 0.0 if np.mean(normal) == np.mean(rootkit) else float("inf")
    return float((np.mean(rootkit) - np.mean(normal)) / pooled)


def audit(base: ContextBatchDataset, context: V1BatchContextDataset) -> dict:
    base.validate()
    context.validate()
    base_index = {value: idx for idx, value in enumerate(base.batch_ids.tolist())}
    context_index = {value: idx for idx, value in enumerate(context.batch_ids.tolist())}
    missing = sorted(set(base_index) - set(context_index))
    extra = sorted(set(context_index) - set(base_index))
    if missing or extra:
        raise ValueError(f"batch mismatch: missing={len(missing)}, extra={len(extra)}")
    order = np.asarray([context_index[value] for value in base.batch_ids], dtype=int)
    metadata_match = {
        "boot_id": bool(np.array_equal(base.boot_ids, context.boot_ids[order])),
        "label": bool(np.array_equal(base.labels, context.labels[order])),
        "condition": bool(np.array_equal(base.conditions, context.conditions[order])),
        "campaign_id": bool(
            np.array_equal(base.campaign_ids, context.campaign_ids[order])
        ),
        "campaign_position": bool(
            np.array_equal(
                base.campaign_positions, context.campaign_positions[order]
            )
        ),
        "quality_valid": bool(
            np.array_equal(base.quality_valid, context.quality_valid[order])
        ),
    }
    if not all(metadata_match.values()):
        raise ValueError(f"metadata mismatch: {metadata_match}")

    values = context.values[order]
    raw = context.raw_values[order]
    feature_rows = []
    normal_mask = base.labels == "normal"
    rootkit_mask = base.labels == "rootkit"
    conditions = sorted(set(base.conditions.tolist()))
    boots = sorted(set(base.boot_ids.tolist()))
    for column, name in enumerate(context.feature_names.tolist()):
        by_condition = {}
        smds = []
        for condition in conditions:
            condition_mask = base.conditions == condition
            normal = values[condition_mask & normal_mask, column]
            rootkit = values[condition_mask & rootkit_mask, column]
            smd = _smd(normal, rootkit)
            smds.append(smd)
            by_condition[condition] = {
                "normal_mean": float(np.mean(normal)),
                "rootkit_mean": float(np.mean(rootkit)),
                "standardized_mean_difference_rootkit_minus_normal": _finite_or_none(
                    smd
                ),
                "normal_nonzero_rate": float(
                    np.mean(raw[condition_mask & normal_mask, column] > 0)
                ),
                "rootkit_nonzero_rate": float(
                    np.mean(raw[condition_mask & rootkit_mask, column] > 0)
                ),
            }
        finite_smds = np.abs(np.asarray(smds, dtype=float))
        finite_smds = finite_smds[np.isfinite(finite_smds)]
        by_boot_nonzero_rate = {
            boot: float(np.mean(raw[base.boot_ids == boot, column] > 0))
            for boot in boots
        }
        feature_rows.append(
            {
                "feature": name,
                "overall_nonzero_rate": float(np.mean(raw[:, column] > 0)),
                "normal_nonzero_rate": float(np.mean(raw[normal_mask, column] > 0)),
                "rootkit_nonzero_rate": float(
                    np.mean(raw[rootkit_mask, column] > 0)
                ),
                "raw_min": float(np.min(raw[:, column])),
                "raw_max": float(np.max(raw[:, column])),
                "max_abs_within_condition_smd": (
                    float(np.max(finite_smds)) if len(finite_smds) else None
                ),
                "by_condition": by_condition,
                "by_boot_nonzero_rate": by_boot_nonzero_rate,
            }
        )

    return {
        "status": "pass",
        "rows": len(base.batch_ids),
        "unique_batch_ids": len(set(base.batch_ids.tolist())),
        "boots": boots,
        "labels": {
            label: int(np.sum(base.labels == label))
            for label in sorted(set(base.labels.tolist()))
        },
        "conditions": {
            condition: int(np.sum(base.conditions == condition))
            for condition in conditions
        },
        "valid_rows": int(np.sum(base.quality_valid)),
        "finite_transformed_values": bool(np.all(np.isfinite(values))),
        "finite_raw_values": bool(np.all(np.isfinite(raw))),
        "metadata_match": metadata_match,
        "features": feature_rows,
        "interpretation_guardrail": (
            "Label effect sizes are a leakage/sanity audit only; they are not used "
            "to select, remove, or tune V1 features after this report."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit(
        ContextBatchDataset.load(args.base),
        V1BatchContextDataset.load(args.context),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({key: report[key] for key in ("status", "rows", "valid_rows")}))


if __name__ == "__main__":
    main()
