from __future__ import annotations

import argparse
import gzip
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np

from .context import process_record


BATCH_CONTEXT_NAMES = np.asarray(
    [
        "log_sched_switch_per_iteration",
        "log_softirq_enter_per_iteration",
        "log_offcpu_positive_per_iteration",
        "log_irq_positive_per_iteration",
        "log_offcpu_total_ns_per_iteration",
        "log_irq_union_total_ns_per_iteration",
    ],
    dtype=str,
)


@dataclass(frozen=True)
class V1BatchContextDataset:
    batch_ids: np.ndarray
    boot_ids: np.ndarray
    labels: np.ndarray
    conditions: np.ndarray
    campaign_ids: np.ndarray
    campaign_positions: np.ndarray
    iterations: np.ndarray
    feature_names: np.ndarray
    values: np.ndarray
    raw_values: np.ndarray
    quality_valid: np.ndarray

    def validate(self) -> None:
        rows = len(self.batch_ids)
        if self.values.shape != (rows, len(self.feature_names)):
            raise ValueError("V1 context values shape does not match rows/features")
        if self.raw_values.shape != self.values.shape:
            raise ValueError("V1 raw context values shape mismatch")
        for name in (
            "boot_ids",
            "labels",
            "conditions",
            "campaign_ids",
            "campaign_positions",
            "iterations",
            "quality_valid",
        ):
            if len(getattr(self, name)) != rows:
                raise ValueError(f"{name} length does not match V1 context rows")
        if len(set(self.batch_ids.tolist())) != rows:
            raise ValueError("Duplicate V1 batch identifiers")
        if not np.all(np.isfinite(self.values)):
            raise ValueError("V1 transformed context contains non-finite values")
        if not np.all(np.isfinite(self.raw_values)):
            raise ValueError("V1 raw context contains non-finite values")

    def save(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(output, **asdict(self))

    @classmethod
    def load(cls, path: str | Path) -> "V1BatchContextDataset":
        with np.load(path, allow_pickle=False) as data:
            dataset = cls(**{field: data[field] for field in cls.__dataclass_fields__})
        dataset.validate()
        return dataset


def _event_count(record: dict, kind: str) -> int:
    stored = record.get("quality", {}).get("event_counts", {}).get(kind)
    if stored is not None:
        return int(stored)
    return sum(event.get("kind") == kind for event in record.get("events", []))


def context_row(record: dict, batch=None) -> tuple[np.ndarray, np.ndarray, bool]:
    """Build label-free batch context from a raw collector record."""

    batch = process_record(record) if batch is None else batch
    iterations = max(1, int(batch.iterations))
    analysis_functions = set(batch.analysis_functions)
    invocations = [
        invocation
        for invocation in batch.invocations
        if invocation.valid and invocation.function in analysis_functions
    ]
    raw = np.asarray(
        [
            _event_count(record, "sched_switch") / iterations,
            _event_count(record, "softirq_enter") / iterations,
            sum(invocation.offcpu_ns > 0 for invocation in invocations) / iterations,
            sum(invocation.irq_union_overlap_ns > 0 for invocation in invocations)
            / iterations,
            sum(invocation.offcpu_ns for invocation in invocations) / iterations,
            sum(invocation.irq_union_overlap_ns for invocation in invocations)
            / iterations,
        ],
        dtype=float,
    )
    transformed = np.log1p(raw)
    return transformed, raw, bool(batch.quality["valid_for_analysis"])


def build_v1_context_dataset(paths: Sequence[Path]) -> V1BatchContextDataset:
    rows: list[np.ndarray] = []
    raw_rows: list[np.ndarray] = []
    batch_ids: list[str] = []
    boot_ids: list[str] = []
    labels: list[str] = []
    conditions: list[str] = []
    campaign_ids: list[str] = []
    campaign_positions: list[int] = []
    iterations: list[int] = []
    quality_valid: list[bool] = []

    total = len(paths)
    for position, path in enumerate(paths, start=1):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        batch = process_record(record)
        transformed, raw, valid = context_row(record, batch)
        rows.append(transformed)
        raw_rows.append(raw)
        batch_ids.append(batch.batch_id)
        boot_ids.append(batch.boot_id)
        labels.append(batch.label)
        conditions.append(batch.condition)
        campaign_ids.append(batch.campaign_id)
        campaign_positions.append(batch.campaign_position)
        iterations.append(batch.iterations)
        quality_valid.append(valid)
        if position % 100 == 0 or position == total:
            print(f"processed {position}/{total} raw batches", flush=True)

    dataset = V1BatchContextDataset(
        batch_ids=np.asarray(batch_ids, dtype=str),
        boot_ids=np.asarray(boot_ids, dtype=str),
        labels=np.asarray(labels, dtype=str),
        conditions=np.asarray(conditions, dtype=str),
        campaign_ids=np.asarray(campaign_ids, dtype=str),
        campaign_positions=np.asarray(campaign_positions, dtype=np.int64),
        iterations=np.asarray(iterations, dtype=np.int64),
        feature_names=BATCH_CONTEXT_NAMES.copy(),
        values=np.asarray(rows, dtype=float),
        raw_values=np.asarray(raw_rows, dtype=float),
        quality_valid=np.asarray(quality_valid, dtype=bool),
    )
    dataset.validate()
    return dataset


def _input_paths(inputs: Sequence[Path]) -> list[Path]:
    paths: list[Path] = []
    for item in inputs:
        if item.is_dir():
            paths.extend(sorted(item.glob("boot_*/batch_*.json.gz")))
            paths.extend(sorted(item.glob("batch_*.json.gz")))
        elif item.is_file():
            paths.append(item)
        else:
            raise FileNotFoundError(item)
    unique = list(dict.fromkeys(path.resolve() for path in paths))
    if not unique:
        raise ValueError("No batch_*.json.gz inputs found")
    return unique


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", nargs="+", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    paths = _input_paths(args.input)
    dataset = build_v1_context_dataset(paths)
    dataset.save(args.output)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "batches": len(dataset.batch_ids),
                "valid": int(np.sum(dataset.quality_valid)),
                "features": dataset.feature_names.tolist(),
            }
        )
    )


if __name__ == "__main__":
    main()
