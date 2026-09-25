from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np


_BATCH_RE = re.compile(r"events_(?P<stamp>.+)_(?:normal|rootkit)\.json\.gz$")


@dataclass(frozen=True)
class BatchDataset:
    batch_ids: np.ndarray
    timestamps: np.ndarray
    labels: np.ndarray
    descriptions: np.ndarray
    interval_names: np.ndarray
    quantile_probs: np.ndarray
    values: np.ndarray
    counts: np.ndarray

    def save(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(
            output,
            batch_ids=self.batch_ids,
            timestamps=self.timestamps,
            labels=self.labels,
            descriptions=self.descriptions,
            interval_names=self.interval_names,
            quantile_probs=self.quantile_probs,
            values=self.values,
            counts=self.counts,
        )

    @classmethod
    def load(cls, path: str | Path) -> "BatchDataset":
        with np.load(path, allow_pickle=False) as data:
            return cls(**{field: data[field] for field in cls.__dataclass_fields__})

    def validate(self) -> None:
        n_batches = len(self.batch_ids)
        n_intervals = len(self.interval_names)
        n_quantiles = len(self.quantile_probs)
        if self.values.shape != (n_batches, n_intervals, n_quantiles):
            raise ValueError(f"Unexpected values shape: {self.values.shape}")
        if self.counts.shape != (n_batches, n_intervals):
            raise ValueError(f"Unexpected counts shape: {self.counts.shape}")
        for arr_name in ("timestamps", "labels", "descriptions"):
            if len(getattr(self, arr_name)) != n_batches:
                raise ValueError(f"{arr_name} length does not match batches")
        unknown_labels = set(np.unique(self.labels)) - {"normal", "rootkit"}
        if unknown_labels:
            raise ValueError(f"Unknown labels: {sorted(unknown_labels)}")
        if len(set(self.batch_ids.tolist())) != n_batches:
            raise ValueError("Duplicate batch identifiers in feature archive")


def _timestamp_from_filename(filename: str) -> str:
    match = _BATCH_RE.search(Path(filename).name)
    return match.group("stamp") if match else Path(filename).name


def _finalize_batch(
    filename: str,
    label: str,
    description: str,
    interval_values: dict[str, list[int]],
    quantile_probs: np.ndarray,
) -> dict:
    return {
        "batch_id": filename,
        "timestamp": _timestamp_from_filename(filename),
        "label": label,
        "description": description,
        "features": {
            name: np.quantile(np.asarray(values, dtype=np.float64), quantile_probs).tolist()
            for name, values in interval_values.items()
            if values
        },
        "counts": {name: len(values) for name, values in interval_values.items()},
    }


def stream_summarize_intervals(
    csv_path: str | Path,
    num_quantiles: int = 9,
    progress_bytes: int = 256 * 1024 * 1024,
) -> BatchDataset:
    """Convert the 3+ GB interval CSV to one compact record per batch.

    The official export is contiguous by filename. We verify that a completed
    filename never reappears, because otherwise streaming would silently split
    a batch and invalidate its quantiles.
    """

    if num_quantiles < 1:
        raise ValueError("num_quantiles must be positive")
    input_path = Path(csv_path)
    quantile_probs = np.linspace(
        0.0, 1.0 - 1.0 / (num_quantiles + 1), num_quantiles + 1
    )[1:]
    records: list[dict] = []
    seen_completed: set[str] = set()
    current_filename: str | None = None
    current_label = ""
    current_description = ""
    current_values: dict[str, list[int]] = {}
    next_progress = progress_bytes
    bytes_processed = 0
    started = time.monotonic()

    with input_path.open("r", encoding="utf-8", buffering=8 * 1024 * 1024) as handle:
        header_line = handle.readline()
        bytes_processed += len(header_line.encode("utf-8"))
        header = header_line.rstrip("\r\n")
        if header != "filename,name,id,delta,label,description":
            raise ValueError(f"Unexpected CSV header: {header!r}")

        for line_number, line in enumerate(handle, start=2):
            bytes_processed += len(line.encode("utf-8"))
            parts = line.rstrip("\r\n").split(",")
            if len(parts) != 6:
                raise ValueError(f"Line {line_number}: expected 6 columns, got {len(parts)}")
            filename, name, _row_id, delta_text, label, description = parts
            if filename != current_filename:
                if current_filename is not None:
                    records.append(
                        _finalize_batch(
                            current_filename,
                            current_label,
                            current_description,
                            current_values,
                            quantile_probs,
                        )
                    )
                    seen_completed.add(current_filename)
                if filename in seen_completed:
                    raise ValueError(
                        f"Batch {filename!r} is not contiguous; streaming quantiles are unsafe"
                    )
                current_filename = filename
                current_label = label
                current_description = description
                current_values = {}
            elif label != current_label or description != current_description:
                raise ValueError(f"Line {line_number}: metadata changed within one batch")

            try:
                delta = int(delta_text)
            except ValueError as exc:
                raise ValueError(f"Line {line_number}: invalid delta {delta_text!r}") from exc
            if delta < 0:
                raise ValueError(f"Line {line_number}: negative interval {delta}")
            current_values.setdefault(name, []).append(delta)

            if bytes_processed >= next_progress:
                elapsed = max(time.monotonic() - started, 1e-9)
                gib = bytes_processed / (1024**3)
                rate = bytes_processed / elapsed / (1024**2)
                print(
                    f"processed {gib:.2f} GiB, {len(records)} completed batches, "
                    f"{rate:.1f} MiB/s",
                    file=sys.stderr,
                    flush=True,
                )
                next_progress += progress_bytes

    if current_filename is not None:
        records.append(
            _finalize_batch(
                current_filename,
                current_label,
                current_description,
                current_values,
                quantile_probs,
            )
        )

    interval_names = np.asarray(
        sorted({name for record in records for name in record["features"]}), dtype=str
    )
    interval_index = {name: idx for idx, name in enumerate(interval_names)}
    values = np.full(
        (len(records), len(interval_names), len(quantile_probs)), np.nan, dtype=np.float64
    )
    counts = np.zeros((len(records), len(interval_names)), dtype=np.int64)
    for batch_idx, record in enumerate(records):
        for name, quantiles in record["features"].items():
            interval_idx = interval_index[name]
            values[batch_idx, interval_idx, :] = quantiles
            counts[batch_idx, interval_idx] = record["counts"][name]

    dataset = BatchDataset(
        batch_ids=np.asarray([r["batch_id"] for r in records], dtype=str),
        timestamps=np.asarray([r["timestamp"] for r in records], dtype=str),
        labels=np.asarray([r["label"] for r in records], dtype=str),
        descriptions=np.asarray([r["description"] for r in records], dtype=str),
        interval_names=interval_names,
        quantile_probs=quantile_probs,
        values=values,
        counts=counts,
    )
    dataset.validate()
    return dataset


def dataset_manifest(dataset: BatchDataset) -> dict:
    counts: dict[str, dict[str, int]] = {}
    for description in sorted(np.unique(dataset.descriptions)):
        counts[description] = {}
        for label in ("normal", "rootkit"):
            counts[description][label] = int(
                np.sum((dataset.descriptions == description) & (dataset.labels == label))
            )
    return {
        "batches": len(dataset.batch_ids),
        "intervals": dataset.interval_names.tolist(),
        "quantiles": dataset.quantile_probs.tolist(),
        "counts": counts,
    }


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--quantiles", default=9, type=int)
    args = parser.parse_args(argv)
    dataset = stream_summarize_intervals(args.input, args.quantiles)
    dataset.save(args.output)
    manifest = dataset_manifest(dataset)
    manifest_path = args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
