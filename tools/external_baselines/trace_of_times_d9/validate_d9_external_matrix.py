#!/usr/bin/env python3
"""Validate and summarize the frozen four-scenario D9 comparison matrix."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


EXPECTED = {
    (scenario, label): count
    for scenario in ("default", "file_count", "system_load", "filename_length")
    for label, count in (("normal", 150), ("rootkit", 100))
}
PROTOCOL = "D9-external-four-scenario-matrix-r1-2026-09-24"
RUNNER_SHA256 = "cc7c0ef27d31381070f4d425ad6a84731e2fcf074b83878482c1d5843669183a"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"INVALID: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    log_path = args.directory / "collection.jsonl"
    with log_path.open(encoding="utf-8") as stream:
        summaries = [json.loads(line) for line in stream]
    if len(summaries) != 1000:
        fail(f"collection log has {len(summaries)} records, expected 1000")

    names = [row["file"] for row in summaries]
    if len(set(names)) != len(names):
        fail("collection log contains duplicate filenames")
    disk = {path.name: path for path in args.directory.glob("batch_*.json.gz")}
    if set(disk) != set(names):
        fail("collection log and batch files are not one-to-one")

    counts: Counter[tuple[str, str]] = Counter()
    indices: dict[tuple[str, str], list[int]] = defaultdict(list)
    source_hash_sets: dict[str, set[str]] = defaultdict(set)
    boot_ids: set[str] = set()
    kernels: set[str] = set()
    seed_pairs: set[tuple[int, int]] = set()
    confusion: Counter[str] = Counter()
    scenario_confusion: dict[str, Counter[str]] = defaultdict(Counter)
    elapsed_by_scenario: dict[str, list[float]] = defaultdict(list)
    transactions = 0

    for position, summary in enumerate(summaries, 1):
        path = disk[summary["file"]]
        if sha256(path) != summary.get("sha256"):
            fail(f"hash mismatch for {path.name}")
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            row = json.load(stream)

        key = (row.get("scenario"), row.get("label"))
        if key not in EXPECTED:
            fail(f"batch {position} has unexpected group {key}")
        if summary.get("scenario") != key[0] or summary.get("label") != key[1]:
            fail(f"summary metadata mismatch for {path.name}")
        if summary.get("index") != row.get("index"):
            fail(f"summary index mismatch for {path.name}")
        if summary.get("valid") is not True or row.get("valid") is not True:
            fail(f"batch not marked valid: {path.name}")
        if (
            row.get("protocol_revision") != PROTOCOL
            or row.get("iterations") != 100
            or row.get("buffer_size") != 65536
            or row.get("cell_count") != 256
        ):
            fail(f"frozen protocol mismatch for {path.name}")
        if row.get("source_hashes", {}).get("runner") != RUNNER_SHA256:
            fail(f"runner hash mismatch for {path.name}")

        batch_transactions = row.get("transactions")
        if not isinstance(batch_transactions, list) or len(batch_transactions) != 100:
            fail(f"{path.name} does not contain exactly 100 transactions")
        positive = key[1] == "rootkit"
        expected_difference = int(row.get("expected_difference_count"))
        if expected_difference != (int(row["parameters"]["hidden_files"]) if positive else 0):
            fail(f"unexpected difference count for {path.name}")
        if bool(row.get("batch_detected")) != positive:
            fail(f"wrong batch decision for {path.name}")

        for transaction in batch_transactions:
            if (
                transaction.get("measurement_valid") is not True
                or transaction.get("decode_success") is not True
                or transaction.get("decoded_exact") is not True
                or bool(transaction.get("difference_detected")) != positive
                or int(transaction.get("upstream_only_count")) != expected_difference
                or int(transaction.get("downstream_only_count")) != 0
                or int(transaction.get("residual_cells")) != 0
            ):
                fail(f"invalid transaction in {path.name}")
            outcome = "tp" if positive else "tn"
            confusion[outcome] += 1
            scenario_confusion[key[0]][outcome] += 1
            transactions += 1

        counts[key] += 1
        indices[key].append(int(row["index"]))
        elapsed_by_scenario[key[0]].append(float(row["elapsed_seconds"]))
        boot_ids.add(row["environment"]["boot_id"])
        kernels.add(row["environment"]["kernel"])
        seed_pairs.add((int(row["hash_seed1"]), int(row["hash_seed2"])))
        for name, value in row["source_hashes"].items():
            source_hash_sets[name].add(value)

    for key, count in EXPECTED.items():
        if counts[key] != count:
            fail(f"{key} has {counts[key]} batches; expected {count}")
        if sorted(indices[key]) != list(range(count)):
            fail(f"{key} indices are not exactly 0..{count - 1}")
    if len(boot_ids) != 1 or len(kernels) != 1 or len(seed_pairs) != 1:
        fail("environment or hash seeds changed within the matrix")
    if any(len(values) != 1 for values in source_hash_sets.values()):
        fail("a source hash changed within the matrix")
    if transactions != 100000:
        fail(f"found {transactions} transactions, expected 100000")

    report = {
        "status": "valid",
        "batches": len(summaries),
        "transactions": transactions,
        "boot_id": next(iter(boot_ids)),
        "kernel": next(iter(kernels)),
        "hash_seed_pair": list(next(iter(seed_pairs))),
        "collection_log_sha256": sha256(log_path),
        "counts": {f"{key[0]}/{key[1]}": counts[key] for key in EXPECTED},
        "confusion": dict(confusion),
        "per_scenario_confusion": {
            scenario: dict(values) for scenario, values in scenario_confusion.items()
        },
        "elapsed_seconds": {
            scenario: {
                "sum": sum(values),
                "mean_per_batch": statistics.fmean(values),
                "median_per_batch": statistics.median(values),
            }
            for scenario, values in elapsed_by_scenario.items()
        },
        "source_hashes": {
            name: next(iter(values)) for name, values in source_hash_sets.items()
        },
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
