#!/usr/bin/env python3
"""Validate the sealed four-scenario Trace of the Times evaluation outputs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


SCENARIOS = {"default", "file_count", "system_load", "filename_length"}
GROUPINGS = ("fun", "seq")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def validate_grouping(root: Path, grouping: str) -> dict[str, object]:
    directory = root / f"evaluation_four_{grouping}"
    best = directory / f"results_offline_best_shift_{grouping}.csv"
    confusion = directory / f"results_offline_confusion_shift_{grouping}.csv"
    all_results = directory / f"results_offline_all_shift_{grouping}.csv"
    stdout = directory / "stdout.log"
    resource = directory / "resource.log"
    summary = directory / "summary.json"
    required = (best, confusion, all_results, stdout, resource, summary)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SystemExit(f"missing {grouping} outputs: {missing}")

    best_rows = read_csv(best)
    if len(best_rows) != 100:
        raise SystemExit(f"{grouping}: expected 100 best rows, found {len(best_rows)}")
    run_ids = sorted(int(row["run"]) for row in best_rows)
    if run_ids != list(range(1, 101)):
        raise SystemExit(f"{grouping}: run ids are not exactly 1..100")

    stdout_text = stdout.read_text(encoding="utf-8", errors="replace")
    completed_runs = stdout_text.count("Results (Run")
    if completed_runs != 100:
        raise SystemExit(f"{grouping}: stdout records {completed_runs} completed runs")

    report = json.loads(summary.read_text(encoding="utf-8"))
    if report.get("runs") != 100:
        raise SystemExit(f"{grouping}: summary does not contain 100 runs")
    reported_scenarios = set(report.get("by_same_scenario", {}))
    if reported_scenarios != SCENARIOS:
        raise SystemExit(
            f"{grouping}: scenarios {sorted(reported_scenarios)} != {sorted(SCENARIOS)}"
        )

    return {
        "directory": str(directory),
        "completed_runs": completed_runs,
        "best_rows": len(best_rows),
        "scenarios": sorted(reported_scenarios),
        "overall_mean": {
            "recall": report["overall"]["tpr"]["mean"],
            "fpr": report["overall"]["fpr"]["mean"],
            "precision": report["overall"]["p"]["mean"],
            "f1": report["overall"]["fone"]["mean"],
            "accuracy": report["overall"]["acc"]["mean"],
        },
        "sha256": {path.name: sha256(path) for path in required},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("event_count") != 1000:
        raise SystemExit("manifest event_count is not 1000")
    if set(manifest.get("included_scenarios", [])) != SCENARIOS:
        raise SystemExit("manifest does not contain the four frozen scenarios")
    expected_counts = {
        f"{scenario}/{label}": count
        for scenario in SCENARIOS
        for label, count in (("normal", 150), ("rootkit", 100))
    }
    if manifest.get("counts") != expected_counts:
        raise SystemExit("manifest scenario/label counts do not match the frozen matrix")

    validation = {
        "status": "PASS",
        "manifest": str(args.manifest),
        "manifest_sha256": sha256(args.manifest),
        "event_count": manifest["event_count"],
        "groupings": {
            grouping: validate_grouping(args.root, grouping)
            for grouping in GROUPINGS
        },
    }
    args.output.write_text(
        json.dumps(validation, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(validation, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
