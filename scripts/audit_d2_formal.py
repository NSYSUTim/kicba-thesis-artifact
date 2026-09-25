#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


EXPECTED_CONDITIONS = ("baseline", "cpu", "memory", "mixed")
EXPECTED_LABELS = ("normal", "rootkit")
EXPECTED_PRIMARY = ("iterate_dir", "filldir64", "touch_atime")
EXPECTED_SEEDS = (1001, 1002, 1003, 1004, 1005)
EXPECTED_MODULE_SHA256 = (
    "a4edd4a2bd79d01677af8e95cf7da5511539e87a90fb89143bf49215a868f390"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit(root: Path, state_path: Path) -> dict:
    errors: list[str] = []
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("status") != "complete":
        errors.append(f"state is {state.get('status')!r}, not complete")
    completed_state = state.get("completed_boots", [])
    if len(completed_state) != 5:
        errors.append(f"state contains {len(completed_state)} completed boots, not 5")

    boot_dirs = sorted(path for path in root.glob("boot_*" ) if path.is_dir())
    if [path.name for path in boot_dirs] != [f"boot_{i:02d}" for i in range(1, 6)]:
        errors.append("formal root does not contain exactly boot_01 through boot_05")

    boot_summaries: list[dict] = []
    all_batch_ids: set[str] = set()
    all_boot_ids: list[str] = []
    overall_cells: Counter[tuple[str, str]] = Counter()
    zero_hits_by_label: Counter[tuple[str, str]] = Counter()
    total_batches = 0
    invalid_batches = 0
    lost_events_total = 0
    target_mismatch_batches = 0

    for boot_number, boot_dir in enumerate(boot_dirs, start=1):
        manifests = list(boot_dir.glob("campaign_*.json"))
        if len(manifests) != 1:
            errors.append(f"{boot_dir.name}: found {len(manifests)} manifests")
            continue
        manifest_path = manifests[0]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        schedule = manifest.get("schedule", [])
        boot_id = str(manifest.get("boot_id"))
        all_boot_ids.append(boot_id)
        expected_seed = EXPECTED_SEEDS[boot_number - 1]
        if manifest.get("schema_version") != 2:
            errors.append(f"{boot_dir.name}: manifest schema is not 2")
        if manifest.get("protocol_revision") != "D2-r1-2026-09-14":
            errors.append(f"{boot_dir.name}: wrong protocol revision")
        if tuple(manifest.get("primary_timing_functions", [])) != EXPECTED_PRIMARY:
            errors.append(f"{boot_dir.name}: wrong primary function set")
        if manifest.get("seed") != expected_seed:
            errors.append(f"{boot_dir.name}: seed is not {expected_seed}")
        if manifest.get("rounds") != 30 or manifest.get("iterations_per_batch") != 100:
            errors.append(f"{boot_dir.name}: wrong rounds or iterations")
        if manifest.get("caraxes_sha256") != EXPECTED_MODULE_SHA256:
            errors.append(f"{boot_dir.name}: wrong CARAXES SHA-256")
        if manifest.get("failure") or not manifest.get("completed_utc"):
            errors.append(f"{boot_dir.name}: manifest is failed or incomplete")
        if len(schedule) != 240:
            errors.append(f"{boot_dir.name}: schedule has {len(schedule)} items")
        positions = [item.get("position") for item in schedule]
        if sorted(positions) != list(range(240)):
            errors.append(f"{boot_dir.name}: campaign positions are incomplete or duplicated")
        if any(item.get("status") != "complete" for item in schedule):
            errors.append(f"{boot_dir.name}: schedule contains incomplete item")

        scheduled_cells = Counter(
            (str(item.get("label")), str(item.get("condition"))) for item in schedule
        )
        for label in EXPECTED_LABELS:
            for condition in EXPECTED_CONDITIONS:
                if scheduled_cells[(label, condition)] != 30:
                    errors.append(
                        f"{boot_dir.name}: {label}/{condition} has "
                        f"{scheduled_cells[(label, condition)]} scheduled batches"
                    )

        local_batches = {path.name: path for path in boot_dir.glob("batch_*.json.gz")}
        if len(local_batches) != 240:
            errors.append(f"{boot_dir.name}: found {len(local_batches)} batch files")
        boot_cells: Counter[tuple[str, str]] = Counter()
        boot_invalid = 0
        boot_lost = 0
        boot_mismatches = 0
        for item in schedule:
            batch_name = Path(str(item.get("output"))).name
            batch_path = local_batches.get(batch_name)
            if batch_path is None:
                errors.append(f"{boot_dir.name}: missing scheduled output {batch_name}")
                continue
            with gzip.open(batch_path, "rt", encoding="utf-8") as handle:
                batch = json.load(handle)
            total_batches += 1
            batch_id = str(batch.get("batch_id"))
            if batch_id in all_batch_ids:
                errors.append(f"duplicate batch ID {batch_id}")
            all_batch_ids.add(batch_id)
            truth = batch.get("truth", {})
            cell = (str(truth.get("label")), str(truth.get("condition")))
            boot_cells[cell] += 1
            overall_cells[cell] += 1
            collection = batch.get("collection", {})
            quality = batch.get("quality", {})
            if batch.get("schema_version") != 2:
                errors.append(f"{boot_dir.name}/{batch_name}: schema is not 2")
            if batch.get("environment", {}).get("boot_id") != boot_id:
                errors.append(f"{boot_dir.name}/{batch_name}: boot ID mismatch")
            if collection.get("campaign_id") != manifest.get("campaign_id"):
                errors.append(f"{boot_dir.name}/{batch_name}: campaign ID mismatch")
            if collection.get("campaign_position") != item.get("position"):
                errors.append(f"{boot_dir.name}/{batch_name}: campaign position mismatch")
            if collection.get("campaign_seed") != expected_seed:
                errors.append(f"{boot_dir.name}/{batch_name}: campaign seed mismatch")
            if truth.get("label") != item.get("label") or truth.get("condition") != item.get("condition"):
                errors.append(f"{boot_dir.name}/{batch_name}: truth/schedule mismatch")
            if collection.get("iterations") != 100:
                errors.append(f"{boot_dir.name}/{batch_name}: iterations is not 100")
            if tuple(collection.get("primary_timing_functions", [])) != EXPECTED_PRIMARY:
                errors.append(f"{boot_dir.name}/{batch_name}: wrong primary functions")
            if not quality.get("valid_for_analysis"):
                boot_invalid += 1
            lost = int(collection.get("lost_events", 0))
            boot_lost += lost
            counts = quality.get("target_function_counts", {})
            mismatch = any(
                int(value.get("enter", -1)) != int(value.get("return", -2))
                for value in counts.values()
            )
            if mismatch:
                boot_mismatches += 1
            for function in EXPECTED_PRIMARY:
                function_counts = counts.get(function, {})
                if int(function_counts.get("enter", 0)) <= 0:
                    errors.append(f"{boot_dir.name}/{batch_name}: {function} has no entries")
            for function in quality.get("zero_hit_functions", []):
                zero_hits_by_label[(cell[0], str(function))] += 1

        for label in EXPECTED_LABELS:
            for condition in EXPECTED_CONDITIONS:
                if boot_cells[(label, condition)] != 30:
                    errors.append(
                        f"{boot_dir.name}: raw {label}/{condition} has "
                        f"{boot_cells[(label, condition)]} batches"
                    )
        invalid_batches += boot_invalid
        lost_events_total += boot_lost
        target_mismatch_batches += boot_mismatches
        boot_summaries.append(
            {
                "boot_number": boot_number,
                "boot_id": boot_id,
                "seed": manifest.get("seed"),
                "kernel": manifest.get("kernel"),
                "machine": manifest.get("machine"),
                "batches": sum(boot_cells.values()),
                "cells": {f"{k[0]}/{k[1]}": v for k, v in sorted(boot_cells.items())},
                "invalid_batches": boot_invalid,
                "lost_events": boot_lost,
                "target_mismatch_batches": boot_mismatches,
                "manifest_sha256": _sha256(manifest_path),
            }
        )

    if len(set(all_boot_ids)) != 5:
        errors.append(f"found {len(set(all_boot_ids))} unique boot IDs, not 5")
    if total_batches != 1200:
        errors.append(f"audited {total_batches} batches, not 1200")
    if invalid_batches:
        errors.append(f"found {invalid_batches} collector-invalid batches")
    if lost_events_total:
        errors.append(f"found {lost_events_total} lost events")
    if target_mismatch_batches:
        errors.append(f"found {target_mismatch_batches} batches with target mismatches")

    report = {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "pass" if not errors else "fail",
        "protocol_revision": "D2-r1-2026-09-14",
        "formal_root": str(root.resolve()),
        "state_path": str(state_path.resolve()),
        "state_sha256": _sha256(state_path),
        "unique_boot_ids": len(set(all_boot_ids)),
        "total_batches": total_batches,
        "invalid_batches": invalid_batches,
        "lost_events": lost_events_total,
        "target_mismatch_batches": target_mismatch_batches,
        "overall_cells": {
            f"{key[0]}/{key[1]}": value for key, value in sorted(overall_cells.items())
        },
        "zero_hits_by_label": {
            f"{key[0]}/{key[1]}": value
            for key, value in sorted(zero_hits_by_label.items())
        },
        "boots": boot_summaries,
        "errors": errors,
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = audit(args.root, args.state)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
