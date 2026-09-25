#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


CONDITIONS = ("baseline", "cpu", "memory", "mixed")
PRIMARY = ("iterate_dir", "filldir64", "touch_atime")
TEST_SEEDS = (6101, 6201, 6301, 6401, 6501)
MODULE_SHA256 = "a4edd4a2bd79d01677af8e95cf7da5511539e87a90fb89143bf49215a868f390"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _campaign_specs(root: Path) -> list[tuple[str, Path, str, int, int]]:
    specs = [("calibration", root / "calibration", "calibration", 6001, 120)]
    specs.extend(
        (
            f"test/boot_{number:02d}",
            root / "test" / f"boot_{number:02d}",
            "test",
            TEST_SEEDS[number - 1],
            240,
        )
        for number in range(1, 6)
    )
    return specs


def audit(root: Path, state_path: Path, d2_state_path: Path) -> dict:
    errors: list[str] = []
    state = json.loads(state_path.read_text(encoding="utf-8"))
    d2_state = json.loads(d2_state_path.read_text(encoding="utf-8"))
    if state.get("status") != "complete" or len(state.get("completed_boots", [])) != 6:
        errors.append("D3 state is not complete with exactly six boots")
    if state.get("protocol_revision") != "D3-r1-2026-09-18":
        errors.append("D3 state protocol revision mismatch")
    prior_boot_ids = {
        str(item.get("boot_id")) for item in d2_state.get("completed_boots", [])
    }
    all_boot_ids: list[str] = []
    all_batch_ids: set[str] = set()
    campaign_summaries: list[dict] = []
    total_batches = 0
    invalid_batches = 0
    lost_events = 0
    mismatch_batches = 0

    for name, directory, role, seed, expected_batches in _campaign_specs(root):
        if not directory.is_dir():
            errors.append(f"missing campaign directory {name}")
            continue
        manifests = list(directory.glob("campaign_*.json"))
        if len(manifests) != 1:
            errors.append(f"{name}: expected one manifest, found {len(manifests)}")
            continue
        manifest_path = manifests[0]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        schedule = manifest.get("schedule", [])
        boot_id = str(manifest.get("boot_id"))
        all_boot_ids.append(boot_id)
        if boot_id in prior_boot_ids:
            errors.append(f"{name}: boot ID was already used by D2")
        expected = {
            "schema_version": 3,
            "protocol_revision": "D3-r1-2026-09-18",
            "study_role": role,
            "seed": seed,
            "batches_per_cell": 30,
            "iterations_per_batch": 100,
            "cpu_workers": 4,
            "memory": "256M",
            "caraxes_sha256": MODULE_SHA256,
        }
        for key, value in expected.items():
            if manifest.get(key) != value:
                errors.append(f"{name}: {key} is {manifest.get(key)!r}, expected {value!r}")
        if tuple(manifest.get("primary_timing_functions", [])) != PRIMARY:
            errors.append(f"{name}: primary timing functions mismatch")
        if manifest.get("failure") or not manifest.get("completed_utc"):
            errors.append(f"{name}: manifest failed or incomplete")
        if len(schedule) != expected_batches:
            errors.append(f"{name}: schedule length is {len(schedule)}, expected {expected_batches}")
        if sorted(item.get("position") for item in schedule) != list(
            range(expected_batches)
        ):
            errors.append(f"{name}: positions are missing or duplicated")
        if any(item.get("status") != "complete" for item in schedule):
            errors.append(f"{name}: incomplete schedule item")
        labels = [str(item.get("label")) for item in schedule]
        transitions = sum(
            labels[position] != labels[position - 1]
            for position in range(1, len(labels))
        )
        if role == "calibration":
            if set(labels) != {"normal"} or transitions != 0:
                errors.append(f"{name}: calibration labels are not all normal")
        elif set(labels) != {"normal", "rootkit"} or transitions != 1:
            errors.append(f"{name}: test does not contain two sustained label episodes")
        cells = Counter(
            (str(item.get("label")), str(item.get("condition")))
            for item in schedule
        )
        expected_labels = ("normal",) if role == "calibration" else ("normal", "rootkit")
        for label in expected_labels:
            for condition in CONDITIONS:
                if cells[(label, condition)] != 30:
                    errors.append(
                        f"{name}: scheduled {label}/{condition}={cells[(label, condition)]}, expected 30"
                    )

        local_batches = {path.name: path for path in directory.glob("batch_*.json.gz")}
        if len(local_batches) != expected_batches:
            errors.append(
                f"{name}: found {len(local_batches)} batches, expected {expected_batches}"
            )
        campaign_invalid = 0
        campaign_lost = 0
        campaign_mismatch = 0
        for item in schedule:
            batch_name = Path(str(item.get("output"))).name
            batch_path = local_batches.get(batch_name)
            if batch_path is None:
                errors.append(f"{name}: missing {batch_name}")
                continue
            with gzip.open(batch_path, "rt", encoding="utf-8") as handle:
                batch = json.load(handle)
            total_batches += 1
            batch_id = str(batch.get("batch_id"))
            if batch_id in all_batch_ids:
                errors.append(f"duplicate batch ID {batch_id}")
            all_batch_ids.add(batch_id)
            truth = batch.get("truth", {})
            collection = batch.get("collection", {})
            quality = batch.get("quality", {})
            if batch.get("schema_version") != 2:
                errors.append(f"{name}/{batch_name}: collector schema mismatch")
            if batch.get("environment", {}).get("boot_id") != boot_id:
                errors.append(f"{name}/{batch_name}: boot ID mismatch")
            if (
                collection.get("campaign_id") != manifest.get("campaign_id")
                or collection.get("campaign_position") != item.get("position")
                or collection.get("campaign_seed") != seed
            ):
                errors.append(f"{name}/{batch_name}: campaign metadata mismatch")
            if (
                truth.get("label") != item.get("label")
                or truth.get("condition") != item.get("condition")
            ):
                errors.append(f"{name}/{batch_name}: truth/schedule mismatch")
            if collection.get("iterations") != 100:
                errors.append(f"{name}/{batch_name}: iterations mismatch")
            if tuple(collection.get("primary_timing_functions", [])) != PRIMARY:
                errors.append(f"{name}/{batch_name}: primary functions mismatch")
            if not quality.get("valid_for_analysis"):
                campaign_invalid += 1
            campaign_lost += int(collection.get("lost_events", 0))
            counts = quality.get("target_function_counts", {})
            mismatch = any(
                int(value.get("enter", -1)) != int(value.get("return", -2))
                for value in counts.values()
            )
            campaign_mismatch += int(mismatch)
            for function in PRIMARY:
                if int(counts.get(function, {}).get("enter", 0)) <= 0:
                    errors.append(f"{name}/{batch_name}: {function} has no entries")
        invalid_batches += campaign_invalid
        lost_events += campaign_lost
        mismatch_batches += campaign_mismatch
        campaign_summaries.append(
            {
                "name": name,
                "role": role,
                "boot_id": boot_id,
                "seed": seed,
                "batches": expected_batches,
                "invalid_batches": campaign_invalid,
                "lost_events": campaign_lost,
                "target_mismatch_batches": campaign_mismatch,
                "manifest_sha256": _sha256(manifest_path),
            }
        )

    if len(set(all_boot_ids)) != 6:
        errors.append(f"found {len(set(all_boot_ids))} unique D3 boot IDs, expected 6")
    if total_batches != 1320:
        errors.append(f"audited {total_batches} D3 batches, expected 1320")
    if invalid_batches:
        errors.append(f"found {invalid_batches} invalid batches")
    if lost_events:
        errors.append(f"found {lost_events} lost events")
    if mismatch_batches:
        errors.append(f"found {mismatch_batches} target mismatch batches")
    return {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "pass" if not errors else "fail",
        "protocol_revision": "D3-r1-2026-09-18",
        "formal_root": str(root.resolve()),
        "state_sha256": _sha256(state_path),
        "d2_state_sha256": _sha256(d2_state_path),
        "unique_boot_ids": len(set(all_boot_ids)),
        "total_batches": total_batches,
        "invalid_batches": invalid_batches,
        "lost_events": lost_events,
        "target_mismatch_batches": mismatch_batches,
        "campaigns": campaign_summaries,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--d2-state", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = audit(args.root, args.state, args.d2_state)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
