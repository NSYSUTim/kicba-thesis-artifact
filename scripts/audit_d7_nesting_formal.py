#!/usr/bin/env python3
"""Integrity audit for locked D7 eight-boot formal data."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path


PROTOCOL = "D7-nesting-confirmatory-r1-2026-09-21"
STATES = ("unloaded", "pass", "active", "hiding")
CONDITIONS = ("baseline", "cpu", "memory", "mixed")
STATE_ORDERS = (
    ("unloaded", "pass", "hiding", "active"),
    ("pass", "active", "unloaded", "hiding"),
    ("active", "hiding", "pass", "unloaded"),
    ("hiding", "unloaded", "active", "pass"),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_hashes(files: dict) -> tuple[dict, list[str]]:
    actual = {}
    failures = []
    for name, item in files.items():
        path = Path(item["path"])
        actual[name] = _sha256(path)
        if actual[name] != item["sha256"]:
            failures.append(f"local file hash mismatch: {name}")
    return actual, failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    state = json.loads(args.state.read_text(encoding="utf-8"))
    failures = []
    actual_hashes, hash_failures = verify_hashes(lock["files"])
    failures.extend(hash_failures)
    if lock.get("protocol_revision") != PROTOCOL:
        failures.append("lock protocol mismatch")
    if state.get("protocol_revision") != PROTOCOL or state.get("status") != "complete":
        failures.append("state is not complete D7")
    if len(state.get("completed_boots", [])) != 8:
        failures.append("state does not contain eight completed boots")
    if state.get("multiboot_runner_sha256") != lock["files"][
        "multiboot_runner"
    ]["sha256"]:
        failures.append("state multiboot hash mismatch")
    if state.get("campaign_runner_sha256") != lock["files"][
        "campaign_runner"
    ]["sha256"]:
        failures.append("state campaign hash mismatch")
    boot_dirs = sorted(
        path for path in args.input.iterdir()
        if path.is_dir() and path.name.startswith("boot_")
    )
    expected_dirs = [f"boot_{index:02d}" for index in range(1, 9)]
    if [path.name for path in boot_dirs] != expected_dirs:
        failures.append("boot directory set mismatch")
    manifests = []
    manifest_hashes = {}
    batch_count = 0
    state_counts = Counter()
    cell_counts = Counter()
    for sequence, root in enumerate(boot_dirs, start=1):
        paths = list(root.glob("campaign_*.json"))
        if len(paths) != 1:
            failures.append(f"manifest count mismatch: {root.name}")
            continue
        path = paths[0]
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifests.append(manifest)
        manifest_hashes[root.name] = _sha256(path)
        expected_order = list(STATE_ORDERS[(sequence - 1) % 4])
        if (
            manifest.get("protocol_revision") != PROTOCOL
            or manifest.get("status") != "complete"
            or manifest.get("sequence") != sequence
            or manifest.get("state_order") != expected_order
        ):
            failures.append(f"manifest identity/order mismatch: {root.name}")
        source = manifest.get("source_hashes", {})
        mapping = {
            "campaign_runner": "campaign_runner",
            "helper": "helper",
            "bpf": "bpf",
        }
        for key, lock_key in mapping.items():
            if source.get(key) != lock["files"][lock_key]["sha256"]:
                failures.append(f"manifest source mismatch {key}: {root.name}")
        for state_name in ("pass", "active", "hiding"):
            if source.get(f"module_{state_name}") != lock["module_hashes"][state_name]:
                failures.append(f"module hash mismatch {state_name}: {root.name}")
        schedule = manifest.get("schedule", [])
        if len(schedule) != 48 or any(
            item.get("status") != "complete" for item in schedule
        ):
            failures.append(f"schedule incomplete: {root.name}")
        expected_cells = Counter({
            (state_name, condition): 3
            for state_name in STATES for condition in CONDITIONS
        })
        schedule_cells = Counter(
            (item.get("state"), item.get("condition")) for item in schedule
        )
        if schedule_cells != expected_cells:
            failures.append(f"schedule cells mismatch: {root.name}")
        raw_paths = sorted(root.glob("batch_*.json.gz"))
        if len(raw_paths) != 48:
            failures.append(f"raw batch count mismatch: {root.name}")
        for raw_path in raw_paths:
            with gzip.open(raw_path, "rt", encoding="utf-8") as handle:
                record = json.load(handle)
            batch_count += 1
            truth = record.get("truth", {})
            state_name = truth.get("state")
            condition = truth.get("condition")
            state_counts[state_name] += 1
            cell_counts[(state_name, condition)] += 1
            if (
                record.get("protocol_revision") != PROTOCOL
                or record.get("evidence_role") != "locked_confirmatory"
                or record.get("environment", {}).get("boot_id")
                != manifest.get("boot_id")
                or not record.get("quality", {}).get("valid_for_analysis")
                or not record.get("quality", {}).get("exact_output_pass")
            ):
                failures.append(f"record quality/identity failure: {raw_path}")
            inputs = record.get("collection", {}).get(
                "structural_decision_inputs"
            )
            if inputs != ["forwarded_top_calls", "short_circuit_top_calls"]:
                failures.append(f"decision input mismatch: {raw_path}")
            rows = record.get("transactions", [])
            if len(rows) != 20:
                failures.append(f"transaction count mismatch: {raw_path}")
            for row in rows:
                if (
                    row.get("top_level_calls")
                    != row.get("forwarded_top_calls", -1)
                    + row.get("short_circuit_top_calls", -1)
                    or row.get("return_underflows") != 0
                    or row.get("iterate_dir_calls", 0) < 2
                ):
                    failures.append(f"transaction invariant failure: {raw_path}")
                    break
    boot_ids = [manifest.get("boot_id") for manifest in manifests]
    if len(boot_ids) != 8 or len(set(boot_ids)) != 8:
        failures.append("boot IDs are not eight unique values")
    completed_ids = [
        item.get("boot_id") for item in state.get("completed_boots", [])
    ]
    if boot_ids != completed_ids:
        failures.append("state/manifest boot ID order mismatch")
    if batch_count != 384:
        failures.append(f"expected 384 batches, got {batch_count}")
    if state_counts != Counter({state_name: 96 for state_name in STATES}):
        failures.append(f"state balance mismatch: {dict(state_counts)}")
    expected_global_cells = Counter({
        (state_name, condition): 24
        for state_name in STATES for condition in CONDITIONS
    })
    if cell_counts != expected_global_cells:
        failures.append("global cell balance mismatch")
    position_balance = {
        state_name: sorted(
            manifest["state_order"].index(state_name) for manifest in manifests
        ) if len(manifests) == 8 else []
        for state_name in STATES
    }
    if any(values != [0, 0, 1, 1, 2, 2, 3, 3]
           for values in position_balance.values()):
        failures.append("state position balance mismatch")
    report = {
        "protocol": PROTOCOL,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "boots": len(boot_ids),
        "unique_boots": len(set(boot_ids)),
        "batches": batch_count,
        "state_counts": dict(state_counts),
        "state_position_balance": position_balance,
        "local_file_hashes": actual_hashes,
        "state_sha256": _sha256(args.state),
        "manifest_sha256": manifest_hashes,
    }
    args.output.mkdir(parents=True)
    (args.output / "audit.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
