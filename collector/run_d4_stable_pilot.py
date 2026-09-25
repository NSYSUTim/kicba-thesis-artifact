#!/usr/bin/env python3
"""Exploratory same-inode D4 pilot; not a D5 confirmatory campaign."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import random
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from collect_d4_batch import _directory_names, _sha256_lines
from run_campaign import ACK, _atomic_manifest, _boot_id
from run_d4_sham_control import _loaded_modules, _set_state, _sha256


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sham-ko", required=True, type=Path)
    parser.add_argument("--hiding-ko", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cardinality", type=int, default=128)
    parser.add_argument("--filename-length", type=int, default=32)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--calibration-per-condition", type=int, default=12)
    parser.add_argument("--sham-calibration-per-condition", type=int, default=0)
    parser.add_argument("--test-per-state-condition", type=int, default=6)
    parser.add_argument("--seed", type=int, default=7601)
    parser.add_argument(
        "--schedule-mode", choices=("randomized", "blocks"), default="randomized"
    )
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or "microsoft" in platform.release().lower():
        parser.error("requires root in native isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if (args.iterations < 1 or args.calibration_per_condition < 1
            or args.sham_calibration_per_condition < 0
            or args.test_per_state_condition < 1):
        parser.error("counts must be positive")
    if _loaded_modules() & {"caraxes", "caraxes_sham"}:
        raise RuntimeError("modules must be unloaded at start")
    if subprocess.run(["ip", "route", "show", "default"],
                      capture_output=True, text=True, check=True).stdout.strip():
        raise RuntimeError("default route present")
    output = args.output.resolve()
    fixture = output.parent / f"{output.name}_fixture"
    if output.exists() or fixture.exists():
        raise FileExistsError("refusing to overwrite output or fixture")
    output.mkdir(parents=True)
    fixture.mkdir()
    visible, hidden, creation, slot = _directory_names(
        args.cardinality, args.filename_length, "middle"
    )
    for name in creation:
        (fixture / name).touch()
    fixture_stat = fixture.stat()
    boot_id = _boot_id()
    campaign_id = f"d4stable_{boot_id}_{args.seed}_{uuid.uuid4().hex[:8]}"
    rng = random.Random(args.seed)
    calibration_schedule = [
        {"phase": "calibration", "state": "unloaded", "condition": condition}
        for condition in ("baseline", "cpu")
        for _ in range(args.calibration_per_condition)
    ]
    calibration_schedule.extend(
        {"phase": "calibration", "state": "sham", "condition": condition}
        for condition in ("baseline", "cpu")
        for _ in range(args.sham_calibration_per_condition)
    )
    rng.shuffle(calibration_schedule)
    if args.schedule_mode == "randomized":
        test = [
            {"phase": "test", "state": state, "condition": condition,
             "segment": "randomized"}
            for state in ("unloaded", "sham", "hiding")
            for condition in ("baseline", "cpu")
            for _ in range(args.test_per_state_condition)
        ]
        rng.shuffle(test)
    else:
        # Long blocks separately expose adaptation latency and persistent-attack
        # contamination for W20, W50, and W100.  The three windows are replayed
        # independently; they are never fused.
        blocks = (
            ("normal_pre", "unloaded", "baseline", 30),
            ("benign_cpu_drift", "unloaded", "cpu", 120),
            ("normal_recovery_1", "unloaded", "baseline", 30),
            ("persistent_attack_baseline", "hiding", "baseline", 120),
            ("normal_recovery_2", "unloaded", "baseline", 30),
            ("persistent_attack_cpu", "hiding", "cpu", 60),
            ("sham_negative_baseline", "sham", "baseline", 20),
            ("sham_negative_cpu", "sham", "cpu", 20),
        )
        test = [
            {"phase": "test", "state": state, "condition": condition,
             "segment": segment, "segment_offset": offset}
            for segment, state, condition, count in blocks
            for offset in range(count)
        ]
    schedule = calibration_schedule + test
    for position, item in enumerate(schedule):
        item.update(position=position, status="pending", output=None)
    collector = Path(__file__).with_name("collect_d4_aggregate_batch.py")
    bpf_source = Path(__file__).with_name("bpf_d4_aggregate.c")
    manifest = {
        "schema_version": 1,
        "protocol_revision": "D4-stable-development-pilot-2026-09-19",
        "status": "running",
        "campaign_id": campaign_id,
        "boot_id": boot_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "iterations": args.iterations,
        "calibration_per_condition": args.calibration_per_condition,
        "sham_calibration_per_condition": args.sham_calibration_per_condition,
        "test_per_state_condition": args.test_per_state_condition,
        "schedule_mode": args.schedule_mode,
        "fixture": str(fixture),
        "fixture_device": fixture_stat.st_dev,
        "fixture_inode": fixture_stat.st_ino,
        "fixture_creation_order_sha256": _sha256_lines(creation, sorted_lines=False),
        "fixture_hidden_creation_index": slot,
        "cardinality": args.cardinality,
        "filename_length": args.filename_length,
        "sham_sha256": _sha256(args.sham_ko),
        "hiding_sha256": _sha256(args.hiding_ko),
        "collector_sha256": _sha256(collector),
        "bpf_source_sha256": _sha256(bpf_source),
        "runner_sha256": _sha256(Path(__file__)),
        "schedule": schedule,
    }
    manifest_path = output / f"campaign_{campaign_id}.json"
    _atomic_manifest(manifest_path, manifest)
    try:
        for item in schedule:
            _set_state(item["state"], args.sham_ko, args.hiding_ko)
            label = "rootkit" if item["state"] == "hiding" else "normal"
            command = [
                sys.executable, str(collector),
                "--output", str(output),
                "--fixture-dir", str(fixture),
                "--iterations", str(args.iterations),
                "--label", label,
                "--condition", item["condition"],
                "--probe-profile", "role_aggregate",
                "--poll-policy", "none",
                "--directory-cardinality", str(args.cardinality),
                "--filename-length", str(args.filename_length),
                "--hidden-slot", "middle",
                "--campaign-id", campaign_id,
                "--campaign-position", str(item["position"]),
                "--campaign-phase", item["phase"] + ":" + item["state"],
                "--campaign-seed", str(args.seed),
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(f"collector exit={result.returncode}: {result.stderr!r}")
            path = Path(result.stdout.strip().splitlines()[-1])
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                record = json.load(handle)
            if (not record["quality"]["valid_for_analysis"]
                or record["environment"]["boot_id"] != boot_id
                or record["directory_factor"]["fixture_inode"] != fixture_stat.st_ino):
                raise RuntimeError(f"invalid stable batch: {path}")
            item["status"] = "complete"
            item["output"] = str(path)
            item["completed_utc"] = datetime.now(timezone.utc).isoformat()
            _atomic_manifest(manifest_path, manifest)
    except BaseException as exc:
        manifest["status"] = "failed"
        manifest["failure"] = f"{type(exc).__name__}: {exc}"
        _atomic_manifest(manifest_path, manifest)
        raise
    finally:
        _set_state("unloaded", args.sham_ko, args.hiding_ko)
    manifest["status"] = "complete"
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    _atomic_manifest(manifest_path, manifest)
    print(manifest_path)


if __name__ == "__main__":
    main()
