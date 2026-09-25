#!/usr/bin/env python3
"""Frozen D6-r2 one-boot confirmatory campaign with counterbalanced episodes."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import random
import subprocess
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from collect_d4_batch import _directory_names, _sha256_lines
from run_campaign import ACK, _atomic_manifest, _boot_id
from run_d4_sham_control import _loaded_modules, _set_state, _sha256


PROTOCOL = "D6-r2-2026-09-20"
CALIBRATION_PER_STATE_CONDITION = 25
ITERATIONS = 20
CARDINALITY = 128
FILENAME_LENGTH = 32
EXPECTED_BATCHES = 460
TEST_BATCHES = 360


def _block(segment: str, state: str, condition: str, count: int) -> tuple:
    return segment, state, condition, count


def episode_blocks(sequence: int) -> tuple[list[str], dict[str, list[tuple]]]:
    """Return a five-episode cyclic Latin-square schedule for one boot."""
    if sequence not in range(1, 6):
        raise ValueError("sequence must be 1..5")
    reverse_pair = sequence % 2 == 0
    early_normal = [
        _block("normal_baseline", "unloaded", "baseline", 20),
        _block("benign_cpu", "unloaded", "cpu", 40),
    ]
    workload_normal = [
        _block("benign_memory", "unloaded", "memory", 40),
        _block("benign_mixed", "unloaded", "mixed", 40),
    ]
    if reverse_pair:
        early_normal.reverse()
        workload_normal.reverse()

    attack_conditions = ["baseline", "cpu", "memory", "mixed"]
    shift = (sequence - 1) % len(attack_conditions)
    attack_conditions = attack_conditions[shift:] + attack_conditions[:shift]
    attack = [
        _block(f"attack_{condition}", "hiding", condition, 40)
        for condition in attack_conditions
    ]
    recovery = [
        _block("normal_recovery", "unloaded", "baseline", 40),
    ]
    sham = [
        _block("sham_negative_baseline", "sham", "baseline", 10),
        _block("sham_negative_cpu", "sham", "cpu", 10),
    ]
    if reverse_pair:
        sham.reverse()

    episodes = {
        "normal_early": early_normal,
        "normal_workloads": workload_normal,
        "attack": attack,
        "recovery": recovery,
        "sham_control": sham,
    }
    base_order = list(episodes)
    offset = sequence - 1
    order = base_order[offset:] + base_order[:offset]
    return order, episodes


def build_schedule(sequence: int, seed: int) -> tuple[list[dict], list[str]]:
    calibration = [
        {"phase": "calibration", "state": state, "condition": condition,
         "segment": "calibration", "episode": "calibration",
         "episode_ordinal": -1}
        for state in ("unloaded", "sham")
        for condition in ("baseline", "cpu")
        for _ in range(CALIBRATION_PER_STATE_CONDITION)
    ]
    random.Random(seed).shuffle(calibration)
    order, episodes = episode_blocks(sequence)
    test = []
    for episode_ordinal, episode in enumerate(order):
        for segment, state, condition, count in episodes[episode]:
            for offset in range(count):
                test.append({
                    "phase": "test",
                    "state": state,
                    "condition": condition,
                    "segment": segment,
                    "segment_offset": offset,
                    "episode": episode,
                    "episode_ordinal": episode_ordinal,
                })
    if len(test) != TEST_BATCHES:
        raise AssertionError(len(test))
    counts = Counter(item["state"] for item in test)
    if counts != {"unloaded": 180, "hiding": 160, "sham": 20}:
        raise AssertionError(counts)
    schedule = calibration + test
    if len(schedule) != EXPECTED_BATCHES:
        raise AssertionError(len(schedule))
    for position, item in enumerate(schedule):
        item.update(position=position, status="pending", output=None)
    return schedule, order


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sham-ko", required=True, type=Path)
    parser.add_argument("--hiding-ko", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or "microsoft" in platform.release().lower():
        parser.error("requires root in native isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if _loaded_modules() & {"caraxes", "caraxes_sham"}:
        raise RuntimeError("modules must be unloaded at start")
    if subprocess.run(
        ["ip", "route", "show", "default"], capture_output=True,
        text=True, check=True,
    ).stdout.strip():
        raise RuntimeError("default route present")

    output = args.output.resolve()
    fixture = output.parent / f"{output.name}_fixture"
    if output.exists() or fixture.exists():
        raise FileExistsError("refusing to overwrite D6-r2 output or fixture")
    output.mkdir(parents=True)
    fixture.mkdir()
    visible, hidden, creation, slot = _directory_names(
        CARDINALITY, FILENAME_LENGTH, "middle"
    )
    for name in creation:
        (fixture / name).touch()
    fixture_stat = fixture.stat()
    boot_id = _boot_id()
    campaign_id = f"d6r2_{boot_id}_{args.seed}_{uuid.uuid4().hex[:8]}"
    schedule, episode_order = build_schedule(args.sequence, args.seed)
    collector = Path(__file__).with_name("collect_d4_aggregate_batch.py")
    bpf_source = Path(__file__).with_name("bpf_d4_aggregate.c")
    manifest = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "status": "running",
        "campaign_id": campaign_id,
        "sequence": args.sequence,
        "episode_order": episode_order,
        "boot_id": boot_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "iterations": ITERATIONS,
        "expected_batches": EXPECTED_BATCHES,
        "fixture": str(fixture),
        "fixture_device": fixture_stat.st_dev,
        "fixture_inode": fixture_stat.st_ino,
        "fixture_creation_order_sha256": _sha256_lines(
            creation, sorted_lines=False
        ),
        "fixture_hidden_creation_index": slot,
        "cardinality": CARDINALITY,
        "filename_length": FILENAME_LENGTH,
        "sham_sha256": _sha256(args.sham_ko.resolve()),
        "hiding_sha256": _sha256(args.hiding_ko.resolve()),
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
            command = [
                sys.executable, str(collector),
                "--output", str(output),
                "--fixture-dir", str(fixture),
                "--iterations", str(ITERATIONS),
                "--label", "rootkit" if item["state"] == "hiding" else "normal",
                "--condition", item["condition"],
                "--probe-profile", "role_aggregate",
                "--poll-policy", "none",
                "--directory-cardinality", str(CARDINALITY),
                "--filename-length", str(FILENAME_LENGTH),
                "--hidden-slot", "middle",
                "--campaign-id", campaign_id,
                "--campaign-position", str(item["position"]),
                "--campaign-phase", item["phase"] + ":" + item["state"],
                "--campaign-seed", str(args.seed),
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(
                    f"collector exit={result.returncode}: {result.stderr!r}"
                )
            path = Path(result.stdout.strip().splitlines()[-1])
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                record = json.load(handle)
            if (
                not record["quality"]["valid_for_analysis"]
                or record["environment"]["boot_id"] != boot_id
                or record["directory_factor"]["fixture_inode"] != fixture_stat.st_ino
            ):
                raise RuntimeError(f"invalid D6-r2 batch: {path}")
            item["status"] = "complete"
            item["output"] = str(path)
            item["completed_utc"] = datetime.now(timezone.utc).isoformat()
            _atomic_manifest(manifest_path, manifest)
    except BaseException as exc:
        manifest["status"] = "failed"
        manifest["failure"] = f"{type(exc).__name__}: {exc}"
        manifest["failed_utc"] = datetime.now(timezone.utc).isoformat()
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
