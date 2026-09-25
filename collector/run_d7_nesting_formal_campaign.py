#!/usr/bin/env python3
"""Frozen one-boot D7 nesting confirmation with matched causal controls."""

from __future__ import annotations

import argparse
import ctypes as ct
import gzip
import hashlib
import json
import os
import platform
import random
import subprocess
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from collect_batch import _set_flag, _stress_command
from collect_d4_batch import _directory_names, _sha256_lines, _spawn_blocked_ls
from run_campaign import ACK, _atomic_manifest, _boot_id
from run_d7_nesting_pilot import (
    COUNTERS, MODULE_BY_STATE, _counter_snapshot, _delete, _loaded_modules,
    _map_value, _set_state, _sha256,
)


PROTOCOL = "D7-nesting-confirmatory-r1-2026-09-21"
STATES = ("unloaded", "pass", "active", "hiding")
CONDITIONS = ("baseline", "cpu", "memory", "mixed")
REPLICATES = 3
ITERATIONS = 20
CARDINALITY = 128
FILENAME_LENGTH = 32
EXPECTED_BATCHES = 48
STATE_ORDERS = (
    ("unloaded", "pass", "hiding", "active"),
    ("pass", "active", "unloaded", "hiding"),
    ("active", "hiding", "pass", "unloaded"),
    ("hiding", "unloaded", "active", "pass"),
)
NESTING_MAPS = (
    "depth_by_pid", "top_has_child", "top_level_calls",
    "forwarded_top_calls", "short_circuit_top_calls",
    "max_depth_by_pid", "return_underflows",
)
TIMING_MAPS = (
    "iterate_start", "iterate_calls", "first_iterate_ns", "last_iterate_ns",
)


def state_order(sequence: int) -> tuple[str, ...]:
    if sequence not in range(1, 9):
        raise ValueError("sequence must be 1..8")
    return STATE_ORDERS[(sequence - 1) % 4]


def build_schedule(sequence: int, seed: int) -> tuple[list[dict], tuple[str, ...]]:
    order = state_order(sequence)
    schedule = []
    for episode_ordinal, state in enumerate(order):
        block = [
            {"state": state, "condition": condition, "replicate": replicate}
            for condition in CONDITIONS
            for replicate in range(REPLICATES)
        ]
        random.Random(seed + episode_ordinal * 1009).shuffle(block)
        for row in block:
            row["episode_ordinal"] = episode_ordinal
            schedule.append(row)
    for position, row in enumerate(schedule):
        row.update({"position": position, "status": "pending", "output": None})
    if len(schedule) != EXPECTED_BATCHES:
        raise AssertionError(len(schedule))
    return schedule, order


def structural_alert(forwarded: int, shorted: int) -> bool:
    return forwarded > 0 and shorted > 0


def _collect_batch(
    *, enabled, monitored, maps: dict, fixture: Path, hidden: str,
    expected: set[str], state: str, condition: str, position: int,
    campaign_id: str, output: Path, boot_id: str, seed: int,
) -> Path:
    module = MODULE_BY_STATE.get(state)
    before = _counter_snapshot(module)
    stress = None
    transactions = []
    mismatch_iterations = []
    hidden_visible = 0
    command = _stress_command(condition, 4, "256M")
    started_utc = datetime.now(timezone.utc).isoformat()
    try:
        if command:
            stress = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(1.0)
        enabled_start = time.monotonic_ns()
        _set_flag(enabled, 1)
        for iteration in range(ITERATIONS):
            with tempfile.TemporaryFile() as output_stream:
                process = _spawn_blocked_ls(str(fixture), output_stream)
                key = ct.c_uint(process.pid)
                monitored[key] = ct.c_ubyte(1)
                try:
                    assert process.stdin is not None
                    process.stdin.write(b"\n")
                    process.stdin.close()
                    process.stdin = None
                    process.wait(timeout=60)
                    _stdout, stderr = process.communicate()
                    if process.returncode:
                        raise RuntimeError(stderr.decode("utf-8", "replace"))
                    output_stream.seek(0)
                    observed = output_stream.read().decode(
                        "utf-8", "replace"
                    ).splitlines()
                    forwarded = _map_value(maps["forwarded_top_calls"], key)
                    shorted = _map_value(
                        maps["short_circuit_top_calls"], key
                    )
                    transactions.append({
                        "iteration": iteration,
                        "top_level_calls": _map_value(
                            maps["top_level_calls"], key
                        ),
                        "forwarded_top_calls": forwarded,
                        "short_circuit_top_calls": shorted,
                        "max_depth": _map_value(
                            maps["max_depth_by_pid"], key
                        ),
                        "return_underflows": _map_value(
                            maps["return_underflows"], key
                        ),
                        "iterate_dir_calls": _map_value(
                            maps["iterate_calls"], key
                        ),
                        "first_raw_wall_ns": _map_value(
                            maps["first_iterate_ns"], key
                        ),
                        "last_raw_wall_ns": _map_value(
                            maps["last_iterate_ns"], key
                        ),
                        "structural_alert": structural_alert(
                            forwarded, shorted
                        ),
                    })
                finally:
                    _delete(monitored, key)
                    for table in maps.values():
                        _delete(table, key)
            if set(observed) != expected or len(observed) != len(expected):
                mismatch_iterations.append(iteration)
            if hidden in observed:
                hidden_visible += 1
        _set_flag(enabled, 0)
        enabled_wall_ns = time.monotonic_ns() - enabled_start
    finally:
        _set_flag(enabled, 0)
        if stress is not None:
            stress.terminate()
            try:
                stress.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stress.kill()
                stress.wait()
    after = _counter_snapshot(module)
    complete = (
        len(transactions) == ITERATIONS
        and all(
            row["top_level_calls"]
            == row["forwarded_top_calls"] + row["short_circuit_top_calls"]
            and row["top_level_calls"] > 0
            and row["return_underflows"] == 0
            and row["iterate_dir_calls"] >= 2
            and row["first_raw_wall_ns"] > 0
            and row["last_raw_wall_ns"] > 0
            for row in transactions
        )
    )
    exact_output = not mismatch_iterations
    record = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "batch_id": uuid.uuid4().hex,
        "evidence_role": "locked_confirmatory",
        "truth": {"state": state, "condition": condition},
        "environment": {"boot_id": boot_id, "kernel": platform.release()},
        "collection": {
            "campaign_id": campaign_id,
            "campaign_position": position,
            "campaign_seed": seed,
            "started_utc": started_utc,
            "enabled_wall_duration_ns": enabled_wall_ns,
            "structural_decision_inputs": [
                "forwarded_top_calls", "short_circuit_top_calls"
            ],
            "timing_comparator_inputs": [
                "first_raw_wall_ns", "last_raw_wall_ns"
            ],
        },
        "directory_factor": {
            "visible_cardinality": CARDINALITY,
            "filename_length": FILENAME_LENGTH,
            "fixture_inode": fixture.stat().st_ino,
        },
        "listing_audit_not_detector_input": {
            "exact_output_pass": exact_output,
            "mismatch_iterations": mismatch_iterations,
            "hidden_visible_iterations": hidden_visible,
        },
        "module_counter_audit_not_detector_input": {
            name: after[name] - before[name] for name in COUNTERS
        },
        "quality": {
            "valid_for_analysis": complete and exact_output,
            "all_transactions_complete": complete,
            "exact_output_pass": exact_output,
        },
        "transactions": transactions,
    }
    path = output / f"batch_{position:03d}_{record['batch_id'][:8]}.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(record, handle, separators=(",", ":"))
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pass-ko", required=True, type=Path)
    parser.add_argument("--active-ko", required=True, type=Path)
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
    if subprocess.run(
        ["ip", "route", "show", "default"], check=True,
        capture_output=True, text=True,
    ).stdout.strip():
        raise RuntimeError("default route present")
    modules = {
        "pass": args.pass_ko.resolve(),
        "active": args.active_ko.resolve(),
        "hiding": args.hiding_ko.resolve(),
    }
    known = set(MODULE_BY_STATE.values()) | {"caraxes", "caraxes_sham"}
    if _loaded_modules() & known:
        raise RuntimeError("D7/CARAXES module loaded at campaign start")
    output = args.output.resolve()
    fixture = output.parent / f"{output.name}_fixture"
    if output.exists() or fixture.exists():
        raise FileExistsError("refusing to overwrite formal output/fixture")
    output.mkdir(parents=True)
    fixture.mkdir()
    visible, hidden, creation, slot = _directory_names(
        CARDINALITY, FILENAME_LENGTH, "middle"
    )
    for name in creation:
        (fixture / name).touch()
    source = Path(__file__).with_name("bpf_d7_nesting_formal.c")
    bpf = BPF(src_file=str(source))
    for event in (b"filldir64", b"iterate_dir"):
        if not BPF.get_kprobe_functions(event):
            raise RuntimeError(f"required kprobe unavailable: {event!r}")
    bpf.attach_kprobe(event="filldir64", fn_name="trace_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="trace_filldir64_return", maxactive=256
    )
    bpf.attach_kprobe(event="iterate_dir", fn_name="trace_iterate_dir_enter")
    bpf.attach_kretprobe(
        event="iterate_dir", fn_name="trace_iterate_dir_return", maxactive=128
    )
    enabled = bpf["collection_enabled"]
    monitored = bpf["monitored_pids"]
    maps = {name: bpf[name] for name in (*NESTING_MAPS, *TIMING_MAPS)}
    boot_id = _boot_id()
    campaign_id = f"d7formal_{boot_id}_{args.seed}_{uuid.uuid4().hex[:8]}"
    schedule, order = build_schedule(args.sequence, args.seed)
    manifest = {
        "protocol_revision": PROTOCOL,
        "status": "running",
        "evidence_role": "locked_confirmatory",
        "campaign_id": campaign_id,
        "sequence": args.sequence,
        "state_order": list(order),
        "boot_id": boot_id,
        "seed": args.seed,
        "expected_batches": EXPECTED_BATCHES,
        "iterations": ITERATIONS,
        "fixture_inode": fixture.stat().st_ino,
        "fixture_creation_order_sha256": _sha256_lines(
            creation, sorted_lines=False
        ),
        "fixture_hidden_creation_index": slot,
        "source_hashes": {
            "campaign_runner": _sha256(Path(__file__)),
            "helper": _sha256(Path(__file__).with_name("run_d7_nesting_pilot.py")),
            "bpf": _sha256(source),
            **{f"module_{state}": _sha256(path) for state, path in modules.items()},
        },
        "schedule": schedule,
    }
    manifest_path = output / f"campaign_{campaign_id}.json"
    _atomic_manifest(manifest_path, manifest)
    try:
        for item in schedule:
            _set_state(item["state"], modules)
            expected = {".", "..", *visible}
            if item["state"] != "hiding":
                expected.add(hidden)
            path = _collect_batch(
                enabled=enabled, monitored=monitored, maps=maps,
                fixture=fixture, hidden=hidden, expected=expected,
                state=item["state"], condition=item["condition"],
                position=item["position"], campaign_id=campaign_id,
                output=output, boot_id=boot_id, seed=args.seed,
            )
            item.update({
                "status": "complete", "output": str(path),
                "completed_utc": datetime.now(timezone.utc).isoformat(),
            })
            _atomic_manifest(manifest_path, manifest)
    except BaseException as exc:
        manifest.update({
            "status": "failed", "failure": f"{type(exc).__name__}: {exc}",
            "failed_utc": datetime.now(timezone.utc).isoformat(),
        })
        _atomic_manifest(manifest_path, manifest)
        raise
    finally:
        _set_flag(enabled, 0)
        _set_state("unloaded", modules)
        bpf.cleanup()
    manifest["status"] = "complete"
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    _atomic_manifest(manifest_path, manifest)
    print(manifest_path)


if __name__ == "__main__":
    main()
