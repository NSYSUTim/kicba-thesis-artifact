#!/usr/bin/env python3
"""D4 first/last iterate_dir timing with in-kernel per-PID aggregation."""

from __future__ import annotations

import argparse
import ctypes as ct
import gzip
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from collect_batch import (
    _cpu_frequency_snapshot,
    _module_loaded,
    _read_boot_id,
    _set_flag,
    _stress_command,
)
from collect_d4_batch import _directory_names, _sha256_lines, _spawn_blocked_ls


PROTOCOL_REVISION = "D4-aggregate-development-2026-09-19"


def _proc_stat_snapshot() -> dict[str, int]:
    snapshot: dict[str, int] = {}
    for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "cpu":
            values = [int(value) for value in parts[1:]]
            names = ("user", "nice", "system", "idle", "iowait", "irq",
                     "softirq", "steal", "guest", "guest_nice")
            snapshot.update({f"cpu_{name}": value for name, value in zip(names, values)})
        elif parts[0] in {"ctxt", "intr", "softirq"}:
            snapshot[parts[0]] = int(parts[1])
    required = {"cpu_user", "cpu_nice", "cpu_system", "cpu_idle", "cpu_iowait",
                "cpu_irq", "cpu_softirq", "cpu_steal", "ctxt", "intr", "softirq"}
    if not required <= snapshot.keys():
        raise RuntimeError(f"incomplete /proc/stat snapshot: {required - snapshot.keys()}")
    return snapshot


def _proc_stat_context(before: dict[str, int], after: dict[str, int], duration_ns: int) -> dict:
    delta = {key: after[key] - before[key] for key in before}
    busy = sum(delta[key] for key in (
        "cpu_user", "cpu_nice", "cpu_system", "cpu_irq", "cpu_softirq", "cpu_steal"
    ))
    idle = delta["cpu_idle"] + delta["cpu_iowait"]
    total = busy + idle
    seconds = duration_ns / 1e9
    return {
        "source": "/proc/stat",
        "cpu_busy_fraction": busy / total if total > 0 else None,
        "context_switches_per_second": delta["ctxt"] / seconds if seconds > 0 else None,
        "interrupts_per_second": delta["intr"] / seconds if seconds > 0 else None,
        "softirqs_per_second": delta["softirq"] / seconds if seconds > 0 else None,
        "cpu_ticks_delta": total,
    }


def _map_value(table, key: ct.c_uint) -> int | None:
    try:
        return int(table[key].value)
    except KeyError:
        return None


def _delete_if_present(table, key: ct.c_uint) -> None:
    try:
        del table[key]
    except KeyError:
        pass


def collect(args: argparse.Namespace) -> Path:
    if os.geteuid() != 0:
        raise PermissionError("Run the aggregate collector as root")
    if args.label == "rootkit" and not _module_loaded("caraxes"):
        raise RuntimeError("Refusing rootkit label because CARAXES is not loaded")
    if args.label == "normal" and _module_loaded("caraxes"):
        raise RuntimeError("Refusing normal label because CARAXES is loaded")
    if args.probe_profile != "role_aggregate" or args.poll_policy != "none":
        raise ValueError("aggregate collector requires role_aggregate and none policy")

    visible, hidden, creation, hidden_creation_index = _directory_names(
        args.directory_cardinality, args.filename_length, args.hidden_slot
    )
    source_path = Path(__file__).with_name("bpf_d4_aggregate.c")
    bpf = BPF(src_file=str(source_path))
    if not BPF.get_kprobe_functions(b"iterate_dir"):
        raise RuntimeError("iterate_dir kprobe is unavailable")
    bpf.attach_kprobe(event="iterate_dir", fn_name="trace_iterate_dir_enter")
    bpf.attach_kretprobe(event="iterate_dir", fn_name="trace_iterate_dir_return")
    monitored = bpf["monitored_pids"]
    enabled = bpf["collection_enabled"]
    starts = bpf["start_times"]
    counts = bpf["call_counts"]
    first = bpf["first_durations"]
    last = bpf["last_durations"]

    expected = [".", "..", *visible]
    if args.label == "normal":
        expected.append(hidden)
    expected_set = set(expected)
    transactions: list[dict] = []
    mismatch_iterations: list[int] = []
    first_observed_order: list[str] | None = None
    order_hashes: dict[str, int] = {}
    observed_set_hashes: dict[str, int] = {}
    hidden_visible_iterations = 0
    stress = None
    condition_command = _stress_command(
        args.condition, args.cpu_workers, args.memory
    )
    started_wall = datetime.now(timezone.utc).isoformat()
    started_mono = time.monotonic_ns()
    initial_cpu_frequency_khz = _cpu_frequency_snapshot()
    enabled_started_ns = 0
    enabled_ended_ns = 0
    cpu_started_ns = 0
    cpu_ended_ns = 0
    proc_stat_before: dict[str, int] | None = None
    proc_stat_after: dict[str, int] | None = None
    fixture_dir = getattr(args, "fixture_dir", None)
    temp_context = (
        None if fixture_dir else tempfile.TemporaryDirectory(prefix="kicba-d4-agg-")
    )
    temp_dir = Path(fixture_dir).resolve() if fixture_dir else Path(temp_context.name)
    if fixture_dir:
        if not temp_dir.is_dir() or not all(
            (temp_dir / name).is_file() for name in creation
        ):
            raise RuntimeError("persistent fixture is missing expected files")
    fixture_stat = temp_dir.stat()
    created_paths: list[Path] = []
    try:
        if temp_context is not None:
            for name in creation:
                path = temp_dir / name
                path.touch()
                created_paths.append(path)
        if condition_command:
            stress = subprocess.Popen(
                condition_command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(args.warmup_seconds)
        enabled_started_ns = time.monotonic_ns()
        cpu_started_ns = time.process_time_ns()
        proc_stat_before = _proc_stat_snapshot()
        _set_flag(enabled, 1)
        for iteration in range(args.iterations):
            with tempfile.TemporaryFile() as output_stream:
                process = _spawn_blocked_ls(str(temp_dir), output_stream)
                key = ct.c_uint(process.pid)
                monitored[key] = ct.c_ubyte(1)
                try:
                    assert process.stdin is not None
                    process.stdin.write(b"\n")
                    process.stdin.close()
                    process.stdin = None
                    try:
                        process.wait(timeout=args.iteration_timeout_seconds)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise TimeoutError(f"ls iteration {iteration} timed out")
                    _stdout, stderr = process.communicate()
                    if process.returncode:
                        raise RuntimeError(stderr.decode("utf-8", "replace"))
                    output_stream.seek(0)
                    observed = output_stream.read().decode(
                        "utf-8", "replace"
                    ).splitlines()
                    call_count = _map_value(counts, key)
                    first_ns = _map_value(first, key)
                    last_ns = _map_value(last, key)
                    incomplete_start = _map_value(starts, key) is not None
                    transactions.append(
                        {
                            "iteration": iteration,
                            "pid": process.pid,
                            "call_count": call_count,
                            "first_raw_wall_ns": first_ns,
                            "last_raw_wall_ns": last_ns,
                            "incomplete_start": incomplete_start,
                        }
                    )
                finally:
                    _delete_if_present(monitored, key)
                    for table in (starts, counts, first, last):
                        _delete_if_present(table, key)
            if first_observed_order is None:
                first_observed_order = observed
            if set(observed) != expected_set or len(observed) != len(expected):
                mismatch_iterations.append(iteration)
            if hidden in observed:
                hidden_visible_iterations += 1
            order_hash = _sha256_lines(observed, sorted_lines=False)
            set_hash = _sha256_lines(observed, sorted_lines=True)
            order_hashes[order_hash] = order_hashes.get(order_hash, 0) + 1
            observed_set_hashes[set_hash] = observed_set_hashes.get(set_hash, 0) + 1
    finally:
        _set_flag(enabled, 0)
        proc_stat_after = _proc_stat_snapshot()
        cpu_ended_ns = time.process_time_ns()
        enabled_ended_ns = time.monotonic_ns()
        if stress is not None:
            stress.terminate()
            try:
                stress.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stress.kill()
                stress.wait()
        for path in reversed(created_paths):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        if temp_context is not None:
            temp_context.cleanup()
        bpf.cleanup()

    ended_mono = time.monotonic_ns()
    ended_wall = datetime.now(timezone.utc).isoformat()
    complete = (
        len(transactions) == args.iterations
        and all(
            item["call_count"] is not None
            and item["call_count"] >= 2
            and item["first_raw_wall_ns"] is not None
            and item["last_raw_wall_ns"] is not None
            and not item["incomplete_start"]
            for item in transactions
        )
    )
    exact_output = not mismatch_iterations
    valid = complete and exact_output
    first_observed_order = first_observed_order or []
    batch_id = (
        f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}_"
        f"{uuid.uuid4().hex[:8]}"
    )
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"batch_{batch_id}.json.gz"
    record = {
        "schema_version": 4,
        "protocol_revision": PROTOCOL_REVISION,
        "batch_id": batch_id,
        "truth": {"label": args.label, "condition": args.condition},
        "directory_factor": {
            "visible_cardinality": args.directory_cardinality,
            "filename_length": args.filename_length,
            "hidden_slot": args.hidden_slot,
            "hidden_creation_index": hidden_creation_index,
            "creation_order_sha256": _sha256_lines(creation, sorted_lines=False),
            "fixture_mode": "persistent" if fixture_dir else "ephemeral",
            "fixture_device": fixture_stat.st_dev,
            "fixture_inode": fixture_stat.st_ino,
        },
        "environment": {
            "kernel": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "is_wsl": "microsoft" in platform.release().lower(),
            "boot_id": _read_boot_id(),
        },
        "collection": {
            "started_wall": started_wall,
            "ended_wall": ended_wall,
            "duration_ns": ended_mono - started_mono,
            "enabled_started_ns": enabled_started_ns,
            "enabled_ended_ns": enabled_ended_ns,
            "enabled_wall_duration_ns": enabled_ended_ns - enabled_started_ns,
            "collector_process_cpu_ns": cpu_ended_ns - cpu_started_ns,
            "iterations": args.iterations,
            "condition_command": condition_command,
            "probe_profile": args.probe_profile,
            "poll_policy": args.poll_policy,
            "event_transport": "bpf_maps",
            "bpf_source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
            "context_tracepoints_enabled": False,
            "attached_functions": ["iterate_dir"],
            "primary_timing_functions": ["iterate_dir"],
            "lost_events": 0,
            "campaign_id": args.campaign_id,
            "campaign_position": args.campaign_position,
            "campaign_phase": args.campaign_phase,
            "campaign_seed": args.campaign_seed,
            "initial_cpu_frequency_khz": initial_cpu_frequency_khz,
            "final_cpu_frequency_khz": _cpu_frequency_snapshot(),
        },
        "batch_context": _proc_stat_context(
            proc_stat_before, proc_stat_after, enabled_ended_ns - enabled_started_ns
        ),
        "listing_validation": {
            "exact_output_pass": exact_output,
            "expected_entry_count": len(expected),
            "expected_set_sha256": _sha256_lines(expected, sorted_lines=True),
            "observed_set_hash_counts": observed_set_hashes,
            "observed_order_hash_counts": order_hashes,
            "mismatch_iterations": mismatch_iterations,
            "hidden_visible_iterations": hidden_visible_iterations,
            "first_observed_entry_count": len(first_observed_order),
            "first_observed_hidden_index": (
                first_observed_order.index(hidden)
                if hidden in first_observed_order else None
            ),
            "first_observed_order": first_observed_order,
            "first_observed_prefix": first_observed_order[:8],
            "first_observed_suffix": first_observed_order[-8:],
        },
        "quality": {
            "valid_for_analysis": valid,
            "exact_output_pass": exact_output,
            "all_transactions_complete": complete,
            "reason": None if valid else "incomplete map transaction or exact output failed",
        },
        "transaction_durations": transactions,
        "events": [],
    }
    with gzip.open(output_path, "wt", encoding="utf-8") as handle:
        json.dump(record, handle, separators=(",", ":"))
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--iterations", default=20, type=int)
    parser.add_argument(
        "--condition", choices=("baseline", "cpu", "memory", "mixed"),
        default="baseline",
    )
    parser.add_argument("--label", choices=("normal", "rootkit"), required=True)
    parser.add_argument("--cpu-workers", default=min(4, os.cpu_count() or 1), type=int)
    parser.add_argument("--memory", default="256M")
    parser.add_argument("--warmup-seconds", default=1.0, type=float)
    parser.add_argument("--iteration-timeout-seconds", default=60.0, type=float)
    parser.add_argument("--probe-profile", default="role_aggregate")
    parser.add_argument("--poll-policy", default="none")
    parser.add_argument("--directory-cardinality", default=128, type=int)
    parser.add_argument("--filename-length", default=32, type=int)
    parser.add_argument("--hidden-slot", choices=("early", "middle", "late"), default="middle")
    parser.add_argument("--fixture-dir", type=Path)
    parser.add_argument("--campaign-id")
    parser.add_argument("--campaign-position", type=int)
    parser.add_argument("--campaign-phase")
    parser.add_argument("--campaign-seed", type=int)
    args = parser.parse_args()
    if args.iterations < 1 or args.directory_cardinality < 1:
        parser.error("iterations and cardinality must be positive")
    if not 24 <= args.filename_length <= 200:
        parser.error("filename length must be in [24, 200]")
    print(collect(args))


if __name__ == "__main__":
    main()
