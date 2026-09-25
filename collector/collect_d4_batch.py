#!/usr/bin/env python3
"""D4 collector with exact directory-output validation and role metadata.

This intentionally lives beside, rather than replacing, the frozen D2/D3
collector.  D4 changes the benchmark semantics and therefore has its own
schema and hash.
"""

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
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from collect_batch import (
    EVENT_NAMES,
    FUNCTIONS,
    Event,
    _cpu_frequency_snapshot,
    _module_loaded,
    _read_boot_id,
    _set_flag,
    _stress_command,
)


PROTOCOL_REVISION = "D4-development-2026-09-19"
PROFILE_FUNCTIONS = {
    "role": ("iterate_dir",),
    "security": ("iterate_dir", "filldir64"),
    "full": ("iterate_dir", "filldir64", "verify_dirent_name", "touch_atime"),
    "role_minimal": ("iterate_dir",),
    "security_minimal": ("iterate_dir", "filldir64"),
}


def _sha256_lines(lines: list[str], *, sorted_lines: bool) -> str:
    values = sorted(lines) if sorted_lines else lines
    payload = ("\n".join(values) + "\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _padded_name(prefix: str, index: int, length: int) -> str:
    stem = f"{prefix}_{index:04d}_"
    if len(stem) > length:
        raise ValueError(f"filename length {length} is too short for {stem!r}")
    return stem + ("x" * (length - len(stem)))


def _directory_names(cardinality: int, filename_length: int, hidden_slot: str):
    visible = [
        _padded_name("visible", index, filename_length)
        for index in range(cardinality)
    ]
    hidden = _padded_name("sample_caraxes_hidden", 0, filename_length)
    slots = {"early": 0, "middle": cardinality // 2, "late": cardinality}
    creation = list(visible)
    creation.insert(slots[hidden_slot], hidden)
    return visible, hidden, creation, slots[hidden_slot]


def _spawn_blocked_ls(directory: str, output_stream) -> subprocess.Popen:
    # -U preserves directory enumeration order.  Exact semantic validation is
    # set based, while the order hash is retained for the position factor.
    command = 'read -r _; exec ls -a1U -- "$1"'
    return subprocess.Popen(
        ["bash", "-c", command, "bash", directory],
        stdin=subprocess.PIPE,
        # A pipe can fill for the large-cardinality cells while the parent is
        # polling eBPF events, deadlocking ls.  A temporary file lets both
        # operations advance without dropping either the listing or events.
        stdout=output_stream,
        stderr=subprocess.PIPE,
    )


def _attach_selected(bpf: BPF, selected: tuple[str, ...]) -> list[str]:
    attached: list[str] = []
    for function_name in selected:
        if not BPF.get_kprobe_functions(function_name.encode()):
            raise RuntimeError(f"required probe is unavailable: {function_name}")
        bpf.attach_kprobe(
            event=function_name, fn_name=f"trace_{function_name}_enter"
        )
        bpf.attach_kretprobe(
            event=function_name, fn_name=f"trace_{function_name}_return"
        )
        attached.append(function_name)
    return attached


def collect(args: argparse.Namespace) -> Path:
    if os.geteuid() != 0:
        raise PermissionError("Run the D4 collector as root")
    if args.label == "rootkit" and not _module_loaded("caraxes"):
        raise RuntimeError("Refusing rootkit label because CARAXES is not loaded")
    if args.label == "normal" and _module_loaded("caraxes"):
        raise RuntimeError("Refusing normal label because CARAXES is loaded")

    visible_names, hidden_name, creation_order, hidden_creation_index = (
        _directory_names(
            args.directory_cardinality, args.filename_length, args.hidden_slot
        )
    )
    selected = PROFILE_FUNCTIONS[args.probe_profile]
    minimal_trace = args.probe_profile.endswith("_minimal")
    poll_policy = getattr(args, "poll_policy", "continuous")
    if poll_policy not in {"continuous", "wait_drain"}:
        raise ValueError(f"unknown poll policy {poll_policy!r}")
    if poll_policy == "wait_drain" and args.probe_profile != "role_minimal":
        raise ValueError("wait_drain is restricted to low-volume role_minimal")
    source_path = Path(__file__).with_name(
        "bpf_d4_minimal.c" if minimal_trace else "bpf_context.c"
    )
    bpf = BPF(src_file=str(source_path))
    attached_functions = _attach_selected(bpf, selected)
    events: list[dict] = []
    lost_events = 0

    def on_event(_cpu, data, _size):
        raw = ct.cast(data, ct.POINTER(Event)).contents
        events.append(
            {
                "ts": int(raw.ts),
                "kind": EVENT_NAMES[int(raw.kind)],
                "function": FUNCTIONS.get(int(raw.function_id)),
                "pid": int(raw.pid),
                "tgid": int(raw.tgid),
                "other_pid": int(raw.other_pid),
                "cpu": int(raw.cpu),
                "aux": int(raw.aux),
                "comm": bytes(raw.comm)
                .split(b"\0", 1)[0]
                .decode("utf-8", "replace"),
            }
        )

    def on_lost(_cpu, count):
        nonlocal lost_events
        lost_events += int(count)

    bpf["events"].open_perf_buffer(on_event, page_cnt=256, lost_cb=on_lost)
    monitored = bpf["monitored_pids"]
    enabled = bpf["collection_enabled"]
    condition_command = _stress_command(
        args.condition, args.cpu_workers, args.memory
    )
    stress = None

    expected = [".", "..", *visible_names]
    if args.label == "normal":
        expected.append(hidden_name)
    expected_set = set(expected)
    observed_order_hashes: Counter[str] = Counter()
    observed_set_hashes: Counter[str] = Counter()
    mismatch_iterations: list[int] = []
    missing_counter: Counter[str] = Counter()
    unexpected_counter: Counter[str] = Counter()
    hidden_visible_iterations = 0
    first_observed_order: list[str] | None = None
    spawned_pids: list[int] = []

    started_wall = datetime.now(timezone.utc).isoformat()
    started_mono = time.monotonic_ns()
    initial_cpu_frequency_khz = _cpu_frequency_snapshot()
    enabled_started_ns = 0
    enabled_ended_ns = 0
    process_cpu_started_ns = 0
    process_cpu_ended_ns = 0

    temp_context = tempfile.TemporaryDirectory(prefix="kicba-d4-")
    temp_dir = Path(temp_context.name)
    created_paths: list[Path] = []
    try:
        for name in creation_order:
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
        process_cpu_started_ns = time.process_time_ns()
        _set_flag(enabled, 1)
        for iteration in range(args.iterations):
            with tempfile.TemporaryFile() as output_stream:
                process = _spawn_blocked_ls(str(temp_dir), output_stream)
                spawned_pids.append(process.pid)
                monitored[ct.c_uint(process.pid)] = ct.c_ubyte(1)
                try:
                    assert process.stdin is not None
                    process.stdin.write(b"\n")
                    process.stdin.close()
                    process.stdin = None
                    if poll_policy == "wait_drain":
                        try:
                            process.wait(timeout=args.iteration_timeout_seconds)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                            raise TimeoutError(
                                f"ls iteration {iteration} exceeded "
                                f"{args.iteration_timeout_seconds} seconds"
                            )
                        # At most 14 target events per listing in the D4
                        # factor grid.  Drain after the child exits; no
                        # userspace polling contends with the measured call.
                        for _drain in range(4):
                            before = len(events)
                            bpf.perf_buffer_poll(timeout=0)
                            if len(events) == before:
                                break
                    else:
                        deadline = time.monotonic() + args.iteration_timeout_seconds
                        while process.poll() is None:
                            if time.monotonic() >= deadline:
                                process.kill()
                                process.wait()
                                raise TimeoutError(
                                    f"ls iteration {iteration} exceeded "
                                    f"{args.iteration_timeout_seconds} seconds"
                                )
                            bpf.perf_buffer_poll(timeout=10)
                        for _drain in range(3):
                            bpf.perf_buffer_poll(timeout=1)
                    _stdout, stderr = process.communicate()
                    if process.returncode:
                        raise RuntimeError(stderr.decode("utf-8", "replace"))
                    output_stream.seek(0)
                    observed = output_stream.read().decode(
                        "utf-8", "replace"
                    ).splitlines()
                finally:
                    del monitored[ct.c_uint(process.pid)]
            if first_observed_order is None:
                first_observed_order = observed
            observed_set = set(observed)
            missing = expected_set - observed_set
            unexpected = observed_set - expected_set
            if missing or unexpected or len(observed) != len(expected):
                mismatch_iterations.append(iteration)
                missing_counter.update(missing)
                unexpected_counter.update(unexpected)
            if hidden_name in observed_set:
                hidden_visible_iterations += 1
            observed_order_hashes.update([_sha256_lines(observed, sorted_lines=False)])
            observed_set_hashes.update([_sha256_lines(observed, sorted_lines=True)])
    finally:
        _set_flag(enabled, 0)
        process_cpu_ended_ns = time.process_time_ns()
        enabled_ended_ns = time.monotonic_ns()
        if stress is not None:
            stress.terminate()
            try:
                stress.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stress.kill()
                stress.wait()
        # Remove known paths explicitly because an active Rootkit changes
        # enumeration and TemporaryDirectory cannot discover hidden names.
        for path in reversed(created_paths):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        temp_context.cleanup()
        bpf.cleanup()

    ended_mono = time.monotonic_ns()
    ended_wall = datetime.now(timezone.utc).isoformat()
    events.sort(key=lambda event: event["ts"])
    kind_counts = {
        name: sum(event["kind"] == name for event in events)
        for name in EVENT_NAMES.values()
    }
    target_function_counts = {
        function: {
            "enter": sum(
                event["kind"] == "target_enter"
                and event["function"] == function
                for event in events
            ),
            "return": sum(
                event["kind"] == "target_return"
                and event["function"] == function
                for event in events
            ),
        }
        for function in attached_functions
    }
    complete = all(
        counts["enter"] > 0 and counts["enter"] == counts["return"]
        for counts in target_function_counts.values()
    )
    iterate_event_pids = {
        event["pid"]
        for event in events
        if event["kind"] == "target_enter"
        and event["function"] == "iterate_dir"
    }
    all_listings_observed = iterate_event_pids == set(spawned_pids)
    exact_output = not mismatch_iterations
    valid_for_analysis = (
        complete and lost_events == 0 and exact_output and all_listings_observed
    )

    first_observed_order = first_observed_order or []
    listing_validation = {
        "exact_output_pass": exact_output,
        "expected_entry_count": len(expected),
        "expected_set_sha256": _sha256_lines(expected, sorted_lines=True),
        "observed_set_hash_counts": dict(observed_set_hashes),
        "observed_order_hash_counts": dict(observed_order_hashes),
        "mismatch_iterations": mismatch_iterations,
        "missing_visible_counts": dict(missing_counter),
        "unexpected_counts": dict(unexpected_counter),
        "hidden_visible_iterations": hidden_visible_iterations,
        "first_observed_entry_count": len(first_observed_order),
        "first_observed_hidden_index": (
            first_observed_order.index(hidden_name)
            if hidden_name in first_observed_order
            else None
        ),
        "first_observed_order": first_observed_order,
        "first_observed_prefix": first_observed_order[:8],
        "first_observed_suffix": first_observed_order[-8:],
    }

    batch_id = (
        f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}_"
        f"{uuid.uuid4().hex[:8]}"
    )
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"batch_{batch_id}.json.gz"
    record = {
        "schema_version": 3,
        "protocol_revision": PROTOCOL_REVISION,
        "batch_id": batch_id,
        "truth": {"label": args.label, "condition": args.condition},
        "directory_factor": {
            "visible_cardinality": args.directory_cardinality,
            "filename_length": args.filename_length,
            "hidden_slot": args.hidden_slot,
            "hidden_creation_index": hidden_creation_index,
            "creation_order_sha256": _sha256_lines(
                creation_order, sorted_lines=False
            ),
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
            "collector_process_cpu_ns": (
                process_cpu_ended_ns - process_cpu_started_ns
            ),
            "iterations": args.iterations,
            "condition_command": condition_command,
            "probe_profile": args.probe_profile,
            "poll_policy": poll_policy,
            "bpf_source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
            "context_tracepoints_enabled": not minimal_trace,
            "attached_functions": attached_functions,
            "primary_timing_functions": attached_functions,
            "lost_events": lost_events,
            "campaign_id": args.campaign_id,
            "campaign_position": args.campaign_position,
            "campaign_phase": args.campaign_phase,
            "campaign_seed": args.campaign_seed,
            "initial_cpu_frequency_khz": initial_cpu_frequency_khz,
            "final_cpu_frequency_khz": _cpu_frequency_snapshot(),
        },
        "listing_validation": listing_validation,
        "quality": {
            "valid_for_analysis": valid_for_analysis,
            "event_counts": kind_counts,
            "target_function_counts": target_function_counts,
            "all_listings_observed": all_listings_observed,
            "exact_output_pass": exact_output,
            "reason": (
                None
                if valid_for_analysis
                else "target intervals incomplete, a listing has no target event, events lost, or exact output failed"
            ),
        },
        "events": events,
    }
    with gzip.open(output_path, "wt", encoding="utf-8") as handle:
        json.dump(record, handle, separators=(",", ":"))
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--iterations", default=100, type=int)
    parser.add_argument(
        "--condition", choices=["baseline", "cpu", "memory", "mixed"],
        default="baseline",
    )
    parser.add_argument("--label", choices=["normal", "rootkit"], required=True)
    parser.add_argument("--cpu-workers", default=min(4, os.cpu_count() or 1), type=int)
    parser.add_argument("--memory", default="256M")
    parser.add_argument("--warmup-seconds", default=1.0, type=float)
    parser.add_argument("--iteration-timeout-seconds", default=60.0, type=float)
    parser.add_argument("--probe-profile", choices=PROFILE_FUNCTIONS, default="security")
    parser.add_argument(
        "--poll-policy", choices=("continuous", "wait_drain"),
        default="continuous",
    )
    parser.add_argument("--directory-cardinality", default=16, type=int)
    parser.add_argument("--filename-length", default=32, type=int)
    parser.add_argument("--hidden-slot", choices=["early", "middle", "late"], default="middle")
    parser.add_argument("--campaign-id")
    parser.add_argument("--campaign-position", type=int)
    parser.add_argument("--campaign-phase")
    parser.add_argument("--campaign-seed", type=int)
    args = parser.parse_args()
    if args.iterations < 1 or args.directory_cardinality < 1:
        parser.error("iterations and directory cardinality must be positive")
    if not 24 <= args.filename_length <= 200:
        parser.error("filename length must be in [24, 200]")
    output = collect(args)
    print(output)


if __name__ == "__main__":
    main()
