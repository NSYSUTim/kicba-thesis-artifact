#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes as ct
import gzip
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF


EVENT_NAMES = {
    1: "target_enter",
    2: "target_return",
    3: "sched_switch",
    4: "hardirq_enter",
    5: "hardirq_exit",
    6: "softirq_enter",
    7: "softirq_exit",
    8: "cpu_frequency",
}
FUNCTIONS = {
    1: "iterate_dir",
    2: "filldir64",
    3: "verify_dirent_name",
    4: "touch_atime",
}
PRIMARY_TIMING_FUNCTIONS = (
    "iterate_dir",
    "filldir64",
    "touch_atime",
)


class Event(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("aux", ct.c_ulonglong),
        ("kind", ct.c_uint),
        ("function_id", ct.c_uint),
        ("pid", ct.c_uint),
        ("tgid", ct.c_uint),
        ("other_pid", ct.c_int),
        ("cpu", ct.c_uint),
        ("comm", ct.c_char * 16),
    ]


def _module_loaded(name: str) -> bool:
    result = subprocess.run(["lsmod"], check=True, capture_output=True, text=True)
    return any(line.split()[0] == name for line in result.stdout.splitlines()[1:] if line)


def _stress_command(condition: str, workers: int, memory: str) -> list[str] | None:
    cpu = ["stress-ng", "--cpu", str(workers), "--cpu-method", "all"]
    mem = ["stress-ng", "--vm", "1", "--vm-bytes", memory, "--vm-keep"]
    if condition == "baseline":
        return None
    if condition == "cpu":
        return cpu
    if condition == "memory":
        return mem
    if condition == "mixed":
        return cpu + mem[1:]
    raise ValueError(condition)


def _set_flag(table, value: int) -> None:
    table[ct.c_uint(0)] = ct.c_ubyte(value)


def _cpu_frequency_snapshot() -> dict[str, int | None]:
    """Read best-effort per-CPU frequency without turning absence into data."""

    snapshot: dict[str, int | None] = {}
    cpu_root = Path("/sys/devices/system/cpu")
    for cpu_dir in sorted(cpu_root.glob("cpu[0-9]*")):
        frequency_path = cpu_dir / "cpufreq" / "scaling_cur_freq"
        try:
            snapshot[cpu_dir.name] = int(frequency_path.read_text().strip())
        except (FileNotFoundError, OSError, ValueError):
            snapshot[cpu_dir.name] = None
    return snapshot


def _read_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "unknown"


def _spawn_blocked_ls(directory: str) -> subprocess.Popen:
    command = 'read -r _; exec ls -a1 -- "$1"'
    return subprocess.Popen(
        ["bash", "-c", command, "bash", directory],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _attach_targets(bpf: BPF) -> list[str]:
    attached: list[str] = []
    missing: list[str] = []
    for function_id, function_name in FUNCTIONS.items():
        if not BPF.get_kprobe_functions(function_name.encode()):
            missing.append(function_name)
            continue
        bpf.attach_kprobe(
            event=function_name, fn_name=f"trace_{function_name}_enter"
        )
        bpf.attach_kretprobe(
            event=function_name, fn_name=f"trace_{function_name}_return"
        )
        attached.append(function_name)
    if missing:
        raise RuntimeError(
            "The instrument requires all four probeable functions; missing: "
            + ", ".join(missing)
        )
    return attached


def collect(args: argparse.Namespace) -> Path:
    if os.geteuid() != 0:
        raise PermissionError("Run the collector as root")
    if args.label == "rootkit" and not _module_loaded("caraxes"):
        raise RuntimeError("Refusing rootkit label because module 'caraxes' is not loaded")

    source_path = Path(__file__).with_name("bpf_context.c")
    bpf = BPF(src_file=str(source_path))
    attached_functions = _attach_targets(bpf)
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
                "comm": bytes(raw.comm).split(b"\0", 1)[0].decode("utf-8", "replace"),
            }
        )

    def on_lost(_cpu, count):
        nonlocal lost_events
        lost_events += int(count)

    bpf["events"].open_perf_buffer(on_event, page_cnt=256, lost_cb=on_lost)
    monitored = bpf["monitored_pids"]
    enabled = bpf["collection_enabled"]
    stress = None
    condition_command = _stress_command(args.condition, args.cpu_workers, args.memory)

    started_wall = datetime.now(timezone.utc).isoformat()
    started_mono = time.monotonic_ns()
    initial_cpu_frequency_khz = _cpu_frequency_snapshot()
    enabled_started_ns = None
    enabled_ended_ns = None
    enabled_process_cpu_started_ns = None
    enabled_process_cpu_ended_ns = None
    with tempfile.TemporaryDirectory(prefix="kicba-") as temp_dir:
        visible = Path(temp_dir, "visible_file")
        hidden = Path(temp_dir, "sample_caraxes_hidden")
        visible.touch()
        hidden.touch()
        if condition_command:
            stress = subprocess.Popen(
                condition_command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(args.warmup_seconds)
        enabled_started_ns = time.monotonic_ns()
        enabled_process_cpu_started_ns = time.process_time_ns()
        _set_flag(enabled, 1)
        try:
            for _ in range(args.iterations):
                process = _spawn_blocked_ls(temp_dir)
                monitored[ct.c_uint(process.pid)] = ct.c_ubyte(1)
                assert process.stdin is not None
                process.stdin.write(b"\n")
                process.stdin.close()
                process.stdin = None
                while process.poll() is None:
                    bpf.perf_buffer_poll(timeout=10)
                for _drain in range(3):
                    bpf.perf_buffer_poll(timeout=1)
                stdout, stderr = process.communicate()
                if process.returncode:
                    raise RuntimeError(stderr.decode("utf-8", "replace"))
                listing = stdout.decode("utf-8", "replace")
                hidden_visible = "sample_caraxes_hidden" in listing
                if args.label == "normal" and not hidden_visible:
                    raise RuntimeError("Normal run unexpectedly hid the CARAXES-named file")
                if args.label == "rootkit" and hidden_visible:
                    raise RuntimeError("Rootkit run did not hide the CARAXES-named file")
                del monitored[ct.c_uint(process.pid)]
        finally:
            _set_flag(enabled, 0)
            enabled_process_cpu_ended_ns = time.process_time_ns()
            enabled_ended_ns = time.monotonic_ns()
            if stress is not None:
                stress.terminate()
                try:
                    stress.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    stress.kill()
                    stress.wait()
            # CARAXES hides the sentinel from directory enumeration, which is
            # exactly the behavior under test.  TemporaryDirectory.cleanup()
            # also enumerates before unlinking, so it cannot discover that
            # file while the module is active and would fail with ENOTEMPTY.
            # Remove both known sentinels by exact pathname first; pathname
            # unlink is not dependent on the manipulated readdir results.
            for sentinel in (hidden, visible):
                try:
                    sentinel.unlink()
                except FileNotFoundError:
                    pass
    ended_mono = time.monotonic_ns()
    ended_wall = datetime.now(timezone.utc).isoformat()
    # BCC otherwise relies on Python object finalization.  The overhead tool
    # deliberately calls collect() many times in one process, so implicit
    # cleanup can retain kprobe/perf descriptors until the process hits its
    # file-descriptor limit.  Detach and close deterministically after every
    # completed collection window.
    bpf.cleanup()
    events.sort(key=lambda event: event["ts"])
    kind_counts = {
        name: sum(event["kind"] == name for event in events)
        for name in EVENT_NAMES.values()
    }
    target_function_counts = {
        function: {
            "enter": sum(
                event["kind"] == "target_enter" and event["function"] == function
                for event in events
            ),
            "return": sum(
                event["kind"] == "target_return" and event["function"] == function
                for event in events
            ),
        }
        for function in attached_functions
    }
    primary_complete = all(
        target_function_counts[function]["enter"] > 0
        and target_function_counts[function]["enter"]
        == target_function_counts[function]["return"]
        for function in PRIMARY_TIMING_FUNCTIONS
    )
    all_observed_pairs_complete = all(
        counts["enter"] == counts["return"]
        for counts in target_function_counts.values()
    )
    valid_for_analysis = (
        primary_complete and all_observed_pairs_complete and lost_events == 0
    )
    zero_hit_functions = [
        function
        for function, counts in target_function_counts.items()
        if counts["enter"] == 0 and counts["return"] == 0
    ]

    batch_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}_{uuid.uuid4().hex[:8]}"
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"batch_{batch_id}.json.gz"
    record = {
        "schema_version": 2,
        "batch_id": batch_id,
        "truth": {"label": args.label, "condition": args.condition},
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
                enabled_process_cpu_ended_ns - enabled_process_cpu_started_ns
            ),
            "iterations": args.iterations,
            "condition_command": condition_command,
            "attached_functions": attached_functions,
            "primary_timing_functions": list(PRIMARY_TIMING_FUNCTIONS),
            "lost_events": lost_events,
            "campaign_id": args.campaign_id,
            "campaign_position": args.campaign_position,
            "campaign_seed": args.campaign_seed,
            "initial_cpu_frequency_khz": initial_cpu_frequency_khz,
            "final_cpu_frequency_khz": _cpu_frequency_snapshot(),
        },
        "quality": {
            "valid_for_analysis": valid_for_analysis,
            "event_counts": kind_counts,
            "target_function_counts": target_function_counts,
            "primary_timing_functions": list(PRIMARY_TIMING_FUNCTIONS),
            "zero_hit_functions": zero_hit_functions,
            "reason": None
            if valid_for_analysis
            else "primary target intervals absent/incomplete, entry/return mismatch, or perf events lost",
        },
        "events": events,
    }
    with gzip.open(output_path, "wt", encoding="utf-8") as handle:
        json.dump(record, handle, separators=(",", ":"))
    if not valid_for_analysis:
        print(
            "WARNING: batch saved for diagnostics but is invalid for analysis: "
            + record["quality"]["reason"],
            file=sys.stderr,
        )
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/d2_raw", type=Path)
    parser.add_argument("--iterations", default=100, type=int)
    parser.add_argument(
        "--condition", choices=["baseline", "cpu", "memory", "mixed"], default="baseline"
    )
    parser.add_argument("--label", choices=["normal", "rootkit"], default="normal")
    parser.add_argument("--cpu-workers", default=min(4, os.cpu_count() or 1), type=int)
    parser.add_argument("--memory", default="256M")
    parser.add_argument("--warmup-seconds", default=1.0, type=float)
    parser.add_argument("--campaign-id")
    parser.add_argument("--campaign-position", type=int)
    parser.add_argument("--campaign-seed", type=int)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    output = collect(args)
    print(output)


if __name__ == "__main__":
    main()
