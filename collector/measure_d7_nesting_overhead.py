#!/usr/bin/env python3
"""Paired overhead pilot for the D7 kernel-only nesting detector.

The deployment model is an explicitly periodic diagnostic scan: twenty
controlled listings once per minute.  We report relative latency but judge the
pre-specified deployment budget by absolute scan time and amortized wall-time
duty, because the detector is not proposed as an always-on interceptor.
"""

from __future__ import annotations

import argparse
import ctypes as ct
import hashlib
import json
import os
import platform
import random
import statistics
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from collect_batch import _set_flag, _stress_command
from collect_d4_batch import _directory_names, _spawn_blocked_ls


PROTOCOL = "D7-nesting-overhead-development-r1-2026-09-21"
CONDITIONS = ("baseline", "cpu", "memory", "mixed")
CARDINALITY = 128
FILENAME_LENGTH = 32
SCAN_PERIOD_SECONDS = 60.0
MAX_SCAN_WALL_SECONDS = 1.0
MAX_AMORTIZED_ADDED_WALL_FRACTION = 0.001
MAPS = (
    "depth_by_pid", "top_has_child", "top_level_calls",
    "forwarded_top_calls", "short_circuit_top_calls",
    "max_depth_by_pid", "return_underflows",
)


def _module_loaded(name: str) -> bool:
    return any(
        line.split()[0] == name
        for line in Path("/proc/modules").read_text(encoding="utf-8").splitlines()
        if line
    )


def _delete(table, key: ct.c_uint) -> None:
    try:
        del table[key]
    except KeyError:
        pass


def _value(table, key: ct.c_uint) -> int:
    try:
        return int(table[key].value)
    except KeyError:
        return 0


def _run_listings(
    *, fixture: Path, expected: set[str], condition: str, iterations: int,
    instrumented: bool, source: Path,
) -> tuple[int, int, list[dict]]:
    bpf = None
    enabled = monitored = None
    maps = {}
    if instrumented:
        bpf = BPF(src_file=str(source))
        bpf.attach_kprobe(event="filldir64", fn_name="trace_filldir64_enter")
        bpf.attach_kretprobe(
            event="filldir64", fn_name="trace_filldir64_return", maxactive=256
        )
        enabled = bpf["collection_enabled"]
        monitored = bpf["monitored_pids"]
        maps = {name: bpf[name] for name in MAPS}
    stress = None
    records = []
    command = _stress_command(condition, 4, "256M")
    try:
        if command:
            stress = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(1.0)
        if instrumented:
            _set_flag(enabled, 1)
        cpu_start = time.process_time_ns()
        wall_start = time.monotonic_ns()
        for iteration in range(iterations):
            with tempfile.TemporaryFile() as output_stream:
                process = _spawn_blocked_ls(str(fixture), output_stream)
                key = ct.c_uint(process.pid)
                if instrumented:
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
                    if set(observed) != expected or len(observed) != len(expected):
                        raise RuntimeError("listing differs from fixture")
                    if instrumented:
                        row = {
                            "iteration": iteration,
                            "top": _value(maps["top_level_calls"], key),
                            "forwarded": _value(
                                maps["forwarded_top_calls"], key
                            ),
                            "shorted": _value(
                                maps["short_circuit_top_calls"], key
                            ),
                            "max_depth": _value(maps["max_depth_by_pid"], key),
                            "underflows": _value(
                                maps["return_underflows"], key
                            ),
                        }
                        if (
                            row["top"] != CARDINALITY + 3
                            or row["forwarded"] != 0
                            or row["shorted"] != CARDINALITY + 3
                            or row["max_depth"] != 1
                            or row["underflows"] != 0
                        ):
                            raise RuntimeError(f"unexpected unloaded shape: {row}")
                        records.append(row)
                finally:
                    if instrumented:
                        _delete(monitored, key)
                        for table in maps.values():
                            _delete(table, key)
        wall = time.monotonic_ns() - wall_start
        cpu = time.process_time_ns() - cpu_start
    finally:
        if instrumented:
            _set_flag(enabled, 0)
        if stress is not None:
            stress.terminate()
            try:
                stress.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stress.kill()
                stress.wait()
        if bpf is not None:
            bpf.cleanup()
    return wall, cpu, records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--iterations", default=20, type=int)
    parser.add_argument("--repeats", default=5, type=int)
    parser.add_argument("--seed", default=10708, type=int)
    args = parser.parse_args()
    if os.geteuid() != 0 or "microsoft" in platform.release().lower():
        parser.error("requires root in the native VM")
    if subprocess.run(
        ["ip", "route", "show", "default"], check=True,
        capture_output=True, text=True,
    ).stdout.strip():
        raise RuntimeError("default route present")
    known = {
        "caraxes", "caraxes_sham", "kicba_d7_pass", "kicba_d7_active",
        "kicba_d7_hiding",
    }
    if any(_module_loaded(name) for name in known):
        raise RuntimeError("D7/CARAXES module loaded")
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.mkdir(parents=True)
    source = Path(__file__).with_name("bpf_d7_nesting.c")
    visible, hidden, creation, _slot = _directory_names(
        CARDINALITY, FILENAME_LENGTH, "middle"
    )
    expected = {".", "..", *visible, hidden}
    rng = random.Random(args.seed)
    report = {
        "protocol": PROTOCOL,
        "status": "running",
        "evidence_role": "single_boot_development_overhead_pilot",
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "iterations_per_scan": args.iterations,
        "repeats": args.repeats,
        "seed": args.seed,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "bpf_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "deployment_model": {
            "scan_period_seconds": SCAN_PERIOD_SECONDS,
            "max_scan_wall_seconds": MAX_SCAN_WALL_SECONDS,
            "max_amortized_added_wall_fraction": (
                MAX_AMORTIZED_ADDED_WALL_FRACTION
            ),
            "note": (
                "Relative target-operation latency is reported but is not the "
                "success rule for this explicitly periodic detector."
            ),
        },
        "pairs": [],
    }
    report_path = args.output / "overhead_report.json"
    with tempfile.TemporaryDirectory(prefix="kicba-d7-nesting-overhead-") as tmp:
        fixture = Path(tmp)
        for name in creation:
            (fixture / name).touch()
        try:
            for condition in CONDITIONS:
                for repeat in range(args.repeats):
                    order = ["control", "instrumented"]
                    rng.shuffle(order)
                    pair = {
                        "condition": condition,
                        "repeat": repeat,
                        "order": order,
                    }
                    for mode in order:
                        wall, cpu, records = _run_listings(
                            fixture=fixture, expected=expected,
                            condition=condition, iterations=args.iterations,
                            instrumented=mode == "instrumented", source=source,
                        )
                        pair[f"{mode}_wall_ns"] = wall
                        pair[f"{mode}_collector_cpu_ns"] = cpu
                        if mode == "instrumented":
                            pair["instrumented_transactions"] = len(records)
                    added = pair["instrumented_wall_ns"] - pair["control_wall_ns"]
                    pair["added_wall_ns"] = added
                    pair["relative_wall_overhead"] = (
                        added / pair["control_wall_ns"]
                    )
                    pair["amortized_added_wall_fraction"] = max(0, added) / (
                        SCAN_PERIOD_SECONDS * 1e9
                    )
                    report["pairs"].append(pair)
                    report_path.write_text(
                        json.dumps(report, indent=2), encoding="utf-8"
                    )
        except BaseException as exc:
            report.update({
                "status": "failed",
                "failure": f"{type(exc).__name__}: {exc}",
            })
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            raise
    summary = []
    for condition in CONDITIONS:
        rows = [row for row in report["pairs"] if row["condition"] == condition]
        summary.append({
            "condition": condition,
            "pairs": len(rows),
            "mean_relative_wall_overhead": statistics.fmean(
                row["relative_wall_overhead"] for row in rows
            ),
            "median_relative_wall_overhead": statistics.median(
                row["relative_wall_overhead"] for row in rows
            ),
            "mean_added_wall_ms_per_scan": statistics.fmean(
                row["added_wall_ns"] for row in rows
            ) / 1e6,
            "max_instrumented_scan_wall_ms": max(
                row["instrumented_wall_ns"] for row in rows
            ) / 1e6,
            "mean_amortized_added_wall_fraction": statistics.fmean(
                row["amortized_added_wall_fraction"] for row in rows
            ),
        })
    report["summary"] = summary
    report["deployment_rule"] = {
        "rule": (
            "for every workload: max 20-listing scan wall <= 1 s and mean "
            "positive added wall / 60 s <= 0.1%"
        ),
        "pass": all(
            row["max_instrumented_scan_wall_ms"] <= MAX_SCAN_WALL_SECONDS * 1e3
            and row["mean_amortized_added_wall_fraction"]
            <= MAX_AMORTIZED_ADDED_WALL_FRACTION
            for row in summary
        ),
    }
    report["status"] = "complete"
    report["completed_utc"] = datetime.now(timezone.utc).isoformat()
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(report_path)


if __name__ == "__main__":
    main()
