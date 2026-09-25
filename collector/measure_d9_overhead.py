#!/usr/bin/env python3
"""Paired end-to-end overhead development benchmark for D9."""

from __future__ import annotations

import argparse
import ctypes as ct
import hashlib
import json
import os
import platform
import random
import resource
import shutil
import statistics
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from collect_batch import _stress_command
from run_campaign import ACK
from run_d9_reconciliation_smoke import (
    DEFAULT_SEED1,
    DEFAULT_SEED2,
    _set_array,
    collect_once,
)


PROTOCOL = "D9-reconciliation-overhead-development-r1-2026-09-24"
MODES = ("raw_count", "userspace_sketch", "full_d9")
CONDITIONS = ("baseline", "cpu", "memory", "mixed")
CARDINALITIES = (512, 8192, 65536)
BUFFER_SIZE = 65536
CELL_COUNT = 256


def _rusage_seconds() -> float:
    self_usage = resource.getrusage(resource.RUSAGE_SELF)
    child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return (
        self_usage.ru_utime + self_usage.ru_stime
        + child_usage.ru_utime + child_usage.ru_stime
    )


def _spawn_d9(probe: Path, fixture: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [
            str(probe), str(fixture), str(BUFFER_SIZE), str(CELL_COUNT),
            str(DEFAULT_SEED1), str(DEFAULT_SEED2),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _run_raw_once(probe: Path, fixture: Path, expected_count: int) -> int:
    process = subprocess.Popen(
        [str(probe), str(fixture)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = process.communicate("\n", timeout=60)
    if process.returncode:
        raise RuntimeError(stderr.strip())
    if int(stdout.strip()) != expected_count:
        raise RuntimeError("raw probe count mismatch")
    return len(stdout.encode())


def _run_sketch_once(probe: Path, fixture: Path, expected_count: int) -> tuple[int, int]:
    process = _spawn_d9(probe, fixture)
    stdout, stderr = process.communicate("\n", timeout=60)
    if process.returncode:
        raise RuntimeError(stderr.strip())
    result = json.loads(stdout)
    if int(result["count"]) != expected_count:
        raise RuntimeError("sketch probe count mismatch")
    return len(stdout.encode()), int(result["scan_ns"])


def _attach(bpf: BPF) -> None:
    bpf.attach_kprobe(event="filldir64", fn_name="d9_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="d9_filldir64_return", maxactive=256
    )


def _detach(bpf: BPF) -> None:
    bpf.detach_kprobe(event="filldir64")
    bpf.detach_kretprobe(event="filldir64")


def _run_batch(
    *, mode: str, iterations: int, raw_probe: Path, d9_probe: Path,
    fixture: Path, expected_count: int, bpf: BPF,
) -> dict:
    attached = False
    output_bytes = 0
    scan_ns_values = []
    logical_map_payload_bytes = []
    try:
        if mode == "full_d9":
            _attach(bpf)
            attached = True
            _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(1))
        cpu_start = _rusage_seconds()
        wall_start = time.monotonic_ns()
        for _ in range(iterations):
            if mode == "raw_count":
                output_bytes += _run_raw_once(
                    raw_probe, fixture, expected_count
                )
            elif mode == "userspace_sketch":
                size, scan_ns = _run_sketch_once(
                    d9_probe, fixture, expected_count
                )
                output_bytes += size
                scan_ns_values.append(scan_ns)
            else:
                result = collect_once(
                    bpf, d9_probe, fixture, BUFFER_SIZE, CELL_COUNT,
                    DEFAULT_SEED1, DEFAULT_SEED2,
                )
                if not (
                    result["measurement_valid"]
                    and result["fingerprint_equal"]
                    and result["decode_success"]
                    and not result["upstream_only"]
                    and not result["downstream_only"]
                ):
                    raise RuntimeError("full D9 validation failed")
                output_bytes += result["userspace"]["stdout_bytes"]
                scan_ns_values.append(result["userspace"]["scan_ns"])
                # Configured logical upper bound only: fingerprint (24 bytes)
                # plus cell key/value payload (8 + 40 bytes).  This is not a
                # measurement of allocator overhead.
                logical_map_payload_bytes.append(24 + CELL_COUNT * 48)
        wall_ns = time.monotonic_ns() - wall_start
        cpu_seconds = _rusage_seconds() - cpu_start
        return {
            "wall_ns": wall_ns,
            "cpu_seconds": cpu_seconds,
            "iterations": iterations,
            "stdout_bytes": output_bytes,
            "median_probe_scan_ns": (
                statistics.median(scan_ns_values) if scan_ns_values else None
            ),
            "configured_logical_bpf_map_payload_upper_bound_bytes": (
                max(logical_map_payload_bytes)
                if logical_map_payload_bytes else 0
            ),
        }
    finally:
        if mode == "full_d9":
            _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(0))
        if attached:
            _detach(bpf)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--raw-probe", required=True, type=Path)
    parser.add_argument("--d9-probe", required=True, type=Path)
    parser.add_argument("--iterations", default=10, type=int)
    parser.add_argument("--repeats", default=3, type=int)
    parser.add_argument("--seed", default=12011, type=int)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or "microsoft" in platform.release().lower():
        parser.error("requires root in the native isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if subprocess.run(
        ["ip", "route", "show", "default"], check=True,
        capture_output=True, text=True,
    ).stdout.strip():
        raise RuntimeError("default route present")
    if args.output.exists():
        raise FileExistsError(args.output)
    for path in (args.raw_probe, args.d9_probe):
        if not path.is_file():
            raise FileNotFoundError(path)
    if shutil.which("stress-ng") is None:
        raise RuntimeError("stress-ng is required")

    cardinalities = (512, 8192) if args.quick else CARDINALITIES
    conditions = ("baseline", "mixed") if args.quick else CONDITIONS
    args.output.mkdir(parents=True)
    temporary = Path(tempfile.mkdtemp(prefix="d9_overhead_", dir="/home/kicba"))
    fixtures = {}
    for cardinality in cardinalities:
        fixture = temporary / f"n_{cardinality}"
        fixture.mkdir()
        for index in range(cardinality):
            (fixture / f"visible_{index:08d}").touch()
        fixtures[cardinality] = fixture

    source = Path(__file__).with_name("bpf_d9_reconciliation.c")
    bpf = BPF(src_file=str(source), cflags=[f"-I{source.parent.resolve()}"])
    _set_array(bpf["hash_seeds"], 0, ct.c_ulonglong(DEFAULT_SEED1))
    _set_array(bpf["hash_seeds"], 1, ct.c_ulonglong(DEFAULT_SEED2))
    _set_array(bpf["iblt_cell_count"], 0, ct.c_uint(CELL_COUNT))
    _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(0))
    rng = random.Random(args.seed)
    rows = []
    try:
        for cardinality in cardinalities:
            fixture = fixtures[cardinality]
            expected_count = cardinality + 2
            for condition in conditions:
                for repeat in range(args.repeats):
                    order = list(MODES)
                    rng.shuffle(order)
                    stress = None
                    command = _stress_command(condition, 2, "128M")
                    try:
                        if command:
                            stress = subprocess.Popen(
                                command, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                            )
                            time.sleep(0.5)
                        for mode in order:
                            measurement = _run_batch(
                                mode=mode, iterations=args.iterations,
                                raw_probe=args.raw_probe.resolve(),
                                d9_probe=args.d9_probe.resolve(),
                                fixture=fixture, expected_count=expected_count,
                                bpf=bpf,
                            )
                            rows.append({
                                "cardinality": cardinality,
                                "condition": condition,
                                "repeat": repeat,
                                "order": order,
                                "mode": mode,
                                **measurement,
                            })
                    finally:
                        if stress is not None:
                            stress.terminate()
                            try:
                                stress.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                stress.kill()
                                stress.wait(timeout=5)
    finally:
        _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(0))
        bpf.cleanup()
        shutil.rmtree(temporary, ignore_errors=True)

    report = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "evidence_role": "single_boot_development_overhead_not_confirmatory",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "kernel": platform.release(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        },
        "parameters": {
            "quick": args.quick,
            "iterations_per_batch": args.iterations,
            "repeats": args.repeats,
            "seed": args.seed,
            "buffer_size": BUFFER_SIZE,
            "cells": CELL_COUNT,
            "cardinalities": list(cardinalities),
            "conditions": list(conditions),
        },
        "source_hashes": {
            "runner": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "bpf": hashlib.sha256(source.read_bytes()).hexdigest(),
            "raw_probe": hashlib.sha256(
                args.raw_probe.read_bytes()
            ).hexdigest(),
            "d9_probe": hashlib.sha256(args.d9_probe.read_bytes()).hexdigest(),
        },
        "rows": rows,
    }
    output = args.output / "overhead.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "rows": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
