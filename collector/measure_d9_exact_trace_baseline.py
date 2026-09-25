#!/usr/bin/env python3
"""Paired resource baseline for D9 versus accepted per-entry exact tracing."""

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
    _delete_if_present,
    _set_array,
    collect_once,
)


PROTOCOL = "D9-exact-trace-resource-baseline-r1-2026-09-24"
MODES = ("raw_count", "full_d9", "exact_accepted_map_trace")
BUFFER_SIZE = 65536
CELL_COUNT = 256


def _usage_seconds() -> float:
    own = resource.getrusage(resource.RUSAGE_SELF)
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + child.ru_utime + child.ru_stime


def _spawn_raw(probe: Path, fixture: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [str(probe), str(fixture)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def _run_raw(probe: Path, fixture: Path, expected: int) -> None:
    process = _spawn_raw(probe, fixture)
    stdout, stderr = process.communicate("\n", timeout=60)
    if process.returncode or int(stdout.strip()) != expected:
        raise RuntimeError(stderr.strip() or "raw count mismatch")


def _attach_d9(bpf: BPF) -> None:
    bpf.attach_kprobe(event="filldir64", fn_name="d9_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="d9_filldir64_return", maxactive=256
    )


def _detach_d9(bpf: BPF) -> None:
    bpf.detach_kprobe(event="filldir64")
    bpf.detach_kretprobe(event="filldir64")


def _attach_exact(bpf: BPF) -> None:
    bpf.attach_kprobe(event="filldir64", fn_name="exact_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="exact_filldir64_return", maxactive=256
    )


def _detach_exact(bpf: BPF) -> None:
    bpf.detach_kprobe(event="filldir64")
    bpf.detach_kretprobe(event="filldir64")


def _exact_scan(
    bpf: BPF, raw_probe: Path, fixture: Path, expected: int
) -> dict:
    process = _spawn_raw(raw_probe, fixture)
    pid_key = ct.c_uint(process.pid)
    bpf["monitored_pids"][pid_key] = ct.c_ubyte(1)
    try:
        stdout, stderr = process.communicate("\n", timeout=60)
        if process.returncode or int(stdout.strip()) != expected:
            raise RuntimeError(stderr.strip() or "exact trace raw count mismatch")
        stats = bpf["stats_by_pid"][pid_key]
        sequence = bpf["sequence_by_pid"][pid_key]
        accepted = int(sequence.value)
        event_count = sum(
            1 for key, _ in bpf["events_by_pid"].items()
            if int(key.pid) == process.pid
        )
        values = {
            name: int(getattr(stats, name))
            for name in (
                "accepted", "rejected", "read_errors",
                "map_failures", "return_underflows",
            )
        }
        if (
            accepted != expected or event_count != expected
            or values["accepted"] != expected
            or values["read_errors"] or values["map_failures"]
            or values["return_underflows"]
        ):
            raise RuntimeError(
                f"invalid exact trace: accepted={accepted}, "
                f"events={event_count}, stats={values}"
            )
        return {
            "accepted_events": accepted,
            "rejected_callbacks": values["rejected"],
            # exact_key is 8 bytes; exact_event is 272 bytes.
            "logical_trace_payload_bytes": event_count * 280,
        }
    finally:
        _delete_if_present(bpf["monitored_pids"], pid_key)
        for name in ("pending_by_pid", "sequence_by_pid", "stats_by_pid"):
            _delete_if_present(bpf[name], pid_key)
        for key, _ in list(bpf["events_by_pid"].items()):
            if int(key.pid) == process.pid:
                _delete_if_present(bpf["events_by_pid"], key)


def _run_mode(
    *, mode: str, iterations: int, raw_probe: Path, d9_probe: Path,
    fixture: Path, expected: int, d9_bpf: BPF, exact_bpf: BPF,
) -> dict:
    attached = None
    detail = []
    try:
        if mode == "full_d9":
            _attach_d9(d9_bpf)
            attached = "d9"
            _set_array(d9_bpf["collection_enabled"], 0, ct.c_ubyte(1))
        elif mode == "exact_accepted_map_trace":
            _attach_exact(exact_bpf)
            attached = "exact"
            _set_array(exact_bpf["collection_enabled"], 0, ct.c_ubyte(1))
        cpu_start = _usage_seconds()
        wall_start = time.monotonic_ns()
        for _ in range(iterations):
            if mode == "raw_count":
                _run_raw(raw_probe, fixture, expected)
            elif mode == "full_d9":
                result = collect_once(
                    d9_bpf, d9_probe, fixture, BUFFER_SIZE, CELL_COUNT,
                    DEFAULT_SEED1, DEFAULT_SEED2,
                )
                if not (
                    result["measurement_valid"] and result["fingerprint_equal"]
                    and result["decode_success"]
                ):
                    raise RuntimeError("D9 validation failed")
                detail.append({
                    "logical_payload_bytes": 24 + CELL_COUNT * 48,
                    "accepted_events": result["kernel_fingerprint"][0],
                    "rejected_callbacks": result["kernel_stats"]["rejected_entries"],
                })
            else:
                detail.append(_exact_scan(
                    exact_bpf, raw_probe, fixture, expected
                ))
        return {
            "wall_ns": time.monotonic_ns() - wall_start,
            "cpu_seconds": _usage_seconds() - cpu_start,
            "iterations": iterations,
            "detail": detail,
        }
    finally:
        if attached == "d9":
            _set_array(d9_bpf["collection_enabled"], 0, ct.c_ubyte(0))
            _detach_d9(d9_bpf)
        elif attached == "exact":
            _set_array(exact_bpf["collection_enabled"], 0, ct.c_ubyte(0))
            _detach_exact(exact_bpf)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--raw-probe", required=True, type=Path)
    parser.add_argument("--d9-probe", required=True, type=Path)
    parser.add_argument("--iterations", default=3, type=int)
    parser.add_argument("--repeats", default=3, type=int)
    parser.add_argument("--seed", default=12012, type=int)
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

    cardinalities = (512, 8192) if args.quick else (512, 8192, 65536)
    conditions = ("baseline", "mixed") if args.quick else ("baseline", "mixed")
    args.output.mkdir(parents=True)
    temporary = Path(tempfile.mkdtemp(prefix="d9_exact_baseline_", dir="/home/kicba"))
    fixtures = {}
    for cardinality in cardinalities:
        fixture = temporary / f"n_{cardinality}"
        fixture.mkdir()
        for index in range(cardinality):
            (fixture / f"visible_{index:08d}").touch()
        fixtures[cardinality] = fixture

    d9_source = Path(__file__).with_name("bpf_d9_reconciliation.c")
    exact_source = Path(__file__).with_name("bpf_d9_exact_map_trace.c")
    d9_bpf = BPF(src_file=str(d9_source), cflags=[f"-I{d9_source.parent.resolve()}"])
    exact_bpf = BPF(src_file=str(exact_source))
    _set_array(d9_bpf["hash_seeds"], 0, ct.c_ulonglong(DEFAULT_SEED1))
    _set_array(d9_bpf["hash_seeds"], 1, ct.c_ulonglong(DEFAULT_SEED2))
    _set_array(d9_bpf["iblt_cell_count"], 0, ct.c_uint(CELL_COUNT))
    _set_array(d9_bpf["collection_enabled"], 0, ct.c_ubyte(0))
    _set_array(exact_bpf["collection_enabled"], 0, ct.c_ubyte(0))
    rng = random.Random(args.seed)
    rows = []
    try:
        for cardinality in cardinalities:
            expected = cardinality + 2
            for condition in conditions:
                for repeat in range(args.repeats):
                    order = list(MODES)
                    rng.shuffle(order)
                    command = _stress_command(condition, 2, "128M")
                    stress = None
                    try:
                        if command:
                            stress = subprocess.Popen(
                                command, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                            )
                            time.sleep(0.5)
                        for mode in order:
                            rows.append({
                                "cardinality": cardinality,
                                "condition": condition,
                                "repeat": repeat,
                                "order": order,
                                "mode": mode,
                                **_run_mode(
                                    mode=mode, iterations=args.iterations,
                                    raw_probe=args.raw_probe.resolve(),
                                    d9_probe=args.d9_probe.resolve(),
                                    fixture=fixtures[cardinality], expected=expected,
                                    d9_bpf=d9_bpf, exact_bpf=exact_bpf,
                                ),
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
        d9_bpf.cleanup()
        exact_bpf.cleanup()
        shutil.rmtree(temporary, ignore_errors=True)

    report = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "evidence_role": "single_boot_development_resource_baseline_not_confirmatory",
        "baseline_scope": (
            "Efficient accepted-entry map trace implemented for resource "
            "comparison; not a line-for-line reproduction of Synacktiv and "
            "not a complete malicious-rootkit classifier."
        ),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "kernel": platform.release(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        },
        "parameters": {
            "quick": args.quick, "iterations": args.iterations,
            "repeats": args.repeats, "seed": args.seed,
            "cardinalities": list(cardinalities),
            "conditions": list(conditions),
        },
        "source_hashes": {
            "runner": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "d9_bpf": hashlib.sha256(d9_source.read_bytes()).hexdigest(),
            "exact_bpf": hashlib.sha256(exact_source.read_bytes()).hexdigest(),
        },
        "rows": rows,
    }
    output = args.output / "exact_trace_baseline.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "rows": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
