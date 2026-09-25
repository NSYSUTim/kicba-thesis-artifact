#!/usr/bin/env python3
"""Native-VM smoke test for transaction-aligned fingerprint/IBLT collection."""

from __future__ import annotations

import argparse
import ctypes as ct
import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from bcc import BPF

from kicba.reconciliation import IBLT
from run_campaign import ACK


DEFAULT_SEED1 = 0x0123456789ABCDEF
DEFAULT_SEED2 = 0xF0E1D2C3B4A59687


def _set_array(table, index: int, value) -> None:
    table[ct.c_int(index)] = value


def _lookup(table, key):
    try:
        return table[key]
    except KeyError:
        return None


def _scalar(value) -> int | None:
    if value is None:
        return None
    return int(getattr(value, "value", value))


def _rows_from_sparse(
    cell_count: int, sparse: list[list[int]]
) -> list[tuple[int, int, int, int, int]]:
    rows = [(0, 0, 0, 0, 0) for _ in range(cell_count)]
    for index, count, key_hash, inode, d_type, check in sparse:
        rows[index] = (count, key_hash, inode, d_type, check)
    return rows


def _kernel_rows(table, pid: int, cell_count: int):
    rows = [(0, 0, 0, 0, 0) for _ in range(cell_count)]
    keys = []
    for key, value in table.items():
        if int(key.pid) != pid:
            continue
        index = int(key.index)
        if index >= cell_count:
            raise RuntimeError(f"kernel cell index outside configured table: {index}")
        rows[index] = (
            int(value.count),
            int(value.key_xor),
            int(value.inode_xor),
            int(value.type_xor),
            int(value.check_xor),
        )
        keys.append(key)
    return rows, keys


def _delete_if_present(table, key) -> None:
    try:
        del table[key]
    except KeyError:
        pass


def result_for_pid(
    bpf: BPF,
    pid: int,
    visible: dict,
    cell_count: int,
    seed1: int,
    seed2: int,
) -> dict:
    """Read and validate one completed PID without changing its BPF maps."""

    pid_key = ct.c_uint(pid)
    configured_seed1 = _scalar(_lookup(bpf["hash_seeds"], ct.c_int(0)))
    configured_seed2 = _scalar(_lookup(bpf["hash_seeds"], ct.c_int(1)))
    configured_cells = _scalar(_lookup(bpf["iblt_cell_count"], ct.c_int(0)))
    collection_enabled = _scalar(
        _lookup(bpf["collection_enabled"], ct.c_int(0))
    )
    configuration_valid = (
        configured_seed1 == seed1
        and configured_seed2 == seed2
        and configured_cells == cell_count
        and collection_enabled == 1
    )
    fingerprint = _lookup(bpf["kernel_fingerprints"], pid_key)
    stats = _lookup(bpf["stats_by_pid"], pid_key)
    if fingerprint is None or stats is None:
        raise RuntimeError("missing kernel fingerprint or statistics")
    kernel_rows, _ = _kernel_rows(bpf["kernel_iblt"], pid, cell_count)
    visible_rows = _rows_from_sparse(cell_count, visible["cells"])
    difference = IBLT.from_rows(
        kernel_rows, seed1, seed2
    ).subtract(
        IBLT.from_rows(visible_rows, seed1, seed2)
    ).decode()
    kernel_fp = (
        int(fingerprint.count), int(fingerprint.sum1), int(fingerprint.sum2)
    )
    visible_fp = (
        int(visible["count"]), int(visible["sum1"]), int(visible["sum2"])
    )
    statistic_fields = (
        "outer_entries", "accepted_entries", "rejected_entries",
        "name_read_errors", "invalid_name_lengths",
        "pending_update_failures", "fingerprint_update_failures",
        "iblt_update_failures", "return_underflows",
    )
    statistic_values = {
        name: int(getattr(stats, name)) for name in statistic_fields
    }
    depth = _lookup(bpf["depth_by_pid"], pid_key)
    pending = _lookup(bpf["pending_by_pid"], pid_key)
    measurement_valid = (
        configuration_valid
        and depth is None
        and pending is None
        and statistic_values["name_read_errors"] == 0
        and statistic_values["invalid_name_lengths"] == 0
        and statistic_values["pending_update_failures"] == 0
        and statistic_values["fingerprint_update_failures"] == 0
        and statistic_values["iblt_update_failures"] == 0
        and statistic_values["return_underflows"] == 0
        and statistic_values["accepted_entries"] == kernel_fp[0]
    )
    return {
        "measurement_valid": measurement_valid,
        "configuration_valid": configuration_valid,
        "configuration": {
            "kernel_seed1": configured_seed1,
            "kernel_seed2": configured_seed2,
            "kernel_cells": configured_cells,
            "collection_enabled": collection_enabled,
            "expected_seed1": seed1,
            "expected_seed2": seed2,
            "expected_cells": cell_count,
        },
        "fingerprint_equal": kernel_fp == visible_fp,
        "kernel_fingerprint": kernel_fp,
        "visible_fingerprint": visible_fp,
        "decode_success": difference.success,
        "upstream_only": [
            [item.key_hash, item.inode, item.d_type]
            for item in difference.upstream_only
        ],
        "downstream_only": [
            [item.key_hash, item.inode, item.d_type]
            for item in difference.downstream_only
        ],
        "residual_cells": difference.residual_cells,
        "kernel_stats": statistic_values,
        "userspace": {
            **{
                key: visible[key]
                for key in ("count", "syscalls", "returned_bytes", "scan_ns")
            },
            "stdout_bytes": visible.get("_stdout_bytes"),
        },
    }


def cleanup_pid(bpf: BPF, pid: int) -> None:
    pid_key = ct.c_uint(pid)
    _delete_if_present(bpf["monitored_pids"], pid_key)
    for name in (
        "depth_by_pid", "pending_by_pid", "kernel_fingerprints",
        "stats_by_pid",
    ):
        _delete_if_present(bpf[name], pid_key)
    try:
        for key, _ in list(bpf["kernel_iblt"].items()):
            if int(key.pid) == pid:
                _delete_if_present(bpf["kernel_iblt"], key)
    except KeyError:
        pass


def collect_once(
    bpf: BPF,
    probe: Path,
    fixture: Path,
    buffer_size: int,
    cell_count: int,
    seed1: int,
    seed2: int,
) -> dict:
    monitored = bpf["monitored_pids"]
    process = subprocess.Popen(
        [
            str(probe), str(fixture), str(buffer_size), str(cell_count),
            str(seed1), str(seed2),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    pid_key = ct.c_uint(process.pid)
    monitored[pid_key] = ct.c_ubyte(1)
    try:
        stdout, stderr = process.communicate("\n", timeout=60)
        if process.returncode:
            raise RuntimeError(stderr.strip())
        visible = json.loads(stdout)
        visible["_stdout_bytes"] = len(stdout.encode())
        return result_for_pid(
            bpf, process.pid, visible, cell_count, seed1, seed2
        )
    finally:
        cleanup_pid(bpf, process.pid)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--buffer-size", default=256, type=int)
    parser.add_argument("--cells", default=64, type=int)
    parser.add_argument("--entries", default=512, type=int)
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
    if args.cells < 4 or args.cells & (args.cells - 1):
        parser.error("--cells must be a power of two >= 4")
    if not args.probe.is_file():
        raise FileNotFoundError(args.probe)

    temporary = Path(tempfile.mkdtemp(prefix="d9_reconciliation_smoke_"))
    fixture = temporary / "fixture"
    fixture.mkdir()
    try:
        for index in range(args.entries):
            (fixture / f"visible_{index:08d}").touch()
        source = Path(__file__).with_name("bpf_d9_reconciliation.c")
        bpf = BPF(
            src_file=str(source), cflags=[f"-I{source.parent.resolve()}"]
        )
        if not BPF.get_kprobe_functions(b"filldir64"):
            raise RuntimeError("required filldir64 kprobe unavailable")
        bpf.attach_kprobe(event="filldir64", fn_name="d9_filldir64_enter")
        bpf.attach_kretprobe(
            event="filldir64", fn_name="d9_filldir64_return", maxactive=256
        )
        _set_array(bpf["hash_seeds"], 0, ct.c_ulonglong(DEFAULT_SEED1))
        _set_array(bpf["hash_seeds"], 1, ct.c_ulonglong(DEFAULT_SEED2))
        _set_array(bpf["iblt_cell_count"], 0, ct.c_uint(args.cells))
        _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(1))
        try:
            result = collect_once(
                bpf, args.probe.resolve(), fixture, args.buffer_size,
                args.cells, DEFAULT_SEED1, DEFAULT_SEED2,
            )
        finally:
            _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(0))
            bpf.cleanup()
        print(json.dumps(result, indent=2))
        if not (
            result["measurement_valid"]
            and result["fingerprint_equal"]
            and result["decode_success"]
            and not result["upstream_only"]
            and not result["downstream_only"]
            and result["kernel_stats"]["rejected_entries"] > 0
            and result["userspace"]["syscalls"] > 2
        ):
            raise RuntimeError("pagination smoke criteria failed")
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


if __name__ == "__main__":
    main()
