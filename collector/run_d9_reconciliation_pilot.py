#!/usr/bin/env python3
"""One-boot mechanism pilot for fingerprint + IBLT directory reconciliation."""

from __future__ import annotations

import argparse
import ctypes as ct
import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from kicba.reconciliation import token_for_entry
from run_campaign import ACK
from run_d9_reconciliation_smoke import (
    DEFAULT_SEED1,
    DEFAULT_SEED2,
    _set_array,
    collect_once,
)


PROTOCOL = "D9-reconciliation-mechanism-pilot-r3-2026-09-24"
STATES = (
    "unloaded",
    "filldir_pass",
    "filldir_active",
    "filldir_hiding",
    "getdents_pass",
    "getdents_active",
    "getdents_hiding",
    "getdents_substitution",
    "policy_filter",
)
SUPPRESSION_STATES = {
    "filldir_hiding": "d8_hidden_",
    "getdents_hiding": "d8_hidden_",
    "policy_filter": "d8_policy_",
}
SUBSTITUTION_STATE = "getdents_substitution"
KNOWN_MODULES = {
    "kicba_d7_pass",
    "kicba_d7_active",
    "kicba_d7_hiding",
    "kicba_d8_getdents_pass",
    "kicba_d8_getdents_active",
    "kicba_d8_getdents_hiding",
    "kicba_d8_getdents_policy",
    "kicba_d9_getdents_substitute",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _loaded_modules() -> set[str]:
    return {
        line.split()[0]
        for line in Path("/proc/modules").read_text(encoding="utf-8").splitlines()
        if line
    }


def _unload_known() -> None:
    for module in sorted(_loaded_modules() & KNOWN_MODULES):
        subprocess.run(["rmmod", module], check=True)


def _set_state(state: str, modules: dict[str, Path]) -> None:
    _unload_known()
    if state == "unloaded":
        return
    command = ["insmod", str(modules[state])]
    if state.startswith("filldir_"):
        command.append("counter_comm=d9_enum_probe")
        if state in {"filldir_active", "filldir_hiding"}:
            command.append("magic_word=d8_hidden_")
    elif state == SUBSTITUTION_STATE:
        command.extend([
            "target_comm=d9_enum_probe",
            "match_prefix=d9_swap_a_",
            "replacement_prefix=d9_swap_b_",
        ])
    else:
        command.append("target_comm=d9_enum_probe")
        if state in {"getdents_active", "getdents_hiding"}:
            command.append("match_prefix=d8_hidden_")
        if state == "policy_filter":
            command.append("policy_authorized=1")
    subprocess.run(command, check=True)
    if modules[state].stem not in _loaded_modules():
        raise RuntimeError(f"module did not load: {modules[state].stem}")


def _expected_missing(
    fixture: Path, prefix: str | None, seed1: int, seed2: int
) -> list[list[int]]:
    if prefix is None:
        return []
    values = []
    for path in sorted(fixture.iterdir()):
        if not path.name.startswith(prefix):
            continue
        stat = path.stat()
        token = token_for_entry(path.name, stat.st_ino, 8, seed1, seed2)
        values.append([token.key_hash, token.inode, token.d_type])
    return sorted(values)


def _expected_substitution(
    fixture: Path, seed1: int, seed2: int
) -> tuple[list[list[int]], list[list[int]]]:
    upstream = []
    downstream = []
    for path in sorted(fixture.iterdir()):
        if not path.name.startswith("d9_swap_a_"):
            continue
        stat = path.stat()
        before = token_for_entry(path.name, stat.st_ino, 8, seed1, seed2)
        after_name = "d9_swap_b_" + path.name.removeprefix("d9_swap_a_")
        after = token_for_entry(after_name, stat.st_ino, 8, seed1, seed2)
        upstream.append([before.key_hash, before.inode, before.d_type])
        downstream.append([after.key_hash, after.inode, after.d_type])
    return sorted(upstream), sorted(downstream)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--d7-pass-ko", required=True, type=Path)
    parser.add_argument("--d7-active-ko", required=True, type=Path)
    parser.add_argument("--d7-hiding-ko", required=True, type=Path)
    parser.add_argument("--d8-pass-ko", required=True, type=Path)
    parser.add_argument("--d8-active-ko", required=True, type=Path)
    parser.add_argument("--d8-hiding-ko", required=True, type=Path)
    parser.add_argument("--d8-policy-ko", required=True, type=Path)
    parser.add_argument("--d9-substitute-ko", required=True, type=Path)
    parser.add_argument("--visible", default=512, type=int)
    parser.add_argument("--hidden", default=4, type=int)
    parser.add_argument("--buffer-size", default=256, type=int)
    parser.add_argument("--cells", default=64, type=int)
    parser.add_argument("--iterations", default=3, type=int)
    parser.add_argument("--seed", default=12001, type=int)
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
    if args.cells < 4 or args.cells & (args.cells - 1):
        parser.error("--cells must be a power of two >= 4")
    modules = {
        "filldir_pass": args.d7_pass_ko.resolve(),
        "filldir_active": args.d7_active_ko.resolve(),
        "filldir_hiding": args.d7_hiding_ko.resolve(),
        "getdents_pass": args.d8_pass_ko.resolve(),
        "getdents_active": args.d8_active_ko.resolve(),
        "getdents_hiding": args.d8_hiding_ko.resolve(),
        "policy_filter": args.d8_policy_ko.resolve(),
        "getdents_substitution": args.d9_substitute_ko.resolve(),
    }
    for path in [args.probe.resolve(), *modules.values()]:
        if not path.is_file():
            raise FileNotFoundError(path)
    if _loaded_modules() & KNOWN_MODULES:
        raise RuntimeError("known research module loaded at pilot start")

    args.output.mkdir(parents=True)
    temporary = Path(tempfile.mkdtemp(prefix="d9_reconciliation_pilot_"))
    fixture = temporary / "fixture"
    fixture.mkdir()
    for index in range(args.visible):
        (fixture / f"visible_{index:08d}").touch()
    for index in range(args.hidden):
        (fixture / f"d8_hidden_{index:08d}").touch()
        (fixture / f"d8_policy_{index:08d}").touch()
        (fixture / f"d9_swap_a_{index:08d}").touch()
    # Freeze the exact oracle before any filtering module is loaded.  Building
    # this view after loading filldir_hiding would make the oracle itself use
    # the compromised enumeration path and silently omit the hidden names.
    expected_by_state = {}
    for state in STATES:
        if state == SUBSTITUTION_STATE:
            expected_by_state[state] = _expected_substitution(
                fixture, DEFAULT_SEED1, DEFAULT_SEED2
            )
        else:
            expected_by_state[state] = (
                _expected_missing(
                    fixture, SUPPRESSION_STATES.get(state),
                    DEFAULT_SEED1, DEFAULT_SEED2,
                ),
                [],
            )

    source = Path(__file__).with_name("bpf_d9_reconciliation.c")
    bpf = BPF(src_file=str(source), cflags=[f"-I{source.parent.resolve()}"])
    bpf.attach_kprobe(event="filldir64", fn_name="d9_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="d9_filldir64_return", maxactive=256
    )
    _set_array(bpf["hash_seeds"], 0, ct.c_ulonglong(DEFAULT_SEED1))
    _set_array(bpf["hash_seeds"], 1, ct.c_ulonglong(DEFAULT_SEED2))
    _set_array(bpf["iblt_cell_count"], 0, ct.c_uint(args.cells))
    _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(1))
    schedule = list(STATES) * args.iterations
    random.Random(args.seed).shuffle(schedule)
    rows = []
    try:
        for position, state in enumerate(schedule):
            _set_state(state, modules)
            result = collect_once(
                bpf, args.probe.resolve(), fixture, args.buffer_size,
                args.cells, DEFAULT_SEED1, DEFAULT_SEED2,
            )
            expected_upstream, expected_downstream = expected_by_state[state]
            detected = not result["fingerprint_equal"]
            exact_recovery = (
                result["decode_success"]
                and sorted(result["upstream_only"]) == expected_upstream
                and sorted(result["downstream_only"]) == expected_downstream
            )
            row = {
                "position": position,
                "state": state,
                "difference_present": (
                    state in SUPPRESSION_STATES or state == SUBSTITUTION_STATE
                ),
                "suppression_present": state in SUPPRESSION_STATES,
                "equal_cardinality_substitution": state == SUBSTITUTION_STATE,
                "authorized_policy": state == "policy_filter",
                "expected_upstream_only": expected_upstream,
                "expected_downstream_only": expected_downstream,
                "difference_detected": detected,
                "exact_recovery": exact_recovery,
                **result,
            }
            rows.append(row)
            if not result["measurement_valid"]:
                raise RuntimeError(f"invalid measurement at {position}: {state}")
    finally:
        _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(0))
        _unload_known()
        bpf.cleanup()
        shutil.rmtree(temporary, ignore_errors=True)

    failures = []
    for row in rows:
        expected_alert = row["difference_present"]
        if row["difference_detected"] != expected_alert:
            failures.append(
                f"detection:{row['position']}:{row['state']}"
            )
        if not row["exact_recovery"]:
            failures.append(
                f"recovery:{row['position']}:{row['state']}"
            )
    record = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "evidence_role": "single_boot_development_pilot_not_confirmatory",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "kernel": platform.release(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        },
        "parameters": {
            "visible": args.visible,
            "hidden_per_prefix": args.hidden,
            "buffer_size": args.buffer_size,
            "cells": args.cells,
            "iterations_per_state": args.iterations,
            "seed": args.seed,
            "hash_seed1": DEFAULT_SEED1,
            "hash_seed2": DEFAULT_SEED2,
        },
        "source_hashes": {
            "runner": _sha256(Path(__file__)),
            "smoke_helper": _sha256(
                Path(__file__).with_name("run_d9_reconciliation_smoke.py")
            ),
            "bpf": _sha256(source),
            "hash_header": _sha256(
                Path(__file__).with_name("d9_reconciliation_hash.h")
            ),
            "probe": _sha256(args.probe.resolve()),
            **{f"module_{state}": _sha256(path) for state, path in modules.items()},
        },
        "success": not failures,
        "failures": failures,
        "rows": rows,
    }
    output_file = args.output / "pilot.json"
    output_file.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(output_file),
        "success": not failures,
        "rows": len(rows),
        "failures": failures,
    }, indent=2))
    if failures:
        raise RuntimeError("pilot criteria failed")


if __name__ == "__main__":
    main()
