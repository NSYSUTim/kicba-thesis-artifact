#!/usr/bin/env python3
"""D9 excluded calibration or multi-boot confirmatory campaign runner."""

from __future__ import annotations

import argparse
import ctypes as ct
import gzip
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

from run_campaign import ACK
from run_d9_boundary_suite import (
    CONDITIONS,
    _background_load,
    _build_fixture,
    _expected,
    _module_audit,
    _recovery_matches_oracle,
)
from run_d9_reconciliation_pilot import (
    KNOWN_MODULES,
    STATES,
    SUBSTITUTION_STATE,
    _loaded_modules,
    _set_state,
    _sha256,
    _unload_known,
)
from run_d9_reconciliation_smoke import _set_array, collect_once


PROTOCOL = "D9-reconciliation-campaign-r1-2026-09-24"
CONTROL_STATES = (
    "unloaded", "filldir_pass", "filldir_active",
    "getdents_pass", "getdents_active",
)
BUFFERS = (128, 256, 4096, 65536)
VISIBLE = 512
DIFFERENCE = 16
CELLS = 256


def _delta(after: dict[str, int], before: dict[str, int]) -> dict[str, int]:
    return {name: after[name] - before.get(name, 0) for name in after}


def _local_audit(state: str, result: dict, batch_audit: dict[str, int]) -> dict[str, int]:
    local = dict(batch_audit)
    if state in {"getdents_hiding", "policy_filter"}:
        local["records_removed"] = (
            result["kernel_fingerprint"][0]
            - result["visible_fingerprint"][0]
        )
    elif state == SUBSTITUTION_STATE:
        local["records_rewritten"] = DIFFERENCE
    elif state == "filldir_hiding":
        local["filter_matches"] = DIFFERENCE
    return local


def _validate_transaction(
    *, state: str, result: dict, intended_up: list[list[int]],
    intended_down: list[list[int]], batch_audit: dict[str, int],
) -> dict:
    oracle_match, oracle_scope, expected_up, expected_down = (
        _recovery_matches_oracle(
            state=state, result=result,
            intended_upstream=intended_up,
            intended_downstream=intended_down,
            audit=_local_audit(state, result, batch_audit),
        )
    )
    expected_difference = bool(expected_up or expected_down)
    detected = not result["fingerprint_equal"]
    return {
        "expected_difference": expected_difference,
        "difference_detected": detected,
        "d8_count_alert": (
            result["kernel_fingerprint"][0]
            > result["visible_fingerprint"][0]
        ),
        "oracle_scope": oracle_scope,
        "expected_upstream_count": expected_up,
        "expected_downstream_count": expected_down,
        "decoded_exact": result["decode_success"] and oracle_match,
        "incorrect_success": result["decode_success"] and not oracle_match,
    }


def _batch_treatment_valid(
    state: str, audit: dict[str, int], transactions: list[dict]
) -> bool:
    if audit.get("parse_errors", 0):
        return False
    if state == "filldir_hiding":
        return audit.get("filter_matches") == DIFFERENCE * len(transactions)
    if state in {"getdents_hiding", "policy_filter"}:
        observed = sum(
            tx["kernel_fingerprint"][0] - tx["visible_fingerprint"][0]
            for tx in transactions
        )
        return audit.get("records_removed") == observed and observed > 0
    if state == SUBSTITUTION_STATE:
        return audit.get("records_rewritten") == DIFFERENCE * len(transactions)
    if state == "filldir_active":
        # A buffer-full callback returns false and the VFS may present that
        # entry again on the next getdents64 page.  The active control forwards
        # it, so its match counter legitimately includes these retries.
        return audit.get("filter_matches", 0) >= DIFFERENCE * len(transactions)
    if state == "getdents_active":
        return audit.get("filter_matches", 0) >= DIFFERENCE * len(transactions)
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("calibration", "formal"), required=True)
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
    parser.add_argument("--boot-index", default=1, type=int)
    parser.add_argument("--boot-total", default=8, type=int)
    parser.add_argument("--iterations", default=20, type=int)
    parser.add_argument("--repeats", default=1, type=int)
    parser.add_argument("--seed", default=12013, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or "microsoft" in platform.release().lower():
        parser.error("requires root in the native isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if not 1 <= args.boot_index <= args.boot_total:
        parser.error("boot index outside boot total")
    if args.output.exists():
        raise FileExistsError(args.output)
    if _loaded_modules() & KNOWN_MODULES:
        raise RuntimeError("known research module loaded at campaign start")
    if subprocess.run(
        ["ip", "route", "show", "default"], check=True,
        capture_output=True, text=True,
    ).stdout.strip():
        raise RuntimeError("default route present")

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

    args.output.mkdir(parents=True)
    temporary = Path(tempfile.mkdtemp(prefix="d9_campaign_", dir="/home/kicba"))
    fixture = _build_fixture(temporary, VISIBLE, DIFFERENCE, "ascii")
    rng = random.Random(args.seed ^ (args.boot_index * 0x9E3779B1))
    seed1 = rng.getrandbits(64) or 1
    seed2 = rng.getrandbits(64) or 2
    expected_by_state = {
        state: _expected(fixture, state, seed1, seed2) for state in STATES
    }
    selected_states = CONTROL_STATES if args.role == "calibration" else STATES
    if args.role == "formal":
        shift = (args.boot_index - 1) % len(selected_states)
        state_order = selected_states[shift:] + selected_states[:shift]
    else:
        state_order = list(selected_states)
        rng.shuffle(state_order)

    source = Path(__file__).with_name("bpf_d9_reconciliation.c")
    bpf = BPF(src_file=str(source), cflags=[f"-I{source.parent.resolve()}"])
    bpf.attach_kprobe(event="filldir64", fn_name="d9_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="d9_filldir64_return", maxactive=256
    )
    _set_array(bpf["hash_seeds"], 0, ct.c_ulonglong(seed1))
    _set_array(bpf["hash_seeds"], 1, ct.c_ulonglong(seed2))
    _set_array(bpf["iblt_cell_count"], 0, ct.c_uint(CELLS))
    _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(1))
    batches = []
    failures = []
    try:
        position = 0
        for episode, state in enumerate(state_order):
            _set_state(state, modules)
            cells = [
                (condition, buffer_size, repeat)
                for condition in CONDITIONS
                for buffer_size in BUFFERS
                for repeat in range(args.repeats)
            ]
            rng.shuffle(cells)
            for condition, buffer_size, repeat in cells:
                before = _module_audit(state, modules)
                transactions = []
                with _background_load(condition):
                    for iteration in range(args.iterations):
                        result = collect_once(
                            bpf, args.probe.resolve(), fixture,
                            buffer_size, CELLS, seed1, seed2,
                        )
                        intended_up, intended_down = expected_by_state[state]
                        validated = _validate_transaction(
                            state=state, result=result,
                            intended_up=intended_up,
                            intended_down=intended_down,
                            batch_audit={},
                        )
                        transactions.append({
                            "iteration": iteration,
                            **validated,
                            **result,
                        })
                after = _module_audit(state, modules)
                audit = _delta(after, before)
                treatment_valid = _batch_treatment_valid(
                    state, audit, transactions
                )
                transaction_valid = all(
                    tx["measurement_valid"]
                    and tx["difference_detected"] == tx["expected_difference"]
                    and tx["decoded_exact"]
                    and not tx["incorrect_success"]
                    for tx in transactions
                )
                batch_failures = []
                if not treatment_valid:
                    batch_failures.append("treatment_invalid")
                if not transaction_valid:
                    batch_failures.append("transaction_invalid")
                batch = {
                    "position": position,
                    "episode": episode,
                    "state": state,
                    "condition": condition,
                    "buffer_size": buffer_size,
                    "repeat": repeat,
                    "module_audit": audit,
                    "treatment_valid": treatment_valid,
                    "transaction_valid": transaction_valid,
                    "batch_failures": batch_failures,
                    "transactions": transactions,
                }
                batches.append(batch)
                for failure in batch_failures:
                    failures.append(f"{position}:{state}:{failure}")
                position += 1
            _unload_known()
    finally:
        _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(0))
        _unload_known()
        bpf.cleanup()
        shutil.rmtree(temporary, ignore_errors=True)

    record = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "evidence_role": (
            "excluded_single_boot_timing_calibration"
            if args.role == "calibration"
            else "confirmatory_formal_boot"
        ),
        "role": args.role,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "kernel": platform.release(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "boot_index": args.boot_index,
            "boot_total": args.boot_total,
        },
        "parameters": {
            "seed": args.seed,
            "hash_seed1": seed1,
            "hash_seed2": seed2,
            "visible": VISIBLE,
            "difference": DIFFERENCE,
            "cells": CELLS,
            "buffers": list(BUFFERS),
            "conditions": list(CONDITIONS),
            "iterations_per_batch": args.iterations,
            "repeats_per_cell": args.repeats,
            "state_order": list(state_order),
        },
        "source_hashes": {
            "runner": _sha256(Path(__file__)),
            "smoke_helper": _sha256(
                Path(__file__).with_name("run_d9_reconciliation_smoke.py")
            ),
            "boundary_helper": _sha256(
                Path(__file__).with_name("run_d9_boundary_suite.py")
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
        "batches": batches,
    }
    output_file = args.output / "campaign.json.gz"
    with gzip.open(output_file, "wt", encoding="utf-8") as stream:
        json.dump(record, stream, separators=(",", ":"))
    digest = hashlib.sha256(output_file.read_bytes()).hexdigest()
    (args.output / "campaign.sha256").write_text(
        f"{digest}  {output_file.name}\n", encoding="utf-8"
    )
    print(json.dumps({
        "output": str(output_file), "success": not failures,
        "batches": len(batches), "transactions": sum(
            len(batch["transactions"]) for batch in batches
        ), "failures": failures,
    }, indent=2))
    if failures:
        raise RuntimeError("campaign criteria failed")


if __name__ == "__main__":
    main()
