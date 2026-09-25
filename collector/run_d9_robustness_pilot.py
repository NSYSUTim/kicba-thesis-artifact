#!/usr/bin/env python3
"""D9 churn, concurrent-PID, and fail-closed development pilot."""

from __future__ import annotations

import argparse
import ctypes as ct
import json
import os
import platform
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from run_campaign import ACK
from run_d9_boundary_suite import (
    _build_fixture,
    _expected,
    _module_audit,
    _recovery_matches_oracle,
)
from run_d9_reconciliation_pilot import (
    KNOWN_MODULES,
    SUBSTITUTION_STATE,
    _loaded_modules,
    _set_state,
    _sha256,
    _unload_known,
)
from run_d9_reconciliation_smoke import (
    DEFAULT_SEED1,
    DEFAULT_SEED2,
    _set_array,
    cleanup_pid,
    collect_once,
    result_for_pid,
)


PROTOCOL = "D9-reconciliation-robustness-pilot-r1-2026-09-24"
CHURN_STATES = (
    "unloaded", "filldir_hiding", "getdents_hiding",
    "getdents_substitution", "policy_filter",
)
CONCURRENT_STATES = (
    "unloaded", "filldir_hiding", "getdents_hiding",
    "getdents_substitution",
)


def _spawn_probe(
    probe: Path, fixture: Path, buffer_size: int, cells: int,
    seed1: int = DEFAULT_SEED1, seed2: int = DEFAULT_SEED2,
) -> subprocess.Popen:
    return subprocess.Popen(
        [
            str(probe), str(fixture), str(buffer_size), str(cells),
            str(seed1), str(seed2),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _start_all(processes: list[subprocess.Popen]) -> None:
    for process in processes:
        assert process.stdin is not None
        process.stdin.write("\n")
        process.stdin.flush()
        process.stdin.close()
        process.stdin = None


def _churn_worker(fixture: Path, stop: threading.Event, counts: dict) -> None:
    index = 0
    while not stop.is_set():
        first = fixture / f"churn_a_{index % 128:04d}"
        second = fixture / f"churn_b_{index % 128:04d}"
        try:
            first.touch(exist_ok=True)
            counts["create"] += 1
            first.replace(second)
            counts["rename"] += 1
            second.unlink(missing_ok=True)
            counts["delete"] += 1
        except FileNotFoundError:
            counts["races"] += 1
        index += 1


def _validate_one(
    state: str,
    result: dict,
    intended_upstream: list[list[int]],
    intended_downstream: list[list[int]],
    audit: dict[str, int],
) -> dict:
    oracle_match, oracle_scope, expected_up, expected_down = (
        _recovery_matches_oracle(
            state=state,
            result=result,
            intended_upstream=intended_upstream,
            intended_downstream=intended_downstream,
            audit=audit,
        )
    )
    expected_difference = bool(expected_up or expected_down)
    return {
        "expected_difference": expected_difference,
        "difference_detected": not result["fingerprint_equal"],
        "oracle_scope": oracle_scope,
        "expected_upstream_count": expected_up,
        "expected_downstream_count": expected_down,
        "decoded_exact": result["decode_success"] and oracle_match,
        "incorrect_success": result["decode_success"] and not oracle_match,
    }


def _concurrent_collect(
    *, bpf: BPF, probe: Path, fixture: Path, workers: int,
    buffer_size: int, cells: int,
) -> list[dict]:
    processes = [
        _spawn_probe(probe, fixture, buffer_size, cells)
        for _ in range(workers)
    ]
    monitored = bpf["monitored_pids"]
    for process in processes:
        monitored[ct.c_uint(process.pid)] = ct.c_ubyte(1)
    outputs = []
    try:
        _start_all(processes)
        for process in processes:
            stdout, stderr = process.communicate(timeout=60)
            if process.returncode:
                raise RuntimeError(stderr.strip())
            visible = json.loads(stdout)
            outputs.append(result_for_pid(
                bpf, process.pid, visible, cells,
                DEFAULT_SEED1, DEFAULT_SEED2,
            ))
        return outputs
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            cleanup_pid(bpf, process.pid)


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
    temporary = Path(tempfile.mkdtemp(prefix="d9_robustness_", dir="/home/kicba"))
    fixture = _build_fixture(temporary, 8192, 16, "ascii")
    large_fixture = _build_fixture(temporary, 65536, 0, "ascii")
    source = Path(__file__).with_name("bpf_d9_reconciliation.c")
    bpf = BPF(src_file=str(source), cflags=[f"-I{source.parent.resolve()}"])
    bpf.attach_kprobe(event="filldir64", fn_name="d9_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="d9_filldir64_return", maxactive=256
    )
    _set_array(bpf["hash_seeds"], 0, ct.c_ulonglong(DEFAULT_SEED1))
    _set_array(bpf["hash_seeds"], 1, ct.c_ulonglong(DEFAULT_SEED2))
    _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(1))
    rows = []
    failures = []
    try:
        # Normal create/rename/delete activity during the listing.
        for state in CHURN_STATES:
            for buffer_size in (256, 4096):
                _unload_known()
                intended_up, intended_down = _expected(fixture, state)
                _set_state(state, modules)
                _set_array(bpf["iblt_cell_count"], 0, ct.c_uint(256))
                stop = threading.Event()
                counts = {"create": 0, "rename": 0, "delete": 0, "races": 0}
                thread = threading.Thread(
                    target=_churn_worker, args=(fixture, stop, counts), daemon=True
                )
                thread.start()
                time.sleep(0.02)
                try:
                    result = collect_once(
                        bpf, args.probe.resolve(), fixture, buffer_size, 256,
                        DEFAULT_SEED1, DEFAULT_SEED2,
                    )
                finally:
                    stop.set()
                    thread.join(timeout=5)
                audit = _module_audit(state, modules)
                validated = _validate_one(
                    state, result, intended_up, intended_down, audit
                )
                ok = (
                    result["measurement_valid"]
                    and validated["difference_detected"]
                        == validated["expected_difference"]
                    and validated["decoded_exact"]
                    and counts["create"] > 0
                )
                row = {
                    "axis": "normal_churn", "state": state,
                    "buffer_size": buffer_size, "churn": counts,
                    "module_audit": audit, "pass": ok,
                    **validated, **result,
                }
                rows.append(row)
                if not ok:
                    failures.append(f"churn:{state}:{buffer_size}")

        # Multiple monitored PIDs running at the same time.
        for state in CONCURRENT_STATES:
            for workers in (2, 4, 8, 16):
                _unload_known()
                intended_up, intended_down = _expected(fixture, state)
                _set_state(state, modules)
                _set_array(bpf["iblt_cell_count"], 0, ct.c_uint(256))
                results = _concurrent_collect(
                    bpf=bpf, probe=args.probe.resolve(), fixture=fixture,
                    workers=workers, buffer_size=256, cells=256,
                )
                audit = _module_audit(state, modules)
                per_pid = []
                for result in results:
                    if state in {"getdents_hiding"}:
                        # The module audit counter is aggregate.  Per PID, the
                        # count delta is the independently observed removed count.
                        local_audit = {**audit, "records_removed": (
                            result["kernel_fingerprint"][0]
                            - result["visible_fingerprint"][0]
                        )}
                    elif state == SUBSTITUTION_STATE:
                        local_audit = {**audit, "records_rewritten": 16}
                    elif state == "filldir_hiding":
                        local_audit = {**audit, "filter_matches": 16}
                    else:
                        local_audit = audit
                    per_pid.append({
                        **_validate_one(
                            state, result, intended_up, intended_down, local_audit
                        ),
                        **result,
                    })
                aggregate_observed = sum(
                    len(item["upstream_only"]) for item in per_pid
                )
                if state == "getdents_hiding":
                    audit_count = audit["records_removed"]
                elif state == SUBSTITUTION_STATE:
                    audit_count = audit["records_rewritten"]
                elif state == "filldir_hiding":
                    audit_count = audit["filter_matches"]
                else:
                    audit_count = 0
                ok = (
                    all(item["measurement_valid"] for item in per_pid)
                    and all(
                        item["difference_detected"] == item["expected_difference"]
                        and item["decoded_exact"]
                        for item in per_pid
                    )
                    and aggregate_observed == audit_count
                )
                rows.append({
                    "axis": "concurrent_pid", "state": state,
                    "workers": workers, "module_audit": audit,
                    "aggregate_recovered_upstream": aggregate_observed,
                    "audit_difference_count": audit_count,
                    "pass": ok, "per_pid": per_pid,
                })
                if not ok:
                    failures.append(f"concurrent:{state}:{workers}")

        # Invalid IBLT configuration must never be reported as a clean negative.
        _unload_known()
        _set_array(bpf["iblt_cell_count"], 0, ct.c_uint(2))
        invalid_cells = collect_once(
            bpf, args.probe.resolve(), fixture, 4096, 64,
            DEFAULT_SEED1, DEFAULT_SEED2,
        )
        ok = (
            not invalid_cells["measurement_valid"]
            and not invalid_cells["configuration_valid"]
            and invalid_cells["kernel_stats"]["iblt_update_failures"] > 0
        )
        rows.append({
            "axis": "fault_injection", "fault": "invalid_kernel_cell_count",
            "pass": ok, **invalid_cells,
        })
        if not ok:
            failures.append("fault:invalid_kernel_cell_count")

        # A controller seed mismatch is also invalid, even though it creates a
        # fingerprint difference that could otherwise look like an alert.
        _set_array(
            bpf["hash_seeds"], 0, ct.c_ulonglong(DEFAULT_SEED1 ^ 0x55)
        )
        _set_array(bpf["iblt_cell_count"], 0, ct.c_uint(64))
        wrong_seed = collect_once(
            bpf, args.probe.resolve(), fixture, 4096, 64,
            DEFAULT_SEED1, DEFAULT_SEED2,
        )
        ok = not wrong_seed["measurement_valid"] and not wrong_seed["configuration_valid"]
        rows.append({
            "axis": "fault_injection", "fault": "controller_seed_mismatch",
            "pass": ok, **wrong_seed,
        })
        if not ok:
            failures.append("fault:controller_seed_mismatch")
        _set_array(bpf["hash_seeds"], 0, ct.c_ulonglong(DEFAULT_SEED1))

        # An unregistered process yields no kernel-side transaction and must be
        # rejected instead of being interpreted as a no-difference result.
        process = _spawn_probe(args.probe.resolve(), fixture, 4096, 64)
        rejected = False
        try:
            stdout, stderr = process.communicate("\n", timeout=60)
            if process.returncode:
                raise RuntimeError(stderr.strip())
            try:
                result_for_pid(
                    bpf, process.pid, json.loads(stdout), 64,
                    DEFAULT_SEED1, DEFAULT_SEED2,
                )
            except RuntimeError:
                rejected = True
        finally:
            cleanup_pid(bpf, process.pid)
        rows.append({
            "axis": "fault_injection", "fault": "unregistered_pid",
            "pass": rejected, "collector_rejected": rejected,
        })
        if not rejected:
            failures.append("fault:unregistered_pid")

        # Kill a registered large scan immediately after its start gate.
        process = _spawn_probe(args.probe.resolve(), large_fixture, 128, 64)
        bpf["monitored_pids"][ct.c_uint(process.pid)] = ct.c_ubyte(1)
        interrupted_rejected = False
        returncode = None
        try:
            assert process.stdin is not None
            process.stdin.write("\n")
            process.stdin.flush()
            process.kill()
            process.wait(timeout=5)
            returncode = process.returncode
            interrupted_rejected = returncode != 0
        finally:
            cleanup_pid(bpf, process.pid)
        rows.append({
            "axis": "fault_injection", "fault": "interrupted_enumeration",
            "pass": interrupted_rejected,
            "process_returncode": returncode,
            "collector_rejected": interrupted_rejected,
        })
        if not interrupted_rejected:
            failures.append("fault:interrupted_enumeration")
    finally:
        _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(0))
        _unload_known()
        bpf.cleanup()
        shutil.rmtree(temporary, ignore_errors=True)

    record = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "evidence_role": "single_boot_development_robustness_pilot_not_confirmatory",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "kernel": platform.release(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
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
            "probe": _sha256(args.probe.resolve()),
        },
        "success": not failures,
        "failures": failures,
        "rows": rows,
    }
    output_file = args.output / "robustness_pilot.json"
    output_file.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(output_file), "success": not failures,
        "rows": len(rows), "failures": failures,
    }, indent=2))
    if failures:
        raise RuntimeError("robustness pilot criteria failed")


if __name__ == "__main__":
    main()
