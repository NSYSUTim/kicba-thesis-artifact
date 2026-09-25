#!/usr/bin/env python3
"""One-boot development pilot for the D7 filldir64 nesting invariant.

The detector feature is kernel-only: for each controlled directory listing it
counts outer filldir64 invocations that do and do not invoke a nested copy of
the same symbol.  File names, userspace entry counts, module names, and labels
are used only for ground-truth/quality audit, never by the decision rule.
"""

from __future__ import annotations

import argparse
import ctypes as ct
import gzip
import hashlib
import json
import os
import platform
import random
import subprocess
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from collect_batch import _set_flag, _stress_command
from collect_d4_batch import _directory_names, _sha256_lines, _spawn_blocked_ls
from run_campaign import ACK, _atomic_manifest, _boot_id


PROTOCOL = "D7-nesting-development-r1-2026-09-21"
STATES = ("unloaded", "pass", "active", "hiding")
CONDITIONS = ("baseline", "cpu", "memory", "mixed")
REPLICATES = 3
ITERATIONS = 20
CARDINALITY = 128
FILENAME_LENGTH = 32
MODULE_BY_STATE = {
    "pass": "kicba_d7_pass",
    "active": "kicba_d7_active",
    "hiding": "kicba_d7_hiding",
}
COUNTERS = (
    "fillonedir_calls", "filldir_calls", "filldir64_calls",
    "compat_fillonedir_calls", "compat_filldir_calls",
    "filter_checks", "filter_matches",
)
MAPS = (
    "depth_by_pid", "top_has_child", "top_level_calls",
    "forwarded_top_calls", "short_circuit_top_calls",
    "max_depth_by_pid", "return_underflows",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _loaded_modules() -> set[str]:
    return {
        line.split()[0]
        for line in Path("/proc/modules").read_text(encoding="utf-8").splitlines()
        if line
    }


def _set_state(state: str, modules: dict[str, Path]) -> None:
    known = set(MODULE_BY_STATE.values()) | {"caraxes", "caraxes_sham"}
    for module in sorted(_loaded_modules() & known):
        subprocess.run(["rmmod", module], check=True)
    if state != "unloaded":
        subprocess.run(["insmod", str(modules[state])], check=True)
    expected = set() if state == "unloaded" else {MODULE_BY_STATE[state]}
    actual = _loaded_modules() & known
    if actual != expected:
        raise RuntimeError(f"failed to enter {state}: {sorted(actual)}")


def _counter_snapshot(module: str | None) -> dict[str, int]:
    if module is None:
        return {name: 0 for name in COUNTERS}
    root = Path("/sys/module") / module / "parameters"
    return {
        name: int((root / name).read_text(encoding="utf-8").strip())
        for name in COUNTERS
    }


def _map_value(table, key: ct.c_uint) -> int:
    try:
        return int(table[key].value)
    except KeyError:
        return 0


def _delete(table, key: ct.c_uint) -> None:
    try:
        del table[key]
    except KeyError:
        pass


def build_schedule(seed: int) -> list[dict]:
    rows = [
        {"state": state, "condition": condition, "replicate": replicate}
        for state in STATES
        for condition in CONDITIONS
        for replicate in range(REPLICATES)
    ]
    random.Random(seed).shuffle(rows)
    for position, row in enumerate(rows):
        row.update({"position": position, "status": "pending", "output": None})
    return rows


def _collect_batch(
    *, bpf: BPF, enabled, monitored, maps: dict, fixture: Path,
    hidden: str, expected: set[str], state: str, condition: str,
    position: int, campaign_id: str, output: Path,
) -> Path:
    module = MODULE_BY_STATE.get(state)
    before = _counter_snapshot(module)
    stress = None
    transactions = []
    mismatch_iterations = []
    hidden_visible = 0
    command = _stress_command(condition, 4, "256M")
    started = datetime.now(timezone.utc).isoformat()
    started_ns = time.monotonic_ns()
    try:
        if command:
            stress = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(1.0)
        _set_flag(enabled, 1)
        for iteration in range(ITERATIONS):
            with tempfile.TemporaryFile() as output_stream:
                process = _spawn_blocked_ls(str(fixture), output_stream)
                key = ct.c_uint(process.pid)
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
                    row = {
                        "iteration": iteration,
                        "top_level_calls": _map_value(maps["top_level_calls"], key),
                        "forwarded_top_calls": _map_value(
                            maps["forwarded_top_calls"], key
                        ),
                        "short_circuit_top_calls": _map_value(
                            maps["short_circuit_top_calls"], key
                        ),
                        "max_depth": _map_value(maps["max_depth_by_pid"], key),
                        "return_underflows": _map_value(
                            maps["return_underflows"], key
                        ),
                    }
                    # The detector uses only the two structural counts below.
                    row["structural_alert"] = (
                        row["forwarded_top_calls"] > 0
                        and row["short_circuit_top_calls"] > 0
                    )
                    transactions.append(row)
                finally:
                    _delete(monitored, key)
                    for table in maps.values():
                        _delete(table, key)
            if set(observed) != expected or len(observed) != len(expected):
                mismatch_iterations.append(iteration)
            if hidden in observed:
                hidden_visible += 1
    finally:
        _set_flag(enabled, 0)
        if stress is not None:
            stress.terminate()
            try:
                stress.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stress.kill()
                stress.wait()
    ended_ns = time.monotonic_ns()
    after = _counter_snapshot(module)
    complete = (
        len(transactions) == ITERATIONS
        and all(
            row["top_level_calls"]
            == row["forwarded_top_calls"] + row["short_circuit_top_calls"]
            and row["top_level_calls"] > 0
            and row["return_underflows"] == 0
            for row in transactions
        )
    )
    exact_output = not mismatch_iterations
    record = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "batch_id": uuid.uuid4().hex,
        "evidence_role": "single_boot_development_pilot_not_confirmatory",
        "truth": {"state": state, "condition": condition},
        "environment": {"boot_id": _boot_id(), "kernel": platform.release()},
        "collection": {
            "campaign_id": campaign_id,
            "campaign_position": position,
            "started_utc": started,
            "enabled_wall_duration_ns": ended_ns - started_ns,
            "attached_functions": ["filldir64 entry", "filldir64 return"],
            "feature_inputs": [
                "forwarded_top_calls", "short_circuit_top_calls"
            ],
        },
        "decision_rule": (
            "alert iff a listing contains both a top-level filldir64 call "
            "with a nested filldir64 child and one without such a child"
        ),
        "directory_factor": {
            "visible_cardinality": CARDINALITY,
            "filename_length": FILENAME_LENGTH,
            "fixture_inode": fixture.stat().st_ino,
        },
        "listing_audit_not_detector_input": {
            "exact_output_pass": exact_output,
            "mismatch_iterations": mismatch_iterations,
            "hidden_visible_iterations": hidden_visible,
        },
        "module_counter_audit_not_detector_input": {
            name: after[name] - before[name] for name in COUNTERS
        },
        "quality": {
            "valid_for_analysis": complete and exact_output,
            "all_transactions_complete": complete,
            "exact_output_pass": exact_output,
        },
        "transactions": transactions,
    }
    path = output / f"batch_{position:03d}_{record['batch_id'][:8]}.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(record, handle, separators=(",", ":"))
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pass-ko", required=True, type=Path)
    parser.add_argument("--active-ko", required=True, type=Path)
    parser.add_argument("--hiding-ko", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed", default=10707, type=int)
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
    modules = {
        "pass": args.pass_ko.resolve(),
        "active": args.active_ko.resolve(),
        "hiding": args.hiding_ko.resolve(),
    }
    known = set(MODULE_BY_STATE.values()) | {"caraxes", "caraxes_sham"}
    if _loaded_modules() & known:
        raise RuntimeError("D7/CARAXES module loaded at pilot start")
    output = args.output.resolve()
    fixture = output.parent / f"{output.name}_fixture"
    if output.exists() or fixture.exists():
        raise FileExistsError("refusing to overwrite pilot output/fixture")
    output.mkdir(parents=True)
    fixture.mkdir()
    visible, hidden, creation, slot = _directory_names(
        CARDINALITY, FILENAME_LENGTH, "middle"
    )
    for name in creation:
        (fixture / name).touch()
    source = Path(__file__).with_name("bpf_d7_nesting.c")
    bpf = BPF(src_file=str(source))
    if not BPF.get_kprobe_functions(b"filldir64"):
        raise RuntimeError("filldir64 kprobe unavailable")
    bpf.attach_kprobe(event="filldir64", fn_name="trace_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="trace_filldir64_return", maxactive=256
    )
    enabled = bpf["collection_enabled"]
    monitored = bpf["monitored_pids"]
    maps = {name: bpf[name] for name in MAPS}
    boot_id = _boot_id()
    campaign_id = f"d7nest_{boot_id}_{args.seed}_{uuid.uuid4().hex[:8]}"
    schedule = build_schedule(args.seed)
    manifest = {
        "protocol_revision": PROTOCOL,
        "status": "running",
        "evidence_role": "single_boot_development_pilot_not_confirmatory",
        "campaign_id": campaign_id,
        "boot_id": boot_id,
        "seed": args.seed,
        "expected_batches": len(schedule),
        "iterations": ITERATIONS,
        "fixture_inode": fixture.stat().st_ino,
        "fixture_creation_order_sha256": _sha256_lines(
            creation, sorted_lines=False
        ),
        "fixture_hidden_creation_index": slot,
        "source_hashes": {
            "runner": _sha256(Path(__file__)),
            "bpf": _sha256(source),
            **{f"module_{state}": _sha256(path) for state, path in modules.items()},
        },
        "schedule": schedule,
    }
    manifest_path = output / f"campaign_{campaign_id}.json"
    _atomic_manifest(manifest_path, manifest)
    try:
        for item in schedule:
            _set_state(item["state"], modules)
            expected = {".", "..", *visible}
            if item["state"] != "hiding":
                expected.add(hidden)
            path = _collect_batch(
                bpf=bpf, enabled=enabled, monitored=monitored, maps=maps,
                fixture=fixture, hidden=hidden, expected=expected,
                state=item["state"], condition=item["condition"],
                position=item["position"], campaign_id=campaign_id,
                output=output,
            )
            item.update({
                "status": "complete", "output": str(path),
                "completed_utc": datetime.now(timezone.utc).isoformat(),
            })
            _atomic_manifest(manifest_path, manifest)
    except BaseException as exc:
        manifest.update({
            "status": "failed", "failure": f"{type(exc).__name__}: {exc}",
            "failed_utc": datetime.now(timezone.utc).isoformat(),
        })
        _atomic_manifest(manifest_path, manifest)
        raise
    finally:
        _set_flag(enabled, 0)
        _set_state("unloaded", modules)
        bpf.cleanup()
    manifest["status"] = "complete"
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    _atomic_manifest(manifest_path, manifest)
    print(manifest_path)


if __name__ == "__main__":
    main()
