#!/usr/bin/env python3
"""One-boot D9 boundary suite; development evidence, never formal evidence."""

from __future__ import annotations

import argparse
import ctypes as ct
import hashlib
import json
import os
import platform
import random
import shutil
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from collect_batch import _stress_command
from kicba.reconciliation import recommended_cell_count, token_for_entry
from run_campaign import ACK
from run_d9_reconciliation_pilot import (
    KNOWN_MODULES,
    STATES,
    SUBSTITUTION_STATE,
    SUPPRESSION_STATES,
    _loaded_modules,
    _set_state,
    _sha256,
    _unload_known,
)
from run_d9_reconciliation_smoke import (
    DEFAULT_SEED1,
    DEFAULT_SEED2,
    _set_array,
    collect_once,
)


PROTOCOL = "D9-reconciliation-boundary-suite-r1-2026-09-24"
CONDITIONS = ("baseline", "cpu", "memory", "mixed")


def _dtype(mode: int) -> int:
    if stat.S_ISFIFO(mode):
        return 1
    if stat.S_ISCHR(mode):
        return 2
    if stat.S_ISDIR(mode):
        return 4
    if stat.S_ISBLK(mode):
        return 6
    if stat.S_ISREG(mode):
        return 8
    if stat.S_ISLNK(mode):
        return 10
    if stat.S_ISSOCK(mode):
        return 12
    return 0


def _name(prefix: str, index: int, profile: str) -> str:
    suffix = f"{index:08d}"
    if profile == "unicode":
        return f"{prefix}資料_測試_{suffix}"
    if profile == "long":
        base = prefix + suffix + "_"
        return base + ("x" * (255 - len(base.encode("ascii"))))
    return prefix + suffix


def _create_entry(path: Path, kind_index: int, anchor: Path) -> None:
    kind = kind_index % 4
    if kind == 0:
        path.touch()
    elif kind == 1:
        path.mkdir()
    elif kind == 2:
        path.symlink_to(anchor.name)
    else:
        os.link(anchor, path)


def _build_fixture(
    parent: Path, visible: int, difference: int, profile: str
) -> Path:
    fixture = Path(tempfile.mkdtemp(prefix="d9_boundary_", dir=parent))
    anchor = fixture / "visible_anchor"
    anchor.touch()
    for index in range(visible):
        (fixture / _name("visible_", index, profile)).touch()
    for prefix in ("d8_hidden_", "d8_policy_", "d9_swap_a_"):
        for index in range(difference):
            target = fixture / _name(prefix, index, profile)
            if profile == "types":
                _create_entry(target, index, anchor)
            else:
                target.touch()
    return fixture


def _prefix_tokens(
    fixture: Path, prefix: str,
    seed1: int = DEFAULT_SEED1, seed2: int = DEFAULT_SEED2,
) -> list[list[int]]:
    tokens = []
    with os.scandir(fixture) as entries:
        for entry in entries:
            if not entry.name.startswith(prefix):
                continue
            mode = entry.stat(follow_symlinks=False).st_mode
            token = token_for_entry(
                os.fsencode(entry.name), entry.inode(), _dtype(mode),
                seed1, seed2,
            )
            tokens.append([token.key_hash, token.inode, token.d_type])
    return sorted(tokens)


def _expected(
    fixture: Path, state: str,
    seed1: int = DEFAULT_SEED1, seed2: int = DEFAULT_SEED2,
) -> tuple[list[list[int]], list[list[int]]]:
    if state == SUBSTITUTION_STATE:
        upstream = _prefix_tokens(fixture, "d9_swap_a_", seed1, seed2)
        downstream = []
        with os.scandir(fixture) as entries:
            for entry in entries:
                if not entry.name.startswith("d9_swap_a_"):
                    continue
                replacement = "d9_swap_b_" + entry.name.removeprefix("d9_swap_a_")
                mode = entry.stat(follow_symlinks=False).st_mode
                token = token_for_entry(
                    os.fsencode(replacement), entry.inode(), _dtype(mode),
                    seed1, seed2,
                )
                downstream.append([token.key_hash, token.inode, token.d_type])
        return upstream, sorted(downstream)
    prefix = SUPPRESSION_STATES.get(state)
    return (
        _prefix_tokens(fixture, prefix, seed1, seed2), []
    ) if prefix else ([], [])


def _module_audit(state: str, modules: dict[str, Path]) -> dict[str, int]:
    if state == "unloaded":
        return {}
    names = []
    if state.startswith("filldir_"):
        names = ["filter_checks", "filter_matches"]
    elif state in {"getdents_hiding", "policy_filter"}:
        names = ["filter_matches", "records_removed", "parse_errors"]
    elif state == SUBSTITUTION_STATE:
        names = ["records_rewritten", "parse_errors"]
    else:
        names = ["filter_matches", "parse_errors"]
    root = Path("/sys/module") / modules[state].stem / "parameters"
    values = {}
    for name in names:
        path = root / name
        values[name] = int(path.read_text(encoding="utf-8").strip())
    return values


def _recovery_matches_oracle(
    *, state: str, result: dict, intended_upstream: list[list[int]],
    intended_downstream: list[list[int]], audit: dict[str, int],
) -> tuple[bool, str, int, int]:
    """Validate decoded identities without treating post-EOF files as observed."""

    recovered_upstream = sorted(result["upstream_only"])
    recovered_downstream = sorted(result["downstream_only"])
    if state in {"getdents_hiding", "policy_filter"}:
        observed = audit["records_removed"]
        matches = (
            len(recovered_upstream) == observed
            and not recovered_downstream
            and set(map(tuple, recovered_upstream)).issubset(
                set(map(tuple, intended_upstream))
            )
        )
        return matches, "observed_transaction_subset", observed, 0
    if state == SUBSTITUTION_STATE:
        observed = audit["records_rewritten"]
        matches = (
            len(recovered_upstream) == observed
            and len(recovered_downstream) == observed
            and set(map(tuple, recovered_upstream)).issubset(
                set(map(tuple, intended_upstream))
            )
            and set(map(tuple, recovered_downstream)).issubset(
                set(map(tuple, intended_downstream))
            )
        )
        return matches, "observed_transaction_subset", observed, observed
    if state == "filldir_hiding":
        observed = audit["filter_matches"]
        matches = (
            len(recovered_upstream) == observed
            and not recovered_downstream
            and recovered_upstream == intended_upstream
        )
        return matches, "full_fixture", observed, 0
    matches = not recovered_upstream and not recovered_downstream
    return matches, "zero_difference", 0, 0


@contextmanager
def _background_load(condition: str):
    command = _stress_command(condition, 2, "128M")
    process = None
    try:
        if command:
            process = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(0.25)
        yield
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def _case(
    axis: str,
    state: str,
    visible: int = 512,
    difference: int = 4,
    buffer_size: int = 256,
    cells: int | None = None,
    condition: str = "baseline",
    profile: str = "ascii",
    filesystem: str = "ext4",
    require_decode: bool = True,
) -> dict:
    if cells is None:
        cells = recommended_cell_count(max(1, difference), factor=8)
    return {
        "axis": axis,
        "state": state,
        "visible": visible,
        "difference": difference,
        "buffer_size": buffer_size,
        "cells": cells,
        "condition": condition,
        "profile": profile,
        "filesystem": filesystem,
        "require_decode": require_decode,
    }


def build_cases(seed: int, quick: bool) -> list[dict]:
    cases: list[dict] = []
    buffers = (128, 4096) if quick else (128, 256, 4096, 65536)
    conditions = ("baseline", "mixed") if quick else CONDITIONS
    states = STATES if not quick else (
        "unloaded", "filldir_active", "filldir_hiding",
        "getdents_active", "getdents_hiding",
        "getdents_substitution", "policy_filter",
    )
    for state in states:
        for buffer_size in buffers:
            for condition in conditions:
                cases.append(_case(
                    "core_factorial", state, buffer_size=buffer_size,
                    condition=condition,
                ))

    sizes = (0, 16, 512, 8192) if quick else (0, 1, 16, 512, 8192, 65536)
    for visible in sizes:
        for state in ("unloaded", "getdents_hiding"):
            cases.append(_case(
                "directory_scale", state, visible=visible,
                buffer_size=4096,
            ))

    differences = (1, 16, 64) if quick else (1, 4, 16, 64, 256, 512)
    for difference in differences:
        for state in (
            "filldir_hiding", "getdents_hiding",
            "getdents_substitution", "policy_filter",
        ):
            cases.append(_case(
                "difference_scale", state,
                visible=max(512, difference * 2), difference=difference,
                buffer_size=256,
            ))

    capacity_differences = (16,) if quick else (16, 64, 256)
    for difference in capacity_differences:
        for state in ("getdents_hiding", "getdents_substitution"):
            for factor in (1, 2, 4, 8):
                cases.append(_case(
                    "capacity_boundary", state,
                    visible=max(512, difference * 2), difference=difference,
                    buffer_size=4096,
                    cells=recommended_cell_count(difference, factor=factor),
                    require_decode=factor == 8,
                ))

    profiles = ("unicode", "long", "types")
    profile_states = ("unloaded", "getdents_hiding", "getdents_substitution")
    for profile in profiles:
        for state in profile_states:
            cases.append(_case(
                "entry_profile", state, visible=32, difference=8,
                buffer_size=512 if profile == "long" else 256,
                profile=profile,
            ))

    for filesystem in ("ext4", "tmpfs"):
        for state in ("unloaded", "getdents_hiding", "getdents_substitution"):
            cases.append(_case(
                "filesystem", state, visible=512, difference=16,
                buffer_size=256, filesystem=filesystem,
            ))

    random.Random(seed).shuffle(cases)
    for position, case in enumerate(cases):
        case["position"] = position
    return cases


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
    parser.add_argument("--seed", default=12010, type=int)
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
    if shutil.which("stress-ng") is None:
        raise RuntimeError("stress-ng is required")

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
        raise RuntimeError("known research module loaded at suite start")

    cases = build_cases(args.seed, args.quick)
    args.output.mkdir(parents=True)
    roots = {
        "ext4": Path(tempfile.mkdtemp(prefix="d9_suite_ext4_", dir="/home/kicba")),
        "tmpfs": Path(tempfile.mkdtemp(prefix="d9_suite_tmpfs_", dir="/dev/shm")),
    }
    fixtures: dict[tuple, Path] = {}
    rows = []
    failures = []
    source = Path(__file__).with_name("bpf_d9_reconciliation.c")
    bpf = BPF(src_file=str(source), cflags=[f"-I{source.parent.resolve()}"])
    bpf.attach_kprobe(event="filldir64", fn_name="d9_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="d9_filldir64_return", maxactive=256
    )
    _set_array(bpf["hash_seeds"], 0, ct.c_ulonglong(DEFAULT_SEED1))
    _set_array(bpf["hash_seeds"], 1, ct.c_ulonglong(DEFAULT_SEED2))
    _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(1))
    try:
        for case in cases:
            _unload_known()
            cache_key = (
                case["filesystem"], case["visible"],
                case["difference"], case["profile"],
            )
            fixture = fixtures.get(cache_key)
            if fixture is None:
                fixture = _build_fixture(
                    roots[case["filesystem"]], case["visible"],
                    case["difference"], case["profile"],
                )
                fixtures[cache_key] = fixture
            intended_upstream, intended_downstream = _expected(
                fixture, case["state"]
            )
            _set_state(case["state"], modules)
            _set_array(
                bpf["iblt_cell_count"], 0, ct.c_uint(case["cells"])
            )
            with _background_load(case["condition"]):
                result = collect_once(
                    bpf, args.probe.resolve(), fixture,
                    case["buffer_size"], case["cells"],
                    DEFAULT_SEED1, DEFAULT_SEED2,
                )
            audit = _module_audit(case["state"], modules)
            oracle_match, oracle_scope, expected_upstream_count, expected_downstream_count = (
                _recovery_matches_oracle(
                    state=case["state"], result=result,
                    intended_upstream=intended_upstream,
                    intended_downstream=intended_downstream,
                    audit=audit,
                )
            )
            expected_difference = bool(
                expected_upstream_count or expected_downstream_count
            )
            decoded_exact = result["decode_success"] and oracle_match
            incorrect_success = result["decode_success"] and not oracle_match
            count_delta = (
                result["kernel_fingerprint"][0]
                - result["visible_fingerprint"][0]
            )
            row = {
                **case,
                "expected_difference": expected_difference,
                "intended_upstream_count": len(intended_upstream),
                "intended_downstream_count": len(intended_downstream),
                "expected_upstream_count": expected_upstream_count,
                "expected_downstream_count": expected_downstream_count,
                "oracle_scope": oracle_scope,
                "module_audit": audit,
                "difference_detected": not result["fingerprint_equal"],
                "d8_count_alert": count_delta > 0,
                "count_delta": count_delta,
                "decoded_exact": decoded_exact,
                "incorrect_success": incorrect_success,
                **result,
            }
            row_failures = []
            if not result["measurement_valid"]:
                row_failures.append("measurement_invalid")
            if row["difference_detected"] != expected_difference:
                row_failures.append("detection_mismatch")
            if incorrect_success:
                row_failures.append("incorrect_successful_decode")
            if case["require_decode"] and not decoded_exact:
                row_failures.append("required_exact_decode_failed")
            if not expected_difference and not decoded_exact:
                row_failures.append("zero_difference_decode_failed")
            row["row_failures"] = row_failures
            rows.append(row)
            for failure in row_failures:
                failures.append(f"{case['position']}:{failure}")
    finally:
        _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(0))
        _unload_known()
        bpf.cleanup()
        for root in roots.values():
            shutil.rmtree(root, ignore_errors=True)

    record = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "evidence_role": "single_boot_development_boundary_suite_not_confirmatory",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "kernel": platform.release(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        },
        "parameters": {
            "quick": args.quick,
            "seed": args.seed,
            "hash_seed1": DEFAULT_SEED1,
            "hash_seed2": DEFAULT_SEED2,
            "case_count": len(cases),
        },
        "source_hashes": {
            "runner": _sha256(Path(__file__)),
            "pilot_helper": _sha256(
                Path(__file__).with_name("run_d9_reconciliation_pilot.py")
            ),
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
    output_file = args.output / "boundary_suite.json"
    output_file.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(output_file),
        "success": not failures,
        "rows": len(rows),
        "failures": failures,
    }, indent=2))
    if failures:
        raise RuntimeError("boundary suite criteria failed")


if __name__ == "__main__":
    main()
