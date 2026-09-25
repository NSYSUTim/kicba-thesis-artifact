#!/usr/bin/env python3
"""Collect D9 on the four getdents64-compatible Trace scenarios."""

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
import string
import subprocess
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from kicba.reconciliation import token_for_entry
from run_campaign import ACK
from run_d9_reconciliation_pilot import _loaded_modules, _sha256, _unload_known
from run_d9_reconciliation_smoke import _set_array, collect_once


PROTOCOL = "D9-external-four-scenario-matrix-r1-2026-09-24"
SCENARIOS = ("default", "file_count", "system_load", "filename_length")
LABEL_COUNTS = (("normal", 150), ("rootkit", 100))
ITERATIONS = 100
BUFFER_SIZE = 65536
CELL_COUNT = 256
MAGIC = "caraxes"


def stable_rng(seed: int, scenario: str, label: str, index: int) -> random.Random:
    digest = hashlib.sha256(
        f"{seed}:{scenario}:{label}:{index}".encode("utf-8")
    ).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def scenario_parameters(
    seed: int, scenario: str, label: str, index: int
) -> dict[str, int | bool]:
    rng = stable_rng(seed, scenario, label, index)
    value: dict[str, int | bool] = {
        "visible_files": 1,
        "hidden_files": 1,
        "file_name_length": 8,
        "system_load": scenario == "system_load",
    }
    if scenario == "file_count":
        value["visible_files"] = rng.randint(10, 100)
        value["hidden_files"] = rng.randint(10, 100)
    elif scenario == "filename_length":
        value["file_name_length"] = rng.randint(20, 60)
    return value


def unique_name(rng: random.Random, length: int, used: set[str]) -> str:
    alphabet = string.ascii_uppercase + string.digits
    while True:
        name = "".join(rng.choices(alphabet, k=length))
        if name not in used:
            used.add(name)
            return name


def build_fixture(
    parent: Path,
    seed: int,
    scenario: str,
    label: str,
    index: int,
    parameters: dict[str, int | bool],
) -> tuple[Path, list[Path]]:
    fixture = parent / "fixture"
    fixture.mkdir()
    rng = stable_rng(seed ^ 0xD9, scenario, label, index)
    used: set[str] = set()
    length = int(parameters["file_name_length"])
    for _ in range(int(parameters["visible_files"])):
        (fixture / unique_name(rng, length, used)).touch()
    hidden_paths = []
    for _ in range(int(parameters["hidden_files"])):
        base = unique_name(rng, length, used)
        insertion = rng.randint(0, length)
        name = base[:insertion] + f"_{MAGIC}_" + base[insertion:]
        if name in used:
            raise RuntimeError("generated hidden-name collision")
        used.add(name)
        path = fixture / name
        path.touch()
        hidden_paths.append(path)
    return fixture, hidden_paths


@contextmanager
def background_load(enabled: bool):
    process = None
    if enabled:
        process = subprocess.Popen(
            ["stress-ng", "--cpu", "10"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)
    try:
        yield
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def set_treatment(label: str, module: Path) -> None:
    _unload_known()
    if label == "normal":
        return
    subprocess.run(
        [
            "insmod",
            str(module),
            f"magic_word={MAGIC}",
            "counter_comm=d9_enum_probe",
        ],
        check=True,
    )


def expected_tokens(paths: list[Path], seed1: int, seed2: int) -> list[list[int]]:
    result = []
    for path in paths:
        stat = path.stat()
        token = token_for_entry(path.name, stat.st_ino, 8, seed1, seed2)
        result.append([token.key_hash, token.inode, token.d_type])
    return sorted(result)


def compact_transaction(result: dict, expected: list[list[int]]) -> dict:
    decoded = sorted(result["upstream_only"])
    exact = (
        result["decode_success"]
        and decoded == expected
        and not result["downstream_only"]
    )
    return {
        "measurement_valid": result["measurement_valid"],
        "difference_detected": not result["fingerprint_equal"],
        "decode_success": result["decode_success"],
        "decoded_exact": exact,
        "upstream_only_count": len(result["upstream_only"]),
        "downstream_only_count": len(result["downstream_only"]),
        "residual_cells": result["residual_cells"],
        "kernel_fingerprint": result["kernel_fingerprint"],
        "visible_fingerprint": result["visible_fingerprint"],
        "kernel_stats": result["kernel_stats"],
        "userspace": result["userspace"],
    }


def inventory(output: Path) -> dict[tuple[str, str], list[Path]]:
    result: dict[tuple[str, str], list[Path]] = {}
    for path in sorted(output.glob("batch_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            value = json.load(stream)
        result.setdefault((value["scenario"], value["label"]), []).append(path)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--hiding-ko", required=True, type=Path)
    parser.add_argument("--seed", default=42, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0 or "microsoft" in platform.release().lower():
        parser.error("requires root in the native isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if subprocess.run(
        ["ip", "route", "show", "default"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip():
        raise RuntimeError("default route present")
    if not args.probe.is_file() or not args.hiding_ko.is_file():
        raise FileNotFoundError("probe or hiding module missing")
    if _loaded_modules() & {"kicba_d7_hiding"}:
        raise RuntimeError("hiding module loaded at matrix start")

    args.output.mkdir(parents=True, exist_ok=True)
    existing = inventory(args.output)
    source = Path(__file__).with_name("bpf_d9_reconciliation.c")
    rng = random.Random(args.seed ^ 0xD9D9)
    seed1 = rng.getrandbits(64) or 1
    seed2 = rng.getrandbits(64) or 2
    bpf = BPF(src_file=str(source), cflags=[f"-I{source.parent.resolve()}"])
    bpf.attach_kprobe(event="filldir64", fn_name="d9_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="d9_filldir64_return", maxactive=256
    )
    _set_array(bpf["hash_seeds"], 0, ct.c_ulonglong(seed1))
    _set_array(bpf["hash_seeds"], 1, ct.c_ulonglong(seed2))
    _set_array(bpf["iblt_cell_count"], 0, ct.c_uint(CELL_COUNT))
    _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(1))
    try:
        for scenario in SCENARIOS:
            for label, target in LABEL_COUNTS:
                have = len(existing.get((scenario, label), []))
                if have > target:
                    raise RuntimeError(f"too many batches for {scenario}/{label}")
                for index in range(have, target):
                    parameters = scenario_parameters(
                        args.seed, scenario, label, index
                    )
                    temporary = Path(
                        tempfile.mkdtemp(prefix="d9_external_", dir="/home/kicba")
                    )
                    try:
                        fixture, hidden_paths = build_fixture(
                            temporary,
                            args.seed,
                            scenario,
                            label,
                            index,
                            parameters,
                        )
                        expected = (
                            expected_tokens(hidden_paths, seed1, seed2)
                            if label == "rootkit"
                            else []
                        )
                        set_treatment(label, args.hiding_ko.resolve())
                        started = time.monotonic()
                        transactions = []
                        with background_load(bool(parameters["system_load"])):
                            for _ in range(ITERATIONS):
                                result = collect_once(
                                    bpf,
                                    args.probe.resolve(),
                                    fixture,
                                    BUFFER_SIZE,
                                    CELL_COUNT,
                                    seed1,
                                    seed2,
                                )
                                transactions.append(
                                    compact_transaction(result, expected)
                                )
                        elapsed = time.monotonic() - started
                    finally:
                        _unload_known()
                        shutil.rmtree(temporary, ignore_errors=True)

                    valid = all(
                        row["measurement_valid"]
                        and row["decoded_exact"]
                        and row["difference_detected"] == (label == "rootkit")
                        for row in transactions
                    )
                    record = {
                        "schema_version": 1,
                        "protocol_revision": PROTOCOL,
                        "created_utc": datetime.now(timezone.utc).isoformat(),
                        "scenario": scenario,
                        "label": label,
                        "index": index,
                        "parameters": parameters,
                        "iterations": ITERATIONS,
                        "buffer_size": BUFFER_SIZE,
                        "cell_count": CELL_COUNT,
                        "hash_seed1": seed1,
                        "hash_seed2": seed2,
                        "expected_difference_count": len(expected),
                        "batch_detected": any(
                            row["difference_detected"] for row in transactions
                        ),
                        "valid": valid,
                        "elapsed_seconds": elapsed,
                        "environment": {
                            "kernel": platform.release(),
                            "boot_id": Path(
                                "/proc/sys/kernel/random/boot_id"
                            ).read_text().strip(),
                        },
                        "source_hashes": {
                            "runner": _sha256(Path(__file__)),
                            "bpf": _sha256(source),
                            "probe": _sha256(args.probe.resolve()),
                            "hiding_module": _sha256(args.hiding_ko.resolve()),
                        },
                        "transactions": transactions,
                    }
                    filename = (
                        f"batch_{scenario}_{label}_{index:03d}.json.gz"
                    )
                    path = args.output / filename
                    with gzip.open(path, "wt", encoding="utf-8") as stream:
                        json.dump(record, stream, separators=(",", ":"))
                    summary = {
                        "scenario": scenario,
                        "label": label,
                        "index": index,
                        "file": filename,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "valid": valid,
                        "elapsed_seconds": elapsed,
                    }
                    with (args.output / "collection.jsonl").open(
                        "a", encoding="utf-8"
                    ) as stream:
                        stream.write(json.dumps(summary) + "\n")
                    print(json.dumps(summary), flush=True)
                    if not valid:
                        raise RuntimeError(f"invalid D9 batch: {summary}")
    finally:
        _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(0))
        _unload_known()
        bpf.cleanup()

    final = inventory(args.output)
    counts = {
        f"{scenario}/{label}": len(final.get((scenario, label), []))
        for scenario in SCENARIOS
        for label, _ in LABEL_COUNTS
    }
    print(json.dumps({"event": "complete", "counts": counts}, indent=2))


if __name__ == "__main__":
    main()
