#!/usr/bin/env python3
"""One-boot frozen Decloaker ext4 comparison campaign."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from run_campaign import ACK
from run_d9_reconciliation_pilot import _loaded_modules, _sha256, _unload_known


PROTOCOL = "D9-decloaker-ext4-comparison-r1-2026-09-24"
STATES = ("unloaded", "filldir_pass", "filldir_active", "filldir_hiding")
VISIBLE = 512
HIDDEN = 16


def set_state(state: str, modules: dict[str, Path]) -> None:
    _unload_known()
    if state == "unloaded":
        return
    command = ["insmod", str(modules[state]), "counter_comm=decloaker-v0.0"]
    if state in {"filldir_active", "filldir_hiding"}:
        command.append("magic_word=d8_hidden_")
    subprocess.run(command, check=True)


def visible_count(fixture: Path) -> int:
    result = subprocess.run(
        ["ls", "-A1", str(fixture)],
        check=True,
        capture_output=True,
        text=True,
    )
    return len(result.stdout.splitlines())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--decloaker", required=True, type=Path)
    parser.add_argument("--device", default="/dev/sda2")
    parser.add_argument("--d7-pass-ko", required=True, type=Path)
    parser.add_argument("--d7-active-ko", required=True, type=Path)
    parser.add_argument("--d7-hiding-ko", required=True, type=Path)
    parser.add_argument("--boot-index", required=True, type=int)
    parser.add_argument("--boot-total", default=9, type=int)
    parser.add_argument("--scans", default=20, type=int)
    parser.add_argument("--seed", default=42091, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0 or "microsoft" in platform.release().lower():
        parser.error("requires root in the native isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if not 1 <= args.boot_index <= args.boot_total:
        parser.error("boot index outside boot total")
    if args.scans != 20 or args.boot_total != 9:
        parser.error("formal design requires 9 boots and 20 scans/state/boot")
    if args.output.exists():
        raise FileExistsError(args.output)
    if subprocess.run(
        ["ip", "route", "show", "default"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip():
        raise RuntimeError("default route present")
    if _loaded_modules():
        research = {
            name for name in _loaded_modules()
            if name.startswith("kicba_d7_") or name.startswith("kicba_d8_")
        }
        if research:
            raise RuntimeError(f"research module loaded at start: {research}")

    modules = {
        "filldir_pass": args.d7_pass_ko.resolve(),
        "filldir_active": args.d7_active_ko.resolve(),
        "filldir_hiding": args.d7_hiding_ko.resolve(),
    }
    for path in [args.decloaker.resolve(), *modules.values()]:
        if not path.is_file():
            raise FileNotFoundError(path)
    if not Path(args.device).exists():
        raise FileNotFoundError(args.device)

    args.output.mkdir(parents=True)
    temporary = Path(
        tempfile.mkdtemp(prefix="d9_decloaker_formal_", dir="/home/kicba")
    )
    fixture = temporary / "fixture"
    fixture.mkdir()
    for index in range(VISIBLE):
        (fixture / f"visible_{index:08d}").touch()
    for index in range(HIDDEN):
        (fixture / f"d8_hidden_{index:08d}").touch()
    subprocess.run(["sync"], check=True)

    shift = (args.boot_index - 1) % len(STATES)
    state_order = STATES[shift:] + STATES[:shift]
    rng = random.Random(args.seed ^ args.boot_index)
    rows = []
    failures = []
    try:
        for state in state_order:
            set_state(state, modules)
            observed = visible_count(fixture)
            expected = VISIBLE if state == "filldir_hiding" else VISIBLE + HIDDEN
            if observed != expected:
                failures.append(
                    f"{state}:treatment_count:{observed}:expected:{expected}"
                )
            order = list(range(args.scans))
            rng.shuffle(order)
            for position, scan_index in enumerate(order):
                command = [
                    str(args.decloaker.resolve()),
                    "--format=json",
                    "--log-level=detection",
                    "disk",
                    "ls",
                    f"--dev={args.device}",
                    "--compare",
                    str(fixture),
                ]
                started = time.perf_counter_ns()
                result = subprocess.run(
                    command, check=False, capture_output=True, text=True,
                    timeout=120,
                )
                elapsed_ns = time.perf_counter_ns() - started
                combined = result.stdout + "\n" + result.stderr
                detected = "HIDDEN" in combined.upper()
                error = result.returncode != 0
                if error:
                    failures.append(f"{state}:{scan_index}:returncode:{result.returncode}")
                rows.append({
                    "state": state,
                    "position": position,
                    "scan_index": scan_index,
                    "expected_positive": state == "filldir_hiding",
                    "detected": detected,
                    "returncode": result.returncode,
                    "elapsed_ns": elapsed_ns,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                })
            _unload_known()
    finally:
        _unload_known()
        shutil.rmtree(temporary, ignore_errors=True)

    record = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "kernel": platform.release(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "boot_index": args.boot_index,
            "boot_total": args.boot_total,
            "device": args.device,
            "filesystem": subprocess.run(
                ["findmnt", "-T", "/home", "-n", "-o", "FSTYPE"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
        },
        "parameters": {
            "visible": VISIBLE,
            "hidden": HIDDEN,
            "scans_per_state": args.scans,
            "state_order": list(state_order),
            "seed": args.seed,
        },
        "source_hashes": {
            "runner": _sha256(Path(__file__)),
            "decloaker_binary": _sha256(args.decloaker.resolve()),
            **{f"module_{name}": _sha256(path) for name, path in modules.items()},
        },
        "success": not failures,
        "failures": failures,
        "rows": rows,
    }
    payload = args.output / "campaign.json.gz"
    with gzip.open(payload, "wt", encoding="utf-8") as stream:
        json.dump(record, stream, separators=(",", ":"))
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    (args.output / "campaign.sha256").write_text(
        f"{digest}  {payload.name}\n", encoding="utf-8"
    )
    print(json.dumps({
        "output": str(payload),
        "success": not failures,
        "rows": len(rows),
        "failures": failures,
    }, indent=2))
    if failures:
        raise RuntimeError("Decloaker campaign criteria failed")


if __name__ == "__main__":
    main()
