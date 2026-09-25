#!/usr/bin/env python3
"""Randomized one-boot D7 mechanism qualification.

This is development/qualification evidence, not confirmatory detector data.
It verifies output semantics and callback-path equivalence for unloaded,
matched-pass, active-logic, and hiding states under all four workloads.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import random
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from collect_d4_batch import _directory_names, _sha256_lines
from run_campaign import ACK, _atomic_manifest, _boot_id


PROTOCOL = "D7-mechanism-r2-2026-09-21"
STATES = ("unloaded", "pass", "active", "hiding")
CONDITIONS = ("baseline", "cpu", "memory", "mixed")
REPLICATES = 3
ITERATIONS = 20
CARDINALITY = 128
FILENAME_LENGTH = 32
EXPECTED_BATCHES = len(STATES) * len(CONDITIONS) * REPLICATES
MODULE_BY_STATE = {
    "pass": "kicba_d7_pass",
    "active": "kicba_d7_active",
    "hiding": "kicba_d7_hiding",
}


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


def build_schedule(seed: int) -> list[dict]:
    schedule = [
        {
            "state": state,
            "condition": condition,
            "replicate": replicate,
            "status": "pending",
            "output": None,
        }
        for state in STATES
        for condition in CONDITIONS
        for replicate in range(REPLICATES)
    ]
    random.Random(seed).shuffle(schedule)
    for position, item in enumerate(schedule):
        item["position"] = position
    return schedule


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pass-ko", required=True, type=Path)
    parser.add_argument("--active-ko", required=True, type=Path)
    parser.add_argument("--hiding-ko", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed", default=10701, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or "microsoft" in platform.release().lower():
        parser.error("requires root in the native isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if subprocess.run(
        ["ip", "route", "show", "default"], capture_output=True,
        text=True, check=True,
    ).stdout.strip():
        raise RuntimeError("default route present")

    modules = {
        "pass": args.pass_ko.resolve(),
        "active": args.active_ko.resolve(),
        "hiding": args.hiding_ko.resolve(),
    }
    if _loaded_modules() & (set(MODULE_BY_STATE.values()) | {"caraxes", "caraxes_sham"}):
        raise RuntimeError("D7/CARAXES module loaded at qualification start")
    output = args.output.resolve()
    fixture = output.parent / f"{output.name}_fixture"
    if output.exists() or fixture.exists():
        raise FileExistsError("refusing to overwrite qualification output/fixture")
    output.mkdir(parents=True)
    fixture.mkdir()
    visible, hidden, creation, slot = _directory_names(
        CARDINALITY, FILENAME_LENGTH, "middle"
    )
    for name in creation:
        (fixture / name).touch()
    fixture_stat = fixture.stat()
    boot_id = _boot_id()
    campaign_id = f"d7mech_{boot_id}_{args.seed}_{uuid.uuid4().hex[:8]}"
    schedule = build_schedule(args.seed)
    collector = Path(__file__).with_name("collect_d7_mechanism_batch_r2.py")
    base_collector = Path(__file__).with_name("collect_d4_aggregate_batch.py")
    bpf_source = Path(__file__).with_name("bpf_d4_aggregate.c")
    manifest = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "evidence_role": "mechanism_qualification_not_confirmatory",
        "status": "running",
        "campaign_id": campaign_id,
        "boot_id": boot_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "iterations": ITERATIONS,
        "expected_batches": EXPECTED_BATCHES,
        "states": list(STATES),
        "conditions": list(CONDITIONS),
        "replicates_per_cell": REPLICATES,
        "fixture": str(fixture),
        "fixture_device": fixture_stat.st_dev,
        "fixture_inode": fixture_stat.st_ino,
        "fixture_creation_order_sha256": _sha256_lines(
            creation, sorted_lines=False
        ),
        "fixture_hidden_creation_index": slot,
        "hidden_name": hidden,
        "cardinality": CARDINALITY,
        "filename_length": FILENAME_LENGTH,
        "module_sha256": {
            state: _sha256(path) for state, path in modules.items()
        },
        "collector_sha256": _sha256(collector),
        "base_collector_sha256": _sha256(base_collector),
        "bpf_source_sha256": _sha256(bpf_source),
        "runner_sha256": _sha256(Path(__file__)),
        "schedule": schedule,
    }
    manifest_path = output / f"campaign_{campaign_id}.json"
    _atomic_manifest(manifest_path, manifest)
    try:
        for item in schedule:
            _set_state(item["state"], modules)
            command = [
                sys.executable, str(collector),
                "--output", str(output),
                "--fixture-dir", str(fixture),
                "--iterations", str(ITERATIONS),
                "--label", "rootkit" if item["state"] == "hiding" else "normal",
                "--condition", item["condition"],
                "--probe-profile", "role_aggregate",
                "--poll-policy", "none",
                "--directory-cardinality", str(CARDINALITY),
                "--filename-length", str(FILENAME_LENGTH),
                "--hidden-slot", "middle",
                "--campaign-id", campaign_id,
                "--campaign-position", str(item["position"]),
                "--campaign-phase", "qualification:" + item["state"],
                "--campaign-seed", str(args.seed),
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(
                    f"collector exit={result.returncode}: {result.stderr!r}"
                )
            path = Path(result.stdout.strip().splitlines()[-1])
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                record = json.load(handle)
            if (
                record.get("protocol_revision") != PROTOCOL
                or record["d7_control"]["state"] != item["state"]
                or not record["quality"]["valid_for_analysis"]
                or record["environment"]["boot_id"] != boot_id
                or record["directory_factor"]["fixture_inode"] != fixture_stat.st_ino
            ):
                raise RuntimeError(f"invalid D7 qualification batch: {path}")
            item["status"] = "complete"
            item["output"] = str(path)
            item["completed_utc"] = datetime.now(timezone.utc).isoformat()
            _atomic_manifest(manifest_path, manifest)
    except BaseException as exc:
        manifest["status"] = "failed"
        manifest["failure"] = f"{type(exc).__name__}: {exc}"
        manifest["failed_utc"] = datetime.now(timezone.utc).isoformat()
        _atomic_manifest(manifest_path, manifest)
        raise
    finally:
        _set_state("unloaded", modules)
    manifest["status"] = "complete"
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    _atomic_manifest(manifest_path, manifest)
    print(manifest_path)


if __name__ == "__main__":
    main()
