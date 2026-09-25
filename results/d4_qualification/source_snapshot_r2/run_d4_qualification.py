#!/usr/bin/env python3
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

from run_campaign import ACK, _atomic_manifest, _boot_id, _module_loaded, _set_rootkit_state


PROTOCOL_REVISION = "D4-Q1-r1-2026-09-19"
CARDINALITIES = (8, 128, 1024)
FILENAME_LENGTHS = (32, 160)
HIDDEN_SLOTS = ("early", "middle", "late")
CONDITIONS = ("baseline", "cpu")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _has_default_route() -> bool:
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        check=True,
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


def build_schedule(repeats: int, seed: int) -> list[dict]:
    schedule: list[dict] = []
    for repeat in range(repeats):
        for cardinality in CARDINALITIES:
            for filename_length in FILENAME_LENGTHS:
                for hidden_slot in HIDDEN_SLOTS:
                    for condition in CONDITIONS:
                        for label in ("normal", "rootkit"):
                            schedule.append(
                                {
                                    "repeat": repeat,
                                    "label": label,
                                    "condition": condition,
                                    "directory_cardinality": cardinality,
                                    "filename_length": filename_length,
                                    "hidden_slot": hidden_slot,
                                    "status": "pending",
                                    "output": None,
                                }
                            )
    random.Random(seed).shuffle(schedule)
    for position, item in enumerate(schedule):
        item["position"] = position
    return schedule


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--caraxes-ko", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repeats", default=2, type=int)
    parser.add_argument("--iterations", default=20, type=int)
    parser.add_argument("--seed", default=7301, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root inside the isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if "microsoft" in platform.release().lower():
        parser.error("WSL is excluded from D4 evidence collection")
    if _has_default_route():
        raise RuntimeError("D4 refuses a VM with a default route")
    if _module_loaded():
        raise RuntimeError("D4 refuses to start with CARAXES loaded")
    if args.repeats < 1 or args.iterations < 1:
        parser.error("repeats and iterations must be positive")

    module_path = args.caraxes_ko.resolve()
    output = args.output.resolve()
    if not module_path.is_file() or module_path.name != "caraxes.ko":
        parser.error("--caraxes-ko must resolve to caraxes.ko")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    output.mkdir(parents=True)

    boot_id = _boot_id()
    campaign_id = f"d4q_{boot_id}_{args.seed}_{uuid.uuid4().hex[:8]}"
    schedule = build_schedule(args.repeats, args.seed)
    manifest_path = output / f"campaign_{campaign_id}.json"
    collector = Path(__file__).with_name("collect_d4_batch.py")
    manifest = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL_REVISION,
        "status": "running",
        "campaign_id": campaign_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "boot_id": boot_id,
        "kernel": platform.release(),
        "seed": args.seed,
        "repeats": args.repeats,
        "iterations": args.iterations,
        "probe_profile": "security",
        "cpu_workers": 4,
        "memory": "256M",
        "caraxes_sha256": _sha256(module_path),
        "collector_sha256": _sha256(collector),
        "schedule": schedule,
    }
    _atomic_manifest(manifest_path, manifest)
    try:
        for item in schedule:
            _set_rootkit_state(item["label"] == "rootkit", module_path)
            command = [
                sys.executable,
                str(collector),
                "--output", str(output),
                "--iterations", str(args.iterations),
                "--condition", item["condition"],
                "--label", item["label"],
                "--cpu-workers", "4",
                "--memory", "256M",
                "--probe-profile", "security",
                "--directory-cardinality", str(item["directory_cardinality"]),
                "--filename-length", str(item["filename_length"]),
                "--hidden-slot", item["hidden_slot"],
                "--campaign-id", campaign_id,
                "--campaign-position", str(item["position"]),
                "--campaign-phase", "qualification",
                "--campaign-seed", str(args.seed),
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(
                    f"collector exit={result.returncode}; stdout={result.stdout!r}; "
                    f"stderr={result.stderr!r}"
                )
            paths = [line for line in result.stdout.splitlines() if line.strip()]
            if not paths:
                raise RuntimeError("collector returned no output path")
            batch_path = Path(paths[-1])
            with gzip.open(batch_path, "rt", encoding="utf-8") as handle:
                record = json.load(handle)
            if not record["quality"]["valid_for_analysis"]:
                raise RuntimeError(f"invalid D4 qualification batch: {batch_path}")
            if record["environment"]["boot_id"] != boot_id:
                raise RuntimeError("boot ID changed during qualification")
            item["status"] = "complete"
            item["output"] = str(batch_path)
            item["completed_utc"] = datetime.now(timezone.utc).isoformat()
            _atomic_manifest(manifest_path, manifest)
    except BaseException as exc:
        manifest["status"] = "failed"
        manifest["failure"] = f"{type(exc).__name__}: {exc}"
        manifest["failed_utc"] = datetime.now(timezone.utc).isoformat()
        _atomic_manifest(manifest_path, manifest)
        raise
    finally:
        _set_rootkit_state(False, module_path)

    manifest["status"] = "complete"
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    _atomic_manifest(manifest_path, manifest)
    print(manifest_path)


if __name__ == "__main__":
    main()
