#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import random
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from .run_campaign import (
        ACK,
        CONDITIONS,
        PRIMARY_TIMING_FUNCTIONS,
        _atomic_manifest,
        _boot_id,
        _module_loaded,
        _set_rootkit_state,
        _sha256,
    )
except ImportError:
    from run_campaign import (
        ACK,
        CONDITIONS,
        PRIMARY_TIMING_FUNCTIONS,
        _atomic_manifest,
        _boot_id,
        _module_loaded,
        _set_rootkit_state,
        _sha256,
    )


PROTOCOL_REVISION = "D3-r1-2026-09-18"


def _has_default_route() -> bool:
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        check=True,
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


def build_schedule(role: str, batches_per_cell: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    labels = ["normal"] if role == "calibration" else ["normal", "rootkit"]
    if role == "test":
        rng.shuffle(labels)
    schedule: list[dict] = []
    for episode, label in enumerate(labels):
        conditions = list(CONDITIONS)
        rng.shuffle(conditions)
        for condition_block, condition in enumerate(conditions):
            for repeat in range(batches_per_cell):
                schedule.append(
                    {
                        "position": len(schedule),
                        "episode": episode,
                        "label": label,
                        "condition": condition,
                        "condition_block": condition_block,
                        "repeat": repeat,
                        "status": "pending",
                        "output": None,
                    }
                )
    return schedule


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run one frozen KICBA D3 calibration or test campaign."
    )
    parser.add_argument("--role", choices=("calibration", "test"), required=True)
    parser.add_argument("--caraxes-ko", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--batches-per-cell", default=30, type=int)
    parser.add_argument("--iterations", default=100, type=int)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--cpu-workers", default=4, type=int)
    parser.add_argument("--memory", default="256M")
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.error("run as root inside the isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if "microsoft" in platform.release().lower():
        parser.error("WSL is excluded from the D3 evidence environment")
    if _has_default_route():
        raise RuntimeError("D3 collection refuses a VM with a default route")
    if args.batches_per_cell < 1 or args.iterations < 1:
        parser.error("batches-per-cell and iterations must be positive")
    if args.cpu_workers != 4 or args.memory != "256M":
        parser.error("D3-r1 primary workload is frozen at 4 CPU workers and 256M")
    module_path = args.caraxes_ko.resolve()
    if not module_path.is_file() or module_path.name != "caraxes.ko":
        parser.error("--caraxes-ko must resolve to the pinned caraxes.ko")
    output_root = args.output.resolve()
    if output_root.exists():
        raise FileExistsError(f"refusing to overwrite D3 output {output_root}")
    output_root.mkdir(parents=True)

    boot_id = _boot_id()
    campaign_id = f"d3_{args.role}_{boot_id}_{args.seed}_{uuid.uuid4().hex[:8]}"
    manifest_path = output_root / f"campaign_{campaign_id}.json"
    schedule = build_schedule(args.role, args.batches_per_cell, args.seed)
    manifest = {
        "schema_version": 3,
        "protocol_revision": PROTOCOL_REVISION,
        "study_role": args.role,
        "primary_timing_functions": list(PRIMARY_TIMING_FUNCTIONS),
        "campaign_id": campaign_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "boot_id": boot_id,
        "kernel": platform.release(),
        "machine": platform.machine(),
        "seed": args.seed,
        "batches_per_cell": args.batches_per_cell,
        "iterations_per_batch": args.iterations,
        "cpu_workers": args.cpu_workers,
        "memory": args.memory,
        "caraxes_sha256": _sha256(module_path),
        "schedule": schedule,
    }
    _atomic_manifest(manifest_path, manifest)
    collector = Path(__file__).with_name("collect_batch.py")

    try:
        _set_rootkit_state(False, module_path)
        for item in schedule:
            rootkit = item["label"] == "rootkit"
            _set_rootkit_state(rootkit, module_path)
            command = [
                sys.executable,
                str(collector),
                "--output",
                str(output_root),
                "--iterations",
                str(args.iterations),
                "--condition",
                item["condition"],
                "--label",
                item["label"],
                "--cpu-workers",
                str(args.cpu_workers),
                "--memory",
                args.memory,
                "--campaign-id",
                campaign_id,
                "--campaign-position",
                str(item["position"]),
                "--campaign-seed",
                str(args.seed),
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(
                    f"collector exit={result.returncode}; stdout={result.stdout!r}; "
                    f"stderr={result.stderr!r}"
                )
            output_lines = [line for line in result.stdout.splitlines() if line.strip()]
            if not output_lines:
                raise RuntimeError("collector returned no output path")
            batch_path = Path(output_lines[-1])
            with gzip.open(batch_path, "rt", encoding="utf-8") as handle:
                record = json.load(handle)
            if not record.get("quality", {}).get("valid_for_analysis", False):
                raise RuntimeError(f"collector marked batch invalid: {batch_path}")
            if record.get("environment", {}).get("boot_id") != boot_id:
                raise RuntimeError("boot ID changed during D3 campaign")
            collection = record.get("collection", {})
            if (
                collection.get("campaign_id") != campaign_id
                or int(collection.get("campaign_position", -1)) != item["position"]
                or int(collection.get("campaign_seed", -1)) != args.seed
            ):
                raise RuntimeError("collector campaign metadata mismatch")
            item["output"] = str(batch_path)
            item["status"] = "complete"
            item["completed_utc"] = datetime.now(timezone.utc).isoformat()
            _atomic_manifest(manifest_path, manifest)
    except BaseException as exc:
        manifest["failed_utc"] = datetime.now(timezone.utc).isoformat()
        manifest["failure"] = f"{type(exc).__name__}: {exc}"
        _atomic_manifest(manifest_path, manifest)
        raise
    finally:
        try:
            _set_rootkit_state(False, module_path)
        except Exception as cleanup_error:
            print(
                "CRITICAL: CARAXES cleanup failed; power off and restore checkpoint: "
                + str(cleanup_error),
                file=sys.stderr,
            )

    if _module_loaded():
        raise RuntimeError("CARAXES remained loaded after D3 campaign")
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    _atomic_manifest(manifest_path, manifest)
    print(manifest_path)


if __name__ == "__main__":
    main()
