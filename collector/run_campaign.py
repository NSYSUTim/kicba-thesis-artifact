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


ACK = "I_UNDERSTAND_THIS_LOADS_A_ROOTKIT_IN_AN_ISOLATED_VM"
CONDITIONS = ("baseline", "cpu", "memory", "mixed")
PROTOCOL_REVISION = "D2-r1-2026-09-14"
PRIMARY_TIMING_FUNCTIONS = ("iterate_dir", "filldir64", "touch_atime")


def _boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def _module_loaded() -> bool:
    modules = Path("/proc/modules").read_text().splitlines()
    return any(line.split()[0] == "caraxes" for line in modules if line)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_manifest(path: Path, manifest: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    temporary.replace(path)


def _set_rootkit_state(enabled: bool, module_path: Path) -> None:
    loaded = _module_loaded()
    if enabled and not loaded:
        subprocess.run(["insmod", str(module_path)], check=True)
    elif not enabled and loaded:
        subprocess.run(["rmmod", "caraxes"], check=True)
    if _module_loaded() != enabled:
        raise RuntimeError(f"Failed to set CARAXES loaded state to {enabled}")


def _schedule(rounds: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    schedule: list[dict] = []
    for block in range(rounds):
        labels = ["normal", "rootkit"]
        rng.shuffle(labels)
        for label in labels:
            conditions = list(CONDITIONS)
            rng.shuffle(conditions)
            for condition in conditions:
                schedule.append(
                    {
                        "position": len(schedule),
                        "block": block,
                        "label": label,
                        "condition": condition,
                        "status": "pending",
                        "output": None,
                    }
                )
    return schedule


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run one randomized D2 boot campaign inside a disposable native VM."
    )
    parser.add_argument("--caraxes-ko", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rounds", default=30, type=int)
    parser.add_argument("--iterations", default=100, type=int)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.error("run as root inside the isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if "microsoft" in platform.release().lower():
        parser.error("WSL is excluded from the D2 evidence environment")
    if args.rounds < 1 or args.iterations < 1:
        parser.error("--rounds and --iterations must be positive")
    module_path = args.caraxes_ko.resolve()
    if not module_path.is_file() or module_path.name != "caraxes.ko":
        parser.error("--caraxes-ko must resolve to the pinned caraxes.ko file")

    output_root = args.output.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    boot_id = _boot_id()
    campaign_id = f"{boot_id}_{args.seed}_{uuid.uuid4().hex[:8]}"
    manifest_path = output_root / f"campaign_{campaign_id}.json"
    manifest = {
        "schema_version": 2,
        "protocol_revision": PROTOCOL_REVISION,
        "primary_timing_functions": list(PRIMARY_TIMING_FUNCTIONS),
        "campaign_id": campaign_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "boot_id": boot_id,
        "kernel": platform.release(),
        "machine": platform.machine(),
        "seed": args.seed,
        "rounds": args.rounds,
        "iterations_per_batch": args.iterations,
        "caraxes_sha256": _sha256(module_path),
        "schedule": _schedule(args.rounds, args.seed),
    }
    _atomic_manifest(manifest_path, manifest)
    collector = Path(__file__).with_name("collect_batch.py")

    try:
        _set_rootkit_state(False, module_path)
        for item in manifest["schedule"]:
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
                    "Collector failed with exit code "
                    f"{result.returncode}; stdout={result.stdout!r}; "
                    f"stderr={result.stderr!r}"
                )
            output_lines = [line for line in result.stdout.splitlines() if line.strip()]
            if not output_lines:
                raise RuntimeError("Collector returned no output path")
            batch_path = Path(output_lines[-1])
            with gzip.open(batch_path, "rt", encoding="utf-8") as handle:
                batch_record = json.load(handle)
            if not batch_record.get("quality", {}).get("valid_for_analysis", False):
                raise RuntimeError(f"Collector marked batch invalid: {batch_path}")
            if batch_record.get("environment", {}).get("boot_id") != boot_id:
                raise RuntimeError("Boot ID changed during campaign")
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
                "CRITICAL: CARAXES cleanup failed; power off and restore the VM snapshot: "
                + str(cleanup_error),
                file=sys.stderr,
            )

    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    _atomic_manifest(manifest_path, manifest)
    print(manifest_path)


if __name__ == "__main__":
    main()
