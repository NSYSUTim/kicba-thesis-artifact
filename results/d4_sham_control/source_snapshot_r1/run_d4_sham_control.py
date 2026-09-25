#!/usr/bin/env python3
"""Three-state D4 control: unloaded, pass-through ftrace, actual hiding."""

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

try:
    from .run_campaign import ACK, _atomic_manifest, _boot_id
except ImportError:
    from run_campaign import ACK, _atomic_manifest, _boot_id


PROTOCOL_REVISION = "D4-sham-control-r1-2026-09-19"
STATES = ("unloaded", "sham", "hiding")
CARDINALITIES = (8, 128, 1024)
LENGTHS = (32, 160)
CONDITIONS = ("baseline", "cpu")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _loaded_modules() -> set[str]:
    return {
        line.split()[0]
        for line in Path("/proc/modules").read_text().splitlines()
        if line
    }


def _set_state(state: str, sham_ko: Path, hiding_ko: Path) -> None:
    for module in ("caraxes_sham", "caraxes"):
        if module in _loaded_modules():
            subprocess.run(["rmmod", module], check=True)
    if state == "sham":
        subprocess.run(["insmod", str(sham_ko)], check=True)
    elif state == "hiding":
        subprocess.run(["insmod", str(hiding_ko)], check=True)
    elif state != "unloaded":
        raise ValueError(state)
    expected = {
        "unloaded": set(),
        "sham": {"caraxes_sham"},
        "hiding": {"caraxes"},
    }[state]
    if _loaded_modules() & {"caraxes", "caraxes_sham"} != expected:
        raise RuntimeError(f"failed to enter {state!r} module state")


def build_schedule(seed: int) -> list[dict]:
    schedule = [
        {
            "state": state,
            "condition": condition,
            "directory_cardinality": cardinality,
            "filename_length": filename_length,
            "hidden_slot": "middle",
            "status": "pending",
            "output": None,
        }
        for cardinality in CARDINALITIES
        for filename_length in LENGTHS
        for condition in CONDITIONS
        for state in STATES
    ]
    random.Random(seed).shuffle(schedule)
    for position, item in enumerate(schedule):
        item["position"] = position
    return schedule


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sham-ko", required=True, type=Path)
    parser.add_argument("--hiding-ko", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--iterations", default=20, type=int)
    parser.add_argument("--seed", default=7401, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root inside the isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if "microsoft" in platform.release().lower():
        parser.error("WSL is excluded from D4 evidence collection")
    if subprocess.run(
        ["ip", "route", "show", "default"],
        check=True, capture_output=True, text=True,
    ).stdout.strip():
        raise RuntimeError("D4 control refuses a VM with a default route")
    if _loaded_modules() & {"caraxes", "caraxes_sham"}:
        raise RuntimeError("D4 control refuses to start with a module loaded")
    if args.iterations < 1:
        parser.error("iterations must be positive")

    sham_ko = args.sham_ko.resolve()
    hiding_ko = args.hiding_ko.resolve()
    collector = Path(__file__).with_name("collect_d4_batch.py")
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    for module in (sham_ko, hiding_ko):
        if not module.is_file():
            raise FileNotFoundError(module)
    output.mkdir(parents=True)

    boot_id = _boot_id()
    campaign_id = f"d4sham_{boot_id}_{args.seed}_{uuid.uuid4().hex[:8]}"
    schedule = build_schedule(args.seed)
    manifest_path = output / f"campaign_{campaign_id}.json"
    manifest = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL_REVISION,
        "status": "running",
        "campaign_id": campaign_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "boot_id": boot_id,
        "kernel": platform.release(),
        "seed": args.seed,
        "iterations": args.iterations,
        "probe_profile": "security",
        "sham_sha256": _sha256(sham_ko),
        "hiding_sha256": _sha256(hiding_ko),
        "collector_sha256": _sha256(collector),
        "runner_sha256": _sha256(Path(__file__)),
        "schedule": schedule,
    }
    _atomic_manifest(manifest_path, manifest)
    try:
        for item in schedule:
            state = item["state"]
            _set_state(state, sham_ko, hiding_ko)
            label = "rootkit" if state == "hiding" else "normal"
            command = [
                sys.executable, str(collector),
                "--output", str(output),
                "--iterations", str(args.iterations),
                "--condition", item["condition"],
                "--label", label,
                "--cpu-workers", "4",
                "--memory", "256M",
                "--probe-profile", "security",
                "--directory-cardinality", str(item["directory_cardinality"]),
                "--filename-length", str(item["filename_length"]),
                "--hidden-slot", item["hidden_slot"],
                "--campaign-id", campaign_id,
                "--campaign-position", str(item["position"]),
                "--campaign-phase", state,
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
                raise RuntimeError(f"invalid three-state batch: {batch_path}")
            if record["environment"]["boot_id"] != boot_id:
                raise RuntimeError("boot ID changed during three-state control")
            if record["collection"]["campaign_phase"] != state:
                raise RuntimeError("state metadata mismatch")
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
        _set_state("unloaded", sham_ko, hiding_ko)

    manifest["status"] = "complete"
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    _atomic_manifest(manifest_path, manifest)
    print(manifest_path)


if __name__ == "__main__":
    main()
