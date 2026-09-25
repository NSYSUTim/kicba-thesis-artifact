#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from .run_campaign import ACK
except ImportError:
    from run_campaign import ACK


CALIBRATION_SEED = 6001
TEST_SEEDS = (6101, 6201, 6301, 6401, 6501)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def _module_loaded() -> bool:
    return any(
        line.split()[0] == "caraxes"
        for line in Path("/proc/modules").read_text().splitlines()
        if line
    )


def _has_default_route() -> bool:
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        check=True,
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


def _write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temporary.replace(path)


def _read_state(path: Path) -> dict:
    if path.exists():
        state = json.loads(path.read_text(encoding="utf-8"))
        if state.get("protocol_revision") != "D3-r1-2026-09-18":
            raise RuntimeError("existing state has a different D3 protocol")
        return state
    return {
        "schema_version": 1,
        "protocol_revision": "D3-r1-2026-09-18",
        "created_utc": _utc_now(),
        "total_boots": 6,
        "next_sequence": 1,
        "status": "ready",
        "completed_boots": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the frozen six-boot KICBA D3 collection."
    )
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--caraxes-ko", required=True, type=Path)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--batches-per-cell", default=30, type=int)
    parser.add_argument("--iterations", default=100, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root inside the isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if args.batches_per_cell != 30 or args.iterations != 100:
        parser.error("D3-r1 is frozen at 30 batches per cell and 100 iterations")
    if _has_default_route():
        raise RuntimeError("D3 collection refuses a VM with a default route")
    if _module_loaded():
        raise RuntimeError("D3 collection refuses to start with CARAXES loaded")

    state_path = args.state.resolve()
    state = _read_state(state_path)
    sequence = int(state["next_sequence"])
    if sequence > 6:
        state["status"] = "complete"
        state.setdefault("completed_utc", _utc_now())
        _write_state(state_path, state)
        return

    boot_id = _boot_id()
    prior_boot_ids = {item["boot_id"] for item in state["completed_boots"]}
    if boot_id in prior_boot_ids:
        raise RuntimeError("a clean reboot is required before the next D3 campaign")
    if sequence == 1:
        role = "calibration"
        seed = CALIBRATION_SEED
        output_dir = args.output_root.resolve() / "calibration"
        expected_batches = 120
    else:
        role = "test"
        seed = TEST_SEEDS[sequence - 2]
        output_dir = args.output_root.resolve() / "test" / f"boot_{sequence - 1:02d}"
        expected_batches = 240
    if output_dir.exists():
        raise RuntimeError(f"refusing to overwrite {output_dir}")

    state.update(
        {
            "status": "running",
            "active_sequence": sequence,
            "active_role": role,
            "active_boot_id": boot_id,
            "active_seed": seed,
            "active_started_utc": _utc_now(),
        }
    )
    _write_state(state_path, state)
    runner = args.project_root.resolve() / "collector" / "run_d3_campaign.py"
    command = [
        sys.executable,
        str(runner),
        "--role",
        role,
        "--caraxes-ko",
        str(args.caraxes_ko.resolve()),
        "--output",
        str(output_dir),
        "--batches-per-cell",
        str(args.batches_per_cell),
        "--iterations",
        str(args.iterations),
        "--seed",
        str(seed),
        "--cpu-workers",
        "4",
        "--memory",
        "256M",
        "--isolated-vm-ack",
        ACK,
    ]
    try:
        subprocess.run(command, check=True, cwd=args.project_root.resolve())
        manifests = list(output_dir.glob("campaign_*.json"))
        if len(manifests) != 1:
            raise RuntimeError("D3 campaign did not produce exactly one manifest")
        manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
        completed = sum(
            item.get("status") == "complete" for item in manifest["schedule"]
        )
        if (
            manifest.get("failure")
            or not manifest.get("completed_utc")
            or completed != expected_batches
        ):
            raise RuntimeError(f"incomplete D3 manifest: {completed}/{expected_batches}")
    except BaseException as exc:
        state["status"] = "failed"
        state["failed_utc"] = _utc_now()
        state["failure"] = f"{type(exc).__name__}: {exc}"
        _write_state(state_path, state)
        raise

    state["completed_boots"].append(
        {
            "sequence": sequence,
            "role": role,
            "boot_id": boot_id,
            "seed": seed,
            "batches": expected_batches,
            "manifest": str(manifests[0]),
            "completed_utc": _utc_now(),
        }
    )
    state["next_sequence"] = sequence + 1
    state.pop("failure", None)
    state.pop("failed_utc", None)
    if sequence == 6:
        state["status"] = "complete"
        state["completed_utc"] = _utc_now()
        _write_state(state_path, state)
        return
    state["status"] = "rebooting"
    _write_state(state_path, state)
    subprocess.run(["sync"], check=True)
    subprocess.run(["systemctl", "reboot"], check=True)


if __name__ == "__main__":
    main()
