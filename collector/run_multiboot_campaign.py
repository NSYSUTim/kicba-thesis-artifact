#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ACK = "I_UNDERSTAND_THIS_LOADS_A_ROOTKIT_IN_AN_ISOLATED_VM"
SEEDS = (1001, 1002, 1003, 1004, 1005)


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


def _read_state(path: Path, total_boots: int) -> dict:
    if path.exists():
        state = json.loads(path.read_text(encoding="utf-8"))
        if int(state.get("total_boots", -1)) != total_boots:
            raise RuntimeError("Existing state uses a different total_boots value")
        return state
    return {
        "schema_version": 1,
        "protocol_revision": "D2-r1-2026-09-14",
        "created_utc": _utc_now(),
        "total_boots": total_boots,
        "next_boot_number": 1,
        "status": "ready",
        "completed_boots": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run one formal campaign per clean reboot and stop after all boots."
    )
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--caraxes-ko", required=True, type=Path)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--total-boots", default=5, type=int)
    parser.add_argument("--rounds", default=30, type=int)
    parser.add_argument("--iterations", default=100, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.error("run as root inside the isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if not 1 <= args.total_boots <= len(SEEDS):
        parser.error(f"--total-boots must be between 1 and {len(SEEDS)}")
    if _has_default_route():
        raise RuntimeError("Formal collection refuses a VM with a default route")
    if _module_loaded():
        raise RuntimeError("Formal collection refuses to start with CARAXES loaded")

    state_path = args.state.resolve()
    state = _read_state(state_path, args.total_boots)
    boot_number = int(state["next_boot_number"])
    if boot_number > args.total_boots:
        state["status"] = "complete"
        state.setdefault("completed_utc", _utc_now())
        _write_state(state_path, state)
        return

    boot_id = _boot_id()
    prior_boot_ids = {item["boot_id"] for item in state["completed_boots"]}
    if boot_id in prior_boot_ids:
        raise RuntimeError("A clean reboot is required before the next formal campaign")

    output_dir = args.output_root.resolve() / f"boot_{boot_number:02d}"
    if output_dir.exists():
        raise RuntimeError(f"Refusing to overwrite existing formal output {output_dir}")

    seed = SEEDS[boot_number - 1]
    state.update(
        {
            "status": "running",
            "active_boot_number": boot_number,
            "active_boot_id": boot_id,
            "active_seed": seed,
            "active_started_utc": _utc_now(),
        }
    )
    _write_state(state_path, state)

    runner = args.project_root.resolve() / "collector" / "run_campaign.py"
    command = [
        sys.executable,
        str(runner),
        "--caraxes-ko",
        str(args.caraxes_ko.resolve()),
        "--output",
        str(output_dir),
        "--rounds",
        str(args.rounds),
        "--iterations",
        str(args.iterations),
        "--seed",
        str(seed),
        "--isolated-vm-ack",
        ACK,
    ]
    try:
        subprocess.run(command, check=True, cwd=args.project_root.resolve())
        manifests = list(output_dir.glob("campaign_*.json"))
        if len(manifests) != 1:
            raise RuntimeError("Formal boot did not produce exactly one campaign manifest")
        manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
        expected_batches = args.rounds * 8
        completed_batches = sum(
            item.get("status") == "complete" for item in manifest["schedule"]
        )
        if (
            manifest.get("failure")
            or not manifest.get("completed_utc")
            or completed_batches != expected_batches
        ):
            raise RuntimeError(
                f"Formal manifest is incomplete: {completed_batches}/{expected_batches}"
            )
    except BaseException as exc:
        state["status"] = "failed"
        state["failed_utc"] = _utc_now()
        state["failure"] = f"{type(exc).__name__}: {exc}"
        _write_state(state_path, state)
        raise

    state["completed_boots"].append(
        {
            "boot_number": boot_number,
            "boot_id": boot_id,
            "seed": seed,
            "batches": expected_batches,
            "manifest": str(manifests[0]),
            "completed_utc": _utc_now(),
        }
    )
    state["next_boot_number"] = boot_number + 1
    state.pop("failure", None)
    state.pop("failed_utc", None)
    if boot_number == args.total_boots:
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
