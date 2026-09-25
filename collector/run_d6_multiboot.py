#!/usr/bin/env python3
"""Frozen five-boot D6 orchestrator."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from run_campaign import ACK
from run_d6_campaign import EXPECTED_BATCHES, PROTOCOL


SEEDS = (9601, 9602, 9603, 9604, 9605)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def _write(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--sham-ko", required=True, type=Path)
    parser.add_argument("--hiding-ko", required=True, type=Path)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.isolated_vm_ack != ACK:
        parser.error("root and isolated ack required")
    if subprocess.run(
        ["ip", "route", "show", "default"], capture_output=True,
        text=True, check=True,
    ).stdout.strip():
        raise RuntimeError("default route present")
    loaded = {
        line.split()[0] for line in Path("/proc/modules").read_text().splitlines()
        if line
    }
    if loaded & {"caraxes", "caraxes_sham"}:
        raise RuntimeError("module loaded at boot start")
    state = (
        json.loads(args.state.read_text()) if args.state.exists() else {
            "schema_version": 1,
            "protocol_revision": PROTOCOL,
            "created_utc": _now(),
            "total_boots": 5,
            "next_sequence": 1,
            "status": "ready",
            "completed_boots": [],
        }
    )
    if state.get("protocol_revision") != PROTOCOL:
        raise RuntimeError("state protocol mismatch")
    sequence = int(state["next_sequence"])
    if sequence > 5:
        state["status"] = "complete"
        state.setdefault("completed_utc", _now())
        _write(args.state, state)
        return
    boot_id = _boot_id()
    if boot_id in {item["boot_id"] for item in state["completed_boots"]}:
        raise RuntimeError("new boot required")
    output = args.output_root.resolve() / f"boot_{sequence:02d}"
    if output.exists():
        raise RuntimeError(f"refusing overwrite {output}")
    state.update(
        status="running",
        active_sequence=sequence,
        active_boot_id=boot_id,
        active_seed=SEEDS[sequence - 1],
        active_started_utc=_now(),
    )
    _write(args.state, state)
    command = [
        sys.executable,
        str(args.project_root.resolve() / "collector" / "run_d6_campaign.py"),
        "--sham-ko", str(args.sham_ko.resolve()),
        "--hiding-ko", str(args.hiding_ko.resolve()),
        "--output", str(output),
        "--seed", str(SEEDS[sequence - 1]),
        "--isolated-vm-ack", ACK,
    ]
    try:
        subprocess.run(command, check=True, cwd=args.project_root.resolve())
        manifests = list(output.glob("campaign_*.json"))
        manifest = (
            json.loads(manifests[0].read_text()) if len(manifests) == 1 else {}
        )
        done = sum(
            item.get("status") == "complete"
            for item in manifest.get("schedule", [])
        )
        if manifest.get("status") != "complete" or done != EXPECTED_BATCHES:
            raise RuntimeError(f"incomplete manifest {done}/{EXPECTED_BATCHES}")
    except BaseException as exc:
        state.update(
            status="failed",
            failed_utc=_now(),
            failure=f"{type(exc).__name__}: {exc}",
        )
        _write(args.state, state)
        raise
    state["completed_boots"].append({
        "sequence": sequence,
        "boot_id": boot_id,
        "seed": SEEDS[sequence - 1],
        "batches": EXPECTED_BATCHES,
        "manifest": str(manifests[0]),
        "completed_utc": _now(),
    })
    state["next_sequence"] = sequence + 1
    if sequence == 5:
        state.update(status="complete", completed_utc=_now())
        _write(args.state, state)
        return
    state["status"] = "rebooting"
    _write(args.state, state)
    subprocess.run(["sync"], check=True)
    subprocess.run(["systemctl", "reboot"], check=True)


if __name__ == "__main__":
    main()
