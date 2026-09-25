#!/usr/bin/env python3
"""Create the immutable D9 formal-analysis/source manifest."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


PROTOCOL = "D9-reconciliation-campaign-r1-2026-09-24"
LOCAL_RUNTIME_FILES = {
    "runner": Path("collector/run_d9_campaign.py"),
    "smoke_helper": Path("collector/run_d9_reconciliation_smoke.py"),
    "boundary_helper": Path("collector/run_d9_boundary_suite.py"),
    "bpf": Path("collector/bpf_d9_reconciliation.c"),
    "hash_header": Path("collector/d9_reconciliation_hash.h"),
}
LOCKED_FILES = {
    "campaign_runner": Path("collector/run_d9_campaign.py"),
    "smoke_helper": Path("collector/run_d9_reconciliation_smoke.py"),
    "boundary_helper": Path("collector/run_d9_boundary_suite.py"),
    "bpf": Path("collector/bpf_d9_reconciliation.c"),
    "hash_header": Path("collector/d9_reconciliation_hash.h"),
    "fit_timing": Path("scripts/fit_d9_timing_baseline.py"),
    "analysis_core": Path("scripts/analyze_d9_formal.py"),
    "multiboot_runner": Path("scripts/run_d9_multiboot.py"),
    "protocol": Path("docs/D9_RECONCILIATION_RESEARCH_PROTOCOL_zh-TW.md"),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calibration", required=True, type=Path)
    parser.add_argument("--timing-model", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    with gzip.open(args.calibration, "rt", encoding="utf-8") as stream:
        calibration = json.load(stream)
    timing = json.loads(args.timing_model.read_text(encoding="utf-8"))
    if (
        calibration.get("protocol_revision") != PROTOCOL
        or calibration.get("role") != "calibration"
        or not calibration.get("success")
        or calibration.get("parameters", {}).get("repeats_per_cell") != 3
        or calibration.get("parameters", {}).get("iterations_per_batch") != 20
    ):
        raise ValueError("calibration does not match the locked design")
    if timing.get("input_sha256") != _sha256(args.calibration):
        raise ValueError("timing model was not fitted from this calibration")
    runtime_hashes = calibration["source_hashes"]
    for key, path in LOCAL_RUNTIME_FILES.items():
        observed = _sha256(path)
        if observed != runtime_hashes.get(key):
            raise ValueError(
                f"local {path} changed after calibration: "
                f"{observed} != {runtime_hashes.get(key)}"
            )
    missing = [path for path in LOCKED_FILES.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(missing)
    files = {name: _sha256(path) for name, path in LOCKED_FILES.items()}
    files["timing_model"] = _sha256(args.timing_model)
    lock = {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "research_question": (
            "Can fixed-size multiset fingerprints detect accepted-filldir64 "
            "to getdents64-output identity discrepancies, and can an IBLT "
            "recover small differences across mechanisms and controls?"
        ),
        "protocol_revision": PROTOCOL,
        "formal_design": {
            "boots": 9,
            "states": 9,
            "conditions": 4,
            "buffers": 4,
            "repeats_per_cell": 1,
            "transactions_per_batch": 20,
            "batches": 1296,
            "transactions": 25920,
            "state_order": "nine-position cyclic rotation",
        },
        "calibration": {
            "role": "excluded_from_confirmatory_performance",
            "sha256": _sha256(args.calibration),
            "batches": 240,
            "transactions": 4800,
        },
        "runtime_source_hashes": runtime_hashes,
        "files": files,
        "no_post_lock_changes": (
            "Any source, binary, model, design, criterion, or oracle change "
            "requires a new revision and invalidates use of this lock."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(lock, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "calibration_sha256": lock["calibration"]["sha256"],
        "locked_files": len(files),
        "runtime_hashes": len(runtime_hashes),
    }, indent=2))


if __name__ == "__main__":
    main()
