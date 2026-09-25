#!/usr/bin/env python3
"""Paired no-probe versus D7 map-aggregate composition overhead pilot."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import random
import statistics
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from collect_batch import _module_loaded
from collect_d7_composition_batch import collect
from measure_d4_overhead import _control, _hash


CONDITIONS = ("baseline", "cpu", "memory", "mixed")
CARDINALITY = 128
FILENAME_LENGTH = 32
PROTOCOL = "D7-composition-overhead-pilot-r1-2026-09-21"


def _instrumented(output: Path, condition: str, iterations: int,
                  position: int, seed: int) -> tuple[int, int, str]:
    args = SimpleNamespace(
        output=output,
        iterations=iterations,
        condition=condition,
        label="normal",
        cpu_workers=4,
        memory="256M",
        warmup_seconds=1.0,
        iteration_timeout_seconds=60.0,
        probe_profile="composition_aggregate",
        poll_policy="none",
        directory_cardinality=CARDINALITY,
        filename_length=FILENAME_LENGTH,
        hidden_slot="middle",
        fixture_dir=None,
        campaign_id="d7_composition_overhead",
        campaign_position=position,
        campaign_phase="overhead",
        campaign_seed=seed,
    )
    path = collect(args)
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        record = json.load(handle)
    if not record["quality"]["valid_for_analysis"]:
        raise RuntimeError(f"invalid instrumented overhead batch {path}")
    collection = record["collection"]
    return (
        int(collection["enabled_wall_duration_ns"]),
        int(collection["collector_process_cpu_ns"]),
        str(path),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--iterations", default=20, type=int)
    parser.add_argument("--repeats", default=5, type=int)
    parser.add_argument("--seed", default=10706, type=int)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root inside the isolated VM")
    if "microsoft" in platform.release().lower():
        parser.error("WSL is excluded")
    if subprocess.run(
        ["ip", "route", "show", "default"], check=True,
        capture_output=True, text=True,
    ).stdout.strip():
        raise RuntimeError("default route present")
    loaded = {
        "caraxes", "caraxes_sham", "kicba_d7_pass", "kicba_d7_active",
        "kicba_d7_hiding",
    }
    if any(_module_loaded(name) for name in loaded):
        raise RuntimeError("D7/CARAXES module loaded")
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.mkdir(parents=True)
    rng = random.Random(args.seed)
    source = Path(__file__).with_name("collect_d7_composition_batch.py")
    bpf_source = Path(__file__).with_name("bpf_d7_composition.c")
    result = {
        "protocol_revision": PROTOCOL,
        "status": "running",
        "evidence_role": "single_boot_development_overhead_pilot",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "seed": args.seed,
        "repeats": args.repeats,
        "iterations": args.iterations,
        "visible_cardinality": CARDINALITY,
        "filename_length": FILENAME_LENGTH,
        "collector_sha256": _hash(source),
        "bpf_sha256": _hash(bpf_source),
        "pairs": [],
    }
    report_path = args.output / "overhead_report.json"
    try:
        for condition in CONDITIONS:
            for repeat in range(args.repeats):
                modes = ["control", "instrumented"]
                rng.shuffle(modes)
                pair = {
                    "condition": condition,
                    "repeat": repeat,
                    "order": modes,
                }
                for mode in modes:
                    if mode == "control":
                        pair["control_wall_ns"] = _control(
                            cardinality=CARDINALITY,
                            filename_length=FILENAME_LENGTH,
                            condition=condition,
                            iterations=args.iterations,
                        )
                    else:
                        wall, cpu, path = _instrumented(
                            args.output, condition, args.iterations,
                            len(result["pairs"]), args.seed,
                        )
                        pair["instrumented_wall_ns"] = wall
                        pair["collector_process_cpu_ns"] = cpu
                        pair["batch_path"] = path
                pair["wall_overhead_fraction"] = (
                    pair["instrumented_wall_ns"] - pair["control_wall_ns"]
                ) / pair["control_wall_ns"]
                result["pairs"].append(pair)
                report_path.write_text(
                    json.dumps(result, indent=2), encoding="utf-8"
                )
    except BaseException as exc:
        result["status"] = "failed"
        result["failure"] = f"{type(exc).__name__}: {exc}"
        report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        raise

    summary = []
    for condition in CONDITIONS:
        values = [
            row["wall_overhead_fraction"] for row in result["pairs"]
            if row["condition"] == condition
        ]
        summary.append({
            "condition": condition,
            "pairs": len(values),
            "mean_wall_overhead_fraction": statistics.fmean(values),
            "median_wall_overhead_fraction": statistics.median(values),
            "min_wall_overhead_fraction": min(values),
            "max_wall_overhead_fraction": max(values),
        })
    all_values = [row["wall_overhead_fraction"] for row in result["pairs"]]
    result["summary"] = summary
    result["overall_mean_wall_overhead_fraction"] = statistics.fmean(all_values)
    result["deployment_rule"] = {
        "rule": "each condition mean wall overhead <= 0.05",
        "pass": all(row["mean_wall_overhead_fraction"] <= 0.05 for row in summary),
    }
    result["status"] = "complete"
    result["completed_utc"] = datetime.now(timezone.utc).isoformat()
    report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(report_path)


if __name__ == "__main__":
    main()
