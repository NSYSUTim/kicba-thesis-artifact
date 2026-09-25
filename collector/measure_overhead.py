#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import os
import random
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

from collect_batch import (
    _module_loaded,
    _spawn_blocked_ls,
    _stress_command,
    collect,
)


CONDITIONS = ("baseline", "cpu", "memory", "mixed")


def _run_control(condition: str, iterations: int, workers: int, memory: str) -> int:
    stress = None
    command = _stress_command(condition, workers, memory)
    with tempfile.TemporaryDirectory(prefix="kicba-overhead-") as temp_dir:
        Path(temp_dir, "visible_file").touch()
        Path(temp_dir, "sample_caraxes_hidden").touch()
        if command:
            stress = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(1.0)
        started = time.monotonic_ns()
        try:
            for _ in range(iterations):
                process = _spawn_blocked_ls(temp_dir)
                assert process.stdin is not None
                process.stdin.write(b"\n")
                process.stdin.close()
                process.stdin = None
                stdout, stderr = process.communicate()
                if process.returncode:
                    raise RuntimeError(stderr.decode("utf-8", "replace"))
                if b"sample_caraxes_hidden" not in stdout:
                    raise RuntimeError("CARAXES must be unloaded for overhead controls")
        finally:
            ended = time.monotonic_ns()
            if stress is not None:
                stress.terminate()
                try:
                    stress.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    stress.kill()
                    stress.wait()
    return ended - started


def _run_instrumented(
    output: Path, condition: str, iterations: int, workers: int, memory: str
) -> tuple[int, int, str]:
    args = SimpleNamespace(
        output=output,
        iterations=iterations,
        condition=condition,
        label="normal",
        cpu_workers=workers,
        memory=memory,
        warmup_seconds=1.0,
        campaign_id="overhead",
        campaign_position=None,
        campaign_seed=None,
    )
    path = collect(args)
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        record = json.load(handle)
    if not record["quality"]["valid_for_analysis"]:
        raise RuntimeError(f"Instrumented overhead batch is invalid: {path}")
    collection = record["collection"]
    return (
        int(collection["enabled_wall_duration_ns"]),
        int(collection["collector_process_cpu_ns"]),
        str(path),
    )


def _bootstrap_ci(values: list[float], seed: int, samples: int = 10_000) -> list[float]:
    rng = random.Random(seed)
    means = [
        statistics.fmean(rng.choice(values) for _ in values) for _ in range(samples)
    ]
    means.sort()
    return [means[int(0.025 * samples)], means[int(0.975 * samples)]]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure randomized paired workload overhead with and without KICBA instrumentation."
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repeats", default=20, type=int)
    parser.add_argument("--iterations", default=100, type=int)
    parser.add_argument("--seed", default=20260914, type=int)
    parser.add_argument("--cpu-workers", default=min(4, os.cpu_count() or 1), type=int)
    parser.add_argument("--memory", default="256M")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root inside the isolated VM")
    if _module_loaded("caraxes"):
        parser.error("unload CARAXES before measuring normal overhead")
    if args.repeats < 2 or args.iterations < 1:
        parser.error("--repeats must be >=2 and --iterations must be positive")

    args.output.mkdir(parents=True, exist_ok=True)
    raw: list[dict] = []
    rng = random.Random(args.seed)
    for condition in CONDITIONS:
        for repeat in range(args.repeats):
            order = ["control", "instrumented"]
            rng.shuffle(order)
            pair: dict[str, object] = {"condition": condition, "repeat": repeat}
            for mode in order:
                if mode == "control":
                    pair["control_wall_ns"] = _run_control(
                        condition, args.iterations, args.cpu_workers, args.memory
                    )
                else:
                    wall, process_cpu, path = _run_instrumented(
                        args.output,
                        condition,
                        args.iterations,
                        args.cpu_workers,
                        args.memory,
                    )
                    pair["instrumented_wall_ns"] = wall
                    pair["collector_process_cpu_ns"] = process_cpu
                    pair["batch_path"] = path
            pair["wall_overhead_fraction"] = (
                int(pair["instrumented_wall_ns"]) - int(pair["control_wall_ns"])
            ) / int(pair["control_wall_ns"])
            raw.append(pair)

    summary: list[dict] = []
    for condition in CONDITIONS:
        values = [
            float(row["wall_overhead_fraction"])
            for row in raw
            if row["condition"] == condition
        ]
        lo, hi = _bootstrap_ci(values, args.seed)
        summary.append(
            {
                "condition": condition,
                "pairs": len(values),
                "mean_wall_overhead_fraction": statistics.fmean(values),
                "bootstrap_ci_lo": lo,
                "bootstrap_ci_hi": hi,
                "median_collector_process_cpu_ns": statistics.median(
                    int(row["collector_process_cpu_ns"])
                    for row in raw
                    if row["condition"] == condition
                ),
            }
        )
    report = {
        "seed": args.seed,
        "iterations": args.iterations,
        "repeats": args.repeats,
        "raw_pairs": raw,
        "summary": summary,
        "interpretation": (
            "Wall overhead includes BPF execution, perf polling, and userspace event handling "
            "during the workload; BPF compilation/attachment and stress warm-up are excluded."
        ),
    }
    output_path = args.output / "overhead_report.json"
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(output_path)


if __name__ == "__main__":
    main()
