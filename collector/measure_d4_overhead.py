#!/usr/bin/env python3
"""Paired D4 no-probe vs minimal/full-profile wall-time measurements."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import random
import statistics
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

try:
    from .collect_d4_batch import (
        _directory_names,
        _module_loaded,
        _spawn_blocked_ls,
        _stress_command,
        collect,
    )
except ImportError:
    from collect_d4_batch import (
        _directory_names,
        _module_loaded,
        _spawn_blocked_ls,
        _stress_command,
        collect,
    )


PROFILES = ("role_minimal", "security_minimal", "security", "role_aggregate")
CONDITIONS = ("baseline", "cpu")
FACTORS = ((8, 32), (1024, 160))


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _control(
    *, cardinality: int, filename_length: int, condition: str, iterations: int,
) -> int:
    visible, hidden, creation, _slot = _directory_names(
        cardinality, filename_length, "middle"
    )
    expected = {".", "..", *visible, hidden}
    stress = None
    with tempfile.TemporaryDirectory(prefix="kicba-d4-overhead-") as directory:
        for name in creation:
            (Path(directory) / name).touch()
        command = _stress_command(condition, 4, "256M")
        if command:
            stress = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(1.0)
        started = time.monotonic_ns()
        try:
            for _ in range(iterations):
                with tempfile.TemporaryFile() as output_stream:
                    process = _spawn_blocked_ls(directory, output_stream)
                    assert process.stdin is not None
                    process.stdin.write(b"\n")
                    process.stdin.close()
                    process.stdin = None
                    try:
                        _stdout, stderr = process.communicate(timeout=60)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                        raise
                    if process.returncode:
                        raise RuntimeError(stderr.decode("utf-8", "replace"))
                    output_stream.seek(0)
                    observed = output_stream.read().decode(
                        "utf-8", "replace"
                    ).splitlines()
                    if set(observed) != expected or len(observed) != len(expected):
                        raise RuntimeError("control listing differs from expected set")
        finally:
            elapsed = time.monotonic_ns() - started
            if stress is not None:
                stress.terminate()
                try:
                    stress.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    stress.kill()
                    stress.wait()
    return elapsed


def _instrumented(
    *, output: Path, cardinality: int, filename_length: int,
    condition: str, iterations: int, profile: str, poll_policy: str,
    position: int, seed: int,
) -> tuple[int, int, int, str]:
    args = SimpleNamespace(
        output=output,
        iterations=iterations,
        condition=condition,
        label="normal",
        cpu_workers=4,
        memory="256M",
        warmup_seconds=1.0,
        iteration_timeout_seconds=60.0,
        probe_profile=profile,
        poll_policy=poll_policy,
        directory_cardinality=cardinality,
        filename_length=filename_length,
        hidden_slot="middle",
        campaign_id="d4_overhead",
        campaign_position=position,
        campaign_phase="overhead",
        campaign_seed=seed,
    )
    if profile == "role_aggregate":
        try:
            from .collect_d4_aggregate_batch import collect as aggregate_collect
        except ImportError:
            from collect_d4_aggregate_batch import collect as aggregate_collect
        path = aggregate_collect(args)
    else:
        path = collect(args)
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        record = json.load(handle)
    if not record["quality"]["valid_for_analysis"]:
        raise RuntimeError(f"invalid instrumented overhead batch {path}")
    collection = record["collection"]
    return (
        int(collection["enabled_wall_duration_ns"]),
        int(collection["collector_process_cpu_ns"]),
        len(record.get("transaction_durations", record["events"])),
        str(path),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--iterations", default=20, type=int)
    parser.add_argument("--repeats", default=3, type=int)
    parser.add_argument("--seed", default=7501, type=int)
    parser.add_argument(
        "--profiles", nargs="+", choices=PROFILES, default=list(PROFILES)
    )
    parser.add_argument(
        "--role-poll-policy", choices=("continuous", "wait_drain"),
        default="continuous",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root inside the isolated VM")
    if "microsoft" in platform.release().lower():
        parser.error("WSL is excluded from D4 overhead evidence")
    if subprocess.run(
        ["ip", "route", "show", "default"],
        check=True, capture_output=True, text=True,
    ).stdout.strip():
        raise RuntimeError("overhead measurement refuses a default route")
    if _module_loaded("caraxes") or _module_loaded("caraxes_sham"):
        raise RuntimeError("unload both modules before overhead measurement")
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite {args.output}")
    if args.iterations < 1 or args.repeats < 1:
        parser.error("iterations and repeats must be positive")
    args.output.mkdir(parents=True)
    rng = random.Random(args.seed)
    source = Path(__file__).with_name("collect_d4_batch.py")
    result = {
        "protocol_revision": "D4-overhead-development-r1-2026-09-19",
        "status": "running",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "seed": args.seed,
        "repeats": args.repeats,
        "iterations": args.iterations,
        "profiles": args.profiles,
        "role_poll_policy": args.role_poll_policy,
        "collector_sha256": _hash(source),
        "aggregate_collector_sha256": _hash(Path(__file__).with_name("collect_d4_aggregate_batch.py")),
        "aggregate_bpf_sha256": _hash(Path(__file__).with_name("bpf_d4_aggregate.c")),
        "minimal_bpf_sha256": _hash(Path(__file__).with_name("bpf_d4_minimal.c")),
        "context_bpf_sha256": _hash(Path(__file__).with_name("bpf_context.c")),
        "pairs": [],
    }
    report_path = args.output / "overhead_report.json"
    try:
        for cardinality, filename_length in FACTORS:
            for condition in CONDITIONS:
                for profile in args.profiles:
                    for repeat in range(args.repeats):
                        modes = ["control", "instrumented"]
                        rng.shuffle(modes)
                        pair = {
                            "visible_cardinality": cardinality,
                            "filename_length": filename_length,
                            "condition": condition,
                            "profile": profile,
                            "poll_policy": (
                                "none" if profile == "role_aggregate"
                                else args.role_poll_policy if profile == "role_minimal"
                                else "continuous"
                            ),
                            "repeat": repeat,
                            "order": modes,
                        }
                        for mode in modes:
                            if mode == "control":
                                pair["control_wall_ns"] = _control(
                                    cardinality=cardinality,
                                    filename_length=filename_length,
                                    condition=condition,
                                    iterations=args.iterations,
                                )
                            else:
                                wall, cpu, events, path = _instrumented(
                                    output=args.output,
                                    cardinality=cardinality,
                                    filename_length=filename_length,
                                    condition=condition,
                                    iterations=args.iterations,
                                    profile=profile,
                                    poll_policy=pair["poll_policy"],
                                    position=len(result["pairs"]),
                                    seed=args.seed,
                                )
                                pair["instrumented_wall_ns"] = wall
                                pair["collector_process_cpu_ns"] = cpu
                                pair["events"] = events
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
    for cardinality, filename_length in FACTORS:
        for condition in CONDITIONS:
            for profile in args.profiles:
                subset = [
                    row for row in result["pairs"]
                    if row["visible_cardinality"] == cardinality
                    and row["filename_length"] == filename_length
                    and row["condition"] == condition
                    and row["profile"] == profile
                ]
                summary.append(
                    {
                        "visible_cardinality": cardinality,
                        "filename_length": filename_length,
                        "condition": condition,
                        "profile": profile,
                        "poll_policy": (
                            "none" if profile == "role_aggregate"
                            else args.role_poll_policy if profile == "role_minimal"
                            else "continuous"
                        ),
                        "pairs": len(subset),
                        "mean_wall_overhead_fraction": statistics.fmean(
                            row["wall_overhead_fraction"] for row in subset
                        ),
                        "median_events_per_iteration": statistics.median(
                            row["events"] / args.iterations for row in subset
                        ),
                    }
                )
    result["status"] = "complete"
    result["completed_utc"] = datetime.now(timezone.utc).isoformat()
    result["summary"] = summary
    report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(report_path)


if __name__ == "__main__":
    main()
