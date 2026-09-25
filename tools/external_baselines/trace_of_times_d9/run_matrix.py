#!/usr/bin/env python3
"""Run the frozen Trace of the Times five-scenario collection matrix."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import random
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


SCENARIOS = (
    "default",
    "file_count",
    "system_load",
    "ls_basic",
    "filename_length",
)
LABEL_COUNTS = (("normal", 150), ("rootkit", 100))
ACK = "I_UNDERSTAND_THIS_LOADS_A_ROOTKIT_IN_AN_ISOLATED_VM"


def load_metadata(path: Path) -> dict:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        value = json.load(stream)
    return {
        "label": value["label"],
        "description": value["description"],
        "iterations": value["iterations"],
        "visible_files": value["visible_files"],
        "hidden_files": value["hidden_files"],
        "load": value["load"],
        "executable": value["executable"],
        "events": len(value["events"]),
    }


def stable_rng(seed: int, scenario: str, label: str, index: int) -> random.Random:
    digest = hashlib.sha256(
        f"{seed}:{scenario}:{label}:{index}".encode("utf-8")
    ).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def batch_args(
    scenario: str, label: str, index: int, seed: int, iterations: int
) -> list[str]:
    args = [
        "python3",
        "probing.py",
        "--normal" if label == "normal" else "--rootkit",
        "--iterations",
        str(iterations),
        "--description",
        scenario,
    ]
    rng = stable_rng(seed, scenario, label, index)
    if scenario == "file_count":
        args += [
            "--visible-files",
            str(rng.randint(10, 100)),
            "--hidden-files",
            str(rng.randint(10, 100)),
        ]
    elif scenario == "system_load":
        args += ["--load"]
    elif scenario == "ls_basic":
        args += ["--executable", "./ls-basic"]
    elif scenario == "filename_length":
        args += ["--file-name-length", str(rng.randint(20, 60))]
    return args


def inventory(events_dir: Path) -> dict[tuple[str, str], list[Path]]:
    result: dict[tuple[str, str], list[Path]] = {}
    for path in sorted(events_dir.glob("events_*.json.gz")):
        metadata = load_metadata(path)
        key = (metadata["description"], metadata["label"])
        result.setdefault(key, []).append(path)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", default=Path("events"), type=Path)
    parser.add_argument("--log", default=Path("collection.jsonl"), type=Path)
    parser.add_argument("--seed", default=42, type=int)
    parser.add_argument("--iterations", default=100, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.error("run as root in the isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if subprocess.run(
        ["ip", "route", "show", "default"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip():
        raise RuntimeError("default route present")
    if args.iterations != 100:
        raise ValueError("formal matrix requires exactly 100 listings per batch")
    if not Path("probing.py").is_file() or not Path("ls-basic").is_file():
        raise FileNotFoundError("run from the integrated upstream directory")

    args.events.mkdir(exist_ok=True)
    existing = inventory(args.events)
    for scenario in SCENARIOS:
        for label, target in LABEL_COUNTS:
            have = len(existing.get((scenario, label), []))
            if have > target:
                raise RuntimeError(f"too many existing batches for {scenario}/{label}")
            for index in range(have, target):
                command = batch_args(
                    scenario, label, index, args.seed, args.iterations
                )
                before = set(args.events.glob("events_*.json.gz"))
                started = time.monotonic()
                completed = subprocess.run(
                    command, check=False, capture_output=True, text=True
                )
                elapsed = time.monotonic() - started
                after = set(args.events.glob("events_*.json.gz"))
                created = sorted(after - before)
                if completed.returncode or len(created) != 1:
                    raise RuntimeError(
                        f"batch failed: {scenario}/{label}/{index}\n"
                        f"returncode={completed.returncode}\n"
                        f"stdout={completed.stdout}\n"
                        f"stderr={completed.stderr}\n"
                        f"created={created}"
                    )
                metadata = load_metadata(created[0])
                if (
                    metadata["description"] != scenario
                    or metadata["label"] != label
                    or metadata["iterations"] != args.iterations
                    or metadata["events"] == 0
                ):
                    raise RuntimeError(f"invalid batch metadata: {metadata}")
                record = {
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                    "scenario": scenario,
                    "label": label,
                    "index": index,
                    "elapsed_seconds": elapsed,
                    "file": created[0].name,
                    "sha256": hashlib.sha256(created[0].read_bytes()).hexdigest(),
                    "command": command,
                    "metadata": metadata,
                }
                with args.log.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, separators=(",", ":")) + "\n")
                print(json.dumps(record), flush=True)

    final = inventory(args.events)
    counts = {
        f"{scenario}/{label}": len(final.get((scenario, label), []))
        for scenario in SCENARIOS
        for label, _ in LABEL_COUNTS
    }
    if any(
        counts[f"{scenario}/{label}"] != target
        for scenario in SCENARIOS
        for label, target in LABEL_COUNTS
    ):
        raise RuntimeError(f"incomplete final matrix: {counts}")
    print(json.dumps({"event": "complete", "counts": counts}, indent=2))


if __name__ == "__main__":
    main()
