#!/usr/bin/env python3
"""Create an auditable symlink-only four-scenario view of sealed Trace data."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path


INCLUDED = ("default", "file_count", "system_load", "filename_length")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collection", required=True, type=Path)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if args.output.exists():
        raise FileExistsError(args.output)
    records = [
        json.loads(line)
        for line in args.collection.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    selected = [record for record in records if record["scenario"] in INCLUDED]
    counts = Counter((record["scenario"], record["label"]) for record in selected)
    expected = Counter({
        **{(scenario, "normal"): 150 for scenario in INCLUDED},
        **{(scenario, "rootkit"): 100 for scenario in INCLUDED},
    })
    if counts != expected or len(selected) != 1000:
        raise RuntimeError(f"unexpected selected matrix: {dict(counts)}")

    args.output.mkdir(parents=True)
    manifest_records = []
    for record in selected:
        source = (args.events / record["file"]).resolve(strict=True)
        if sha256(source) != record["sha256"]:
            raise RuntimeError(f"hash mismatch: {record['file']}")
        destination = args.output / record["file"]
        destination.symlink_to(source)
        manifest_records.append({
            "scenario": record["scenario"],
            "label": record["label"],
            "file": record["file"],
            "sha256": record["sha256"],
            "target": os.readlink(destination),
        })

    manifest = {
        "purpose": "Trace of the Times four-scenario head-to-head view",
        "included_scenarios": list(INCLUDED),
        "excluded_scenario": "ls_basic",
        "selection_reason": "ls_basic uses legacy getdents/filldir, outside D9 getdents64/filldir64 scope",
        "collection_sha256": sha256(args.collection),
        "event_count": len(manifest_records),
        "counts": {f"{scenario}/{label}": value for (scenario, label), value in sorted(counts.items())},
        "records": manifest_records,
    }
    manifest_path = args.output.parent / f"{args.output.name}_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({key: value for key, value in manifest.items() if key != "records"}, indent=2))


if __name__ == "__main__":
    main()
