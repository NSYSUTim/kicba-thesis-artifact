#!/usr/bin/env python3
"""Quarantine selected Trace batches without deleting provenance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path


ACK = "I_UNDERSTAND_THIS_MOVES_FORMAL_BATCHES_TO_QUARANTINE"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_lines(path: Path, lines: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.writelines(lines)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--quarantine", type=Path, required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--apply-ack", required=True)
    args = parser.parse_args()

    if args.apply_ack != ACK:
        parser.error(f"--apply-ack must equal {ACK}")
    if not args.events.is_dir() or not args.log.is_file():
        parser.error("events directory and collection log must already exist")
    if args.quarantine.exists():
        parser.error("quarantine path must not already exist")

    kept_lines: list[str] = []
    excluded_lines: list[str] = []
    records: list[dict] = []
    with args.log.open("r", encoding="utf-8") as stream:
        for raw_line in stream:
            record = json.loads(raw_line)
            if (
                record.get("scenario") == args.scenario
                and record.get("label") == args.label
            ):
                records.append(record)
                excluded_lines.append(raw_line)
            else:
                kept_lines.append(raw_line)

    if not records:
        raise RuntimeError("selection matched no collection records")
    filenames = [record["file"] for record in records]
    if len(filenames) != len(set(filenames)):
        raise RuntimeError("selection contains duplicate filenames")

    sources = [args.events / filename for filename in filenames]
    for source, record in zip(sources, records, strict=True):
        if not source.is_file():
            raise FileNotFoundError(source)
        actual = sha256(source)
        if actual != record["sha256"]:
            raise RuntimeError(
                f"hash mismatch for {source.name}: {actual} != {record['sha256']}"
            )

    args.quarantine.mkdir(parents=False)
    quarantine_events = args.quarantine / "events"
    quarantine_events.mkdir()
    shutil.copy2(args.log, args.quarantine / "collection.before_exclusion.jsonl")
    write_lines(
        args.quarantine / "collection.excluded_records.jsonl", excluded_lines
    )
    replacement_log = args.log.with_suffix(args.log.suffix + ".replacement")
    write_lines(replacement_log, kept_lines)

    moved: list[tuple[Path, Path]] = []
    try:
        for source in sources:
            destination = quarantine_events / source.name
            source.rename(destination)
            moved.append((source, destination))
        os.replace(replacement_log, args.log)
    except Exception:
        for source, destination in reversed(moved):
            if destination.exists() and not source.exists():
                destination.rename(source)
        replacement_log.unlink(missing_ok=True)
        raise

    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "reason": args.reason,
        "selection": {"scenario": args.scenario, "label": args.label},
        "excluded_batches": len(records),
        "kept_log_records": len(kept_lines),
        "index_min": min(record["index"] for record in records),
        "index_max": max(record["index"] for record in records),
        "script_sha256": sha256(Path(__file__)),
        "files": [
            {"file": record["file"], "sha256": record["sha256"]}
            for record in records
        ],
    }
    manifest_path = args.quarantine / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({k: v for k, v in manifest.items() if k != "files"}, indent=2))


if __name__ == "__main__":
    main()
