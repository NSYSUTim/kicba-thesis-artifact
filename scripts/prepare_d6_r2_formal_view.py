#!/usr/bin/env python3
"""Prepare a byte-identical D6-r2 boot-only view after the pre-analysis audit bug.

The frozen collector stores each workload fixture beside its boot directory as
``boot_NN_fixture``.  The frozen audit/analysis scripts select directories with
``startswith("boot_")`` and therefore mistake fixtures for boots.  This tool
does not alter raw data or any locked analysis code.  It copies only the five
pre-specified formal boot directories and records byte-level provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


PROTOCOL = "D6-r2-2026-09-20"
FORMAL_BOOTS = tuple(f"boot_{sequence:02d}" for sequence in range(1, 6))
FIXTURE_DIRS = tuple(f"{boot}_fixture" for boot in FORMAL_BOOTS)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        rows.append({
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256(path),
        })
    return rows


def inventory_digest(rows: list[dict[str, object]]) -> str:
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_formal_view(source: Path, output: Path) -> dict[str, object]:
    source = source.resolve()
    output = output.resolve()
    if output.exists():
        raise FileExistsError(output)
    if not source.is_dir():
        raise NotADirectoryError(source)

    directory_names = sorted(
        path.name for path in source.iterdir() if path.is_dir()
    )
    expected_names = sorted(FORMAL_BOOTS + FIXTURE_DIRS)
    if directory_names != expected_names:
        raise RuntimeError(
            f"unexpected D6-r2 raw directories: {directory_names!r}"
        )

    output.mkdir(parents=True)
    try:
        for name in FORMAL_BOOTS:
            source_boot = source / name
            destination_boot = output / name
            shutil.copytree(source_boot, destination_boot, copy_function=shutil.copy2)
        source_rows = []
        for name in FORMAL_BOOTS:
            for row in inventory(source / name):
                source_rows.append({
                    "path": f"{name}/{row['path']}",
                    "size": row["size"],
                    "sha256": row["sha256"],
                })
        output_rows = inventory(output)
        if source_rows != output_rows:
            raise RuntimeError("formal view is not byte-identical to source boots")
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise

    return {
        "protocol": PROTOCOL,
        "formal_boots": list(FORMAL_BOOTS),
        "excluded_fixture_directories": list(FIXTURE_DIRS),
        "file_count": len(output_rows),
        "inventory_sha256": inventory_digest(output_rows),
        "files": output_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--original-audit", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    args = parser.parse_args()
    if args.provenance.exists():
        raise FileExistsError(args.provenance)

    original_audit = json.loads(
        args.original_audit.read_text(encoding="utf-8")
    )
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    if original_audit.get("protocol") != PROTOCOL:
        raise RuntimeError("original audit protocol mismatch")
    if original_audit.get("status") != "FAIL":
        raise RuntimeError("the preserved original audit is not FAIL")
    if "boot directory set mismatch" not in original_audit.get("failures", []):
        raise RuntimeError("the preserved audit does not contain the known bug")
    if lock.get("protocol_revision") != PROTOCOL:
        raise RuntimeError("analysis lock protocol mismatch")

    locked_audit = Path(lock["files"]["d6_r2_audit"]["path"])
    locked_analysis = Path(lock["files"]["analysis"]["path"])
    if sha256(locked_audit) != lock["files"]["d6_r2_audit"]["sha256"]:
        raise RuntimeError("locked audit script changed")
    if sha256(locked_analysis) != lock["files"]["analysis"]["sha256"]:
        raise RuntimeError("locked analysis script changed")

    report = build_formal_view(args.input, args.output)
    report.update({
        "status": "PASS",
        "correction": (
            "Present only exact boot_NN directories to unchanged locked "
            "audit and analysis scripts; exclude boot_NN_fixture directories."
        ),
        "raw_input": str(args.input.resolve()),
        "formal_view": str(args.output.resolve()),
        "original_audit": str(args.original_audit.resolve()),
        "original_audit_sha256": sha256(args.original_audit),
        "analysis_lock": str(args.lock.resolve()),
        "analysis_lock_sha256": sha256(args.lock),
        "locked_audit_sha256": sha256(locked_audit),
        "locked_analysis_sha256": sha256(locked_analysis),
        "method_or_threshold_change": False,
        "raw_data_change": False,
    })
    args.provenance.parent.mkdir(parents=True, exist_ok=True)
    args.provenance.write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps({
        key: value for key, value in report.items() if key != "files"
    }, indent=2))


if __name__ == "__main__":
    main()
