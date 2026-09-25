#!/usr/bin/env python3
"""Create an auditable D7 input view without sibling fixture directories.

The D7 collector intentionally creates ``boot_XX_fixture`` next to each
``boot_XX`` result directory.  The pre-registered audit and analysis scripts
select directories with ``startswith('boot_')`` and therefore mistake the
fixtures for additional boots.  This utility does not transform records.  It
copies only the eight exact formal boot directories, verifies every copied
byte by SHA-256, and writes a manifest outside the canonical view.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path


BOOT_PATTERN = re.compile(r"boot_[0-9]{2}")
FIXTURE_PATTERN = re.compile(r"boot_[0-9]{2}_fixture")
EXPECTED_BOOTS = tuple(f"boot_{index:02d}" for index in range(1, 9))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inventory(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def prepare_view(source: Path, output: Path, manifest_path: Path) -> dict:
    if output.exists():
        raise FileExistsError(f"refusing to overwrite canonical view: {output}")
    if manifest_path.exists():
        raise FileExistsError(f"refusing to overwrite manifest: {manifest_path}")
    if not source.is_dir():
        raise NotADirectoryError(source)

    directories = sorted(path for path in source.iterdir() if path.is_dir())
    boots = [path for path in directories if BOOT_PATTERN.fullmatch(path.name)]
    fixtures = [
        path for path in directories if FIXTURE_PATTERN.fullmatch(path.name)
    ]
    unexpected_boot_like = [
        path.name
        for path in directories
        if path.name.startswith("boot_")
        and not BOOT_PATTERN.fullmatch(path.name)
        and not FIXTURE_PATTERN.fullmatch(path.name)
    ]
    if tuple(path.name for path in boots) != EXPECTED_BOOTS:
        raise RuntimeError(
            f"exact formal boot set mismatch: {[path.name for path in boots]}"
        )
    if tuple(path.name for path in fixtures) != tuple(
        f"{name}_fixture" for name in EXPECTED_BOOTS
    ):
        raise RuntimeError(
            f"fixture set mismatch: {[path.name for path in fixtures]}"
        )
    if unexpected_boot_like:
        raise RuntimeError(
            f"unexpected boot-like directories: {unexpected_boot_like}"
        )

    output.mkdir(parents=True)
    per_boot = {}
    for boot in boots:
        destination = output / boot.name
        shutil.copytree(boot, destination, copy_function=shutil.copy2)
        source_inventory = _inventory(boot)
        destination_inventory = _inventory(destination)
        if source_inventory != destination_inventory:
            raise RuntimeError(f"byte inventory mismatch after copy: {boot.name}")
        per_boot[boot.name] = {
            "files": len(source_inventory),
            "inventory": source_inventory,
        }

    report = {
        "schema_version": 1,
        "purpose": "D7 post-lock input-layout erratum",
        "status": "PASS",
        "transformation": "none; byte-identical copy of exact boot_01..boot_08",
        "included_directories": list(EXPECTED_BOOTS),
        "excluded_fixture_directories": [path.name for path in fixtures],
        "per_boot": per_boot,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    report = prepare_view(args.source, args.output, args.manifest)
    print(json.dumps({
        "status": report["status"],
        "included_directories": report["included_directories"],
        "excluded_fixture_directories": report["excluded_fixture_directories"],
        "files": sum(item["files"] for item in report["per_boot"].values()),
    }, indent=2))


if __name__ == "__main__":
    main()
