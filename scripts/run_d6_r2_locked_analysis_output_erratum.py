#!/usr/bin/env python3
"""Run the frozen D6-r2 analysis with a CSV-only serialization correction.

The frozen analysis imports a historical CSV helper that derives columns from
the first row.  D6-r2 intentionally combines public-baseline and proposed
prediction rows with different diagnostic fields, so the helper raises before
the report is written.  This wrapper replaces only that output helper with a
union-of-fields writer and then calls the unchanged frozen ``main`` function.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import run_d6_r2_locked_analysis as locked


def write_csv_union(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for name in row:
            if name not in seen:
                seen.add(name)
                fieldnames.append(name)
    with path.open("w", newline="", encoding="utf-8") as handle:
        if not fieldnames:
            return
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    locked._write_csv = write_csv_union
    locked.main()


if __name__ == "__main__":
    main()
