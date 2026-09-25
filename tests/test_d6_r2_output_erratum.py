from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from run_d6_r2_locked_analysis_output_erratum import write_csv_union


class D6R2OutputErratumTests(unittest.TestCase):
    def test_union_writer_accepts_heterogeneous_diagnostic_fields(self):
        rows = [
            {"method": "fixed", "score": 1.0},
            {
                "method": "proposed",
                "score": 2.0,
                "context_stratum": "low",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rows.csv"
            write_csv_union(path, rows)
            with path.open(newline="", encoding="utf-8") as handle:
                written = list(csv.DictReader(handle))
        self.assertEqual(
            list(written[0]), ["method", "score", "context_stratum"]
        )
        self.assertEqual(written[0]["context_stratum"], "")
        self.assertEqual(written[1]["context_stratum"], "low")


if __name__ == "__main__":
    unittest.main()
