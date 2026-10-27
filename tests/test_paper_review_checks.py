"""Check the documented counterexamples and block-pairing analysis."""
import unittest

from scripts.verify_paper_review_checks import duplicate_cases, paired_cost


class PaperReviewChecks(unittest.TestCase):
    def cost_rows(self):
        rows = []
        for block in range(10):
            for mode in ("legacy", "packed"):
                wall = (100 if block < 5 else 1000) if mode == "legacy" else 90
                rows.append(dict(kind="cost", cardinality=65536, condition="baseline",
                                 warmup=False, implementation=mode, block=block,
                                 verdict="equal", returncode=0, measurement_valid=True,
                                 count_match=True, load_active=True, decode_success=True,
                                 fingerprint_equal=True, coverage={"valid": True},
                                 wall_ns=wall, wall_with_coverage_ns=wall + 10))
        return rows

    def test_ratio_uses_pairs_rather_than_independent_medians(self):
        result = paired_cost(self.cost_rows())
        self.assertAlmostEqual(result["ratio_without_queries_median"], 0.495)
        self.assertNotAlmostEqual(result["ratio_without_queries_median"], 90 / 550)

    def test_missing_or_duplicate_observations_are_rejected(self):
        rows = self.cost_rows()
        for invalid in (rows[:-1], rows + [rows[0]]):
            with self.subTest(length=len(invalid)):
                with self.assertRaises(RuntimeError):
                    paired_cost(invalid)

    def test_invalid_quality_cannot_be_silently_discarded(self):
        rows = self.cost_rows()
        rows[0]["coverage"]["valid"] = False
        with self.assertRaisesRegex(RuntimeError, "Invalid primary"):
            paired_cost(rows)

    def test_duplicate_counterexamples_include_failure_and_false_success(self):
        records = duplicate_cases()["cases"]
        self.assertEqual(len(records), 6)
        false_empty = [r for r in records if r["decode_success"]]
        self.assertEqual([r["cells"] for r in false_empty], [8, 256])
        enlarged = next(r for r in records if r["case"] == "two_X_vs_two_Y" and r["cells"] == 4096)
        self.assertEqual(set(enlarged["x_positions"]) & set(enlarged["y_positions"]), {2555})
        self.assertEqual(sorted(c["count"] for c in enlarged["nonzero_cells"]), [-2, -2, 2, 2])


if __name__ == "__main__":
    unittest.main()
