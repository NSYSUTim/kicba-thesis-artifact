from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReviewBundleSourceTests(unittest.TestCase):
    def test_central_evidence_map_covers_d1_through_d7(self) -> None:
        text = (ROOT / "docs" / "DATASET_AND_EVIDENCE_MAP_zh-TW.md").read_text(
            encoding="utf-8"
        )
        for dataset in ("D1", "D2", "D3", "D4", "D5", "D6-r1", "D6-r2", "D7"):
            self.assertIn(dataset, text)

    def test_readme_documents_canonical_views_without_code_paths_in_papers(self) -> None:
        track_a = (
            ROOT / "docs" / "papers" / "TRACK_A_LOW_FALSE_POSITIVE_ROOTKIT_zh-TW.md"
        ).read_text(encoding="utf-8")
        track_b = (
            ROOT / "docs" / "papers" / "TRACK_B_SAFE_ONLINE_ADAPTATION_zh-TW.md"
        ).read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("results/d7_formal/raw_r1_canonical", track_a)
        self.assertNotIn("results/d6_r2_formal/raw_r1", track_b)
        self.assertNotIn("results/d6_r2_formal/formal_boot_view_r1", track_b)
        self.assertIn("results/d7_formal/raw_r1_canonical", readme)
        self.assertIn("results/d6_r2_formal/formal_boot_view_r1", readme)

    def test_d7_development_and_formal_evidence_are_distinguished(self) -> None:
        evidence_map = (
            ROOT / "docs" / "DATASET_AND_EVIDENCE_MAP_zh-TW.md"
        ).read_text(encoding="utf-8")
        self.assertIn("active-logic false-positive rate 75%", evidence_map)
        self.assertIn("D7 development", evidence_map)
        self.assertIn("D7-r1 formal", evidence_map)
        self.assertIn("13 條方法功效規則", evidence_map)

    def test_d7_formal_report_matches_paper_claims(self) -> None:
        report = json.loads(
            (ROOT / "results" / "d7_formal" / "confirmatory_r1" / "report.json")
            .read_text(encoding="utf-8")
        )
        proposed = next(
            row for row in report["overall"] if row["method"] == "nesting_invariant"
        )
        self.assertEqual(8, report["boots"])
        self.assertEqual(384, report["batches"])
        self.assertEqual((96, 0, 0, 288), (
            proposed["tp"], proposed["fn"], proposed["fp"], proposed["tn"]
        ))
        self.assertTrue(report["method_efficacy_pass"])
        paper = (
            ROOT / "docs" / "papers" / "TRACK_A_LOW_FALSE_POSITIVE_ROOTKIT_zh-TW.md"
        ).read_text(encoding="utf-8")
        self.assertIn("真陽性 96、偽陰性 0、偽陽性 0、真陰性 288", paper)
        self.assertIn("13 項預先設定的成效規則全部成立", paper)

    def test_d6_r2_formal_report_matches_paper_claims(self) -> None:
        report = json.loads(
            (
                ROOT
                / "results"
                / "d6_r2_formal"
                / "confirmatory_r1_output_erratum"
                / "report.json"
            ).read_text(encoding="utf-8")
        )
        proposed = next(
            row
            for row in report["overall"]
            if row["method"] == "proposed_factorized_guard_w50"
        )
        self.assertEqual(5, report["boots"])
        self.assertAlmostEqual(0.9375, proposed["attack_recall"])
        self.assertAlmostEqual(0.0625, proposed["attack_update_rate"])
        self.assertAlmostEqual(
            0.4791666666666667, proposed["max_window_attack_fraction"]
        )
        self.assertFalse(report["method_efficacy_pass"])
        paper = (
            ROOT
            / "docs"
            / "papers"
            / "TRACK_B_SAFE_ONLINE_ADAPTATION_zh-TW.md"
        ).read_text(encoding="utf-8")
        self.assertIn("rootkit 召回率為 93.75%", paper)
        self.assertIn("攻擊資料更新率為 6.25%", paper)
        self.assertIn("視窗最高攻擊占比達 47.92%", paper)
        self.assertIn("15 項成效規則中通過 9 項", paper)

    def test_bundle_has_one_named_current_output(self) -> None:
        script = (ROOT / "scripts" / "build_ai_review_bundle.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("KICBA_AI_REVIEW_CURRENT", script)
        self.assertNotIn("KICBA_TWO_TRACK_REVIEW_R2_20260921", script)
        self.assertIn("'results/d7_formal'", script)
        self.assertIn("docs/D7_R1_CONFIRMATORY_RESULTS_zh-TW.md", script)
        self.assertIn("Generated package unexpectedly contains raw payloads", script)


if __name__ == "__main__":
    unittest.main()
