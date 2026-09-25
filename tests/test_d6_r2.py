from __future__ import annotations

import importlib
import sys
import tempfile
import types
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch


class D6R2ScheduleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.modules.setdefault("bcc", types.SimpleNamespace(BPF=object))
        cls.campaign = importlib.import_module("run_d6_r2_campaign")

    def test_five_boot_episode_latin_square_and_counts(self):
        orders = []
        positions = {name: [] for name in (
            "normal_early", "normal_workloads", "attack", "recovery",
            "sham_control",
        )}
        for sequence in range(1, 6):
            schedule, order = self.campaign.build_schedule(
                sequence, 9700 + sequence
            )
            orders.append(tuple(order))
            self.assertEqual(len(schedule), 460)
            test = [row for row in schedule if row["phase"] == "test"]
            self.assertEqual(len(test), 360)
            self.assertEqual(
                Counter(row["state"] for row in test),
                {"unloaded": 180, "hiding": 160, "sham": 20},
            )
            attack_positions = [
                index for index, row in enumerate(test)
                if row["state"] == "hiding"
            ]
            self.assertEqual(len(attack_positions), 160)
            self.assertEqual(
                attack_positions[-1] - attack_positions[0] + 1, 160
            )
            for name in positions:
                positions[name].append(order.index(name))
        self.assertEqual(len(set(orders)), 5)
        for values in positions.values():
            self.assertEqual(sorted(values), [0, 1, 2, 3, 4])


class D6R2AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = importlib.import_module("d6_r2_analysis_core")

    def test_proposed_predicts_before_update_and_has_three_states(self):
        clean = [
            {"cpu_busy_fraction": 0.1, "first_raw_median": 10.0},
        ] * 4
        sham = [{}] * 4
        test = [
            (
                {"position": 1, "episode": "normal_early",
                 "episode_ordinal": 0, "segment": "benign_cpu",
                 "state": "unloaded", "condition": "cpu"},
                None,
                {"cpu_busy_fraction": 0.1, "first_raw_median": 20.0,
                 "security": False},
            ),
            (
                {"position": 2, "episode": "attack",
                 "episode_ordinal": 1, "segment": "attack_cpu",
                 "state": "hiding", "condition": "cpu"},
                None,
                {"cpu_busy_fraction": 0.1, "first_raw_median": 30.0,
                 "security": True},
            ),
            (
                {"position": 3, "episode": "recovery",
                 "episode_ordinal": 2, "segment": "normal_recovery",
                 "state": "unloaded", "condition": "baseline"},
                None,
                {"cpu_busy_fraction": 0.1, "first_raw_median": 10.0,
                 "security": False},
            ),
        ]
        security_model = {"context_split": 0.5}
        operational_model = {
            "context_split": 0.5,
            "strata": {
                "low": {"threshold": 1.1, "initial": [10.0] * 4},
                "high": {"threshold": 1.1, "initial": [10.0] * 4},
            },
        }

        def score(_model, row):
            return "low", 1.0, 2.0, row["security"]

        with patch.object(self.core, "fit_context_axis", return_value=security_model), \
             patch.object(self.core, "score_context_axis", side_effect=score), \
             patch.object(self.core, "_fit_operational", return_value=operational_model):
            rows = self.core.replay_proposed(
                {"boot_id": "boot"}, clean, sham, test
            )
        self.assertEqual([row["decision"] for row in rows], [
            "drift", "attack", "normal",
        ])
        self.assertEqual([row["updated"] for row in rows], [True, False, True])
        self.assertEqual(rows[0]["operational_score"], 2.0)

    def test_fpr_denominators_are_separate(self):
        def row(state, alert, condition="baseline"):
            return {
                "truth_state": state,
                "security_alert": alert,
                "updated": not alert,
                "window_attack_fraction": 0.0,
                "condition": condition,
                "decision": "attack" if alert else "normal",
            }
        rows = [
            row("hiding", True),
            row("unloaded", True),
            row("unloaded", False, "cpu"),
            row("sham", True),
        ]
        result = self.core.metric_row(rows, "boot", self.core.PROPOSED)
        self.assertEqual(result["unloaded_normal_fpr"], 0.5)
        self.assertEqual(result["sham_fpr"], 1.0)
        self.assertAlmostEqual(result["non_attack_fpr"], 2 / 3)
        self.assertEqual(result["unloaded_n"], 2)
        self.assertEqual(result["sham_n"], 1)


class D6R2AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = importlib.import_module("audit_d6_r2")

    def test_hash_verification_detects_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "locked.txt"
            path.write_text("original", encoding="utf-8")
            expected = self.audit._sha256(path)
            files = {"item": {"path": str(path), "sha256": expected}}
            _, failures = self.audit.verify_local_file_hashes(files)
            self.assertEqual(failures, [])
            path.write_text("changed", encoding="utf-8")
            _, failures = self.audit.verify_local_file_hashes(files)
            self.assertEqual(failures, ["local file hash mismatch: item"])


if __name__ == "__main__":
    unittest.main()
