from __future__ import annotations

import importlib
import sys
import types
import unittest
from collections import Counter


class D7FormalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.modules.setdefault("bcc", types.SimpleNamespace(BPF=object))
        cls.formal = importlib.import_module(
            "run_d7_nesting_formal_campaign"
        )

    def test_eight_boot_balanced_latin_square(self):
        positions = {state: [] for state in self.formal.STATES}
        for sequence in range(1, 9):
            schedule, order = self.formal.build_schedule(
                sequence, 11700 + sequence
            )
            self.assertEqual(len(schedule), 48)
            self.assertEqual(
                Counter((row["state"], row["condition"]) for row in schedule),
                Counter({
                    (state, condition): 3
                    for state in self.formal.STATES
                    for condition in self.formal.CONDITIONS
                }),
            )
            for state in self.formal.STATES:
                positions[state].append(order.index(state))
        for values in positions.values():
            self.assertEqual(sorted(values), [0, 0, 1, 1, 2, 2, 3, 3])

    def test_structural_rule_has_only_two_count_inputs(self):
        rule = self.formal.structural_alert
        self.assertFalse(rule(0, 131))       # ordinary unhooked path
        self.assertFalse(rule(131, 0))       # every wrapper call forwards
        self.assertTrue(rule(130, 1))        # selective short circuit
        self.assertTrue(rule(1, 130))

    def test_behavior_separation_metric_is_direction_agnostic(self):
        analysis = importlib.import_module("run_d7_nesting_locked_analysis")
        rows = []
        for state, proposed_alert, timing_alert in (
            ("unloaded", False, False),
            ("pass", False, False),
            ("active", False, False),
            ("hiding", True, False),
        ):
            common = {
                "boot_id": "b", "batch_id": state,
                "state": state, "condition": "baseline",
            }
            rows.append({
                **common, "method": analysis.STRUCTURAL,
                "alert": proposed_alert,
            })
            rows.append({
                **common, "method": analysis.TIMING,
                "alert": timing_alert,
            })
        proposed = analysis._metrics(rows, analysis.STRUCTURAL)
        timing = analysis._metrics(rows, analysis.TIMING)
        self.assertEqual(proposed["hiding_active_separation"], 1.0)
        self.assertEqual(timing["hiding_active_separation"], 0.0)


if __name__ == "__main__":
    unittest.main()
