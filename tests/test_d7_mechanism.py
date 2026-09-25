from __future__ import annotations

import importlib
import sys
import types
import unittest
from collections import Counter


class D7MechanismScheduleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.modules.setdefault("bcc", types.SimpleNamespace(BPF=object))
        cls.campaign = importlib.import_module(
            "run_d7_mechanism_qualification"
        )
        cls.campaign_r2 = importlib.import_module(
            "run_d7_mechanism_qualification_r2"
        )

    def test_randomized_balanced_schedule(self):
        schedule = self.campaign.build_schedule(10701)
        self.assertEqual(len(schedule), self.campaign.EXPECTED_BATCHES)
        self.assertEqual(
            Counter((row["state"], row["condition"]) for row in schedule),
            Counter({
                (state, condition): self.campaign.REPLICATES
                for state in self.campaign.STATES
                for condition in self.campaign.CONDITIONS
            }),
        )
        self.assertEqual(
            [row["position"] for row in schedule],
            list(range(self.campaign.EXPECTED_BATCHES)),
        )
        self.assertNotEqual(
            [(row["state"], row["condition"]) for row in schedule],
            sorted((row["state"], row["condition"]) for row in schedule),
        )

    def test_r2_randomized_balanced_schedule(self):
        schedule = self.campaign_r2.build_schedule(10702)
        self.assertEqual(len(schedule), self.campaign_r2.EXPECTED_BATCHES)
        self.assertEqual(
            Counter((row["state"], row["condition"]) for row in schedule),
            Counter({
                (state, condition): self.campaign_r2.REPLICATES
                for state in self.campaign_r2.STATES
                for condition in self.campaign_r2.CONDITIONS
            }),
        )
        self.assertEqual(
            [row["position"] for row in schedule],
            list(range(self.campaign_r2.EXPECTED_BATCHES)),
        )

    def test_nesting_schedule_is_randomized_and_balanced(self):
        nesting = importlib.import_module("run_d7_nesting_pilot")
        schedule = nesting.build_schedule(10707)
        self.assertEqual(len(schedule), 48)
        self.assertEqual(
            Counter((row["state"], row["condition"]) for row in schedule),
            Counter({
                (state, condition): nesting.REPLICATES
                for state in nesting.STATES
                for condition in nesting.CONDITIONS
            }),
        )
        self.assertEqual(
            [row["position"] for row in schedule], list(range(48))
        )


if __name__ == "__main__":
    unittest.main()
