import unittest
from phase1.summarize import coverage_summary, cost_summary


class SummaryTests(unittest.TestCase):
    def test_missed_windows_count_invalid_verdicts_without_reclassifying_them(self):
        row = {"kind": "concurrent_loss", "maxactive": 1,
               "coverage": {"per_event": {"r": {"missed_delta": 3}}},
               "transactions": [{"verdict": "invalid"}, {"verdict": "equal"}]}
        result = coverage_summary([row])["maxactive_1"]
        self.assertEqual(result["missed_windows"], 1)
        self.assertEqual(result["transactions"], 2)
        self.assertEqual(result["false_valid_when_missed"], 1)

    def test_cost_summary_excludes_warmup_and_invalid_but_reports_their_counts(self):
        base = {"kind": "cost", "mode": "decode", "condition": "baseline",
                "cardinality": 512, "warmup": False, "count_matches": True,
                "load_active": True, "original_valid": True, "verdict": "equal",
                "decode_success": True, "upstream_only": [], "downstream_only": [],
                "userspace": {"scan_ns": 8}}
        rows = [dict(base, wall_ns=10, block=0), dict(base, wall_ns=20, block=1),
                dict(base, wall_ns=999, warmup=True, block=-1),
                dict(base, wall_ns=1, verdict="invalid", block=2)]
        result = cost_summary(rows)
        self.assertEqual(result["warmups"], 1)
        self.assertEqual(result["excluded_primary"], 1)
        group = result["groups"]["512/baseline/decode"]
        self.assertEqual(group["wall_ns"]["n"], 2)
        self.assertEqual(group["wall_ns"]["median"], 15)
