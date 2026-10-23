"""Literal counter fixtures exercise the pure coverage validity boundary."""

import json
import unittest

from phase1.coverage import combine_verdict, compare_window, parse_profile


EVENTS = ["p_filldir64", "r_filldir64"]
BEFORE = "p_filldir64 12 0\nr_filldir64 12 0\n"
AFTER = "p_filldir64 20 0\nr_filldir64 20 0\n"


class ProfileTests(unittest.TestCase):
    def test_parse_retains_exact_names_and_integer_counters(self):
        self.assertEqual(
            parse_profile(" \tp_filldir64  12 0\n\nr_filldir64\t17\t3\n"),
            {"p_filldir64": {"hits": 12, "missed": 0},
             "r_filldir64": {"hits": 17, "missed": 3}},
        )

    def test_parse_rejects_empty_or_missing_source(self):
        for text in ("", " \n\t", None, {}, b"p_filldir64 1 0"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_profile(text)

    def test_parse_rejects_duplicate_event_even_when_counts_match(self):
        with self.assertRaises(ValueError):
            parse_profile("p_filldir64 12 0\np_filldir64 12 0\n")

    def test_parse_rejects_missing_extra_or_malformed_columns(self):
        for line in ("p_filldir64", "p_filldir64 12", "p_filldir64 12 0 extra",
                     "p_filldir64 NaN 0", "p_filldir64 1.0 0",
                     "p_filldir64 1 0x0", "p_filldir64 +1 0",
                     "p_filldir64 １２ 0", "p_filldir64 -1 0",
                     "p_filldir64 1 -1"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_profile(line)


class WindowTests(unittest.TestCase):
    def assert_unavailable(self, result):
        self.assertFalse(result["available"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["reasons"])
        json.dumps(result, allow_nan=False)

    def test_complete_zero_miss_window_is_valid(self):
        result = compare_window(BEFORE, AFTER, EVENTS)
        self.assertTrue(result["available"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["reasons"], [])
        self.assertEqual(result["missed_scope"], "global")
        self.assertEqual(result["per_event"], {
            "p_filldir64": {"hits_delta": 8, "missed_delta": 0},
            "r_filldir64": {"hits_delta": 8, "missed_delta": 0},
        })
        json.dumps(result, allow_nan=False)

    def test_parsed_dicts_use_the_same_contract(self):
        before = {"p_filldir64": {"hits": 12, "missed": 4},
                  "r_filldir64": {"hits": 12, "missed": 2}}
        after = {"p_filldir64": {"hits": 20, "missed": 4},
                 "r_filldir64": {"hits": 17, "missed": 2}}
        result = compare_window(before, after, EVENTS)
        self.assertTrue(result["valid"])
        self.assertEqual(result["per_event"]["r_filldir64"]["hits_delta"], 5)

    def test_missing_snapshot_never_becomes_zero(self):
        for missing in (None, "", {}, " \n"):
            for before, after in ((missing, AFTER), (BEFORE, missing)):
                with self.subTest(before=before, after=after):
                    result = compare_window(before, after, EVENTS)
                    self.assert_unavailable(result)
                    self.assertIsNone(result["per_event"]["r_filldir64"]["missed_delta"])

    def test_parse_errors_fail_closed_instead_of_raising_or_using_partial_data(self):
        for bad in (BEFORE + "p_filldir64 12 0\n", BEFORE + "other garbage 0\n"):
            for before, after in ((bad, AFTER), (BEFORE, bad)):
                with self.subTest(before=before, after=after):
                    result = compare_window(before, after, EVENTS)
                    self.assert_unavailable(result)
                    self.assertIsNone(result["per_event"]["p_filldir64"]["hits_delta"])

    def test_exact_identity_cannot_be_replaced_by_an_unrelated_event(self):
        for wrong in ("r_filldir640", "R_filldir64", "group/r_filldir64"):
            with self.subTest(wrong=wrong):
                result = compare_window(BEFORE, f"p_filldir64 20 0\n{wrong} 20 0\n", EVENTS)
                self.assert_unavailable(result)
                self.assertIsNone(result["per_event"]["r_filldir64"]["missed_delta"])

    def test_unrelated_events_do_not_replace_or_rename_expected_events(self):
        result = compare_window(BEFORE + "other 10 0\n", AFTER + "other 11 0\n", EVENTS)
        self.assertTrue(result["valid"])
        self.assertEqual(set(result["per_event"]), set(EVENTS))

    def test_missing_parsed_counter_does_not_default_to_zero(self):
        for record in ({"hits": 20}, {"missed": 0}, {}, {"hits": 20, "missed": None}):
            with self.subTest(record=record):
                result = compare_window(BEFORE, {"p_filldir64": record,
                    "r_filldir64": {"hits": 20, "missed": 0}}, EVENTS)
                self.assert_unavailable(result)

    def test_parsed_counters_must_be_nonnegative_integers_excluding_booleans(self):
        for field in ("hits", "missed"):
            for bad in (-1, 1.0, "1", True, False, None, float("nan")):
                record = {"hits": 20, "missed": 0}
                record[field] = bad
                with self.subTest(field=field, bad=bad):
                    result = compare_window(BEFORE, {"p_filldir64": record,
                        "r_filldir64": {"hits": 20, "missed": 0}}, EVENTS)
                    self.assert_unavailable(result)

    def test_both_counter_resets_invalidate_without_clamping_negative_deltas(self):
        result = compare_window("p_filldir64 12 4\nr_filldir64 12 2\n",
                                "p_filldir64 1 0\nr_filldir64 17 2\n", EVENTS)
        self.assertTrue(result["available"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["reasons"])
        self.assertEqual(result["per_event"]["p_filldir64"],
                         {"hits_delta": -11, "missed_delta": -4})

    def test_hits_reset_alone_invalidates(self):
        result = compare_window(BEFORE, "p_filldir64 1 0\nr_filldir64 20 0\n", EVENTS)
        self.assertTrue(result["available"])
        self.assertFalse(result["valid"])

    def test_missed_reset_alone_invalidates(self):
        result = compare_window("p_filldir64 12 4\nr_filldir64 12 0\n", AFTER, EVENTS)
        self.assertTrue(result["available"])
        self.assertFalse(result["valid"])

    def test_global_missed_increment_invalidates_whole_window(self):
        result = compare_window(BEFORE, "p_filldir64 20 0\nr_filldir64 17 3\n", EVENTS)
        self.assertTrue(result["available"])
        self.assertFalse(result["valid"])
        self.assertEqual(result["missed_scope"], "global")
        self.assertEqual(result["per_event"]["r_filldir64"]["missed_delta"], 3)
        self.assertTrue(any("global" in reason for reason in result["reasons"]))
        self.assertEqual(combine_verdict(True, True, result), "invalid")

    def test_empty_duplicate_or_malformed_expected_identities_invalidate(self):
        for expected in (None, [], EVENTS + ["p_filldir64"], "p_filldir64",
                         [""], [None], ["r_filldir64 "], [123]):
            with self.subTest(expected=expected):
                self.assert_unavailable(compare_window(BEFORE, AFTER, expected))

    def test_record_with_malformed_identity_or_shape_fails_closed(self):
        for bad in ({None: {"hits": 1, "missed": 0}},
                    {"": {"hits": 1, "missed": 0}},
                    {"bad name": {"hits": 1, "missed": 0}},
                    {"p_filldir64": [20, 0]},
                    {"p_filldir64": {"hits": 20, "missed": 0, "extra": 1}}):
            with self.subTest(bad=bad):
                self.assert_unavailable(compare_window(bad, AFTER, EVENTS))


class VerdictTests(unittest.TestCase):
    def test_valid_original_completion_and_coverage_allow_fingerprint_verdict(self):
        coverage = compare_window(BEFORE, AFTER, EVENTS)
        self.assertEqual(combine_verdict(True, True, coverage), "equal")
        self.assertEqual(combine_verdict(True, False, coverage), "different")

    def test_missing_or_failed_original_completion_always_invalidates(self):
        coverage = compare_window(BEFORE, AFTER, EVENTS)
        for original in (None, False, {}, "complete", 1):
            with self.subTest(original=original):
                self.assertEqual(combine_verdict(original, True, coverage), "invalid")
                self.assertEqual(combine_verdict(original, False, coverage), "invalid")

    def test_coverage_failure_dominates_both_fingerprint_states(self):
        for coverage in (None, {}, {"valid": True}, {"available": True},
                         {"available": False, "valid": True},
                         {"available": True, "valid": False},
                         {"available": 1, "valid": 1},
                         {"available": True, "valid": True, "reasons": ["error"]}):
            for equal in (True, False):
                with self.subTest(coverage=coverage, equal=equal):
                    self.assertEqual(combine_verdict(True, equal, coverage), "invalid")

    def test_unknown_fingerprint_status_is_invalid(self):
        coverage = compare_window(BEFORE, AFTER, EVENTS)
        for equal in (None, "equal", 0, 1):
            with self.subTest(equal=equal):
                self.assertEqual(combine_verdict(True, equal, coverage), "invalid")


if __name__ == "__main__":
    unittest.main()
