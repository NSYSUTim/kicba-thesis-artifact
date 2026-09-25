from __future__ import annotations

import random
import unittest

from kicba.reconciliation import (
    IBLT,
    MultisetFingerprint,
    recommended_cell_count,
    token_for_entry,
)


SEED1 = 0x0123456789ABCDEF
SEED2 = 0xF0E1D2C3B4A59687


def tokens(count: int, prefix: str = "entry"):
    return [
        token_for_entry(f"{prefix}_{index:06d}", 1000 + index, 8, SEED1, SEED2)
        for index in range(count)
    ]


class D9ReconciliationTests(unittest.TestCase):
    def test_fingerprint_is_order_independent_and_multiplicity_sensitive(self):
        values = tokens(100)
        shuffled = values[:]
        random.Random(42).shuffle(shuffled)
        self.assertEqual(
            MultisetFingerprint.from_tokens(values).as_tuple(),
            MultisetFingerprint.from_tokens(shuffled).as_tuple(),
        )
        self.assertNotEqual(
            MultisetFingerprint.from_tokens(values).as_tuple(),
            MultisetFingerprint.from_tokens(values + [values[0]]).as_tuple(),
        )

    def test_equal_cardinality_substitution_is_detected_and_recovered(self):
        upstream = tokens(128)
        downstream = upstream[:-1] + tokens(1, "injected")
        self.assertNotEqual(
            MultisetFingerprint.from_tokens(upstream).as_tuple(),
            MultisetFingerprint.from_tokens(downstream).as_tuple(),
        )
        left = IBLT.from_tokens(upstream, 16, SEED1, SEED2)
        right = IBLT.from_tokens(downstream, 16, SEED1, SEED2)
        decoded = left.subtract(right).decode()
        self.assertTrue(decoded.success)
        self.assertEqual(decoded.upstream_only, (upstream[-1],))
        self.assertEqual(decoded.downstream_only, (downstream[-1],))

    def test_large_directory_with_small_difference_uses_difference_sized_table(self):
        upstream = tokens(20_000)
        missing_indices = {3, 907, 9_999, 19_999}
        downstream = [
            token for index, token in enumerate(upstream)
            if index not in missing_indices
        ]
        cells = recommended_cell_count(len(missing_indices), factor=4)
        decoded = IBLT.from_tokens(
            upstream, cells, SEED1, SEED2
        ).subtract(
            IBLT.from_tokens(downstream, cells, SEED1, SEED2)
        ).decode()
        self.assertTrue(decoded.success)
        self.assertEqual(set(decoded.upstream_only), {
            upstream[index] for index in missing_indices
        })
        self.assertEqual(decoded.downstream_only, ())

    def test_over_capacity_is_an_honest_unresolved_result(self):
        upstream = tokens(200)
        downstream = upstream[100:]
        decoded = IBLT.from_tokens(
            upstream, 8, SEED1, SEED2
        ).subtract(
            IBLT.from_tokens(downstream, 8, SEED1, SEED2)
        ).decode()
        self.assertFalse(decoded.success)
        self.assertGreater(decoded.residual_cells, 0)
        self.assertNotEqual(
            MultisetFingerprint.from_tokens(upstream).as_tuple(),
            MultisetFingerprint.from_tokens(downstream).as_tuple(),
        )

    def test_zero_difference_decodes_empty(self):
        values = tokens(1_000)
        difference = IBLT.from_tokens(
            values, 32, SEED1, SEED2
        ).subtract(
            IBLT.from_tokens(reversed(values), 32, SEED1, SEED2)
        ).decode()
        self.assertTrue(difference.success)
        self.assertEqual(difference.upstream_only, ())
        self.assertEqual(difference.downstream_only, ())

    def test_parameter_mismatch_is_rejected(self):
        left = IBLT(16, SEED1, SEED2)
        right = IBLT(32, SEED1, SEED2)
        with self.assertRaises(ValueError):
            left.subtract(right)

    def test_recommended_size_is_power_of_two(self):
        for difference in range(100):
            size = recommended_cell_count(difference)
            self.assertGreaterEqual(size, 4)
            self.assertEqual(size & (size - 1), 0)


if __name__ == "__main__":
    unittest.main()
