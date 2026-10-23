import unittest

from phase1.run_experiments import cost_blocks, canonical_records


class RunnerContractTests(unittest.TestCase):
    def test_each_random_block_contains_every_cost_mode_once(self):
        expected = {"parse", "user_fp", "user_iblt", "empty", "bookkeeping",
                    "names", "kernel_fp", "kernel_iblt", "readback", "decode"}
        blocks = cost_blocks(1202301, 10)
        self.assertEqual(len(blocks), 10)
        for block in blocks:
            self.assertEqual(set(block), expected)
            self.assertEqual(len(block), 10)
        self.assertNotEqual(blocks[0], blocks[1])
        self.assertEqual(blocks, cost_blocks(1202301, 10))

    def test_exact_record_comparison_keeps_multiplicity_and_name_bytes(self):
        one = {"name_hex": "ff61", "inode": 101, "d_type": 8}
        self.assertEqual(canonical_records([one]), [(b"\xffa", 101, 8)])
        self.assertEqual(len(canonical_records([one, one])), 2)
        self.assertNotEqual(canonical_records([one]), canonical_records([one, one]))

    def test_malformed_exact_record_cannot_be_treated_as_valid_empty_output(self):
        for row in ({}, {"name_hex": "zz", "inode": 1, "d_type": 8},
                    {"name_hex": "61", "inode": -1, "d_type": 8},
                    {"name_hex": "61", "inode": 1, "d_type": True}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                canonical_records([row])
