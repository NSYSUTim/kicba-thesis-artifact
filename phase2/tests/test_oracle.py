import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
try:
    from phase2 import oracle
except ImportError:
    oracle = None


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(oracle, 'phase-two oracle is not implemented')
        self.rows = [{'name_hex': b'.'.hex(), 'inode': 11, 'd_type': 4},
                     {'name_hex': b'phase2_subject'.hex(), 'inode': 22, 'd_type': 8},
                     {'name_hex': b'other'.hex(), 'inode': 33, 'd_type': 8}]

    def test_reordering_does_not_change_multiset(self):
        output = oracle.transform(self.rows, 'reorder')
        self.assertEqual(oracle.identities(output), oracle.identities(self.rows))
        self.assertEqual(oracle.difference(self.rows, output), ([], []))

    def test_inode_and_type_change_only_designated_field(self):
        for action, field, value in [('inode', 'inode', 22 ^ (1 << 62)),
                                      ('type', 'd_type', 4)]:
            with self.subTest(action=action):
                expected = [dict(r) for r in self.rows]
                expected[1][field] = value
                output = oracle.transform(self.rows, action)
                self.assertEqual(output, expected)
                up, down = oracle.difference(self.rows, output)
                self.assertEqual((len(up), len(down)), (1, 1))

    def test_name_length_changes_preserve_count(self):
        for action, name in [('grow', b'phase2_subject_much_longer_name'), ('shrink', b'p2x')]:
            with self.subTest(action=action):
                output = oracle.transform(self.rows, action)
                self.assertEqual(len(output), 3)
                self.assertEqual(bytes.fromhex(output[1]['name_hex']), name)
                self.assertEqual((output[1]['inode'], output[1]['d_type']), (22, 8))
                self.assertEqual(tuple(map(len, oracle.difference(self.rows, output))), (1, 1))

    def test_insert_and_remove_have_signed_single_difference(self):
        output = oracle.transform(self.rows, 'insert')
        self.assertEqual(output[-1], {'name_hex': b'phase2_inserted'.hex(),
                                      'inode': 0x7fff000000000123, 'd_type': 8})
        self.assertEqual(tuple(map(len, oracle.difference(self.rows, output))), (0, 1))
        output = oracle.transform(self.rows, 'remove')
        self.assertEqual(output, [self.rows[0], self.rows[2]])
        self.assertEqual(tuple(map(len, oracle.difference(self.rows, output))), (1, 0))

    def test_duplicate_identity_is_not_collapsed(self):
        self.assertEqual(tuple(map(len, oracle.difference(self.rows, self.rows + [self.rows[-1]]))), (0, 1))

    def test_unknown_action_and_missing_subject_are_rejected(self):
        with self.assertRaises(ValueError):
            oracle.transform(self.rows, 'nonsense')
        with self.assertRaises(ValueError):
            oracle.transform(self.rows[:1], 'inode')


if __name__ == '__main__':
    unittest.main()
