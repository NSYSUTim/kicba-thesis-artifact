"""Exercise the new Linux C diagnostic modes against independent fixtures."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from kicba.reconciliation import IBLT, MultisetFingerprint, token_for_entry


ROOT = Path(__file__).resolve().parents[2]
SEED1, SEED2 = 0x0123456789ABCDEF, 0xF0E1D2C3B4A59687


@unittest.skipUnless(os.name == "posix", "requires Linux getdents64")
class EnumVariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="phase1_c_tests_")
        cls.root = Path(cls.workspace.name)
        cls.binary = cls.root / "enum_probe"
        subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-std=gnu11",
                        str(ROOT / "phase1/enum_probe.c"), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root)
        self.fixture = Path(self.directory.name)
        (self.fixture / "alpha").touch()
        (self.fixture / "資料").touch()
        self.entries = [(b".", self.fixture.stat().st_ino, 4),
                        (b"..", self.fixture.parent.stat().st_ino, 4),
                        (b"alpha", (self.fixture / "alpha").stat().st_ino, 8),
                        ("資料".encode(), (self.fixture / "資料").stat().st_ino, 8)]
        self.tokens = [token_for_entry(*entry, SEED1, SEED2) for entry in self.entries]

    def tearDown(self):
        self.directory.cleanup()

    def run_probe(self, mode, dump=None, buffer=65536):
        args = [str(self.binary), str(self.fixture), str(buffer), "256", str(SEED1), str(SEED2), str(mode)]
        if dump is not None:
            args.append(str(dump))
        return subprocess.run(args, input="\n", capture_output=True, text=True, timeout=15)

    def test_parse_mode_counts_without_claiming_hashes(self):
        process = self.run_probe(0)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["count"], 4)
        self.assertEqual((result["sum1"], result["sum2"], result["cells"]), (0, 0, []))

    def test_fingerprint_mode_matches_independent_python_and_has_no_table(self):
        process = self.run_probe(1)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual((result["count"], result["sum1"], result["sum2"]),
                         MultisetFingerprint.from_tokens(self.tokens).as_tuple())
        self.assertEqual(result["cells"], [])

    def test_full_mode_table_cancels_against_independent_python(self):
        process = self.run_probe(2)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        rows = [[0, 0, 0, 0, 0] for _ in range(256)]
        for index, *cell in result["cells"]:
            rows[index] = cell
        decoded = IBLT.from_rows(rows, SEED1, SEED2).subtract(
            IBLT.from_tokens(self.tokens, 256, SEED1, SEED2)).decode()
        self.assertTrue(decoded.success)
        self.assertEqual((decoded.upstream_only, decoded.downstream_only), ((), ()))

    def test_exact_dump_retains_name_bytes_and_identity(self):
        dump = self.root / (self.fixture.name + ".jsonl")
        process = self.run_probe(2, dump=dump, buffer=64)
        self.assertEqual(process.returncode, 0, process.stderr)
        records = [json.loads(line) for line in dump.read_text().splitlines()]
        actual = {(bytes.fromhex(row["name_hex"]), row["inode"], row["d_type"]) for row in records}
        self.assertEqual(actual, set(self.entries))
        self.assertEqual(len(records), 4)

    def test_existing_dump_is_never_overwritten(self):
        dump = self.root / (self.fixture.name + ".existing")
        dump.write_text("keep this evidence\n")
        process = self.run_probe(2, dump=dump)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(dump.read_text(), "keep this evidence\n")

    def test_invalid_mode_or_numeric_arguments_are_rejected(self):
        for mode in (3, -1, "", "1bad", "18446744073709551616"):
            with self.subTest(mode=mode):
                self.assertNotEqual(self.run_probe(mode).returncode, 0)
        for buffer in (0, -1, "", "1bad", "18446744073709551616"):
            with self.subTest(buffer=buffer):
                self.assertNotEqual(self.run_probe(2, buffer=buffer).returncode, 0)


if __name__ == "__main__":
    unittest.main()
