"""Native-VM integration checks; diagnostics must keep acceptance semantics."""

import os
import tempfile
import unittest
from pathlib import Path

from phase1 import run_experiments as runner


@unittest.skipUnless(os.name == "posix" and getattr(os, "geteuid", lambda: -1)() == 0
                     and runner.ROOT == Path("/home/kicba/research_phase1_20261023"),
                     "requires root in the protected Linux VM")
class BPFVariantTests(unittest.TestCase):
    def test_additive_modes_keep_accepted_counts_and_full_fingerprint(self):
        runner.runtime()
        with tempfile.TemporaryDirectory(dir=runner.ROOT / "phase1") as directory:
            fixture = runner.make_simple_fixture(Path(directory) / "fixture", 16)
            for mode in range(5):
                with self.subTest(mode=mode):
                    bpf = runner.new_bpf(mode)
                    try:
                        runner.attach(bpf)
                        row = runner.one_scan(bpf, mode, fixture, 64,
                                              readback=mode == 4, decode=mode == 4)
                        self.assertTrue(row["original_valid"], row)
                        self.assertTrue(row["coverage"]["valid"], row)
                        self.assertEqual(row["userspace"]["count"], 18)
                        if mode:
                            self.assertEqual(row["kernel_fingerprint"][0], 18)
                        if mode == 2:
                            self.assertGreater(row["kernel_stats"]["name_read_checksum"], 0)
                        if mode >= 3:
                            self.assertEqual(row["verdict"], "equal")
                        if mode == 4:
                            self.assertTrue(row["decode_success"])
                            self.assertEqual((row["upstream_only"], row["downstream_only"]), ([], []))
                    finally:
                        bpf.cleanup()
