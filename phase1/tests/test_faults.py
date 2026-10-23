"""Record real configuration/state faults separately from confirmation data."""

import ctypes as ct
import hashlib
import json
import os
import subprocess
import unittest
from pathlib import Path

from phase1 import run_experiments as runner


PROTECTED = (os.name == "posix" and getattr(os, "geteuid", lambda: -1)() == 0
             and runner.ROOT == Path("/home/kicba/research_phase1_20261023"))


@unittest.skipUnless(PROTECTED, "requires the protected native VM and its checkpoint")
class FaultChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runner.runtime()
        lock = json.loads((runner.ROOT / "phase1/LOCK.json").read_text())
        if not lock["checkpoint"]["success"]:
            raise RuntimeError("checkpoint required")
        for family in ([], ["-6"]):
            if subprocess.run(["ip", *family, "route", "show", "default"],
                              capture_output=True, text=True, check=True).stdout.strip():
                raise RuntimeError("default route present")
        if runner._loaded_modules() & runner.KNOWN_MODULES:
            raise RuntimeError("do not disturb an existing module experiment")
        cls.output = runner.ROOT / "evidence/fault_checks_attempt1"
        cls.output.mkdir(exist_ok=False)
        cls.fixture = runner._build_fixture(cls.output, 512, 16, "ascii")
        runner.save(cls.output / "manifest.json", {
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "protocol_sha256": runner.sha(runner.ROOT / "phase1/FAULT_CHECK_PROTOCOL_zh-TW.md"),
            "test_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "original_cells": runner.CELLS,
        })

    def test_invalid_cell_configuration_is_invalid(self):
        bpf = runner.new_bpf(4)
        try:
            runner.attach(bpf)
            runner._set_array(bpf["iblt_cell_count"], 0, ct.c_uint(3))
            row = runner.one_scan(bpf, 4, self.fixture, 65536)
            runner.save(self.output / "invalid_cells.json", row)
            self.assertEqual(row["verdict"], "invalid")
            self.assertGreater(row["kernel_stats"]["iblt_update_failures"], 0)
        finally:
            bpf.cleanup()

    def test_seed_configuration_mismatch_is_invalid(self):
        bpf = runner.new_bpf(4)
        try:
            runner.attach(bpf)
            runner._set_array(bpf["hash_seeds"], 0, ct.c_ulonglong(runner.SEED1 ^ 1))
            row = runner.one_scan(bpf, 4, self.fixture, 65536)
            runner.save(self.output / "seed_mismatch.json", row)
            self.assertEqual(row["verdict"], "invalid")
        finally:
            bpf.cleanup()

    def check_injected_state(self, missing_stats):
        bpf = runner.new_bpf(4)
        process = None
        try:
            runner.attach(bpf)
            first = runner.snapshot()
            process = runner.begin_probe(bpf, 4, self.fixture, 65536)
            runner.release(process)
            stdout, stderr = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 0, stderr)
            visible = json.loads(stdout)
            before = runner.telemetry(bpf, process.pid, False)
            self.assertTrue(before["original_valid"])
            key = ct.c_uint(process.pid)
            if missing_stats:
                del bpf["stats_by_pid"][key]
            else:
                bpf["depth_by_pid"][key] = ct.c_uint(1)
            after = runner.telemetry(bpf, process.pid, False)
            last = runner.snapshot()
            coverage = runner.coverage_between(first, last)
            verdict = runner.combine_verdict(after["original_valid"],
                after["kernel_fingerprint"] == [visible["count"], visible["sum1"], visible["sum2"]], coverage)
            runner.save(self.output / ("missing_stats.json" if missing_stats else "unpaired_state.json"),
                        {"injection": "owned_map_state", "before": before, "after": after,
                         "coverage": coverage, "verdict": verdict, "userspace": visible})
            self.assertEqual(verdict, "invalid")
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
                runner.cleanup_pid(bpf, process.pid)
            bpf.cleanup()

    def test_missing_kernel_statistics_is_invalid(self):
        self.check_injected_state(True)

    def test_unpaired_state_is_invalid(self):
        self.check_injected_state(False)

    def test_capacity_failure_retains_difference_verdict(self):
        runner.CELLS = 8
        bpf = runner.new_bpf(4)
        try:
            runner.attach(bpf)
            modules = {"getdents_hiding": runner.ROOT / "attack_variants/d8_getdents_controls/kicba_d8_getdents_hiding.ko"}
            runner._set_state("getdents_hiding", modules)
            row = runner.one_scan(bpf, 4, self.fixture, 65536, readback=True, decode=True)
            runner.save(self.output / "valid_small_capacity.json", {"cells": 8, **row})
            self.assertTrue(row["original_valid"])
            self.assertFalse(row["decode_success"])
            self.assertEqual(row["verdict"], "different")
        finally:
            runner._unload_known()
            bpf.cleanup()
            runner.CELLS = 256
