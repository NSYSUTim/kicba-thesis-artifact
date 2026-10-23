"""Compare against the unchanged original validity function, after confirmation.

This separate replay resolves an interpretation issue: the diagnostic runner's
original_valid field also includes an extra accounting invariant, so it cannot
by itself be reported as the unchanged historical implementation's decision.
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phase1 import run_experiments as runner

if ROOT != Path("/home/kicba/research_phase1_20261023") or os.geteuid() != 0:
    raise RuntimeError("protected guest root required")
runner.runtime()
from run_d9_reconciliation_smoke import result_for_pid
output = ROOT / "evidence/original_gate_reference_attempt1"
output.mkdir(exist_ok=False)
fixture = runner.make_simple_fixture(output / "fixture", 8192)
runner.save(output / "manifest.json", {
    "purpose": "supplemental unchanged original-function replay, not confirmation data",
    "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    "reference_source_sha256": runner.sha(ROOT / "collector/run_d9_reconciliation_smoke.py"),
    "replay_source_sha256": runner.sha(Path(__file__)),
    "design": {"maxactive": [1, 256], "workers": [4, 8, 16], "scans_per_worker": 2},
})
with (output / "attempts.jsonl").open("x") as stream:
    for active in (1, 256):
        bpf = runner.new_bpf(4)
        try:
            runner.attach(bpf, active)
            for workers in (4, 8, 16):
                first = runner.snapshot()
                records = []
                for _ in range(2):
                    processes = [runner.begin_probe(bpf, 4, fixture, 65536) for _ in range(workers)]
                    for process in processes:
                        runner.release(process)
                    for process in processes:
                        row = {"pid": process.pid}
                        try:
                            stdout, stderr = process.communicate(timeout=60)
                            row.update(returncode=process.returncode, stderr=stderr)
                            if process.returncode:
                                raise RuntimeError("C probe failed")
                            visible = json.loads(stdout)
                            key = runner.ct.c_uint(process.pid)
                            depth = bpf["depth_by_pid"].get(key)
                            row["depth_at_original_check"] = None if depth is None else int(depth.value)
                            row["pending_present_at_original_check"] = bpf["pending_by_pid"].get(key) is not None
                            old = result_for_pid(bpf, process.pid, visible, runner.CELLS, runner.SEED1, runner.SEED2)
                            row["original_result"] = old
                            row["original_valid"] = old["measurement_valid"]
                        except Exception as error:
                            row.update(original_valid=False, original_pipeline_error=repr(error))
                        finally:
                            if process.poll() is None:
                                process.kill()
                                process.communicate()
                            runner.cleanup_pid(bpf, process.pid)
                        records.append(row)
                last = runner.snapshot()
                coverage = runner.coverage_between(first, last)
                runner.emit(stream, {"maxactive": active, "workers": workers,
                                     "coverage": coverage, "coverage_before": first,
                                     "coverage_after": last, "transactions": records})
        finally:
            bpf.cleanup()
print(json.dumps({"completed": True, "output": str(output)}))
