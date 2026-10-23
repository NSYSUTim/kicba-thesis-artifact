"""Run exactly one fresh confirmation boot, restoring timer state afterward."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phase1.record_environment import inventory
from phase1.summarize import load, coverage_summary, fidelity_summary, cost_summary


def save(path, record):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)


def restore_timers(before):
    units = ["apt-daily.timer", "apt-daily-upgrade.timer", "apt-daily.service", "apt-daily-upgrade.service"]
    subprocess.run(["systemctl", "unmask", "--runtime", *units], check=True, capture_output=True)
    for unit in units[:2]:
        if "ActiveState=active" in before["update_units"][unit]["stdout"]:
            subprocess.run(["systemctl", "start", unit], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--boot-index", type=int, choices=(1, 2, 3), required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or ROOT != Path("/home/kicba/research_phase1_20261023"):
        raise RuntimeError("protected native VM root required")
    baseline = json.loads((ROOT / "environment_before.json").read_text())
    before = inventory()
    if before["kernel"] != baseline["kernel"] or before["package_inventory_sha256"] != baseline["package_inventory_sha256"]:
        raise RuntimeError("guest environment drift before confirmation")
    if before["boot_id"] == baseline["boot_id"]:
        raise RuntimeError("confirmation requires a fresh boot, not the pilot boot")
    for previous in (ROOT / "evidence/confirmation").glob("boot_*/environment_before.json"):
        if json.loads(previous.read_text())["boot_id"] == before["boot_id"]:
            raise RuntimeError("duplicate confirmation boot ID")
    output = ROOT / "evidence/confirmation" / ("boot_" + str(args.boot_index).zfill(2))
    output.mkdir(parents=True, exist_ok=False)
    save(output / "environment_before.json", before)
    summary = {"boot_index": args.boot_index, "boot_id": before["boot_id"], "completed": False}
    units = ["apt-daily.timer", "apt-daily-upgrade.timer", "apt-daily.service", "apt-daily-upgrade.service"]
    started = time.monotonic()
    try:
        subprocess.run(["systemctl", "stop", *units[:2]], check=True)
        subprocess.run(["systemctl", "mask", "--runtime", *units], check=True, capture_output=True)
        for service in units[2:]:
            if subprocess.run(["systemctl", "is-active", "--quiet", service]).returncode == 0:
                raise RuntimeError("package operation already active: " + service)
        for suite in ("coverage", "fidelity", "cost"):
            with (output / (suite + ".log")).open("x") as log:
                subprocess.run([sys.executable, str(ROOT / "phase1/run_experiments.py"), suite,
                                "--role", "confirmation", "--seed", str(1202301 + args.boot_index),
                                "--output", str(output / suite)],
                               check=True, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            rows = load(output / suite / "attempts.jsonl")
            if suite == "coverage":
                result = coverage_summary(rows)
                good = (result["maxactive_1"]["missed_windows"] >= 10
                        and result["maxactive_1"]["false_valid_when_missed"] == 0
                        and result["normal"] == {"windows": 30, "equal": 30, "different": 0,
                                                  "invalid": 0, "decode_failures": 0})
            elif suite == "fidelity":
                result = fidelity_summary(rows)
                good = result == {"trials": 600, "full_trials": 240, "setup_failures": 0,
                                  "output_mismatch": 0, "verdict_mismatch": 0, "decode_mismatch": 0}
            else:
                result = cost_summary(rows)
                good = (result["attempts"] == 720 and result["primary"] == 600
                        and result["excluded_primary"] == 0 and len(result["groups"]) == 60
                        and all(value["wall_ns"]["n"] == 10 for value in result["groups"].values()))
            summary[suite] = result
            save(output / (suite + "_summary.json"), result)
            if not good:
                raise RuntimeError("confirmation quality criterion failed: " + suite)
        summary["completed"] = True
    except BaseException as error:
        summary["error"] = repr(error)
        raise
    finally:
        try:
            restore_timers(before)
            summary["timers_restored"] = True
        except Exception as error:
            summary["timer_restore_error"] = repr(error)
            summary["completed"] = False
        after = inventory()
        save(output / "environment_after.json", after)
        summary["environment_unchanged"] = (
            after["kernel"] == before["kernel"]
            and after["package_inventory_sha256"] == before["package_inventory_sha256"])
        summary["elapsed_seconds"] = time.monotonic() - started
        save(output / "summary.json", summary)
        archive = ROOT / ("confirmation_boot_" + str(args.boot_index).zfill(2) + ".tar.gz")
        with tarfile.open(archive, "x:gz") as bundle:
            for path in sorted(output.rglob("*")):
                if path.is_file() and path.suffix in {".json", ".jsonl", ".log", ".txt"}:
                    bundle.add(path, arcname=str(path.relative_to(ROOT)), recursive=False)
        save(archive.with_suffix(archive.suffix + ".sha256.json"),
             {"filename": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()})
    if not summary["completed"] or not summary["environment_unchanged"]:
        raise RuntimeError("confirmation did not complete cleanly")
    print(json.dumps({"boot_index": args.boot_index, "boot_id": summary["boot_id"],
                      "completed": True, "elapsed_seconds": summary["elapsed_seconds"]}))


if __name__ == "__main__":
    main()
