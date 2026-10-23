"""Verify and export evidence plus exact frozen source bytes from the guest."""

import hashlib
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phase1.record_environment import inventory

if ROOT != Path("/home/kicba/research_phase1_20261023"):
    raise RuntimeError("protected guest directory required")
before = json.loads((ROOT / "environment_before.json").read_text())
after = inventory()
lock = json.loads((ROOT / "phase1/CONFIRMATION_LOCK.json").read_text())
drift = [name for name, digest in lock["source_sha256"].items()
         if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest]
modules = [line.split()[0] for line in Path("/proc/modules").read_text().splitlines()
           if line.startswith(("kicba_d7_", "kicba_d8_", "kicba_d9_"))]
record = {
    "kernel_unchanged": after["kernel"] == before["kernel"],
    "packages_unchanged": after["package_inventory_sha256"] == before["package_inventory_sha256"],
    "timer_states": after["update_units"], "source_drift": drift,
    "known_modules_loaded": modules,
    "remaining_tracefs_probes": Path("/sys/kernel/debug/tracing/kprobe_events").read_text(),
}
with (ROOT / "final_verification.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2)
if not record["kernel_unchanged"] or not record["packages_unchanged"] or drift or modules:
    raise RuntimeError("final verification failed")
source_bundle = ROOT / "phase1_frozen_sources.tar.gz"
with tarfile.open(source_bundle, "x:gz") as bundle:
    for name in lock["source_sha256"]:
        bundle.add(ROOT / name, arcname=name, recursive=False)
    bundle.add(ROOT / "phase1/CONFIRMATION_LOCK.json", arcname="phase1/CONFIRMATION_LOCK.json")
extra_bundle = ROOT / "phase1_pilot_and_faults.tar.gz"
with tarfile.open(extra_bundle, "x:gz") as bundle:
    files = list(ROOT.glob("*.json")) + list(ROOT.glob("*.log")) + list(ROOT.glob("*.txt"))
    files += list((ROOT / "evidence/pilot").rglob("*"))
    files += list((ROOT / "evidence/fault_checks_attempt1").rglob("*"))
    files += [ROOT / "phase1/FAULT_CHECK_PROTOCOL_zh-TW.md", ROOT / "phase1/tests/test_faults.py"]
    # Retain the first deployed source versions as well as the final source lock.
    files += list(ROOT.glob("*attempt*.tar")) + list(ROOT.glob("*bootstrap.tar")) + list(ROOT.glob("*red.tar"))
    for path in sorted(set(files)):
        if path.is_file() and path.suffix in {".json", ".jsonl", ".log", ".txt", ".md", ".py", ".tar"}:
            bundle.add(path, arcname=str(path.relative_to(ROOT)), recursive=False)
with (ROOT / "phase1_exports.sha256.json").open("x", encoding="utf-8") as stream:
    json.dump({path.name: hashlib.sha256(path.read_bytes()).hexdigest()
               for path in (source_bundle, extra_bundle)}, stream, indent=2)
print(json.dumps(record))
