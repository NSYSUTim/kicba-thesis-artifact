"""Freeze reviewed experiment inputs before any confirmation boot."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
files = [ROOT / "phase1" / name for name in (
    "run_experiments.py", "run_confirmation.py", "coverage.py", "summarize.py",
    "record_environment.py", "bpf_measurement.c", "enum_probe.c", "bin/d9_enum_probe",
    "PROTOCOL_zh-TW.md", "LOCK.json", "create_confirmation_lock.py")]
files += [path for path in (ROOT / "collector").iterdir() if path.suffix in {".py", ".c", ".h"}]
files += list((ROOT / "src/kicba").glob("*.py"))
files += list((ROOT / "attack_variants").glob("*/*.ko"))
record = {
    "recorded_at": datetime.now(timezone.utc).isoformat(),
    "boot_indices": [1, 2, 3], "seeds": [1202302, 1202303, 1202304],
    "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in files},
    "pilot_review": {
        "coverage": "30/30 maxactive=1 windows induced real misses; 0 false-valid transactions; normal 30/30 equal",
        "fidelity": "60/60 expected outputs, no full-verdict or decode mismatch",
        "cost": "300 retained trials including 120 warmups; no invalid/count/load/difference failure",
        "prototype_changes": "Keep the observable name checksum in all modes >=2 for additive comparisons; save original pilot sources/hashes in manifests.",
    },
    "interpretation": "Diagnostic variants preserve acceptance semantics; additional checks and controller timing differ from the frozen original implementation. Do not overwrite the original 4.76x result.",
}
with (ROOT / "phase1/CONFIRMATION_LOCK.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2)
print(json.dumps({"frozen_files": len(files), "seeds": record["seeds"]}))
