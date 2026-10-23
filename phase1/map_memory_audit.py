"""Read kernel-reported map metadata; no probes are attached."""

import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phase1 import run_experiments as runner

if os.geteuid() != 0 or ROOT != Path("/home/kicba/research_phase1_20261023"):
    raise RuntimeError("protected guest root required")
runner.runtime()
bpf = runner.new_bpf(4)
record = {"bpf_source_sha256": runner.sha(ROOT / "phase1/bpf_measurement.c"),
          "audit_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "probes_attached": False, "maps": {}}
try:
    for name in ("monitored_pids", "collection_enabled", "hash_seeds", "iblt_cell_count",
                 "depth_by_pid", "pending_by_pid", "kernel_fingerprints", "kernel_iblt", "stats_by_pid"):
        table = bpf[name]
        descriptor = table.map_fd
        raw = Path(f"/proc/self/fdinfo/{descriptor}").read_text()
        fields = dict(line.split(":", 1) for line in raw.splitlines() if ":" in line)
        record["maps"][name] = {"raw_fdinfo": raw,
            "fields": {key: value.strip() for key, value in fields.items()}}
finally:
    bpf.cleanup()
runner.save(ROOT / "evidence/map_memory_audit.json", record)
print(json.dumps({name: values["fields"] for name, values in record["maps"].items()}))
