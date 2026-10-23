"""Save immutable protocol and original tracked-file hashes for this phase."""

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


root = Path(__file__).resolve().parents[1]
output = root / "phase1" / "LOCK.json"
tracked = subprocess.run(["git", "ls-files", "-z"], cwd=root,
                         check=True, capture_output=True).stdout.decode().split("\0")
record = {
    "schema_version": 1,
    "recorded_at": datetime.now(timezone.utc).isoformat(),
    "base_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                                  capture_output=True, text=True, check=True).stdout.strip(),
    "protocol_sha256": hashlib.sha256((root / "phase1/PROTOCOL_zh-TW.md").read_bytes()).hexdigest(),
    "checkpoint": json.loads((root / "phase1/host/evidence/checkpoint.json").read_text(encoding="utf-8-sig")),
    "original_tracked_sha256": {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in tracked if name and not name.startswith("phase1/")
    },
    "pilot_seed": 1202301, "confirmation_seed": 1202302,
}
if not record["checkpoint"].get("success"):
    raise RuntimeError("checkpoint not verified")
with output.open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, ensure_ascii=False)
print(json.dumps({"output": str(output), "original_files": len(record["original_tracked_sha256"]),
                  "protocol_sha256": record["protocol_sha256"]}))
