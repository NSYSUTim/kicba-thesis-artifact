"""Verify retained archives before selectively extracting evidence for review."""

import hashlib
import json
import tarfile
from pathlib import Path

PHASE = Path(__file__).resolve().parent
downloads = PHASE / "evidence/downloads"
expected = json.loads((downloads / "phase1_exports.sha256.json").read_text())
for index in (1, 2, 3):
    path = downloads / f"confirmation_boot_{index:02d}.tar.gz.sha256.json"
    record = json.loads(path.read_text())
    expected[record["filename"]] = record["sha256"]
for name, digest in expected.items():
    if hashlib.sha256((downloads / name).read_bytes()).hexdigest() != digest:
        raise RuntimeError("archive checksum mismatch: " + name)
with tarfile.open(downloads / "phase1_pilot_and_faults.tar.gz") as bundle:
    for member in bundle.getmembers():
        if not member.isfile() or member.name.startswith("phase1/") or member.name.endswith(".tar"):
            continue
        destination = PHASE / member.name
        if destination.exists():
            payload = bundle.extractfile(member).read()
            if hashlib.sha256(destination.read_bytes()).digest() != hashlib.sha256(payload).digest():
                raise RuntimeError("conflicting existing evidence: " + member.name)
        else:
            bundle.extract(member, PHASE, filter="data")
lock = json.loads((PHASE / "CONFIRMATION_LOCK.json").read_text())
with tarfile.open(downloads / "phase1_frozen_sources.tar.gz") as bundle:
    for name, digest in lock["source_sha256"].items():
        if hashlib.sha256(bundle.extractfile(name).read()).hexdigest() != digest:
            raise RuntimeError("frozen source archive mismatch: " + name)
record = {"archives_verified": len(expected), "frozen_source_files_verified": len(lock["source_sha256"]),
          "archive_sha256": expected}
verification_path = PHASE / "evidence/EXPORT_VERIFICATION.json"
if verification_path.exists():
    if json.loads(verification_path.read_text()) != record:
        raise RuntimeError("saved archive verification differs")
else:
    with verification_path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
print(json.dumps({"archives_verified": len(expected), "frozen_source_files_verified": len(lock["source_sha256"])}))
