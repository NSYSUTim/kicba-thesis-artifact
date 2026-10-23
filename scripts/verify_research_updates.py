"""Verify published supplements without rewriting historical reports or locks.

The original report builders also audited a particular pair of local checkouts.
This portable entry point instead verifies immutable Git baselines, permits only
the explicitly listed catalog updates, and writes a separate verification file.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CATALOG_UPDATES = {
    "README.md", "ARTIFACT_SCOPE.md", "THIRD_PARTY_NOTICES.md",
    "FILE_SHA256.csv", "docs/METHOD_AND_NEXT_STEPS_zh-TW.md",
}


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def check_snapshot(ref, expected):
    queries = "".join(f"{ref}:{name}\n" for name in expected).encode()
    process = subprocess.run(["git", "cat-file", "--batch"], input=queries,
                             cwd=ROOT, capture_output=True, check=True)
    payload = process.stdout
    offset = 0
    for name, digest in expected.items():
        end = payload.index(b"\n", offset)
        header = payload[offset:end].split()
        if len(header) != 3 or header[1] != b"blob":
            raise RuntimeError("Missing Git baseline; use a clone with history: " + ref + ":" + name)
        size = int(header[2]); start = end + 1
        if sha(payload[start:start + size]) != digest:
            raise RuntimeError("Historical baseline differs: " + ref + ":" + name)
        offset = start + size + 1
    return len(expected)


def unpack_evidence(archive, phase):
    allowed = ROOT / phase / "evidence"
    with tarfile.open(archive) as bundle:
        for member in bundle:
            if not member.isfile():
                continue
            name = PurePosixPath(member.name)
            if "\\" in member.name or name.is_absolute() or ".." in name.parts:
                raise RuntimeError("Unsafe archive member: " + member.name)
            parts = name.parts
            if phase == "phase1" and parts[0] == "evidence":
                parts = (phase, *parts)
            if parts[:2] != (phase, "evidence"):
                continue  # Never unpack executable sources or nested deployment archives.
            destination = ROOT.joinpath(*parts)
            destination.resolve().relative_to(allowed.resolve())
            data = bundle.extractfile(member).read()
            if destination.exists():
                if sha(destination.read_bytes()) != sha(data):
                    raise RuntimeError("Conflicting retained evidence: " + str(destination))
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as stream:
                    stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recompute", action="store_true", help="Unpack verified evidence and independently recompute summaries/output checks")
    parser.add_argument("--output", type=Path, required=True, help="New derived JSON; existing files are never replaced")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    first = read(ROOT / "phase1/LOCK.json")
    second = read(ROOT / "phase2/LOCK.json")
    snapshots = {
        first["base_commit"]: check_snapshot(first["base_commit"], first["original_tracked_sha256"]),
        second["base_commit"]: check_snapshot(second["base_commit"], second["original_and_phase1_sha256"]),
    }
    changed_catalog = []
    for name, digest in second["original_and_phase1_sha256"].items():
        if sha((ROOT / name).read_bytes()) != digest:
            if name not in CATALOG_UPDATES:
                raise RuntimeError("Protected baseline file changed: " + name)
            changed_catalog.append(name)
    result = {"historical_snapshots_verified": snapshots,
              "explicit_catalog_updates": changed_catalog, "archives": {}, "frozen_sources": {}}
    for phase, evidence in (("phase1", "FINAL_VERIFICATION.json"), ("phase2", "EXPORT_VERIFICATION.json")):
        record = read(ROOT / phase / "evidence" / evidence)
        directory = ROOT / phase / "evidence/downloads"
        for name, digest in record["archive_sha256"].items():
            path = directory / name
            if sha(path.read_bytes()) != digest:
                raise RuntimeError("Archive checksum mismatch: " + str(path))
            result["archives"][phase + "/" + name] = digest
            if args.recompute and "frozen_sources" not in name:
                unpack_evidence(path, phase)
    source_sets = [("phase1/CONFIRMATION_LOCK.json", "phase1/evidence/downloads/phase1_frozen_sources.tar.gz")]
    source_sets += [(f"phase2/locks/{tag}.json", f"phase2/evidence/downloads/frozen_sources_{tag}.tar.gz")
                    for tag in ("kernel65", "kernel68")]
    for lock_path, archive_path in source_sets:
        lock = read(ROOT / lock_path)
        with tarfile.open(ROOT / archive_path) as bundle:
            for name, digest in lock["source_sha256"].items():
                if sha(bundle.extractfile(name).read()) != digest:
                    raise RuntimeError("Frozen source mismatch: " + name)
                current = ROOT / name
                if current.is_file() and sha(current.read_bytes()) != digest:
                    # Kernel-specific .ko bytes are checked inside each own archive.
                    if current.suffix != ".ko":
                        raise RuntimeError("Current frozen input changed: " + name)
        result["frozen_sources"][lock_path] = len(lock["source_sha256"])
    if args.recompute:
        from phase1.summarize import load, coverage_summary, fidelity_summary, cost_summary
        from phase2.summary import summarize
        from phase2.analysis.make_report import audit_static, audit_dynamic, audit_native
        phase1 = []
        for i in (1, 2, 3):
            folder = ROOT / f"phase1/evidence/confirmation/boot_{i:02d}"
            saved = read(folder / "summary.json")
            derived = {"coverage": coverage_summary(load(folder / "coverage/attempts.jsonl")),
                       "fidelity": fidelity_summary(load(folder / "fidelity/attempts.jsonl")),
                       "cost": cost_summary(load(folder / "cost/attempts.jsonl"))}
            if any(saved[key] != value for key, value in derived.items()):
                raise RuntimeError("Phase-one summary differs: " + str(i))
            phase1.append({"boot_id": saved["boot_id"], "coverage": derived["coverage"],
                           "fidelity": derived["fidelity"], "cost_primary": derived["cost"]["primary"]})
        phase2 = []; native = {}
        for tag in ("kernel68", "kernel65"):
            lock = read(ROOT / f"phase2/locks/{tag}.json")
            native[tag] = audit_native(tag, lock)
            for i in (1, 2, 3):
                folder = ROOT / f"phase2/evidence/{tag}/confirmation_boot_{i:02d}"
                saved = read(folder / "summary.json")
                rows = load(folder / "campaign/attempts.jsonl")
                derived = summarize(rows)
                if any(saved[key] != derived[key] for key in ("quality", "cost")) or not saved["completed"]:
                    raise RuntimeError("Phase-two summary differs: " + tag + "/" + str(i))
                audits = {"static": audit_static(folder / "campaign", rows),
                          "dynamic": audit_dynamic(folder / "campaign", rows)}
                if any(value for audit in audits.values() for key, value in audit.items() if key != "trials"):
                    raise RuntimeError("Raw output audit failed: " + str(audits))
                phase2.append({"environment": tag, "boot_id": saved["boot_id"],
                               "quality": derived["quality"], "raw_audit": audits,
                               "paired_65536_baseline": derived["cost"]["paired"]["65536/baseline"]})
        if len({b["boot_id"] for b in phase1 + phase2}) != 9:
            raise RuntimeError("Supplement confirmation boot IDs are not distinct")
        result.update(phase1=phase1, phase2=phase2, native_checks=native)
    result["passed"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
    print(json.dumps({"passed": True, "archives": len(result["archives"]),
                      "source_files": result["frozen_sources"], "recomputed": args.recompute,
                      "output": str(args.output)}, ensure_ascii=True))


if __name__ == "__main__":
    main()
