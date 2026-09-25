#!/usr/bin/env python3
"""Pre-analysis integrity audit for frozen D6-r2 raw data."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROTOCOL = "D6-r2-2026-09-20"
EPISODES = [
    "normal_early",
    "normal_workloads",
    "attack",
    "recovery",
    "sham_control",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_local_file_hashes(files: dict) -> tuple[dict, list[str]]:
    hashes = {}
    failures = []
    for name, item in files.items():
        actual = _sha256(Path(item["path"]))
        hashes[name] = actual
        if actual != item["sha256"]:
            failures.append(f"local file hash mismatch: {name}")
    return hashes, failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--generic-audit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    state = json.loads(args.state.read_text(encoding="utf-8"))
    generic = json.loads(args.generic_audit.read_text(encoding="utf-8"))
    failures = []

    if lock.get("protocol_revision") != PROTOCOL:
        failures.append("lock protocol mismatch")
    file_hashes, hash_failures = verify_local_file_hashes(lock["files"])
    failures.extend(hash_failures)
    if state.get("protocol_revision") != PROTOCOL or state.get("status") != "complete":
        failures.append("state is not complete D6-r2")
    if len(state.get("completed_boots", [])) != 5:
        failures.append("state does not contain five completed boots")
    if state.get("multiboot_runner_sha256") != lock["files"][
        "multiboot_runner"
    ]["sha256"]:
        failures.append("state multiboot runner hash mismatch")
    if state.get("campaign_runner_sha256") != lock["files"][
        "campaign_runner"
    ]["sha256"]:
        failures.append("state campaign runner hash mismatch")
    if not generic.get("all_valid") or not generic.get("role_composition_match"):
        failures.append("generic raw audit failed")
    if generic.get("batches") != 2300 or generic.get("boots") != 5:
        failures.append("generic audit count mismatch")

    boot_dirs = sorted(
        path for path in args.input.iterdir()
        if path.is_dir() and path.name.startswith("boot_")
    )
    if [path.name for path in boot_dirs] != [f"boot_{i:02d}" for i in range(1, 6)]:
        failures.append("boot directory set mismatch")
    manifests = []
    manifest_hashes = {}
    for sequence, root in enumerate(boot_dirs, start=1):
        paths = list(root.glob("campaign_*.json"))
        if len(paths) != 1:
            failures.append(f"manifest count mismatch: {root.name}")
            continue
        manifest = json.loads(paths[0].read_text(encoding="utf-8"))
        manifest_hashes[root.name] = _sha256(paths[0])
        manifests.append(manifest)
        if (
            manifest.get("protocol_revision") != PROTOCOL
            or manifest.get("status") != "complete"
            or manifest.get("sequence") != sequence
        ):
            failures.append(f"manifest identity/status mismatch: {root.name}")
        schedule = manifest.get("schedule", [])
        if len(schedule) != 460 or any(
            item.get("status") != "complete" for item in schedule
        ):
            failures.append(f"manifest schedule incomplete: {root.name}")
        batch_count = len(list(root.glob("batch_*.json.gz")))
        if batch_count != 460:
            failures.append(f"raw batch count {batch_count}: {root.name}")
        expected_order = EPISODES[sequence - 1:] + EPISODES[:sequence - 1]
        if manifest.get("episode_order") != expected_order:
            failures.append(f"episode order mismatch: {root.name}")
        test = [item for item in schedule if item.get("phase") == "test"]
        counts = Counter(item.get("state") for item in test)
        if counts != {"unloaded": 180, "hiding": 160, "sham": 20}:
            failures.append(f"test state counts mismatch: {root.name}")
        if manifest.get("collector_sha256") != lock["files"]["collector"]["sha256"]:
            failures.append(f"collector hash mismatch: {root.name}")
        if manifest.get("bpf_source_sha256") != lock["files"]["bpf"]["sha256"]:
            failures.append(f"BPF hash mismatch: {root.name}")
        if manifest.get("runner_sha256") != lock["files"][
            "campaign_runner"
        ]["sha256"]:
            failures.append(f"campaign runner hash mismatch: {root.name}")
        if manifest.get("hiding_sha256") != lock["module_hashes"]["hiding"]:
            failures.append(f"hiding module hash mismatch: {root.name}")
        if manifest.get("sham_sha256") != lock["module_hashes"]["sham"]:
            failures.append(f"sham module hash mismatch: {root.name}")

    boot_ids = [manifest.get("boot_id") for manifest in manifests]
    if len(boot_ids) != 5 or len(set(boot_ids)) != 5:
        failures.append("boot IDs are not five unique values")
    completed_ids = [item.get("boot_id") for item in state.get("completed_boots", [])]
    if boot_ids != completed_ids:
        failures.append("state/manifest boot ID order mismatch")
    position_balance = {
        episode: sorted(
            manifest["episode_order"].index(episode) for manifest in manifests
        ) if len(manifests) == 5 else []
        for episode in EPISODES
    }
    if any(value != [0, 1, 2, 3, 4] for value in position_balance.values()):
        failures.append("episode ordinal positions are not Latin-square balanced")

    report = {
        "protocol": PROTOCOL,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "local_file_hashes": file_hashes,
        "boots": len(boot_ids),
        "unique_boots": len(set(boot_ids)),
        "raw_batches": generic.get("batches"),
        "all_batches_valid": generic.get("all_valid"),
        "role_composition_match": generic.get("role_composition_match"),
        "episode_position_balance": position_balance,
        "state_sha256": _sha256(args.state),
        "generic_audit_sha256": _sha256(args.generic_audit),
        "manifest_sha256": manifest_hashes,
    }
    args.output.mkdir(parents=True)
    (args.output / "audit.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
