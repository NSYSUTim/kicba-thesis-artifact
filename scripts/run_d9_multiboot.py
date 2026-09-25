#!/usr/bin/env python3
"""Run and retrieve the locked nine-boot D9 confirmatory campaign."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shlex
import subprocess
import time
from pathlib import Path


ACK = "I_UNDERSTAND_THIS_LOADS_A_ROOTKIT_IN_AN_ISOLATED_VM"


def _run(command: list[str], *, check: bool = True, timeout: int | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        command, check=False, text=True, capture_output=True, timeout=timeout
    )
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {command}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _ssh_base(args: argparse.Namespace) -> list[str]:
    return [
        str(args.ssh), "-i", str(args.identity), "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o",
        f"UserKnownHostsFile={args.known_hosts}",
        "-o", "ConnectTimeout=5", args.host,
    ]


def _remote(args: argparse.Namespace, command: str, **kwargs) -> subprocess.CompletedProcess:
    return _run([*_ssh_base(args), command], **kwargs)


def _boot_id(args: argparse.Namespace) -> str:
    result = _remote(args, "cat /proc/sys/kernel/random/boot_id", timeout=15)
    return result.stdout.strip()


def _wait_for_new_boot(args: argparse.Namespace, previous: str) -> str:
    deadline = time.monotonic() + args.reboot_timeout
    saw_disconnect = False
    while time.monotonic() < deadline:
        try:
            result = _remote(
                args, "cat /proc/sys/kernel/random/boot_id",
                check=False, timeout=10,
            )
        except subprocess.TimeoutExpired:
            result = None
        if result is None or result.returncode:
            saw_disconnect = True
        else:
            current = result.stdout.strip()
            if current and current != previous:
                print(json.dumps({
                    "event": "new_boot_ready", "boot_id": current,
                    "saw_disconnect": saw_disconnect,
                }), flush=True)
                return current
        time.sleep(5)
    raise TimeoutError("VM did not return with a new boot ID")


def _verify_local(
    directory: Path, boot_index: int, lock: dict, expected_boot_id: str
) -> dict:
    payload = directory / "campaign.json.gz"
    checksum = directory / "campaign.sha256"
    if not payload.is_file() or not checksum.is_file():
        raise FileNotFoundError(f"missing retrieved evidence in {directory}")
    expected_digest = checksum.read_text(encoding="utf-8").split()[0]
    observed_digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    if observed_digest != expected_digest:
        raise ValueError(f"retrieved checksum mismatch in {directory}")
    with gzip.open(payload, "rt", encoding="utf-8") as stream:
        record = json.load(stream)
    if (
        record.get("role") != "formal"
        or not record.get("success")
        or record.get("environment", {}).get("boot_index") != boot_index
        or record.get("environment", {}).get("boot_total") != 9
        or record.get("environment", {}).get("boot_id") != expected_boot_id
        or record.get("source_hashes") != lock.get("runtime_source_hashes")
        or len(record.get("batches", [])) != 144
    ):
        raise ValueError(f"retrieved campaign failed verification: {directory}")
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh", required=True, type=Path)
    parser.add_argument("--scp", required=True, type=Path)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--known-hosts", required=True, type=Path)
    parser.add_argument("--host", required=True)
    parser.add_argument("--remote-root", default="/home/kicba/kicba")
    parser.add_argument("--remote-output-root", default="/home/kicba/d9_formal")
    parser.add_argument("--local-output", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--seed", default=92103, type=int)
    parser.add_argument("--reboot-timeout", default=240, type=int)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if args.local_output.exists() and any(args.local_output.iterdir()):
        raise FileExistsError(args.local_output)
    args.local_output.mkdir(parents=True, exist_ok=True)
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    if lock.get("formal_design", {}).get("boots") != 9:
        raise ValueError("lock does not specify nine formal boots")

    scp_base = [
        str(args.scp), "-i", str(args.identity), "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o",
        f"UserKnownHostsFile={args.known_hosts}",
    ]
    previous_completed_boot_id = None
    summary = []
    for boot_index in range(1, 10):
        if boot_index == 1:
            # Start confirmatory evidence from a clean boot after all calibration
            # and locking activity has finished.
            old = _boot_id(args)
            print(json.dumps({
                "event": "reboot_before_formal", "old_boot_id": old,
            }), flush=True)
            _remote(args, "sudo -n reboot", check=False, timeout=15)
            current_boot_id = _wait_for_new_boot(args, old)
        else:
            current_boot_id = _boot_id(args)
        if current_boot_id == previous_completed_boot_id:
            raise RuntimeError("formal campaigns would share a boot ID")
        remote_output = f"{args.remote_output_root}/boot_{boot_index:02d}"
        command = [
            "sudo", "-n", "env", f"PYTHONPATH={args.remote_root}/src",
            "python3", "collector/run_d9_campaign.py",
            "--role", "formal", "--output", remote_output,
            "--probe", "/home/kicba/d9_enum_probe",
            "--d7-pass-ko", "attack_variants/d7_controls_r2/kicba_d7_pass.ko",
            "--d7-active-ko", "attack_variants/d7_controls_r2/kicba_d7_active.ko",
            "--d7-hiding-ko", "attack_variants/d7_controls_r2/kicba_d7_hiding.ko",
            "--d8-pass-ko", "attack_variants/d8_getdents_controls/kicba_d8_getdents_pass.ko",
            "--d8-active-ko", "attack_variants/d8_getdents_controls/kicba_d8_getdents_active.ko",
            "--d8-hiding-ko", "attack_variants/d8_getdents_controls/kicba_d8_getdents_hiding.ko",
            "--d8-policy-ko", "attack_variants/d8_getdents_controls/kicba_d8_getdents_policy.ko",
            "--d9-substitute-ko", "attack_variants/d9_getdents_substitute/kicba_d9_getdents_substitute.ko",
            "--boot-index", str(boot_index), "--boot-total", "9",
            "--iterations", "20", "--repeats", "1",
            "--seed", str(args.seed), "--isolated-vm-ack", ACK,
        ]
        remote_command = f"cd {shlex.quote(args.remote_root)} && {shlex.join(command)}"
        print(json.dumps({
            "event": "campaign_start", "boot_index": boot_index,
            "boot_id": current_boot_id,
        }), flush=True)
        result = _remote(args, remote_command, timeout=1800)
        print(result.stdout.strip(), flush=True)
        local_boot = args.local_output / f"boot_{boot_index:02d}"
        local_boot.mkdir()
        _run([
            *scp_base, f"{args.host}:{remote_output}/campaign.*", str(local_boot),
        ], timeout=120)
        record = _verify_local(local_boot, boot_index, lock, current_boot_id)
        summary.append({
            "boot_index": boot_index, "boot_id": current_boot_id,
            "campaign_sha256": hashlib.sha256(
                (local_boot / "campaign.json.gz").read_bytes()
            ).hexdigest(),
            "batches": len(record["batches"]),
        })
        print(json.dumps({
            "event": "campaign_verified", **summary[-1],
        }), flush=True)
        previous_completed_boot_id = current_boot_id
        if boot_index < 9:
            _remote(args, "sudo -n reboot", check=False, timeout=15)
            _wait_for_new_boot(args, current_boot_id)
    manifest = {
        "role": "d9_nine_boot_retrieval_manifest",
        "lock_sha256": hashlib.sha256(args.lock.read_bytes()).hexdigest(),
        "seed": args.seed,
        "campaigns": summary,
    }
    manifest_path = args.local_output / "retrieval_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({
        "event": "complete", "manifest": str(manifest_path),
        "boots": len(summary), "batches": sum(row["batches"] for row in summary),
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
