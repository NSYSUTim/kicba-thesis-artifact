"""Host coordinator for three fresh boots; never replaces failed experiments."""

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "phase1/host/evidence"
SSH = ["C:/Windows/System32/OpenSSH/ssh.exe", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
       "-o", "UserKnownHostsFile=D:/KICBA-Lab/ssh/known_hosts", "-o", "ConnectTimeout=5",
       "-o", "LogLevel=ERROR", "-i", "D:/KICBA-Lab/ssh/kicba_ed25519", "kicba@192.168.77.2"]
SCP = ["C:/Windows/System32/OpenSSH/scp.exe", "-q", *SSH[1:-1]]
GUEST = "/home/kicba/research_phase1_20261023"


def remote(command, **kwargs):
    return subprocess.run([*SSH, command], **kwargs)


def sampler(index):
    stop = HOST / f"confirmation_boot_{index:02d}.stop"
    samples = HOST / f"confirmation_boot_{index:02d}_samples.jsonl"
    if stop.exists() or samples.exists():
        raise FileExistsError("host sampling attempt already exists")
    process = subprocess.Popen(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                                str(ROOT / "phase1/host/sample_host.ps1"), "-OutputPath", str(samples),
                                "-StopFile", str(stop)], creationflags=subprocess.CREATE_NO_WINDOW)
    return process, stop


def main():
    events_path = HOST / "confirmation_orchestration.jsonl"
    with events_path.open("x", encoding="utf-8") as events:
        def event(kind, **details):
            record = {"recorded_at": datetime.now(timezone.utc).isoformat(), "kind": kind, **details}
            text = json.dumps(record)
            events.write(text + "\n")
            events.flush()
            print(text, flush=True)

        (HOST / "pilot_sampling.stop").touch(exist_ok=False)
        for index in (1, 2, 3):
            before = remote("cat /proc/sys/kernel/random/boot_id", check=True, capture_output=True, text=True).stdout.strip()
            samples, stop = sampler(index)
            try:
                event("reboot_requested", boot_index=index, previous_boot_id=before)
                remote("sudo -n reboot", capture_output=True, text=True, timeout=15)
                deadline = time.monotonic() + 240
                fresh = None
                while time.monotonic() < deadline:
                    time.sleep(3)
                    probe = remote("cat /proc/sys/kernel/random/boot_id", capture_output=True, text=True)
                    if probe.returncode == 0 and probe.stdout.strip() and probe.stdout.strip() != before:
                        fresh = probe.stdout.strip()
                        break
                if fresh is None:
                    raise RuntimeError("new boot did not become available")
                event("confirmation_started", boot_index=index, boot_id=fresh)
                result = remote(f"sudo -n env PYTHONDONTWRITEBYTECODE=1 python3 {GUEST}/phase1/run_confirmation.py --boot-index {index}",
                                capture_output=True, text=True)
                (HOST / f"confirmation_boot_{index:02d}_ssh.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
                archive_name = f"confirmation_boot_{index:02d}.tar.gz"
                downloads = ROOT / "phase1/evidence/downloads"
                downloads.mkdir(parents=True, exist_ok=True)
                archive = downloads / archive_name
                digest_path = downloads / (archive_name + ".sha256.json")
                if archive.exists() or digest_path.exists():
                    raise FileExistsError("download destination already exists")
                for name in (archive_name, archive_name + ".sha256.json"):
                    subprocess.run([*SCP, f"kicba@192.168.77.2:{GUEST}/{name}", str(downloads / name)], check=True)
                expected = json.loads(digest_path.read_text())["sha256"]
                if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
                    raise RuntimeError("download checksum mismatch")
                with tarfile.open(archive) as bundle:
                    bundle.extractall(ROOT / "phase1", filter="data")
                summary = json.loads((ROOT / f"phase1/evidence/confirmation/boot_{index:02d}/summary.json").read_text())
                event("confirmation_finished", boot_index=index, boot_id=fresh,
                      returncode=result.returncode, completed=summary.get("completed"),
                      environment_unchanged=summary.get("environment_unchanged"),
                      elapsed_seconds=summary.get("elapsed_seconds"))
                if result.returncode or not summary.get("completed") or not summary.get("environment_unchanged"):
                    raise RuntimeError("confirmation stopped on retained failure")
            finally:
                stop.touch(exist_ok=False)
                try:
                    samples.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    event("sampler_stopping", boot_index=index)
        event("all_three_boots_complete")


if __name__ == "__main__":
    main()
