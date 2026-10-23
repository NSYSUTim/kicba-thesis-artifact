"""Read the guest environment without installing or changing anything."""

import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def inventory():
    packages = command("dpkg-query", "-W")
    return {
        "kernel": platform.release(), "machine": platform.machine(),
        "python": platform.python_version(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "proc_version": Path("/proc/version").read_text().strip(),
        "packages": packages,
        "package_inventory_sha256": hashlib.sha256(packages["stdout"].encode()).hexdigest(),
        "routes4": command("ip", "route", "show"),
        "routes6": command("ip", "-6", "route", "show"),
        "update_units": {
            unit: command("systemctl", "show", unit, "--property=ActiveState,UnitFileState")
            for unit in ("apt-daily.timer", "apt-daily-upgrade.timer", "unattended-upgrades.service")
        },
        "cpu": command("lscpu"), "mounts": command("findmnt", "-J"),
        "gcc": command("gcc", "--version"),
        "modules": command("lsmod"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    record = inventory()
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
    else:
        print(json.dumps(record, ensure_ascii=False, indent=2))
