"""Trace of the Times loader adapter for the shared D9 filldir treatment.

The upstream collector imports this module as ``linux``.  Only rootkit
loading is adapted; event collection and anomaly evaluation remain upstream.
"""

import subprocess
import sys


ROOTKIT_NAME = "kicba_d7_hiding"
KERNEL_OBJECT_PATH = (
    "/home/kicba/kicba/attack_variants/d7_controls_r2/"
)


def list_modules() -> list[str]:
    result = subprocess.run(["lsmod"], capture_output=True, text=True, check=True)
    return [
        line.split(" ", maxsplit=1)[0]
        for line in result.stdout.splitlines()[1:]
        if line
    ]


def insert_rootkit() -> None:
    result = subprocess.run(
        [
            "sudo",
            "-n",
            "insmod",
            KERNEL_OBJECT_PATH + ROOTKIT_NAME + ".ko",
            "magic_word=caraxes",
            "counter_comm=ls",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)


def remove_rootkit() -> None:
    result = subprocess.run(
        ["sudo", "-n", "rmmod", ROOTKIT_NAME],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)


def shell(cmd: str, mute: bool = False) -> str:
    command = subprocess.Popen(
        cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = command.communicate()
    output = stdout.decode("utf-8")
    if not mute:
        print(output, file=sys.stderr, end="")
    if command.returncode != 0:
        raise RuntimeError(stderr.decode("utf-8"))
    return output


def run_background(cmd: str) -> subprocess.Popen:
    return subprocess.Popen(cmd.split(" "))
