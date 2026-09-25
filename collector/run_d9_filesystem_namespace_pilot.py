#!/usr/bin/env python3
"""D9 overlay, pseudo-filesystem, and namespace development pilot."""

from __future__ import annotations

import argparse
import ctypes as ct
import json
import os
import platform
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from bcc import BPF

from run_campaign import ACK
from run_d9_boundary_suite import (
    _build_fixture,
    _expected,
    _module_audit,
    _recovery_matches_oracle,
)
from run_d9_reconciliation_pilot import (
    KNOWN_MODULES,
    _loaded_modules,
    _set_state,
    _sha256,
    _unload_known,
)
from run_d9_reconciliation_smoke import (
    DEFAULT_SEED1,
    DEFAULT_SEED2,
    _set_array,
    cleanup_pid,
    result_for_pid,
)


PROTOCOL = "D9-filesystem-namespace-pilot-r1-2026-09-24"
STATES = ("unloaded", "getdents_hiding", "getdents_substitution")
NAMESPACES = ("host", "mount", "user_mount")


def _probe_command(
    namespace: str, probe: Path, directory: Path, cells: int
) -> list[str]:
    base = [
        str(probe), str(directory), "256", str(cells),
        str(DEFAULT_SEED1), str(DEFAULT_SEED2),
    ]
    if namespace == "host":
        return base
    if namespace == "mount":
        return ["unshare", "--mount", "--propagation", "private", "--", *base]
    if namespace == "user_mount":
        return [
            "unshare", "--user", "--map-root-user", "--mount",
            "--propagation", "private", "--", *base,
        ]
    raise ValueError(namespace)


def _collect_command(
    bpf: BPF, command: list[str], cells: int,
) -> dict:
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    bpf["monitored_pids"][ct.c_uint(process.pid)] = ct.c_ubyte(1)
    try:
        stdout, stderr = process.communicate("\n", timeout=60)
        if process.returncode:
            raise RuntimeError(stderr.strip())
        visible = json.loads(stdout)
        visible["_stdout_bytes"] = len(stdout.encode())
        return result_for_pid(
            bpf, process.pid, visible, cells,
            DEFAULT_SEED1, DEFAULT_SEED2,
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        cleanup_pid(bpf, process.pid)


def _namespace_support(namespace: str) -> tuple[bool, str]:
    if namespace == "host":
        return True, "host namespace"
    command = ["unshare", "--mount", "--propagation", "private", "--", "true"]
    if namespace == "user_mount":
        command = [
            "unshare", "--user", "--map-root-user", "--mount",
            "--propagation", "private", "--", "true",
        ]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode == 0, result.stderr.strip()


def _validate(
    state: str, result: dict, intended_up: list[list[int]],
    intended_down: list[list[int]], audit: dict[str, int],
) -> dict:
    oracle_match, scope, expected_up, expected_down = _recovery_matches_oracle(
        state=state, result=result,
        intended_upstream=intended_up,
        intended_downstream=intended_down,
        audit=audit,
    )
    expected_difference = bool(expected_up or expected_down)
    detected = not result["fingerprint_equal"]
    decoded = result["decode_success"] and oracle_match
    return {
        "expected_difference": expected_difference,
        "difference_detected": detected,
        "decoded_exact": decoded,
        "oracle_scope": scope,
        "expected_upstream_count": expected_up,
        "expected_downstream_count": expected_down,
        "pass": (
            result["measurement_valid"]
            and detected == expected_difference
            and decoded
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--d7-pass-ko", required=True, type=Path)
    parser.add_argument("--d7-active-ko", required=True, type=Path)
    parser.add_argument("--d7-hiding-ko", required=True, type=Path)
    parser.add_argument("--d8-pass-ko", required=True, type=Path)
    parser.add_argument("--d8-active-ko", required=True, type=Path)
    parser.add_argument("--d8-hiding-ko", required=True, type=Path)
    parser.add_argument("--d8-policy-ko", required=True, type=Path)
    parser.add_argument("--d9-substitute-ko", required=True, type=Path)
    parser.add_argument("--isolated-vm-ack", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or "microsoft" in platform.release().lower():
        parser.error("requires root in the native isolated VM")
    if args.isolated_vm_ack != ACK:
        parser.error(f"--isolated-vm-ack must equal {ACK}")
    if subprocess.run(
        ["ip", "route", "show", "default"], check=True,
        capture_output=True, text=True,
    ).stdout.strip():
        raise RuntimeError("default route present")
    if args.output.exists():
        raise FileExistsError(args.output)

    modules = {
        "filldir_pass": args.d7_pass_ko.resolve(),
        "filldir_active": args.d7_active_ko.resolve(),
        "filldir_hiding": args.d7_hiding_ko.resolve(),
        "getdents_pass": args.d8_pass_ko.resolve(),
        "getdents_active": args.d8_active_ko.resolve(),
        "getdents_hiding": args.d8_hiding_ko.resolve(),
        "policy_filter": args.d8_policy_ko.resolve(),
        "getdents_substitution": args.d9_substitute_ko.resolve(),
    }
    for path in [args.probe.resolve(), *modules.values()]:
        if not path.is_file():
            raise FileNotFoundError(path)
    if _loaded_modules() & KNOWN_MODULES:
        raise RuntimeError("known research module loaded at pilot start")

    args.output.mkdir(parents=True)
    # A user namespace maps the invoking root, not the host `kicba` owner.
    # /home/kicba is mode 0750, so place namespace-visible fixtures and a probe
    # copy below /tmp instead of silently classifying EACCES as method failure.
    temporary = Path(tempfile.mkdtemp(prefix="d9_fs_namespace_", dir="/tmp"))
    temporary.chmod(0o755)
    accessible_probe = temporary / "d9_enum_probe"
    shutil.copy2(args.probe.resolve(), accessible_probe)
    accessible_probe.chmod(0o755)
    native_parent = temporary / "native"
    native_parent.mkdir()
    native = _build_fixture(native_parent, 1024, 16, "ascii")
    lower_parent = temporary / "lower_parent"
    lower_parent.mkdir()
    lower = _build_fixture(lower_parent, 1024, 16, "ascii")
    upper = temporary / "upper"
    work = temporary / "work"
    merged = temporary / "merged"
    for path in (upper, work, merged):
        path.mkdir()
    subprocess.run([
        "mount", "-t", "overlay", "overlay", "-o",
        f"lowerdir={lower},upperdir={upper},workdir={work}", str(merged),
    ], check=True)

    source = Path(__file__).with_name("bpf_d9_reconciliation.c")
    bpf = BPF(src_file=str(source), cflags=[f"-I{source.parent.resolve()}"])
    bpf.attach_kprobe(event="filldir64", fn_name="d9_filldir64_enter")
    bpf.attach_kretprobe(
        event="filldir64", fn_name="d9_filldir64_return", maxactive=256
    )
    _set_array(bpf["hash_seeds"], 0, ct.c_ulonglong(DEFAULT_SEED1))
    _set_array(bpf["hash_seeds"], 1, ct.c_ulonglong(DEFAULT_SEED2))
    _set_array(bpf["iblt_cell_count"], 0, ct.c_uint(256))
    _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(1))

    support = {
        namespace: _namespace_support(namespace) for namespace in NAMESPACES
    }
    rows = []
    failures = []
    try:
        for filesystem, fixture, namespaces in (
            ("ext4", native, NAMESPACES),
            ("overlayfs", merged, NAMESPACES),
        ):
            for namespace in namespaces:
                supported, reason = support[namespace]
                if not supported:
                    rows.append({
                        "axis": "namespace", "filesystem": filesystem,
                        "namespace": namespace, "supported": False,
                        "reason": reason,
                    })
                    continue
                for state in STATES:
                    _unload_known()
                    intended_up, intended_down = _expected(fixture, state)
                    _set_state(state, modules)
                    result = _collect_command(
                        bpf,
                        _probe_command(
                            namespace, accessible_probe, fixture, 256
                        ),
                        256,
                    )
                    audit = _module_audit(state, modules)
                    validated = _validate(
                        state, result, intended_up, intended_down, audit
                    )
                    rows.append({
                        "axis": "namespace", "filesystem": filesystem,
                        "namespace": namespace, "supported": True,
                        "state": state, "module_audit": audit,
                        **validated, **result,
                    })
                    if not validated["pass"]:
                        failures.append(
                            f"namespace:{filesystem}:{namespace}:{state}"
                        )

        # Dynamic pseudo filesystems are control-only: D9 should reconcile the
        # actual transaction even if the directory changes independently.
        _unload_known()
        for directory in (Path("/proc"), Path("/sys"), Path("/dev")):
            for namespace in ("host", "mount"):
                supported, reason = support[namespace]
                if not supported:
                    rows.append({
                        "axis": "pseudo_filesystem", "directory": str(directory),
                        "namespace": namespace, "supported": False,
                        "reason": reason,
                    })
                    continue
                result = _collect_command(
                    bpf,
                    _probe_command(
                        namespace, accessible_probe, directory, 256
                    ),
                    256,
                )
                ok = (
                    result["measurement_valid"]
                    and result["fingerprint_equal"]
                    and result["decode_success"]
                    and not result["upstream_only"]
                    and not result["downstream_only"]
                )
                rows.append({
                    "axis": "pseudo_filesystem", "directory": str(directory),
                    "namespace": namespace, "supported": True,
                    "pass": ok, **result,
                })
                if not ok:
                    failures.append(f"pseudo:{directory}:{namespace}")
    finally:
        _set_array(bpf["collection_enabled"], 0, ct.c_ubyte(0))
        _unload_known()
        bpf.cleanup()
        subprocess.run(["umount", str(merged)], check=True)
        shutil.rmtree(temporary, ignore_errors=True)

    report = {
        "schema_version": 1,
        "protocol_revision": PROTOCOL,
        "evidence_role": "single_boot_development_filesystem_namespace_not_confirmatory",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "kernel": platform.release(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "namespace_support": {
                name: {"supported": value[0], "reason": value[1]}
                for name, value in support.items()
            },
        },
        "source_hashes": {
            "runner": _sha256(Path(__file__)),
            "bpf": _sha256(source),
            "probe": _sha256(args.probe.resolve()),
        },
        "success": not failures,
        "failures": failures,
        "rows": rows,
    }
    output = args.output / "filesystem_namespace_pilot.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(output), "success": not failures,
        "rows": len(rows), "failures": failures,
    }, indent=2))
    if failures:
        raise RuntimeError("filesystem/namespace pilot criteria failed")


if __name__ == "__main__":
    main()
