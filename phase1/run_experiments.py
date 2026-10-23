"""Phase-one VM experiments; raw attempts are append-only and never replaced."""

from __future__ import annotations

import argparse
import ctypes as ct
import hashlib
import json
import os
import platform
import random
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, ROOT / "src", ROOT / "collector"):
    sys.path.insert(0, str(directory))
from phase1.coverage import compare_window, combine_verdict
from kicba.reconciliation import IBLT, MultisetFingerprint, token_for_entry

SEED1, SEED2, CELLS = 0x0123456789ABCDEF, 0xF0E1D2C3B4A59687, 256
MODES = {
    "parse": (None, 0, False, False), "user_fp": (None, 1, False, False),
    "user_iblt": (None, 2, False, False), "empty": (0, 2, False, False),
    "bookkeeping": (1, 2, False, False), "names": (2, 2, False, False),
    "kernel_fp": (3, 2, False, False), "kernel_iblt": (4, 2, False, False),
    "readback": (4, 2, True, False), "decode": (4, 2, True, True),
}
STATES = ("unloaded", "filldir_pass", "filldir_hiding", "getdents_pass",
          "getdents_hiding", "getdents_substitution")
ERROR_FIELDS = ("name_read_errors", "invalid_name_lengths", "pending_update_failures",
                "fingerprint_update_failures", "iblt_update_failures", "return_underflows")


def cost_blocks(seed, repeats):
    rng = random.Random(seed)
    blocks = []
    for _ in range(repeats):
        names = list(MODES)
        rng.shuffle(names)
        blocks.append(names)
    return blocks


def canonical_records(rows):
    records = []
    for row in rows:
        try:
            name, inode, kind = bytes.fromhex(row["name_hex"]), row["inode"], row["d_type"]
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("malformed exact record") from error
        if (type(inode) is not int or not 0 <= inode < 2**64
                or type(kind) is not int or not 0 <= kind < 256 or not name or b"\0" in name):
            raise ValueError("malformed exact identity")
        records.append((name, inode, kind))
    return sorted(records)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, record):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, ensure_ascii=True)


def emit(stream, record):
    record["recorded_at"] = datetime.now(timezone.utc).isoformat()
    stream.write(json.dumps(record, ensure_ascii=True) + "\n")
    stream.flush()


def runtime():
    global BPF, cleanup_pid, _kernel_rows, _rows_from_sparse, _set_array
    global _set_state, _unload_known, _loaded_modules, KNOWN_MODULES, _build_fixture
    from bcc import BPF
    from run_d9_reconciliation_smoke import cleanup_pid, _kernel_rows, _rows_from_sparse, _set_array
    from run_d9_reconciliation_pilot import _set_state, _unload_known, _loaded_modules, KNOWN_MODULES
    from run_d9_boundary_suite import _build_fixture


def new_bpf(mode):
    return BPF(src_file=str(ROOT / "phase1/bpf_measurement.c"), cflags=[
        "-I" + str(ROOT / "phase1"), "-I" + str(ROOT / "collector"),
        "-DPHASE1_MODE=" + str(mode), "-Wno-macro-redefined"])


def attach(bpf, maxactive=256):
    started = time.monotonic_ns()
    bpf.attach_kprobe(event="filldir64", fn_name="d9_filldir64_enter")
    try:
        bpf.attach_kretprobe(event="filldir64", fn_name="d9_filldir64_return", maxactive=maxactive)
    except Exception:
        bpf.detach_kprobe(event="filldir64")
        raise
    for name, index, value in (("collection_enabled", 0, ct.c_ubyte(1)),
                                ("hash_seeds", 0, ct.c_ulonglong(SEED1)),
                                ("hash_seeds", 1, ct.c_ulonglong(SEED2)),
                                ("iblt_cell_count", 0, ct.c_uint(CELLS))):
        _set_array(bpf[name], index, value)
    return time.monotonic_ns() - started


def detach(bpf):
    bpf.detach_kprobe(event="filldir64")
    bpf.detach_kretprobe(event="filldir64")


def snapshot():
    name = "r_filldir64_bcc_" + str(os.getpid())
    base = Path("/sys/kernel/debug/tracing")
    lines = [line for line in (base / "kprobe_events").read_text().splitlines()
             if line.split()[0].split("/")[-1] == name]
    event_id = base / "events/kprobes" / name / "id"
    return {"profile": (base / "kprobe_profile").read_text(),
            "event": name, "definition": lines,
            "event_id": event_id.read_text().strip() if event_id.exists() else None}


def coverage_between(first, last):
    result = compare_window(first["profile"], last["profile"], [first["event"]])
    if (first["event"] != last["event"] or len(first["definition"]) != 1
            or first["definition"] != last["definition"] or first["event_id"] is None
            or first["event_id"] != last["event_id"]):
        result["valid"] = False
        result["reasons"].append("probe_definition_or_generation_changed")
    result["entry_counter_visibility"] = "not_exposed_by_original_perf_attachment"
    return result


def begin_probe(bpf, kernel_mode, fixture, buffer, dump=None, user_mode=2):
    command = [str(ROOT / "phase1/bin/d9_enum_probe"), str(fixture), str(buffer),
               str(CELLS), str(SEED1), str(SEED2), str(user_mode)]
    if dump is not None:
        command.append(str(dump))
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    if bpf is not None and kernel_mode != 0:
        try:
            bpf["monitored_pids"][ct.c_uint(process.pid)] = ct.c_ubyte(1)
        except Exception:
            process.kill()
            process.communicate()
            raise
    return process


def release(process):
    process.stdin.write("\n")
    process.stdin.flush()


def telemetry(bpf, pid, readback):
    key = ct.c_uint(pid)
    fp = bpf["kernel_fingerprints"].get(key)
    stats = bpf["stats_by_pid"].get(key)
    fields = ("outer_entries", "accepted_entries", "rejected_entries", *ERROR_FIELDS,
              "name_read_checksum")
    values = {field: int(getattr(stats, field)) for field in fields} if stats is not None else {}
    fingerprint = [int(fp.count), int(fp.sum1), int(fp.sum2)] if fp is not None else None
    config = [int(bpf["hash_seeds"][ct.c_int(index)].value) for index in (0, 1)]
    config += [int(bpf["iblt_cell_count"][ct.c_int(0)].value),
               int(bpf["collection_enabled"][ct.c_int(0)].value)]
    valid = bool(fp is not None and stats is not None
                 and bpf["depth_by_pid"].get(key) is None
                 and bpf["pending_by_pid"].get(key) is None
                 and all(values[field] == 0 for field in ERROR_FIELDS)
                 and values["accepted_entries"] == fingerprint[0]
                 and values["outer_entries"] == values["accepted_entries"] + values["rejected_entries"]
                 and config == [SEED1, SEED2, CELLS, 1])
    rows = _kernel_rows(bpf["kernel_iblt"], pid, CELLS)[0] if readback else None
    return {"original_valid": valid, "kernel_fingerprint": fingerprint,
            "kernel_stats": values, "configuration": config, "kernel_rows": rows}


def finish_probe(process, bpf, kernel_mode, readback=False, decode=False):
    record = {"pid": process.pid, "original_valid": False,
              "readback_ns": 0, "decode_ns": 0, "cleanup_ns": 0}
    try:
        stdout, stderr = process.communicate(timeout=60)
        record.update(returncode=process.returncode, stderr=stderr)
        if process.returncode:
            record["stdout"] = stdout
            return record
        parse_started = time.monotonic_ns()
        visible = json.loads(stdout)
        record["json_parse_ns"] = time.monotonic_ns() - parse_started
        record["userspace"] = visible
        record["original_valid"] = True
        if bpf is not None and kernel_mode != 0:
            started = time.monotonic_ns()
            record.update(telemetry(bpf, process.pid, readback))
            record["readback_ns"] = time.monotonic_ns() - started
            record["fingerprint_equal"] = record["kernel_fingerprint"] == [
                visible["count"], visible["sum1"], visible["sum2"]]
            if decode:
                started = time.monotonic_ns()
                difference = IBLT.from_rows(record["kernel_rows"], SEED1, SEED2).subtract(
                    IBLT.from_rows(_rows_from_sparse(CELLS, visible["cells"]), SEED1, SEED2)).decode()
                record["decode_ns"] = time.monotonic_ns() - started
                record.update(decode_success=difference.success,
                              upstream_only=[[token.key_hash, token.inode, token.d_type]
                                             for token in difference.upstream_only],
                              downstream_only=[[token.key_hash, token.inode, token.d_type]
                                               for token in difference.downstream_only],
                              residual_cells=difference.residual_cells)
        return record
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        record.update(error="timeout", stdout=stdout, stderr=stderr)
        return record
    except Exception as error:
        record["original_valid"] = False
        record["error"] = repr(error)
        return record
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
        if bpf is not None and kernel_mode != 0:
            started = time.monotonic_ns()
            cleanup_pid(bpf, process.pid)
            record["cleanup_ns"] = time.monotonic_ns() - started


def one_scan(bpf, kernel_mode, fixture, buffer, user_mode=2, dump=None,
             readback=False, decode=False):
    total_started = time.monotonic_ns()
    first = snapshot() if bpf is not None else None
    wall_started = time.monotonic_ns()
    process = begin_probe(bpf, kernel_mode, fixture, buffer, dump, user_mode)
    release_error = None
    try:
        release(process)
    except (BrokenPipeError, OSError) as error:
        release_error = repr(error)
    record = finish_probe(process, bpf, kernel_mode, readback, decode)
    if release_error:
        record.update(release_error=release_error, original_valid=False)
    record["wall_ns"] = time.monotonic_ns() - wall_started
    last = snapshot() if bpf is not None else None
    record["wall_with_coverage_ns"] = time.monotonic_ns() - total_started
    if bpf is not None:
        coverage = coverage_between(first, last)
        record.update(coverage=coverage, coverage_before=first, coverage_after=last)
        if kernel_mode >= 3:
            record["verdict"] = combine_verdict(
                record["original_valid"], record.get("fingerprint_equal"), coverage)
        else:
            record["verdict"] = "diagnostic" if record["original_valid"] and coverage["valid"] else "invalid"
    else:
        record["verdict"] = "not_measured"
    return record


def make_simple_fixture(path, count):
    path.mkdir()
    for index in range(count):
        (path / ("visible_" + str(index).zfill(8))).touch()
    return path


def run_coverage(args, output, stream):
    fixture = make_simple_fixture(output / "fixture", 8192)
    for active in (1, 256):
        bpf = new_bpf(4)
        try:
            attach(bpf, active)
            for workers in (4, 8, 16):
                for repetition in range(10):
                    first = snapshot()
                    transactions = []
                    for _ in range(2):
                        processes = [begin_probe(bpf, 4, fixture, 65536) for _ in range(workers)]
                        for process in processes:
                            release(process)
                        transactions.extend(finish_probe(process, bpf, 4) for process in processes)
                    last = snapshot()
                    coverage = coverage_between(first, last)
                    for transaction in transactions:
                        transaction["verdict"] = combine_verdict(transaction["original_valid"],
                                                                transaction.get("fingerprint_equal"), coverage)
                    emit(stream, {"kind": "concurrent_loss", "maxactive": active,
                                  "workers": workers, "repetition": repetition,
                                  "coverage_before": first, "coverage_after": last,
                                  "coverage": coverage, "transactions": transactions})
            if active == 256:
                for repetition in range(30):
                    row = one_scan(bpf, 4, fixture, 65536, readback=True, decode=True)
                    emit(stream, {"kind": "normal_quality", "repetition": repetition, **row})
        finally:
            bpf.cleanup()


def fixture_records(fixture):
    rows = [(b".", fixture.stat().st_ino, 4), (b"..", fixture.parent.stat().st_ino, 4)]
    rows += [(os.fsencode(entry.name), entry.inode(), 8) for entry in os.scandir(fixture)]
    return sorted(rows)


def expected_records(original, state):
    output = []
    for name, inode, kind in original:
        if state in {"filldir_hiding", "getdents_hiding"} and name.startswith(b"d8_hidden_"):
            continue
        if state == "getdents_substitution" and name.startswith(b"d9_swap_a_"):
            name = b"d9_swap_b_" + name[len(b"d9_swap_a_"):]
        output.append((name, inode, kind))
    return sorted(output)


def token_counter(records):
    return Counter((token.key_hash, token.inode, token.d_type)
                   for token in (token_for_entry(*row, SEED1, SEED2) for row in records))


def run_fidelity(args, output, stream):
    fixture = _build_fixture(output, 512, 16, "ascii")
    original = fixture_records(fixture)
    save(output / "oracle.json", [[name.hex(), inode, kind] for name, inode, kind in original])
    modules = {
        "filldir_pass": ROOT / "attack_variants/d7_controls_r2/kicba_d7_pass.ko",
        "filldir_hiding": ROOT / "attack_variants/d7_controls_r2/kicba_d7_hiding.ko",
        "getdents_pass": ROOT / "attack_variants/d8_getdents_controls/kicba_d8_getdents_pass.ko",
        "getdents_hiding": ROOT / "attack_variants/d8_getdents_controls/kicba_d8_getdents_hiding.ko",
        "getdents_substitution": ROOT / "attack_variants/d9_getdents_substitute/kicba_d9_getdents_substitute.ko",
    }
    ordinal = 0
    for state in STATES:
        expected = expected_records(original, state)
        for mode, order in ((None, "none"), (0, "probe_first"), (0, "module_first"),
                            (4, "probe_first"), (4, "module_first")):
            _unload_known()
            bpf = new_bpf(mode) if mode is not None else None
            operations = []
            try:
                if order == "probe_first":
                    attach(bpf)
                    operations.append("attach")
                _set_state(state, modules)
                operations.append("state:" + state)
                if order == "module_first":
                    attach(bpf)
                    operations.append("attach")
                for buffer in ((65536,) if args.role == "pilot" else (256, 65536)):
                    for repetition in range(2 if args.role == "pilot" else 10):
                        dump = output / ("actual_" + str(ordinal).zfill(5) + ".jsonl")
                        ordinal += 1
                        row = one_scan(bpf, mode, fixture, buffer, dump=dump,
                                       readback=mode == 4, decode=mode == 4)
                        actual = canonical_records([json.loads(line) for line in dump.read_text().splitlines()])
                        row.update(kind="fidelity", state=state, kernel_mode=mode, order=order,
                                   operations=operations, buffer=buffer, repetition=repetition,
                                   exact_dump=dump.name, output_matches_expected=actual == expected)
                        if mode == 4 and "decode_success" in row:
                            up, down = token_counter(original), token_counter(expected)
                            row["decoded_exact"] = (row["decode_success"]
                                and Counter(map(tuple, row["upstream_only"])) == up - down
                                and Counter(map(tuple, row["downstream_only"])) == down - up)
                            row["expected_difference"] = original != expected
                            row["verdict_matches_expected"] = row["verdict"] == (
                                "different" if original != expected else "equal")
                        emit(stream, row)
            except Exception as error:
                emit(stream, {"kind": "fidelity_setup_failure", "state": state,
                              "kernel_mode": mode, "order": order, "operations": operations,
                              "error": repr(error)})
            finally:
                if bpf is not None:
                    bpf.cleanup()
                _unload_known()


def stop_stress(process):
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def run_cost(args, output, stream):
    programs = {mode: new_bpf(mode) for mode in range(5)}
    try:
        for cardinality in (512, 8192, 65536):
            fixture = make_simple_fixture(output / ("fixture_" + str(cardinality)), cardinality)
            for condition in ("baseline", "cpu"):
                stress = None
                try:
                    if condition == "cpu":
                        stress = subprocess.Popen(["stress-ng", "--cpu", "2", "--quiet"],
                                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                                  start_new_session=True)
                        time.sleep(0.5)
                    blocks = cost_blocks(args.seed ^ cardinality ^ (1 if condition == "cpu" else 0),
                                         2 + (3 if args.role == "pilot" else 10))
                    for block_index, names in enumerate(blocks):
                        for name in names:
                            kernel_mode, user_mode, readback, decode = MODES[name]
                            bpf = programs[kernel_mode] if kernel_mode is not None else None
                            attached = False
                            try:
                                attach_ns = attach(bpf) if bpf is not None else 0
                                attached = bpf is not None
                                row = one_scan(bpf, kernel_mode, fixture, 65536,
                                               user_mode=user_mode, readback=readback, decode=decode)
                                visible = row.get("userspace", {})
                                row.update(kind="cost", mode=name, cardinality=cardinality,
                                           condition=condition, block=block_index - 2,
                                           warmup=block_index < 2, order=names, attach_ns=attach_ns,
                                           count_matches=visible.get("count") == cardinality + 2,
                                           load_active=stress is None or stress.poll() is None,
                                           guest_load=os.getloadavg())
                                emit(stream, row)
                            finally:
                                if attached:
                                    detach(bpf)
                finally:
                    stop_stress(stress)
    finally:
        for bpf in programs.values():
            bpf.cleanup()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", choices=("coverage", "fidelity", "cost"))
    parser.add_argument("--role", choices=("pilot", "confirmation"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=1202301)
    args = parser.parse_args()
    if os.geteuid() != 0 or "microsoft" in platform.release().lower():
        parser.error("requires root in the protected native VM")
    if ROOT != Path("/home/kicba/research_phase1_20261023"):
        parser.error("requires the new version directory")
    lock = json.loads((ROOT / "phase1/LOCK.json").read_text())
    if (not lock["checkpoint"]["success"]
            or sha(ROOT / "phase1/PROTOCOL_zh-TW.md") != lock["protocol_sha256"]):
        raise RuntimeError("checkpoint or protocol lock failed")
    if args.role == "confirmation":
        confirmation = json.loads((ROOT / "phase1/CONFIRMATION_LOCK.json").read_text())
        for relative, expected in confirmation["source_sha256"].items():
            if sha(ROOT / relative) != expected:
                raise RuntimeError("confirmation source drift: " + relative)
    for command in (["ip", "route", "show", "default"], ["ip", "-6", "route", "show", "default"]):
        if subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip():
            raise RuntimeError("guest default route present")
    runtime()
    if _loaded_modules() & KNOWN_MODULES:
        raise RuntimeError("research module already loaded; do not disturb another run")
    output = args.output.resolve()
    if ROOT not in output.parents:
        raise ValueError("output must remain under the new version directory")
    output.mkdir(parents=True, exist_ok=False)
    sources = [*ROOT.glob("phase1/*.py"), *ROOT.glob("phase1/*.c"),
               *ROOT.glob("collector/*d9*"), ROOT / "src/kicba/reconciliation.py"]
    save(output / "manifest.json", {
        "suite": args.suite, "role": args.role, "seed": args.seed,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "kernel": platform.release(), "protocol_sha256": lock["protocol_sha256"],
        "sources": {str(path.relative_to(ROOT)): sha(path) for path in sources if path.is_file()},
        "package_sha256": hashlib.sha256(subprocess.run(
            ["dpkg-query", "-W"], check=True, capture_output=True).stdout).hexdigest(),
    })
    with (output / "attempts.jsonl").open("x", encoding="utf-8") as stream:
        try:
            globals()["run_" + args.suite](args, output, stream)
            save(output / "completion.json", {"completed": True})
        except BaseException as error:
            emit(stream, {"kind": "suite_failure", "error": repr(error)})
            save(output / "completion.json", {"completed": False, "error": repr(error)})
            raise
    print(json.dumps({"suite": args.suite, "output": str(output), "completed": True}))


if __name__ == "__main__":
    main()
