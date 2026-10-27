"""Reproduce the paper's offline duplicate cases and inclusive cost analysis.

Reads the existing reconciliation implementation and six checksum-verified raw
archives. It does not load kernel modules, extract archives, change the decoder,
or add these offline cases to any VM experiment denominator.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from kicba.reconciliation import IBLT, MultisetFingerprint, token_for_entry

SEED1 = 0x0123456789ABCDEF
SEED2 = 0xF0E1D2C3B4A59687
PAPER = "paper/cross_layer_directory_entry_consistency_revised33_zhTW.docx"
PAPER_SHA256 = "47169ad7e18b432ce8f66e26d6f2bfaad559d46302f43dd22b56b2711b61bca8"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def duplicate_cases():
    x = token_for_entry("entry_00074.txt", 101, 8, SEED1, SEED2)
    y = token_for_entry("entry_00934.txt", 101, 8, SEED1, SEED2)
    records = []
    for cells in (8, 256, 4096):
        for name, right in (("two_X_vs_empty", []), ("two_X_vs_two_Y", [y, y])):
            upstream = IBLT.from_tokens([x, x], cells, SEED1, SEED2)
            downstream = IBLT.from_tokens(right, cells, SEED1, SEED2)
            delta = upstream.subtract(downstream)
            decoded = delta.decode()
            left_fp = MultisetFingerprint.from_tokens([x, x]).as_tuple()
            right_fp = MultisetFingerprint.from_tokens(right).as_tuple()
            nonzero = [{"position": i, "count": cell.count,
                        "xor_fields": [cell.key_xor, cell.inode_xor,
                                       cell.type_xor, cell.check_xor]}
                       for i, cell in enumerate(delta.cells) if not cell.is_empty()]
            false_empty = name == "two_X_vs_two_Y" and cells in (8, 256)
            expected_residual = 0 if false_empty else (3 if not right else 4)
            if (decoded.success != false_empty
                    or decoded.residual_cells != expected_residual
                    or decoded.upstream_only or decoded.downstream_only
                    or left_fp == right_fp):
                raise RuntimeError("Offline counterexample changed: " + name + "/" + str(cells))
            if any(any(cell["xor_fields"]) or abs(cell["count"]) != 2 for cell in nonzero):
                raise RuntimeError("Unexpected duplicate-cell contents")
            records.append({
                "case": name, "cells": cells,
                "x_positions": sorted(upstream._positions(x.key_hash)),
                "y_positions": sorted(upstream._positions(y.key_hash)),
                "upstream_fingerprint": list(left_fp),
                "downstream_fingerprint": list(right_fp),
                "fingerprints_equal": False, "decode_success": decoded.success,
                "decoded_upstream_count": len(decoded.upstream_only),
                "decoded_downstream_count": len(decoded.downstream_only),
                "residual_cells": decoded.residual_cells,
                "nonzero_cells": nonzero,
            })
    return {"scope": "offline data-structure counterexamples; no VM or rootkit trial",
            "names": ["entry_00074.txt", "entry_00934.txt"],
            "inode": 101, "d_type": 8,
            "seeds_hex": [hex(SEED1), hex(SEED2)], "cases": records}


def paired_cost(rows):
    groups = {}
    for row in rows:
        if not (row.get("kind") == "cost" and row.get("cardinality") == 65536
                and row.get("condition") == "baseline" and row.get("warmup") is False
                and row.get("implementation") in ("legacy", "packed")):
            continue
        if (row.get("verdict") != "equal" or row.get("returncode") != 0
                or any(row.get(key) is not True for key in
                       ("measurement_valid", "count_match", "load_active",
                        "decode_success", "fingerprint_equal"))
                or row.get("coverage", {}).get("valid") is not True):
            raise RuntimeError("Invalid primary cost observation")
        block, mode = row["block"], row["implementation"]
        pair = groups.setdefault(block, {})
        if mode in pair:
            raise RuntimeError("Duplicate implementation in a cost block")
        if not (0 < row["wall_ns"] <= row["wall_with_coverage_ns"]):
            raise RuntimeError("Invalid timing interval")
        pair[mode] = row
    if set(groups) != set(range(10)) or any(set(pair) != {"legacy", "packed"}
                                           for pair in groups.values()):
        raise RuntimeError("Expected ten complete primary cost pairs")
    pairs = []
    for block, pair in sorted(groups.items()):
        item = {"block": block}
        for metric in ("wall_ns", "wall_with_coverage_ns"):
            item[metric] = {mode: pair[mode][metric] for mode in ("legacy", "packed")}
            item[metric]["ratio"] = pair["packed"][metric] / pair["legacy"][metric]
        pairs.append(item)
    return {
        "pairs": pairs, "valid_pairs": len(pairs),
        "ratio_without_queries_median": statistics.median(p["wall_ns"]["ratio"] for p in pairs),
        "ratio_with_queries_median": statistics.median(p["wall_with_coverage_ns"]["ratio"] for p in pairs),
        "with_queries_median_ms": {
            mode: statistics.median(p["wall_with_coverage_ns"][mode] for p in pairs) / 1e6
            for mode in ("legacy", "packed")},
    }


def inclusive_costs():
    record = json.loads((ROOT / "phase2/evidence/EXPORT_VERIFICATION.json").read_text(encoding="utf-8"))
    boots = []
    for tag in ("kernel68", "kernel65"):
        for boot in (1, 2, 3):
            name = f"confirmation_{tag}_boot_{boot:02d}.tar.gz"
            archive = ROOT / "phase2/evidence/downloads" / name
            digest = sha(archive.read_bytes())
            if digest != record["archive_sha256"][name]:
                raise RuntimeError("Archive checksum mismatch: " + name)
            member_name = f"phase2/evidence/{tag}/confirmation_boot_{boot:02d}/campaign/attempts.jsonl"
            with tarfile.open(archive) as bundle:
                with bundle.extractfile(member_name) as stream:
                    rows = [json.loads(line) for line in stream if line.strip()]
            boots.append({"environment": tag, "boot_index": boot, "archive": name,
                          "sha256": digest, "member": member_name, **paired_cost(rows)})
    result = {"scope": "65536 entries; no additional load; six saved confirmation boots",
              "primary_metric": "wall_ns excludes return-probe statistics and event-identity queries",
              "additional_metric": "wall_with_coverage_ns includes those queries and window evaluation",
              "both_metrics_exclude": "BPF compilation and attachment",
              "aggregation": "packed/legacy within each block, then median within each boot",
              "prespecified_adoption_metric": "wall_ns, plus no loss of measurement quality",
              "inclusive_analysis_status": "post hoc additional check; not a new adoption criterion",
              "boots": boots}
    for name, key in (("without_queries", "ratio_without_queries_median"),
                      ("with_queries", "ratio_with_queries_median")):
        values = [b[key] for b in boots]
        result[name] = {"per_boot_ratio_median_range": [min(values), max(values)],
                        "reduction_percent_range": [100 * (1 - max(values)), 100 * (1 - min(values))]}
    for mode in ("legacy", "packed"):
        values = [b["with_queries_median_ms"][mode] for b in boots]
        result[f"{mode}_inclusive_median_ms_range"] = [min(values), max(values)]
    return result


def recompute():
    digest = sha((ROOT / PAPER).read_bytes())
    if digest != PAPER_SHA256:
        raise RuntimeError("The published paper does not match the reviewed revised33 source")
    return {"schema_version": 1, "as_of": "2026-10-27",
            "paper": {"path": PAPER, "original_filename": "paper_final_submission_v3_revised33_clean.docx",
                      "sha256": digest, "copied_without_editing": True},
            "implementation_sha256": sha((ROOT / "src/kicba/reconciliation.py").read_bytes()),
            "new_vm_experiments": False, "experiment_denominators_unchanged": True,
            "offline_iblt": duplicate_cases(), "costs": inclusive_costs(), "passed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--output", type=Path, help="Write a new JSON file; existing files are never replaced")
    target.add_argument("--check", type=Path, help="Recompute and compare with an existing JSON file")
    args = parser.parse_args()
    if args.output and args.output.exists():
        raise FileExistsError(args.output)
    result = recompute()
    if args.check:
        if result != json.loads(args.check.read_text(encoding="utf-8")):
            raise RuntimeError("Published paper-review evidence differs from recomputation")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps({"passed": True, "offline_cases": len(result["offline_iblt"]["cases"]),
                      "confirmation_boots": len(result["costs"]["boots"]),
                      "mode": "check" if args.check else "output"}))


if __name__ == "__main__":
    main()
