"""Descriptive summaries with explicit invalid and warmup denominators."""

import json
import statistics
from collections import defaultdict
from pathlib import Path


def load(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


def distribution(values):
    if not values:
        return {"n": 0, "median": None, "min": None, "max": None, "q1": None, "q3": None}
    quartiles = statistics.quantiles(values, n=4, method="inclusive") if len(values) > 1 else [values[0]] * 3
    return {"n": len(values), "median": statistics.median(values),
            "min": min(values), "max": max(values), "q1": quartiles[0], "q3": quartiles[2]}


def coverage_summary(rows):
    summary = {}
    for active in (1, 256):
        selected = [row for row in rows if row.get("kind") == "concurrent_loss"
                    and row["maxactive"] == active]
        positive = [row for row in selected if any((value["missed_delta"] or 0) > 0
                    for value in row["coverage"]["per_event"].values())]
        summary["maxactive_" + str(active)] = {
            "windows": len(selected), "missed_windows": len(positive),
            "missed_total": sum(sum((value["missed_delta"] or 0)
                                for value in row["coverage"]["per_event"].values()) for row in selected),
            "transactions": sum(len(row["transactions"]) for row in selected),
            "invalid_transactions": sum(tx.get("verdict") == "invalid" for row in selected for tx in row["transactions"]),
            "false_valid_when_missed": sum(tx.get("verdict") != "invalid" for row in positive for tx in row["transactions"]),
        }
    normal = [row for row in rows if row.get("kind") == "normal_quality"]
    summary["normal"] = {"windows": len(normal),
                         "equal": sum(row.get("verdict") == "equal" for row in normal),
                         "different": sum(row.get("verdict") == "different" for row in normal),
                         "invalid": sum(row.get("verdict") == "invalid" for row in normal),
                         "decode_failures": sum(row.get("decode_success") is not True for row in normal)}
    return summary


def fidelity_summary(rows):
    trials = [row for row in rows if row.get("kind") == "fidelity"]
    full = [row for row in trials if row["kernel_mode"] == 4]
    return {"trials": len(trials), "full_trials": len(full),
            "setup_failures": sum(row.get("kind") == "fidelity_setup_failure" for row in rows),
            "output_mismatch": sum(row.get("output_matches_expected") is not True for row in trials),
            "verdict_mismatch": sum(row.get("verdict_matches_expected") is not True for row in full),
            "decode_mismatch": sum(row.get("decoded_exact") is not True for row in full)}


def cost_eligible(row):
    return (row.get("count_matches") is True and row.get("load_active") is True
            and row.get("original_valid") is True
            and row.get("verdict") in {"equal", "diagnostic", "not_measured"}
            and (row.get("mode") != "decode" or (
                row.get("decode_success") is True
                and row.get("upstream_only") == [] and row.get("downstream_only") == [])))


def cost_summary(rows):
    attempts = [row for row in rows if row.get("kind") == "cost"]
    primary = [row for row in attempts if not row["warmup"]]
    eligible = [row for row in primary if cost_eligible(row)]
    groups = defaultdict(list)
    for row in eligible:
        groups[f"{row['cardinality']}/{row['condition']}/{row['mode']}"].append(row)
    result = {"attempts": len(attempts), "warmups": len(attempts) - len(primary),
              "primary": len(primary), "excluded_primary": len(primary) - len(eligible), "groups": {}}
    metrics = ("wall_ns", "wall_with_coverage_ns", "readback_ns", "decode_ns", "cleanup_ns", "json_parse_ns")
    for key, group in groups.items():
        result["groups"][key] = {metric: distribution([row[metric] for row in group if metric in row]) for metric in metrics}
        result["groups"][key]["scan_ns"] = distribution([row["userspace"]["scan_ns"] for row in group])
    increments = [("user_fp", "parse"), ("user_iblt", "user_fp"), ("empty", "user_iblt"),
                  ("bookkeeping", "empty"), ("names", "bookkeeping"), ("kernel_fp", "names"),
                  ("kernel_iblt", "kernel_fp"), ("readback", "kernel_iblt"), ("decode", "readback")]
    paired = defaultdict(dict)
    for row in eligible:
        paired[(row["cardinality"], row["condition"], row["block"])][row["mode"]] = row["wall_ns"]
    differences = defaultdict(list)
    ratios = defaultdict(list)
    for (count, condition, _), block in paired.items():
        for high, low in increments:
            if high in block and low in block:
                differences[f"{count}/{condition}/{high}-{low}"].append(block[high] - block[low])
        if "decode" in block and "parse" in block:
            ratios[f"{count}/{condition}/full_over_parse"].append(block["decode"] / block["parse"])
    result["paired_differences_ns"] = {key: distribution(values) for key, values in differences.items()}
    result["paired_ratios"] = {key: distribution(values) for key, values in ratios.items()}
    return result
