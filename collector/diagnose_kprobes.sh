#!/usr/bin/env bash
set -euo pipefail

# Exercise the exact BPF program and workload used by the D2 collector.  A
# separate funccount-based check produced false zero-hit results for functions
# that the real paired entry/return probes observed, so the formal gate must
# use the same instrument as the experiment.

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
output_dir="$(mktemp -d /tmp/kicba-probe-diagnostic.XXXXXX)"
trap 'rm -rf -- "$output_dir"' EXIT

python3 "$script_dir/collect_batch.py" \
    --condition baseline \
    --iterations 5 \
    --output "$output_dir" >/dev/null

python3 - "$output_dir" <<'PY'
import gzip
import json
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
batches = sorted(output.glob("batch_*.json.gz"))
if len(batches) != 1:
    raise SystemExit(f"expected exactly one diagnostic batch, found {len(batches)}")

with gzip.open(batches[0], "rt", encoding="utf-8") as handle:
    record = json.load(handle)

quality = record["quality"]
print(f"batch={batches[0].name}")
print(f"lost_events={record['collection']['lost_events']}")
for function, counts in quality["target_function_counts"].items():
    print(f"{function}: enter={counts['enter']} return={counts['return']}")

if not quality["valid_for_analysis"]:
    raise SystemExit("FAIL: diagnostic batch is not valid for analysis")
print("PASS: all preregistered target probes produced paired events")
PY
