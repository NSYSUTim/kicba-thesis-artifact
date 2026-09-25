#!/usr/bin/env python3
"""D7 aggregate collector with matched-control callback counters.

This wraps the frozen D4 aggregate collector without modifying it.  The only
label-awareness change is to treat ``kicba_d7_hiding`` as the hiding module.
After collection, the wrapper appends read-only module counters to the gzip
record so the causal-control path can be audited per batch.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import collect_d4_aggregate_batch as base


PROTOCOL = "D7-mechanism-r2-2026-09-21"
MODULE_BY_STATE = {
    "pass": "kicba_d7_pass",
    "active": "kicba_d7_active",
    "hiding": "kicba_d7_hiding",
}
COUNTERS = (
    "fillonedir_calls",
    "filldir_calls",
    "filldir64_calls",
    "compat_fillonedir_calls",
    "compat_filldir_calls",
    "filter_checks",
    "filter_matches",
)


_original_module_loaded = base._module_loaded
_original_collect = base.collect


def _d7_aware_module_loaded(name: str) -> bool:
    if name == "caraxes":
        return _original_module_loaded("kicba_d7_hiding")
    return _original_module_loaded(name)


def _loaded_state() -> tuple[str, str | None]:
    loaded = [
        (state, module)
        for state, module in MODULE_BY_STATE.items()
        if _original_module_loaded(module)
    ]
    if not loaded:
        return "unloaded", None
    if len(loaded) != 1:
        raise RuntimeError(f"multiple D7 modules loaded: {loaded}")
    return loaded[0]


def _read_counters(module: str | None) -> dict[str, int]:
    if module is None:
        return {name: 0 for name in COUNTERS}
    root = Path("/sys/module") / module / "parameters"
    values = {}
    for name in COUNTERS:
        path = root / name
        if not path.is_file():
            raise RuntimeError(f"missing D7 counter: {path}")
        values[name] = int(path.read_text(encoding="utf-8").strip())
    return values


def collect(args):
    state_before, module_before = _loaded_state()
    counters_before = _read_counters(module_before)
    path = _original_collect(args)
    state_after, module_after = _loaded_state()
    if (state_after, module_after) != (state_before, module_before):
        raise RuntimeError("D7 module state changed during collection")
    counters_after = _read_counters(module_after)
    deltas = {
        name: counters_after[name] - counters_before[name]
        for name in COUNTERS
    }
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        record = json.load(handle)
    record["protocol_revision"] = PROTOCOL
    record["d7_control"] = {
        "state": state_after,
        "module": module_after,
        "counters_before": counters_before,
        "counters_after": counters_after,
        "counter_deltas": deltas,
        "total_callback_calls": sum(
            deltas[name] for name in COUNTERS[:5]
        ),
    }
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(record, handle, separators=(",", ":"))
    return path


base._module_loaded = _d7_aware_module_loaded
base.collect = collect
base.PROTOCOL_REVISION = PROTOCOL


if __name__ == "__main__":
    base.main()
