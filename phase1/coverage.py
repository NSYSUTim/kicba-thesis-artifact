"""Conservative decisions for the exact probe counters observed in a window.

These are global probe counters, not per-process counters. A valid window says
only that the explicitly named counters did not report misses or resets; it
does not certify mechanisms that the attachment backend does not expose.
"""

from __future__ import annotations

import re
from typing import Any


_EVENT = re.compile(r"[A-Za-z_][A-Za-z0-9_:/.-]*", re.ASCII)
_COUNTER = re.compile(r"[0-9]+", re.ASCII)


def _event_name(value: Any) -> bool:
    return isinstance(value, str) and _EVENT.fullmatch(value) is not None


def parse_profile(text: str) -> dict[str, dict[str, int]]:
    """Parse exact ``event hits missed`` rows; reject ambiguous partial data."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("missing or empty profile")
    rows: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if (len(fields) != 3 or not _event_name(fields[0])
                or any(_COUNTER.fullmatch(value) is None for value in fields[1:])):
            raise ValueError("malformed profile row")
        name, hits, missed = fields
        if name in rows:
            raise ValueError("duplicate profile event")
        rows[name] = {"hits": int(hits), "missed": int(missed)}
    if not rows:
        raise ValueError("empty profile")
    return rows


def _snapshot(value: Any) -> dict[str, dict[str, int]]:
    if isinstance(value, str):
        return parse_profile(value)
    if not isinstance(value, dict) or not value:
        raise ValueError("missing profile snapshot")
    for name, record in value.items():
        if (not _event_name(name) or not isinstance(record, dict)
                or set(record) != {"hits", "missed"}
                or any(type(number) is not int or number < 0
                       for number in record.values())):
            raise ValueError("malformed profile snapshot")
    return value


def compare_window(before: Any, after: Any, expected_events: Any) -> dict:
    """Fail closed on missing/ambiguous counters and invalidate on global loss.

    Strings or parsed dictionaries are accepted. Unavailable deltas remain
    None. Negative deltas are retained as evidence of a reset, never clamped.
    The caller must separately establish the lifetime/definition of its probes.
    """
    result = {
        "available": False, "valid": False, "reasons": [],
        "missed_scope": "global", "covered_events": [], "per_event": {},
    }
    if (not isinstance(expected_events, (list, tuple)) or not expected_events
            or any(not _event_name(name) for name in expected_events)
            or len(set(expected_events)) != len(expected_events)):
        result["reasons"].append("invalid_expected_event_identity")
        return result
    result["covered_events"] = list(expected_events)
    result["per_event"] = {
        name: {"hits_delta": None, "missed_delta": None}
        for name in expected_events
    }
    try:
        first, last = _snapshot(before), _snapshot(after)
    except ValueError as error:
        result["reasons"].append(str(error))
        return result
    missing = [name for name in expected_events if name not in first or name not in last]
    if missing:
        result["reasons"].extend("missing_exact_event:" + name for name in missing)
        return result
    result["available"] = True
    for name in expected_events:
        hits = last[name]["hits"] - first[name]["hits"]
        missed = last[name]["missed"] - first[name]["missed"]
        result["per_event"][name] = {"hits_delta": hits, "missed_delta": missed}
        if hits < 0 or missed < 0:
            result["reasons"].append("counter_reset:" + name)
        if missed > 0:
            result["reasons"].append("global_probe_missed:" + name)
    result["valid"] = not result["reasons"]
    return result


def combine_verdict(original_valid: Any, fingerprint_equal: Any, coverage: Any) -> str:
    """The coverage/measurement validity gate takes precedence over equality."""
    if (original_valid is not True or type(fingerprint_equal) is not bool
            or not isinstance(coverage, dict)
            or coverage.get("available") is not True
            or coverage.get("valid") is not True
            or coverage.get("reasons") != []):
        return "invalid"
    return "equal" if fingerprint_equal else "different"
