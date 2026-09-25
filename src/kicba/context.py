from __future__ import annotations

import argparse
import gzip
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np


FEATURE_NAMES = np.asarray(
    [
        "raw_wall_ns",
        "oncpu_ns",
        "offcpu_ns",
        "hardirq_overlap_ns",
        "softirq_overlap_ns",
        "irq_union_overlap_ns",
        "irq_adjusted_wall_ns",
        "accounted_exec_ns",
        "offcpu_fraction",
        "irq_fraction",
        "cpu_migrations",
        "frequency_changes",
    ],
    dtype=str,
)


@dataclass(frozen=True)
class Span:
    start_ns: int
    end_ns: int
    cpu: int
    complete: bool = True


@dataclass(frozen=True)
class Invocation:
    batch_id: str
    label: str
    condition: str
    function: str
    pid: int
    start_ns: int
    end_ns: int
    raw_wall_ns: int
    oncpu_ns: int
    offcpu_ns: int
    hardirq_overlap_ns: int
    softirq_overlap_ns: int
    irq_union_overlap_ns: int
    accounted_exec_ns: int
    offcpu_fraction: float
    irq_fraction: float
    cpu_migrations: int
    frequency_changes: int
    valid: bool
    quality_reasons: tuple[str, ...]

    def feature_vector(self) -> np.ndarray:
        return np.asarray(
            [
                self.raw_wall_ns,
                self.oncpu_ns,
                self.offcpu_ns,
                self.hardirq_overlap_ns,
                self.softirq_overlap_ns,
                self.irq_union_overlap_ns,
                self.raw_wall_ns - self.irq_union_overlap_ns,
                self.accounted_exec_ns,
                self.offcpu_fraction,
                self.irq_fraction,
                self.cpu_migrations,
                self.frequency_changes,
            ],
            dtype=float,
        )


@dataclass(frozen=True)
class ProcessedBatch:
    batch_id: str
    boot_id: str
    label: str
    condition: str
    iterations: int
    campaign_id: str
    campaign_position: int
    analysis_functions: tuple[str, ...]
    invocations: tuple[Invocation, ...]
    quality: dict


@dataclass(frozen=True)
class ContextBatchDataset:
    batch_ids: np.ndarray
    boot_ids: np.ndarray
    labels: np.ndarray
    conditions: np.ndarray
    iterations: np.ndarray
    campaign_ids: np.ndarray
    campaign_positions: np.ndarray
    function_names: np.ndarray
    feature_names: np.ndarray
    quantile_probs: np.ndarray
    values: np.ndarray
    invocation_counts: np.ndarray
    quality_valid: np.ndarray

    def validate(self) -> None:
        expected = (
            len(self.batch_ids),
            len(self.function_names),
            len(self.feature_names),
            len(self.quantile_probs),
        )
        if self.values.shape != expected:
            raise ValueError(f"Unexpected context values shape {self.values.shape}; expected {expected}")
        if self.invocation_counts.shape != expected[:2]:
            raise ValueError("invocation_counts shape does not match batches/functions")
        for name in (
            "boot_ids",
            "labels",
            "conditions",
            "iterations",
            "campaign_ids",
            "campaign_positions",
            "quality_valid",
        ):
            if len(getattr(self, name)) != len(self.batch_ids):
                raise ValueError(f"{name} length does not match batches")
        if len(set(self.batch_ids.tolist())) != len(self.batch_ids):
            raise ValueError("Duplicate context batch identifiers")

    def save(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(output, **asdict(self))

    @classmethod
    def load(cls, path: str | Path) -> "ContextBatchDataset":
        with np.load(path, allow_pickle=False) as data:
            dataset = cls(**{field: data[field] for field in cls.__dataclass_fields__})
        dataset.validate()
        return dataset


def _union_duration(spans: Iterable[tuple[int, int]]) -> int:
    ordered = sorted((int(start), int(end)) for start, end in spans if end > start)
    if not ordered:
        return 0
    total = 0
    current_start, current_end = ordered[0]
    for start, end in ordered[1:]:
        if start <= current_end:
            current_end = max(current_end, end)
        else:
            total += current_end - current_start
            current_start, current_end = start, end
    return total + current_end - current_start


def _overlap_spans(run_spans: Sequence[Span], interrupt_spans: Sequence[Span]) -> list[tuple[int, int]]:
    intersections: list[tuple[int, int]] = []
    for run in run_spans:
        for interrupt in interrupt_spans:
            if run.cpu != interrupt.cpu:
                continue
            start = max(run.start_ns, interrupt.start_ns)
            end = min(run.end_ns, interrupt.end_ns)
            if end > start:
                intersections.append((start, end))
    return intersections


def _pair_interrupts(
    events: Sequence[dict],
    prefix: str,
    collection_start_ns: int,
    collection_end_ns: int,
) -> tuple[list[Span], int, int]:
    stacks: dict[tuple[int, int], list[int]] = defaultdict(list)
    spans: list[Span] = []
    unmatched_exits = 0
    enter_kind = f"{prefix}_enter"
    exit_kind = f"{prefix}_exit"
    for event in events:
        kind = event.get("kind")
        if kind not in (enter_kind, exit_kind):
            continue
        key = (int(event.get("cpu", -1)), int(event.get("aux", -1)))
        timestamp = int(event["ts"])
        if kind == enter_kind:
            stacks[key].append(timestamp)
        elif stacks[key]:
            start = stacks[key].pop()
            if timestamp >= start:
                spans.append(Span(start, timestamp, key[0], True))
        else:
            unmatched_exits += 1
            spans.append(Span(collection_start_ns, timestamp, key[0], False))
    unmatched_entries = sum(len(stack) for stack in stacks.values())
    for (cpu, _aux), stack in stacks.items():
        for start in stack:
            spans.append(Span(start, collection_end_ns, cpu, False))
    return spans, unmatched_entries, unmatched_exits


def _pair_targets(events: Sequence[dict]) -> tuple[list[tuple[dict, dict]], int, int]:
    stacks: dict[tuple[int, str], list[dict]] = defaultdict(list)
    pairs: list[tuple[dict, dict]] = []
    unmatched_returns = 0
    for event in events:
        kind = event.get("kind")
        function = event.get("function")
        if kind not in ("target_enter", "target_return") or not function:
            continue
        key = (int(event.get("pid", -1)), str(function))
        if kind == "target_enter":
            stacks[key].append(event)
        elif stacks[key]:
            entry = stacks[key].pop()
            if int(event["ts"]) >= int(entry["ts"]):
                pairs.append((entry, event))
            else:
                unmatched_returns += 1
        else:
            unmatched_returns += 1
    unmatched_entries = sum(len(stack) for stack in stacks.values())
    return pairs, unmatched_entries, unmatched_returns


def _running_spans(
    entry: dict, return_event: dict, schedule_events: Sequence[dict]
) -> tuple[list[Span], int, tuple[str, ...]]:
    pid = int(entry["pid"])
    start_ns = int(entry["ts"])
    end_ns = int(return_event["ts"])
    current_cpu = int(entry.get("cpu", -1))
    last_cpu = current_cpu
    run_start = start_ns
    running = True
    migrations = 0
    spans: list[Span] = []
    reasons: list[str] = []

    for event in schedule_events:
        timestamp = int(event["ts"])
        if timestamp <= start_ns or timestamp >= end_ns:
            continue
        switched_out = int(event.get("pid", -1)) == pid
        switched_in = int(event.get("other_pid", -1)) == pid
        if switched_out:
            if not running:
                reasons.append("duplicate_sched_out")
            else:
                spans.append(Span(run_start, timestamp, current_cpu, True))
                running = False
        if switched_in:
            new_cpu = int(event.get("cpu", -1))
            if running:
                reasons.append("sched_in_while_running")
            else:
                if last_cpu != new_cpu:
                    migrations += 1
                current_cpu = new_cpu
                last_cpu = new_cpu
                run_start = timestamp
                running = True

    if running:
        return_cpu = int(return_event.get("cpu", current_cpu))
        if return_cpu != current_cpu:
            reasons.append("cpu_changed_without_sched_switch")
        spans.append(Span(run_start, end_ns, current_cpu, True))
    else:
        reasons.append("return_while_offcpu")
    return spans, migrations, tuple(sorted(set(reasons)))


def _invocation_from_pair(
    batch_id: str,
    label: str,
    condition: str,
    entry: dict,
    return_event: dict,
    schedule_events: Sequence[dict],
    hardirq_spans: Sequence[Span],
    softirq_spans: Sequence[Span],
    frequency_events: Sequence[dict],
) -> Invocation:
    start_ns = int(entry["ts"])
    end_ns = int(return_event["ts"])
    raw_wall_ns = end_ns - start_ns
    run_spans, migrations, schedule_reasons = _running_spans(
        entry, return_event, schedule_events
    )
    oncpu_ns = _union_duration((span.start_ns, span.end_ns) for span in run_spans)
    offcpu_ns = max(0, raw_wall_ns - oncpu_ns)
    hard_intersections = _overlap_spans(run_spans, hardirq_spans)
    soft_intersections = _overlap_spans(run_spans, softirq_spans)
    hardirq_overlap_ns = _union_duration(hard_intersections)
    softirq_overlap_ns = _union_duration(soft_intersections)
    irq_union_overlap_ns = _union_duration(hard_intersections + soft_intersections)
    accounted_exec_ns = max(0, raw_wall_ns - offcpu_ns - irq_union_overlap_ns)

    incomplete_interrupt = any(
        not span.complete
        and _overlap_spans(run_spans, [span])
        for span in (*hardirq_spans, *softirq_spans)
    )
    reasons = list(schedule_reasons)
    if incomplete_interrupt:
        reasons.append("incomplete_interrupt_boundary")
    if raw_wall_ns <= 0:
        reasons.append("nonpositive_interval")

    frequency_changes = 0
    for event in frequency_events:
        timestamp = int(event["ts"])
        cpu = int(event.get("cpu", -1))
        if any(
            span.cpu == cpu and span.start_ns <= timestamp <= span.end_ns
            for span in run_spans
        ):
            frequency_changes += 1

    return Invocation(
        batch_id=batch_id,
        label=label,
        condition=condition,
        function=str(entry["function"]),
        pid=int(entry["pid"]),
        start_ns=start_ns,
        end_ns=end_ns,
        raw_wall_ns=raw_wall_ns,
        oncpu_ns=oncpu_ns,
        offcpu_ns=offcpu_ns,
        hardirq_overlap_ns=hardirq_overlap_ns,
        softirq_overlap_ns=softirq_overlap_ns,
        irq_union_overlap_ns=irq_union_overlap_ns,
        accounted_exec_ns=accounted_exec_ns,
        offcpu_fraction=offcpu_ns / raw_wall_ns if raw_wall_ns > 0 else float("nan"),
        irq_fraction=irq_union_overlap_ns / raw_wall_ns if raw_wall_ns > 0 else float("nan"),
        cpu_migrations=migrations,
        frequency_changes=frequency_changes,
        valid=not reasons,
        quality_reasons=tuple(sorted(set(reasons))),
    )


def process_record(record: dict) -> ProcessedBatch:
    if int(record.get("schema_version", -1)) not in {1, 2, 3}:
        raise ValueError(f"Unsupported collector schema {record.get('schema_version')!r}")
    batch_id = str(record["batch_id"])
    boot_id = str(record.get("environment", {}).get("boot_id", "unknown"))
    truth = record.get("truth", {})
    label = str(truth.get("label", "unknown"))
    condition = str(truth.get("condition", "unknown"))
    events = sorted(record.get("events", []), key=lambda event: int(event["ts"]))
    collection = record.get("collection", {})
    iterations = int(collection.get("iterations", 0))
    campaign_id = str(collection.get("campaign_id") or "unknown")
    raw_campaign_position = collection.get("campaign_position", -1)
    campaign_position = (
        -1 if raw_campaign_position is None else int(raw_campaign_position)
    )
    timestamps = [int(event["ts"]) for event in events]
    collection_start_ns = int(
        collection.get("enabled_started_ns")
        or (min(timestamps) if timestamps else 0)
    )
    collection_end_ns = int(
        collection.get("enabled_ended_ns")
        or (max(timestamps) if timestamps else collection_start_ns)
    )
    if collection_end_ns < collection_start_ns:
        raise ValueError("Collection end precedes start")

    hardirq_spans, hard_unmatched_entry, hard_unmatched_exit = _pair_interrupts(
        events, "hardirq", collection_start_ns, collection_end_ns
    )
    softirq_spans, soft_unmatched_entry, soft_unmatched_exit = _pair_interrupts(
        events, "softirq", collection_start_ns, collection_end_ns
    )
    target_pairs, target_unmatched_entry, target_unmatched_return = _pair_targets(events)
    schedule_events = [event for event in events if event.get("kind") == "sched_switch"]
    frequency_events = [event for event in events if event.get("kind") == "cpu_frequency"]
    invocations = tuple(
        _invocation_from_pair(
            batch_id,
            label,
            condition,
            entry,
            return_event,
            schedule_events,
            hardirq_spans,
            softirq_spans,
            frequency_events,
        )
        for entry, return_event in target_pairs
    )

    lost_events = int(collection.get("lost_events", 0))
    raw_valid = bool(record.get("quality", {}).get("valid_for_analysis", True))
    invalid_invocations = sum(not invocation.valid for invocation in invocations)
    reasons: list[str] = []
    if not raw_valid:
        reasons.append("collector_quality_failure")
    if lost_events:
        reasons.append("perf_events_lost")
    if target_unmatched_entry or target_unmatched_return:
        reasons.append("unmatched_target_events")
    if not invocations:
        reasons.append("no_complete_target_intervals")
    observed_functions = {invocation.function for invocation in invocations}
    configured_analysis_functions = (
        collection.get("primary_timing_functions")
        or record.get("quality", {}).get("primary_timing_functions")
        or collection.get("attached_functions")
    )
    expected_functions = set(configured_analysis_functions or observed_functions)
    if expected_functions - observed_functions:
        reasons.append("missing_target_function_intervals")
    if invalid_invocations:
        reasons.append("invalid_invocations")
    quality = {
        "valid_for_analysis": not reasons,
        "reasons": reasons,
        "lost_events": lost_events,
        "invocations": len(invocations),
        "valid_invocations": len(invocations) - invalid_invocations,
        "invalid_invocations": invalid_invocations,
        "unmatched_target_entries": target_unmatched_entry,
        "unmatched_target_returns": target_unmatched_return,
        "unmatched_hardirq_entries": hard_unmatched_entry,
        "unmatched_hardirq_exits": hard_unmatched_exit,
        "unmatched_softirq_entries": soft_unmatched_entry,
        "unmatched_softirq_exits": soft_unmatched_exit,
    }
    return ProcessedBatch(
        batch_id,
        boot_id,
        label,
        condition,
        iterations,
        campaign_id,
        campaign_position,
        tuple(sorted(expected_functions)),
        invocations,
        quality,
    )


def read_batch(path: str | Path) -> ProcessedBatch:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return process_record(json.load(handle))


def build_context_dataset(
    batches: Sequence[ProcessedBatch], num_quantiles: int = 9
) -> ContextBatchDataset:
    if num_quantiles < 1:
        raise ValueError("num_quantiles must be positive")
    quantile_probs = np.linspace(
        0.0, 1.0 - 1.0 / (num_quantiles + 1), num_quantiles + 1
    )[1:]
    function_sets = {batch.analysis_functions for batch in batches}
    if len(function_sets) > 1:
        raise ValueError("Batches do not use one consistent primary timing function set")
    function_names = np.asarray(
        sorted(next(iter(function_sets), ())), dtype=str
    )
    shape = (len(batches), len(function_names), len(FEATURE_NAMES), len(quantile_probs))
    values = np.full(shape, np.nan, dtype=float)
    counts = np.zeros(shape[:2], dtype=np.int64)
    function_index = {name: idx for idx, name in enumerate(function_names)}
    for batch_idx, batch in enumerate(batches):
        by_function: dict[str, list[np.ndarray]] = defaultdict(list)
        for invocation in batch.invocations:
            if invocation.valid:
                by_function[invocation.function].append(invocation.feature_vector())
        for function, vectors in by_function.items():
            if function not in function_index:
                continue
            matrix = np.asarray(vectors, dtype=float)
            function_idx = function_index[function]
            values[batch_idx, function_idx] = np.quantile(
                matrix, quantile_probs, axis=0
            ).T
            counts[batch_idx, function_idx] = len(matrix)

    dataset = ContextBatchDataset(
        batch_ids=np.asarray([batch.batch_id for batch in batches], dtype=str),
        boot_ids=np.asarray([batch.boot_id for batch in batches], dtype=str),
        labels=np.asarray([batch.label for batch in batches], dtype=str),
        conditions=np.asarray([batch.condition for batch in batches], dtype=str),
        iterations=np.asarray([batch.iterations for batch in batches], dtype=np.int64),
        campaign_ids=np.asarray([batch.campaign_id for batch in batches], dtype=str),
        campaign_positions=np.asarray(
            [batch.campaign_position for batch in batches], dtype=np.int64
        ),
        function_names=function_names,
        feature_names=FEATURE_NAMES.copy(),
        quantile_probs=quantile_probs,
        values=values,
        invocation_counts=counts,
        quality_valid=np.asarray(
            [bool(batch.quality["valid_for_analysis"]) for batch in batches], dtype=bool
        ),
    )
    dataset.validate()
    return dataset


def _input_paths(inputs: Sequence[Path]) -> list[Path]:
    paths: list[Path] = []
    for item in inputs:
        if item.is_dir():
            paths.extend(sorted(item.glob("batch_*.json.gz")))
        elif item.is_file():
            paths.append(item)
        else:
            raise FileNotFoundError(item)
    unique = list(dict.fromkeys(path.resolve() for path in paths))
    if not unique:
        raise ValueError("No batch_*.json.gz inputs found")
    return unique


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", nargs="+", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--quality-output", type=Path)
    parser.add_argument("--quantiles", default=9, type=int)
    args = parser.parse_args(argv)
    paths = _input_paths(args.input)
    quality_path = args.quality_output or args.output.with_suffix(".quality.jsonl")
    quality_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_quality_path = quality_path.with_suffix(quality_path.suffix + ".tmp")
    batch_ids: list[str] = []
    boot_ids: list[str] = []
    labels: list[str] = []
    conditions: list[str] = []
    iterations: list[int] = []
    campaign_ids: list[str] = []
    campaign_positions: list[int] = []
    value_rows: list[np.ndarray] = []
    count_rows: list[np.ndarray] = []
    quality_valid: list[bool] = []
    function_names: np.ndarray | None = None
    feature_names: np.ndarray | None = None
    quantile_probs: np.ndarray | None = None
    with temporary_quality_path.open("w", encoding="utf-8") as handle:
        for path in paths:
            batch = read_batch(path)
            one = build_context_dataset([batch], args.quantiles)
            if function_names is None:
                function_names = one.function_names.copy()
                feature_names = one.feature_names.copy()
                quantile_probs = one.quantile_probs.copy()
            elif (
                not np.array_equal(function_names, one.function_names)
                or not np.array_equal(feature_names, one.feature_names)
                or not np.array_equal(quantile_probs, one.quantile_probs)
            ):
                raise ValueError("Batch feature schema changed during streaming conversion")
            batch_ids.append(batch.batch_id)
            boot_ids.append(batch.boot_id)
            labels.append(batch.label)
            conditions.append(batch.condition)
            iterations.append(batch.iterations)
            campaign_ids.append(batch.campaign_id)
            campaign_positions.append(batch.campaign_position)
            value_rows.append(one.values[0])
            count_rows.append(one.invocation_counts[0])
            quality_valid.append(bool(batch.quality["valid_for_analysis"]))
            handle.write(
                json.dumps(
                    {"source": str(path), "batch_id": batch.batch_id, **batch.quality},
                    separators=(",", ":"),
                )
                + "\n"
            )
    if function_names is None or feature_names is None or quantile_probs is None:
        raise ValueError("No batches were converted")
    dataset = ContextBatchDataset(
        batch_ids=np.asarray(batch_ids, dtype=str),
        boot_ids=np.asarray(boot_ids, dtype=str),
        labels=np.asarray(labels, dtype=str),
        conditions=np.asarray(conditions, dtype=str),
        iterations=np.asarray(iterations, dtype=np.int64),
        campaign_ids=np.asarray(campaign_ids, dtype=str),
        campaign_positions=np.asarray(campaign_positions, dtype=np.int64),
        function_names=function_names,
        feature_names=feature_names,
        quantile_probs=quantile_probs,
        values=np.stack(value_rows),
        invocation_counts=np.stack(count_rows),
        quality_valid=np.asarray(quality_valid, dtype=bool),
    )
    dataset.validate()
    dataset.save(args.output)
    temporary_quality_path.replace(quality_path)
    print(
        json.dumps(
            {
                "input_batches": len(batch_ids),
                "valid_batches": int(np.sum(dataset.quality_valid)),
                "functions": dataset.function_names.tolist(),
                "features": dataset.feature_names.tolist(),
                "output": str(args.output),
                "quality_output": str(quality_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
