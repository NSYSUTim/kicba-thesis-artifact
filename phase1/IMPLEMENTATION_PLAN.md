# Phase-one reliability and cost implementation plan

> For agentic workers: use superpowers:subagent-driven-development for independently scoped implementation and review. This plan executes the user-approved first phase only.

Goal: obtain auditable measurements of probe loss, observation fidelity and component costs without modifying the frozen research artifact.

Architecture: all additions live under phase1/ in a separate worktree. Original collector/ and src/ files are imported or included unchanged. A standalone coverage module supplies conservative validity decisions; compile-time benchmark variants retain the original acceptance semantics. VM experiments are gated on a verified Hyper-V checkpoint and frozen protocol.

Tech stack: Python standard library, C/GCC, existing BCC 0.18.0, Linux 6.8, Hyper-V; no new guest packages. Host-only plotting dependencies are isolated under phase1/.render_deps/.

Spec: phase1/PROTOCOL_zh-TW.md; parent approved assessment ../review/RESEARCH_EXECUTION_ASSESSMENT_20261023_zh-TW.md.

## Global constraints

- Do not modify collector/, src/, original results/, existing locks, paper or slides.
- All new code and output stays in phase1/ or /home/kicba/research_phase1_20261023/.
- Never overwrite an attempt or suppress invalid/failing measurements.
- Verify checkpoint and preserve environment before any new VM probe or module experiment.
- No package refresh, install or upgrade; save package inventories and temporarily pause update timers, restoring their original state at the end.
- First phase stops after its report. Directions 3--7 are not implemented here.

## Task 1: protected baseline and protocol lock

- [x] Create separate worktree from b6fd4af; verify original checkout remains clean.
- [x] Run seven baseline unit tests and original locked analysis into phase1/baseline/.
- [x] Verify Hyper-V checkpoint, record guest inventory, hash original locked files and protocol.
- [x] Save pilot/confirmation counts and cost accounting in the lock before new experiments.

Files: phase1/host/create_checkpoint.ps1, phase1/PROTOCOL_zh-TW.md, phase1/LOCK.json, phase1/host/evidence/, phase1/baseline/.

## Task 2: real coverage parser and validity gate

Create phase1/coverage.py and phase1/tests/test_coverage.py. No BCC import is allowed in this pure module.

Interfaces: parse_profile(text: str) -> dict of exact event-name to hits/missed record; compare_window(before, after, expected_events) -> JSON-compatible result with available, valid, reason list, per-event deltas. Missing/duplicate/malformed/negative rows, count decreases, and missing event identity must never yield valid. Nonzero global missed invalidates the whole window. combine_verdict(original_valid, fingerprint_equal, coverage) yields one of invalid, equal, different; coverage failure must dominate fingerprint status.

- [x] Write tests using literal profile lines and expected decisions, including a normal zero-miss window, missing data, malformed numbers, resets, unrelated-event mismatch and a missed increment with equal fingerprints.
- [x] Run tests to observe failure before implementation.
- [x] Implement minimal parser/gate; run tests and original tests.
- [x] Root reviewed the behavior and recorded source/identity constraints. Independent review was unavailable after agent usage limits; it is not claimed as completed.

Example behavioral requirement:

```python
before = "p_filldir64 12 0\nr_filldir64 12 0\n"
after = "p_filldir64 20 0\nr_filldir64 17 3\n"
# Expected: invalid, r_filldir64 missed_delta=3, even if original fingerprints equal.
```

## Task 3: additive diagnostic variants

Create phase1/bpf_measurement.c and phase1/enum_probe.c, with supporting tests under phase1/tests/. Include the unchanged hash header from collector/. Compile-time branches must retain the original depth/outer-acceptance contract, report invalid states and preserve an observable name-read dependency so optimization cannot delete the diagnostic operation.

Interfaces: BPF phase selector 0 empty, 1 acceptance bookkeeping, 2 name read, 3 fingerprint, 4 full IBLT; existing map names remain compatible with the original controller where relevant. C parser accepts DIRECTORY BUFFER CELLS SEED1 SEED2 MODE; modes 0 parsing/count, 1 fingerprint, 2 full IBLT. JSON preserves count, sum1, sum2, syscalls, returned_bytes, scan_ns and cells. An optional exact-record output is outside the timed scan and includes name bytes, inode and type for fidelity tests.

- [x] Write executable fixture tests for C mode counts, fingerprint agreement and full IBLT rows, malformed configuration and nonempty names.
- [x] Run tests against missing new implementation to observe intended failure.
- [x] Implement variants without changing original files; compile and execute tests in the protected VM once checkpoint is verified.
- [x] Compare full variant against the unchanged implementation on normal and existing controlled differences.

## Task 4: pilot runner and evidence

Create phase1/run_experiments.py with separate coverage, fidelity and cost commands, and phase1/record_environment.py. All commands refuse existing output paths, write raw JSONL per attempt, capture command errors/timeouts and perform owned-resource cleanup. Require an explicit checkpoint evidence file and protocol lock. Record attach and module ordering, actual runtime code hashes, guest boot ID and inventories.

- [x] Exercise coverage snapshots with original BCC attachment and explicit event identification; preserve raw profile/event definitions.
- [x] Run the frozen pilot, including real maxactive=1 loss injection, normal maxactive=256 and exact output controls.
- [x] Run additive random paired cost blocks with recorded timings for readback, decode, cleanup and total boundaries.
- [x] Review pilot against the protocol; retain negative results and revise only with an archived rationale before confirming.

## Task 5: confirmation and final report

- [x] Freeze reviewed implementation hashes and confirmation protocol before three fresh boot campaigns.
- [x] Capture all three boot IDs, timing variation and all failed/invalid attempts; no automatic replacement of failures.
- [x] Produce phase1/REPORT_zh-TW.md with literal counts, distributions, valid-denominator explanations and limits.
- [x] Restore timers, verify environment and original-file hashes, rerun relevant tests, review whole change.
- [x] Stop after first phase; do not merge, publish or update paper/slides.

Completion note: three confirmation boots and five separate fault checks are retained. The diagnostic original_valid flag was corrected in reporting; a separate unchanged-original replay supplies direct reference evidence. See CORRECTIONS_zh-TW.md. Branch and worktree are retained locally; no merge, push, paper or slide edit is authorized in this phase.
