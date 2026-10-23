# Phase-two applicability and retained-evidence cost plan

> For agentic workers: execute the user-approved second phase inline with superpowers:executing-plans; preserve review checkpoints and evidence.

Goal: answer the applicability and optimization questions in PROTOCOL_zh-TW.md, preserving original data and scope.

Architecture: phase2 adds one packed-state BPF implementation, a controlled output-transform module, independent-source fixtures, and a runner which compares retained phase1 behavior with the candidate. Existing phase1 and collector files remain byte-identical.

Tech stack: existing Python/BCC/GCC, isolated Hyper-V VM; designated offline kernel packages only on a clone.

Spec: phase2/PROTOCOL_zh-TW.md. User approval: request to complete phase two, with author decisions reserved for real changes of scope or necessary tradeoffs.

## Global constraints

- Match protocol semantics and logical cells; no weakened validity checks or dropped localization.
- Tests, pilots, confirmation, source hashes and failures retained separately.
- All modifications under phase2/. Original VM package versions unchanged.
- Do not implement directions 4/5, general-process collection, /proc or policy decisions.

## Task 1: preservation and versioned sources

- [x] Create and verify pre-phase-two checkpoint, save inventory and original timer states.
- [x] Pin third-party source commit, retain upstream source and compatibility diff; inspect hook scope before building.
- [x] Save original hash lists and protocol before probe/module experiments.
- [x] Verify optional clone can be created with existing host resources; use official pinned 6.5 package bytes only there.

Files: host checkpoint/clone helpers, source provenance JSON, evidence/pilot/, LOCK.json.

## Task 2: real packed-state collector

Files: phase2/bpf_packed.c, phase2/measurement.py, phase2/tests/test_measurement.py.

Interfaces: new_bpf() creates BPF; attach()/detach() retain original symbol and return profile; begin(directory,buffer,dump) registers process state before release; finish() returns validated fingerprint, cells, statistics, timings and decoded difference. State fields include depth, pending_valid, seeds, cells, count, sums, error counters and cells[256].

- [x] Write host behavior tests for oracle transformations, invalid dominance and multiplicity; observe missing implementation failures.
- [x] Implement packed state with preallocated per-thread records, unchanged name hash and outer-return acceptance.
- [x] Add real Linux integration tests comparing all fingerprints/cells with independent Python on long names, tiny buffers, ordinary files and directories.
- [x] Prove invalid config/state and genuine return loss reject; prove 16 concurrent scans stay separated; record legal small-table decode failure.

## Task 3: controlled differences and independent hiding

Files: phase2/module/transform.c, Makefile, phase2/oracle.py, phase2/tests/test_actions.py, third_party/.

Interfaces: transform module mode selects reorder/insert/grow/shrink/inode/type/remove, only acts on a named fixture subject; read-only sysfs counters report actual transformations and no-space skips. oracle returns expected raw identities and upstream-only/downstream-only token multisets from the specified action, independently of collector decoding.

- [x] Tests require exact unchanged common records, legitimate aligned record lengths, decoded identity changes and reorder equality.
- [x] Build transform module using existing ftrace compatibility helper, preserving source attribution.
- [x] Run no-probe exact-output controls; verify real mutation counters, retain skips.
- [x] Build pinned third-party filter with explicit compatibility-only changes; separately verify suppression with and without probes and both attachment orders.

## Task 4: pilot, frozen confirmation and analysis

Files: phase2/run_campaign.py, run_confirmation.py, orchestrate.py, analysis/make_report.py, REPORT_zh-TW.md.

Interfaces: one append-only row per attempt with environment/boot ID, FS, action, implementation, buffer, raw output path, quality, expected and actual identities, timing boundaries and errors. A single confirmation lock names every runtime input digest.

- [x] Run each pilot on supported environments; inspect failures before locking exact matrix and sample counts.
- [x] Freeze reviewed code and protocol before three fresh confirmation boots per supported kernel.
- [x] Execute static actions, active dynamic churn, fidelity controls, randomized paired costs and map allocations.
- [x] Derive per-boot counts, invalid reasons, correct/failed/incorrect decodes, timing distributions and paired ratios; keep invalid data out of valid metrics while reporting it.
- [x] Archive complete raw records with SHA-256, verify original files/environment and restore timers. Stop at phase-two report; local commit only.

## Completion record

Six confirmation boot IDs completed: three each on Linux 6.8 and 6.5. Retained confirmation totals: 5,760 measured static trials, 264 no-probe controls, 480 active dynamic trials, 1,080 primary cost observations and 216 warmups. All independent raw-output, signed-recovery and dynamic fingerprint/cell/activity checks passed. Unexercised insertions (252 including controls) remain separate from positive cases.

Both kernels passed the 10 native test methods; 18 evidence records per kernel cover the subcases. The final host regression run executed 43 tests successfully, with 12 Linux-only checks skipped on Windows. See analysis/PYTHON_TESTS.json and analysis/TEST_RUN_NOTES.md.

The complete phase2/LOCK.json was assembled after pilots; it does not pretend to be a pre-pilot timestamp. The prior phase-one lock/commit and pilot protocol/source manifests preserve the earlier baseline. The two confirmation locks and exact executable/source archives were created before all confirmation boots.

An additional agent review was requested but failed with workspace credits exhausted; no independent agent approval is claimed. Main-agent source inspection, native tests and independent raw-data recomputation are the verification actually completed.

The original VM package inventory, kernel, source hashes, timer states, module and probe cleanup passed final checks. All 11 evidence archives and both 66-input confirmation source bundles passed SHA-256 verification. Original main and phase-one files remain unchanged. Keep this research branch and worktree locally; no merge, push, paper/slides edit or phase-three execution.
