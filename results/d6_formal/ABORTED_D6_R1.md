# D6-r1 aborted record

- Aborted at: 2026-09-20 16:18 Asia/Taipei (state failure timestamp `2026-09-20T08:18:59.584907+00:00`).
- Reason: collection was stopped after identifying design/implementation inconsistencies before any D6-r1 outcome analysis.
- Completed: boot 1 and boot 2, 460 batches each.
- Partial: boot 3 stopped during campaign position 272; exported directory contains all files preserved by the guest.
- Preserved locally: 1,199 `batch_*.json.gz` files, three campaign manifests, state, and service log.
- Guest service: disabled and inactive after the stop.
- Guest safety state after stop: `caraxes` and `caraxes_sham` unloaded; no default route.
- Local/guest state SHA-256: `616e3a186287f53a9b46c0f4a23a6800fd639b6d9af6e0ca6102cb8217476f2f`.
- Local/guest service-log SHA-256: `ff99a1fb844e17b555979a8ecf45c29539425459b2050e7efd32b8ba048361c4`.

## Evidence policy

D6-r1 is retained as an aborted protocol-execution record. It must not be used as confirmatory efficacy evidence and its attack/normal outcomes must not be inspected to tune D6-r2. The original guest state and manifests were not edited to disguise the interruption; the local `aborted_r1` directory is a byte-preserving export.

## Required D6-r2 corrections

1. Implement the operational detector and explicit `attack` / `drift` / `normal` state machine described by the protocol, or remove those claims from the protocol.
2. Counterbalance test block order across boots so state and elapsed campaign time are not deterministically confounded.
3. Separate pure unloaded-normal FPR, sham FPR, and aggregate non-attack FPR in code and reporting.
4. Add D6-specific tests for schedule balance, prequential prediction/update order, metrics denominators, hash validation, and refusal to overwrite/reanalyse.
5. Verify collector, BPF, campaign runner, multiboot runner, modules, manifests, and audit before the one-shot analysis.
