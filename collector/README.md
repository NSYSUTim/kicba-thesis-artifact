# D2 live-kernel collector

This collector records raw events needed to determine whether target function
wall time overlaps scheduling, hard IRQ, or soft IRQ activity. It is a research
instrument, not an endpoint security product.

## Supported development environment

- Linux x86-64 with BCC and tracefs/debugfs.
- Tested initially on the local WSL2 6.6 kernel for **normal-only feasibility**.
- WSL2 results must not be treated as native-machine evidence because host and
  hypervisor delays are not completely observable from the guest.

## Normal smoke test

```bash
cd /path/to/project
sudo python3 collector/collect_batch.py \
  --condition baseline --iterations 100 \
  --output data/d2_raw
```

Available normal conditions are `baseline`, `cpu`, `memory`, and `mixed`.
Each invocation produces one gzip-compressed JSON batch plus a manifest. The
collector records experiment truth separately from raw events.

The `rootkit` label is rejected unless a module named `caraxes` is already
loaded. Rootkit loading/removal is deliberately kept outside this collector so
that experiment truth cannot be created accidentally by a command-line label.

## Event model

- target function entry/return: `iterate_dir`, `filldir64`,
  `verify_dirent_name`, `touch_atime`
- `sched_switch` involving the monitored `ls` task
- hard IRQ entry/exit
- SoftIRQ entry/exit
- CPU-frequency changes
- perf-buffer lost-event count

Target interval pairing and overlap accounting are performed offline. Missing
or unmatched events are retained as quality failures rather than silently
dropped.

Protocol revision D2-r1 uses `iterate_dir`, `filldir64`, and `touch_atime` as
the primary timing feature set. `verify_dirent_name` remains attached and its
counts remain in every raw record, but its zero-hit state under CARAXES is not
used as a primary detector feature. See `docs/protocol_amendment_D2_r1.md`.

## Full native-VM campaign

After probe diagnostics succeed and a disposable VM snapshot exists, one boot
campaign is run as root with an explicit acknowledgement:

The helper below provisions a fresh native Ubuntu VM, pins both upstream
repositories, and builds—but never loads—CARAXES:

```bash
sudo bash collector/provision_ubuntu_vm.sh
```

Pinned revisions:

- Trace of the Times: `269d9b0bc6aafb403cba209bb47b8bdb902ba10e`
- CARAXES: `899e8be6b5f6c7236bd23b52aa65051de757e0b3`

Take a clean VM snapshot after provisioning. Then run the diagnostic and only
continue if all target probes receive events during `ls`.

```bash
python3 collector/run_campaign.py \
  --caraxes-ko /opt/kicba/caraxes/caraxes.ko \
  --output data/d2_raw --rounds 30 --iterations 100 --seed 1001 \
  --isolated-vm-ack I_UNDERSTAND_THIS_LOADS_A_ROOTKIT_IN_AN_ISOLATED_VM
```

The script refuses WSL, records the boot ID, CARAXES SHA-256, randomized block
schedule and output of every batch, and attempts to unload CARAXES on every
exit path. Use a clean reboot for at least five boot IDs and a different
preassigned seed per boot. Retain the clean snapshot for recovery if module
cleanup fails; do not overwrite failed campaign evidence.

Process and evaluate only after all campaigns complete:

```bash
PYTHONPATH=src python3 scripts/process_context_batches.py \
  --input data/d2_raw --output data/processed/context_q9.npz
PYTHONPATH=src python3 scripts/run_d2_experiments.py \
  --data data/processed/context_q9.npz --output results/d2
```

Measure overhead separately with CARAXES unloaded. The script randomizes paired
uninstrumented/instrumented blocks and excludes BPF compile/attach and workload
warm-up from the measured interval:

```bash
sudo python3 collector/measure_overhead.py \
  --output data/d2_overhead --repeats 20 --iterations 100 --seed 20260914
```

`results/d2/comparisons.csv` contains boot-clustered bootstrap intervals for the
preregistered KICBA comparisons. Condition-level FPR tests also include Holm
adjustment; `drift` excludes the baseline condition and is the primary scope.
