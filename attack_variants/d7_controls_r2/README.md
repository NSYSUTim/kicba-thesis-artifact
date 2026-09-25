# KICBA D7 matched causal controls, qualification r2

Three modules are built from the same wrapper implementation and install the
same five ftrace hooks:

- `kicba_d7_pass.ko`: five-hook pass-through control; no filename test.
- `kicba_d7_active.ko`: performs the same `strstr` test and branch as the
  treatment but always calls the original actor.
- `kicba_d7_hiding.ko`: performs the same test and suppresses a matching entry
  by returning `true` without calling the original actor.

Read-only counters are exposed under
`/sys/module/<module>/parameters/` for all five callbacks plus
`filter_checks` and `filter_matches`. The hooks and treatment remain global,
but these counters default to tasks whose `comm` is `ls`, so unrelated VM
directory walks cannot contaminate the path-equivalence measurement. They are
mechanism-qualification instrumentation and must not be silently removed after
detector development.

These modules do not modify the frozen D6-r2 modules or results.
