# CARAXES continue-enumeration research variant

This directory is derived from CARAXES commit
`899e8be6b5f6c7236bd23b52aa65051de757e0b3` and is used only inside the
isolated KICBA-Lab VM.

The upstream `hooks_filldir.h` returns `false` and sets `-ENOENT` when a name
contains `MAGIC_WORD`.  For a `dir_context` actor, `false` terminates the
enumeration.  That caused the D2/D3 benchmark to omit visible entries after the
hidden entry and changed the number and role of `iterate_dir` invocations.

This controlled variant skips the original actor for the matched entry but
returns `true`, so enumeration continues.  It must pass the D4 Q0 exact-output
gate before any timing result is interpreted.  It is not installed on the
Windows host and must never be used outside the isolated, host-only VM.
