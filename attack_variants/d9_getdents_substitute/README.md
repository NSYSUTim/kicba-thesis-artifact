# D9 equal-cardinality substitution fixture

This isolated-VM-only kernel module rewrites the prefix `d9_swap_a_` to the
same-length prefix `d9_swap_b_` in records returned by `getdents64` to the
`d9_enum_probe` process.  It does not change the record count or returned byte
count.

The fixture is not presented as a real-world rootkit.  It is a controlled
counterexample for count-only consistency checks: one upstream identity is
replaced by one downstream identity, so cardinality is equal while the sets
differ.  D9 should report both the upstream-only and downstream-only tokens.

Build and load only inside the network-isolated KICBA VM.
