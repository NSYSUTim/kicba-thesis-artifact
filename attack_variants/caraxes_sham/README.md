# Sham ftrace-hook control

This module installs a pass-through `filldir64` ftrace hook but never hides a
directory entry.  The D4 experiment can therefore separate the cost of having
an ftrace hook from the effect of the controlled CARAXES hiding branch.  It is
not a benign filesystem baseline in production and is used only inside the
isolated VM.

The module imports the exact ftrace helper from the neighboring
`caraxes_continue` source directory.  It must pass the exact-normal-output
check before its timings are interpreted.
