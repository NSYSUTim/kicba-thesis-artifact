# D8 getdents64 matched controls

These modules provide a buffer-editing mechanism that is distinct from the
CARAXES-derived `filldir64` callback wrappers used in D7.  They share only the
generic ftrace attachment helper already used by the project.

All modules are restricted to a process whose `comm` equals
`d8_enum_probe`.  The four build targets are:

- `kicba_d8_getdents_pass.ko`: installs the syscall hook and returns the
  original buffer unchanged.
- `kicba_d8_getdents_active.ko`: copies and parses the returned dirent buffer,
  and performs the same prefix match as the hiding module, but preserves every
  record.
- `kicba_d8_getdents_hiding.ko`: removes records whose name begins with
  `d8_hidden_` before returning the buffer to user space.
- `kicba_d8_getdents_policy.ko`: an explicitly authorized policy control that
  removes records beginning with `d8_policy_`.  It refuses to load unless the
  module parameter `policy_authorized=1` is supplied.

The policy module is not a non-suppression negative control.  It is a
non-malicious suppression control: a behavior detector should alert on it,
while a detector claiming to identify malicious intent should not treat that
alert as sufficient evidence.

These modules are research fixtures for the isolated KICBA-Lab VM.  They must
not be loaded on the Windows host or on a network-connected production system.
