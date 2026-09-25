# Third-party notices

This research artifact contains or derives selected components from earlier academic and open-source work. It does **not** vendor the complete upstream Trace of the Times repository.

## Trace of the Times

- Project: `ait-aecid/rootkit-detection-ebpf-time-trace`
- Repository: https://github.com/ait-aecid/rootkit-detection-ebpf-time-trace
- Research-pinned revision: `269d9b0bc6aafb403cba209bb47b8bdb902ba10e`
- Upstream license: GPL-3.0
- Use here: experimental starting point, public-data reproduction, and frozen timing comparator.

## CARAXES

- Project: `ait-aecid/caraxes`
- Repository: https://github.com/ait-aecid/caraxes
- Upstream license: GPL-3.0
- Included derivative area: `attack_variants/caraxes_continue/`
- Research changes: continue-enumeration behavior plus matched pass-through, active-logic, and hiding controls. See `attack_variants/caraxes_continue/README_VARIANT.md` and `docs/method_provenance_audit_2026-09-20.md`.

The copied GPL text is retained at `attack_variants/caraxes_continue/LICENSE`. Some CARAXES files also identify code originating from Diamorphine and `ilammy/ftrace-hook`; their notices and source references remain in the relevant source files.

## Public data set

- M. Landauer et al., *Kernel Function Time Measurement Data Set for Anomaly-based Rootkit Detection*.
- DOI: https://doi.org/10.5281/zenodo.14679675
- The original data archive is not redistributed in this repository. Only derived results, compact formal views, provenance, and checksum information needed for the thesis evidence chain are included.

Third-party materials remain subject to their original licenses and attribution requirements. No repository-wide license is granted by this notice.
