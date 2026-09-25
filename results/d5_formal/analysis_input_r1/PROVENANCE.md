# D5-r1 locked-analysis input

This directory was materialized before running the one-time locked primary analysis.
It contains exact copies of `raw_r1/boot_01` through `raw_r1/boot_05` only.

The complete, unmodified VM export remains in `raw_r1`. Its sibling
`boot_XX_fixture` directories contain fixture files but no campaign manifest or
formal `batch_*.json.gz` observations. They are excluded here because the locked
analysis script requires exactly five directories matching `boot_*`.

No feature, threshold, W20 setting, fusion rule, success rule, manifest, or batch
file was changed.
