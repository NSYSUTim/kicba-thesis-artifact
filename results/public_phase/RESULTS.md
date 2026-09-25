# Public-data phase results

Dataset: 1250 batches; 4 function intervals; 30 split/order seeds.

> These are D1 public-data reproduction and replay results. They do not validate kernel-context gating, because D1 has no synchronized scheduler/IRQ/frequency context.

## Upstream-style seed-42 reproduction

Combined TP=499, FP=9, TN=491, FN=1, F1=0.9901.

This mirrors the source code policy that selects the threshold on test labels and is reported only as a reproduction check.

## Same-scenario detection

| Scenario | Empirical recall | Empirical FPR | Exploratory OAS recall | OAS FPR | Oracle-test F1 |
|---|---:|---:|---:|---:|---:|
| default | 96.7% | 6.8% | 96.8% | 7.6% | 99.6% |
| file_count | 100.0% | 10.6% | 98.2% | 9.1% | 99.3% |
| filename_length | 100.0% | 9.3% | 100.0% | 8.7% | 99.9% |
| ls_basic | 99.7% | 6.7% | 99.6% | 7.4% | 99.3% |
| system_load | 66.9% | 5.8% | 85.7% | 6.4% | 98.1% |

The oracle threshold is selected on test labels to mirror the upstream evaluation style; it is optimistic and is not the primary result.
OAS covariance shrinkage was added after observing split instability. It is a labeled exploratory robustness baseline even though its fit and threshold use normal data only.

## Default-trained cross-scenario test

| Target scenario | Normal FPR | Rootkit recall |
|---|---:|---:|
| default | 6.8% | 96.7% |
| file_count | 100.0% | 100.0% |
| filename_length | 9.9% | 96.7% |
| ls_basic | 100.0% | 100.0% |
| system_load | 99.1% | 100.0% |

## Online replay: drift then persistent rootkit

| Method | Recall | Normal FPR | Update contamination | Benign update acceptance |
|---|---:|---:|---:|---:|
| fixed | 100.0% | 99.0% | NA | 0.0% |
| blind_50 | 15.1% | 12.4% | 66.7% | 100.0% |
| score_gated | 100.0% | 99.0% | 0.0% | 1.0% |
| dual_anchor | 100.0% | 99.0% | 0.0% | 1.0% |

## Interpretation boundary

- Blind-window contamination is a model-state result, not proof that an alerting system forgets an already latched incident.
- Score-gated and dual-anchor are generic timing-only baselines, not the proposed kernel-context method.
- Seed intervals here quantify split/order sensitivity on one public collection, not population confidence across independent machines or days.
- RQ4/RQ5 remain pending until D2 live-kernel data are collected.
