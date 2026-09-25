import unittest

import numpy as np

from collector.run_d3_campaign import build_schedule
from collector.run_d4_qualification import build_schedule as build_d4_qualification_schedule
from collector.run_d4_sham_control import build_schedule as build_d4_sham_schedule
from kicba.detector import ShiftDetector, calibrate_threshold, predict
from kicba.context import build_context_dataset, process_record
from kicba.d2_experiments import _comparisons
from kicba.factor_analysis import rank_auc
from kicba.invocation_composition import _pair_iterate_dir
from kicba.kicba import KICBA
from kicba.metrics import classification_metrics
from kicba.online import run_replay
from kicba.v1 import ConditionalResidualGuard, SafeAdaptiveDetector
from kicba.v1_features import context_row


class DetectorTests(unittest.TestCase):
    def setUp(self):
        rng = np.random.default_rng(7)
        self.normal = rng.normal(10.0, 0.2, size=(60, 2, 3))
        self.attack = rng.normal(14.0, 0.2, size=(30, 2, 3))

    def test_shift_detector_separates_large_shift(self):
        detector = ShiftDetector().fit(self.normal[:40])
        threshold = calibrate_threshold(detector, self.normal[40:])
        normal_pred = predict(detector, self.normal[40:], threshold)
        attack_pred = predict(detector, self.attack, threshold)
        self.assertLessEqual(np.mean(normal_pred), 0.10)
        self.assertGreaterEqual(np.mean(attack_pred), 0.95)

    def test_metrics(self):
        metrics = classification_metrics(
            np.asarray([False, False, True, True]),
            np.asarray([False, True, True, False]),
        )
        self.assertEqual(metrics["tp"], 1)
        self.assertEqual(metrics["fp"], 1)
        self.assertAlmostEqual(metrics["f1"], 0.5)

    def test_blind_window_becomes_contaminated(self):
        replay = run_replay(
            initial_values=self.normal[:20],
            initial_is_attack=np.zeros(20, dtype=bool),
            replay_values=self.attack[:20],
            replay_is_attack=np.ones(20, dtype=bool),
            threshold=0.01,
            method="blind_50",
            window_size=10,
        )
        self.assertEqual(replay.metrics()["attack_updates"], 20)
        self.assertEqual(replay.window_attack_fraction[-1], 1.0)

    def test_rank_auc_counts_ties_as_half(self):
        self.assertEqual(rank_auc(np.asarray([0.0, 1.0]), np.asarray([2.0, 3.0])), 1.0)
        self.assertEqual(rank_auc(np.asarray([2.0, 3.0]), np.asarray([0.0, 1.0])), 0.0)
        self.assertEqual(rank_auc(np.asarray([1.0]), np.asarray([1.0])), 0.5)

    def test_pair_iterate_dir_is_per_pid_and_ignores_other_functions(self):
        events = [
            {"ts": 1, "kind": "target_enter", "function": "iterate_dir", "pid": 7},
            {"ts": 2, "kind": "target_enter", "function": "filldir64", "pid": 7},
            {"ts": 3, "kind": "target_return", "function": "filldir64", "pid": 7},
            {"ts": 5, "kind": "target_return", "function": "iterate_dir", "pid": 7},
            {"ts": 6, "kind": "target_enter", "function": "iterate_dir", "pid": 8},
            {"ts": 9, "kind": "target_return", "function": "iterate_dir", "pid": 8},
        ]
        self.assertEqual(_pair_iterate_dir(events), [(7, 1, 4), (8, 6, 3)])


class ContextAccountingTests(unittest.TestCase):
    @staticmethod
    def _record(events):
        return {
            "schema_version": 1,
            "batch_id": "synthetic-1",
            "truth": {"label": "normal", "condition": "cpu"},
            "collection": {
                "enabled_started_ns": 0,
                "enabled_ended_ns": 3000,
                "lost_events": 0,
            },
            "quality": {"valid_for_analysis": True},
            "events": events,
        }

    def test_offcpu_irq_union_and_migration_accounting(self):
        events = [
            {"ts": 1000, "kind": "target_enter", "function": "iterate_dir", "pid": 7, "cpu": 0},
            {"ts": 1100, "kind": "hardirq_enter", "cpu": 0, "aux": 1},
            {"ts": 1150, "kind": "softirq_enter", "cpu": 0, "aux": 2},
            {"ts": 1200, "kind": "hardirq_exit", "cpu": 0, "aux": 1},
            {"ts": 1250, "kind": "softirq_exit", "cpu": 0, "aux": 2},
            {"ts": 1300, "kind": "sched_switch", "pid": 7, "other_pid": 8, "cpu": 0},
            {"ts": 1350, "kind": "hardirq_enter", "cpu": 0, "aux": 3},
            {"ts": 1450, "kind": "hardirq_exit", "cpu": 0, "aux": 3},
            {"ts": 1500, "kind": "sched_switch", "pid": 8, "other_pid": 7, "cpu": 1},
            {"ts": 1600, "kind": "cpu_frequency", "cpu": 1, "aux": 2200000},
            {"ts": 2000, "kind": "target_return", "function": "iterate_dir", "pid": 7, "cpu": 1},
        ]
        batch = process_record(self._record(events))
        self.assertTrue(batch.quality["valid_for_analysis"])
        invocation = batch.invocations[0]
        self.assertTrue(invocation.valid)
        self.assertEqual(invocation.raw_wall_ns, 1000)
        self.assertEqual(invocation.oncpu_ns, 800)
        self.assertEqual(invocation.offcpu_ns, 200)
        self.assertEqual(invocation.hardirq_overlap_ns, 100)
        self.assertEqual(invocation.softirq_overlap_ns, 100)
        self.assertEqual(invocation.irq_union_overlap_ns, 150)
        self.assertEqual(invocation.accounted_exec_ns, 650)
        self.assertEqual(invocation.cpu_migrations, 1)
        self.assertEqual(invocation.frequency_changes, 1)

        dataset = build_context_dataset([batch], num_quantiles=3)
        self.assertEqual(dataset.values.shape, (1, 1, 12, 3))
        self.assertEqual(dataset.invocation_counts[0, 0], 1)
        self.assertTrue(dataset.quality_valid[0])

    def test_d4_schema_three_preserves_context_accounting(self):
        record = self._record(
            [
                {"ts": 1000, "kind": "target_enter", "function": "iterate_dir", "pid": 7, "cpu": 0},
                {"ts": 1200, "kind": "target_return", "function": "iterate_dir", "pid": 7, "cpu": 0},
            ]
        )
        record["schema_version"] = 3
        record["collection"]["primary_timing_functions"] = ["iterate_dir"]
        batch = process_record(record)
        self.assertTrue(batch.quality["valid_for_analysis"])
        self.assertEqual(batch.invocations[0].raw_wall_ns, 200)

    def test_v1_batch_context_preserves_sparse_counts(self):
        events = [
            {"ts": 1000, "kind": "target_enter", "function": "iterate_dir", "pid": 7, "cpu": 0},
            {"ts": 1100, "kind": "softirq_enter", "cpu": 0, "aux": 2},
            {"ts": 1150, "kind": "softirq_exit", "cpu": 0, "aux": 2},
            {"ts": 1200, "kind": "sched_switch", "pid": 7, "other_pid": 8, "cpu": 0},
            {"ts": 1400, "kind": "sched_switch", "pid": 8, "other_pid": 7, "cpu": 0},
            {"ts": 1600, "kind": "target_return", "function": "iterate_dir", "pid": 7, "cpu": 0},
        ]
        record = self._record(events)
        record["collection"]["iterations"] = 2
        transformed, raw, valid = context_row(record)
        self.assertTrue(valid)
        np.testing.assert_allclose(raw, [1.0, 0.5, 0.5, 0.5, 100.0, 25.0])
        np.testing.assert_allclose(transformed, np.log1p(raw))

    def test_unmatched_target_event_invalidates_batch(self):
        events = [
            {"ts": 1000, "kind": "target_enter", "function": "iterate_dir", "pid": 7, "cpu": 0}
        ]
        batch = process_record(self._record(events))
        self.assertFalse(batch.quality["valid_for_analysis"])
        self.assertEqual(batch.quality["unmatched_target_entries"], 1)

    def test_interrupt_boundary_uncertainty_invalidates_overlap(self):
        events = [
            {"ts": 1000, "kind": "target_enter", "function": "iterate_dir", "pid": 7, "cpu": 0},
            {"ts": 1050, "kind": "softirq_exit", "cpu": 0, "aux": 4},
            {"ts": 1100, "kind": "target_return", "function": "iterate_dir", "pid": 7, "cpu": 0},
        ]
        batch = process_record(self._record(events))
        self.assertFalse(batch.quality["valid_for_analysis"])
        self.assertIn(
            "incomplete_interrupt_boundary", batch.invocations[0].quality_reasons
        )

    def test_optional_probe_with_zero_hits_is_not_a_primary_quality_failure(self):
        functions = ("iterate_dir", "filldir64", "touch_atime")
        events = []
        for index, function in enumerate(functions):
            start = 1000 + index * 200
            events.extend(
                [
                    {"ts": start, "kind": "target_enter", "function": function, "pid": 7, "cpu": 0},
                    {"ts": start + 100, "kind": "target_return", "function": function, "pid": 7, "cpu": 0},
                ]
            )
        record = self._record(events)
        record["schema_version"] = 2
        record["collection"]["attached_functions"] = [
            *functions,
            "verify_dirent_name",
        ]
        record["collection"]["primary_timing_functions"] = list(functions)

        batch = process_record(record)
        self.assertTrue(batch.quality["valid_for_analysis"])
        dataset = build_context_dataset([batch], num_quantiles=3)
        self.assertEqual(set(dataset.function_names.tolist()), set(functions))
        self.assertNotIn("verify_dirent_name", dataset.function_names.tolist())

    def test_missing_primary_probe_intervals_invalidates_batch(self):
        record = self._record(
            [
                {"ts": 1000, "kind": "target_enter", "function": "iterate_dir", "pid": 7, "cpu": 0},
                {"ts": 1100, "kind": "target_return", "function": "iterate_dir", "pid": 7, "cpu": 0},
            ]
        )
        record["schema_version"] = 2
        record["collection"]["primary_timing_functions"] = [
            "iterate_dir",
            "filldir64",
            "touch_atime",
        ]
        batch = process_record(record)
        self.assertFalse(batch.quality["valid_for_analysis"])
        self.assertIn("missing_target_function_intervals", batch.quality["reasons"])


class KICBATests(unittest.TestCase):
    def setUp(self):
        rng = np.random.default_rng(19)
        self.raw_fit = rng.normal(10.0, 0.2, size=(40, 2, 3))
        self.residual_fit = rng.normal(10.0, 0.2, size=(40, 2, 3))
        self.context_fit = rng.normal(0.2, 0.02, size=(40, 2, 3))
        self.raw_cal = rng.normal(10.0, 0.2, size=(20, 2, 3))
        self.residual_cal = rng.normal(10.0, 0.2, size=(20, 2, 3))
        self.context_cal = rng.normal(0.2, 0.02, size=(20, 2, 3))
        self.model = KICBA(window_size=20).fit(
            self.raw_fit,
            self.residual_fit,
            self.context_fit,
            self.raw_cal,
            self.residual_cal,
            self.context_cal,
        )

    def test_measured_wall_shift_can_update_when_residual_is_normal(self):
        step = self.model.step(
            np.full((2, 3), 14.0),
            self.residual_fit[0],
            self.context_fit[0],
            True,
        )
        self.assertEqual(step.decision, "normal")
        self.assertTrue(step.updated)
        self.assertGreater(step.raw_adaptive_score, self.model.raw_threshold)

    def test_residual_attack_is_not_updated(self):
        step = self.model.step(
            np.full((2, 3), 14.0),
            np.full((2, 3), 14.0),
            self.context_fit[0],
            True,
            evaluation_is_attack=True,
        )
        self.assertEqual(step.decision, "suspicious")
        self.assertFalse(step.updated)
        self.assertEqual(step.window_attack_fraction, 0.0)

    def test_out_of_envelope_context_abstains(self):
        step = self.model.step(
            self.raw_fit[0],
            self.residual_fit[0],
            np.full((2, 3), 10.0),
            True,
        )
        self.assertEqual(step.decision, "unknown")
        self.assertFalse(step.updated)

    def test_no_context_ablation_does_not_abstain_on_context(self):
        model = KICBA(window_size=20, use_context_envelope=False).fit(
            self.raw_fit,
            self.residual_fit,
            self.context_fit,
            self.raw_cal,
            self.residual_cal,
            self.context_cal,
        )
        step = model.step(
            self.raw_fit[0],
            self.residual_fit[0],
            np.full((2, 3), 10.0),
            True,
        )
        self.assertEqual(step.decision, "normal")
        self.assertTrue(step.updated)

    def test_no_fixed_anchor_ablation_uses_adaptive_alert(self):
        model = KICBA(
            window_size=20,
            use_residual_anchor=False,
            use_adaptive_alert_without_anchor=True,
        ).fit(
            self.raw_fit,
            self.residual_fit,
            self.context_fit,
            self.raw_cal,
            self.residual_cal,
            self.context_cal,
        )
        step = model.step(
            np.full((2, 3), 14.0),
            self.residual_fit[0],
            self.context_fit[0],
            True,
        )
        self.assertEqual(step.decision, "suspicious")
        self.assertFalse(step.updated)


class V1Tests(unittest.TestCase):
    def test_conditional_guard_models_normal_context_relationship(self):
        rng = np.random.default_rng(123)
        context = rng.normal(size=(120, 2))
        base = 10.0 + 2.0 * context[:, 0] - 1.5 * context[:, 1]
        residual = np.stack(
            [
                base
                + rng.normal(0.0, 0.08, size=len(base))
                + offset
                for offset in (0.0, 0.2, 0.4)
            ],
            axis=1,
        )[:, np.newaxis, :]
        guard = ConditionalResidualGuard().fit(
            context[:80], residual[:80], context[80:100], residual[80:100]
        )
        normal_acceptance = np.mean(guard.accepts(context[100:], residual[100:]))
        attacked = residual[100:] + 5.0
        attack_acceptance = np.mean(guard.accepts(context[100:], attacked))
        self.assertGreaterEqual(normal_acceptance, 0.75)
        self.assertLessEqual(attack_acceptance, 0.05)

    def test_safe_adaptive_updates_benign_shift_but_not_attack(self):
        rng = np.random.default_rng(321)
        fit = rng.normal(0.0, 0.08, size=(30, 1, 3))
        calibration = rng.normal(0.0, 0.08, size=(20, 1, 3))
        model = SafeAdaptiveDetector(window_size=10).fit(
            fit, calibration, np.ones(len(calibration), dtype=bool)
        )
        benign_steps = [
            model.step(
                np.full((1, 3), 2.0)
                + rng.normal(0.0, 0.03, size=(1, 3)),
                quality_valid=True,
                update_guard_accepted=True,
            )
            for _ in range(15)
        ]
        self.assertEqual(benign_steps[0].decision, "suspicious")
        self.assertEqual(benign_steps[-1].decision, "normal")

        model.reset()
        attack_steps = [
            model.step(
                np.full((1, 3), 2.0),
                quality_valid=True,
                update_guard_accepted=False,
                evaluation_is_attack=True,
            )
            for _ in range(5)
        ]
        self.assertTrue(all(step.decision == "suspicious" for step in attack_steps))
        self.assertTrue(all(not step.updated for step in attack_steps))
        self.assertEqual(attack_steps[-1].window_attack_fraction, 0.0)


class D3ScheduleTests(unittest.TestCase):
    def test_d3_schedule_has_frozen_cells_and_sustained_episodes(self):
        calibration = build_schedule("calibration", 30, 6001)
        self.assertEqual(len(calibration), 120)
        self.assertEqual({item["label"] for item in calibration}, {"normal"})
        self.assertEqual(
            {
                (label, condition): sum(
                    item["label"] == label and item["condition"] == condition
                    for item in calibration
                )
                for label in ("normal",)
                for condition in ("baseline", "cpu", "memory", "mixed")
            },
            {
                ("normal", condition): 30
                for condition in ("baseline", "cpu", "memory", "mixed")
            },
        )

        test = build_schedule("test", 30, 6101)
        self.assertEqual(len(test), 240)
        self.assertEqual([item["position"] for item in test], list(range(240)))
        for label in ("normal", "rootkit"):
            for condition in ("baseline", "cpu", "memory", "mixed"):
                self.assertEqual(
                    sum(
                        item["label"] == label and item["condition"] == condition
                        for item in test
                    ),
                    30,
                )
        transitions = sum(
            test[position]["label"] != test[position - 1]["label"]
            for position in range(1, len(test))
        )
        self.assertEqual(transitions, 1)


class D4QualificationScheduleTests(unittest.TestCase):
    def test_factorial_cells_are_balanced_and_seeded(self):
        schedule = build_d4_qualification_schedule(1, 7301)
        self.assertEqual(len(schedule), 72)
        self.assertEqual(schedule, build_d4_qualification_schedule(1, 7301))
        self.assertEqual(
            [item["position"] for item in schedule], list(range(len(schedule)))
        )
        counts = {}
        for item in schedule:
            cell = (
                item["directory_cardinality"],
                item["filename_length"],
                item["hidden_slot"],
                item["condition"],
            )
            counts.setdefault(cell, {"normal": 0, "rootkit": 0})[
                item["label"]
            ] += 1
        self.assertEqual(len(counts), 36)
        self.assertTrue(
            all(labels == {"normal": 1, "rootkit": 1} for labels in counts.values())
        )

    def test_sham_control_has_three_states_per_factor_cell(self):
        schedule = build_d4_sham_schedule(7401)
        self.assertEqual(len(schedule), 36)
        grouped = {}
        for item in schedule:
            key = (
                item["directory_cardinality"],
                item["filename_length"],
                item["condition"],
            )
            grouped.setdefault(key, set()).add(item["state"])
        self.assertEqual(len(grouped), 12)
        self.assertTrue(
            all(states == {"unloaded", "sham", "hiding"} for states in grouped.values())
        )


class D2StatisticsTests(unittest.TestCase):
    def test_boot_paired_comparison_and_holm_fields(self):
        rows = []
        for scope in ("drift", "cpu", "memory"):
            for fold in range(5):
                rows.extend(
                    [
                        {
                            "scope": scope,
                            "fold": fold,
                            "method": "fixed_raw",
                            "fpr": 0.40,
                            "recall": 0.99,
                            "contamination_rate": float("nan"),
                            "abstention_rate": 0.0,
                        },
                        {
                            "scope": scope,
                            "fold": fold,
                            "method": "blind_50_raw",
                            "fpr": 0.10,
                            "recall": 0.60,
                            "contamination_rate": 0.50,
                            "abstention_rate": 0.0,
                        },
                        {
                            "scope": scope,
                            "fold": fold,
                            "method": "kicba",
                            "fpr": 0.20,
                            "recall": 0.98,
                            "contamination_rate": 0.10,
                            "abstention_rate": 0.05,
                        },
                    ]
                )
        comparisons = {row["scope"]: row for row in _comparisons(rows)}
        self.assertAlmostEqual(comparisons["drift"]["fpr_reduction_mean"], 0.20)
        self.assertAlmostEqual(
            comparisons["drift"]["contamination_relative_reduction_mean"], 0.80
        )
        self.assertAlmostEqual(comparisons["drift"]["recall_loss_mean"], 0.01)
        self.assertTrue(comparisons["drift"]["passes_fpr_rule"])
        self.assertTrue(np.isfinite(comparisons["cpu"]["fpr_reduction_holm_p"]))


if __name__ == "__main__":
    unittest.main()
