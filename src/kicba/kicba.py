from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .context import ContextBatchDataset
from .detector import ShiftDetector, calibrate_distance_threshold


RAW_FEATURES = ("raw_wall_ns",)
RESIDUAL_FEATURES = ("accounted_exec_ns",)
CONTEXT_FEATURES = (
    "offcpu_fraction",
    "irq_fraction",
    "cpu_migrations",
    "frequency_changes",
)


def feature_view(dataset: ContextBatchDataset, feature_names: tuple[str, ...]) -> np.ndarray:
    """Return [batch, function-feature, quantile] data for ShiftDetector."""

    available = dataset.feature_names.tolist()
    missing = [name for name in feature_names if name not in available]
    if missing:
        raise ValueError(f"Missing context features: {missing}")
    indices = [available.index(name) for name in feature_names]
    selected = dataset.values[:, :, indices, :]
    return selected.reshape(
        len(dataset.batch_ids), len(dataset.function_names) * len(indices), -1
    )


@dataclass(frozen=True)
class KICBAStep:
    decision: str
    updated: bool
    raw_adaptive_score: float
    residual_anchor_score: float
    context_score: float
    window_attack_fraction: float


class KICBA:
    """Prequential kernel-interference-constrained baseline adaptation.

    The adaptive model tracks wall-clock timing. A batch may update that model
    only when (1) collection quality is complete, (2) execution time remaining
    after measured off-CPU/IRQ subtraction is compatible with the immutable
    trusted normal anchor, and (3) the measured context lies inside the normal
    calibration envelope. Rootkit labels are accepted only for evaluation and
    never participate in the decision.
    """

    def __init__(
        self,
        window_size: int = 50,
        target_fpr: float = 0.05,
        *,
        use_residual_anchor: bool = True,
        use_context_envelope: bool = True,
        use_adaptive_alert_without_anchor: bool = False,
    ):
        if window_size < 2:
            raise ValueError("window_size must be at least 2")
        self.window_size = window_size
        self.target_fpr = target_fpr
        self.use_residual_anchor = use_residual_anchor
        self.use_context_envelope = use_context_envelope
        self.use_adaptive_alert_without_anchor = use_adaptive_alert_without_anchor
        self._raw_window: list[np.ndarray] = []
        self._evaluation_labels: list[bool] = []
        self._residual_anchor: ShiftDetector | None = None
        self._context_anchor: ShiftDetector | None = None
        self.raw_threshold = float("nan")
        self.residual_threshold = float("nan")
        self.context_threshold = float("nan")

    def fit(
        self,
        raw_fit: np.ndarray,
        residual_fit: np.ndarray,
        context_fit: np.ndarray,
        raw_calibration: np.ndarray,
        residual_calibration: np.ndarray,
        context_calibration: np.ndarray,
    ) -> "KICBA":
        lengths = {len(raw_fit), len(residual_fit), len(context_fit)}
        if len(lengths) != 1 or next(iter(lengths)) < 2:
            raise ValueError("Fit views must have one-to-one batches and length >= 2")
        calibration_lengths = {
            len(raw_calibration),
            len(residual_calibration),
            len(context_calibration),
        }
        if len(calibration_lengths) != 1 or next(iter(calibration_lengths)) < 1:
            raise ValueError("Calibration views must have one-to-one batches")

        raw_anchor = ShiftDetector(covariance="oas").fit(raw_fit)
        self._residual_anchor = (
            ShiftDetector(covariance="oas").fit(residual_fit)
            if self.use_residual_anchor
            else None
        )
        self._context_anchor = (
            ShiftDetector(covariance="oas").fit(context_fit)
            if self.use_context_envelope
            else None
        )
        self.raw_threshold = calibrate_distance_threshold(
            raw_anchor, raw_calibration, self.target_fpr
        )
        self.residual_threshold = (
            calibrate_distance_threshold(
                self._residual_anchor, residual_calibration, self.target_fpr
            )
            if self._residual_anchor is not None
            else float("nan")
        )
        self.context_threshold = (
            calibrate_distance_threshold(
                self._context_anchor, context_calibration, self.target_fpr
            )
            if self._context_anchor is not None
            else float("nan")
        )
        self._raw_window = [batch.copy() for batch in raw_fit[-self.window_size :]]
        self._evaluation_labels = [False] * len(self._raw_window)
        return self

    def step(
        self,
        raw_batch: np.ndarray,
        residual_batch: np.ndarray,
        context_batch: np.ndarray,
        quality_valid: bool,
        *,
        evaluation_is_attack: bool = False,
    ) -> KICBAStep:
        if not self._raw_window:
            raise RuntimeError("KICBA must be fitted before step")
        adaptive = ShiftDetector(covariance="oas").fit(np.stack(self._raw_window))
        raw_score = adaptive.max_distance_squared(raw_batch)
        residual_score = (
            self._residual_anchor.max_distance_squared(residual_batch)
            if self._residual_anchor is not None
            else float("nan")
        )
        context_score = (
            self._context_anchor.max_distance_squared(context_batch)
            if self._context_anchor is not None
            else float("nan")
        )

        residual_alert = (
            self.use_residual_anchor
            and (
                not np.isfinite(residual_score)
                or residual_score > self.residual_threshold
            )
        )
        context_admissible = (
            not self.use_context_envelope
            or (
                np.isfinite(context_score)
                and context_score <= self.context_threshold
            )
        )
        adaptive_alert = (
            not self.use_residual_anchor
            and self.use_adaptive_alert_without_anchor
            and (not np.isfinite(raw_score) or raw_score > self.raw_threshold)
        )
        if not quality_valid:
            decision = "unknown"
        elif residual_alert or adaptive_alert:
            decision = "suspicious"
        elif not context_admissible:
            decision = "unknown"
        else:
            decision = "normal"

        updated = decision == "normal"
        if updated:
            self._raw_window.append(raw_batch.copy())
            self._evaluation_labels.append(bool(evaluation_is_attack))
            self._raw_window = self._raw_window[-self.window_size :]
            self._evaluation_labels = self._evaluation_labels[-self.window_size :]
        return KICBAStep(
            decision=decision,
            updated=updated,
            raw_adaptive_score=float(raw_score),
            residual_anchor_score=float(residual_score),
            context_score=float(context_score),
            window_attack_fraction=float(np.mean(self._evaluation_labels)),
        )
