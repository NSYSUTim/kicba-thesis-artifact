from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .detector import ShiftDetector, calibrate_distance_threshold


def _upper_quantile(values: np.ndarray, probability: float) -> float:
    values = np.asarray(values, dtype=float)
    values = values[np.isfinite(values)]
    if not len(values):
        raise ValueError("No finite values available for threshold calibration")
    try:
        return float(np.quantile(values, probability, method="higher"))
    except TypeError:  # NumPy < 1.22 compatibility
        return float(np.quantile(values, probability, interpolation="higher"))


class FixedResidualGate:
    def __init__(self, target_fpr: float = 0.05):
        self.target_fpr = target_fpr
        self.detector: ShiftDetector | None = None
        self.threshold = float("nan")

    def fit(self, fit_values: np.ndarray, calibration_values: np.ndarray) -> "FixedResidualGate":
        self.detector = ShiftDetector(covariance="oas").fit(fit_values)
        self.threshold = calibrate_distance_threshold(
            self.detector, calibration_values, self.target_fpr
        )
        return self

    def scores(self, values: np.ndarray) -> np.ndarray:
        if self.detector is None:
            raise RuntimeError("FixedResidualGate must be fitted")
        return np.asarray(
            [self.detector.max_distance_squared(batch) for batch in values], dtype=float
        )

    def accepts(self, values: np.ndarray) -> np.ndarray:
        scores = self.scores(values)
        return np.isfinite(scores) & (scores <= self.threshold)


class ConditionalResidualGuard:
    """Immutable normal-only p(residual | batch context) update guard."""

    def __init__(self, ridge_lambda: float = 1.0, target_fpr: float = 0.05):
        if ridge_lambda < 0:
            raise ValueError("ridge_lambda must be non-negative")
        self.ridge_lambda = ridge_lambda
        self.target_fpr = target_fpr
        self.context_mean: np.ndarray | None = None
        self.context_scale: np.ndarray | None = None
        self.residual_mean: np.ndarray | None = None
        self.residual_scale: np.ndarray | None = None
        self.coefficients: np.ndarray | None = None
        self.error_detector: ShiftDetector | None = None
        self.context_detector: ShiftDetector | None = None
        self.error_threshold = float("nan")
        self.context_threshold = float("nan")
        self.residual_shape: tuple[int, int] | None = None

    @staticmethod
    def _scale(values: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        mean = np.mean(values, axis=0)
        scale = np.std(values, axis=0)
        scale = np.where(scale > 0, scale, 1.0)
        return (values - mean) / scale, mean, scale

    def fit(
        self,
        context_fit: np.ndarray,
        residual_fit: np.ndarray,
        context_calibration: np.ndarray,
        residual_calibration: np.ndarray,
    ) -> "ConditionalResidualGuard":
        context_fit = np.asarray(context_fit, dtype=float)
        context_calibration = np.asarray(context_calibration, dtype=float)
        residual_fit = np.asarray(residual_fit, dtype=float)
        residual_calibration = np.asarray(residual_calibration, dtype=float)
        if context_fit.ndim != 2:
            raise ValueError("context_fit must have shape [batch, feature]")
        if residual_fit.ndim != 3:
            raise ValueError("residual_fit must have shape [batch, function, quantile]")
        if len(context_fit) != len(residual_fit):
            raise ValueError("fit context/residual rows do not align")
        if len(context_calibration) != len(residual_calibration):
            raise ValueError("calibration context/residual rows do not align")
        if not (
            np.all(np.isfinite(context_fit))
            and np.all(np.isfinite(context_calibration))
            and np.all(np.isfinite(residual_fit))
            and np.all(np.isfinite(residual_calibration))
        ):
            raise ValueError("conditional guard inputs must be finite")

        self.residual_shape = (residual_fit.shape[1], residual_fit.shape[2])
        flat_fit = residual_fit.reshape(len(residual_fit), -1)
        x_fit, self.context_mean, self.context_scale = self._scale(context_fit)
        y_fit, self.residual_mean, self.residual_scale = self._scale(flat_fit)
        gram = x_fit.T @ x_fit + self.ridge_lambda * np.eye(x_fit.shape[1])
        cross = x_fit.T @ y_fit
        try:
            self.coefficients = np.linalg.solve(gram, cross)
        except np.linalg.LinAlgError:
            self.coefficients = np.linalg.pinv(gram) @ cross

        fit_errors = y_fit - x_fit @ self.coefficients
        fit_error_view = fit_errors.reshape(len(fit_errors), *self.residual_shape)
        calibration_errors = self.errors(context_calibration, residual_calibration)
        self.error_detector = ShiftDetector(covariance="oas").fit(fit_error_view)
        self.error_threshold = calibrate_distance_threshold(
            self.error_detector, calibration_errors, self.target_fpr
        )

        context_fit_view = x_fit[:, np.newaxis, :]
        context_calibration_view = self.standardized_context(context_calibration)[
            :, np.newaxis, :
        ]
        self.context_detector = ShiftDetector(covariance="oas").fit(context_fit_view)
        self.context_threshold = calibrate_distance_threshold(
            self.context_detector, context_calibration_view, self.target_fpr
        )
        return self

    def standardized_context(self, context: np.ndarray) -> np.ndarray:
        if self.context_mean is None or self.context_scale is None:
            raise RuntimeError("ConditionalResidualGuard must be fitted")
        return (np.asarray(context, dtype=float) - self.context_mean) / self.context_scale

    def errors(self, context: np.ndarray, residual: np.ndarray) -> np.ndarray:
        if (
            self.coefficients is None
            or self.residual_mean is None
            or self.residual_scale is None
            or self.residual_shape is None
        ):
            raise RuntimeError("ConditionalResidualGuard must be fitted")
        context = np.asarray(context, dtype=float)
        residual = np.asarray(residual, dtype=float)
        x = self.standardized_context(context)
        flat = residual.reshape(len(residual), -1)
        standardized = (flat - self.residual_mean) / self.residual_scale
        errors = standardized - x @ self.coefficients
        return errors.reshape(len(errors), *self.residual_shape)

    def score_components(
        self, context: np.ndarray, residual: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray]:
        if self.error_detector is None or self.context_detector is None:
            raise RuntimeError("ConditionalResidualGuard must be fitted")
        errors = self.errors(context, residual)
        standardized_context = self.standardized_context(context)[:, np.newaxis, :]
        error_scores = np.asarray(
            [self.error_detector.max_distance_squared(batch) for batch in errors],
            dtype=float,
        )
        context_scores = np.asarray(
            [
                self.context_detector.max_distance_squared(batch)
                for batch in standardized_context
            ],
            dtype=float,
        )
        return error_scores, context_scores

    def accepts(self, context: np.ndarray, residual: np.ndarray) -> np.ndarray:
        error_scores, context_scores = self.score_components(context, residual)
        return (
            np.isfinite(error_scores)
            & np.isfinite(context_scores)
            & (error_scores <= self.error_threshold)
            & (context_scores <= self.context_threshold)
        )


@dataclass(frozen=True)
class SafeAdaptiveStep:
    decision: str
    updated: bool
    adaptive_score: float
    update_guard_accepted: bool
    window_attack_fraction: float


class SafeAdaptiveDetector:
    """Adaptive raw decision model with an externally supplied immutable update gate."""

    def __init__(self, window_size: int = 50, target_fpr: float = 0.05):
        if window_size < 2:
            raise ValueError("window_size must be at least 2")
        self.window_size = window_size
        self.target_fpr = target_fpr
        self.threshold = float("nan")
        self._initial_window: list[np.ndarray] = []
        self._window: list[np.ndarray] = []
        self._evaluation_labels: list[bool] = []

    @staticmethod
    def _score(window: list[np.ndarray], batch: np.ndarray) -> float:
        detector = ShiftDetector(covariance="oas").fit(np.stack(window))
        return float(detector.max_distance_squared(batch))

    def fit(
        self,
        raw_fit: np.ndarray,
        raw_calibration: np.ndarray,
        calibration_update_eligible: np.ndarray,
    ) -> "SafeAdaptiveDetector":
        raw_fit = np.asarray(raw_fit, dtype=float)
        raw_calibration = np.asarray(raw_calibration, dtype=float)
        eligible = np.asarray(calibration_update_eligible, dtype=bool)
        if len(raw_fit) < 2:
            raise ValueError("At least two fit batches are required")
        if len(raw_calibration) != len(eligible):
            raise ValueError("Calibration eligibility length mismatch")
        self._initial_window = [
            batch.copy() for batch in raw_fit[-self.window_size :]
        ]
        calibration_window = [batch.copy() for batch in self._initial_window]
        scores: list[float] = []
        for batch, should_update in zip(raw_calibration, eligible):
            scores.append(self._score(calibration_window, batch))
            if should_update:
                calibration_window.append(batch.copy())
                calibration_window = calibration_window[-self.window_size :]
        self.threshold = _upper_quantile(
            np.asarray(scores, dtype=float), 1.0 - self.target_fpr
        )
        self.reset()
        return self

    def reset(self) -> None:
        if not self._initial_window:
            raise RuntimeError("SafeAdaptiveDetector must be fitted before reset")
        self._window = [batch.copy() for batch in self._initial_window]
        self._evaluation_labels = [False] * len(self._window)

    def step(
        self,
        raw_batch: np.ndarray,
        *,
        quality_valid: bool,
        update_guard_accepted: bool,
        guard_alert_for_union: bool = False,
        union_alert: bool = False,
        evaluation_is_attack: bool = False,
    ) -> SafeAdaptiveStep:
        if not self._window:
            raise RuntimeError("SafeAdaptiveDetector must be fitted before step")
        score = self._score(self._window, raw_batch)
        adaptive_alert = not np.isfinite(score) or score > self.threshold
        if not quality_valid:
            decision = "unknown"
        elif adaptive_alert or (union_alert and guard_alert_for_union):
            decision = "suspicious"
        else:
            decision = "normal"

        updated = bool(quality_valid and update_guard_accepted)
        if updated:
            self._window.append(np.asarray(raw_batch, dtype=float).copy())
            self._evaluation_labels.append(bool(evaluation_is_attack))
            self._window = self._window[-self.window_size :]
            self._evaluation_labels = self._evaluation_labels[-self.window_size :]
        return SafeAdaptiveStep(
            decision=decision,
            updated=updated,
            adaptive_score=score,
            update_guard_accepted=bool(update_guard_accepted),
            window_attack_fraction=float(np.mean(self._evaluation_labels)),
        )
