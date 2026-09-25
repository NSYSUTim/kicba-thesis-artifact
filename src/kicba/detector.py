from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.stats import chi2


@dataclass(frozen=True)
class IntervalModel:
    mean: np.ndarray
    covariance_inverse: np.ndarray
    degrees_of_freedom: int


def _oas_covariance(values: np.ndarray) -> np.ndarray:
    """OAS covariance following the published scikit-learn formulation."""

    centered = values - np.mean(values, axis=0)
    n_samples, n_features = centered.shape
    empirical = centered.T @ centered / n_samples
    alpha = float(np.mean(empirical**2))
    mu = float(np.trace(empirical) / n_features)
    mu_squared = mu**2
    denominator = (n_samples + 1.0) * (alpha - mu_squared / n_features)
    shrinkage = 1.0 if denominator <= 0 else min((alpha + mu_squared) / denominator, 1.0)
    shrunk = (1.0 - shrinkage) * empirical
    shrunk.flat[:: n_features + 1] += shrinkage * mu
    return np.atleast_2d(shrunk)


class ShiftDetector:
    """Batch-level quantile shift detector matching the public baseline's core."""

    def __init__(self, min_presence: float = 0.5, covariance: str = "empirical"):
        if not 0 < min_presence <= 1:
            raise ValueError("min_presence must be in (0, 1]")
        if covariance not in {"empirical", "oas"}:
            raise ValueError("covariance must be 'empirical' or 'oas'")
        self.min_presence = min_presence
        self.covariance = covariance
        self.models: dict[int, IntervalModel] = {}

    def fit(self, values: np.ndarray) -> "ShiftDetector":
        if values.ndim != 3:
            raise ValueError("values must have shape [batch, interval, quantile]")
        n_batches, n_intervals, _ = values.shape
        required = max(2, int(np.ceil(n_batches * self.min_presence)))
        models: dict[int, IntervalModel] = {}
        for interval_idx in range(n_intervals):
            interval_values = values[:, interval_idx, :]
            valid = np.all(np.isfinite(interval_values), axis=1)
            observed = interval_values[valid]
            if len(observed) < required:
                continue
            mean = np.mean(observed, axis=0)
            covariance = (
                _oas_covariance(observed)
                if self.covariance == "oas"
                else np.atleast_2d(np.cov(observed, rowvar=False))
            )
            try:
                covariance_inverse = np.linalg.inv(covariance)
            except np.linalg.LinAlgError:
                try:
                    covariance_inverse = np.linalg.inv(
                        covariance + 1e-6 * np.eye(covariance.shape[0])
                    )
                except np.linalg.LinAlgError:
                    covariance_inverse = np.linalg.pinv(covariance)
            models[interval_idx] = IntervalModel(
                mean=mean,
                covariance_inverse=covariance_inverse,
                degrees_of_freedom=observed.shape[1],
            )
        if not models:
            raise ValueError("No interval type had sufficient complete training batches")
        self.models = models
        return self
    def p_values(self, batch_values: np.ndarray) -> dict[int, float]:
        if batch_values.ndim != 2:
            raise ValueError("batch_values must have shape [interval, quantile]")
        p_values: dict[int, float] = {}
        for interval_idx, model in self.models.items():
            observed = batch_values[interval_idx]
            if not np.all(np.isfinite(observed)):
                continue
            difference = observed - model.mean
            distance_squared = float(
                np.sum(difference @ model.covariance_inverse * difference)
            )
            distance_squared = max(0.0, distance_squared)
            p_values[interval_idx] = float(
                chi2.sf(distance_squared, df=model.degrees_of_freedom)
            )
        return p_values

    def distance_squared(self, batch_values: np.ndarray) -> dict[int, float]:
        """Return Mahalanobis squared distances without tail-probability underflow."""

        if batch_values.ndim != 2:
            raise ValueError("batch_values must have shape [interval, quantile]")
        distances: dict[int, float] = {}
        for interval_idx, model in self.models.items():
            observed = batch_values[interval_idx]
            if not np.all(np.isfinite(observed)):
                continue
            difference = observed - model.mean
            distance_squared = float(
                np.sum(difference @ model.covariance_inverse * difference)
            )
            distances[interval_idx] = max(0.0, distance_squared)
        return distances

    def max_distance_squared(self, batch_values: np.ndarray) -> float:
        distances = self.distance_squared(batch_values)
        return max(distances.values()) if distances else float("nan")

    def min_p_value(self, batch_values: np.ndarray) -> float:
        p_values = self.p_values(batch_values)
        return min(p_values.values()) if p_values else float("nan")

    def anomaly_score(self, batch_values: np.ndarray) -> float:
        p_value = self.min_p_value(batch_values)
        if not np.isfinite(p_value):
            return float("nan")
        return float(-np.log10(max(p_value, np.finfo(float).tiny)))


def calibrate_threshold(
    detector: ShiftDetector,
    calibration_values: np.ndarray,
    target_fpr: float = 0.05,
) -> float:
    """Return a p-value threshold using normal calibration batches only."""

    if not 0 < target_fpr < 1:
        raise ValueError("target_fpr must be in (0, 1)")
    p_values = np.asarray(
        [detector.min_p_value(batch) for batch in calibration_values], dtype=float
    )
    p_values = p_values[np.isfinite(p_values)]
    if not len(p_values):
        raise ValueError("No valid calibration scores")
    try:
        return float(np.quantile(p_values, target_fpr, method="lower"))
    except TypeError:  # NumPy < 1.22 compatibility
        return float(np.quantile(p_values, target_fpr, interpolation="lower"))


def calibrate_distance_threshold(
    detector: ShiftDetector,
    calibration_values: np.ndarray,
    target_fpr: float = 0.05,
) -> float:
    """Calibrate an upper-tail distance threshold on normal batches only."""

    if not 0 < target_fpr < 1:
        raise ValueError("target_fpr must be in (0, 1)")
    scores = np.asarray(
        [detector.max_distance_squared(batch) for batch in calibration_values],
        dtype=float,
    )
    scores = scores[np.isfinite(scores)]
    if not len(scores):
        raise ValueError("No valid calibration scores")
    try:
        return float(np.quantile(scores, 1.0 - target_fpr, method="higher"))
    except TypeError:  # NumPy < 1.22 compatibility
        return float(np.quantile(scores, 1.0 - target_fpr, interpolation="higher"))


def predict(detector: ShiftDetector, values: np.ndarray, threshold: float) -> np.ndarray:
    p_values = np.asarray([detector.min_p_value(batch) for batch in values])
    return np.where(np.isfinite(p_values), p_values < threshold, True)


def predict_distance(
    detector: ShiftDetector, values: np.ndarray, threshold: float
) -> np.ndarray:
    scores = np.asarray([detector.max_distance_squared(batch) for batch in values])
    return np.where(np.isfinite(scores), scores > threshold, True)
