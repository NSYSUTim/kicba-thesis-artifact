from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .detector import ShiftDetector
from .metrics import classification_metrics, first_detection_delay


@dataclass
class ReplayResult:
    method: str
    truth: np.ndarray
    predicted: np.ndarray
    scores: np.ndarray
    score_kind: str
    updated: np.ndarray
    window_attack_fraction: np.ndarray

    def metrics(self) -> dict[str, float | int | str]:
        result = {"method": self.method}
        result.update(classification_metrics(self.truth, self.predicted))
        attack_updates = int(np.sum(self.updated & self.truth))
        normal_updates = int(np.sum(self.updated & ~self.truth))
        total_updates = attack_updates + normal_updates
        result.update(
            {
                "attack_updates": attack_updates,
                "normal_updates": normal_updates,
                "contamination_rate": attack_updates / total_updates if total_updates else float("nan"),
                "benign_update_acceptance": normal_updates / int(np.sum(~self.truth))
                if np.sum(~self.truth)
                else float("nan"),
                "first_detection_delay": first_detection_delay(self.truth, self.predicted),
            }
        )
        return result


def run_replay(
    initial_values: np.ndarray,
    initial_is_attack: np.ndarray,
    replay_values: np.ndarray,
    replay_is_attack: np.ndarray,
    threshold: float,
    method: str,
    window_size: int = 50,
    score_kind: str = "p_value",
    covariance: str = "empirical",
) -> ReplayResult:
    """Evaluate one prequential public-data replay.

    Supported methods are fixed, blind_50, score_gated, and dual_anchor.
    The last two are generic timing-only baselines, not the D2 KICBA method.
    """

    if method not in {"fixed", "blind_50", "score_gated", "dual_anchor"}:
        raise ValueError(f"Unknown replay method: {method}")
    if score_kind not in {"p_value", "distance"}:
        raise ValueError(f"Unknown score kind: {score_kind}")
    if len(initial_values) < 2:
        raise ValueError("At least two initial batches are required")
    trusted = ShiftDetector(covariance=covariance).fit(initial_values)
    adaptive_window = [batch.copy() for batch in initial_values[-window_size:]]
    adaptive_labels = [bool(value) for value in initial_is_attack[-window_size:]]
    predictions: list[bool] = []
    scores: list[float] = []
    updates: list[bool] = []
    attack_fractions: list[float] = []

    for batch, is_attack in zip(replay_values, replay_is_attack):
        adaptive = ShiftDetector(covariance=covariance).fit(np.stack(adaptive_window))
        current_score = (
            _score(trusted, batch, score_kind)
            if method == "fixed"
            else _score(adaptive, batch, score_kind)
        )
        predicted = _is_anomaly(current_score, threshold, score_kind)
        trusted_score = _score(trusted, batch, score_kind)

        if method == "fixed":
            should_update = False
        elif method == "blind_50":
            should_update = True
        elif method == "score_gated":
            should_update = not predicted
        else:
            should_update = (
                not predicted
                and np.isfinite(trusted_score)
                and not _is_anomaly(trusted_score, threshold, score_kind)
            )

        predictions.append(predicted)
        scores.append(current_score)
        updates.append(should_update)
        if should_update:
            adaptive_window.append(batch.copy())
            adaptive_labels.append(bool(is_attack))
            adaptive_window = adaptive_window[-window_size:]
            adaptive_labels = adaptive_labels[-window_size:]
        attack_fractions.append(float(np.mean(adaptive_labels)))

    return ReplayResult(
        method=method,
        truth=np.asarray(replay_is_attack, dtype=bool),
        predicted=np.asarray(predictions, dtype=bool),
        scores=np.asarray(scores, dtype=float),
        score_kind=score_kind,
        updated=np.asarray(updates, dtype=bool),
        window_attack_fraction=np.asarray(attack_fractions, dtype=float),
    )


def _score(detector: ShiftDetector, batch: np.ndarray, score_kind: str) -> float:
    if score_kind == "distance":
        return detector.max_distance_squared(batch)
    return detector.min_p_value(batch)


def _is_anomaly(score: float, threshold: float, score_kind: str) -> bool:
    if not np.isfinite(score):
        return True
    return score > threshold if score_kind == "distance" else score < threshold
