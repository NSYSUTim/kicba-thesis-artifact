from __future__ import annotations

import math

import numpy as np


def classification_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float | int]:
    truth = np.asarray(y_true, dtype=bool)
    predicted = np.asarray(y_pred, dtype=bool)
    if truth.shape != predicted.shape:
        raise ValueError("truth and prediction shapes differ")
    tp = int(np.sum(truth & predicted))
    fp = int(np.sum(~truth & predicted))
    tn = int(np.sum(~truth & ~predicted))
    fn = int(np.sum(truth & ~predicted))
    recall = tp / (tp + fn) if tp + fn else float("nan")
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    precision = tp / (tp + fp) if tp + fp else float("nan")
    f1 = (
        2 * precision * recall / (precision + recall)
        if np.isfinite(precision + recall) and precision + recall
        else float("nan")
    )
    accuracy = (tp + tn) / len(truth) if len(truth) else float("nan")
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denominator if denominator else float("nan")
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": recall,
        "fpr": fpr,
        "precision": precision,
        "f1": f1,
        "accuracy": accuracy,
        "mcc": mcc,
    }


def first_detection_delay(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    truth = np.asarray(y_true, dtype=bool)
    predicted = np.asarray(y_pred, dtype=bool)
    attack_positions = np.flatnonzero(truth)
    if not len(attack_positions):
        return float("nan")
    start = int(attack_positions[0])
    detected = np.flatnonzero(truth[start:] & predicted[start:])
    return float(detected[0]) if len(detected) else float("inf")

