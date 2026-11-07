"""
ml/behavior_model/anomaly.py
=============================
Unsupervised Behavioral Anomaly Detection Engine (Station 3 — Think).
Uses an Isolation Forest to establish a baseline of normal workstation activity
and flags behavioral deviations (brute force logins, off-hour activity bursts,
rapid process spawning, and anomalous network storms).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from configs.loader import get_config
from ml.behavior_model.features import (
    BEHAVIOR_FEATURE_NAMES,
    extract_behavior_features,
    to_feature_vector,
)

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent / "behavior_model.joblib"


def _generate_baseline_dataset(n_samples: int = 4000) -> np.ndarray:
    """
    Generate synthetic representative baseline of normal enterprise user telemetry.
    Workday hours, expected typing/browsing event rates, occasional benign download.
    """
    rng = np.random.RandomState(42)

    # Normal working hours (8:00 - 19:00 with slight evening spread)
    hours = rng.choice(range(7, 21), size=n_samples)
    off_hours = np.zeros(n_samples)
    weekends = rng.choice([0, 1], size=n_samples, p=[0.85, 0.15])

    # Standard workstation event volume
    event_rate = rng.gamma(shape=2.5, scale=4.0, size=n_samples)          # mean ~10/min
    proc_rate = rng.poisson(lam=2.0, size=n_samples)                       # mean ~2/min
    failed_logins = rng.choice([0, 1], size=n_samples, p=[0.97, 0.03])   # 0 or rare 1 typo
    net_rate = rng.gamma(shape=3.0, scale=3.5, size=n_samples)            # mean ~10.5/min
    dns_rate = rng.gamma(shape=3.0, scale=5.0, size=n_samples)            # mean ~15/min
    dl_rate = rng.poisson(lam=0.4, size=n_samples)                         # mean ~0.4/min

    return np.column_stack([
        hours, off_hours, weekends, event_rate, proc_rate,
        failed_logins, net_rate, dns_rate, dl_rate,
    ])


class BehaviorAnomalyDetector:
    """
    IsolationForest-powered behavioral anomaly detector.
    Evaluates telemetry window feature vectors and flags anomalous patterns.
    """

    def __init__(self, model_file: Path | str = MODEL_PATH):
        self.model_path = Path(model_file)
        self.model: IsolationForest | None = None
        cfg = get_config()
        self.thresholds = cfg.get("decision_thresholds", {
            "allow_max": 0.30,
            "monitor_max": 0.60,
            "warn_max": 0.80,
            "strong_warning_max": 0.95,
        })
        self._load_or_train()

    def _load_or_train(self) -> None:
        """Load trained Isolation Forest model or fit a new baseline model."""
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                logger.info("Loaded behavior anomaly model from %s", self.model_path)
                return
            except Exception as exc:
                logger.warning("Could not load %s, retraining baseline: %s", self.model_path, exc)

        logger.info("Training fresh Isolation Forest baseline model...")
        X_train = _generate_baseline_dataset(n_samples=4000)
        clf = IsolationForest(
            n_estimators=100,
            contamination=0.03,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        clf.fit(X_train)
        self.model = clf
        try:
            joblib.dump(clf, self.model_path)
            logger.info("Saved baseline behavior anomaly model to %s", self.model_path)
        except Exception as exc:
            logger.warning("Could not save model to %s: %s", self.model_path, exc)

    def score(self, telemetry_data: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate behavioral anomaly score from a telemetry dictionary.

        Returns
        -------
        dict with:
          - anomaly_score: float in [0.00, 1.00]
          - severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
          - is_anomaly: bool (True if anomaly_score > monitor_max)
          - indicators: list[str] explaining specific anomalies
          - features: extracted feature dictionary
        """
        feats = extract_behavior_features(telemetry_data)
        vec = np.array([to_feature_vector(feats)])

        # Base model score from Isolation Forest decision_function
        if self.model is not None:
            raw_decision = float(self.model.decision_function(vec)[0])
        else:
            raw_decision = 0.15

        # Piecewise mapping:
        # positive decision_function indicates typical baseline (mapped to LOW <= 0.30)
        # negative decision_function indicates statistical outlier (mapped to > 0.50)
        if raw_decision >= 0:
            norm_score = max(0.05, 0.30 - raw_decision)
        else:
            norm_score = min(1.0, 0.50 + abs(raw_decision) * 2.5)

        indicators: list[str] = []

        # Heuristic rules and domain explanations
        # 1. Failed login brute-force or credential stuffing
        if feats["failed_login_count"] >= 5:
            norm_score = max(norm_score, 0.85)
            indicators.append(
                f"Severe spike in failed logins ({feats['failed_login_count']} attempts) - potential brute force"
            )
        elif feats["failed_login_count"] >= 3:
            norm_score = max(norm_score, 0.65)
            indicators.append(
                f"Elevated failed login count ({feats['failed_login_count']} attempts)"
            )

        # 2. Process creation storm (ransomware / fork bomb / automated dropper)
        if feats["process_start_rate_per_min"] >= 40.0:
            norm_score = max(norm_score, 0.88)
            indicators.append(
                f"Abnormal process creation burst ({feats['process_start_rate_per_min']:.0f} proc/min)"
            )
        elif feats["process_start_rate_per_min"] >= 15.0:
            norm_score = max(norm_score, 0.60)
            indicators.append(
                f"Elevated process spawn rate ({feats['process_start_rate_per_min']:.0f} proc/min)"
            )

        # 3. Off-hours activity surge
        if feats["is_off_hours"] and feats["event_rate_per_min"] >= 30.0:
            norm_score = max(norm_score, 0.75)
            indicators.append(
                f"High-volume activity surge during off-hours ({feats['hour_of_day']:02d}:00 UTC)"
            )

        # 4. Outbound network connection storm
        if feats["network_conn_rate_per_min"] >= 60.0:
            norm_score = max(norm_score, 0.82)
            indicators.append(
                f"Anomalous outbound network storm ({feats['network_conn_rate_per_min']:.0f} conns/min)"
            )

        # 5. Mass file download burst
        if feats["file_download_rate_per_min"] >= 8.0:
            norm_score = max(norm_score, 0.70)
            indicators.append(
                f"High download frequency burst ({feats['file_download_rate_per_min']:.0f} downloads/min)"
            )

        anomaly_score = round(min(1.0, max(0.0, norm_score)), 4)

        if anomaly_score <= self.thresholds.get("allow_max", 0.30):
            severity = "LOW"
        elif anomaly_score <= self.thresholds.get("monitor_max", 0.60):
            severity = "MEDIUM"
        elif anomaly_score <= self.thresholds.get("warn_max", 0.80):
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        is_anomaly = anomaly_score > self.thresholds.get("monitor_max", 0.60)

        if not indicators:
            indicators.append("Behavioral patterns conform to normal baseline activity")

        return {
            "anomaly_score": anomaly_score,
            "severity": severity,
            "is_anomaly": is_anomaly,
            "indicators": indicators,
            "features": feats,
        }


# Global singleton instance
behavior_detector = BehaviorAnomalyDetector()
