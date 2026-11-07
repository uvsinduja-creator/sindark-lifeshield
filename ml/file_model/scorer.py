"""
ml/file_model/scorer.py
========================
Static File Risk Scoring Engine (Station 3 — Think).
Evaluates file risk from metadata and heuristic attributes,
producing a normalized risk score [0.00, 1.00], severity classification,
and human-readable threat indicators.
"""

from __future__ import annotations

import logging
from typing import Any

from configs.loader import get_config
from ml.file_model.features import extract_file_features

logger = logging.getLogger(__name__)


class FileRiskScorer:
    """
    Computes heuristic and metadata-driven risk scores for created
    and downloaded files before execution.
    """

    def __init__(self):
        cfg = get_config()
        self.thresholds = cfg.get("decision_thresholds", {
            "allow_max": 0.30,
            "monitor_max": 0.60,
            "warn_max": 0.80,
            "strong_warning_max": 0.95,
        })

    def score(self, file_data: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate file risk score from a metadata dictionary.

        Returns
        -------
        dict with:
          - risk_score: float in [0.00, 1.00]
          - severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
          - is_threat: bool (True if risk_score > monitor_max)
          - indicators: list[str] explaining specific risk triggers
          - features: extracted feature dictionary
        """
        feats = extract_file_features(file_data)
        indicators: list[str] = []
        raw_score = 0.05  # baseline background risk

        # 1. Double extension masquerading (very high risk)
        if feats["is_double_extension"]:
            raw_score += 0.45
            indicators.append(f"Double extension masquerading detected on '{feats['filename']}'")

        # 2. Executable / script dropped in temporary or startup directory
        if feats["in_startup_dir"]:
            raw_score += 0.40
            indicators.append("File located in autostart / startup persistence directory")
        elif feats["in_temp_dir"] and (feats["is_executable"] or feats["is_script"]):
            raw_score += 0.35
            indicators.append("Executable or script staged in system temporary directory")
        elif feats["in_downloads_dir"] and feats["is_executable"]:
            raw_score += 0.25
            indicators.append("Direct binary executable downloaded into user directory")
        elif feats["in_downloads_dir"] and feats["is_script"]:
            raw_score += 0.30
            indicators.append(f"Direct script ({feats['extension']}) downloaded into user directory")

        # 3. High Shannon entropy (packing / encryption indicator)
        if feats["is_high_entropy"] and (feats["is_executable"] or feats["is_archive"]):
            raw_score += 0.25
            indicators.append(f"High Shannon entropy ({feats['entropy']:.2f}) indicates packed/encrypted binary")

        # 4. Suspiciously small executable (downloader stager)
        if feats["is_tiny_executable"]:
            raw_score += 0.20
            indicators.append(f"Abnormally small binary executable ({feats['size_bytes']} bytes), potential stager")

        # 5. Phishing / social engineering lure keywords combined with executable or script
        if feats["has_lure_keywords"] and (feats["is_executable"] or feats["is_script"]):
            raw_score += 0.20
            matched_str = ", ".join(feats["matched_lures"])
            indicators.append(f"Social engineering lure keywords in executable filename: [{matched_str}]")

        # 6. Hidden attribute on executable or script
        if feats["is_hidden"] and (feats["is_executable"] or feats["is_script"]):
            raw_score += 0.20
            indicators.append("Hidden file attribute set on executable/script file")

        # Clamp score between 0.00 and 1.00
        risk_score = round(min(1.0, max(0.0, raw_score)), 4)

        # Determine severity according to base config thresholds
        if risk_score <= self.thresholds.get("allow_max", 0.30):
            severity = "LOW"
        elif risk_score <= self.thresholds.get("monitor_max", 0.60):
            severity = "MEDIUM"
        elif risk_score <= self.thresholds.get("warn_max", 0.80):
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        is_threat = risk_score > self.thresholds.get("monitor_max", 0.60)

        if not indicators:
            indicators.append("Standard file attributes; no malicious delivery heuristics triggered")

        return {
            "risk_score": risk_score,
            "severity": severity,
            "is_threat": is_threat,
            "indicators": indicators,
            "features": feats,
        }


# Global singleton instance
file_scorer = FileRiskScorer()
