"""
URL Phishing Classifier for LifeShield.
Loads the trained ML model, extracts features, and outputs risk scores [0.0 - 1.0].
"""
import sys
from pathlib import Path
from typing import Dict, Any, List
import joblib

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ml.url_model.features import extract_url_features, features_to_vector
from ml.url_model.train import MODEL_PATH, train_model


class URLPhishingClassifier:
    """
    Inference engine for the URL Phishing Detection Model.
    """

    def __init__(self, model_path: Path = MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.feature_names = None
        self._load_or_train()

    def _load_or_train(self):
        if not self.model_path.exists():
            print(f"[URL Model] Model file not found at {self.model_path}, training now...")
            train_model(self.model_path)

        artifact = joblib.load(str(self.model_path))
        self.model = artifact["model"]
        self.feature_names = artifact.get("feature_names", [])

    def score_url(self, url: str) -> float:
        """
        Returns a phishing probability score between 0.0 (benign) and 1.0 (malicious).
        """
        if not url:
            return 0.0

        features = extract_url_features(url)
        vector = [features_to_vector(features)]
        # predict_proba returns [P(benign), P(phishing)]
        proba = self.model.predict_proba(vector)[0]
        phishing_risk = float(proba[1])
        return round(phishing_risk, 4)

    def classify(self, url: str) -> Dict[str, Any]:
        """
        Performs full classification and returns risk score, verdict, and indicators.
        """
        features = extract_url_features(url)
        risk_score = self.score_url(url)

        # Detect explainable human-readable indicators
        indicators: List[str] = []
        if features["is_ip"] > 0:
            indicators.append("Direct IP address used as host")
        if features["keyword_hits"] > 0:
            indicators.append(f"{int(features['keyword_hits'])} suspicious credential/security keywords detected")
        if features["suspicious_tld"] > 0:
            indicators.append("Suspicious or commonly abused Top-Level Domain (TLD)")
        if features["entropy"] > 4.6:
            indicators.append(f"High character entropy ({features['entropy']:.2f})")
        if features["subdomain_count"] >= 3:
            indicators.append(f"Excessive subdomains ({int(features['subdomain_count'])})")
        if features["url_length"] > 75:
            indicators.append(f"Abnormally long URL length ({int(features['url_length'])} chars)")
        if features["is_https"] == 0:
            indicators.append("Insecure plain HTTP protocol")

        # Map to severity
        if risk_score >= 0.80:
            severity = "CRITICAL"
        elif risk_score >= 0.60:
            severity = "HIGH"
        elif risk_score >= 0.40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "url": url,
            "risk_score": risk_score,
            "is_phishing": bool(risk_score >= 0.50),
            "severity": severity,
            "indicators": indicators,
        }


# Global singleton instance
url_classifier = URLPhishingClassifier()


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=machine+learning",
        "http://192.168.1.1/paypal/signin.php?action=verify",
        "http://chase-bank-verify-account.suspicious-domain.xyz/login.html"
    ]

    for u in test_urls:
        result = url_classifier.classify(u)
        print(f"URL: {u}")
        print(f"  Risk Score : {result['risk_score']}")
        print(f"  Severity   : {result['severity']}")
        print(f"  Indicators : {', '.join(result['indicators']) or 'None'}\n")
