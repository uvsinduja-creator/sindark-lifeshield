"""
Scam Message NLP Classifier for LifeShield.
Loads the trained TF-IDF + Logistic Regression model and outputs risk scores [0.0 - 1.0].
"""
import sys
from pathlib import Path
from typing import Dict, Any, List
import joblib

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ml.nlp_model.features import extract_message_indicators
from ml.nlp_model.train import MODEL_PATH, train_model


class ScamMessageClassifier:
    """
    Inference engine for the Scam / Phishing Message Detection NLP Model.
    """

    def __init__(self, model_path: Path = MODEL_PATH):
        self.model_path = model_path
        self.pipeline = None
        self._load_or_train()

    def _load_or_train(self):
        if not self.model_path.exists():
            print(f"[NLP Model] Model file not found at {self.model_path}, training now...")
            train_model(self.model_path)

        artifact = joblib.load(str(self.model_path))
        self.pipeline = artifact["pipeline"]

    def score_text(self, text: str) -> float:
        """
        Returns a scam probability score between 0.0 (benign) and 1.0 (scam/phishing).
        """
        if not text or not text.strip():
            return 0.0

        proba = self.pipeline.predict_proba([text])[0]
        # proba is [P(benign), P(scam)]
        scam_prob = float(proba[1])
        return round(scam_prob, 4)

    def classify(self, text: str) -> Dict[str, Any]:
        """
        Performs full classification and returns risk score, verdict, and indicators.
        """
        risk_score = self.score_text(text)
        indicators = extract_message_indicators(text)

        # Map score to severity tier
        if risk_score >= 0.80:
            severity = "CRITICAL"
        elif risk_score >= 0.60:
            severity = "HIGH"
        elif risk_score >= 0.40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "text": text,
            "risk_score": risk_score,
            "is_scam": bool(risk_score >= 0.50),
            "severity": severity,
            "indicators": indicators,
        }


# Global singleton instance
scam_classifier = ScamMessageClassifier()


if __name__ == "__main__":
    test_msgs = [
        "Hey, can you send me the meeting minutes when you have time?",
        "URGENT: Your Chase checking account has been locked. Verify immediately at http://chase-security-verify.xyz",
        "Congratulations! You won a $1,000 Walmart Gift Card. Call 1-800-555-0199 now to claim.",
    ]

    for m in test_msgs:
        res = scam_classifier.classify(m)
        print(f"Message: {m[:60]}...")
        print(f"  Risk Score : {res['risk_score']}")
        print(f"  Verdict    : {'SCAM' if res['is_scam'] else 'BENIGN'} ({res['severity']})")
        print(f"  Indicators : {', '.join(res['indicators']) or 'None'}\n")
