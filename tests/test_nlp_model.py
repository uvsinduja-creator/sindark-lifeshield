"""
Automated unit tests for Week 5 Scam Message NLP Model.
"""
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.nlp_model.features import extract_message_indicators
from ml.nlp_model.classifier import scam_classifier


def test_indicator_extraction_scam():
    """Tests that threat signals are properly recognized in suspicious text."""
    scam_text = "URGENT: Your Bank of America debit card is suspended. Verify password now at http://bofa-verify.xyz or contact 1-800-555-0199."
    indicators = extract_message_indicators(scam_text)
    assert len(indicators) >= 2
    assert any("urgency" in i.lower() for i in indicators)
    assert any("credential" in i.lower() or "link" in i.lower() for i in indicators)


def test_indicator_extraction_benign():
    """Tests that ordinary casual conversation produces no false threat indicators."""
    benign_text = "Hey! Let's grab lunch tomorrow around 1pm at the cafe."
    indicators = extract_message_indicators(benign_text)
    assert len(indicators) == 0


def test_classifier_benign_messages():
    """Tests that benign conversational messages receive low risk scores (< 0.40)."""
    benign_samples = [
        "Hey, are we still meeting for coffee this afternoon?",
        "Can you send me the slides from today's team presentation?",
        "Your doctor appointment is confirmed for Tuesday at 10 AM.",
        "Don't forget to review the pull request when you're free.",
    ]
    for msg in benign_samples:
        res = scam_classifier.classify(msg)
        assert res["risk_score"] < 0.40, f"Expected low risk for '{msg}', got {res['risk_score']}"
        assert res["is_scam"] is False


def test_classifier_scam_messages():
    """Tests that realistic phishing/scam lures receive elevated risk scores (>= 0.50)."""
    scam_samples = [
        "URGENT: Your Chase checking account has been locked. Verify immediately at http://chase-security-auth.top/verify",
        "Congratulations! You won a $1,000 Walmart Gift Card in our raffle. Call 1-800-555-0199 now to claim your cash reward.",
        "MetaMask Alert: Your crypto wallet requires immediate migration. Submit your 12-word seed phrase here to backup assets: http://wallet-backup.icu",
        "IRS Notice: You have an unpaid tax balance. Failure to settle within 24 hours will result in an arrest warrant. Settle now: http://irs-payment.xyz",
    ]
    for msg in scam_samples:
        res = scam_classifier.classify(msg)
        assert res["risk_score"] >= 0.50, f"Expected high risk for '{msg}', got {res['risk_score']}"
        assert res["is_scam"] is True
        assert len(res["indicators"]) > 0
