"""
Automated tests for Week 4 Phishing URL ML Model and scoring pipeline.
"""
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.url_model.features import extract_url_features, calculate_entropy, FEATURE_NAMES
from ml.url_model.classifier import url_classifier


def test_entropy_calculation():
    """Tests entropy calculation on known inputs."""
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaaaa") == 0.0
    # Diverse strings should have positive entropy
    assert calculate_entropy("abcdef123456") > 3.0


def test_feature_extraction_structure():
    """Tests that feature extractor returns all expected features as floats."""
    url = "https://secure-login.example.com/auth/login.php?user=123"
    features = extract_url_features(url)

    for name in FEATURE_NAMES:
        assert name in features
        assert isinstance(features[name], float)

    assert features["is_https"] == 1.0
    assert features["keyword_hits"] >= 2.0  # login, auth


def test_feature_extraction_ip_detection():
    """Tests IP address in host detection."""
    features = extract_url_features("http://192.168.1.1/login.php")
    assert features["is_ip"] == 1.0
    assert features["is_https"] == 0.0


def test_classifier_benign_url_score():
    """Tests that standard legitimate URLs receive low risk scores (< 0.40)."""
    benign_urls = [
        "https://www.google.com/search?q=python+programming",
        "https://github.com/torvalds/linux",
        "https://en.wikipedia.org/wiki/Computer_science",
    ]
    for url in benign_urls:
        score = url_classifier.score_url(url)
        assert 0.0 <= score <= 1.0
        assert score < 0.40, f"Expected low risk for {url}, got {score}"


def test_classifier_phishing_url_score():
    """Tests that suspicious/phishing URLs receive elevated risk scores (> 0.50)."""
    phishing_urls = [
        "http://192.168.1.10/paypal/login.php?cmd=verify&account=update",
        "http://secure-apple-id-verify.account-update.xyz/login.html",
        "http://chase-bank-verify-account.suspicious-domain.xyz/auth.php",
    ]
    for url in phishing_urls:
        result = url_classifier.classify(url)
        assert result["risk_score"] >= 0.50, f"Expected high risk for {url}, got {result['risk_score']}"
        assert result["is_phishing"] is True
        assert len(result["indicators"]) > 0
