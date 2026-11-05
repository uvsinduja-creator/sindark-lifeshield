"""
Training pipeline for LifeShield Phishing URL Model.
Trains a CPU-efficient Random Forest classifier and saves it using joblib.
"""
import sys
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ml.url_model.features import extract_url_features, features_to_vector, FEATURE_NAMES

MODEL_PATH = Path(__file__).parent / "url_model.joblib"

# Representative corpus of legitimate URLs across diverse categories
BENIGN_URLS = [
    "https://www.google.com",
    "https://www.google.com/search?q=cybersecurity+defense",
    "https://github.com",
    "https://github.com/torvalds/linux",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://stackoverflow.com/questions/tagged/python",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://microsoft.com/en-us/windows",
    "https://portal.azure.com",
    "https://news.ycombinator.com",
    "https://www.nytimes.com/section/technology",
    "https://reddit.com/r/netsec",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://pypi.org/project/scikit-learn/",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://duckduckgo.com/?q=privacy+first",
    "https://netflix.com/browse",
    "https://cnn.com/world",
    "https://bbc.com/news",
    "https://spotify.com/us/home",
    "https://linkedin.com/feed",
    "https://twitter.com/explore",
    "https://medium.com/@author/tech-post",
    "https://coursera.org/learn/machine-learning",
    "https://gitlab.com/explore",
    "https://cloudflare.com/learning/access-management/what-is-zero-trust/",
    "https://nist.gov/cyberframework",
    "https://cve.mitre.org",
    "https://kaggle.com/datasets",
    "https://arxiv.org/abs/2301.00000",
    "https://apple.com/macbook-pro",
    "https://adobe.com/products/photoshop",
    "https://dropbox.com/home",
    "https://zoom.us/join",
    "https://slack.com",
    "https://digitalocean.com/community/tutorials",
    "https://docker.com/products/docker-desktop",
]

# Representative corpus of phishing, credential harvesting, and suspicious URLs
PHISHING_URLS = [
    "http://192.168.1.55/paypal/login.php?cmd=verify&account=update",
    "http://10.0.0.1/admin/login.php",
    "http://218.45.19.12/secure-banking/signin.html",
    "http://secure-apple-id-verify.account-update.xyz/login.html",
    "http://paypal-verification-center.account-restore.top/webscr.php",
    "https://microsoft-account-protection-verify.xyz/signin",
    "http://chase-bank-secure-alert.online-banking-auth.xyz/confirm.php",
    "http://bankofamerica-alert-unusual-activity.com.verify-user.tk/auth",
    "http://wellsfargo-security-check.action-required.party/login",
    "http://netflix-billing-update-required.account-payment.top/verify",
    "https://amazon-suspended-order-confirm.customer-support.xyz/help",
    "http://gmail-security-alert-unauthorized-access.buzz/recover-password",
    "http://facebook-security-team-checkpoint.gq/login.php?token=49193294",
    "http://instagram-copyright-infringement-appeal.fit/verify.php",
    "http://binance-wallet-recovery-validation.icu/import",
    "http://metamask-seed-phrase-verification.rest/restore",
    "http://coinbase-auth-unusual-transaction.cam/confirm",
    "http://irs-tax-refund-claim-deposit.top/refund?amount=2400",
    "http://usps-tracking-package-address-update.xyz/redelivery",
    "http://dhl-express-shipment-held-customs.click/track.php?fee=3.99",
    "http://whatsapp-web-synchronization-qr.country/scan",
    "http://telegram-premium-free-activation.top/gift",
    "http://steamcommunity-trade-offer-confirm.link/trade/7489372",
    "http://roblox-free-robux-generator-2026.party/claim",
    "http://epicgames-vbucks-reward-claim.xyz/login",
    "http://google-drive-shared-invoice-view.top/doc.php",
    "http://docusign-envelope-review-sign.cf/document?id=948294",
    "http://adobe-pdf-protected-view-online.ml/view",
    "http://office365-password-expiration-notice.top/owa/auth",
    "http://zoom-meeting-invitation-reconnect.buzz/join?id=8392849",
    "http://linkedin-job-interview-confirmation.xyz/apply",
    "http://twitter-blue-verification-badge-free.top/claim",
    "http://secure-login-portal-verification-update.com-auth.xyz/check",
    "http://account-suspension-warning-action-needed.online/resolve",
    "http://unusual-signin-attempt-blocked.verify-identity.top/login",
    "http://security-update-critical-patch-download.xyz/update.exe",
    "http://appleid-password-reset-confirmation.rest/reset",
    "http://secure-payment-gateway-reauth.buzz/checkout",
    "http://ebay-resolution-center-dispute-claim.top/resolution",
    "http://walmart-giftcard-surveys-reward.party/redeem",
]


def prepare_dataset():
    """Extracts features for both benign and phishing URLs."""
    X = []
    y = []

    for url in BENIGN_URLS:
        features = extract_url_features(url)
        X.append(features_to_vector(features))
        y.append(0)  # 0 = Benign

    for url in PHISHING_URLS:
        features = extract_url_features(url)
        X.append(features_to_vector(features))
        y.append(1)  # 1 = Phishing

    return np.array(X), np.array(y)


def train_model(save_path: Path = MODEL_PATH):
    """Trains the Random Forest model and persists it to disk."""
    X, y = prepare_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=50,
        max_depth=6,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Model trained successfully. Test Accuracy: {acc:.2%}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=["Benign", "Phishing"]))

    # Save artifact
    model_artifact = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "version": "1.0.0",
    }
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_artifact, str(save_path))
    print(f"Saved trained model to {save_path}")
    return clf


if __name__ == "__main__":
    train_model()
