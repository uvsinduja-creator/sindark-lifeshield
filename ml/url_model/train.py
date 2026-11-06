"""
Training and Evaluation pipeline for LifeShield Phishing URL Model.
Trains a CPU-efficient Random Forest classifier on large-scale threat feeds,
computes both Training and Testing metrics, 5-Fold Cross-Validation, and saves model.
"""
import csv
import sys
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split, cross_val_score

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ml.url_model.features import extract_url_features, features_to_vector, FEATURE_NAMES

MODEL_PATH = Path(__file__).parent / "url_model.joblib"
DATASET_CSV = Path(__file__).parent / "data" / "dataset.csv"


def load_dataset():
    """
    Loads dataset from ml/url_model/data/dataset.csv.
    """
    if not DATASET_CSV.exists():
        print(f"[*] Dataset not found at {DATASET_CSV}. Collecting real-world dataset now...")
        from ml.url_model.collect_dataset import build_and_save_dataset
        build_and_save_dataset()

    X = []
    y = []

    print(f"[*] Loading and extracting features from {DATASET_CSV}...")
    with open(DATASET_CSV, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader, None)  # url, label
        count = 0
        for row in reader:
            if len(row) >= 2:
                url_str = row[0].strip()
                try:
                    label = int(row[1].strip())
                except ValueError:
                    continue

                if not url_str:
                    continue

                features = extract_url_features(url_str)
                X.append(features_to_vector(features))
                y.append(label)
                count += 1
                if count % 5000 == 0:
                    print(f"    Extracted features for {count} URLs...")

    print(f"[+] Total samples loaded: {len(X)} (Phishing: {sum(y)}, Benign: {len(y) - sum(y)})")
    return np.array(X), np.array(y)


def train_and_evaluate_model(save_path: Path = MODEL_PATH):
    """
    Trains the Random Forest model and reports:
      - Training Accuracy
      - Testing Accuracy
      - 5-Fold Cross-Validation Accuracy
      - ROC-AUC Score
      - Classification Report (Precision, Recall, F1)
      - Confusion Matrix
    """
    X, y = load_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"\n[*] Training configuration:")
    print(f"    Total samples    : {len(X)}")
    print(f"    Training samples : {len(X_train)} (80%)")
    print(f"    Testing samples  : {len(X_test)} (20%)")
    print(f"    Features         : {len(FEATURE_NAMES)}")

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    print(f"\n[*] Fitting Random Forest model on CPU...")
    clf.fit(X_train, y_train)

    # 1. Training Accuracy
    train_acc = clf.score(X_train, y_train)

    # 2. Testing Accuracy & Predictions
    y_pred = clf.predict(X_test)
    y_pred_proba = clf.predict_proba(X_test)[:, 1]
    test_acc = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    cm = confusion_matrix(y_test, y_pred)

    # 3. 5-Fold Cross-Validation on Training Set
    print(f"[*] Running 5-fold cross-validation on training data...")
    cv_scores = cross_val_score(clf, X_train, y_train, cv=5, n_jobs=-1)
    cv_mean = float(np.mean(cv_scores))
    cv_std = float(np.std(cv_scores))

    # Print comprehensive evaluation report
    print("\n" + "=" * 65)
    print("           LIFESHIELD URL PHISHING MODEL EVALUATION")
    print("=" * 65)
    print(f" Training Accuracy        : {train_acc * 100:.2f}%")
    print(f" Testing / Eval Accuracy  : {test_acc * 100:.2f}%")
    print(f" 5-Fold CV Accuracy (avg) : {cv_mean * 100:.2f}% (+/- {cv_std * 100:.2f}%)")
    print(f" ROC-AUC Score            : {roc_auc:.4f}")
    print("-" * 65)
    print(f" Confusion Matrix (Test Split: {len(y_test)} samples):")
    print(f"   True Benign (TN): {cm[0][0]:<6} | False Phishing (FP): {cm[0][1]}")
    print(f"   False Benign(FN): {cm[1][0]:<6} | True Phishing  (TP): {cm[1][1]}")
    print("-" * 65)
    print(" Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", "Phishing (1)"], digits=4))
    print("=" * 65)

    # Save artifact with complete metrics
    model_artifact = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "version": "1.2.0",
        "sample_count": len(X),
        "train_accuracy": round(float(train_acc), 4),
        "test_accuracy": round(float(test_acc), 4),
        "cv_accuracy_mean": round(cv_mean, 4),
        "roc_auc": round(float(roc_auc), 4),
        "dataset_source": "JPCERT/CC (Jan-Jun 2024) + OpenPhish + Tranco Top 1M",
    }
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_artifact, str(save_path))
    print(f"\n[+] Saved updated model artifact to {save_path}")

    return clf, {
        "train_accuracy": train_acc,
        "test_accuracy": test_acc,
        "cv_mean": cv_mean,
        "cv_std": cv_std,
        "roc_auc": roc_auc,
        "sample_count": len(X),
    }


def train_model(save_path: Path = MODEL_PATH):
    """Compatibility wrapper."""
    clf, _ = train_and_evaluate_model(save_path)
    return clf


if __name__ == "__main__":
    train_and_evaluate_model()
