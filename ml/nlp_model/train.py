"""
Training and Evaluation pipeline for LifeShield Scam Message NLP Model (Week 5).
Uses a TF-IDF + Logistic Regression pipeline, evaluates Training/Testing accuracy,
5-Fold Cross-Validation, and persists the model artifact using joblib.
"""
import csv
import sys
from pathlib import Path
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split, cross_val_score

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

MODEL_PATH = Path(__file__).parent / "nlp_model.joblib"
DATASET_CSV = Path(__file__).parent / "data" / "dataset.csv"


def load_dataset():
    """
    Loads text messages and labels from ml/nlp_model/data/dataset.csv.
    """
    if not DATASET_CSV.exists():
        print(f"[*] Dataset not found at {DATASET_CSV}. Collecting dataset now...")
        from ml.nlp_model.collect_dataset import build_and_save_dataset
        build_and_save_dataset()

    texts = []
    labels = []

    print(f"[*] Loading text messages from {DATASET_CSV}...")
    with open(DATASET_CSV, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader, None)  # text, label
        for row in reader:
            if len(row) >= 2:
                text = row[0].strip()
                try:
                    lbl = int(row[1].strip())
                except ValueError:
                    continue
                if text:
                    texts.append(text)
                    labels.append(lbl)

    print(f"[+] Total samples loaded: {len(texts)} (Scam: {sum(labels)}, Benign: {len(labels) - sum(labels)})")
    return texts, np.array(labels)


def train_and_evaluate_model(save_path: Path = MODEL_PATH):
    """
    Trains the TF-IDF + Logistic Regression pipeline and reports:
      - Training Accuracy
      - Testing Accuracy
      - 5-Fold Cross-Validation Accuracy
      - ROC-AUC Score
      - Classification Report
      - Confusion Matrix
    """
    texts, labels = load_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.20, random_state=42, stratify=labels
    )

    print(f"\n[*] Training configuration:")
    print(f"    Total samples    : {len(texts)}")
    print(f"    Training samples : {len(X_train)} (80%)")
    print(f"    Testing samples  : {len(X_test)} (20%)")
    print(f"    Architecture     : TF-IDF (1-2 ngrams, 5000 max_features) + Logistic Regression")

    pipeline = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 2),
                sublinear_tf=True,
                stop_words="english",
            ),
        ),
        (
            "clf",
            LogisticRegression(
                class_weight="balanced",
                max_iter=1000,
                C=2.0,
                random_state=42,
            ),
        ),
    ])

    print(f"\n[*] Fitting TF-IDF + Logistic Regression pipeline on CPU...")
    pipeline.fit(X_train, y_train)

    # 1. Training Accuracy
    train_acc = pipeline.score(X_train, y_train)

    # 2. Testing Accuracy & Predictions
    y_pred = pipeline.predict(X_test)
    y_pred_proba = pipeline.predict_proba(X_test)[:, 1]
    test_acc = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    cm = confusion_matrix(y_test, y_pred)

    # 3. 5-Fold Cross-Validation on Training Split
    print(f"[*] Running 5-fold cross-validation on training data...")
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=5, n_jobs=-1)
    cv_mean = float(np.mean(cv_scores))
    cv_std = float(np.std(cv_scores))

    # Print comprehensive evaluation report
    print("\n" + "=" * 65)
    print("           LIFESHIELD SCAM NLP MODEL EVALUATION")
    print("=" * 65)
    print(f" Training Accuracy        : {train_acc * 100:.2f}%")
    print(f" Testing / Eval Accuracy  : {test_acc * 100:.2f}%")
    print(f" 5-Fold CV Accuracy (avg) : {cv_mean * 100:.2f}% (+/- {cv_std * 100:.2f}%)")
    print(f" ROC-AUC Score            : {roc_auc:.4f}")
    print("-" * 65)
    print(f" Confusion Matrix (Test Split: {len(y_test)} samples):")
    print(f"   True Benign (TN): {cm[0][0]:<6} | False Scam (FP): {cm[0][1]}")
    print(f"   False Benign(FN): {cm[1][0]:<6} | True Scam  (TP): {cm[1][1]}")
    print("-" * 65)
    print(" Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", "Scam (1)"], digits=4))
    print("=" * 65)

    # Save artifact with complete metrics
    model_artifact = {
        "pipeline": pipeline,
        "version": "1.0.0",
        "sample_count": len(texts),
        "train_accuracy": round(float(train_acc), 4),
        "test_accuracy": round(float(test_acc), 4),
        "cv_accuracy_mean": round(cv_mean, 4),
        "roc_auc": round(float(roc_auc), 4),
        "dataset_source": "UCI SMS Spam Collection + Fraud Email Phishing dataset",
    }
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_artifact, str(save_path))
    print(f"\n[+] Saved trained NLP model artifact to {save_path}")

    return pipeline, {
        "train_accuracy": train_acc,
        "test_accuracy": test_acc,
        "cv_mean": cv_mean,
        "cv_std": cv_std,
        "roc_auc": roc_auc,
        "sample_count": len(texts),
    }


def train_model(save_path: Path = MODEL_PATH):
    """Compatibility wrapper."""
    pipeline, _ = train_and_evaluate_model(save_path)
    return pipeline


if __name__ == "__main__":
    train_and_evaluate_model()
