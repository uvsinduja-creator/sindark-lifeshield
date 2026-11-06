"""
Training pipeline for LifeShield Phishing URL Model.
Trains a CPU-efficient Random Forest classifier on real-world threat feeds
(JPCERT/CC, OpenPhish, and Tranco Top 1M) and saves it using joblib.
"""
import csv
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
DATASET_CSV = Path(__file__).parent / "data" / "dataset.csv"


def load_dataset():
    """
    Loads dataset from ml/url_model/data/dataset.csv.
    If missing, runs collect_dataset to fetch real-world data.
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
                if count % 1000 == 0:
                    print(f"    Extracted features for {count} URLs...")

    print(f"[+] Total samples loaded: {len(X)} (Phishing: {sum(y)}, Benign: {len(y) - sum(y)})")
    return np.array(X), np.array(y)


def train_model(save_path: Path = MODEL_PATH):
    """Trains the Random Forest model and persists it to disk."""
    X, y = load_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Training Random Forest on {len(X_train)} samples (CPU-optimized)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[+] Model trained successfully. Test Accuracy: {acc:.2%}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=["Benign", "Phishing"]))

    # Save artifact
    model_artifact = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "version": "1.1.0",
        "sample_count": len(X),
        "dataset_source": "JPCERT/CC + OpenPhish + Tranco Top 1M",
    }
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_artifact, str(save_path))
    print(f"[+] Saved updated model to {save_path}")
    return clf


if __name__ == "__main__":
    train_model()
