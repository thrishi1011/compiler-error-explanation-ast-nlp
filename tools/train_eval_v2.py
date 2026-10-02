"""
tools/train_eval_v2.py
----------------------
One-command training and evaluation script for Dataset V2.
Trains the ErrorClassifier on data/v2/train.jsonl + val.jsonl using
normalized diagnostic features and evaluates on data/v2/test.jsonl
and accuracy_benchmark.py.
"""

import os
import sys
import json
import argparse
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, f1_score, accuracy_score
import joblib

SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC_DIR)

from error_normalizer import normalize_for_classifier
from accuracy_benchmark import run_benchmark

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data", "v2")
MODEL_OUT = os.path.join(BASE_DIR, "data", "error_classifier.joblib")

def load_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows

def main():
    parser = argparse.ArgumentParser(description="Train and evaluate classifier on Dataset V2.")
    parser.add_argument("--save", action="store_true", help="Save the trained model to data/error_classifier.joblib")
    args = parser.parse_args()

    train_data = load_jsonl(os.path.join(DATA_DIR, "train.jsonl"))
    val_data = load_jsonl(os.path.join(DATA_DIR, "val.jsonl"))
    test_data = load_jsonl(os.path.join(DATA_DIR, "test.jsonl"))

    full_train = train_data + val_data
    X_train = [r["message_norm"] for r in full_train]
    y_train = [r["category"] for r in full_train]

    X_test = [r["message_norm"] for r in test_data]
    y_test = [r["category"] for r in test_data]
    raw_test = [r["message_raw"] for r in test_data]

    print(f"Loaded {len(X_train)} train+val rows, {len(X_test)} test rows.")

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 3), max_features=10000, sublinear_tf=True)),
        ("clf", LogisticRegression(C=3.0, max_iter=500, random_state=42))
    ])

    print("Training model...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    acc = accuracy_score(y_test, y_pred)

    print(f"\n--- Test Set Evaluation ---")
    print(f"Accuracy: {acc*100:.2f}% | Macro-F1: {macro_f1*100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, digits=3))

    if args.save:
        joblib.dump(pipeline, MODEL_OUT, compress=3)
        print(f"Saved model to {MODEL_OUT}")

if __name__ == "__main__":
    main()
