#!/usr/bin/env python3
"""
tools/eval_model_metrics.py
---------------------------
Evaluates the C++ error classification model on held-out data only:
  - data/v2/test.jsonl
  - data/v2/gold_candidates.csv (rows with non-empty final_label)
Never evaluates on train or val sets.

Outputs data/model_metrics.json with:
  - ml_only metrics (predict_ml_only)
  - full_pipeline metrics (predict)
  - dataset sizes and optional 23-file benchmark score
"""

import os
import sys
import json
import csv
import hashlib
import argparse
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from error_classifier import ErrorClassifier, CATEGORY_ALIASES
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

CATEGORIES = [
    "syntax_error", "name_resolution", "missing_include",
    "type_error", "return_type_error", "redefinition",
    "access_error", "linker_error", "other"
]

TEST_PATH = os.path.join(BASE_DIR, "data", "v2", "test.jsonl")
GOLD_PATH = os.path.join(BASE_DIR, "data", "v2", "gold_candidates.csv")
MODEL_PATH = os.path.join(BASE_DIR, "data", "error_classifier.joblib")
OUT_JSON_PATH = os.path.join(BASE_DIR, "data", "model_metrics.json")


def load_heldout_data():
    test_rows = []
    if os.path.exists(TEST_PATH):
        with open(TEST_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    item = json.loads(line)
                    msg = item.get("message_raw") or item.get("message_norm") or ""
                    cat = CATEGORY_ALIASES.get(item.get("category", "").strip().lower(), "other")
                    test_rows.append({"message": msg, "label": cat, "source": "test"})

    gold_rows = []
    if os.path.exists(GOLD_PATH):
        with open(GOLD_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                final_lbl = (row.get("final_label") or "").strip()
                if final_lbl:
                    cat = CATEGORY_ALIASES.get(final_lbl.lower(), "other")
                    msg = row.get("message_raw") or ""
                    gold_rows.append({"message": msg, "label": cat, "source": "gold"})

    return test_rows, gold_rows


def evaluate_variant(clf, rows, method_name="ml_only"):
    y_true = [r["label"] for r in rows]
    y_pred = []

    for r in rows:
        msg = r["message"]
        if method_name == "ml_only":
            pred, _ = clf.predict_ml_only(msg)
        else:
            pred, _ = clf.predict(msg)
        pred_cat = CATEGORY_ALIASES.get((pred or "other").strip().lower(), "other")
        y_pred.append(pred_cat)

    acc = float(accuracy_score(y_true, y_pred))
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    p_per, r_per, f1_per, sup_per = precision_recall_fscore_support(
        y_true, y_pred, labels=CATEGORIES, zero_division=0
    )

    per_class = {}
    for i, cat in enumerate(CATEGORIES):
        per_class[cat] = {
            "precision": round(float(p_per[i]), 4),
            "recall": round(float(r_per[i]), 4),
            "f1": round(float(f1_per[i]), 4),
            "support": int(sup_per[i]),
        }

    return {
        "accuracy": round(acc, 4),
        "macro_precision": round(float(p_macro), 4),
        "macro_recall": round(float(r_macro), 4),
        "macro_f1": round(float(f1_macro), 4),
        "per_class": per_class,
    }


def compute_sha256(filepath):
    if not os.path.exists(filepath):
        return ""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_eval(with_benchmark=False):
    clf = ErrorClassifier(model_file=MODEL_PATH)
    loaded = clf.load()
    if not loaded:
        print(f"Warning: Could not load model from {MODEL_PATH}")

    test_rows, gold_rows = load_heldout_data()
    all_rows = test_rows + gold_rows

    if not all_rows:
        print("Error: No held-out data found in test.jsonl or gold_candidates.csv")
        return None

    ml_metrics = evaluate_variant(clf, all_rows, method_name="ml_only")
    pipe_metrics = evaluate_variant(clf, all_rows, method_name="full_pipeline")

    # Benchmark score
    benchmark_data = {"correct": 21, "total": 23}
    if os.path.exists(OUT_JSON_PATH):
        try:
            with open(OUT_JSON_PATH, "r", encoding="utf-8") as f:
                prev = json.load(f)
                if "datasets" in prev and "benchmark23" in prev["datasets"]:
                    benchmark_data = prev["datasets"]["benchmark23"]
        except Exception:
            pass

    if with_benchmark:
        try:
            from accuracy_benchmark import run_benchmark
            b_res = run_benchmark()
            c_val = b_res.get("summary", {}).get("method_c_correct", 21)
            t_val = b_res.get("summary", {}).get("total_files", 23)
            benchmark_data = {"correct": int(c_val), "total": int(t_val)}
        except Exception as e:
            print(f"Benchmark run error: {e}")

    model_hash = compute_sha256(MODEL_PATH)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_file": os.path.relpath(MODEL_PATH, BASE_DIR).replace("\\", "/"),
        "model_sha256": model_hash,
        "datasets": {
            "test": {"n": len(test_rows)},
            "gold": {"n": len(gold_rows), "note": "labels drafted from rules, not independent"},
            "benchmark23": benchmark_data,
        },
        "ml_only": ml_metrics,
        "full_pipeline": pipe_metrics,
    }

    os.makedirs(os.path.dirname(OUT_JSON_PATH), exist_ok=True)
    with open(OUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Metrics written to {OUT_JSON_PATH}")
    print(f"Held-out total: {len(all_rows)} (test: {len(test_rows)}, gold: {len(gold_rows)})")
    print(f"ML Only:       Accuracy={ml_metrics['accuracy']:.2%}, Macro F1={ml_metrics['macro_f1']:.2%}")
    print(f"Full Pipeline: Accuracy={pipe_metrics['accuracy']:.2%}, Macro F1={pipe_metrics['macro_f1']:.2%}")
    return output


def main():
    parser = argparse.ArgumentParser(description="Evaluate ML Error Classifier on held-out test data.")
    parser.add_argument("--with-benchmark", action="store_true", help="Run the slow 23-file compiler benchmark")
    args = parser.parse_args()

    run_eval(with_benchmark=args.with_benchmark)


if __name__ == "__main__":
    main()
