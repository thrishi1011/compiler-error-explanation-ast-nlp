"""
tools/compare_models.py
-----------------------
Trains candidate Model V2, evaluates both Old Model and Candidate Model V2,
generates the comparison table, confusion matrix on val, and verifies promotion criteria.
"""

import os
import sys
import csv
import json
import time
import joblib
import numpy as np
import pandas as pd
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report

SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC_DIR)

from error_normalizer import normalize_for_classifier
from accuracy_benchmark import run_benchmark
from error_classifier import ErrorClassifier

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_PATH = os.path.join(BASE_DIR, "data", "v2", "train.jsonl")
VAL_PATH = os.path.join(BASE_DIR, "data", "v2", "val.jsonl")
TEST_PATH = os.path.join(BASE_DIR, "data", "v2", "test.jsonl")
GOLD_PATH = os.path.join(BASE_DIR, "data", "v2", "gold_candidates.csv")

OLD_MODEL_PATH = os.path.join(BASE_DIR, "data", "backup_v1", "error_classifier.joblib")
NEW_MODEL_PATH = os.path.join(BASE_DIR, "data", "v2", "model_v2.joblib")
FINAL_MODEL_PATH = os.path.join(BASE_DIR, "data", "error_classifier.joblib")
CONFUSION_OUT = os.path.join(BASE_DIR, "data", "v2", "confusion_val.csv")

CATEGORIES = [
    "syntax_error", "name_resolution", "missing_include",
    "type_error", "return_type_error", "redefinition",
    "access_error", "linker_error", "other"
]

def load_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows

def load_gold():
    rows = []
    with open(GOLD_PATH, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r.get("final_label", "").strip():
                rows.append({
                    "id": r["id"],
                    "message_raw": r["message_raw"],
                    "message_norm": normalize_for_classifier(r["message_raw"]),
                    "category": r["final_label"].strip()
                })
    return rows

def train_new_model():
    train_rows = load_jsonl(TRAIN_PATH)
    X_train = [r["message_norm"] for r in train_rows]
    y_train = [r["category"] for r in train_rows]

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 3), max_features=10000, sublinear_tf=True)),
        ("clf", LogisticRegression(C=3.0, class_weight="balanced", max_iter=500, random_state=42))
    ])

    print("Training Candidate Model V2...")
    pipe.fit(X_train, y_train)
    joblib.dump(pipe, NEW_MODEL_PATH, compress=3)
    return pipe

def evaluate_pipeline(pipe, rows, use_raw=False):
    if use_raw:
        X = [normalize_for_classifier(r.get("message_raw", r["message_norm"])) for r in rows]
    else:
        X = [r["message_norm"] for r in rows]
    y_true = [r["category"] for r in rows]

    # For old model pipeline: check if old model needs raw or normalized
    y_pred = pipe.predict(X)
    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    per_cls_f1 = f1_score(y_true, y_pred, average=None, labels=CATEGORIES, zero_division=0)
    per_cls_dict = {cat: score for cat, score in zip(CATEGORIES, per_cls_f1)}

    return {
        "accuracy": acc,
        "macro_f1": macro_f1,
        "per_class_f1": per_cls_dict,
        "y_true": y_true,
        "y_pred": y_pred
    }

def main():
    print("=== Training Candidate Model V2 & Benchmarking ===")
    
    # 1. Train Model V2
    t0 = time.time()
    new_pipe = train_new_model()
    train_time = time.time() - t0
    print(f"Model V2 trained in {train_time:.2f}s.")

    # Model metrics
    classes_present = list(new_pipe.named_steps["clf"].classes_)
    file_size_kb = os.path.getsize(NEW_MODEL_PATH) / 1024.0

    # Load time
    t_load0 = time.time()
    loaded_pipe = joblib.load(NEW_MODEL_PATH)
    load_time_ms = (time.time() - t_load0) * 1000.0

    # Median predict latency over 1000 calls
    sample_msg = normalize_for_classifier("expected ';' before 'return'")
    latencies = []
    for _ in range(1000):
        t_p0 = time.perf_counter()
        _ = loaded_pipe.predict([sample_msg])
        latencies.append((time.perf_counter() - t_p0) * 1000.0)
    median_latency_ms = np.median(latencies)

    print("\n--- Model V2 Specs ---")
    print(f"Classes Present ({len(classes_present)}): {classes_present}")
    print(f"File Size: {file_size_kb:.1f} KB")
    print(f"Load Time: {load_time_ms:.2f} ms")
    print(f"Median Predict Latency (1000 calls): {median_latency_ms:.3f} ms")

    # 2. Load Old Model
    old_pipe = joblib.load(OLD_MODEL_PATH)

    # 3. Load Datasets
    val_rows = load_jsonl(VAL_PATH)
    test_rows = load_jsonl(TEST_PATH)
    gold_rows = load_gold()

    # 4. Evaluate both models on Val, Test, Gold
    old_val = evaluate_pipeline(old_pipe, val_rows)
    new_val = evaluate_pipeline(new_pipe, val_rows)

    old_test = evaluate_pipeline(old_pipe, test_rows)
    new_test = evaluate_pipeline(new_pipe, test_rows)

    old_gold = evaluate_pipeline(old_pipe, gold_rows, use_raw=True)
    new_gold = evaluate_pipeline(new_pipe, gold_rows, use_raw=True)

    # Save confusion matrix on val
    val_y_true = new_val["y_true"]
    val_y_pred = new_val["y_pred"]
    conf_mat = confusion_matrix(val_y_true, val_y_pred, labels=CATEGORIES)
    conf_df = pd.DataFrame(conf_mat, index=CATEGORIES, columns=CATEGORIES)
    conf_df.to_csv(CONFUSION_OUT)
    print(f"\nSaved Validation Confusion Matrix to {CONFUSION_OUT}")

    # 5. Run 23-File Benchmark for both models
    # Benchmark with old model in place
    import shutil
    shutil.copy(OLD_MODEL_PATH, FINAL_MODEL_PATH)
    old_bench = run_benchmark()

    # Benchmark with new model in place
    shutil.copy(NEW_MODEL_PATH, FINAL_MODEL_PATH)
    new_bench = run_benchmark()

    # 6. Compact Comparison Table
    print("\n" + "="*80)
    print(f"{'METRIC':<35} | {'OLD MODEL':<18} | {'NEW MODEL V2':<18}")
    print("="*80)
    print(f"{'Val Accuracy':<35} | {old_val['accuracy']*100:>16.1f}% | {new_val['accuracy']*100:>16.1f}%")
    print(f"{'Val Macro-F1':<35} | {old_val['macro_f1']*100:>16.1f}% | {new_val['macro_f1']*100:>16.1f}%")
    print(f"{'Test Accuracy':<35} | {old_test['accuracy']*100:>16.1f}% | {new_test['accuracy']*100:>16.1f}%")
    print(f"{'Test Macro-F1':<35} | {old_test['macro_f1']*100:>16.1f}% | {new_test['macro_f1']*100:>16.1f}%")
    print(f"{'Gold Accuracy (n=' + str(len(gold_rows)) + ')':<35} | {old_gold['accuracy']*100:>16.1f}% | {new_gold['accuracy']*100:>16.1f}%")
    print(f"{'Gold Macro-F1':<35} | {old_gold['macro_f1']*100:>16.1f}% | {new_gold['macro_f1']*100:>16.1f}%")
    print(f"{'23-File Benchmark ML Score':<35} | {old_bench['ml_correct']:>14}/23  | {new_bench['ml_correct']:>14}/23 ")
    print(f"{'23-File Benchmark Combined Score':<35} | {old_bench['combo_correct']:>14}/23  | {new_bench['combo_correct']:>14}/23 ")
    print("-"*80)
    print("GOLD PER-CLASS F1:")
    for cat in CATEGORIES:
        o_f1 = old_gold['per_class_f1'].get(cat, 0.0) * 100
        n_f1 = new_gold['per_class_f1'].get(cat, 0.0) * 100
        print(f"  {cat:<33} | {o_f1:>16.1f}% | {n_f1:>16.1f}%")
    print("="*80)

    # 7. Print Gold Errors of New Model
    print("\n--- Gold Rows New Model Gets Wrong ---")
    wrong_gold = []
    for gr, y_t, y_p in zip(gold_rows, new_gold["y_true"], new_gold["y_pred"]):
        if y_t != y_p:
            wrong_gold.append((gr["id"], gr["message_raw"], y_t, y_p))
    
    if not wrong_gold:
        print("None! All gold rows predicted correctly.")
    else:
        for i, (gid, msg, yt, yp) in enumerate(wrong_gold[:15], 1):
            print(f"  {i:2d}. [ID {gid}] True: {yt:<18} | Pred: {yp:<18} | Msg: {msg}")

    # 8. Promotion Gate Checks
    print("\n--- Promotion Criteria Verification ---")
    check1 = (len(classes_present) == 9 and set(classes_present) == set(CATEGORIES))
    check2 = (new_gold["accuracy"] >= old_gold["accuracy"] and new_gold["macro_f1"] >= old_gold["macro_f1"])
    check3 = (new_bench["ml_correct"] >= old_bench["ml_correct"])
    check4 = (
        new_gold["per_class_f1"]["access_error"] >= old_gold["per_class_f1"]["access_error"]
        and new_gold["per_class_f1"]["return_type_error"] >= old_gold["per_class_f1"]["return_type_error"]
    )

    print(f"1. Predicts all 9 categories:         {'PASS' if check1 else 'FAIL'} ({len(classes_present)}/9)")
    print(f"2. Gold Acc & Macro-F1 >= Old:        {'PASS' if check2 else 'FAIL'} (Acc: {new_gold['accuracy']*100:.1f}% vs {old_gold['accuracy']*100:.1f}%, F1: {new_gold['macro_f1']*100:.1f}% vs {old_gold['macro_f1']*100:.1f}%)")
    print(f"3. 23-File Benchmark ML >= 12/23:     {'PASS' if check3 else 'FAIL'} ({new_bench['ml_correct']}/23 vs {old_bench['ml_correct']}/23)")
    print(f"4. Access & Return F1 on Gold >= Old: {'PASS' if check4 else 'FAIL'} (Access: {new_gold['per_class_f1']['access_error']*100:.1f}% vs {old_gold['per_class_f1']['access_error']*100:.1f}%, Return: {new_gold['per_class_f1']['return_type_error']*100:.1f}% vs {old_gold['per_class_f1']['return_type_error']*100:.1f}%)")

    all_passed = check1 and check2 and check3 and check4

    if all_passed:
        print("\nPROMOTION VERDICT: APPROVED (All 4 criteria PASSED). Promoting Model V2 to data/error_classifier.joblib.")
        shutil.copy(NEW_MODEL_PATH, FINAL_MODEL_PATH)
    else:
        print("\nPROMOTION VERDICT: REJECTED (One or more criteria failed). Reverting to backup model.")
        shutil.copy(OLD_MODEL_PATH, FINAL_MODEL_PATH)

if __name__ == "__main__":
    main()
