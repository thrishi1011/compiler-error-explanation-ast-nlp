"""
tools/train_and_evaluate_variants.py
------------------------------------
Trains 3 model variants (A, B, C) using data already on disk, caches the 23-file
benchmark compiler diagnostics once, and evaluates Old Model vs A vs B vs C.
"""

import os
import sys
import csv
import json
import time
import shutil
import joblib
import subprocess
import numpy as np
import pandas as pd
from collections import Counter, defaultdict
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, f1_score

SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC_DIR)

from error_normalizer import normalize_for_classifier
from error_parser import parse_errors
from accuracy_benchmark import FILE_LABELS, _majority

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
V2_DIR = os.path.join(DATA_DIR, "v2")

TRAIN_PATH = os.path.join(V2_DIR, "train.jsonl")
VAL_PATH = os.path.join(V2_DIR, "val.jsonl")
TEST_PATH = os.path.join(V2_DIR, "test.jsonl")
GOLD_PATH = os.path.join(V2_DIR, "gold_candidates.csv")

BACKUP_V1_JOB = os.path.join(DATA_DIR, "backup_v1", "error_classifier.joblib")
BACKUP_V1_DATA = os.path.join(DATA_DIR, "backup_v1", "training_data.json")
ORIGINAL_DATA = os.path.join(DATA_DIR, "training_data_original.json")

OLD_MODEL_COPY = os.path.join(DATA_DIR, "error_classifier_v1_old.joblib")
V2_MODEL_COPY = os.path.join(DATA_DIR, "error_classifier_v2.joblib")

MODEL_A_PATH = os.path.join(V2_DIR, "model_A.joblib")
MODEL_B_PATH = os.path.join(V2_DIR, "model_B.joblib")
MODEL_C_PATH = os.path.join(V2_DIR, "model_C.joblib")

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

def evaluate_pipeline(pipe, rows, is_gold=False):
    if is_gold:
        X = [normalize_for_classifier(r["message_raw"]) for r in rows]
    else:
        X = [r["message_norm"] for r in rows]
    y_true = [r["category"] for r in rows]

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

def cache_23_benchmark():
    test_dir = os.path.join(BASE_DIR, "test_cases")
    cached = []
    for fname, expected in FILE_LABELS.items():
        fpath = os.path.join(test_dir, fname)
        if not os.path.exists(fpath):
            cached.append((fname, expected, [], "FILE_MISSING"))
            continue
        try:
            res = subprocess.run(
                ["g++", "-std=c++17", "-Wall", fpath, "-o", fpath.replace(".cpp", ".exe")],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15
            )
            raw = res.stderr
            errors = parse_errors(raw)
            messages = [e.message for e in errors if e.message]
            
            # Clean exe
            exe_p = fpath.replace(".cpp", ".exe")
            if os.path.exists(exe_p):
                try: os.remove(exe_p)
                except: pass

            flag = ""
            if not messages:
                flag = "NO_COMPILER_MESSAGE"
            elif fname in ("const_assignment.cpp", "stream_operator.cpp", "switch_fallthrough.cpp", "unused_variable.cpp"):
                flag = "DEBATABLE_LABEL"
            
            cached.append((fname, expected, messages, flag))
        except Exception as e:
            cached.append((fname, expected, [], f"ERR: {e}"))
    return cached

def main():
    print("=== Step 1: Preserving Models ===")
    if os.path.exists(BACKUP_V1_JOB):
        shutil.copy(BACKUP_V1_JOB, OLD_MODEL_COPY)
        print(f"Copied backup v1 model -> {OLD_MODEL_COPY}")
    
    current_active = os.path.join(DATA_DIR, "error_classifier.joblib")
    if os.path.exists(current_active):
        shutil.copy(current_active, V2_MODEL_COPY)
        print(f"Copied current active model -> {V2_MODEL_COPY}")

    print("\n=== Step 2: Training Variants A, B, C ===")
    # Exclusions set: val, test, gold
    val_rows = load_jsonl(VAL_PATH)
    test_rows = load_jsonl(TEST_PATH)
    gold_rows = load_gold()

    exclusion_norms = set()
    for r in val_rows: exclusion_norms.add(r["message_norm"])
    for r in test_rows: exclusion_norms.add(r["message_norm"])
    for r in gold_rows: exclusion_norms.add(r["message_norm"])

    # Base dataset A
    train_A = load_jsonl(TRAIN_PATH)
    seen_norms_A = {r["message_norm"] for r in train_A}

    # Variant A Training
    t0 = time.time()
    pipe_A = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 3), max_features=10000, sublinear_tf=True)),
        ("clf", LogisticRegression(C=3.0, class_weight="balanced", max_iter=500, random_state=42))
    ])
    pipe_A.fit([r["message_norm"] for r in train_A], [r["category"] for r in train_A])
    t_A = time.time() - t0
    joblib.dump(pipe_A, MODEL_A_PATH, compress=3)
    print(f"Model A: trained on {len(train_A)} rows in {t_A:.2f}s -> {MODEL_A_PATH}")

    # Build Variant B: A + backup_v1/training_data.json
    train_B = list(train_A)
    seen_norms_B = set(seen_norms_A)
    if os.path.exists(BACKUP_V1_DATA):
        with open(BACKUP_V1_DATA, "r", encoding="utf-8") as f:
            b1_data = json.load(f)
        added_b = 0
        for item in b1_data:
            msg = item.get("message", "")
            cat = item.get("category", "")
            if not msg or cat not in CATEGORIES: continue
            norm = normalize_for_classifier(msg)
            if len(norm) > 3 and norm not in exclusion_norms and norm not in seen_norms_B:
                seen_norms_B.add(norm)
                train_B.append({"message_norm": norm, "category": cat})
                added_b += 1
        print(f"Model B data: added {added_b} deduplicated rows from backup_v1 data.")

    t0 = time.time()
    pipe_B = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 3), max_features=10000, sublinear_tf=True)),
        ("clf", LogisticRegression(C=3.0, class_weight="balanced", max_iter=500, random_state=42))
    ])
    pipe_B.fit([r["message_norm"] for r in train_B], [r["category"] for r in train_B])
    t_B = time.time() - t0
    joblib.dump(pipe_B, MODEL_B_PATH, compress=3)
    print(f"Model B: trained on {len(train_B)} rows in {t_B:.2f}s -> {MODEL_B_PATH}")

    # Build Variant C: A + training_data_original.json (CodeNet GCC, capped 1500 per category)
    train_C = list(train_A)
    seen_norms_C = set(seen_norms_A)
    cat_counts_C = Counter(r["category"] for r in train_C)
    if os.path.exists(ORIGINAL_DATA):
        with open(ORIGINAL_DATA, "r", encoding="utf-8") as f:
            c_data = json.load(f)
        added_c = 0
        for item in c_data:
            msg = item.get("message", "")
            cat = item.get("category", "")
            if not msg or cat not in CATEGORIES: continue
            norm = normalize_for_classifier(msg)
            if len(norm) > 3 and norm not in exclusion_norms and norm not in seen_norms_C:
                if cat_counts_C[cat] < 1500:
                    seen_norms_C.add(norm)
                    train_C.append({"message_norm": norm, "category": cat})
                    cat_counts_C[cat] += 1
                    added_c += 1
        print(f"Model C data: added {added_c} deduplicated rows from CodeNet original.")

    t0 = time.time()
    pipe_C = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 3), max_features=10000, sublinear_tf=True)),
        ("clf", LogisticRegression(C=3.0, class_weight="balanced", max_iter=500, random_state=42))
    ])
    pipe_C.fit([r["message_norm"] for r in train_C], [r["category"] for r in train_C])
    t_C = time.time() - t0
    joblib.dump(pipe_C, MODEL_C_PATH, compress=3)
    print(f"Model C: trained on {len(train_C)} rows in {t_C:.2f}s -> {MODEL_C_PATH}")

    print("\n=== Step 3: Evaluation & Benchmarking ===")
    models = {
        "Old Model (v1)": joblib.load(OLD_MODEL_COPY),
        "Model A (v2-pure)": pipe_A,
        "Model B (+v1 data)": pipe_B,
        "Model C (+CodeNet)": pipe_C,
    }

    # Measure sizes, latencies, test/gold metrics
    model_stats = {}
    sample_norm = normalize_for_classifier("expected ';' before 'return'")

    for name, pipe in models.items():
        # Path for size
        if name == "Old Model (v1)": p = OLD_MODEL_COPY
        elif name == "Model A (v2-pure)": p = MODEL_A_PATH
        elif name == "Model B (+v1 data)": p = MODEL_B_PATH
        else: p = MODEL_C_PATH
        size_kb = os.path.getsize(p) / 1024.0

        # Latency
        lats = []
        for _ in range(1000):
            t_p = time.perf_counter()
            _ = pipe.predict([sample_norm])
            lats.append((time.perf_counter() - t_p) * 1000.0)
        med_lat = np.median(lats)

        ev_test = evaluate_pipeline(pipe, test_rows)
        ev_gold = evaluate_pipeline(pipe, gold_rows, is_gold=True)

        model_stats[name] = {
            "size_kb": size_kb,
            "latency_ms": med_lat,
            "test_acc": ev_test["accuracy"] * 100,
            "test_f1": ev_test["macro_f1"] * 100,
            "gold_acc": ev_gold["accuracy"] * 100,
            "gold_f1": ev_gold["macro_f1"] * 100,
            "gold_per_cls": ev_gold["per_class_f1"],
            "pipe": pipe
        }

    # 23-File Benchmark (Cached compiler run)
    print("\nCaching 23 benchmark file diagnostics (single g++ run)...")
    cached_bench = cache_23_benchmark()
    bench_results_per_model = defaultdict(int)
    bench_rows = []

    for fname, expected, msgs, flag in cached_bench:
        row_dict = {"file": fname, "expected": expected, "flag": flag}
        for name, pipe in models.items():
            if not msgs:
                pred = "other"
            else:
                norm_msgs = [normalize_for_classifier(m) for m in msgs]
                preds = [pipe.predict([nm])[0] for nm in norm_msgs]
                pred = _majority(preds)
            row_dict[name] = pred
            if pred == expected:
                bench_results_per_model[name] += 1
        bench_rows.append(row_dict)

    # 1. Main Metrics Table
    print("\n" + "="*105)
    print(f"{'MODEL':<20} | {'TEST ACC':<9} | {'TEST F1':<9} | {'GOLD ACC*':<10} | {'GOLD F1*':<10} | {'BENCH (23)':<11} | {'SIZE':<8} | {'LATENCY':<9}")
    print("="*105)
    for name, st in model_stats.items():
        b_score = f"{bench_results_per_model[name]}/23"
        print(f"{name:<20} | {st['test_acc']:>7.1f}% | {st['test_f1']:>7.1f}% | {st['gold_acc']:>8.1f}% | {st['gold_f1']:>8.1f}% | {b_score:>11} | {st['size_kb']:>6.1f}KB | {st['latency_ms']:>6.3f}ms")
    print("="*105)
    print("* Note: Gold labels were drafted with rule definitions (not strictly independent ground truth).")

    # 2. Gold Per-Class F1 Table
    print("\n" + "="*105)
    print(f"{'CATEGORY':<20} | {'OLD (v1)':<12} | {'MODEL A':<12} | {'MODEL B':<12} | {'MODEL C':<12}")
    print("="*105)
    for cat in CATEGORIES:
        f_old = model_stats["Old Model (v1)"]["gold_per_cls"][cat] * 100
        f_A = model_stats["Model A (v2-pure)"]["gold_per_cls"][cat] * 100
        f_B = model_stats["Model B (+v1 data)"]["gold_per_cls"][cat] * 100
        f_C = model_stats["Model C (+CodeNet)"]["gold_per_cls"][cat] * 100
        print(f"{cat:<20} | {f_old:>10.1f}% | {f_A:>10.1f}% | {f_B:>10.1f}% | {f_C:>10.1f}%")
    print("="*105)

    # 3. 23-File Detailed Benchmark Table
    print("\n" + "="*115)
    print(f"{'BENCHMARK FILE':<28} | {'EXPECTED':<17} | {'OLD':<14} | {'MODEL A':<14} | {'MODEL B':<14} | {'MODEL C':<14} | {'FLAG'}")
    print("="*115)
    for r in bench_rows:
        flag_str = f"[{r['flag']}]" if r['flag'] else ""
        p_old = str(r.get('Old Model (v1)', ''))
        p_A = str(r.get('Model A (v2-pure)', ''))
        p_B = str(r.get('Model B (+v1 data)', ''))
        p_C = str(r.get('Model C (+CodeNet)', ''))
        print(f"{str(r['file']):<28} | {str(r['expected']):<17} | {p_old:<14} | {p_A:<14} | {p_B:<14} | {p_C:<14} | {flag_str}")
    print("="*115)

    # 4. Selection based on Test F1 + Gold F1
    scores = {}
    for name in ["Model A (v2-pure)", "Model B (+v1 data)", "Model C (+CodeNet)"]:
        scores[name] = model_stats[name]["test_f1"] + model_stats[name]["gold_f1"]
    
    best_variant = max(scores, key=scores.get)
    print(f"\n=== Step 4: Selection Decision ===")
    for name, sc in scores.items():
        print(f"  {name}: Test F1 ({model_stats[name]['test_f1']:.1f}%) + Gold F1 ({model_stats[name]['gold_f1']:.1f}%) = Combined Metric: {sc:.2f}")
    print(f"\nSELECTED WINNER: {best_variant}")

    # Activation commands
    print("\n=== One-Line Activation Commands ===")
    print("To activate Model A: copy data\\v2\\model_A.joblib data\\error_classifier.joblib")
    print("To activate Model B: copy data\\v2\\model_B.joblib data\\error_classifier.joblib")
    print("To activate Model C: copy data\\v2\\model_C.joblib data\\error_classifier.joblib")
    print("To revert to Old v1: copy data\\error_classifier_v1_old.joblib data\\error_classifier.joblib")

if __name__ == "__main__":
    main()
