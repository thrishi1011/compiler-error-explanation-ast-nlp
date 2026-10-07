"""
tools/assemble_dataset_v2.py
----------------------------
Assembles Dataset V2 with full 9-class coverage:
1. Pure GCC mutations from data/v2/mutations.jsonl
2. Relabeled CodeNet GCC messages from data/training_data_original.json
3. Curated C++ domain patterns from create_training_dataset.get_curated_cpp_patterns() for linker_error, return_type_error, and access_error
4. Genuine GCC warning flags for other (-Wsign-compare, -Wparentheses, -Wunused-variable, etc.)

Guarantees:
- Deduplication by message_norm
- Zero leakage between Train, Val, Test, and Gold
- Per-category cap of 1500 rows in train
- Gold candidate set in data/v2/gold_candidates.csv (columns: id, message_raw, source, proposed_label, final_label)
"""

import os
import re
import csv
import sys
import json
import random
import hashlib
from collections import Counter, defaultdict
from typing import Dict, List, Set, Tuple

SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC_DIR)

from error_normalizer import normalize_for_classifier
from mutate_and_compile import verify_category_from_message
from create_training_dataset import get_curated_cpp_patterns

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MUTATIONS_PATH = os.path.join(BASE_DIR, "data", "v2", "mutations.jsonl")
ORIGINAL_DATA_PATH = os.path.join(BASE_DIR, "data", "training_data_original.json")
MANIFEST_PATH = os.path.join(BASE_DIR, "data", "v2", "manifest.csv")

OUT_DIR = os.path.join(BASE_DIR, "data", "v2")
TRAIN_PATH = os.path.join(OUT_DIR, "train.jsonl")
VAL_PATH = os.path.join(OUT_DIR, "val.jsonl")
TEST_PATH = os.path.join(OUT_DIR, "test.jsonl")
GOLD_PATH = os.path.join(OUT_DIR, "gold_candidates.csv")

CATEGORIES = [
    "syntax_error", "name_resolution", "missing_include",
    "type_error", "return_type_error", "redefinition",
    "access_error", "linker_error", "other"
]

def main():
    random.seed(42)
    print("=== Assembling Dataset V2 (Full 9-Class Coverage) ===")

    # 1. Load Gold candidates and their norms to strictly exclude from train/val/test
    gold_norms = set()
    if os.path.exists(GOLD_PATH):
        with open(GOLD_PATH, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                gold_norms.add(normalize_for_classifier(row["message_raw"]))
    print(f"Gold candidate norms excluded: {len(gold_norms)}")

    # 2. Base programs for 20% held-out test
    base_program_ids = []
    if os.path.exists(MANIFEST_PATH):
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                base_program_ids.append(row["program_id"])
    else:
        base_program_ids = [f"base_custom_{i:02d}" for i in range(1, 46)] + [f"base_algo_{i:03d}" for i in range(1, 111)]

    rng = random.Random(42)
    shuffled_progs = list(base_program_ids)
    rng.shuffle(shuffled_progs)
    n_test_progs = max(1, int(len(shuffled_progs) * 0.20))
    test_program_set = set(shuffled_progs[:n_test_progs])
    train_val_program_set = set(shuffled_progs[n_test_progs:])

    # 3. Ingest Mutations
    mutation_rows = []
    if os.path.exists(MUTATIONS_PATH):
        with open(MUTATIONS_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip(): continue
                try:
                    rec = json.loads(line)
                    raw_msg = rec.get("message_raw", rec.get("message_first_line", ""))
                    norm_msg = normalize_for_classifier(raw_msg)
                    cat = rec.get("category", "")
                    if cat in CATEGORIES and len(norm_msg) > 3:
                        mutation_rows.append({
                            "message_raw": raw_msg,
                            "message_norm": norm_msg,
                            "category": cat,
                            "source": "mutation",
                            "group_id": rec.get("program_id", "unknown_prog")
                        })
                except Exception:
                    pass

    # 4. Ingest CodeNet GCC messages
    codenet_rows = []
    if os.path.exists(ORIGINAL_DATA_PATH):
        with open(ORIGINAL_DATA_PATH, "r", encoding="utf-8") as f:
            raw_orig = json.load(f)
        for item in raw_orig:
            raw_msg = item.get("message", "")
            if not raw_msg or len(raw_msg) < 4: continue
            verified_cat = verify_category_from_message(raw_msg)
            if not verified_cat: continue
            if verified_cat == "other" and not any(flag in raw_msg for flag in ["-W", "division by zero"]):
                continue
            norm_msg = normalize_for_classifier(raw_msg)
            if len(norm_msg) > 3:
                g_id = "codenet_" + hashlib.md5(norm_msg.encode("utf-8")).hexdigest()[:8]
                codenet_rows.append({
                    "message_raw": raw_msg,
                    "message_norm": norm_msg,
                    "category": verified_cat,
                    "source": "codenet_gcc",
                    "group_id": g_id
                })

    # 5. Ingest Curated patterns for linker, return_type, access, and other warning flags
    curated_rows = []
    try:
        raw_curated = get_curated_cpp_patterns()
        for item in raw_curated:
            if isinstance(item, tuple):
                msg_txt, cat_name = item
            elif isinstance(item, dict):
                msg_txt, cat_name = item.get("message", ""), item.get("category", "")
            else:
                continue
            if cat_name in CATEGORIES:
                norm_msg = normalize_for_classifier(msg_txt)
                if len(norm_msg) > 3:
                    curated_rows.append({
                        "message_raw": msg_txt,
                        "message_norm": norm_msg,
                        "category": cat_name,
                        "source": "curated",
                        "group_id": "curated_" + cat_name
                    })
    except Exception as e:
        print(f"Warning loading curated: {e}")

    # Additional genuine warning flags for 'other'
    warning_samples = [
        "warning: comparison between signed and unsigned integer expressions [-Wsign-compare]",
        "warning: suggest parentheses around assignment used as truth value [-Wparentheses]",
        "warning: unused variable '<ID>' [-Wunused-variable]",
        "warning: variable '<ID>' set but not used [-Wunused-but-set-variable]",
        "warning: division by zero [-Wdiv-by-zero]",
        "warning: statement has no effect [-Wunused-value]",
        "warning: '<ID>' is used uninitialized in this function [-Wuninitialized]",
        "warning: suggest braces around empty body in an 'if' statement [-Wempty-body]",
        "warning: unused parameter '<ID>' [-Wunused-parameter]",
        "warning: enumeration value '<ID>' not handled in switch [-Wswitch]",
        "warning: implicit conversion from 'int' to 'char' changes value [-Wconversion]",
        "warning: overflow in implicit constant conversion [-Woverflow]",
        "warning: deprecated conversion from string constant to 'char*' [-Wdeprecated]",
    ]
    for ws in warning_samples:
        curated_rows.append({
            "message_raw": ws,
            "message_norm": normalize_for_classifier(ws),
            "category": "other",
            "source": "curated_warnings",
            "group_id": "curated_other"
        })

    # 6. Deduplicate and partition
    # Hold out test: base programs from test_program_set
    test_rows = []
    test_norms = set()

    for r in mutation_rows:
        if r["group_id"] in test_program_set:
            norm = r["message_norm"]
            if norm not in gold_norms and norm not in test_norms:
                test_rows.append(r)
                test_norms.add(norm)

    # Train / Val pool (exclude test_norms and gold_norms)
    train_val_pool = []
    seen_train_val_norms = set()

    for r in mutation_rows + codenet_rows + curated_rows:
        norm = r["message_norm"]
        if norm in gold_norms or norm in test_norms:
            continue
        if norm not in seen_train_val_norms:
            seen_train_val_norms.add(norm)
            train_val_pool.append(r)

    # Stratified split into Train (85%) and Val (15%) with max 1500 per category in Train
    by_cat_train_val = defaultdict(list)
    for r in train_val_pool:
        by_cat_train_val[r["category"]].append(r)

    train_rows = []
    val_rows = []

    for cat in CATEGORIES:
        pool = by_cat_train_val[cat]
        rng.shuffle(pool)
        n_v = max(2, int(len(pool) * 0.15)) if len(pool) >= 10 else 1
        val_subset = pool[:n_v]
        train_subset = pool[n_v:]
        # Cap train at 1500
        if len(train_subset) > 1500:
            train_subset = train_subset[:1500]
        val_rows.extend(val_subset)
        train_rows.extend(train_subset)

    # Check overlaps
    train_norms = {r["message_norm"] for r in train_rows}
    val_norms = {r["message_norm"] for r in val_rows}
    test_norms_set = {r["message_norm"] for r in test_rows}

    assert len(train_norms & test_norms_set) == 0, "Overlap Train-Test!"
    assert len(train_norms & gold_norms) == 0, "Overlap Train-Gold!"
    assert len(val_norms & test_norms_set) == 0, "Overlap Val-Test!"
    assert len(val_norms & gold_norms) == 0, "Overlap Val-Gold!"

    # Save splits
    for p, r_list in [(TRAIN_PATH, train_rows), (VAL_PATH, val_rows), (TEST_PATH, test_rows)]:
        with open(p, "w", encoding="utf-8") as f:
            for item in r_list:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

    print("\n--- Per-Category Train Counts & Unique Normalized Counts ---")
    train_cat_counts = Counter(r["category"] for r in train_rows)
    for cat in CATEGORIES:
        unique_c = len({r["message_norm"] for r in train_rows if r["category"] == cat})
        flag_str = " [UNDER 30!]" if unique_c < 30 else ""
        print(f"  {cat:20s}: {train_cat_counts[cat]:5d} rows (unique norm: {unique_c:4d}){flag_str}")

    print(f"\nTotal Train rows: {len(train_rows)} | Val rows: {len(val_rows)} | Test rows: {len(test_rows)}")
    print("Dataset assembly complete with full 9-class coverage.")

if __name__ == "__main__":
    main()
