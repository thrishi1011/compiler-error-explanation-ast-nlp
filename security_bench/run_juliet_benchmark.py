#!/usr/bin/env python3
"""
run_juliet_benchmark.py
=======================
Automated evaluation runner for the curated NIST SARD Juliet C/C++ benchmark suite.
Measures Detection Rate (Recall), False Positive Rate (FPR), Precision, and Auto-Heal Rate.
"""

import os
import sys
import json
import time
import math
from pathlib import Path

# Add src to sys.path
BENCH_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BENCH_DIR.parent
SRC_DIR = PROJECT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import security_analyzer
import security_healer
from guard.models import Finding


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Calculates Wilson score interval for binomial proportions (95% confidence)."""
    if total == 0:
        return 0.0, 1.0
    p = successes / total
    denom = 1 + (z**2) / total
    center = (p + (z**2) / (2 * total)) / denom
    margin = (z / denom) * math.sqrt((p * (1 - p) / total) + (z**2) / (4 * total**2))
    return round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4)


def run_benchmark():
    juliet_dir = BENCH_DIR / "juliet"
    if not juliet_dir.is_dir():
        print(f"Error: Juliet benchmark directory not found at {juliet_dir}")
        return

    bad_files = sorted(list(juliet_dir.glob("**/*_bad.cpp")))
    good_files = sorted(list(juliet_dir.glob("**/*_good.cpp")))

    print("=" * 70)
    print("      NIST SARD Juliet C/C++ Test Suite Evaluation Runner")
    print("=" * 70)
    print(f"Discovered {len(bad_files)} vulnerable test cases and {len(good_files)} compliant test cases.\n")

    # 1. Evaluate Flawed Test Cases (Recall / True Positives)
    tp_count = 0
    healed_count = 0
    results_bad = []

    print("[1/2] Evaluating Vulnerable Test Cases (*_bad.cpp)...", flush=True)
    for bf in bad_files:
        cwe_folder = bf.parent.name
        rel_path = bf.relative_to(juliet_dir).as_posix()
        findings = security_analyzer.analyze(str(bf), [])
        is_detected = len(findings) > 0
        if is_detected:
            tp_count += 1

        # Test healing recipe availability and fix synthesis
        try:
            with open(bf, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
            was_healed = False
            for sf in findings:
                cat = sf.vulnerability_type.lower().replace(" ", "_")
                recipe = security_healer.get_recipe(cat)
                if recipe:
                    dummy_f = Finding(
                        category=cat,
                        severity=sf.severity,
                        title=sf.vulnerability_type,
                        line=sf.line,
                        evidence=sf.description,
                    )
                    fix = recipe.suggest(code, dummy_f) or recipe.apply(code, dummy_f)
                    if fix and (fix.after or fix.new_source):
                        was_healed = True
                        break
        except Exception:
            was_healed = False

        if was_healed:
            healed_count += 1

        detected_cwes = sorted(list({f.cwe_id for f in findings if f.cwe_id}))
        results_bad.append({
            "file": rel_path,
            "cwe_target": cwe_folder.split("_")[0],
            "detected": is_detected,
            "detected_cwes": detected_cwes,
            "healed": was_healed,
        })
        status_icon = "PASS" if is_detected else "FAIL"
        print(f"  [{status_icon}] {rel_path} -> Detected: {is_detected} | CWEs: {detected_cwes} | Healed: {was_healed}", flush=True)

    # 2. Evaluate Compliant Test Cases (False Positives)
    fp_count = 0
    results_good = []

    print("\n[2/2] Evaluating Compliant Baseline Test Cases (*_good.cpp)...", flush=True)
    for gf in good_files:
        rel_path = gf.relative_to(juliet_dir).as_posix()
        findings = security_analyzer.analyze(str(gf), [])
        is_false_alarm = len(findings) > 0
        if is_false_alarm:
            fp_count += 1

        results_good.append({
            "file": rel_path,
            "false_positive": is_false_alarm,
            "findings_count": len(findings),
        })
        status_icon = "CLEAN" if not is_false_alarm else "FALSE_ALERT"
        print(f"  [{status_icon}] {rel_path} -> False Alerts: {len(findings)}", flush=True)

    # Metrics computation
    total_bad = len(bad_files)
    total_good = len(good_files)

    recall = round(tp_count / total_bad, 4) if total_bad > 0 else 0.0
    recall_ci = wilson_interval(tp_count, total_bad)

    fpr = round(fp_count / total_good, 4) if total_good > 0 else 0.0
    fpr_ci = wilson_interval(fp_count, total_good)

    precision = round(tp_count / (tp_count + fp_count), 4) if (tp_count + fp_count) > 0 else 1.0
    heal_rate = round(healed_count / total_bad, 4) if total_bad > 0 else 0.0

    metrics = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_flawed_cases": total_bad,
        "true_positives": tp_count,
        "recall_detection_rate": recall,
        "recall_95ci": recall_ci,
        "total_compliant_cases": total_good,
        "false_positives": fp_count,
        "false_positive_rate": fpr,
        "fpr_95ci": fpr_ci,
        "precision": precision,
        "heal_success_rate": heal_rate,
        "bad_results": results_bad,
        "good_results": results_good,
    }

    out_metrics_file = BENCH_DIR / "juliet_metrics.json"
    with open(out_metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("\n" + "=" * 70)
    print("                     EVALUATION SUMMARY")
    print("=" * 70)
    print(f"Vulnerability Detection Recall: {recall * 100:.1f}% ({tp_count}/{total_bad})  [95% CI: {recall_ci[0]*100:.1f}%, {recall_ci[1]*100:.1f}%]")
    print(f"False Positive Rate (FPR):       {fpr * 100:.1f}% ({fp_count}/{total_good})  [95% CI: {fpr_ci[0]*100:.1f}%, {fpr_ci[1]*100:.1f}%]")
    print(f"Precision:                      {precision * 100:.1f}%")
    print(f"Automated Healing Success Rate: {heal_rate * 100:.1f}% ({healed_count}/{total_bad})")
    print(f"Metrics saved to: {out_metrics_file.name}")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmark()
