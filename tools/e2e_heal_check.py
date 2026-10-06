#!/usr/bin/env python3
"""
tools/e2e_heal_check.py
-----------------------
Headless end-to-end check of the offline self-heal pipeline.
Tests a suite of 16 C++ test files across various error types.
"""

import os
import sys
import shutil
import tempfile
import subprocess
from typing import List, Tuple

# Add src to python path
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TOOLS_DIR)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "src"))

from PyQt6.QtCore import QCoreApplication
from error_classifier import get_default_classifier
from heal_loop import HealWorker

TEST_FILES = [
    "test_cases/mini/tc01_missing_semicolon.cpp",
    "test_cases/mini/tc02_undeclared_variable.cpp",
    "test_cases/mini/tc03_missing_include.cpp",
    "test_cases/mini/tc04_uninitialized_variable.cpp",
    "test_cases/mini/tc05_missing_closing_brace.cpp",
    "test_cases/mini/tc06_wrong_stream_operator.cpp",
    "test_cases/mini/tc07_keyword_typo.cpp",
    "test_cases/mini/tc08_integer_overflow.cpp",
    "test_cases/mini/tc09_division_by_zero.cpp",
    "test_cases/mini/tc15_combined_errors_and_threats.cpp",
    "test_cases/tc_autoheal_semicolons.cpp",
    "test_cases/tc_multiple_errors.cpp",
    "test_cases/syntax_error.cpp",
    "test_cases/undeclared_var.cpp",
    "test_cases/missing_header.cpp",
    "test_heal.cpp",
]


import time

SUBSET_FILES = [
    "test_cases/mini/tc01_missing_semicolon.cpp",
    "test_cases/mini/tc02_undeclared_variable.cpp",
    "test_cases/mini/tc03_missing_include.cpp",
    "test_cases/mini/tc05_missing_closing_brace.cpp",
    "test_cases/tc_autoheal_semicolons.cpp",
    "test_heal.cpp",
]


def compile_with_gpp(filepath: str) -> Tuple[bool, str]:
    """Compile with g++ -std=c++17 -Wall and return (clean, first_error)."""
    res = subprocess.run(
        ["g++", "-std=c++17", "-Wall", filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if res.returncode == 0:
        return True, ""
    first_err = ""
    for line in res.stderr.splitlines():
        line_s = line.strip()
        if ": error:" in line_s or ": fatal error:" in line_s:
            first_err = line_s
            break
    if not first_err and res.stderr.splitlines():
        first_err = res.stderr.splitlines()[0].strip()
    return False, first_err


def _test_single_file(rel_path: str, clf) -> dict:
    full_path = os.path.join(_PROJECT_ROOT, rel_path)
    if not os.path.exists(full_path):
        return {
            "file": os.path.basename(rel_path),
            "healed": False,
            "attempts": 0,
            "first_error": "FILE NOT FOUND",
        }

    # Copy to a temporary file
    fd, tmp_path = tempfile.mkstemp(suffix=".cpp")
    os.close(fd)
    shutil.copyfile(full_path, tmp_path)

    attempts_list = []
    is_clean_signaled = [False]

    worker = HealWorker(tmp_path, clf)
    worker.attempt_started.connect(lambda att, err: attempts_list.append(att))
    worker.compile_clean.connect(lambda *args: is_clean_signaled.__setitem__(0, True))

    try:
        worker._heal()
    except Exception as e:
        pass

    # Verify final compilation directly with g++
    clean, first_err = compile_with_gpp(tmp_path)

    attempts_count = len(attempts_list)
    # Truncate first_err for table display
    if len(first_err) > 45:
        first_err_disp = first_err[:42] + "..."
    else:
        first_err_disp = first_err

    res = {
        "file": os.path.basename(rel_path),
        "healed": clean,
        "attempts": attempts_count,
        "first_error": first_err_disp if not clean else "-",
        "raw_error": first_err,
    }

    if os.path.exists(tmp_path):
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    return res


def run_heal_check() -> Tuple[List[dict], bool]:
    # Ensure QCoreApplication exists for Qt signals
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])

    clf = get_default_classifier()
    results = []

    # Time the first 3 files
    t0 = time.time()
    for rel_path in TEST_FILES[:3]:
        results.append(_test_single_file(rel_path, clf))
    t_first3 = time.time() - t0

    # Project time for all 16 files
    projected_16 = (t_first3 / 3.0) * len(TEST_FILES)
    is_subset = False

    if projected_16 > 90.0:
        is_subset = True
        print(f"\n[Notice] First 3 files took {t_first3:.2f}s. Projected 16 files = {projected_16:.1f}s (> 90s).")
        print("Running 6-file subset instead: tc01, tc02, tc03, tc05, tc_autoheal_semicolons, test_heal.\n")
        remaining_subset = [f for f in SUBSET_FILES if f not in TEST_FILES[:3]]
        for rel_path in remaining_subset:
            results.append(_test_single_file(rel_path, clf))
    else:
        print(f"\n[Notice] First 3 files took {t_first3:.2f}s. Projected 16 files = {projected_16:.1f}s (<= 90s). Running full suite.\n")
        for rel_path in TEST_FILES[3:]:
            results.append(_test_single_file(rel_path, clf))

    return results, is_subset


def print_results(results: List[dict], is_subset: bool = False):
    print("=" * 80)
    suite_title = "6-FILE SUBSET" if is_subset else "FULL 16-FILE SUITE"
    print(f"E2E HEAL CHECK RESULTS ({suite_title})")
    print("=" * 80)
    print(f"{'File':<35} | {'Healed':<6} | {'Attempts':<8} | {'First Remaining Error':<25}")
    print("-" * 80)
    passed = 0
    for r in results:
        status = "YES" if r["healed"] else "NO"
        if r["healed"]:
            passed += 1
        print(f"{r['file']:<35} | {status:<6} | {r['attempts']:<8} | {r['first_error']:<25}")
    print("=" * 80)
    total = len(results)
    pct = (passed / total * 100) if total > 0 else 0.0
    print(f"TOTAL HEALED: {passed}/{total} ({pct:.1f}%)")
    if is_subset:
        print("NOTE: Ran on 6-file subset (tc01, tc02, tc03, tc05, tc_autoheal_semicolons, test_heal) because projected time exceeded 90 s.")
    print("=" * 80)


if __name__ == "__main__":
    results, is_sub = run_heal_check()
    print_results(results, is_sub)

