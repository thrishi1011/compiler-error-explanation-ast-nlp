"""
accuracy_benchmark.py
---------------------
Feature 4 – Measured accuracy.

Runs every labelled test file through THREE methods and produces a side-by-side
accuracy table:

  Method A – Regex-only          (RegexClassifier from second_opinion.py)
  Method B – ML-only             (ErrorClassifier from error_classifier.py)
  Method C – Combined            (second_opinion.get_second_opinion → final_category)

The benchmark is fully offline: it calls the system g++ compiler and the local
sklearn model; no internet access is required.

Usage (command line):
    python accuracy_benchmark.py

Usage (from Python):
    from accuracy_benchmark import run_benchmark
    results = run_benchmark()   # returns dict with all data

Usage (GUI):
    from accuracy_benchmark import BenchmarkWorker   # QThread subclass
    worker = BenchmarkWorker()
    worker.progress.connect(...)
    worker.finished.connect(...)
    worker.start()
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

# ── Project layout helpers ────────────────────────────────────────────────────
_SRC_DIR     = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SRC_DIR)
_TEST_DIR     = os.path.join(_PROJECT_ROOT, "test_cases")

# Ground-truth labels (identical to build_dataset_from_tests.py so we do not
# duplicate them in two places; import if available, else define locally).
try:
    import sys as _sys
    _sys.path.insert(0, _SRC_DIR)
    from build_dataset_from_tests import FILE_LABELS as _FILE_LABELS_RAW
    FILE_LABELS: Dict[str, Optional[str]] = dict(_FILE_LABELS_RAW)
except Exception:
    # Fallback: minimal inline copy so the module is self-contained.
    FILE_LABELS = {
        "syntax_error.cpp":          "syntax_error",
        "missing_brace.cpp":         "syntax_error",
        "break_outside_loop.cpp":    "syntax_error",
        "continue_outside_loop.cpp": "syntax_error",
        "wrong_main_signature.cpp":  "syntax_error",
        "undeclared_var.cpp":        "name_resolution",
        "missing_header.cpp":        "missing_include",
        "no_matching_function.cpp":  "type_error",
        "function_mismatch.cpp":     "type_error",
        "type_error.cpp":            "type_error",
        "invalid_operands.cpp":      "type_error",
        "invalid_cast.cpp":          "type_error",
        "invalid_array_index.cpp":   "type_error",
        "invalid_use_of_void.cpp":   "type_error",
        "signed_unsigned_compare.cpp": "type_error",
        "sizeof_function.cpp":       "type_error",
        "pointer_misuse.cpp":        "type_error",
        "invalid_return_type.cpp":   "return_type_error",
        "missing_return.cpp":        "return_type_error",
        "redefination.cpp":          "redefinition",
        "multiple_definition.cpp":   "redefinition",
        "const_assignment.cpp":      "access_error",
        "null_dereference.cpp":      "other",
        "success.cpp":               None,
    }

_ERR_PATTERN = re.compile(
    r"^.+?:\d+(?::\d+)?:\s*(error|warning):\s*(.*)$"
)


# ── Compiler helper ──────────────────────────────────────────────────────────

def _extract_messages(fpath: str) -> List[str]:
    """Compile a .cpp file and return all error/warning message strings."""
    try:
        result = subprocess.run(
            ["g++", "-std=c++17", "-Wall", fpath],
            capture_output=True, text=True, timeout=15
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    messages = []
    for line in result.stderr.splitlines():
        m = _ERR_PATTERN.match(line.strip())
        if m:
            messages.append(m.group(2).strip())
    return messages


def _majority(predictions: List[str]) -> str:
    """Return the most-common prediction; 'other' if empty."""
    if not predictions:
        return "other"
    counts: Dict[str, int] = {}
    for p in predictions:
        counts[p] = counts.get(p, 0) + 1
    return max(counts, key=lambda k: counts[k])


# ── Per-row result ────────────────────────────────────────────────────────────

class FileResult:
    """Holds benchmark results for one test file."""

    def __init__(self, filename: str, expected: str):
        self.filename  = filename
        self.expected  = expected
        self.regex_pred: str = "other"
        self.ml_pred:   str = "other"
        self.combo_pred: str = "other"
        self.regex_ok:  bool = False
        self.ml_ok:     bool = False
        self.combo_ok:  bool = False
        self.messages:  List[str] = []

    @property
    def any_ok(self) -> bool:
        return self.regex_ok or self.ml_ok or self.combo_ok


# ── Main benchmark function ───────────────────────────────────────────────────

def run_benchmark(
    test_dir: str = _TEST_DIR,
    progress_callback=None,
) -> dict:
    """
    Run the full three-method benchmark.

    Parameters
    ----------
    test_dir          : Directory containing the .cpp test files.
    progress_callback : Optional callable(int, int, str) — (done, total, filename).

    Returns
    -------
    dict with keys:
        rows          : list[FileResult]
        total         : int
        regex_correct : int
        ml_correct    : int
        combo_correct : int
        regex_pct     : float
        ml_pct        : float
        combo_pct     : float
        per_category  : dict[str, {"regex": int, "ml": int, "combo": int, "total": int}]
    """
    from second_opinion import get_regex_classifier, get_second_opinion

    # Lazy-load ML classifier (may not be trained yet)
    ml_clf = None
    try:
        from error_classifier import get_default_classifier
        ml_clf = get_default_classifier()
        # Trigger train if model file exists but pipeline not loaded
        ml_clf.load()
    except Exception:
        ml_clf = None

    regex_clf = get_regex_classifier()

    labelled = [
        (fname, label)
        for fname, label in FILE_LABELS.items()
        if label is not None
    ]
    total = len(labelled)
    rows: List[FileResult] = []

    regex_correct = ml_correct = combo_correct = 0
    per_category: Dict[str, Dict[str, int]] = {}

    for idx, (fname, expected) in enumerate(labelled):
        if progress_callback:
            progress_callback(idx, total, fname)

        fpath = os.path.join(test_dir, fname)
        row = FileResult(fname, expected)

        if not os.path.exists(fpath):
            # File not found — count as wrong for all methods
            rows.append(row)
            _update_per_cat(per_category, expected, False, False, False)
            continue

        messages = _extract_messages(fpath)
        row.messages = messages

        if not messages:
            # File compiled cleanly or g++ not found
            rows.append(row)
            _update_per_cat(per_category, expected, False, False, False)
            continue

        # ── Method A: regex (vote across all messages) ────────────────────
        regex_preds = [regex_clf.predict(msg)[0] for msg in messages]
        row.regex_pred = _majority(regex_preds)
        row.regex_ok   = (row.regex_pred == expected)

        # ── Method B: ML model ────────────────────────────────────────────
        if ml_clf is not None:
            ml_preds = []
            for msg in messages:
                pred, _ = ml_clf.predict(msg)
                if pred:
                    ml_preds.append(pred)
            row.ml_pred = _majority(ml_preds)
        else:
            row.ml_pred = "unavailable"
        row.ml_ok = (row.ml_pred == expected)

        # ── Method C: combined second-opinion ─────────────────────────────
        combo_preds = []
        for msg in messages:
            opinion = get_second_opinion(msg)
            combo_preds.append(opinion.final_category)
        row.combo_pred = _majority(combo_preds)
        row.combo_ok   = (row.combo_pred == expected)

        if row.regex_ok:  regex_correct  += 1
        if row.ml_ok:     ml_correct     += 1
        if row.combo_ok:  combo_correct  += 1

        _update_per_cat(per_category, expected,
                        row.regex_ok, row.ml_ok, row.combo_ok)
        rows.append(row)

    if progress_callback:
        progress_callback(total, total, "done")

    def pct(n: int) -> float:
        return round(100.0 * n / total, 1) if total else 0.0

    return {
        "rows":           rows,
        "total":          total,
        "regex_correct":  regex_correct,
        "ml_correct":     ml_correct,
        "combo_correct":  combo_correct,
        "regex_pct":      pct(regex_correct),
        "ml_pct":         pct(ml_correct),
        "combo_pct":      pct(combo_correct),
        "per_category":   per_category,
    }


def _update_per_cat(
    per_cat: dict, expected: str,
    regex_ok: bool, ml_ok: bool, combo_ok: bool
) -> None:
    if expected not in per_cat:
        per_cat[expected] = {"regex": 0, "ml": 0, "combo": 0, "total": 0}
    per_cat[expected]["total"] += 1
    if regex_ok:  per_cat[expected]["regex"]  += 1
    if ml_ok:     per_cat[expected]["ml"]     += 1
    if combo_ok:  per_cat[expected]["combo"]  += 1


# ── QThread wrapper for the GUI ───────────────────────────────────────────────

try:
    from PyQt6.QtCore import QThread, pyqtSignal

    class BenchmarkWorker(QThread):
        """
        Run the benchmark in a background thread so the GUI stays responsive.

        Signals
        -------
        progress(done: int, total: int, filename: str)
        finished(results: dict)
        """
        progress = pyqtSignal(int, int, str)
        finished = pyqtSignal(dict)

        def run(self):
            results = run_benchmark(
                progress_callback=lambda done, total, fname:
                    self.progress.emit(done, total, fname)
            )
            self.finished.emit(results)

except ImportError:
    # PyQt6 not available (e.g. when running from command line only)
    BenchmarkWorker = None  # type: ignore


# ── CLI entry point ───────────────────────────────────────────────────────────

def _print_table(results: dict) -> None:
    rows      = results["rows"]
    total     = results["total"]
    SEP       = "-" * 82

    print("\n" + "=" * 82)
    print("  ACCURACY BENCHMARK  --  Three-Method Comparison")
    print("=" * 82)
    print(f"  {'File':<35} {'Expected':<20} {'Regex':^7} {'ML':^7} {'Combined':^9}")
    print(SEP)

    for row in rows:
        r = "OK" if row.regex_ok else "XX"
        m = "OK" if row.ml_ok   else ("--" if row.ml_pred == "unavailable" else "XX")
        c = "OK" if row.combo_ok else "XX"
        print(f"  {row.filename:<35} {row.expected:<20} {r:^7} {m:^7} {c:^9}")

    print(SEP)
    print(f"  {'TOTAL CORRECT':<35} {total} files"
          f"     {results['regex_correct']:^7} {results['ml_correct']:^7} {results['combo_correct']:^9}")
    print(f"  {'ACCURACY %':<35}"
          f"          {results['regex_pct']:>5.1f}%  {results['ml_pct']:>5.1f}%  "
          f"{results['combo_pct']:>7.1f}%")
    print("=" * 82)

    print("\n  Per-category breakdown:")
    print(f"  {'Category':<22} {'Regex':^12} {'ML':^12} {'Combined':^12}")
    print("  " + "-" * 60)
    for cat, counts in sorted(results["per_category"].items()):
        t = counts["total"]
        r = f"{counts['regex']}/{t}"
        m = f"{counts['ml']}/{t}"
        c = f"{counts['combo']}/{t}"
        print(f"  {cat:<22} {r:^12} {m:^12} {c:^12}")
    print()


if __name__ == "__main__":
    print("Running accuracy benchmark …  (this may take ~30 s)")
    results = run_benchmark()
    _print_table(results)
