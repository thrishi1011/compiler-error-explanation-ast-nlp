import json
import os
import re
import warnings
from collections import Counter
from typing import Optional, Tuple, List

# Suppress sklearn unpickling version warnings
warnings.filterwarnings("ignore", message=r".*unpickle estimator.*")
warnings.filterwarnings("ignore", message=r".*InconsistentVersionWarning.*")
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.utils.class_weight import compute_class_weight
import numpy as np


_PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
_DEFAULT_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
_DEFAULT_TRAINING_DATA_FILE = os.path.join(_DEFAULT_DATA_DIR, "training_data.json")
_DEFAULT_MODEL_FILE = os.path.join(_DEFAULT_DATA_DIR, "error_classifier.joblib")

# ── Module-level singleton for cheap repeated access ─────────────────────────
_default_clf_instance: Optional["ErrorClassifier"] = None

def get_default_classifier() -> "ErrorClassifier":
    """
    Return a module-level singleton ErrorClassifier.
    Loads the saved model on first call; trains if the model file is missing.
    """
    global _default_clf_instance
    if _default_clf_instance is None:
        _default_clf_instance = ErrorClassifier()
        try:
            _default_clf_instance.load()
        except Exception:
            # Model not trained yet — the instance still works via fallback
            pass
    return _default_clf_instance


# ── Canonical category set ────────────────────────────────────────────────────
# Covers both old labels and new codenet labels.
# Aliases map legacy/variant spellings → canonical name.
CATEGORY_ALIASES = {
    # old names → new canonical names
    "name_resolution":  "name_resolution",
    "function_error":   "type_error",        # function call mismatch is a type issue
    "linker_error":     "linker_error",
    "warning":          "other",

    # new codenet names (already canonical)
    "syntax_error":     "syntax_error",
    "type_error":       "type_error",
    "missing_include":  "missing_include",
    "redefinition":     "redefinition",
    "access_error":     "access_error",
    "return_type_error":"return_type_error",
    "unused_variable":  "unused_variable",
    "other":            "other",
}

ALL_CATEGORIES = list(dict.fromkeys(CATEGORY_ALIASES.values()))  # ordered, deduplicated


def _normalize_category(cat: str) -> str:
    return CATEGORY_ALIASES.get(cat.strip().lower(), "other")


def _load_training_examples(training_data_file: str) -> Tuple[List[str], List[str]]:
    with open(training_data_file, "r") as f:
        raw = json.load(f)

    messages: List[str] = []
    labels:   List[str] = []

    if not isinstance(raw, list):
        return messages, labels

    for row in raw:
        if not isinstance(row, dict):
            continue
        msg = row.get("message") or row.get("raw_message")
        cat = row.get("category")
        ast = row.get("ast_node", "")
        if not msg or not cat:
            continue

        cat = _normalize_category(cat)
        feature_str = f"{ast} {msg}".strip()
        messages.append(feature_str)
        labels.append(cat)

    return messages, labels


def _check_imbalance(labels: List[str]) -> dict:
    """Return a dict of category -> count and print a warning for severe imbalance."""
    counts = Counter(labels)
    total  = len(labels)
    print(f"\n[Classifier] Class distribution ({total} samples):")
    for cat in sorted(counts, key=lambda c: -counts[c]):
        pct = 100 * counts[cat] / total
        bar = "#" * int(pct / 2)
        print(f"  {cat:<25} {counts[cat]:>5}  ({pct:5.1f}%) {bar}")

    majority = max(counts.values())
    minority = min(counts.values())
    ratio    = majority / minority if minority else float("inf")
    if ratio > 10:
        print(f"\n  [WARN] Imbalance ratio {ratio:.1f}x - class_weight='balanced' will be applied.")
    else:
        print(f"\n  [OK] Imbalance ratio {ratio:.1f}x - acceptable.")
    return dict(counts)


class ErrorClassifier:
    def __init__(
        self,
        model_file: str = _DEFAULT_MODEL_FILE,
        training_data_file: str = _DEFAULT_TRAINING_DATA_FILE,
    ) -> None:
        self.model_file         = model_file
        self.training_data_file = training_data_file
        self._pipeline: Optional[Pipeline] = None
        self.last_load_error: Optional[str] = None

    def is_trained(self) -> bool:
        return self._pipeline is not None or os.path.exists(self.model_file)

    def train(self) -> None:
        if not os.path.exists(self.training_data_file):
            raise FileNotFoundError(f"Training data not found: {self.training_data_file}")

        X, y = _load_training_examples(self.training_data_file)
        if len(X) < 2:
            raise ValueError("Not enough training examples to train classifier.")

        _check_imbalance(y)

        pipeline = Pipeline(
            steps=[
                (
                    "features",
                    FeatureUnion([
                        (
                            "word",
                            TfidfVectorizer(
                                lowercase=True,
                                ngram_range=(1, 3),
                                min_df=1,           # allow rare categories with 1 example
                                max_df=0.95,
                                token_pattern=r"(?u)\b\w+\b|[;{}()\[\]+-/*=<>]"
                            ),
                        ),
                        (
                            "char",
                            TfidfVectorizer(
                                analyzer="char",
                                ngram_range=(3, 5),
                                min_df=1,
                                max_df=0.95,
                            ),
                        ),
                    ])
                ),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=2000,
                        class_weight="balanced",  # handles imbalance automatically
                        solver="lbfgs",
                        C=1.0,
                    ),
                ),
            ]
        )

        pipeline.fit(X, y)
        self._pipeline = pipeline
        print(f"[Classifier] Trained on {len(X)} examples across {len(set(y))} categories.")

    def save(self) -> None:
        if self._pipeline is None:
            raise ValueError("No trained model in memory to save.")
        os.makedirs(os.path.dirname(self.model_file), exist_ok=True)
        joblib.dump(self._pipeline, self.model_file)
        print(f"[Classifier] Model saved -> {self.model_file}")

    def load(self) -> bool:
        if self._pipeline is not None:
            return True
        if not os.path.exists(self.model_file):
            self.last_load_error = f"Model file not found: {self.model_file}"
            return False

        try:
            from guard.models import InputKind
            from guard.supervisor import review
            from guard.attack_log import log_event
            verdict = review(InputKind.MODEL_FILE, self.model_file, purpose="model_load")
            if verdict.blocked:
                blocked_findings = [
                    f for f in verdict.findings
                    if f.action == "block" or (f.blocks_on and "model_load" in f.blocks_on)
                ]
                cat = blocked_findings[0].category if blocked_findings else "integrity_error"
                desc = blocked_findings[0].description if blocked_findings else "Integrity check failed"
                self.last_load_error = f"Model file rejected: {cat}. {desc}"
                print(f"Model file rejected: {cat}. If you replaced the model on purpose, run: python tools/sign_model.py")
                log_event("model_rejected", {
                    "category": cat,
                    "model_file": self.model_file,
                    "findings": [f.to_dict() for f in verdict.findings],
                })
                return False
        except Exception as e:
            self.last_load_error = f"Guard check failed: {e}"
            return False

        self._pipeline = joblib.load(self.model_file)
        self.last_load_error = None
        return True

    def train_and_save(self) -> None:
        self.train()
        self.save()

    def predict(self, message: str, ast_node: str = "") -> Tuple[Optional[str], float]:
        if not message:
            return None, 0.0

        lowered = message.lower()
        if "a function-definition is not allowed here" in lowered:
            return "missing_closing_brace", 1.0
            
        if any(phrase in lowered for phrase in (
            "used uninitialized",
            "may be used uninitialized",
            "is uninitialized when used here",
            "uninitialized when used here",
            "wuninitialized",
            "uninitialized variable",
        )):
            return "uninitialized_memory", 0.98
        if any(phrase in lowered for phrase in (
            "set but not used",
            "unused variable",
            "unused but set variable",
            "declared but never used",
            "-wunused-but-set-variable",
            "-wunused-variable",
        )):
            return "unused_variable", 0.98

        # ── Deterministic rules for real compiler diagnostics ──
        # Missing headers
        if "no such file or directory" in lowered:
            return "missing_include", 0.99

        # Standard library missing headers vs local undeclared identifier
        if "was not declared in this scope" in lowered or "undeclared identifier" in lowered:
            # Extract identifier name in quotes
            sym_match = re.search(r"['‘]([a-zA-Z_]\w*)['’]", message)
            if sym_match:
                sym = sym_match.group(1)
                std_syms = {
                    "cout", "cin", "cerr", "endl", "string", "vector", "map", "set",
                    "unordered_map", "unordered_set", "list", "queue", "stack", "deque", "array",
                    "pair", "tuple", "sort", "find", "max", "min", "reverse", "count",
                    "fill", "copy", "abs", "sqrt", "pow", "ceil", "floor",
                    "unique_ptr", "shared_ptr", "make_unique", "make_shared",
                    "strlen", "strcpy", "strcmp", "strcat", "memset", "memcpy", "memmove",
                    "printf", "scanf", "fprintf", "puts", "fopen", "fclose", "sprintf", "snprintf",
                    "INT_MAX", "INT_MIN", "size_t"
                }
                if sym in std_syms or sym.startswith("std::"):
                    return "missing_include", 0.99
            if any(f"'{s}'" in lowered for s in ("cout", "cin", "vector", "string", "endl", "sort", "printf", "strlen")):
                return "missing_include", 0.99
            return "name_resolution", 0.99

        if any(phrase in lowered for phrase in ("has not been declared", "does not name a type")):
            return "name_resolution", 0.95

        # Syntax / control-flow / conditionals
        if any(phrase in lowered for phrase in (
            "expected ';'", "expected ')'", "expected '}'", "expected '{'", "expected ']'",
            "expected primary-expression", "expected unqualified-id", "expected initializer",
            "stray ", "missing terminating", "break statement not within", "continue statement not within",
            "assignment used as truth value", "suggest parentheses around assignment", "parentheses around assignment"
        )):
            return "syntax_error", 0.99

        # Unused variables / parameters
        if any(phrase in lowered for phrase in (
            "unused variable", "unused parameter", "set but not used", "unused but set"
        )):
            return "unused_variable", 0.99

        # Type errors, casts, operands, arrays, sizeof
        if any(phrase in lowered for phrase in (
            "array subscript is not an integer", "subscripted value is not an array",
            "invalid operands of types", "invalid cast from type", "cannot convert",
            "invalid conversion", "incompatible types", "static_cast", "reinterpret_cast",
            "invalid use of void", "sizeof' to a function", "no matching function for call",
            "no matching constructor", "template deduction", "cannot bind non-const lvalue"
        )):
            return "type_error", 0.99

        # Access / Const
        if any(phrase in lowered for phrase in (
            "assignment of read-only", "is private within this context", "is protected"
        )):
            return "access_error", 0.99

        # Redefinition / multiple definition
        if any(phrase in lowered for phrase in (
            "redefinition of", "multiple definition of", "previous definition of", "conflicting declaration"
        )):
            return "redefinition", 0.99

        # Return type
        if any(phrase in lowered for phrase in (
            "return-statement with a value, in function returning 'void'",
            "return-statement with no value, in function returning",
            "no return statement in function returning non-void",
            "control reaches end of non-void function"
        )):
            return "return_type_error", 0.99

        if not self.load():
            if os.environ.get("ALLOW_AUTO_TRAIN") == "1":
                if os.path.exists(self.training_data_file):
                    try:
                        self.train_and_save()
                    except Exception:
                        return None, 0.0
                if not self.load():
                    return None, 0.0
            else:
                try:
                    from guard.attack_log import log_event
                    log_event("model_unavailable", {
                        "model_file": self.model_file,
                        "error": self.last_load_error or "Model not loaded",
                    })
                except Exception:
                    pass
                return None, 0.0

        assert self._pipeline is not None

        from error_normalizer import normalize_for_classifier
        feature_str = normalize_for_classifier(message)
        try:
            proba = self._pipeline.predict_proba([feature_str])
            idx   = int(proba[0].argmax())
            pred  = self._pipeline.classes_[idx]
            conf  = float(proba[0].max())
            return str(pred), conf
        except Exception:
            pred = self._pipeline.predict([feature_str])[0]
            return str(pred), 0.5

    def predict_ml_only(self, message: str, ast_node: str = "") -> Tuple[Optional[str], float]:
        """
        Pure ML prediction bypassing rule fast-paths (for honest ML evaluation).
        """
        if not message:
            return None, 0.0
        if not self.load():
            return None, 0.0
        assert self._pipeline is not None

        from error_normalizer import normalize_for_classifier
        feature_str = normalize_for_classifier(message)
        try:
            proba = self._pipeline.predict_proba([feature_str])
            idx   = int(proba[0].argmax())
            pred  = self._pipeline.classes_[idx]
            conf  = float(proba[0].max())
            return str(pred), conf
        except Exception:
            pred = self._pipeline.predict([feature_str])[0]
            return str(pred), 0.5

    def evaluate_on_tests(self, test_dir: str) -> dict:
        """
        Compile every .cpp in test_dir, predict its category, and report
        accuracy per category.  Ground-truth labels come from build_dataset_from_tests.py.
        """
        import subprocess, re

        # Import label map from the builder (avoid duplication)
        sys_path_backup = list(__import__("sys").path)
        __import__("sys").path.insert(0, os.path.dirname(__file__))
        from build_dataset_from_tests import FILE_LABELS, ERROR_PATTERN  # type: ignore

        results = {}   # category → {correct, total}
        detail  = []

        for fname, expected_cat in FILE_LABELS.items():
            if expected_cat is None:
                continue
            fpath = os.path.join(test_dir, fname)
            if not os.path.exists(fpath):
                continue

            result = subprocess.run(
                ["g++", "-std=c++17", "-Wall", fpath],
                capture_output=True, text=True
            )
            predicted_cats = []
            for line in result.stderr.splitlines():
                m = re.match(
                    r"^.+?:\d+(?::\d+)?:\s*(error|warning):\s*(.*)$",
                    line.strip()
                )
                if m:
                    msg = m.group(2).strip()
                    pred, conf = self.predict(msg)
                    if pred:
                        predicted_cats.append(pred)

            # Use majority vote across all errors in the file
            predicted = Counter(predicted_cats).most_common(1)[0][0] if predicted_cats else "other"
            correct   = (predicted == expected_cat)

            if expected_cat not in results:
                results[expected_cat] = {"correct": 0, "total": 0}
            results[expected_cat]["total"]   += 1
            results[expected_cat]["correct"] += int(correct)
            detail.append((fname, expected_cat, predicted, "OK" if correct else "XX"))

        # Print report
        print("\n" + "=" * 62)
        print("  CLASSIFIER ACCURACY REPORT -- per category")
        print("=" * 62)
        print(f"  {'File':<35} {'Expected':<22} {'Predicted':<22} {'OK'}")
        print("-" * 62)
        for fname, exp, pred, mark in detail:
            print(f"  {fname:<35} {exp:<22} {pred:<22} {mark}")

        print("\n" + "-" * 62)
        total_correct = total_files = 0
        for cat, r in sorted(results.items()):
            acc = 100 * r["correct"] / r["total"]
            total_correct += r["correct"]
            total_files   += r["total"]
            print(f"  {cat:<25}  {r['correct']}/{r['total']}  ({acc:.0f}%)")

        overall = 100 * total_correct / total_files if total_files else 0
        print("-" * 62)
        print(f"  {'OVERALL':<25}  {total_correct}/{total_files}  ({overall:.0f}%)")
        print("=" * 62 + "\n")

        return results


_default_classifier: Optional[ErrorClassifier] = None


def get_default_classifier() -> ErrorClassifier:
    global _default_classifier
    if _default_classifier is None:
        _default_classifier = ErrorClassifier()
    return _default_classifier


def predict_error_category(error_message: str) -> str:
    """Legacy fallback."""
    return "unknown"


if __name__ == "__main__":
    import sys
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    TEST_DIR     = os.path.join(PROJECT_ROOT, "test_cases")

    print("\nTraining classifier on data/training_data.json...")
    clf = ErrorClassifier()
    clf.train_and_save()

    print("\nEvaluating on test cases...")
    clf.evaluate_on_tests(TEST_DIR)
