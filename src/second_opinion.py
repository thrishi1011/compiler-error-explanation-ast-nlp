"""
second_opinion.py
-----------------
Provides a "second opinion" by running two independent classifiers on the same
error message and comparing their predictions.

Method 1 – REGEX classifier  : the lightweight keyword-rule classifier that
                                was already embedded in gui.py (_KeywordClassifier).
                                Moved here so it can be used everywhere.

Method 2 – ML classifier     : the TF-IDF + Logistic-Regression model in
                                error_classifier.py (ErrorClassifier).

When both methods agree on the top category the confidence score is
reported as HIGH and only one answer is shown.

When they disagree the top-N candidates from BOTH methods are surfaced so
the user can see the doubt instead of a silently wrong answer.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


# ── Threshold constants ──────────────────────────────────────────────────────

# If the ML model's confidence is below this level, show all candidates.
LOW_CONFIDENCE_THRESHOLD = 0.55

# Number of alternative candidates to surface when uncertain.
TOP_N = 3


# ── Method 1: Regex / keyword classifier ────────────────────────────────────

class RegexClassifier:
    """
    Lightweight keyword-rule classifier.  No training required, fully offline.
    Returns a ranked list of (category, score) tuples ordered by match quality.
    """

    _RULES: List[Tuple[str, List[str]]] = [
        ("missing_include",   ["'std::", "was not declared", "no member named", "#include"]),
        ("syntax_error",      ["expected ';'", "expected ')'", "expected '{'",
                               "parse error", "stray", "expected '}'"]),
        ("name_resolution",   ["undeclared", "not declared", "undefined", "cannot find",
                               "was not declared in this scope"]),
        ("type_error",        ["cannot convert", "invalid conversion",
                               "no matching function", "incompatible",
                               "invalid operands", "cannot be used as a function"]),
        ("return_type_error", ["return type", "no return", "control reaches end",
                               "missing return"]),
        ("redefinition",      ["redefinition", "already defined", "multiple definition"]),
        ("linker_error",      ["undefined reference", "linker", "ld returned"]),
        ("access_error",      ["is private", "is protected", "inaccessible",
                               "read-only", "assignment of read-only"]),
    ]

    def predict_ranked(self, message: str, ast_node: str = "") -> List[Tuple[str, float]]:
        """
        Returns all matching categories ranked by number of keyword hits,
        with a score in [0.5, 0.95].
        """
        combined = (message + " " + ast_node).lower()
        scores: Dict[str, int] = {}

        for category, keywords in self._RULES:
            hits = sum(1 for kw in keywords if kw.lower() in combined)
            if hits > 0:
                scores[category] = hits

        if not scores:
            return [("other", 0.45)]

        max_hits = max(scores.values())
        ranked = sorted(scores.items(), key=lambda x: -x[1])

        # Normalise hits to a confidence-like score
        result = []
        for cat, hits in ranked:
            score = 0.5 + 0.45 * (hits / max_hits)
            result.append((cat, round(score, 3)))

        return result

    def predict(self, message: str, ast_node: str = "") -> Tuple[Optional[str], float]:
        """Returns the top-1 prediction and its score."""
        ranked = self.predict_ranked(message, ast_node)
        return ranked[0] if ranked else ("other", 0.45)


# Singleton so callers don't pay construction cost twice.
_default_regex_clf: Optional[RegexClassifier] = None


def get_regex_classifier() -> RegexClassifier:
    global _default_regex_clf
    if _default_regex_clf is None:
        _default_regex_clf = RegexClassifier()
    return _default_regex_clf


# ── Combined second-opinion logic ────────────────────────────────────────────

class SecondOpinionResult:
    """
    Holds the full comparison between the two classifiers.

    Attributes
    ----------
    agreed : bool
        True when both classifiers chose the same top category.
    final_category : str
        The category to use (top choice, or "uncertain" when they disagree
        and confidence is below threshold).
    final_confidence : float
        Blended confidence score.
    regex_top : str
        Top prediction from the regex classifier.
    regex_score : float
        Regex classifier's confidence.
    ml_top : str | None
        Top prediction from the ML classifier (None if model unavailable).
    ml_score : float
        ML classifier's confidence.
    candidates : list[dict]
        When uncertain, a list of {"category": ..., "regex_score": ...,
        "ml_score": ..., "blended": ...} dicts for the top-N options.
    note : str
        Human-readable note describing the agreement state.
    """

    def __init__(self):
        self.agreed: bool = False
        self.final_category: str = "other"
        self.final_confidence: float = 0.0
        self.regex_top: str = "other"
        self.regex_score: float = 0.0
        self.ml_top: Optional[str] = None
        self.ml_score: float = 0.0
        self.candidates: List[Dict] = []
        self.note: str = ""


def get_second_opinion(message: str, ast_node: str = "") -> SecondOpinionResult:
    """
    Run both classifiers and compare results.

    Parameters
    ----------
    message  : The raw compiler error message string.
    ast_node : Optional AST context (may be empty string).

    Returns
    -------
    SecondOpinionResult with full comparison details.
    """
    result = SecondOpinionResult()

    # ── Method 1: Regex ──────────────────────────────────────────────────────
    regex_clf = get_regex_classifier()
    regex_ranked = regex_clf.predict_ranked(message, ast_node)
    result.regex_top, result.regex_score = regex_ranked[0]

    # ── Method 2: ML model (lazy import to avoid hard dependency) ────────────
    ml_ranked: List[Tuple[str, float]] = []
    try:
        from error_classifier import get_default_classifier
        ml_clf = get_default_classifier()
        ml_top, ml_conf = ml_clf.predict(message, ast_node=ast_node)
        if ml_top and ml_conf > 0:
            result.ml_top = ml_top
            result.ml_score = ml_conf
            ml_ranked = [(ml_top, ml_conf)]
            # Try to get additional probabilities if available
            try:
                feature_str = f"{ast_node} {message}".strip()
                if ml_clf._pipeline is not None:
                    proba = ml_clf._pipeline.predict_proba([feature_str])[0]
                    classes = ml_clf._pipeline.classes_
                    ml_ranked = sorted(
                        zip(classes, proba), key=lambda x: -x[1]
                    )[:TOP_N]
            except Exception:
                pass
    except Exception:
        result.ml_top = None
        result.ml_score = 0.0

    # ── Agreement check ──────────────────────────────────────────────────────
    if result.ml_top is not None:
        # Both methods are available
        if result.regex_top == result.ml_top:
            # Full agreement
            result.agreed = True
            # Blend: give more weight to ML when available
            result.final_confidence = round(
                0.35 * result.regex_score + 0.65 * result.ml_score, 3
            )
            result.final_category = result.ml_top
            result.note = (
                f"Both methods agree: {result.final_category} "
                f"(confidence {result.final_confidence:.0%})"
            )
        else:
            # Disagreement — surface candidates
            result.agreed = False

            # Build a unified candidate list
            regex_dict = {cat: score for cat, score in regex_ranked[:TOP_N]}
            ml_dict = {cat: score for cat, score in ml_ranked}

            all_cats = set(regex_dict) | set(ml_dict)
            candidates = []
            for cat in all_cats:
                r_score = regex_dict.get(cat, 0.0)
                m_score = ml_dict.get(cat, 0.0)
                # Blended: prefer ML when available
                blended = round(
                    (0.35 * r_score + 0.65 * m_score)
                    if m_score > 0
                    else (0.5 * r_score),
                    3,
                )
                candidates.append(
                    {"category": cat, "regex_score": r_score,
                     "ml_score": m_score, "blended": blended}
                )

            candidates.sort(key=lambda x: -x["blended"])
            result.candidates = candidates[:TOP_N]

            # Pick winner from blended ranking
            result.final_category = result.candidates[0]["category"]
            result.final_confidence = result.candidates[0]["blended"]

            result.note = (
                f"Methods disagree — regex says '{result.regex_top}', "
                f"ML says '{result.ml_top}'. Showing top options."
            )
    else:
        # ML unavailable — fall back to regex only, but mark as uncertain
        result.agreed = True  # Only one method available; no "disagreement"
        result.final_category = result.regex_top
        result.final_confidence = result.regex_score
        result.note = (
            f"ML model not available. Regex classifier: {result.regex_top} "
            f"(confidence {result.regex_score:.0%})"
        )

    return result


def format_second_opinion(result: SecondOpinionResult) -> str:
    """
    Return a human-readable string suitable for printing to the terminal
    or embedding in the GUI explanation panel.
    """
    lines = ["-- Second Opinion ------------------------------------------"]

    if result.ml_top is not None:
        lines.append(
            f"  Regex classifier : {result.regex_top:<22}  "
            f"({result.regex_score:.0%})"
        )
        lines.append(
            f"  ML classifier    : {result.ml_top:<22}  "
            f"({result.ml_score:.0%})"
        )
    else:
        lines.append(f"  Regex classifier : {result.regex_top}  ({result.regex_score:.0%})")
        lines.append("  ML classifier    : not available")

    lines.append("")
    lines.append(f"  Verdict : {result.note}")

    if not result.agreed and result.candidates:
        lines.append("")
        lines.append("  Top candidates (blended score):")
        for i, c in enumerate(result.candidates, 1):
            lines.append(
                f"    {i}. {c['category']:<22}  {c['blended']:.0%}"
            )

    lines.append("----------------------------------------------------")
    return "\n".join(lines)
