"""
optimization_view.py
--------------------
Pure view-model module for the optimization and complexity layer.
No Qt imports. Fully testable in any environment.
Transforms OptimizationResult objects into UI-ready display dictionaries.
"""

from __future__ import annotations

import sys
import os
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import re
from typing import Any, Dict, List, Optional
from guard.output_safe import safe_text


def complexity_tone(big_o: str) -> str:
    """
    Map Big-O string to UI tone: 'ok' | 'warn' | 'error' | 'muted'.
    """
    if not big_o or big_o.lower() in ("unknown", "n/a", "?"):
        return "muted"

    bo = big_o.replace(" ", "").lower()

    if any(k in bo for k in ["o(n!)", "o(2^n)", "o(3^n)", "o(n^3)", "o(n³)", "o(n^4)"]):
        return "error"
    if any(k in bo for k in ["o(n^2)", "o(n²)", "o(n*m)", "o(m*n)"]):
        return "warn"
    if any(k in bo for k in ["o(1)", "o(logn)", "o(log(n))", "o(n)", "o(nlogn)", "o(n*logn)"]):
        return "ok"

    return "muted"


def complexity_badge_label(big_o: str) -> str:
    """
    Returns empty string. Risk/rating labels ('DANGER', 'GOOD', etc.)
    are disabled to display pure Big-O complexity.
    """
    return ""


def build_complexity_summary(result: Any) -> Dict[str, Any]:
    """
    Build a view summary dictionary for time and space complexity.
    Accepts OptimizationResult, LocalComplexityEstimate, or dictionary.
    """
    if hasattr(result, "to_dict"):
        res = result.to_dict()
    elif isinstance(result, dict):
        res = result
    else:
        res = {}

    time_comp = res.get("time_complexity") or res.get("time_hint") or "Unknown"
    space_comp = res.get("space_complexity") or res.get("space_hint") or "Unknown"
    orig_time_comp = res.get("original_time_complexity") or "Unknown"
    orig_space_comp = res.get("original_space_complexity") or "Unknown"
    time_expl = res.get("time_explanation") or "No explanation available."
    space_expl = res.get("space_explanation") or "No explanation available."

    time_tone = complexity_tone(time_comp)
    space_tone = complexity_tone(space_comp)
    orig_time_tone = complexity_tone(orig_time_comp)
    orig_space_tone = complexity_tone(orig_space_comp)

    time_badge = complexity_badge_label(time_comp)
    space_badge = complexity_badge_label(space_comp)
    orig_time_badge = complexity_badge_label(orig_time_comp)
    orig_space_badge = complexity_badge_label(orig_space_comp)

    bottlenecks = res.get("bottlenecks") or res.get("signals") or []
    count = len(bottlenecks)

    headline = f"Time {orig_time_comp} ➔ {time_comp} · Space {orig_space_comp} ➔ {space_comp} · {count} bottleneck{'s' if count != 1 else ''}"

    return {
        "time_complexity": safe_text(time_comp),
        "time_tone": time_tone,
        "time_badge": time_badge,
        "time_explanation": safe_text(time_expl),
        "space_complexity": safe_text(space_comp),
        "space_tone": space_tone,
        "space_badge": space_badge,
        "space_explanation": safe_text(space_expl),
        "original_time_complexity": safe_text(orig_time_comp),
        "original_time_tone": orig_time_tone,
        "original_time_badge": orig_time_badge,
        "original_space_complexity": safe_text(orig_space_comp),
        "original_space_tone": orig_space_tone,
        "original_space_badge": orig_space_badge,
        "bottleneck_count": count,
        "headline": headline,
    }


def build_bottleneck_views(bottlenecks: List[Any]) -> List[Dict[str, Any]]:
    """
    Converts a list of ComplexityBottleneck items into display dictionaries.
    """
    views = []
    for b in bottlenecks or []:
        if hasattr(b, "to_dict"):
            b_dict = b.to_dict()
        elif isinstance(b, dict):
            b_dict = b
        else:
            continue

        sev = str(b_dict.get("severity") or "Medium").capitalize()
        tone = "error" if sev in ("High", "Critical") else ("warn" if sev == "Medium" else "ok")
        line = b_dict.get("line")
        desc = safe_text(str(b_dict.get("description") or b_dict.get("note") or ""))

        views.append({
            "line": line,
            "line_str": f"Line {line}" if line else "General",
            "severity": sev,
            "tone": tone,
            "description": desc
        })

    # Sort critical/high first, then by line
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(views, key=lambda x: (sev_rank.get(x["severity"], 2), x["line"] or 0))


def build_optimization_summary(result: Any) -> Dict[str, Any]:
    """
    Build a view summary dictionary for optimizations applied and security status.
    """
    if hasattr(result, "to_dict"):
        res = result.to_dict()
    elif isinstance(result, dict):
        res = result
    else:
        res = {}

    opt_code = res.get("optimized_code") or ""
    has_code = bool(opt_code.strip())
    opts_applied = [safe_text(str(o)) for o in res.get("optimizations_applied") or []]
    sec_preserved = bool(res.get("security_preserved", True))
    provider = res.get("provider", "offline")
    model = res.get("model", "")

    if provider == "groq":
        provider_label = f"Groq AI ({model})" if model else "Groq AI"
    elif provider == "gemini":
        provider_label = f"Gemini AI ({model})" if model else "Gemini AI"
    else:
        provider_label = "Local Heuristic (Offline)"

    return {
        "has_optimized_code": has_code,
        "optimized_code": opt_code,
        "optimizations_applied": opts_applied,
        "security_preserved": sec_preserved,
        "security_tone": "ok" if sec_preserved else "error",
        "provider": provider,
        "provider_label": provider_label,
        "error": res.get("error")
    }
