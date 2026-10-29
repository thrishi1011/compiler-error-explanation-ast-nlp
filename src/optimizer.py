"""
optimizer.py
------------
Code optimizer using Groq API and local complexity heuristics.
Analyzes C++ code for algorithmic time & space complexity, identifies bottlenecks,
and generates optimized, secure C++ code.
"""

from __future__ import annotations

import sys
import os
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import json
import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

from complexity_analyzer import scan as local_scan, LocalComplexityEstimate
import llm_client
from guard.output_safe import safe_text


@dataclass
class ComplexityBottleneck:
    line: Optional[int]
    description: str
    severity: str  # "High" | "Medium" | "Low"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OptimizationResult:
    # Complexity
    time_complexity: str
    space_complexity: str
    time_explanation: str
    space_explanation: str
    original_time_complexity: str = ""
    original_space_complexity: str = ""
    bottlenecks: List[ComplexityBottleneck] = field(default_factory=list)

    # Code
    optimized_code: str = ""
    optimizations_applied: List[str] = field(default_factory=list)
    security_preserved: bool = True

    # Meta
    provider: str = "offline"
    model: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["bottlenecks"] = [b.to_dict() if hasattr(b, "to_dict") else b for b in self.bottlenecks]
        return d


SYSTEM_OPTIMIZER_PROMPT = (
    "You are an expert C++ performance optimization engineer and algorithms specialist.\n"
    "Your objective is to optimize the provided C++ code for peak algorithmic efficiency and minimal memory footprint.\n"
    "CRITICAL CONSTRAINTS:\n"
    "1. Preserve ALL existing functionality, inputs/outputs, and algorithmic correctness.\n"
    "2. Preserve ALL security hardening: do NOT reintroduce unsafe functions like strcpy/gets/sprintf, do NOT remove bounds checks, do NOT introduce memory leaks.\n"
    "3. Respond ONLY with a valid JSON object matching the requested schema. Do NOT include markdown code fences or conversational text outside the JSON.\n"
    "4. In the optimized_code, include brief, clear inline C++ comments (// Why: ...) explaining why key lines or structures were modified or added so the user understands the rationale.\n\n"
    "JSON Schema:\n"
    "{\n"
    '  "original_time_complexity": "O(...) for the input code before optimization",\n'
    '  "original_space_complexity": "O(...) for the input code before optimization",\n'
    '  "time_complexity": "O(...) for the optimized code",\n'
    '  "space_complexity": "O(...) for the optimized code",\n'
    '  "time_explanation": "1-2 sentences explaining the time complexity",\n'
    '  "space_explanation": "1-2 sentences explaining the space complexity",\n'
    '  "bottlenecks": [\n'
    '    {"line": 12, "description": "Brief explanation of bottleneck", "severity": "High|Medium|Low"}\n'
    "  ],\n"
    '  "optimized_code": "...full self-contained valid C++ code...",\n'
    '  "optimizations_applied": [\n'
    '    "Replaced nested loop with unordered_map lookup -> O(n²)->O(n)",\n'
    '    "Passed container by const reference to avoid deep copy"\n'
    "  ],\n"
    '  "security_preserved": true\n'
    "}"
)


def _offline_result(
    source_code: str,
    local: LocalComplexityEstimate,
    error_msg: str
) -> OptimizationResult:
    """Builds a fallback result when Groq API is unavailable or returns an error."""
    bottlenecks: List[ComplexityBottleneck] = []
    for s in local.signals:
        sev = "High" if s.get("pattern") in ("loop", "recursion") and s.get("depth", 0) >= 2 else "Medium"
        bottlenecks.append(ComplexityBottleneck(
            line=s.get("line"),
            description=s.get("note", "Potential efficiency bottleneck"),
            severity=sev
        ))

    return OptimizationResult(
        time_complexity=local.time_hint,
        space_complexity=local.space_hint,
        original_time_complexity=local.time_hint,
        original_space_complexity=local.space_hint,
        time_explanation=f"Estimated based on static code structure ({local.confidence} confidence). Connect Groq API for in-depth AI optimization.",
        space_explanation="Estimated based on container usage and allocations.",
        bottlenecks=bottlenecks,
        optimized_code=source_code,  # Return original code unmodified
        optimizations_applied=[],
        security_preserved=True,
        provider="offline",
        model="Static Heuristic",
        error=error_msg,
    )


def analyze(source_code: str) -> OptimizationResult:
    """
    Main entry point for optimizing C++ code.
    Runs local heuristic scan first, then queries Groq API for deep analysis and rewrite.
    Never raises exceptions.
    """
    if not source_code or not source_code.strip():
        return OptimizationResult(
            time_complexity="O(1)",
            space_complexity="O(1)",
            time_explanation="Empty code provided.",
            space_explanation="Empty code provided.",
            bottlenecks=[],
            optimized_code="",
            optimizations_applied=[],
            security_preserved=True,
            provider="offline",
            model="",
            error="No code to analyze"
        )

    # 1. Local static scan
    local_est = local_scan(source_code)

    # 2. Check if Groq key exists
    groq_key = llm_client.get_groq_key()
    if not groq_key:
        return _offline_result(
            source_code,
            local_est,
            "Groq API key not configured. Set GROQ_API_KEY in .env to enable AI code optimization."
        )

    # 3. Build prompt for Groq
    prompt_builder = [
        "// Static Pre-Analysis:",
        f"// Initial Time Complexity Hint: {local_est.time_hint}",
        f"// Initial Space Complexity Hint: {local_est.space_hint}",
        f"// Detected Heuristic Signals: {len(local_est.signals)}",
        "",
        "// Source C++ Code to analyze and optimize:",
        source_code
    ]
    user_prompt = "\n".join(prompt_builder)

    # 4. Invoke LLM via llm_client
    try:
        llm_res = llm_client.ask(
            system=SYSTEM_OPTIMIZER_PROMPT,
            prompt=user_prompt,
            kind="optimize",
            max_tokens=3500,
            code_to_check=source_code
        )
    except Exception as exc:
        return _offline_result(source_code, local_est, f"Optimization query failed: {exc}")

    if not llm_res or not llm_res.text:
        err = llm_res.error if llm_res else "No response from AI provider"
        return _offline_result(source_code, local_est, f"Groq optimization unavailable: {err}")

    # 5. Parse JSON output
    cleaned_text = llm_client.strip_markdown_fences(llm_res.text)
    
    json_match = re.search(r"\{.*\}", cleaned_text, re.DOTALL)
    payload_str = json_match.group(0) if json_match else cleaned_text

    try:
        data = json.loads(payload_str)
    except Exception as parse_err:
        return _offline_result(
            source_code,
            local_est,
            f"Failed to parse optimization response JSON: {parse_err}"
        )

    # 6. Extract fields with fallbacks
    orig_time_comp = str(data.get("original_time_complexity") or local_est.time_hint)
    orig_space_comp = str(data.get("original_space_complexity") or local_est.space_hint)
    time_comp = str(data.get("time_complexity") or local_est.time_hint)
    space_comp = str(data.get("space_complexity") or local_est.space_hint)
    time_expl = str(data.get("time_explanation") or "Time complexity analysis completed.")
    space_expl = str(data.get("space_explanation") or "Space complexity analysis completed.")
    
    raw_bottlenecks = data.get("bottlenecks") or []
    bottlenecks: List[ComplexityBottleneck] = []
    if isinstance(raw_bottlenecks, list):
        for b in raw_bottlenecks:
            if isinstance(b, dict):
                bottlenecks.append(ComplexityBottleneck(
                    line=b.get("line"),
                    description=safe_text(str(b.get("description", "Bottleneck detected"))),
                    severity=str(b.get("severity", "Medium")).capitalize()
                ))

    optimized_code = data.get("optimized_code") or ""
    if not optimized_code.strip():
        optimized_code = source_code

    raw_optimizations = data.get("optimizations_applied") or []
    optimizations_applied: List[str] = []
    if isinstance(raw_optimizations, list):
        for opt in raw_optimizations:
            optimizations_applied.append(safe_text(str(opt)))

    security_preserved = bool(data.get("security_preserved", True))
    model_name = llm_client.get_groq_model()

    return OptimizationResult(
        time_complexity=time_comp,
        space_complexity=space_comp,
        original_time_complexity=orig_time_comp,
        original_space_complexity=orig_space_comp,
        time_explanation=time_expl,
        space_explanation=space_expl,
        bottlenecks=bottlenecks,
        optimized_code=optimized_code,
        optimizations_applied=optimizations_applied,
        security_preserved=security_preserved,
        provider=llm_res.provider or "groq",
        model=model_name,
        error=None
    )
