"""
src/guard/benchmark.py
----------------------
Deterministic benchmark execution engine evaluating detection, attribution,
prevention, false positives, routing efficiency, latency, and security healing.
"""

from __future__ import annotations

import csv
import difflib
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .base import GuardContext
from .config import MAX_SCAN_BYTES
from .models import Finding, InputKind, Verdict
from .output_safe import html_text
from .secrets import scan_secrets
from .supervisor import get_supervisor


# ─── STATISTICAL HELPERS ─────────────────────────────────────────────────────

def wilson_interval(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Computes Wilson 95% score confidence interval for a proportion k / n.
    Standard library math only.
    """
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    # z = 1.959963984540054 for 95% confidence
    z = 1.959963984540054
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = (p + z2 / (2.0 * n)) / denom
    margin = (z * math.sqrt((p * (1.0 - p)) / n + z2 / (4.0 * n * n))) / denom
    lower = max(0.0, centre - margin)
    upper = min(1.0, centre + margin)
    return (round(lower, 4), round(upper, 4))


def make_rate_dict(k: int, n: int) -> Dict[str, Any]:
    rate = round(k / n, 4) if n > 0 else 0.0
    ci = wilson_interval(k, n)
    return {
        "count": k,
        "total": n,
        "rate": rate,
        "ci_95": [ci[0], ci[1]],
    }


def _percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    d0 = sorted_vals[int(f)] * (c - k)
    d1 = sorted_vals[int(c)] * (k - f)
    return d0 + d1


# ─── BASELINE EVALUATION (BEFORE DEFENCE) ────────────────────────────────────

def baseline_eval(case: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Models the original project baseline BEFORE the security guard layer:
    - USER_SOURCE: Evaluated against compiler_runner._sanitize_code patterns.
      Blocks on dangerous system calls, assembly, or sys/ includes.
    - HTTP_REQUEST: Evaluated against original web_server checks.
      Blocks on foreign Host, foreign Origin, or invalid Content-Type on POST.
      Missing token is ALLOWED (token verification did not exist in baseline).
    - PATCH: Evaluated against _sanitize_code and validate_ai_code rules from src/ai_healer.py:
      rejects if _sanitize_code fails, if len(fixed) < 0.60 * len(original), if main()
      was removed, or if changed lines exceed max(int(len(original_lines) * 0.40), 10).
      (Compile validation with g++ is not simulated in benchmark).
    - USER_HINT, COMPILER_OUTPUT, DATASET_ENTRY, MODEL_FILE, display:
      No deterministic defense existed in baseline; returns (True, "no defence").
    """
    kind = case.get("kind")
    payload = case.get("payload") or ""
    meta = case.get("meta") or {}

    if kind == "USER_SOURCE":
        if re.search(r'system\s*\(', payload):
            return (False, "sanitizer:system")
        if re.search(r'popen\s*\(', payload):
            return (False, "sanitizer:popen")
        if re.search(r'exec\s*\(', payload):
            return (False, "sanitizer:exec")
        if re.search(r'fork\s*\(', payload):
            return (False, "sanitizer:fork")
        if re.search(r'__asm__', payload) or re.search(r'shellcode', payload):
            return (False, "sanitizer:asm")
        if re.search(r'#include\s*[<"]\s*sys/', payload):
            return (False, "sanitizer:sys-include")
        return (True, "no defence")

    elif kind == "HTTP_REQUEST":
        headers = {str(k).lower(): str(v) for k, v in meta.get("headers", {}).items()}
        method = str(meta.get("method", "GET")).upper()
        # 1. Host check (original web server)
        host = headers.get("host") or meta.get("host")
        if host:
            host_val = host.split(":")[0].strip().lower()
            if host_val not in ("localhost", "127.0.0.1", "::1"):
                return (False, "http:foreign-host")
        # 2. Origin check (original web server)
        origin = headers.get("origin") or meta.get("origin")
        if origin and origin != "null":
            if not ("localhost" in origin or "127.0.0.1" in origin):
                return (False, "http:foreign-origin")
        # 3. Content-Type check on POST
        if method == "POST":
            ct = headers.get("content-type", "")
            if "application/json" not in ct.lower():
                return (False, "http:content-type")
        return (True, "no defence")

    elif kind == "PATCH":
        # 1. Security check (_sanitize_code)
        if re.search(r'system\s*\(', payload):
            return (False, "sanitizer:system")
        if re.search(r'popen\s*\(', payload):
            return (False, "sanitizer:popen")
        if re.search(r'exec\s*\(', payload):
            return (False, "sanitizer:exec")
        if re.search(r'fork\s*\(', payload):
            return (False, "sanitizer:fork")
        if re.search(r'__asm__', payload) or re.search(r'shellcode', payload):
            return (False, "sanitizer:asm")
        if re.search(r'#include\s*[<"]\s*sys/', payload):
            return (False, "sanitizer:sys-include")
        orig = meta.get("original", "")
        if orig:
            # 2. Length check: at least 60% of original
            if len(payload) < 0.60 * len(orig):
                return (False, "validate_ai_code:length")
            # 3. Main preservation check
            orig_has_main = bool(re.search(r'\b(?:int|void)?\s*main\s*\(', orig))
            fixed_has_main = bool(re.search(r'\b(?:int|void)?\s*main\s*\(', payload))
            if orig_has_main and not fixed_has_main:
                return (False, "validate_ai_code:main-removed")
            # 4. Line change ratio: max(int(len(orig_lines) * 0.40), 10)
            orig_lines = orig.splitlines()
            fixed_lines = payload.splitlines()
            diff = list(difflib.ndiff(orig_lines, fixed_lines))
            changes = sum(1 for d in diff if d.startswith('+ ') or d.startswith('- '))
            max_allowed = max(int(len(orig_lines) * 0.40), 10)
            if changes > max_allowed:
                return (False, "validate_ai_code:line-count")
        return (True, "no defence")

    else:
        # USER_HINT, COMPILER_OUTPUT, DATASET_ENTRY, MODEL_FILE, display
        # No deterministic defense existed in baseline
        return (True, "no defence")


def baseline_allows(case: Dict[str, Any]) -> bool:
    """Returns True if the baseline allows the case, False if blocked."""
    return baseline_eval(case)[0]


# ─── NEUTRALIZATION CHECK ────────────────────────────────────────────────────

def check_neutralized(payload: str) -> bool:
    """
    Checks if a display payload is neutralized by output_safe:
    - No HTML tag (< followed by letter, / or !)
    - No ANSI escape (\x1b)
    - No bidirectional or zero-width character
    - No API secret key
    """
    safe = html_text(payload)
    if re.search(r"<[A-Za-z/!]", safe):
        return False
    if "\x1b" in safe:
        return False
    if re.search(r"[\u202A-\u202E\u2066-\u2069\u200E\u200F\u200B-\u200D\u2060\uFEFF]", safe):
        return False
    if scan_secrets(safe):
        return False
    return True


# ─── BENCHMARK RUNNER ────────────────────────────────────────────────────────

def run_benchmark(
    manifest_path: Optional[str] = None,
    *,
    with_heal: bool = False,
    progress: Optional[Callable[[int, int, str], None]] = None,
) -> Dict[str, Any]:
    """
    Executes the full security benchmark.
    Returns a JSON-safe dictionary containing all evaluation metrics.
    """
    t_start = time.time()

    if manifest_path is None:
        manifest_path = str(Path(__file__).resolve().parent.parent.parent / "security_bench" / "manifest.json")

    manifest_file = Path(manifest_path)
    if not manifest_file.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    cases: List[Dict[str, Any]] = json.loads(manifest_file.read_text(encoding="utf-8"))

    temp_root = Path(tempfile.mkdtemp(prefix="sec_bench_"))
    temp_data_dir = temp_root / "data"
    temp_data_dir.mkdir(parents=True, exist_ok=True)
    temp_log_path = temp_root / "attack_log.jsonl"

    old_env = dict(os.environ)
    os.environ["GUARD_LOG_PATH"] = str(temp_log_path)
    os.environ["GUARD_DATA_DIR"] = str(temp_data_dir)

    # Prepare model files in temp_data_dir
    fake_model_path = temp_data_dir / "error_classifier.joblib"
    fake_model_path.write_bytes(b"FAKE_TRAINED_MODEL_BINARY_CONTENT_12345")
    
    import hashlib
    h = hashlib.sha256(fake_model_path.read_bytes()).hexdigest()
    manifest_data = {
        "model_file": "error_classifier.joblib",
        "sha256": h,
        "size_bytes": fake_model_path.stat().st_size,
        "signed_at": "2026-01-01T00:00:00Z",
    }
    (temp_data_dir / "model_manifest.json").write_text(json.dumps(manifest_data), encoding="utf-8")

    supervisor = get_supervisor()
    case_results: List[Dict[str, Any]] = []

    routing_misses = 0
    run_ratios: List[float] = []

    try:
        total_cases = len(cases)
        for idx, case in enumerate(cases):
            case_id = case["id"]
            if progress:
                progress(idx + 1, total_cases, case_id)

            label = case["label"]
            c_set = case.get("set", "standard")
            family = case["family"]
            kind_str = case["kind"]
            purpose = case["purpose"]
            payload = case.get("payload", "")
            meta = dict(case.get("meta") or {})
            prevention = case.get("prevention", "block")
            expected_agents = case.get("expected_agents", [])
            expected_cat = case.get("expected_category")

            # Setup case-specific temp environment
            case_temp = temp_root / f"case_{case_id}"
            case_temp.mkdir(parents=True, exist_ok=True)

            if "files" in case:
                for fname, fcontent in case["files"].items():
                    fpath = case_temp / fname
                    fpath.parent.mkdir(parents=True, exist_ok=True)
                    fpath.write_text(fcontent, encoding="utf-8")
                meta["source_dir"] = str(case_temp)

            # Model case handling
            model_case = case.get("model_case")
            if kind_str == "MODEL_FILE" or model_case:
                c_model_dir = case_temp / "data"
                c_model_dir.mkdir(parents=True, exist_ok=True)
                c_model_file = c_model_dir / "error_classifier.joblib"
                
                if model_case == "outside_data_dir":
                    outside_file = case_temp / "evil.joblib"
                    outside_file.write_bytes(b"OUTSIDE_MODEL")
                    payload = str(outside_file)
                    meta["model_path"] = str(outside_file)
                    meta["data_dir"] = str(c_model_dir)
                    os.environ["GUARD_DATA_DIR"] = str(c_model_dir)
                else:
                    c_model_file.write_bytes(b"BENCHMARK_MODEL_DATA_BYTES")
                    m_hash = hashlib.sha256(c_model_file.read_bytes()).hexdigest()
                    c_manifest = {
                        c_model_file.name: {
                            "sha256": m_hash,
                            "size": c_model_file.stat().st_size,
                            "signed_at": "2026-01-01T00:00:00Z",
                        }
                    }
                    if model_case != "missing_manifest":
                        (c_model_dir / "model_manifest.json").write_text(json.dumps(c_manifest), encoding="utf-8")
                    if model_case == "flip_byte":
                        c_model_file.write_bytes(b"BENCHMARK_MODEL_DATA_BYTEZ")  # 1 byte flipped
                    payload = str(c_model_file)
                    meta["model_path"] = str(c_model_file)
                    meta["data_dir"] = str(c_model_dir)
                    os.environ["GUARD_DATA_DIR"] = str(c_model_dir)

            if kind_str == "HTTP_REQUEST":
                meta.setdefault("expected_token", "BENCH_TOKEN_123")
                meta.setdefault("server_port", 8000)

            # 1. Normal review
            v_normal = supervisor.review(
                kind_str,
                payload,
                purpose=purpose,
                meta=meta,
                full_scan=False,
                include_vulnerability=True,
            )

            # 2. Full scan review (for routing verification)
            v_full = supervisor.review(
                kind_str,
                payload,
                purpose=purpose,
                meta=meta,
                full_scan=True,
                include_vulnerability=True,
            )

            # Check routing misses: any (agent, category) in full scan not in normal review
            normal_pairs = {(f.agents[0] if f.agents else "", f.category) for f in v_normal.findings}
            full_pairs = {(f.agents[0] if f.agents else "", f.category) for f in v_full.findings}
            missed = full_pairs - normal_pairs
            if missed:
                routing_misses += 1

            # Candidate agents vs run ratio
            kind_enum = InputKind(kind_str) if isinstance(kind_str, str) else kind_str
            candidates = [a for a in supervisor._agents if kind_enum in getattr(a, "handles", set())]
            agents_run = len(v_normal.routing)
            ratio = (agents_run / len(candidates)) if candidates else 1.0
            run_ratios.append(ratio)

            # 3. Evaluate criteria
            exp_origin = case.get("expected_origin", "attack")
            matching_findings = [
                f for f in v_normal.findings
                if f.origin == exp_origin and any(ag in expected_agents for ag in f.agents)
            ]

            # Detected
            detected = len(matching_findings) > 0 if label == "attack" else False

            # Attributed: agent_attributed and category_attributed
            agent_attributed = False
            category_attributed = False
            if label == "attack":
                agent_attributed = detected
                category_attributed = any(f.category == expected_cat for f in matching_findings)

            # Prevented
            prevented = False
            if label == "attack":
                if prevention == "block":
                    prevented = v_normal.blocked
                elif prevention == "neutralize":
                    prevented = check_neutralized(payload)
                elif prevention == "warn":
                    prevented = False  # Excluded from prevention rate

            # False Positives on benign cases
            alert_fp = False
            block_fp = False
            if label == "benign":
                alert_fp = any(f.origin == "attack" and f.severity in ("Medium", "High", "Critical") for f in v_normal.findings)
                block_fp = v_normal.blocked

            # Baseline evaluation
            b_allows, b_reason = baseline_eval(case)

            agents_found = sorted(list(set(ag for f in v_normal.findings for ag in f.agents)))
            cats_found = sorted(list(set(f.category for f in v_normal.findings)))

            case_results.append({
                "id": case_id,
                "label": label,
                "set": c_set,
                "family": family,
                "kind": kind_str,
                "purpose": purpose,
                "prevention": prevention,
                "expected_agents": expected_agents,
                "expected_category": expected_cat,
                "expected_origin": exp_origin,
                "detected": detected,
                "agent_attributed": agent_attributed,
                "category_attributed": category_attributed,
                "attributed": (agent_attributed and category_attributed),
                "prevented": prevented,
                "alert_fp": alert_fp,
                "block_fp": block_fp,
                "baseline_allowed": b_allows,
                "baseline_reason": b_reason,
                "blocked": v_normal.blocked,
                "risk_score": v_normal.risk_score,
                "total_ms": v_normal.total_ms,
                "agents_found": agents_found,
                "categories": cats_found,
                "findings": [f.to_dict() for f in v_normal.findings],
                "notes": case.get("notes", ""),
            })

    finally:
        os.environ.clear()
        os.environ.update(old_env)
        try:
            shutil.rmtree(temp_root)
        except OSError:
            pass

    # ── METRICS COMPUTATION ──────────────────────────────────────────────────

    all_attacks = [c for c in case_results if c["label"] == "attack"]
    benign_cases = [c for c in case_results if c["label"] == "benign"]

    # Headline attacks exclude scanner_evasion (reported separately as a scanner limitation)
    headline_attacks = [c for c in all_attacks if c["family"] != "scanner_evasion"]
    headline_benign = [c for c in benign_cases if c["family"] != "scanner_evasion"]
    std_attacks = [c for c in headline_attacks if c["set"] == "standard"]
    hard_attacks = [c for c in headline_attacks if c["set"] == "hard"]

    # Evaluated headline attacks for prevention / ASR (exclude prevention="warn")
    headline_eval_attacks = [c for c in headline_attacks if c["prevention"] != "warn"]
    std_eval_attacks = [c for c in std_attacks if c["prevention"] != "warn"]
    hard_eval_attacks = [c for c in hard_attacks if c["prevention"] != "warn"]

    # 1. Overall Headline Metrics
    tot_attacks_n = len(headline_attacks)
    tot_detected = sum(1 for c in headline_attacks if c["detected"])
    tot_agent_attrib = sum(1 for c in headline_attacks if c["agent_attributed"])
    tot_cat_attrib = sum(1 for c in headline_attacks if c["category_attributed"])
    tot_attributed = sum(1 for c in headline_attacks if c["attributed"])

    tot_eval_n = len(headline_eval_attacks)
    tot_prevented = sum(1 for c in headline_eval_attacks if c["prevented"])
    defended_asr = (tot_eval_n - tot_prevented) / tot_eval_n if tot_eval_n > 0 else 0.0

    tot_baseline_allowed = sum(1 for c in headline_eval_attacks if c["baseline_allowed"])
    baseline_asr = tot_baseline_allowed / tot_eval_n if tot_eval_n > 0 else 0.0

    tot_benign_n = len(headline_benign)
    tot_alert_fp = sum(1 for c in headline_benign if c["alert_fp"])
    tot_block_fp = sum(1 for c in headline_benign if c["block_fp"])

    precision_denom = tot_detected + tot_alert_fp
    overall_precision = (tot_detected / precision_denom) if precision_denom > 0 else 1.0
    overall_recall = (tot_detected / tot_attacks_n) if tot_attacks_n > 0 else 0.0
    overall_f1 = (2.0 * overall_precision * overall_recall / (overall_precision + overall_recall)) if (overall_precision + overall_recall) > 0 else 0.0

    overall_metrics = {
        "total_cases": len([c for c in case_results if c["family"] != "scanner_evasion"]),
        "total_all_cases": len(case_results),
        "total_attacks": tot_attacks_n,
        "standard_attacks": len(std_attacks),
        "hard_attacks": len(hard_attacks),
        "benign_cases": tot_benign_n,
        "detection_rate": make_rate_dict(tot_detected, tot_attacks_n),
        "agent_attribution_rate": make_rate_dict(tot_agent_attrib, tot_attacks_n),
        "category_attribution_rate": make_rate_dict(tot_cat_attrib, tot_attacks_n),
        "attribution_rate": make_rate_dict(tot_attributed, tot_attacks_n),
        "prevention_rate": make_rate_dict(tot_prevented, tot_eval_n),
        "false_alert_rate": make_rate_dict(tot_alert_fp, tot_benign_n),
        "false_block_rate": make_rate_dict(tot_block_fp, tot_benign_n),
        "precision": round(overall_precision, 4),
        "recall": round(overall_recall, 4),
        "f1_score": round(overall_f1, 4),
        "baseline_asr": round(baseline_asr, 4),
        "defended_asr": round(defended_asr, 4),
    }

    # 2. Per Set Metrics
    set_metrics = {}
    for s_name, s_att, s_eval in [("standard", std_attacks, std_eval_attacks), ("hard", hard_attacks, hard_eval_attacks)]:
        n_att = len(s_att)
        n_det = sum(1 for c in s_att if c["detected"])
        n_agent_attrib = sum(1 for c in s_att if c["agent_attributed"])
        n_cat_attrib = sum(1 for c in s_att if c["category_attributed"])
        n_att_attrib = sum(1 for c in s_att if c["attributed"])
        n_eval = len(s_eval)
        n_prev = sum(1 for c in s_eval if c["prevented"])
        b_allow = sum(1 for c in s_eval if c["baseline_allowed"])
        set_metrics[s_name] = {
            "total_attacks": n_att,
            "detection_rate": make_rate_dict(n_det, n_att),
            "agent_attribution_rate": make_rate_dict(n_agent_attrib, n_att),
            "category_attribution_rate": make_rate_dict(n_cat_attrib, n_att),
            "attribution_rate": make_rate_dict(n_att_attrib, n_att),
            "prevention_rate": make_rate_dict(n_prev, n_eval),
            "baseline_asr": round(b_allow / n_eval, 4) if n_eval > 0 else 0.0,
            "defended_asr": round((n_eval - n_prev) / n_eval, 4) if n_eval > 0 else 0.0,
        }

    # 3. Per Family Metrics
    all_families = sorted(list(set(c["family"] for c in case_results)))
    family_metrics = {}
    for fam in all_families:
        f_attacks = [c for c in all_attacks if c["family"] == fam]
        f_eval_att = [c for c in f_attacks if c["prevention"] != "warn"]
        f_std_att = [c for c in f_attacks if c["set"] == "standard"]
        f_hard_att = [c for c in f_attacks if c["set"] == "hard"]
        f_benign = [c for c in benign_cases if c["family"] == fam]

        f_att_n = len(f_attacks)
        f_det = sum(1 for c in f_attacks if c["detected"])
        f_agent_attrib = sum(1 for c in f_attacks if c["agent_attributed"])
        f_cat_attrib = sum(1 for c in f_attacks if c["category_attributed"])
        f_attrib = sum(1 for c in f_attacks if c["attributed"])
        f_eval_n = len(f_eval_att)
        f_prev = sum(1 for c in f_eval_att if c["prevented"])

        f_b_allow = sum(1 for c in f_eval_att if c["baseline_allowed"])
        b_asr = round(f_b_allow / f_eval_n, 4) if f_eval_n > 0 else 0.0
        d_asr = round((f_eval_n - f_prev) / f_eval_n, 4) if f_eval_n > 0 else 0.0

        f_ben_n = len(f_benign)
        f_alert_fp = sum(1 for c in f_benign if c["alert_fp"])
        f_block_fp = sum(1 for c in f_benign if c["block_fp"])

        std_det = sum(1 for c in f_std_att if c["detected"])
        hard_det = sum(1 for c in f_hard_att if c["detected"])

        family_metrics[fam] = {
            "total_attacks": f_att_n,
            "standard_attacks": len(f_std_att),
            "hard_attacks": len(f_hard_att),
            "benign_cases": f_ben_n,
            "detection_rate": make_rate_dict(f_det, f_att_n),
            "standard_detection_rate": make_rate_dict(std_det, len(f_std_att)),
            "hard_detection_rate": make_rate_dict(hard_det, len(f_hard_att)),
            "agent_attribution_rate": make_rate_dict(f_agent_attrib, f_att_n),
            "category_attribution_rate": make_rate_dict(f_cat_attrib, f_att_n),
            "attribution_rate": make_rate_dict(f_attrib, f_att_n),
            "prevention_rate": make_rate_dict(f_prev, f_eval_n),
            "false_alert_rate": make_rate_dict(f_alert_fp, f_ben_n),
            "false_block_rate": make_rate_dict(f_block_fp, f_ben_n),
            "baseline_asr": b_asr,
            "defended_asr": d_asr,
        }

    # 4. Per Agent Metrics
    all_agents = ["ExecGuard", "ResourceGuard", "OutputGuard", "EndpointGuard", "SecretsGuard", "IntegrityGuard", "PromptGuard", "PatchGuard", "VulnGuard"]
    agent_metrics = {}
    for ag in all_agents:
        ag_expected = [c for c in all_attacks if ag in c["expected_agents"]]
        ag_detected = sum(1 for c in ag_expected if c["detected"])
        ag_fp = sum(1 for c in benign_cases if any(ag in c_f.get("agents", []) for c_f in c["findings"] if c_f.get("origin") == "attack" and c_f.get("severity") in ("Medium", "High", "Critical")))
        ag_prec_denom = ag_detected + ag_fp
        ag_precision = (ag_detected / ag_prec_denom) if ag_prec_denom > 0 else 1.0

        agent_metrics[ag] = {
            "expected_cases": len(ag_expected),
            "detected_cases": ag_detected,
            "recall": make_rate_dict(ag_detected, len(ag_expected)),
            "false_positives": ag_fp,
            "precision": round(ag_precision, 4),
        }

    # 5. Routing Metrics
    routing_metrics = {
        "routing_misses": routing_misses,
        "mean_run_to_candidate_ratio": round(sum(run_ratios) / len(run_ratios), 4) if run_ratios else 1.0,
    }

    # 6. Latency Metrics
    all_latencies = [c["total_ms"] for c in case_results]
    latency_by_kind = {}
    all_kinds = sorted(list(set(c["kind"] for c in case_results)))
    for k in all_kinds:
        k_lat = [c["total_ms"] for c in case_results if c["kind"] == k]
        latency_by_kind[k] = {
            "mean": round(sum(k_lat) / len(k_lat), 3) if k_lat else 0.0,
            "median": round(_percentile(k_lat, 50), 3) if k_lat else 0.0,
            "p95": round(_percentile(k_lat, 95), 3) if k_lat else 0.0,
            "max": round(max(k_lat), 3) if k_lat else 0.0,
        }

    overall_latency = {
        "mean": round(sum(all_latencies) / len(all_latencies), 3) if all_latencies else 0.0,
        "median": round(_percentile(all_latencies, 50), 3) if all_latencies else 0.0,
        "p95": round(_percentile(all_latencies, 95), 3) if all_latencies else 0.0,
        "max": round(max(all_latencies), 3) if all_latencies else 0.0,
        "by_kind": latency_by_kind,
    }

    # 7. Risk Distribution
    risk_by_family = {}
    for fam in all_families:
        fam_risks = [c["risk_score"] for c in all_attacks if c["family"] == fam]
        if fam_risks:
            risk_by_family[fam] = {
                "min": min(fam_risks),
                "median": round(_percentile(fam_risks, 50), 1),
                "mean": round(sum(fam_risks) / len(fam_risks), 1),
                "max": max(fam_risks),
            }
    benign_risks = [c["risk_score"] for c in benign_cases]
    risk_by_family["benign"] = {
        "min": min(benign_risks) if benign_risks else 0,
        "median": round(_percentile(benign_risks, 50), 1) if benign_risks else 0.0,
        "mean": round(sum(benign_risks) / len(benign_risks), 1) if benign_risks else 0.0,
        "max": max(benign_risks) if benign_risks else 0,
    }

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    blocked_by_category: Dict[str, int] = {}
    blocked_by_agent: Dict[str, int] = {}

    for c in case_results:
        for f in c["findings"]:
            sev = f.get("severity")
            if sev in severity_counts:
                severity_counts[sev] += 1
            if c["blocked"]:
                cat = f.get("category", "unknown")
                blocked_by_category[cat] = blocked_by_category.get(cat, 0) + 1
                for ag in f.get("agents", []):
                    blocked_by_agent[ag] = blocked_by_agent.get(ag, 0) + 1

    # 8. Known Misses (strictly every attack where detected == False)
    known_misses = []
    for c in all_attacks:
        if not c["detected"]:
            reason = "Evasion not matched by regex / parser heuristic"
            if c["set"] == "hard":
                reason = f"Hard evasion: {c['notes']}"
            known_misses.append({
                "id": c["id"],
                "set": c["set"],
                "family": c["family"],
                "expected_category": c["expected_category"],
                "detected": c["detected"],
                "prevented": c["prevented"],
                "notes": c["notes"],
                "reason": reason,
            })

    # Attribution mismatches
    attribution_mismatches = []
    for c in all_attacks:
        if not c["agent_attributed"] or not c["category_attributed"]:
            attribution_mismatches.append({
                "id": c["id"],
                "set": c["set"],
                "family": c["family"],
                "expected_agents": ";".join(c["expected_agents"]),
                "agents_found": ";".join(c["agents_found"]),
                "expected_category": c["expected_category"],
                "categories_found": ";".join(c["categories"]),
            })

    # Automatically write data/security_attribution_mismatches.csv
    data_dir = Path(__file__).resolve().parent.parent.parent / "data"
    mismatch_csv = data_dir / "security_attribution_mismatches.csv"
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        with open(mismatch_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["case_id", "set", "family", "expected_agents", "agents_found", "expected_category", "categories_found"])
            for m in attribution_mismatches:
                writer.writerow([
                    m["id"],
                    m["set"],
                    m["family"],
                    m["expected_agents"],
                    m["agents_found"],
                    m["expected_category"],
                    m["categories_found"],
                ])
    except Exception:
        pass

    # 9. Optional Security Healing Evaluation
    heal_section = None
    if with_heal:
        from security_healer import heal_security
        heal_root = Path(__file__).resolve().parent.parent.parent
        heal_targets = [
            heal_root / "test_cases" / "security_heal" / "fixable.cpp",
            heal_root / "test_cases" / "security_heal" / "unfixable.cpp",
            heal_root / "test_cases" / "security_heal" / "clean.cpp",
            heal_root / "security_bench" / "heal" / "gets_sample.cpp",
            heal_root / "security_bench" / "heal" / "strcat_sample.cpp",
            heal_root / "security_bench" / "heal" / "sprintf_sample.cpp",
            heal_root / "security_bench" / "heal" / "leak_sample.cpp",
            heal_root / "security_bench" / "heal" / "double_free_sample.cpp",
        ]

        file_heal_results = []
        tot_f_before = 0
        tot_fixed = 0
        tot_suggested = 0
        tot_skipped = 0
        tot_rejected = 0
        tot_risk_before = 0
        tot_risk_after = 0

        for hpath in heal_targets:
            if not hpath.exists():
                continue
            src = hpath.read_text(encoding="utf-8")
            h_res = heal_security(src)

            f_before_cnt = len(h_res.findings_before)
            n_fixed = sum(1 for o in h_res.outcomes if o.status == "fixed")
            n_sugg = sum(1 for o in h_res.outcomes if o.status == "suggested")
            n_skip = sum(1 for o in h_res.outcomes if o.status == "skipped_behavior")
            n_rej = sum(1 for o in h_res.outcomes if o.status == "rejected")

            tot_f_before += f_before_cnt
            tot_fixed += n_fixed
            tot_suggested += n_sugg
            tot_skipped += n_skip
            tot_rejected += n_rej
            tot_risk_before += h_res.risk_before
            tot_risk_after += h_res.risk_after

            r_red_pct = 0.0
            if h_res.risk_before > 0:
                r_red_pct = round(((h_res.risk_before - h_res.risk_after) / h_res.risk_before) * 100.0, 1)

            file_heal_results.append({
                "file": hpath.name,
                "findings_before": f_before_cnt,
                "fixed": n_fixed,
                "suggested": n_sugg,
                "skipped": n_skip,
                "rejected": n_rej,
                "risk_before": h_res.risk_before,
                "risk_after": h_res.risk_after,
                "risk_reduction_pct": r_red_pct,
                "seconds": round(h_res.seconds, 3),
            })

        overall_risk_red = 0.0
        if tot_risk_before > 0:
            overall_risk_red = round(((tot_risk_before - tot_risk_after) / tot_risk_before) * 100.0, 1)

        heal_section = {
            "files": file_heal_results,
            "totals": {
                "findings_before": tot_f_before,
                "fixed": tot_fixed,
                "suggested": tot_suggested,
                "skipped": tot_skipped,
                "rejected": tot_rejected,
                "risk_before": tot_risk_before,
                "risk_after": tot_risk_after,
                "risk_reduction_pct": overall_risk_red,
                "fix_rate": round(tot_fixed / tot_f_before, 4) if tot_f_before > 0 else 0.0,
            },
        }

    # Environment Info
    gpp_version = "unavailable"
    try:
        from guard import safe_run
        g_res = safe_run(["g++", "--version"], kind="syntax", timeout_s=5.0)
        if g_res.stdout:
            gpp_version = g_res.stdout.splitlines()[0].strip()
    except Exception:
        pass

    git_hash = "unavailable"
    try:
        git_kwargs = {"text": True}
        if os.name == "nt":
            git_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            git_kwargs["startupinfo"] = si
        g_out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], **git_kwargs).strip()
        if g_out:
            git_hash = g_out
    except Exception:
        pass

    env_block = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_version": sys.version.split()[0],
        "os_version": f"{platform.system()} {platform.release()}",
        "compiler_version": gpp_version,
        "git_commit": git_hash,
    }

    return compute_metrics(
        case_results,
        routing_misses=routing_misses,
        run_ratios=run_ratios,
        heal_section=heal_section,
        benchmark_seconds=round(time.time() - t_start, 3),
        env_block=env_block,
    )


# ─── SINGLE AGGREGATE FUNCTION (TASK 1) ──────────────────────────────────────

def compute_metrics(
    case_results: List[Dict[str, Any]],
    *,
    routing_misses: int = 0,
    run_ratios: Optional[List[float]] = None,
    heal_section: Optional[Dict[str, Any]] = None,
    benchmark_seconds: float = 0.0,
    env_block: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Computes all benchmark aggregates from per-case result rows in code once:
    overall, per set, per family, per agent, ASR before and after, prevention,
    attribution, latency, risk, detected_not_prevented, and known_misses.
    Zero numbers are hard-coded in templates or typed in strings.
    """
    all_attacks = [c for c in case_results if c["label"] == "attack"]
    benign_cases = [c for c in case_results if c["label"] == "benign"]

    # Headline cases exclude scanner_evasion (reported separately as a scanner limitation)
    headline_cases = [c for c in case_results if c["family"] != "scanner_evasion"]
    headline_attacks = [c for c in headline_cases if c["label"] == "attack"]
    headline_benign = [c for c in headline_cases if c["label"] == "benign"]

    std_attacks = [c for c in headline_attacks if c["set"] == "standard"]
    hard_attacks = [c for c in headline_attacks if c["set"] == "hard"]

    scanner_cases = [c for c in case_results if c["family"] == "scanner_evasion"]
    scanner_attacks = [c for c in scanner_cases if c["label"] == "attack"]
    scanner_benign = [c for c in scanner_cases if c["label"] == "benign"]

    # Evaluated headline attacks for prevention / ASR (prevention in "block" or "neutralize")
    headline_eval_attacks = [c for c in headline_attacks if c["prevention"] in ("block", "neutralize")]
    std_eval_attacks = [c for c in std_attacks if c["prevention"] in ("block", "neutralize")]
    hard_eval_attacks = [c for c in hard_attacks if c["prevention"] in ("block", "neutralize")]

    # 1. Manifest Totals Summary (Task 5)
    manifest_summary = {
        "total_cases": len(case_results),
        "headline_cases": len(headline_cases),
        "headline_attacks": len(headline_attacks),
        "headline_benign": len(headline_benign),
        "standard_attacks": len(std_attacks),
        "hard_attacks": len(hard_attacks),
        "scanner_evasion_cases": len(scanner_cases),
        "scanner_evasion_attacks": len(scanner_attacks),
        "scanner_evasion_benign": len(scanner_benign),
    }

    # 2. Overall Headline Metrics
    tot_attacks_n = len(headline_attacks)
    tot_detected = sum(1 for c in headline_attacks if c["detected"])
    tot_agent_attrib = sum(1 for c in headline_attacks if c["agent_attributed"])
    tot_cat_attrib = sum(1 for c in headline_attacks if c["category_attributed"])
    tot_attributed = sum(1 for c in headline_attacks if c["attributed"])

    tot_eval_n = len(headline_eval_attacks)
    tot_prevented = sum(1 for c in headline_eval_attacks if c["prevented"])
    defended_asr = (tot_eval_n - tot_prevented) / tot_eval_n if tot_eval_n > 0 else 0.0

    tot_baseline_allowed = sum(1 for c in headline_eval_attacks if c["baseline_allowed"])
    tot_baseline_prevented = tot_eval_n - tot_baseline_allowed
    baseline_asr = tot_baseline_allowed / tot_eval_n if tot_eval_n > 0 else 0.0

    tot_benign_n = len(headline_benign)
    tot_alert_fp = sum(1 for c in headline_benign if c["alert_fp"])
    tot_block_fp = sum(1 for c in headline_benign if c["block_fp"])

    precision_denom = tot_detected + tot_alert_fp
    overall_precision = (tot_detected / precision_denom) if precision_denom > 0 else 1.0
    overall_recall = (tot_detected / tot_attacks_n) if tot_attacks_n > 0 else 0.0
    overall_f1 = (2.0 * overall_precision * overall_recall / (overall_precision + overall_recall)) if (overall_precision + overall_recall) > 0 else 0.0

    overall_metrics = {
        "total_cases": len(headline_cases),
        "total_all_cases": len(case_results),
        "total_attacks": tot_attacks_n,
        "standard_attacks": len(std_attacks),
        "hard_attacks": len(hard_attacks),
        "asr_attacks": tot_eval_n,
        "warn_attacks": tot_attacks_n - tot_eval_n,
        "benign_cases": tot_benign_n,
        "detection_rate": make_rate_dict(tot_detected, tot_attacks_n),
        "agent_attribution_rate": make_rate_dict(tot_agent_attrib, tot_attacks_n),
        "category_attribution_rate": {
            **make_rate_dict(tot_cat_attrib, tot_attacks_n),
            "interpretation": "label-aligned (expected categories were corrected to each agent's canonical names, so this equals the detection rate and is not an independent result)",
        },
        "attribution_rate": make_rate_dict(tot_attributed, tot_attacks_n),
        "prevention_rate": make_rate_dict(tot_prevented, tot_eval_n),
        "baseline_prevented": tot_baseline_prevented,
        "baseline_allowed": tot_baseline_allowed,
        "baseline_asr": round(baseline_asr, 4),
        "defended_asr": round(defended_asr, 4),
        "false_alert_rate": make_rate_dict(tot_alert_fp, tot_benign_n),
        "false_block_rate": make_rate_dict(tot_block_fp, tot_benign_n),
        "precision": round(overall_precision, 4),
        "recall": round(overall_recall, 4),
        "f1_score": round(overall_f1, 4),
    }

    # 3. Per Set Metrics
    set_metrics = {}
    for s_name, s_att, s_eval in [("standard", std_attacks, std_eval_attacks), ("hard", hard_attacks, hard_eval_attacks)]:
        n_att = len(s_att)
        n_det = sum(1 for c in s_att if c["detected"])
        n_agent_attrib = sum(1 for c in s_att if c["agent_attributed"])
        n_cat_attrib = sum(1 for c in s_att if c["category_attributed"])
        n_att_attrib = sum(1 for c in s_att if c["attributed"])
        n_eval = len(s_eval)
        n_prev = sum(1 for c in s_eval if c["prevented"])
        b_allow = sum(1 for c in s_eval if c["baseline_allowed"])
        b_prev = n_eval - b_allow
        set_metrics[s_name] = {
            "total_attacks": n_att,
            "asr_attacks": n_eval,
            "warn_attacks": n_att - n_eval,
            "detected": n_det,
            "prevented": n_prev,
            "baseline_prevented": b_prev,
            "baseline_allowed": b_allow,
            "detection_rate": make_rate_dict(n_det, n_att),
            "agent_attribution_rate": make_rate_dict(n_agent_attrib, n_att),
            "category_attribution_rate": {
                **make_rate_dict(n_cat_attrib, n_att),
                "interpretation": "label-aligned (expected categories were corrected to each agent's canonical names, so this equals the detection rate and is not an independent result)",
            },
            "attribution_rate": make_rate_dict(n_att_attrib, n_att),
            "prevention_rate": make_rate_dict(n_prev, n_eval),
            "baseline_asr": round(b_allow / n_eval, 4) if n_eval > 0 else 0.0,
            "defended_asr": round((n_eval - n_prev) / n_eval, 4) if n_eval > 0 else 0.0,
        }

    # 4. Per Family Metrics
    all_families = sorted(list(set(c["family"] for c in case_results)))
    family_metrics = {}
    for fam in all_families:
        f_attacks = [c for c in all_attacks if c["family"] == fam]
        f_eval_att = [c for c in f_attacks if c["prevention"] in ("block", "neutralize")]
        f_std_att = [c for c in f_attacks if c["set"] == "standard"]
        f_hard_att = [c for c in f_attacks if c["set"] == "hard"]
        f_benign = [c for c in benign_cases if c["family"] == fam]

        f_att_n = len(f_attacks)
        f_det = sum(1 for c in f_attacks if c["detected"])
        f_agent_attrib = sum(1 for c in f_attacks if c["agent_attributed"])
        f_cat_attrib = sum(1 for c in f_attacks if c["category_attributed"])
        f_attrib = sum(1 for c in f_attacks if c["attributed"])
        f_eval_n = len(f_eval_att)
        f_prev = sum(1 for c in f_eval_att if c["prevented"])

        f_b_allow = sum(1 for c in f_eval_att if c["baseline_allowed"])
        f_b_prev = f_eval_n - f_b_allow
        b_asr = round(f_b_allow / f_eval_n, 4) if f_eval_n > 0 else 0.0
        d_asr = round((f_eval_n - f_prev) / f_eval_n, 4) if f_eval_n > 0 else 0.0

        f_ben_n = len(f_benign)
        f_alert_fp = sum(1 for c in f_benign if c["alert_fp"])
        f_block_fp = sum(1 for c in f_benign if c["block_fp"])

        std_det = sum(1 for c in f_std_att if c["detected"])
        hard_det = sum(1 for c in f_hard_att if c["detected"])

        family_metrics[fam] = {
            "total_attacks": f_att_n,
            "standard_attacks": len(f_std_att),
            "hard_attacks": len(f_hard_att),
            "asr_attacks": f_eval_n,
            "warn_attacks": f_att_n - f_eval_n,
            "detected": f_det,
            "prevented": f_prev,
            "baseline_prevented": f_b_prev,
            "baseline_allowed": f_b_allow,
            "benign_cases": f_ben_n,
            "detection_rate": make_rate_dict(f_det, f_att_n),
            "standard_detection_rate": make_rate_dict(std_det, len(f_std_att)),
            "hard_detection_rate": make_rate_dict(hard_det, len(f_hard_att)),
            "agent_attribution_rate": make_rate_dict(f_agent_attrib, f_att_n),
            "category_attribution_rate": {
                **make_rate_dict(f_cat_attrib, f_att_n),
                "interpretation": "label-aligned (expected categories were corrected to each agent's canonical names, so this equals the detection rate and is not an independent result)",
            },
            "attribution_rate": make_rate_dict(f_attrib, f_att_n),
            "prevention_rate": make_rate_dict(f_prev, f_eval_n),
            "false_alert_rate": make_rate_dict(f_alert_fp, f_ben_n),
            "false_block_rate": make_rate_dict(f_block_fp, f_ben_n),
            "baseline_asr": b_asr,
            "defended_asr": d_asr,
        }

    # 5. Per Agent Metrics
    all_agents = ["ExecGuard", "ResourceGuard", "OutputGuard", "EndpointGuard", "SecretsGuard", "IntegrityGuard", "PromptGuard", "PatchGuard", "VulnGuard"]
    agent_metrics = {}
    for ag in all_agents:
        ag_expected = [c for c in all_attacks if ag in c["expected_agents"]]
        ag_detected = sum(1 for c in ag_expected if c["detected"])
        ag_fp = sum(1 for c in benign_cases if any(ag in c_f.get("agents", []) for c_f in c["findings"] if c_f.get("origin") == "attack" and c_f.get("severity") in ("Medium", "High", "Critical")))
        ag_prec_denom = ag_detected + ag_fp
        ag_precision = (ag_detected / ag_prec_denom) if ag_prec_denom > 0 else 1.0

        agent_metrics[ag] = {
            "expected_cases": len(ag_expected),
            "detected_cases": ag_detected,
            "recall": make_rate_dict(ag_detected, len(ag_expected)),
            "false_positives": ag_fp,
            "precision": round(ag_precision, 4),
        }

    # 6. Routing Metrics
    routing_metrics = {
        "routing_misses": routing_misses,
        "mean_run_to_candidate_ratio": round(sum(run_ratios) / len(run_ratios), 4) if run_ratios else 1.0,
        "cases_covered": len(case_results),
    }

    # 7. Latency Metrics
    all_latencies = [c["total_ms"] for c in case_results]
    latency_by_kind = {}
    all_kinds = sorted(list(set(c["kind"] for c in case_results)))
    for k in all_kinds:
        k_lat = [c["total_ms"] for c in case_results if c["kind"] == k]
        latency_by_kind[k] = {
            "mean": round(sum(k_lat) / len(k_lat), 3) if k_lat else 0.0,
            "median": round(_percentile(k_lat, 50), 3) if k_lat else 0.0,
            "p95": round(_percentile(k_lat, 95), 3) if k_lat else 0.0,
            "max": round(max(k_lat), 3) if k_lat else 0.0,
        }

    overall_latency = {
        "mean": round(sum(all_latencies) / len(all_latencies), 3) if all_latencies else 0.0,
        "median": round(_percentile(all_latencies, 50), 3) if all_latencies else 0.0,
        "p95": round(_percentile(all_latencies, 95), 3) if all_latencies else 0.0,
        "max": round(max(all_latencies), 3) if all_latencies else 0.0,
        "cases_covered": len(case_results),
        "by_kind": latency_by_kind,
    }

    # 8. Risk Distribution
    risk_by_family = {}
    for fam in all_families:
        fam_risks = [c["risk_score"] for c in all_attacks if c["family"] == fam]
        if fam_risks:
            risk_by_family[fam] = {
                "min": min(fam_risks),
                "median": round(_percentile(fam_risks, 50), 1),
                "mean": round(sum(fam_risks) / len(fam_risks), 1),
                "max": max(fam_risks),
            }
    benign_risks = [c["risk_score"] for c in benign_cases]
    risk_by_family["benign"] = {
        "min": min(benign_risks) if benign_risks else 0,
        "median": round(_percentile(benign_risks, 50), 1) if benign_risks else 0.0,
        "mean": round(sum(benign_risks) / len(benign_risks), 1) if benign_risks else 0.0,
        "max": max(benign_risks) if benign_risks else 0,
    }

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    blocked_by_category: Dict[str, int] = {}
    blocked_by_agent: Dict[str, int] = {}

    for c in case_results:
        for f in c["findings"]:
            sev = f.get("severity")
            if sev in severity_counts:
                severity_counts[sev] += 1
            if c["blocked"]:
                cat = f.get("category", "unknown")
                blocked_by_category[cat] = blocked_by_category.get(cat, 0) + 1
                for ag in f.get("agents", []):
                    blocked_by_agent[ag] = blocked_by_agent.get(ag, 0) + 1

    # 9. Known Misses (strictly every headline attack where detected == False)
    known_misses = []
    for c in headline_attacks:
        if not c["detected"]:
            reason = "Evasion not matched by regex / parser heuristic"
            if c["set"] == "hard":
                reason = f"Hard evasion: {c['notes']}"
            known_misses.append({
                "id": c["id"],
                "set": c["set"],
                "family": c["family"],
                "expected_category": c["expected_category"],
                "detected": c["detected"],
                "prevented": c["prevented"],
                "notes": c["notes"],
                "reason": reason,
            })

    # 10. Detected Not Prevented (Task 2: attacks with detected == True and prevented == False)
    detected_not_prevented = []
    for c in headline_attacks:
        if c.get("prevention") in ("block", "neutralize") and c["detected"] and not c["prevented"]:
            f_cats = [f.get("category") for f in c.get("findings", [])]
            f_sevs = [f.get("severity") for f in c.get("findings", [])]
            reason = "Detector emitted Medium/Low severity findings with non-blocking action ('warn') that do not trigger supervisor block"
            if c["id"] == "exec_009":
                reason = "Finding category 'obfuscation' emitted with Medium severity and action 'warn'; ExecGuard does not emit a blocking action for macro token-pasting alone without a resolved dangerous syscall"
            detected_not_prevented.append({
                "id": c["id"],
                "set": c["set"],
                "family": c["family"],
                "categories": f_cats,
                "severities": f_sevs,
                "blocked": c["blocked"],
                "purpose": c["purpose"],
                "prevention": c["prevention"],
                "reason": reason,
            })

    # 11. Attribution Mismatches
    attribution_mismatches = []
    for c in all_attacks:
        if not c["agent_attributed"] or not c["category_attributed"]:
            attribution_mismatches.append({
                "id": c["id"],
                "set": c["set"],
                "family": c["family"],
                "expected_agents": ";".join(c["expected_agents"]),
                "agents_found": ";".join(c["agents_found"]),
                "expected_category": c["expected_category"],
                "categories_found": ";".join(c["categories"]),
            })

    # Automatically write data/security_attribution_mismatches.csv
    data_dir = Path(__file__).resolve().parent.parent.parent / "data"
    mismatch_csv = data_dir / "security_attribution_mismatches.csv"
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        with open(mismatch_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["case_id", "set", "family", "expected_agents", "agents_found", "expected_category", "categories_found"])
            for m in attribution_mismatches:
                writer.writerow([
                    m["id"],
                    m["set"],
                    m["family"],
                    m["expected_agents"],
                    m["agents_found"],
                    m["expected_category"],
                    m["categories_found"],
                ])
    except Exception:
        pass

    if env_block is None:
        env_block = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python_version": sys.version.split()[0],
            "os_version": f"{platform.system()} {platform.release()}",
            "compiler_version": "unavailable",
            "git_commit": "unavailable",
        }

    env_block["case_counts"] = {
        "total": len(case_results),
        "headline_cases": len(headline_cases),
        "standard_attacks": len(std_attacks),
        "hard_attacks": len(hard_attacks),
        "benign_cases": len(headline_benign),
        "scanner_evasion_cases": len(scanner_cases),
    }

    return {
        "manifest_summary": manifest_summary,
        "environment": env_block,
        "overall": overall_metrics,
        "by_set": set_metrics,
        "by_family": family_metrics,
        "by_agent": agent_metrics,
        "routing": routing_metrics,
        "latency": overall_latency,
        "risk_distribution": risk_by_family,
        "severity_counts": severity_counts,
        "blocked_by_category": blocked_by_category,
        "blocked_by_agent": blocked_by_agent,
        "known_misses": known_misses,
        "detected_not_prevented": detected_not_prevented,
        "attribution_mismatches": attribution_mismatches,
        "heal": heal_section,
        "cases": case_results,
        "benchmark_seconds": benchmark_seconds,
    }

