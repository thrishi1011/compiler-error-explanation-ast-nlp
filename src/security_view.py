"""
src/security_view.py
--------------------
Pure view-model module for the security layer (Phase 8a).
No Qt imports. Fully testable in any environment.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Set

from guard.output_safe import safe_text


# ── Category titles and rationale ───────────────────────────────────────────

CATEGORY_TITLES: Dict[str, str] = {
    "bad_body": "Malformed body",
    "bad_content_type": "Invalid content type",
    "bad_host": "Untrusted Host header",
    "bad_json": "Malformed JSON",
    "bad_length": "Invalid content length",
    "bad_origin": "Unauthorized Origin",
    "bad_token": "Invalid session token",
    "body_too_large": "Oversized HTTP body",
    "buffer_overflow": "Buffer overflow",
    "cross_site_request": "Cross-site request forgery",
    "dataset_bad_category": "Invalid dataset category",
    "dataset_bad_message": "Invalid dataset message",
    "dataset_directive_message": "Directive in training message",
    "dataset_rate_limit": "Dataset ingestion rate limit",
    "dataset_secret": "Secret in dataset entry",
    "dataset_store_too_large": "Dataset store limit exceeded",
    "destructive_file_op": "Destructive file operation",
    "disabled_safety_check": "Disabled safety check",
    "display_injection": "Display injection",
    "double_free": "Double free",
    "dynamic_loading": "Dynamic library loading",
    "encoded_payload": "Encoded payload",
    "guard_error": "Guard agent error",
    "hardcoded_secret": "Hardcoded secret",
    "hidden_prompt_unicode": "Hidden prompt Unicode",
    "hidden_unicode": "Hidden Unicode character",
    "huge_allocation": "Excessive memory allocation",
    "inline_assembly": "Inline assembly",
    "macro_expansion_bomb": "Macro expansion bomb",
    "missing_length": "Missing Content-Length",
    "model_hash_mismatch": "Model signature mismatch",
    "model_manifest_missing": "Missing model manifest",
    "model_outside_data_dir": "Model path traversal",
    "model_too_large": "Oversized model file",
    "network_access": "Network access",
    "obfuscation": "Code obfuscation",
    "oversized_input": "Oversized input",
    "patch_comments_out_code": "Patch comments out code",
    "patch_injection_text": "Patch prompt injection",
    "patch_introduces_dangerous_code": "Dangerous patch code",
    "patch_marker_leak": "Patch marker leak",
    "patch_new_include": "Prohibited include in patch",
    "patch_removes_guard": "Patch disables guard",
    "patch_secret": "Secret introduced in patch",
    "patch_security_downgrade": "Security downgrade in patch",
    "patch_suppresses_diagnostics": "Suppressed diagnostic in patch",
    "patch_too_large": "Oversized patch",
    "personal_data_access": "Personal data access",
    "policy_bypass_request": "Policy bypass request",
    "possible_infinite_loop": "Infinite loop risk",
    "potential_memory_leak": "Potential memory leak",
    "process_execution": "Process execution",
    "prompt_injection": "Prompt injection",
    "role_marker": "Role marker injection",
    "secret_env_access": "Environment secret access",
    "sensitive_file_access": "Sensitive file access",
    "sensitive_include": "Sensitive system include",
    "special_file_include": "Special file inclusion",
    "spoofed_status": "Spoofed status",
    "startup_code": "Custom startup code",
    "terminal_escape": "Terminal escape sequence",
    "tool_secret_value": "Tool secret exposed",
    "unsafe_include": "Unsafe include path",
    "unsafe_string_function": "Unsafe string function",
    "unsupported_encoding": "Unsupported encoding",
}

CATEGORY_WHY: Dict[str, str] = {
    "bad_body": "Invalid HTTP request body can cause unexpected server parsing errors or crashes.",
    "bad_content_type": "Unrecognized or missing Content-Type header violates HTTP protocol specifications.",
    "bad_host": "Unrecognized Host header may indicate a DNS rebinding or host header injection attack.",
    "bad_json": "Corrupted or non-standard JSON payload can crash parsers or desynchronize state.",
    "bad_length": "Mismatched or invalid Content-Length header can cause HTTP request smuggling or buffer desync.",
    "bad_origin": "Cross-origin requests from unapproved origins violate Same-Origin policy.",
    "bad_token": "Requests lacking a valid authentication token are rejected to protect internal services.",
    "body_too_large": "Excessive request body size can exhaust server memory or trigger denial of service.",
    "buffer_overflow": "Unbounded memory writes can overwrite adjacent memory and hijack control flow.",
    "cross_site_request": "Cross-site requests can trick authenticated endpoints into executing unauthorized actions.",
    "dataset_bad_category": "Unrecognized dataset category corrupts training taxonomy and data integrity.",
    "dataset_bad_message": "Malformed message structure in dataset entry corrupts training corpus.",
    "dataset_directive_message": "System or instruction directives inside dataset messages can cause instruction drift.",
    "dataset_rate_limit": "Exceeding dataset ingestion rate can degrade system responsiveness or exhaust storage.",
    "dataset_secret": "Exposing API keys, passwords, or credentials in datasets risks credential leakage.",
    "dataset_store_too_large": "Accumulating excessive dataset entries exhausts disk storage and memory.",
    "destructive_file_op": "Deleting or wiping files can permanently destroy user data or system integrity.",
    "disabled_safety_check": "Bypassing safety pragmas or security flags compromises runtime protections.",
    "display_injection": "Embedded HTML or control characters can hijack display renderers.",
    "double_free": "Deallocating previously freed memory leads to memory corruption and exploitable vulnerabilities.",
    "dynamic_loading": "Loading arbitrary dynamic libraries enables untrusted code execution.",
    "encoded_payload": "Hex, octal, or obfuscated encodings can hide malicious operations from static scanners.",
    "guard_error": "An internal guard agent encountered an error during security analysis.",
    "hardcoded_secret": "Embedding credentials or tokens directly in source code risks leak and compromise.",
    "hidden_prompt_unicode": "Invisible or bidirectional Unicode characters can hide instructions from human review.",
    "hidden_unicode": "Hidden or directional formatting Unicode characters can spoof logic or disguise attacks.",
    "huge_allocation": "Allocating massive blocks of memory can exhaust heap resources and crash the host.",
    "inline_assembly": "Inline assembly bypasses compiler safety checks and allows arbitrary CPU execution.",
    "macro_expansion_bomb": "Deeply nested or recursive macros can exhaust compiler memory and freeze the tool.",
    "missing_length": "Missing Content-Length on state-changing requests violates HTTP/1.1 safety contracts.",
    "model_hash_mismatch": "Model file hash differs from recorded signature, indicating tampering or corruption.",
    "model_manifest_missing": "Absence of a cryptographic manifest prevents verification of model integrity.",
    "model_outside_data_dir": "Attempting to load models outside approved directories risks path traversal.",
    "model_too_large": "Model file exceeds size limits and risks exhausting host memory.",
    "network_access": "Opening network sockets can enable unauthorized connections or data exfiltration.",
    "obfuscation": "Concealed or scrambled code structures hinder security auditing and disguise threats.",
    "oversized_input": "Payload exceeds allowed size bounds and may cause resource exhaustion.",
    "patch_comments_out_code": "Commenting out critical logic compromises program correctness and hides bugs.",
    "patch_injection_text": "Patch introduces instructions intended to influence or hijack downstream LLMs.",
    "patch_introduces_dangerous_code": "Patch introduces system calls, subprocesses, or prohibited operations.",
    "patch_marker_leak": "Patch exposes internal control markers or secret boundary tokens.",
    "patch_new_include": "Patch adds new external header inclusions that expand attack surface.",
    "patch_removes_guard": "Patch attempts to remove, disable, or bypass security guard checks.",
    "patch_secret": "Patch attempts to insert hardcoded credentials or secret values.",
    "patch_security_downgrade": "Patch weakens compiler warnings, disables mitigations, or lowers safety flags.",
    "patch_suppresses_diagnostics": "Patch suppresses compiler diagnostic warnings without fixing the root cause.",
    "patch_too_large": "Patch diff exceeds acceptable modification bounds.",
    "personal_data_access": "Accessing sensitive user information or personal directories violates privacy boundaries.",
    "policy_bypass_request": "Input attempts to override or disable established guard policies.",
    "possible_infinite_loop": "Unbounded loop condition without progress guarantees can hang execution.",
    "potential_memory_leak": "Allocated resources or memory are not safely freed on all execution paths.",
    "process_execution": "Spawning shell commands or subprocesses can lead to arbitrary code execution.",
    "prompt_injection": "Malicious text intended to override system prompts or deceive AI models.",
    "role_marker": "Role marker injection can hijack conversational AI flow.",
    "secret_env_access": "Reading sensitive environment variables risks leaking API keys or secrets.",
    "sensitive_file_access": "Reading system configuration or password files compromises host security.",
    "sensitive_include": "Including internal or privileged platform headers exposes unsafe low-level APIs.",
    "special_file_include": "Including device files or non-regular paths can hang or corrupt IO.",
    "spoofed_status": "Crafted response tries to falsify operational or security status.",
    "startup_code": "Running code during static initialization can execute unauthorized logic before main.",
    "terminal_escape": "ANSI escape codes in text can spoof terminal UI or alter display output.",
    "tool_secret_value": "Internal tool secret or credential detected in data flow.",
    "unsafe_include": "Including external files outside project boundaries risks path traversal.",
    "unsafe_string_function": "Using unchecked string functions like strcpy or sprintf risks buffer overflows.",
    "unsupported_encoding": "Non-standard character encoding can bypass filters and corrupt processing.",
}

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def get_category_title(category: str) -> str:
    """Return a short human title for the given category, with fallback."""
    cat = category or ""
    return CATEGORY_TITLES.get(cat, cat.replace("_", " ").title() if cat else "Security Finding")


def get_category_why(category: str) -> str:
    """Return one plain sentence explaining why the category is dangerous, with fallback."""
    cat = category or ""
    return CATEGORY_WHY.get(cat, "This pattern poses potential security or operational risks and should be remediated.")


# ── View Builders ───────────────────────────────────────────────────────────

def build_security_summary(guard: dict) -> dict:
    """
    Build a security summary dictionary for UI display.
    Keys: level, score, tone, counts, total, agents, blocked_purposes, headline.
    """
    guard_dict = guard or {}
    level = guard_dict.get("risk_label", "Clean")
    score = int(guard_dict.get("risk_score", 0))

    if level in ("Clean", "Low Risk"):
        tone = "ok"
    elif level == "Moderate":
        tone = "warn"
    else:
        tone = "error"

    findings = guard_dict.get("findings", [])
    counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    agents_set: Set[str] = set()

    for f in findings:
        sev = str(f.get("severity", "Medium")).capitalize()
        if sev in counts:
            counts[sev] += 1
        for a in f.get("agents", []) or []:
            if a:
                agents_set.add(a)

    total = len(findings)
    agents = sorted(list(agents_set))
    blocked_purposes = list(guard_dict.get("blocked_purposes", []))

    if total == 0:
        headline = "Clean, 0 findings"
    else:
        lvl_str = f"{level} risk" if "risk" not in level.lower() else level
        f_word = "finding" if total == 1 else "findings"
        if agents:
            headline = f"{lvl_str}, {total} {f_word}, detected by {', '.join(agents)}"
        else:
            headline = f"{lvl_str}, {total} {f_word}"

    return {
        "level": level,
        "score": score,
        "risk_label": level,
        "risk_score": score,
        "tone": tone,
        "counts": counts,
        "total": total,
        "agents": agents,
        "blocked_purposes": blocked_purposes,
        "headline": headline,
    }


def finding_view(f: dict, current_purposes: Optional[Any] = None) -> dict:
    """
    Build a single finding view-model.
    All text fields are sanitized plain text.
    """
    f = f or {}
    cat = f.get("category", "")
    title = f.get("title") or get_category_title(cat)

    sev_raw = f.get("severity", "Medium")
    severity = str(sev_raw).capitalize() if sev_raw else "Medium"
    if severity not in _SEVERITY_ORDER:
        severity = "Medium"

    if severity in ("Critical", "High"):
        tone = "error"
    elif severity == "Medium":
        tone = "warn"
    else:
        tone = "muted"

    line = f.get("line")
    agents = list(f.get("agents", []) or [])
    if agents:
        detected_by = f"Detected by {', '.join(agents)}"
    else:
        detected_by = "Detected by Security Guard"

    origin = f.get("origin", "attack")
    kind_label = "Attack on the tool" if origin == "attack" else "Weakness in your code"

    # Action label: BLOCKED when finding blocks the current purposes, else WARNING (INFO for Low)
    blocks_on = f.get("blocks_on")
    if blocks_on is None:
        blocks_on_set = set()
    elif isinstance(blocks_on, (set, list, tuple)):
        blocks_on_set = set(blocks_on)
    else:
        blocks_on_set = {str(blocks_on)}

    if current_purposes is not None:
        target_purposes = set(current_purposes)
    else:
        target_purposes = {"compile", "run"}

    is_blocked = (f.get("action") == "block") or bool(blocks_on_set & target_purposes)
    if is_blocked:
        action_label = "BLOCKED"
    elif severity == "Low":
        action_label = "INFO"
    else:
        action_label = "WARNING"

    what = safe_text(str(f.get("description", "")))
    why = get_category_why(cat)
    how = safe_text(str(f.get("recommendation", "")))
    evidence = safe_text(str(f.get("evidence", "")))

    return {
        "title": title,
        "severity": severity,
        "tone": tone,
        "line": line,
        "agents": agents,
        "detected_by": detected_by,
        "kind_label": kind_label,
        "action_label": action_label,
        "what": what,
        "why": why,
        "how": how,
        "evidence": evidence,
    }


def sort_findings(findings: list) -> list:
    """Sort findings by severity (Critical first), then line number."""
    def _key(item: dict) -> tuple:
        sev = str(item.get("severity", "Medium")).capitalize()
        s_rank = _SEVERITY_ORDER.get(sev, 2)
        l_num = item.get("line")
        line_rank = l_num if (l_num is not None and isinstance(l_num, int)) else 0
        return (s_rank, line_rank)

    return sorted(findings or [], key=_key)


def heal_security_view(security: Optional[dict]) -> Optional[dict]:
    """
    Build a view-model for the security section of the auto-heal result.
    Returns None when security is missing or empty.
    """
    if not security or not isinstance(security, dict):
        return None

    risk_before = int(security.get("risk_before", 0))
    risk_after = int(security.get("risk_after", 0))
    label_before = security.get("label_before", "Clean")
    label_after = security.get("label_after", "Clean")

    headline = f"Security: {label_before} ({risk_before}) -> {label_after} ({risk_after})"
    if label_after in ("Clean", "Low Risk"):
        tone = "ok"
    elif label_after == "Moderate":
        tone = "warn"
    else:
        tone = "error"

    outcomes = security.get("outcomes", []) or []
    applied_raw = security.get("applied", []) or []
    suggestions_raw = security.get("suggestions", []) or []
    findings_after_raw = security.get("findings_after", []) or []

    # Map category/line to agent attribution
    cat_agents: Dict[str, list] = {}
    for o in outcomes:
        c = o.get("category")
        if c and o.get("agents"):
            cat_agents[c] = list(o.get("agents"))
    for fb in (security.get("findings_before", []) or []):
        c = fb.get("category")
        if c and fb.get("agents"):
            cat_agents[c] = list(fb.get("agents"))

    if outcomes:
        fixed_count = sum(1 for o in outcomes if o.get("status") == "fixed")
        suggested_count = sum(1 for o in outcomes if o.get("status") in ("suggested", "manual"))
        skipped_count = sum(1 for o in outcomes if o.get("status") in ("skipped_behavior", "skipped"))
        rejected_count = sum(1 for o in outcomes if o.get("status") == "rejected")
    else:
        fixed_count = len(applied_raw)
        suggested_count = len(suggestions_raw)
        skipped_count = 0
        rejected_count = 0

    remaining_count = len(findings_after_raw)

    counts = {
        "fixed": fixed_count,
        "suggested": suggested_count,
        "skipped": skipped_count,
        "rejected": rejected_count,
        "remaining": remaining_count,
    }

    applied = []
    for fix in applied_raw:
        cat = fix.get("finding_category", "")
        title = get_category_title(cat)
        line = fix.get("line")
        agents = cat_agents.get(cat, [])
        det_by = f"Detected by {', '.join(agents)}" if agents else "Detected by ExecGuard"
        applied.append({
            "title": title,
            "line": line,
            "before": safe_text(str(fix.get("before", ""))),
            "after": safe_text(str(fix.get("after", ""))),
            "safety_class": fix.get("safety_class", "auto"),
            "detected_by": det_by,
        })

    suggestions = []
    for s in suggestions_raw:
        cat = s.get("finding_category", "")
        title = get_category_title(cat)
        line = s.get("line")
        agents = cat_agents.get(cat, [])
        det_by = f"Detected by {', '.join(agents)}" if agents else "Detected by Security Guard"
        suggestions.append({
            "title": title,
            "line": line,
            "text": safe_text(str(s.get("description", ""))),
            "detected_by": det_by,
        })

    remaining = [finding_view(f) for f in findings_after_raw]

    return {
        "headline": headline,
        "tone": tone,
        "counts": counts,
        "applied": applied,
        "suggestions": suggestions,
        "remaining": remaining,
    }


def blocked_banner_view(findings: list, purpose: str) -> dict:
    """
    Build a view-model for the blocked banner.
    Title: e.g. "Run blocked by the security layer" or "Compile blocked by the security layer".
    """
    p_name = purpose.capitalize() if purpose else "Execution"
    title = f"{p_name} blocked by the security layer"
    fviews = [finding_view(f, current_purposes=[purpose]) for f in findings or []]
    return {
        "title": title,
        "purpose": purpose,
        "findings": fviews,
    }


# ── Guard Review Helper ─────────────────────────────────────────────────────

def review_source_guard(source: str, source_dir: str = "", file_name: str = "") -> dict:
    """
    Execute supervisor reviews for USER_SOURCE and return the complete guard block.
    Computes blocked_purposes with two fast extra reviews (purpose="compile" and purpose="run", include_vulnerability=False).
    Never raises.
    """
    from guard import get_supervisor, InputKind

    meta: Dict[str, Any] = {}
    if source_dir:
        meta["source_dir"] = source_dir
    if file_name:
        meta["file_name"] = file_name

    sup = get_supervisor()
    try:
        v_analyze = sup.review(InputKind.USER_SOURCE, source, purpose="analyze", meta=meta)
    except Exception:
        return {
            "risk_score": 0,
            "risk_label": "Clean",
            "blocked_purposes": [],
            "findings": [],
            "agents_run": [],
            "total_ms": 0.0,
        }

    blocked_purposes: List[str] = []
    try:
        v_compile = sup.review(
            InputKind.USER_SOURCE, source, purpose="compile", meta=meta, include_vulnerability=False
        )
        if v_compile.blocked:
            blocked_purposes.append("compile")
    except Exception:
        pass

    try:
        v_run = sup.review(
            InputKind.USER_SOURCE, source, purpose="run", meta=meta, include_vulnerability=False
        )
        if v_run.blocked:
            blocked_purposes.append("run")
    except Exception:
        pass

    agents_run = [r["agent"] for r in getattr(v_analyze, "routing", [])] if getattr(v_analyze, "routing", None) else []
    # Deduplicate preserving order
    unique_agents = list(dict.fromkeys(agents_run))

    return {
        "risk_score": v_analyze.risk_score,
        "risk_label": v_analyze.risk_label,
        "blocked_purposes": blocked_purposes,
        "findings": [f.to_dict() for f in v_analyze.findings],
        "agents_run": unique_agents,
        "total_ms": round(float(v_analyze.total_ms), 3),
    }


# ── Agent Roles and Summary ──────────────────────────────────────────────────

AGENT_ROLES: Dict[str, str] = {
    "ExecGuard": "Monitors process spawning, system calls, and unsafe execution.",
    "ResourceGuard": "Detects algorithmic complexity bombs and resource exhaustion.",
    "OutputGuard": "Neutralizes display injections, ANSI escapes, and format attacks.",
    "EndpointGuard": "Validates HTTP headers, origins, tokens, and endpoint abuse.",
    "SecretsGuard": "Scans for API keys, tokens, credentials, and sensitive paths.",
    "IntegrityGuard": "Verifies model signature, weights, and dataset integrity.",
    "PromptGuard": "Detects prompt injection and adversarial instructions in comments.",
    "PatchGuard": "Audits AI-generated patches for malicious code and new includes.",
    "VulnGuard": "Static sanitizer for memory safety, buffer overflows, and unsafe C APIs.",
}


def get_agent_role(name: str) -> str:
    """Returns a concise description of an agent's security purpose."""
    return AGENT_ROLES.get(name, f"Security inspector for {name}.")


def build_agent_rows(
    agents_info: List[Dict[str, Any]],
    guard: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Builds rows for the Security Agents tab given registered agent introspections
    and the latest guard review results.
    """
    guard = guard or {}
    agents_run = set(guard.get("agents_run") or [])
    findings = guard.get("findings") or []
    timings = guard.get("timings_ms") or {}

    findings_per_agent: Dict[str, List[dict]] = {}
    for f in findings:
        for ag in f.get("agents") or []:
            findings_per_agent.setdefault(ag, []).append(f)

    rows: List[Dict[str, Any]] = []
    for info in agents_info:
        name = info.get("name", "")
        handles = info.get("handles", [])
        role = get_agent_role(name)

        did_run = name in agents_run
        ag_findings = findings_per_agent.get(name, [])
        f_count = len(ag_findings)
        is_blocked = any(f.get("action") == "block" for f in ag_findings)
        ms = timings.get(name)

        if not did_run:
            status = "skipped (no signal)"
            live_findings = 0
            live_blocked = False
            live_ms = 0.0
        else:
            status = "active"
            live_findings = f_count
            live_blocked = is_blocked
            live_ms = float(ms) if ms is not None else 0.0

        rows.append({
            "name": name,
            "role": role,
            "handles": handles,
            "did_run": did_run,
            "status": status,
            "findings_count": live_findings,
            "blocked": live_blocked,
            "ms": live_ms,
        })
    return rows


# ── Attack Log View ──────────────────────────────────────────────────────────

def load_attack_log(path: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    """
    Reads only the tail of the attack log file efficiently (never the whole file).
    Skips corrupt lines and returns [] if the file does not exist.
    """
    if path is None:
        path = os.environ.get("GUARD_LOG_PATH", os.path.join("data", "attack_log.jsonl"))

    if not os.path.exists(path):
        return []

    try:
        file_size = os.path.getsize(path)
        if file_size == 0:
            return []

        chunk_size = 8192
        with open(path, "rb") as f:
            if file_size <= chunk_size * 2:
                data = f.read().decode("utf-8", errors="replace")
                raw_lines = data.splitlines()
            else:
                pos = file_size
                buf = b""
                while pos > 0:
                    read_len = min(chunk_size, pos)
                    pos -= read_len
                    f.seek(pos)
                    chunk = f.read(read_len)
                    buf = chunk + buf
                    if buf.count(b"\n") > limit + 10:
                        break
                raw_lines = buf.decode("utf-8", errors="replace").splitlines()

        valid_lines = raw_lines[1:] if (file_size > chunk_size * 2 and pos > 0) else raw_lines

        rows: List[Dict[str, Any]] = []
        for line in valid_lines:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                obj = json.loads(line_str)
                if isinstance(obj, dict):
                    rows.append(obj)
            except Exception:
                continue

        return rows[-limit:] if len(rows) > limit else rows
    except Exception:
        return []


def summarize_attack_log(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregates attack log entries into action counts, agent counts,
    and category frequencies.
    """
    action_counts: Dict[str, int] = {}
    agent_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}

    for row in rows:
        act = row.get("action", "unknown")
        action_counts[act] = action_counts.get(act, 0) + 1

        for ag in row.get("agents") or []:
            agent_counts[ag] = agent_counts.get(ag, 0) + 1

        for cat in row.get("categories") or []:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    top_categories = sorted(category_counts.items(), key=lambda x: (-x[1], x[0]))[:5]

    return {
        "total": len(rows),
        "blocked": action_counts.get("block", 0),
        "logged": action_counts.get("log", 0),
        "actions": action_counts,
        "agents": agent_counts,
        "by_agent": agent_counts,
        "categories": category_counts,
        "by_category": category_counts,
        "top_categories": top_categories,
    }


# ── Benchmark View ───────────────────────────────────────────────────────────

def benchmark_view(metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Transforms security benchmark results (committed JSON or live run)
    into formatted display dictionaries, tolerating missing keys.
    """
    metrics = metrics or {}
    overall = metrics.get("overall") or {}
    by_set = metrics.get("by_set") or {}
    by_family = metrics.get("by_family") or {}
    by_agent = metrics.get("by_agent") or {}
    latency = metrics.get("latency") or {}
    routing = metrics.get("routing") or {}
    env = metrics.get("environment") or {}
    heal = metrics.get("heal") or {}

    std = overall.get("standard_detection") or by_set.get("standard", {}).get("detection_rate") or {}
    std_cnt = std.get("count", 0)
    std_tot = std.get("total", 0)
    std_rate = std.get("rate", (std_cnt / std_tot) if std_tot > 0 else 0.0)
    std_ci = std.get("ci_95", [0.0, 0.0])

    hard = overall.get("hard_detection") or by_set.get("hard", {}).get("detection_rate") or {}
    hard_cnt = hard.get("count", 0)
    hard_tot = hard.get("total", 0)
    hard_rate = hard.get("rate", (hard_cnt / hard_tot) if hard_tot > 0 else 0.0)
    hard_ci = hard.get("ci_95", [0.0, 0.0])

    asr_n = overall.get("asr_attacks", 0)
    base_asr = overall.get("baseline_asr", 0.0)
    if isinstance(base_asr, dict):
        base_asr = base_asr.get("rate", 0.0)
    def_asr = overall.get("defended_asr", 0.0)
    if isinstance(def_asr, dict):
        def_asr = def_asr.get("rate", 0.0)

    fa = overall.get("false_alert_rate") or {}
    fa_cnt = fa.get("count", 0)
    fa_tot = fa.get("total", 0)
    fa_rate = fa.get("rate", (fa_cnt / fa_tot) if fa_tot > 0 else 0.0)
    fa_ci = fa.get("ci_95", [0.0, 0.0])

    med_lat = latency.get("median")
    if med_lat is not None and isinstance(med_lat, (int, float)):
        med_lat_str = f"{med_lat:.2f} ms"
    elif med_lat is not None:
        med_lat_str = str(med_lat)
    else:
        med_lat_str = "N/A"

    routing_misses = routing.get("routing_misses", routing.get("misses", 0))
    asr_str = f"{base_asr * 100:.1f}% -> {def_asr * 100:.1f}%" + (f" ({asr_n})" if asr_n > 0 else "")

    families_data = []
    for fam_name, fam_val in sorted(by_family.items()):
        b_asr = fam_val.get("baseline_asr", 0.0)
        d_asr = fam_val.get("defended_asr", 0.0)
        families_data.append({
            "family": fam_name,
            "title": CATEGORY_TITLES.get(fam_name, fam_name.replace("_", " ").title()),
            "baseline_asr": b_asr,
            "defended_asr": d_asr,
            "attacks": fam_val.get("attacks", 0),
            "detected": fam_val.get("detected", 0),
            "prevented": fam_val.get("prevented", 0),
        })

    agents_data = []
    for ag_name, ag_val in sorted(by_agent.items()):
        rec = ag_val.get("recall") or {}
        prec = ag_val.get("precision", 0.0)
        fa_ag = ag_val.get("false_alert_rate")
        agents_data.append({
            "agent": ag_name,
            "recall": rec.get("rate", 0.0),
            "recall_count": rec.get("count", 0),
            "recall_total": rec.get("total", 0),
            "false_alert": fa_ag.get("rate") if isinstance(fa_ag, dict) else fa_ag,
            "precision": prec,
        })

    ts = env.get("timestamp")
    source_line = f"Source: committed results generated {ts}" if ts else "Source: in-memory live run"

    how_to_read = metrics.get("how_to_read") or (
        "1. Coverage vs. Generalisation: Standard attacks measure known pattern coverage; hard attacks evaluate realistic evasion resistance.\n"
        "2. Benign Set Uncertainty: Zero observed false alerts carries an upper 95% Wilson confidence bound of ~11.0%.\n"
        "3. Scope of Baseline Model: Evaluates against original IDE rules, not third-party tools.\n"
        "4. Security Healing Scope: Evaluated on prepared compilable samples, not arbitrary unconstrained legacy codebases."
    )

    return {
        "headlines": {
            "standard_detection_count": std_cnt,
            "standard_detection_total": std_tot,
            "standard_detection_rate": std_rate,
            "standard_detection_ci": std_ci,
            "standard_detection": f"{std_rate * 100:.1f}% ({std_cnt}/{std_tot}) [{std_ci[0]*100:.1f}%, {std_ci[1]*100:.1f}%]" if std_tot > 0 else "N/A",

            "hard_detection_count": hard_cnt,
            "hard_detection_total": hard_tot,
            "hard_detection_rate": hard_rate,
            "hard_detection_ci": hard_ci,
            "hard_detection": f"{hard_rate * 100:.1f}% ({hard_cnt}/{hard_tot}) [{hard_ci[0]*100:.1f}%, {hard_ci[1]*100:.1f}%]" if hard_tot > 0 else "N/A",

            "attack_success_rate": asr_str,
            "baseline_asr": base_asr,
            "baseline_asr_text": f"{base_asr * 100:.1f}%" + (f" ({int(round(base_asr * asr_n))}/{asr_n})" if asr_n > 0 else ""),
            "defended_asr": def_asr,
            "defended_asr_text": f"{def_asr * 100:.1f}%" + (f" ({int(round(def_asr * asr_n))}/{asr_n})" if asr_n > 0 else ""),

            "false_alerts_count": fa_cnt,
            "false_alerts_total": fa_tot,
            "false_alerts_rate": fa_rate,
            "false_alerts_ci_upper": fa_ci[1] if len(fa_ci) > 1 else 0.0,
            "false_alerts": f"{fa_rate * 100:.1f}% ({fa_cnt}/{fa_tot}) [≤ {fa_ci[1]*100:.1f}%]" if fa_tot > 0 else "N/A",

            "median_latency": med_lat_str,
            "median_latency_ms": med_lat,
            "median_latency_text": med_lat_str,

            "routing_misses": routing_misses,
            "routing_misses_text": str(routing_misses),
        },
        "families": families_data,
        "agents": agents_data,
        "known_misses": metrics.get("known_misses") or [],
        "detected_not_prevented": metrics.get("detected_not_prevented") or [],
        "scanner_evasion": metrics.get("manifest_summary", {}).get("scanner_evasion_attacks", 0),
        "healing_summary": heal.get("totals") or {},
        "source_line": source_line,
        "how_to_read": how_to_read,
    }
