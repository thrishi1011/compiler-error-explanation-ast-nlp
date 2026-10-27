#!/usr/bin/env python3

import argparse
import json
import os
import sys
import textwrap

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from compiler_runner import run_cpp_compiler
from error_parser import parse_errors
from error_explainer import enrich_error
from security_analyzer import analyze, format_security_report
from dataset_logger import log_example
from ast_extractor import extract_ast, extract_node_near_line

RED="\033[91m"
YELLOW="\033[93m"
GREEN="\033[92m"
BLUE="\033[95m"
BOLD="\033[1m"
RESET="\033[0m"


def _is_security_only_diagnostic(error) -> bool:
    message = (getattr(error, "message", "") or "").lower()
    error_type = (getattr(error, "error_type", "") or "").lower()
    return error_type == "warning" and (
        "unused variable" in message
        or "set but not used" in message
        or "declared but never used" in message
    )


def parse_arguments():
    parser=argparse.ArgumentParser(description="C++ Error Explanation Tool")
    parser.add_argument("source_file",help="C++ source file to compile")
    parser.add_argument("-j","--json",action="store_true",help="print output in JSON format")
    parser.add_argument("-v","--verbose",action="store_true",help="show detailed context")
    parser.add_argument("-c","--context",type=int, default=2,help="number of context lines")
    parser.add_argument("--ai",action="store_true",help="enable AI-powered error explanations")

    return parser.parse_args()


def print_error(error, verbose=False):
    etype=error.error_type.lower()

    if etype=="error":
        color=RED
    elif etype=="warning":
        color=YELLOW
    else:
        color=BLUE

    print(f"\n{color}{BOLD}{etype.upper()}:{error.message}{RESET}")

    if error.file:
        location=f"{error.file}"
        if error.line is not None:
            location+=f" (line {error.line}"
            if error.column is not None:
                location+=f", column {error.column}"
            location+=")"
        print(f"  {BLUE}Location:{RESET} {location}")

    if error.explanation:
        print(f"\n  {BLUE}{BOLD}Explanation:{RESET}")
        for block in error.explanation.split("\n\n"):
            wrapped = textwrap.fill(block, width=80)
            print(f"  {BLUE}{wrapped}{RESET}\n")

    if error.suggestion:
        print(f"\n  {GREEN}{BOLD}Suggestion:{RESET}")
        wrapped=textwrap.fill(error.suggestion,width=80)
        for line in wrapped.split("\n"):
            print(f"  {GREEN}{line}{RESET}")

    if hasattr(error, "security_risk"):
        print(f"\n  {YELLOW}{BOLD}Security Assessment:{RESET}")
        print(f"  {YELLOW}Risk Level: {error.security_risk}{RESET}")

        if error.risk_reason:
            print(f"  {YELLOW}{error.risk_reason}{RESET}")

    # Feature 2 — Second opinion
    second_text = getattr(error, "second_opinion_text", "")
    if second_text:
        print(f"\n  {BLUE}{BOLD}Second Opinion:{RESET}")
        for line in second_text.split("\n"):
            print(f"  {BLUE}{line}{RESET}")

    # Feature 1 — AI explanation
    ai = getattr(error, "ai_explanation", None)
    if ai and isinstance(ai, dict):
        provider_name = (ai.get("provider") or "AI").capitalize()
        print(f"\n  {GREEN}{BOLD}AI Explanation ({provider_name}):{RESET}")
        if ai.get("explanation"):
            wrapped = textwrap.fill(ai["explanation"], width=80)
            for line in wrapped.split("\n"):
                print(f"  {GREEN}{line}{RESET}")
        if ai.get("fix"):
            print(f"\n  {GREEN}{BOLD}Suggested Fix:{RESET}")
            for line in ai["fix"].split("\n"):
                print(f"  {GREEN}  {line}{RESET}")
        if ai.get("why"):
            print(f"\n  {GREEN}{BOLD}Why:{RESET}")
            wrapped = textwrap.fill(ai["why"], width=80)
            for line in wrapped.split("\n"):
                print(f"  {GREEN}{line}{RESET}")


    if verbose and error.context and "lines" in error.context:
        print(f"\n  {BOLD}Code Context:{RESET}")
        start=error.context["start_line"]

        for i,line in enumerate(error.context["lines"],start=start):
            marker="→" if i==error.line else " "
            print(f"  {marker} {i}: {line.rstrip()}")

    print()

def _get_vuln_why_explanation(vuln_type: str, desc: str) -> str:
    vt = (vuln_type or "").lower()
    if "overflow" in vt:
        return "In C++, signed integer overflow invokes undefined behavior; values wrap around to negative numbers or cause memory corruptions."
    if "underflow" in vt:
        return "Decrements on unsigned integers at zero wrap around to UINT_MAX (4,294,967,295), creating massive positive numbers that violate program invariants."
    if "division" in vt or "zero" in vt:
        return "Dividing by zero is mathematically undefined and triggers a fatal arithmetic exception (SIGFPE) that aborts the program immediately."
    if "null" in vt:
        return "Dereferencing a null pointer attempts to read or write address 0x0, triggering an immediate OS segmentation fault (SIGSEGV)."
    if "uninitialized" in vt:
        return "Local variables without initializers hold indeterminate garbage memory bytes, resulting in non-deterministic calculations and logic bugs."
    if "recursion" in vt:
        return "Recursive calls without a terminating base condition repeatedly consume stack frames until stack memory is exhausted (Stack Overflow)."
    if "bounds" in vt or "vector" in vt:
        return "Accessing elements outside valid container indices triggers undefined memory access or throws an unhandled std::out_of_range exception."
    if "free" in vt:
        return "Accessing memory after it has been deleted leaves the application vulnerable to heap corruption and remote code execution exploits."
    if "buffer" in vt:
        return "Unbounded input reads can overwrite adjacent stack or heap variables, smashing the stack and corrupting execution control flow."
    if "leak" in vt:
        return "Dynamically allocated memory is never freed before the scope exits, leaking system resources."
    return "This pattern represents unsafe C++ code that violates memory safety, typing, or arithmetic boundaries."


def finding_to_compiler_error(finding, source_file: str):
    from models import CompilerError
    src_lines = []
    try:
        with open(source_file, "r", encoding="utf-8", errors="replace") as f:
            src_lines = f.readlines()
    except Exception:
        pass

    line_no = finding.line or 1
    start_l = max(1, line_no - 2)
    end_l = min(len(src_lines), line_no + 2) if src_lines else line_no
    context = None
    if src_lines and 1 <= line_no <= len(src_lines):
        context = {
            "start_line": start_l,
            "lines": src_lines[start_l - 1:end_l],
        }

    vuln_type = finding.vulnerability_type
    sev = "error" if (finding.severity or "").lower() in ("critical", "high") else "warning"
    cat = vuln_type.lower().replace(" ", "_")

    explanation = (
        f"What happened:\n"
        f"{finding.description}\n\n"
        f"Why it happened:\n"
        f"{_get_vuln_why_explanation(vuln_type, finding.description)}\n\n"
        f"How to fix it:\n"
        f"{finding.recommendation}"
    )

    err = CompilerError(
        file=source_file,
        line=finding.line,
        column=finding.column or 1,
        error_type=sev,
        message=finding.description,
        raw=f"[{finding.severity.upper()}] {finding.description}",
        security_risk=(finding.severity or "Medium").upper(),
        risk_reason=finding.description,
        security_findings=[finding],
    )
    err.explanation = explanation
    err.suggestion = finding.recommendation
    err.category = cat
    err.confidence = 1.0
    err.context = context
    err.origin = "security"
    return err


def _print_guard_cli_report(guard_data: dict) -> None:
    print(f"\nSecurity level: {guard_data.get('risk_label', 'Clean')} (score {guard_data.get('risk_score', 0)})")
    for f in guard_data.get("findings", []):
        sev = (f.get("severity") or "Medium").upper()
        cat = f.get("category") or ""
        agents_str = ", ".join(f.get("agents") or [])
        line_str = f.get("line") if f.get("line") is not None else "?"
        act_str = "BLOCKED" if (f.get("action") == "block" or any(p in (f.get("blocks_on") or []) for p in ("compile", "run"))) else "WARN"
        print(f"[{sev}] {cat} | detected by {agents_str} | line {line_str} | {act_str}")


def _print_quality_cli_report(quality_data: dict) -> None:
    lvl = quality_data.get("level", "Good")
    hints = quality_data.get("hints", [])
    print(f"\nCode quality: {lvl} ({len(hints)} hints)")
    for h in hints:
        print(f"  [line {h.get('line', '?')}] {h.get('title', '')}: {h.get('message', '')} ({h.get('suggestion', '')})")


def main():
    args=parse_arguments()
    try:
        from guard.pathsafe import set_allowed_roots
        set_allowed_roots([os.path.dirname(os.path.abspath(args.source_file))])
    except Exception:
        pass

    src_text = ""
    try:
        with open(args.source_file, "r", encoding="utf-8", errors="replace") as sf:
            src_text = sf.read()
    except Exception:
        pass

    output=run_cpp_compiler(args.source_file)
    errors = parse_errors(output) if output else []

    try:
        from guard import get_supervisor, InputKind
        messages = [getattr(e, "message", "") or "" for e in errors]
        get_supervisor().review(
            InputKind.COMPILER_OUTPUT,
            "\n".join(messages),
            purpose="display",
            meta={"source": "compiler"},
        )
    except Exception:
        pass

    ast_text=extract_ast(args.source_file)

    for e in errors:
        if e.line:
            e.ast_node=extract_node_near_line(ast_text, e.line)
        else:
            e.ast_node=None
        enrich_error(e)
        log_example(e, source_text=src_text)

    security_findings = analyze(args.source_file, errors)
    for e in errors:
        if not getattr(e, "security_findings", None):
            e.security_findings = [
                finding for finding in security_findings
                if finding.source == "compiler_diagnostic"
                and finding.file == (e.file or "")
                and finding.line == e.line
            ]

    # Convert static security findings (not originating from compiler diagnostics) into diagnostic problem cards
    static_errors = [
        finding_to_compiler_error(finding, args.source_file)
        for finding in security_findings
        if finding.source != "compiler_diagnostic"
    ]
    all_diagnostics = errors + static_errors

    visible_errors = [e for e in all_diagnostics if not _is_security_only_diagnostic(e)]
    def _diagnostic_sort_key(e):
        etype = (getattr(e, "error_type", "") or "").lower()
        msg = (getattr(e, "message", "") or "").lower()
        is_minor = "statement has no effect" in msg
        is_priority = "no return statement" in msg or "return-type" in msg or etype == "error"
        return (0 if is_priority else (2 if is_minor else 1), e.line or 0)

    visible_errors.sort(key=_diagnostic_sort_key)
    visible_error_count = sum(1 for e in visible_errors if e.error_type == "error")
    visible_warning_count = sum(1 for e in visible_errors if e.error_type == "warning")

    # AI Explanation if enabled (--ai flag or ENABLE_LLM=1)
    ai_enabled = getattr(args, "ai", False) or os.environ.get("ENABLE_LLM") == "1"
    if ai_enabled and visible_errors:
        try:
            from ai_explainer import explain_errors_batch
            with open(args.source_file, "r", encoding="utf-8", errors="replace") as sf:
                src_code = sf.read()
            ai_results, provider, _ = explain_errors_batch(visible_errors, src_code)
            for idx, err in enumerate(visible_errors):
                if idx in ai_results:
                    err.ai_explanation = ai_results[idx]
        except Exception:
            pass

    # Build guard block (one source of truth)
    guard_data = {
        "risk_score": 0,
        "risk_label": "Clean",
        "blocked_purposes": [],
        "findings": [],
        "agents_run": [],
        "total_ms": 0.0,
    }
    try:
        from security_view import review_source_guard
        src_dir = os.path.dirname(os.path.abspath(args.source_file))
        fname = os.path.basename(args.source_file)
        guard_data = review_source_guard(src_text, source_dir=src_dir, file_name=fname)
    except Exception:
        pass

    # Build quality block (Phase 8b)
    quality_data = {"level": "Good", "score": 0, "hints": []}
    try:
        from quality_hints import analyze_quality
        quality_data = analyze_quality(src_text)
    except Exception:
        pass

    # JSON mode
    if args.json:
        overall_status = "error" if visible_error_count > 0 else ("warning" if visible_warning_count > 0 else "success")
        result={
            "status": overall_status,
            "file": args.source_file,
            "error_count": visible_error_count,
            "warning_count": visible_warning_count,
            "errors": [e.to_dict() for e in visible_errors],
            "security_findings": [finding.to_dict() for finding in security_findings],
            "security_report": format_security_report(security_findings),
            "guard": guard_data,
            "quality": quality_data,
        }

        print(json.dumps(result, indent=2))
        return 1 if visible_error_count > 0 else 0

    # Human readable output
    if not visible_errors:
        print("Compilation successful. 0 errors or warnings detected.")
        print()
        print(format_security_report(security_findings), end="")
        _print_guard_cli_report(guard_data)
        _print_quality_cli_report(quality_data)
        return 0

    print(f"\n{len(visible_errors)} issue(s) found:\n")
    error_count=0
    warning_count=0
    for e in visible_errors:
        if e.error_type=="error":
            error_count+=1
        elif e.error_type=="warning":
            warning_count+=1
        print_error(e,verbose=args.verbose)

    print(f"{error_count} error(s), {warning_count} warning(s)")
    print()
    print(format_security_report(security_findings), end="")
    _print_guard_cli_report(guard_data)
    _print_quality_cli_report(quality_data)
    return 1 if error_count > 0 else 0

if __name__ == "__main__":
    sys.exit(main())
