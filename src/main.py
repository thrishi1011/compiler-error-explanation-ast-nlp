#!/usr/bin/env python3

import argparse
import json
import os
import sys
import textwrap

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

def main():
    args=parse_arguments()
    output=run_cpp_compiler(args.source_file)
    if not output:
        security_findings = analyze(args.source_file, [])
        if args.json:
            print(json.dumps({
                "status": "success",
                "file": args.source_file,
                "security_findings": [finding.to_dict() for finding in security_findings],
                "security_report": format_security_report(security_findings),
            }, indent=2))
        else:
            print("Compilation successful")
            print()
            print(format_security_report(security_findings), end="")
        return 0

    errors=parse_errors(output)
    ast_text=extract_ast(args.source_file)

    for e in errors:

        if e.line:
            e.ast_node=extract_node_near_line(ast_text, e.line)
        else:
            e.ast_node=None

        enrich_error(e)
        log_example(e)

    security_findings = analyze(args.source_file, errors)
    for e in errors:
        if not getattr(e, "security_findings", None):
            e.security_findings = [
                finding for finding in security_findings
                if finding.source == "compiler_diagnostic"
                and finding.file == (e.file or "")
                and finding.line == e.line
            ]

    visible_errors = [e for e in errors if not _is_security_only_diagnostic(e)]
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

    #JSON mode


    if args.json:
        result={
            "status": "error" if visible_errors else "success",
            "file": args.source_file,
            "error_count": visible_error_count,
            "warning_count": visible_warning_count,
            "errors": [e.to_dict() for e in visible_errors],
            "security_findings": [finding.to_dict() for finding in security_findings],
            "security_report": format_security_report(security_findings),
        }

        print(json.dumps(result, indent=2))
        return 1 if visible_error_count > 0 else 0
    
    # Human readable output

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
    return 1 if error_count > 0 else 0

if __name__ == "__main__":
    sys.exit(main())
