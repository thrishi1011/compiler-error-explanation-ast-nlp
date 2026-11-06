#!/usr/bin/env python3
"""
==============================================================================
Automated Evaluation Runner for Comprehensive Cases Suite (`cases/`)
==============================================================================
Runs the complete analysis pipeline across all 12 consolidated test cases in
`cases/` and outputs a comprehensive verification report.
==============================================================================
"""

import sys
from pathlib import Path

# Ensure 'src' is in python search path
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from main import run_pipeline
from security_healer import get_recipe

def evaluate_case(case_path: Path):
    print(f"\n[{'='*25} {case_path.name} {'='*25}]", flush=True)

    result, visible_errors, security_findings, guard_data, quality_data = run_pipeline(
        str(case_path), ai_enabled=False, verbose=False
    )

    err_count = result.get("error_count", 0)
    warn_count = result.get("warning_count", 0)
    print(f"  [Diagnostics] Compiler Errors: {err_count}, Warnings: {warn_count}", flush=True)
    print(f"  [Security]    Total Security Findings: {len(security_findings)}", flush=True)

    cwe_set = sorted(list({f.cwe_id for f in security_findings if getattr(f, "cwe_id", None)}))
    cert_set = sorted(list({f.cert_rule for f in security_findings if getattr(f, "cert_rule", None)}))
    capec_set = sorted(list({f.get("capec_id") for f in guard_data.get("findings", []) if f.get("capec_id")}))

    if cwe_set:
        print(f"  [Taxonomy]    CWE IDs:    {cwe_set}", flush=True)
    if cert_set:
        print(f"  [Taxonomy]    CERT Rules: {cert_set}", flush=True)
    if capec_set:
        print(f"  [Taxonomy]    CAPEC IDs:  {capec_set}", flush=True)

    # Automated Healing Recipe Matching
    healed_count = 0
    for finding in security_findings:
        cat = getattr(finding, "category", None)
        if not cat and hasattr(finding, "vulnerability_type"):
            cat = finding.vulnerability_type.lower().replace(" ", "_").replace("-", "_")
        recipe = get_recipe(cat) if cat else None
        if recipe:
            healed_count += 1
    print(f"  [Healer]      Auto-Healing Recipes: {healed_count}/{len(security_findings)} supported", flush=True)

    risk_label = guard_data.get("risk_label", "Clean")
    risk_score = guard_data.get("risk_score", 0)
    print(f"  [Guard]       Risk Assessment: {risk_label} (Score: {risk_score})", flush=True)

    return {
        "file": case_path.name,
        "diagnostics": err_count + warn_count,
        "findings": len(security_findings),
        "cwes": cwe_set,
        "certs": cert_set,
        "capecs": capec_set,
        "healed": healed_count,
        "risk_label": risk_label
    }

def main():
    cases_dir = ROOT / "cases"
    case_files = sorted(cases_dir.glob("case*.cpp"))

    print(f"Evaluating {len(case_files)} comprehensive test cases in {cases_dir}...", flush=True)
    results = []

    for case_file in case_files:
        try:
            res = evaluate_case(case_file)
            results.append(res)
        except Exception as e:
            print(f"  [ERROR] Failed to evaluate {case_file.name}: {e}", flush=True)

    # Print Summary Table
    print("\n" + "=" * 96, flush=True)
    print("                          COMPREHENSIVE TEST CASES SUMMARY TABLE")
    print("=" * 96, flush=True)
    print(f"{'Case File':<44} | {'Diags':<5} | {'Vulns':<5} | {'Risk Level':<10} | {'Standards'}", flush=True)
    print("-" * 96, flush=True)
    for r in results:
        std_tags = []
        if r["cwes"]:
            std_tags.extend(r["cwes"][:2])
        if r["certs"]:
            std_tags.extend(r["certs"][:1])
        if r["capecs"]:
            std_tags.extend(r["capecs"][:1])
        standards_summary = ", ".join(std_tags) if std_tags else "Compliant / Clean"
        print(f"{r['file']:<44} | {r['diagnostics']:<5} | {r['findings']:<5} | {r['risk_label']:<10} | {standards_summary}", flush=True)
    print("=" * 96, flush=True)

if __name__ == "__main__":
    main()
