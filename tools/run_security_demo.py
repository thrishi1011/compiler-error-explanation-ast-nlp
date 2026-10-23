"""
tools/run_security_demo.py
--------------------------
Headless self-check running security reviews and quality inspections across
the committed demo kit (test_cases/security_demo/).
Never executes or compiles binaries. Mocks external LLM calls.
Prints a formatted verification table and exits with code 0 on success.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

# Ensure src in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _PROJECT_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from guard import get_supervisor, InputKind
from quality_hints import analyze_quality


def run_demo() -> int:
    demo_dir = _PROJECT_ROOT / "test_cases" / "security_demo"
    expected_file = demo_dir / "expected.json"

    if not expected_file.exists():
        print(f"[ERROR] expected.json not found at {expected_file}")
        return 1

    with open(expected_file, "r", encoding="utf-8") as f:
        expected_data = json.load(f)

    # Standard security environment baseline
    os.environ["ALLOW_SYSTEM_CALLS"] = "0"
    os.environ["ALLOW_ASSEMBLY"] = "0"
    os.environ["ALLOW_SYS_INCLUDES"] = "0"
    os.environ["ALLOW_EXTERNAL_INCLUDES"] = "0"

    supervisor = get_supervisor()

    col_w_file = 25
    col_w_exp = 30
    col_w_act = 30
    col_w_status = 6

    header = (
        f"{'File':<{col_w_file}} | "
        f"{'Expected (Risk / Blocked / Q)':<{col_w_exp}} | "
        f"{'Actual (Risk / Blocked / Q)':<{col_w_act}} | "
        f"{'Status':<{col_w_status}}"
    )
    separator = "-" * len(header)
    print("\nSecurity Demo Kit Headless Self-Check")
    print(separator)
    print(header)
    print(separator)

    all_ok = True
    call_count = 0

    # Ensure no network LLM calls can be made
    with patch("llm_client.ask", side_effect=RuntimeError("Real LLM call attempted!")):
        for filename, exp in sorted(expected_data.items()):
            file_path = demo_dir / filename
            if not file_path.exists():
                print(f"{filename:<{col_w_file}} | [FILE MISSING] | FAIL")
                all_ok = False
                continue

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                code_content = f.read()

            kind_str = exp.get("input_kind", "USER_SOURCE")
            purpose = exp.get("purpose", "analyze")
            kind = getattr(InputKind, kind_str, InputKind.USER_SOURCE)

            # Single review call per file (at most 9 supervisor calls overall)
            call_count += 1
            verdict = supervisor.review(kind, code_content, purpose=purpose)

            # Derive blocked purposes
            blocked_purposes = set()
            for finding in verdict.findings:
                if finding.blocks_on:
                    blocked_purposes.update(finding.blocks_on)
                elif finding.action == "block":
                    if finding.category in ("process_execution", "inline_assembly"):
                        blocked_purposes.add("run")
                    elif finding.category in ("sensitive_include", "macro_expansion_bomb"):
                        blocked_purposes.update(["compile", "run"])
                    else:
                        blocked_purposes.update(["compile", "run"])

            if verdict.blocked and purpose:
                blocked_purposes.add(purpose)

            sorted_blocked = sorted(list(blocked_purposes))
            q_res = analyze_quality(code_content)

            act_risk = verdict.risk_label
            act_blocked = sorted_blocked
            act_quality = q_res["level"]
            act_agents = sorted(list(set(a for f in verdict.findings for a in f.agents)))

            exp_risk = exp.get("risk_label", "Clean")
            exp_blocked = sorted(exp.get("blocked_purposes", []))
            exp_quality = exp.get("quality_level", "Good")
            exp_agents = sorted(exp.get("agents", []))

            # Match criteria
            risk_match = (act_risk == exp_risk)
            blocked_match = (set(act_blocked) == set(exp_blocked))
            quality_match = (act_quality == exp_quality)
            agents_match = (set(act_agents) == set(exp_agents))

            file_ok = risk_match and blocked_match and quality_match and agents_match
            if not file_ok:
                all_ok = False

            exp_str = f"{exp_risk} / {exp_blocked} / {exp_quality}"
            act_str = f"{act_risk} / {act_blocked} / {act_quality}"
            status_str = "OK" if file_ok else "FAIL"

            print(
                f"{filename:<{col_w_file}} | "
                f"{exp_str:<{col_w_exp}} | "
                f"{act_str:<{col_w_act}} | "
                f"{status_str:<{col_w_status}}"
            )

    print(separator)
    print(f"Total supervisor review calls: {call_count} (max allowed: 9)")
    if call_count > 9:
        print("[FAIL] More than 9 supervisor calls were made.")
        return 1

    if all_ok:
        print("[OK] All demo cases matched expected security and quality profiles.\n")
        return 0
    else:
        print("[FAIL] One or more demo cases did not match expected results.\n")
        return 1


main = run_demo


if __name__ == "__main__":
    sys.exit(main())
