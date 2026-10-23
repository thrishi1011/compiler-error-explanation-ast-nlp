#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Ensure src directory is in sys.path
_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from guard import InputKind, get_supervisor


def main() -> None:
    parser = argparse.ArgumentParser(description="Compiler Security Guard CLI")
    parser.add_argument("file", help="Path to C++ source file")
    parser.add_argument(
        "--purpose",
        default="run",
        choices=["run", "compile", "analyze"],
        help="Review purpose (default: run)",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON verdict")
    parser.add_argument("--heal-security", action="store_true", help="Heal security issues in source code")
    parser.add_argument("--allow-behavior", action="store_true", help="Allow behavior-changing security fixes")
    parser.add_argument("--write", action="store_true", help="Write healed source to input file, saving .cpp.bak")
    args = parser.parse_args()

    target_path = Path(args.file)
    if not target_path.exists():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    code = target_path.read_text(encoding="utf-8", errors="ignore")

    if args.heal_security:
        import security_healer
        result = security_healer.heal_security(
            code,
            allow_behavior_changes=args.allow_behavior,
            source_dir=str(target_path.parent.resolve()),
        )

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            header = f"{'finding':<30} | {'detected by':<16} | {'severity':<10} | {'line':<6} | {'outcome':<16} | {'reason'}"
            print(header)
            print("-" * len(header))
            for o in result.outcomes:
                agents_str = ", ".join(o.agents)
                line_str = str(o.line) if o.line is not None else "?"
                print(f"{o.category:<30} | {agents_str:<16} | {o.severity:<10} | {line_str:<6} | {o.status:<16} | {o.reason}")

            print(f"\nRisk: {result.risk_before} -> {result.risk_after} ({result.label_before} -> {result.label_after})")

            if result.applied:
                print("\nApplied Fixes:")
                for fix in result.applied:
                    print(f"  [{fix.finding_category}] line {fix.line or '?'}: {fix.description}")
                    print(f"    - {fix.before}")
                    print(f"    + {fix.after}")

            if result.suggestions:
                print("\nSuggestions:")
                for s in result.suggestions:
                    print(f"  [{s.finding_category}] line {s.line or '?'}: {s.description}")
                    for s_line in s.after.splitlines():
                        print(f"    {s_line}")

        if args.write and result.improved:
            bak_path = target_path.with_suffix(".cpp.bak")
            bak_path.write_text(code, encoding="utf-8")
            target_path.write_text(result.source_after, encoding="utf-8")
            if not args.json:
                print(f"\nWrote healed source to {target_path} (backup saved at {bak_path})")

        sys.exit(0)

    supervisor = get_supervisor()
    verdict = supervisor.review(
        kind=InputKind.USER_SOURCE,
        payload=code,
        purpose=args.purpose,
        meta={
            "source_dir": str(target_path.parent.resolve()),
            "file_name": target_path.name,
            "file_path": str(target_path.resolve()),
        },
    )

    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2))
    else:
        print(f"Risk Score: {verdict.risk_score} ({verdict.risk_label})")
        print(f"Action: {verdict.action.upper()} (Blocked: {verdict.blocked})")

        print("\nFindings:")
        if verdict.findings:
            for f in verdict.findings:
                agents_str = ", ".join(f.agents)
                line_str = f"line {f.line}" if f.line is not None else "line ?"
                print(f"  [{f.severity.upper()}] {f.category} | {agents_str} | {line_str} | {f.evidence}")
        else:
            print("  None")

        if verdict.routing:
            print("\nRouting:")
            for r in verdict.routing:
                print(f"  {r.get('agent')}: {r.get('reason')}")

        if verdict.timings_ms:
            print("\nTimings:")
            for agent, ms in verdict.timings_ms.items():
                print(f"  {agent}: {ms:.2f}ms")
            print(f"  Total: {verdict.total_ms:.2f}ms")

    if verdict.blocked:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
