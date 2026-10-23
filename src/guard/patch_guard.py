"""
patch_guard.py
--------------
PatchGuard agent for inspecting proposed code patches (from AI or offline rules).
Checks:
1. patch_introduces_dangerous_code: runs other agents on both versions, flags newly introduced High/Critical dangers.
2. patch_new_include: flags non-standard includes (blocks unistd.h, sys/*, windows.h; warns on filesystem/thread).
3. patch_security_downgrade: swaps bounded calls for unbounded ones (strncpy->strcpy, fgets->gets, etc.).
4. patch_removes_guard: removes assertion, condition check with early return, or bounds/null checks.
5. patch_suppresses_diagnostics: adds #pragma GCC diagnostic ignored, #define NDEBUG, // NOLINT, etc.
6. patch_too_large: changed lines exceed policy thresholds.
7. patch_injection_text: patch introduces prompt injection text not present in original (Medium, warn).
8. patch_marker_leak: patch contains <<<DATA or <<<END boundary markers.
9. patch_secret: patch introduces credentials or secrets not in original.
10. patch_comments_out_code: more than 3 non-comment lines commented out (Medium, warn).

Deterministic Python, standard library only.
"""

from __future__ import annotations

import difflib
import re
from typing import Any, List, Set, Tuple

from .base import GuardAgent, GuardContext
from .config import (
    CPP_STANDARD_HEADERS,
    PATCH_MAX_CHANGED_LINES_AI_MIN,
    PATCH_MAX_CHANGED_LINES_AI_PERCENT,
    PATCH_MAX_CHANGED_LINES_OFFLINE,
)
from .models import Finding, InputKind
from .output_safe import safe_text
from .promptsafe import has_boundary_leak, scan_injection
from .redact import redact
from .secrets import scan_secrets


INCLUDE_RE = re.compile(r'^\s*#\s*include\s*([<"][^>"\r\n]+[>"])', re.MULTILINE)
PRAGMA_SUPPRESS_RE = re.compile(
    r'(?:#\s*pragma\s+GCC\s+diagnostic\s+ignored|#\s*pragma\s+warning\s*\(\s*disable|#\s*define\s+NDEBUG|__attribute__\s*\(\s*\(\s*no_sanitize|//\s*NOLINT|-w\b)',
    re.IGNORECASE
)
GUARD_LINE_RE = re.compile(
    r'(?:assert\s*\(|static_assert\s*\(|if\s*\(.*?\)\s*(?:return|exit|abort|throw|break|continue)\b|if\s*\(.*?(?:!=|==)\s*nullptr\)|if\s*\(.*?(?:<|<=|>|>=)\s*(?:size\b|len\b|n\b|count\b))',
    re.IGNORECASE
)


class PatchGuard(GuardAgent):
    name = "PatchGuard"
    agent_type = "attack"
    handles = {InputKind.PATCH}

    def quick_match(self, ctx: GuardContext) -> bool:
        """quick_match is True for all PATCH payloads when purpose is 'patch'."""
        if ctx.purpose != "patch":
            return False
        return ctx.kind == InputKind.PATCH

    def analyze(self, ctx: GuardContext) -> List[Finding]:
        if ctx.kind != InputKind.PATCH or ctx.purpose != "patch" or ctx.meta.get("_nested"):
            return []

        patched = ctx.payload or ""
        original = str(ctx.meta.get("original") or "")
        origin_val = str(ctx.meta.get("origin") or "ai")

        findings: List[Finding] = []

        orig_lines = original.splitlines()
        patch_lines = patched.splitlines()

        # Compute line diff
        diff = list(difflib.ndiff(orig_lines, patch_lines))
        added_lines = [line[2:] for line in diff if line.startswith("+ ")]
        removed_lines = [line[2:] for line in diff if line.startswith("- ")]
        total_changed = len(added_lines) + len(removed_lines)

        # 1. patch_marker_leak
        if has_boundary_leak(patched):
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="patch_marker_leak",
                severity="High",
                title="Patch contains boundary leak marker",
                description="The patched code contains untrusted boundary marker <<<DATA or <<<END.",
                recommendation="Do not include boundary tokens in patched source.",
                evidence=safe_text(redact("Boundary leak token detected")),
                action="block",
                blocks_on={"patch"},
            ))

        # 2. patch_too_large
        if origin_val == "ai":
            allowed_max = max(
                PATCH_MAX_CHANGED_LINES_AI_MIN,
                int(PATCH_MAX_CHANGED_LINES_AI_PERCENT * len(orig_lines)),
            )
        else:
            allowed_max = PATCH_MAX_CHANGED_LINES_OFFLINE

        if total_changed > allowed_max:
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="patch_too_large",
                severity="High",
                title=f"Patch too large ({total_changed} changed lines > limit {allowed_max})",
                description=f"Patch modified {total_changed} lines which exceeds limit for {origin_val} ({allowed_max}).",
                recommendation="Keep patches minimal and targeted strictly to diagnostic fixes.",
                evidence=f"changed_lines={total_changed}, limit={allowed_max}",
                action="block",
                blocks_on={"patch"},
                details={"changed_lines": total_changed, "limit": allowed_max},
            ))

        # 3. patch_new_include
        orig_includes: Set[str] = set()
        for m in INCLUDE_RE.finditer(original):
            raw = m.group(1)[1:-1].strip()
            orig_includes.add(raw)

        patch_includes: Set[str] = set()
        for m in INCLUDE_RE.finditer(patched):
            raw = m.group(1)[1:-1].strip()
            patch_includes.add(raw)

        new_includes = patch_includes - orig_includes
        for inc in new_includes:
            norm_inc = inc.replace("\\", "/").strip().lower()
            inc_base = norm_inc.split("/")[-1]
            is_std = (norm_inc in CPP_STANDARD_HEADERS) or (inc_base in CPP_STANDARD_HEADERS)

            if not is_std:
                if norm_inc in ("filesystem", "thread"):
                    findings.append(Finding(
                        agents=[self.name],
                        origin="attack",
                        category="patch_new_include",
                        severity="Medium",
                        title=f"New system library include: <{inc}>",
                        description=f"Patch added include <{inc}> which requires attention.",
                        recommendation="Verify whether concurrency or filesystem libraries are necessary.",
                        evidence=f"#include <{inc}>",
                        action="warn",
                        blocks_on=set(),
                        details={"include": inc},
                    ))
                else:
                    findings.append(Finding(
                        agents=[self.name],
                        origin="attack",
                        category="patch_new_include",
                        severity="High",
                        title=f"Patch introduces non-standard include: <{inc}>",
                        description=f"Patch introduces non-standard or external header <{inc}>.",
                        recommendation="Only standard C++ headers are permitted in automated patches.",
                        evidence=f"#include <{inc}>",
                        action="block",
                        blocks_on={"patch"},
                        details={"include": inc},
                    ))

        # 4. patch_security_downgrade
        rem_text = "\n".join(removed_lines)
        add_text = "\n".join(added_lines)

        downgrades = [
            ("strncpy", "strcpy"),
            ("strncat", "strcat"),
            ("snprintf", "sprintf"),
            ("fgets", "gets"),
            ("getline", "gets"),
        ]
        for safe_func, unsafe_func in downgrades:
            if re.search(rf"\b{safe_func}\b", rem_text) and re.search(rf"\b{unsafe_func}\b", add_text):
                findings.append(Finding(
                    agents=[self.name],
                    origin="attack",
                    category="patch_security_downgrade",
                    severity="High",
                    title=f"Security downgrade: {safe_func} -> {unsafe_func}",
                    description=f"Patch replaces bounded call {safe_func} with unsafe/unbounded {unsafe_func}.",
                    recommendation="Keep safe, bounded library calls.",
                    evidence=f"{safe_func} -> {unsafe_func}",
                    action="block",
                    blocks_on={"patch"},
                    details={"from": safe_func, "to": unsafe_func},
                ))

        # Bounded scanf -> unbounded scanf: scanf("%10s" -> "%s"
        if re.search(r'scanf\s*\(\s*["\'][^"\']*%[0-9]+s', rem_text) and re.search(r'scanf\s*\(\s*["\'][^"\']*%s', add_text):
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="patch_security_downgrade",
                severity="High",
                title="Security downgrade: bounded scanf replaced with unbounded %s",
                description="Patch removed width specifier from scanf format string.",
                recommendation="Retain buffer width limits in scanf format strings.",
                evidence='scanf("%<num>s" -> "%s")',
                action="block",
                blocks_on={"patch"},
            ))

        # 5. patch_removes_guard
        for rem_line in removed_lines:
            stripped = rem_line.strip()
            # Ignore comments
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue
            if GUARD_LINE_RE.search(stripped):
                # Check if this guard line was re-added or retained in the patch
                reappeared = any(stripped == add_line.strip() for add_line in added_lines)
                if not reappeared:
                    # Also check if it still exists anywhere in patched
                    in_patched = any(stripped == pline.strip() for pline in patch_lines)
                    if not in_patched:
                        findings.append(Finding(
                            agents=[self.name],
                            origin="attack",
                            category="patch_removes_guard",
                            severity="High",
                            title="Patch removes defensive guard or assertion",
                            description=f"Defensive check or assertion removed: {safe_text(redact(stripped[:80]))}",
                            recommendation="Do not remove bounds checks, assertions, or early validation returns.",
                            evidence=safe_text(redact(stripped[:100])),
                            action="block",
                            blocks_on={"patch"},
                            details={"removed_guard": stripped},
                        ))
                        break

        # 6. patch_suppresses_diagnostics
        for add_line in added_lines:
            stripped = add_line.strip()
            m_supp = PRAGMA_SUPPRESS_RE.search(stripped)
            if m_supp:
                matched_token = m_supp.group(0)
                # Check if this suppression token was already present in original
                if matched_token.lower() not in original.lower():
                    findings.append(Finding(
                        agents=[self.name],
                        origin="attack",
                        category="patch_suppresses_diagnostics",
                        severity="High",
                        title=f"Diagnostic suppression added: {matched_token}",
                        description=f"Patch suppresses compiler diagnostics: {stripped[:80]}",
                        recommendation="Fix underlying code errors instead of suppressing compiler diagnostics.",
                        evidence=safe_text(redact(stripped[:100])),
                        action="block",
                        blocks_on={"patch"},
                        details={"suppression": matched_token},
                    ))
                    break

        # 7. patch_injection_text
        orig_inj = {h.rule for h in scan_injection(original)}
        patch_inj_hits = scan_injection(patched)
        new_inj_hits = [h for h in patch_inj_hits if h.rule not in orig_inj]
        if new_inj_hits:
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="patch_injection_text",
                severity="Medium",
                title="Patch introduces prompt injection phrases",
                description="Patched code contains prompt injection or override phrases not in original.",
                recommendation="Ensure patched comments and strings do not contain adversarial instructions.",
                evidence=safe_text(redact("Prompt injection text added")),
                action="warn",
                blocks_on=set(),
                details={"new_rules": [h.rule for h in new_inj_hits]},
            ))

        # 8. patch_secret
        orig_sec_kinds = {h.kind for h in scan_secrets(original)}
        patch_sec_hits = scan_secrets(patched)
        new_sec_hits = [h for h in patch_sec_hits if h.kind not in orig_sec_kinds]
        if new_sec_hits:
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="patch_secret",
                severity="High",
                title="Patch introduces secret credential or key",
                description="A credential or secret token was introduced in the patched code.",
                recommendation="Remove hardcoded secrets from patch.",
                evidence="[REDACTED:secret]",
                action="block",
                blocks_on={"patch"},
                details={"kinds": [h.kind for h in new_sec_hits]},
            ))

        # 9. patch_comments_out_code
        commented_count = 0
        for rem_line in removed_lines:
            s_rem = rem_line.strip()
            if not s_rem or s_rem.startswith("//") or s_rem.startswith("/*") or s_rem.startswith("*"):
                continue
            # Look for a corresponding added line that is just this line commented out
            for add_line in added_lines:
                s_add = add_line.strip()
                if s_add.startswith("//") and s_rem in s_add:
                    commented_count += 1
                    break
        if commented_count > 3:
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="patch_comments_out_code",
                severity="Medium",
                title=f"Excessive commented-out code ({commented_count} lines)",
                description=f"Patch commented out {commented_count} lines of original code.",
                recommendation="Healer should repair statements rather than disabling multiple lines.",
                evidence=f"commented_lines={commented_count}",
                action="warn",
                blocks_on=set(),
                details={"commented_lines": commented_count},
            ))

        # 10. patch_introduces_dangerous_code (Nested supervisor review)
        try:
            from .supervisor import get_supervisor
            sup = get_supervisor()
            orig_v = sup.review(
                InputKind.USER_SOURCE,
                original,
                purpose="run",
                include_vulnerability=False,
                meta={"_nested": True},
            )
            patch_v = sup.review(
                InputKind.USER_SOURCE,
                patched,
                purpose="run",
                include_vulnerability=False,
                meta={"_nested": True},
            )

            def _f_key(f: Finding) -> tuple[str, str]:
                # Normalize whitespace in evidence
                norm_ev = re.sub(r"\s+", " ", f.evidence or "").strip().lower()
                return (f.category, norm_ev)

            orig_danger_keys = {
                _f_key(f) for f in orig_v.findings
                if f.severity in ("High", "Critical") and f.category != "guard_error"
            }

            new_dangers: dict[str, list[str]] = {}
            for pf in patch_v.findings:
                if pf.severity in ("High", "Critical") and pf.category != "guard_error":
                    if _f_key(pf) not in orig_danger_keys:
                        if pf.category not in new_dangers:
                            new_dangers[pf.category] = list(pf.agents)

            for danger_cat, agents_list in new_dangers.items():
                findings.append(Finding(
                    agents=[self.name],
                    origin="attack",
                    category="patch_introduces_dangerous_code",
                    severity="High",
                    title=f"Patch introduces dangerous code: {danger_cat}",
                    description=f"Patch introduces a new high-severity security hazard ({danger_cat}).",
                    recommendation="Revert patch or eliminate dangerous constructs.",
                    evidence=safe_text(redact(f"Detected by: {', '.join(agents_list)}")),
                    action="block",
                    blocks_on={"patch"},
                    details={"new_category": danger_cat, "agents": agents_list},
                ))
        except Exception:
            pass

        return findings
