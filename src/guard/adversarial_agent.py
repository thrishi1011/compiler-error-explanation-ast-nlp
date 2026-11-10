"""
adversarial_agent.py
--------------------
Autonomous Red-Team Adversary Agent for multi-agent code verification.

In the Red-Team vs. Blue-Team architecture:
- Blue Team (Healer / Generator Agent): Proposes code patches to fix compiler errors,
  optimize performance, or address bugs.
- Red Team (Adversary Auditor Agent - RedTeamAuditor): Independently audits, attacks,
  and stress-tests the proposed patch for hidden backdoors, indirect prompt injections,
  security downgrades, guard removals, and exploitable memory flaws.

If any attack vector is discovered, the Red Team issues an actionable adversarial
critique to force the Blue Team to harden the code in a multi-round verification loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
import difflib
import os
import re
import tempfile
import uuid
from typing import Any, List, Optional, Set

from .base import GuardAgent, GuardContext
from .models import Finding, InputKind
from .output_safe import safe_text
from .redact import redact
from .promptsafe import scan_injection, has_boundary_leak
from .secrets import scan_secrets


@dataclass
class AttackVector:
    category: str
    severity: str  # "Critical" | "High" | "Medium" | "Low"
    title: str
    exploit_mechanism: str
    line: int | None
    evidence: str
    remediation_hint: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AdversaryReport:
    passed: bool
    risk_level: str  # "Clean" | "Low Risk" | "Moderate Risk" | "Critical Threat"
    attack_vectors: list[AttackVector] = field(default_factory=list)
    critique: str = ""
    hardening_guidance: str = ""
    rounds_evaluated: int = 1
    auditor: str = "RedTeamAuditor"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attack_vectors"] = [v.to_dict() if hasattr(v, "to_dict") else v for v in self.attack_vectors]
        return d


class RedTeamAuditor(GuardAgent):
    """
    Autonomous Red-Team Auditor agent.
    Probes candidate patches and code proposals from an adversary's perspective.
    """
    name = "RedTeamAuditor"
    agent_type = "attack"
    handles = {InputKind.PATCH, InputKind.AI_RESPONSE, InputKind.USER_SOURCE}

    def quick_match(self, ctx: GuardContext) -> bool:
        if ctx.kind in (InputKind.PATCH, InputKind.AI_RESPONSE):
            return True
        if ctx.purpose in ("patch", "adversarial_review", "verify"):
            return True
        return False

    def analyze(self, ctx: GuardContext) -> list[Finding]:
        patched_code = ctx.payload or ""
        original_code = str(ctx.meta.get("original") or "")
        origin = str(ctx.meta.get("origin") or "ai")

        report = audit_patch_adversarially(
            original_code=original_code,
            candidate_patch=patched_code,
            origin=origin,
        )

        findings: list[Finding] = []
        for vec in report.attack_vectors:
            act = "block" if vec.severity in ("Critical", "High") else "warn"
            f = Finding(
                id=uuid.uuid4().hex[:8],
                agents=[self.name],
                origin="attack",
                category=vec.category,
                severity=vec.severity,
                title=vec.title,
                description=f"[Red-Team Intercept] {vec.exploit_mechanism}",
                recommendation=vec.remediation_hint,
                line=vec.line,
                column=None,
                evidence=safe_text(redact(vec.evidence)),
                action=act,
                confidence=1.0,
                blocks_on={"patch", "run"},
                details={"adversary_auditor": self.name, "critique": report.critique},
            )
            findings.append(f)

        return findings


def audit_patch_adversarially(
    original_code: str,
    candidate_patch: str,
    origin: str = "ai",
) -> AdversaryReport:
    """
    Conducts deep adversarial audit of a proposed patch against an offensive threat matrix:
    1. Indirect Prompt Injection & Manipulation Vectors
    2. Stealth Backdoors & Disguised Execution
    3. Security Guard Removal & Weakening
    4. Diagnostic Suppression & Obfuscation
    5. Memory Corruption & Unsafe APIs
    """
    attack_vectors: list[AttackVector] = []
    orig_lines = original_code.splitlines() if original_code else []
    patch_lines = candidate_patch.splitlines() if candidate_patch else []

    # Accurate opcode-based line diff
    sm = difflib.SequenceMatcher(None, orig_lines, patch_lines)
    added_lines: list[tuple[int, str]] = []
    removed_lines: list[str] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):
            for j in range(j1, j2):
                added_lines.append((j + 1, patch_lines[j]))
        if tag in ("delete", "replace"):
            for i in range(i1, i2):
                removed_lines.append(orig_lines[i])

    # ── Vector 1: Prompt Injection & Agent Manipulation ─────────────────────────
    if has_boundary_leak(candidate_patch):
        attack_vectors.append(
            AttackVector(
                category="patch_marker_leak",
                severity="Critical",
                title="Agent Boundary Marker Leak",
                exploit_mechanism="Patch leaks internal agent delimiter tokens (<<<DATA or <<<END), indicating boundary escape.",
                line=1,
                evidence="Boundary token detected in patch body",
                remediation_hint="Strip boundary marker leakage and isolate template variables.",
            )
        )

    inj_findings = scan_injection(candidate_patch)
    for inj in inj_findings:
        attack_vectors.append(
            AttackVector(
                category="agent_manipulation",
                severity="High",
                title="Agent Manipulation Directive",
                exploit_mechanism=f"Patch contains prompt manipulation payload: {inj.description}",
                line=inj.line,
                evidence=inj.evidence,
                remediation_hint="Discard attacker-prompted instructions and emit pure C++ logic only.",
            )
        )

    # ── Vector 2: Stealth Backdoors & Disguised Code Execution ───────────────────
    backdoor_patterns = [
        (re.compile(r"\b(system|popen|exec[lv]p?|fork|CreateProcess[AW]?|WinExec|ShellExecute[AW]?)\s*\(", re.IGNORECASE),
         "process_execution", "Critical", "Arbitrary Process Execution Backdoor",
         "Patch introduces external process execution API susceptible to shell hijacking."),
        (re.compile(r"\b(dlopen|LoadLibrary[AW]?)\s*\(", re.IGNORECASE),
         "dynamic_loading", "High", "Dynamic Library Loading Hook",
         "Patch dynamically loads external binary modules, enabling remote code injection."),
        (re.compile(r"##\s*[A-Za-z_]", re.IGNORECASE),
         "obfuscation", "Medium", "Macro Token Pasting Obfuscation",
         "Patch uses ## token concatenation which can disguise function invocation from static analysis."),
        (re.compile(r"(?:socket|connect|WSAStartup|getaddrinfo)\s*\(", re.IGNORECASE),
         "network_access", "High", "Unauthorized Network Socket Creation",
         "Patch attempts network connection which may enable data exfiltration."),
    ]

    for line_idx, line_text in added_lines:
        code_part = line_text.split("//")[0]
        for pat, cat, sev, title, desc in backdoor_patterns:
            m = pat.search(code_part)
            if m:
                attack_vectors.append(
                    AttackVector(
                        category=cat,
                        severity=sev,
                        title=title,
                        exploit_mechanism=desc,
                        line=line_idx,
                        evidence=m.group(0),
                        remediation_hint="Eliminate process execution, dynamic loading, or networking from repair patch.",
                    )
                )

    # ── Vector 3: Security Guard Removal & Weakening ─────────────────────────────
    guard_re = re.compile(
        r"(?:assert\s*\(|static_assert\s*\(|if\s*\(.*?\)\s*(?:return|exit|abort|throw|break|continue)\b|if\s*\(.*?(?:!=|==)\s*nullptr\)|if\s*\(.*?(?:<|<=|>|>=)\s*(?:size\b|len\b|n\b|count\b))",
        re.IGNORECASE,
    )
    removed_guards = [l.strip() for l in removed_lines if guard_re.search(l.split("//")[0])]
    added_guards = [l[1].strip() for l in added_lines if guard_re.search(l[1].split("//")[0])]

    if len(removed_guards) > len(added_guards) and len(removed_guards) > 0:
        attack_vectors.append(
            AttackVector(
                category="guard_removal",
                severity="High",
                title="Security Guard Removal",
                exploit_mechanism=f"Patch removed {len(removed_guards)} safety validation guards without replacement: '{removed_guards[0]}'",
                line=None,
                evidence=removed_guards[0],
                remediation_hint="Retain all defensive assertions, bounds guards, and null pointer checks.",
            )
        )

    # Security downgrade checks (e.g. strncpy -> strcpy, fgets -> gets, snprintf -> sprintf)
    downgrade_pairs = [
        (re.compile(r"\bstrncpy\b"), re.compile(r"\bstrcpy\b"), "strncpy replaced with unsafe strcpy"),
        (re.compile(r"\bfgets\b"), re.compile(r"\bgets\b"), "fgets replaced with banned gets"),
        (re.compile(r"\bsnprintf\b"), re.compile(r"\bsprintf\b"), "snprintf replaced with unbounded sprintf"),
    ]
    for safe_re, unsafe_re, reason in downgrade_pairs:
        had_safe = any(safe_re.search(l) for l in orig_lines)
        added_unsafe = any(unsafe_re.search(l[1]) for l in added_lines)
        if had_safe and added_unsafe:
            attack_vectors.append(
                AttackVector(
                    category="patch_security_downgrade",
                    severity="High",
                    title="Security Downgrade Attack",
                    exploit_mechanism=reason,
                    line=None,
                    evidence=reason,
                    remediation_hint="Always prefer bounded APIs (strncpy, snprintf, fgets) over unchecked legacy calls.",
                )
            )

    # Diagnostic suppression checks
    suppress_re = re.compile(
        r"(?:#\s*pragma\s+GCC\s+diagnostic\s+ignored|#\s*pragma\s+warning\s*\(\s*disable|#\s*define\s+NDEBUG|__attribute__\s*\(\s*\(\s*no_sanitize|//\s*NOLINT|-w\b)",
        re.IGNORECASE,
    )
    for line_idx, line_text in added_lines:
        if suppress_re.search(line_text):
            attack_vectors.append(
                AttackVector(
                    category="patch_suppresses_diagnostics",
                    severity="High",
                    title="Compiler Diagnostic Suppression",
                    exploit_mechanism="Patch suppresses compiler security diagnostics or assertions to mask underlying bugs.",
                    line=line_idx,
                    evidence=line_text.strip(),
                    remediation_hint="Resolve the root diagnostic warning instead of silencing compiler checks.",
                )
            )

    # ── Vector 4: Memory Exploitation & Dangling Pointers ────────────────────────
    import security_analyzer

    orig_vuln_counts: dict[str, int] = {}
    if original_code:
        fd_orig, tmp_orig = tempfile.mkstemp(suffix=".cpp", prefix="redteam_orig_")
        try:
            with os.fdopen(fd_orig, "w", encoding="utf-8") as fo:
                fo.write(original_code)
            orig_sec_findings = security_analyzer.analyze(tmp_orig, [])
            for of in orig_sec_findings:
                orig_vuln_counts[of.vulnerability_type] = orig_vuln_counts.get(of.vulnerability_type, 0) + 1
        finally:
            if os.path.exists(tmp_orig):
                try:
                    os.remove(tmp_orig)
                except OSError:
                    pass

    fd, tmp_file = tempfile.mkstemp(suffix=".cpp", prefix="redteam_audit_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(candidate_patch)
        sec_findings = security_analyzer.analyze(tmp_file, [])
    finally:
        if os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass

    new_vuln_counts: dict[str, int] = {}
    for sf in sec_findings:
        new_vuln_counts[sf.vulnerability_type] = new_vuln_counts.get(sf.vulnerability_type, 0) + 1

    # Flag critical or high findings ACTUALLY INTRODUCED in patch
    for sf in sec_findings:
        if sf.severity in ("Critical", "High") and sf.line is not None:
            # If candidate patch does not increase the count of this vulnerability type,
            # it was pre-existing in the original user code and not introduced by the patch.
            if original_code and new_vuln_counts.get(sf.vulnerability_type, 0) <= orig_vuln_counts.get(sf.vulnerability_type, 0):
                continue

            # Check if this line was modified or added in the patch or if small snippet
            if any(l_idx == sf.line for l_idx, _ in added_lines) or not original_code or len(orig_lines) <= 2:
                attack_vectors.append(
                    AttackVector(
                        category=sf.vulnerability_type.lower().replace(" ", "_"),
                        severity=sf.severity,
                        title=f"Introduced {sf.vulnerability_type}",
                        exploit_mechanism=sf.description,
                        line=sf.line,
                        evidence=sf.description,
                        remediation_hint=sf.recommendation,
                    )
                )

    # ── Assessment & Guidance Synthesis ──────────────────────────────────────────
    passed = len(attack_vectors) == 0
    if passed:
        risk_level = "Clean"
        critique = "Adversarial inspection passed. Zero attack vectors or backdoors detected."
        guidance = "Code patch is certified adversarially robust."
    else:
        has_crit = any(v.severity == "Critical" for v in attack_vectors)
        risk_level = "Critical Threat" if has_crit else "Moderate Risk"
        critique = f"Adversarial audit REJECTED patch: {len(attack_vectors)} attack vector(s) identified."
        guidance_items = [f"- {v.title} (line {v.line or 'scope'}): {v.remediation_hint}" for v in attack_vectors]
        guidance = "Blue Team Hardening Guidance:\n" + "\n".join(guidance_items)

    return AdversaryReport(
        passed=passed,
        risk_level=risk_level,
        attack_vectors=attack_vectors,
        critique=critique,
        hardening_guidance=guidance,
        rounds_evaluated=1,
        auditor="RedTeamAuditor",
    )
