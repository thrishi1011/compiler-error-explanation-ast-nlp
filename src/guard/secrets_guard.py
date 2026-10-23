"""
secrets_guard.py
----------------
SecretsGuard agent for detecting:
1. sensitive_include: compiler includes referencing private/sensitive files (.env, keys)
   or escaping the allowed source directory (path traversal, absolute paths, escaping symlinks).
2. hardcoded_secret: API keys, tokens, JWTs, private keys, and credential assignments.
3. tool_secret_value: exact values of the tool's own sensitive environment variables.
4. personal_data_access: user identity, environment variables, or personal folders.

All findings have origin="attack". Evidence never contains raw secrets.
Deterministic Python, standard library only.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, List, Set

from .base import GuardAgent, GuardContext
from .models import Finding, InputKind
from .pathsafe import is_sensitive_path_component
from .secrets import env_secret_values, mask_secrets, scan_secrets


INCLUDE_RE = re.compile(
    r'''^\s*#\s*(?:include|include_next)\s*([<"][^>"\r\n]+[>"])''',
    re.MULTILINE
)

HAS_INCLUDE_RE = re.compile(
    r'''__has_include\s*\(\s*([<"][^>"\r\n]+[>"])\s*\)'''
)

ENV_VARS_RE = re.compile(
    r'\b(?:getenv|_dupenv_s|GetEnvironmentVariable[AW]?)\s*\(\s*["\'](HOME|USERPROFILE|USERNAME|USER|APPDATA|LOCALAPPDATA|HOMEPATH)["\']'
)

USER_FUNCS_RE = re.compile(
    r'\b(getlogin(?:_r)?|getpwuid|GetUserName[A-Za-z0-9_]*)\s*\('
)

PERSONAL_PATH_RE = re.compile(
    r'''["']([^"'\r\n]*(?:/home/|/Users/|[A-Za-z]:[/\\]+Users[/\\]+|[/\\]+AppData[/\\]+|[/\\]+Desktop[/\\]+|[/\\]+Documents[/\\]+|Login Data|Cookies|\.bash_history)[^"'\r\n]*)["']''',
    re.IGNORECASE
)


class SecretsGuard(GuardAgent):
    name = "SecretsGuard"
    agent_type = "attack"
    handles = {
        InputKind.USER_SOURCE,
        InputKind.COMPILER_OUTPUT,
        InputKind.AI_RESPONSE,
        InputKind.PATCH,
        InputKind.DATASET_ENTRY,
        InputKind.USER_HINT,
    }

    def quick_match(self, ctx: GuardContext) -> bool:
        """
        Cheap signal check. Invariant: returns True whenever analyze could return a finding.
        """
        payload = ctx.payload or ""
        if not payload:
            return False

        payload_lower = payload.lower()
        keywords = (
            "#include",
            "__has_include",
            "include_next",
            "aiza",
            "gsk_",
            "sk-",
            "ghp_",
            "github_pat_",
            "akia",
            "xox",
            "private key",
            "eyj",
            "password",
            "passwd",
            "secret",
            "token",
            "api",
            "getenv",
            "_dupenv",
            "getenvironment",
            "getlogin",
            "getpwuid",
            "getusername",
            "/home/",
            "/users/",
            "\\users\\",
            "appdata",
            "desktop",
            "documents",
            "cookies",
            "login data",
            ".bash_history",
        )
        for kw in keywords:
            if kw in payload_lower:
                return True

        # Check tool's own sensitive environment variable values
        env_vals = env_secret_values(min_len=8)
        for val in env_vals:
            if val and val in payload:
                return True

        return False

    def analyze(self, ctx: GuardContext) -> List[Finding]:
        findings: List[Finding] = []
        payload = ctx.payload or ""
        if not payload:
            return findings

        # 1. sensitive_include (USER_SOURCE only)
        if ctx.kind == InputKind.USER_SOURCE:
            findings.extend(self._check_includes(ctx))

        # 2. hardcoded_secret and tool_secret_value (all handled kinds)
        findings.extend(self._check_secrets(ctx))

        # 3. personal_data_access (USER_SOURCE and PATCH only)
        if ctx.kind in (InputKind.USER_SOURCE, InputKind.PATCH):
            findings.extend(self._check_personal_data(ctx))

        return findings

    def _check_includes(self, ctx: GuardContext) -> List[Finding]:
        findings: List[Finding] = []
        payload = ctx.payload or ""
        source_dir_meta = ctx.meta.get("source_dir")
        allow_external = os.environ.get("ALLOW_EXTERNAL_INCLUDES") == "1"

        lines = payload.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            # Find all includes on this line
            targets: List[str] = []
            for m in INCLUDE_RE.finditer(line):
                raw = m.group(1)
                targets.append(raw[1:-1].strip())
            for m in HAS_INCLUDE_RE.finditer(line):
                raw = m.group(1)
                targets.append(raw[1:-1].strip())

            for target in targets:
                norm_target = target.replace("\\", "/")
                # Normalize double slashes or multiple slashes
                parts = [p for p in norm_target.split("/") if p]

                # Rule 1: sensitive file or component in target
                is_sensitive_name = any(is_sensitive_path_component(p) for p in parts)

                # Rule 2: absolute path or contains ..
                is_abs = (
                    target.startswith("/")
                    or target.startswith("\\")
                    or bool(re.match(r"^[a-zA-Z]:", target))
                )
                has_dotdot = ".." in parts
                has_dir_part = "/" in norm_target

                outside_source_dir = False

                if source_dir_meta:
                    try:
                        src_dir_path = Path(source_dir_meta).resolve()
                        if is_abs:
                            resolved_target = Path(target).resolve()
                            if not resolved_target.is_relative_to(src_dir_path):
                                outside_source_dir = True
                        elif has_dotdot:
                            resolved_target = (src_dir_path / target).resolve()
                            if not resolved_target.is_relative_to(src_dir_path):
                                outside_source_dir = True
                        else:
                            # Check symlink inside source_dir pointing outside
                            cand = src_dir_path / target
                            if cand.exists() or cand.is_symlink():
                                try:
                                    if not cand.resolve().is_relative_to(src_dir_path):
                                        outside_source_dir = True
                                except Exception:
                                    pass
                    except Exception:
                        outside_source_dir = True
                else:
                    # source_dir unknown: block if directory part, absolute path, or ..
                    if has_dir_part or is_abs or has_dotdot:
                        outside_source_dir = True

                if is_sensitive_name:
                    # Always blocked even inside source_dir or with ALLOW_EXTERNAL_INCLUDES=1
                    findings.append(Finding(
                        agents=[self.name],
                        origin="attack",
                        category="sensitive_include",
                        severity="High",
                        title=f"Sensitive include target: {mask_secrets(target)}",
                        description=f"Include target references a sensitive file ({mask_secrets(target)}).",
                        recommendation="Remove includes referencing sensitive configuration, private keys, or credentials.",
                        line=line_idx,
                        evidence=mask_secrets(line.strip()),
                        action="block",
                        blocks_on={"compile", "run"},
                        details={"target": mask_secrets(target), "sensitive": True},
                    ))
                elif outside_source_dir:
                    if allow_external:
                        findings.append(Finding(
                            agents=[self.name],
                            origin="attack",
                            category="sensitive_include",
                            severity="Low",
                            title=f"External include (permitted): {mask_secrets(target)}",
                            description=f"Include target references a file outside source_dir ({mask_secrets(target)}).",
                            recommendation="Ensure external include paths are intended.",
                            line=line_idx,
                            evidence=mask_secrets(line.strip()),
                            action="warn",
                            blocks_on=set(),
                            details={"target": mask_secrets(target), "downgraded": True},
                        ))
                    else:
                        findings.append(Finding(
                            agents=[self.name],
                            origin="attack",
                            category="sensitive_include",
                            severity="High",
                            title=f"Include outside source directory: {mask_secrets(target)}",
                            description=f"Include target escapes source directory ({mask_secrets(target)}).",
                            recommendation="Place included header files inside the source directory or use standard headers.",
                            line=line_idx,
                            evidence=mask_secrets(line.strip()),
                            action="block",
                            blocks_on={"compile", "run"},
                            details={"target": mask_secrets(target), "escapes_source_dir": True},
                        ))

        return findings

    def _check_secrets(self, ctx: GuardContext) -> List[Finding]:
        findings: List[Finding] = []
        payload = ctx.payload or ""
        hits = scan_secrets(payload)

        for hit in hits:
            line_no = payload[:hit.start].count("\n") + 1

            if hit.kind == "tool_secret":
                findings.append(Finding(
                    agents=[self.name],
                    origin="attack",
                    category="tool_secret_value",
                    severity="Critical",
                    title="Tool secret environment value detected",
                    description="An exact value of a sensitive tool environment variable was found.",
                    recommendation="Never print or leak tool API keys or tokens.",
                    line=line_no,
                    evidence="[REDACTED:tool_secret]",
                    action="block" if ctx.purpose == "ai_send" else "warn",
                    blocks_on={"ai_send"},
                    details={"kind": "tool_secret"},
                ))
            elif hit.severity == "High":
                findings.append(Finding(
                    agents=[self.name],
                    origin="attack",
                    category="hardcoded_secret",
                    severity="High",
                    title=f"Hardcoded secret detected ({hit.kind})",
                    description=f"A high-confidence secret token or private key was found ({hit.kind}).",
                    recommendation="Remove hardcoded secrets and load credentials from secure environment variables.",
                    line=line_no,
                    evidence=f"[REDACTED:{hit.kind}]",
                    action="block" if ctx.purpose == "ai_send" else "warn",
                    blocks_on={"ai_send"},
                    details={"kind": hit.kind},
                ))
            else:
                # Medium severity (credential assignments)
                findings.append(Finding(
                    agents=[self.name],
                    origin="attack",
                    category="hardcoded_secret",
                    severity="Medium",
                    title=f"Credential assignment detected ({hit.kind})",
                    description=f"Potential credential or token assignment detected: {hit.kind}",
                    recommendation="Do not hardcode credentials in code.",
                    line=line_no,
                    evidence=f"[REDACTED:{hit.kind}]",
                    action="warn",
                    blocks_on=set(),
                    details={"kind": hit.kind},
                ))

        return findings

    def _check_personal_data(self, ctx: GuardContext) -> List[Finding]:
        findings: List[Finding] = []
        payload = ctx.payload or ""
        lines = payload.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            matched = False
            desc = ""

            m_env = ENV_VARS_RE.search(line)
            if m_env:
                matched = True
                desc = f"Call to retrieve personal environment variable: {m_env.group(1)}"

            if not matched:
                m_user = USER_FUNCS_RE.search(line)
                if m_user:
                    matched = True
                    desc = f"Call to user account function: {m_user.group(1)}"

            if not matched:
                m_path = PERSONAL_PATH_RE.search(line)
                if m_path:
                    matched = True
                    desc = f"String literal containing personal directory path: {mask_secrets(m_path.group(1))}"

            if matched:
                findings.append(Finding(
                    agents=[self.name],
                    origin="attack",
                    category="personal_data_access",
                    severity="Medium",
                    title="Personal data access detected",
                    description=desc,
                    recommendation="Avoid accessing host user profiles or personal paths in student programs.",
                    line=line_idx,
                    evidence=mask_secrets(line.strip()),
                    action="warn",
                    blocks_on=set(),
                    details={"description": desc},
                ))

        return findings
