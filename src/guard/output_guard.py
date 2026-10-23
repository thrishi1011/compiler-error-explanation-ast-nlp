"""
output_guard.py
---------------
OutputGuard detects display injection, spoofed compiler status, terminal escape
sequences, and hidden Unicode (Trojan Source) in compiler output, AI responses,
and user source code.

Findings always set origin='attack' and blocks_on=set() (never blocks; display
sinks neutralize text with safe_text / html_text instead).
"""

from __future__ import annotations

import re
from typing import Any

from .base import GuardAgent, GuardContext
from .lexutil import classify_line_contexts
from .models import Finding, InputKind
from .output_safe import safe_text
from .redact import redact

# Hidden unicode regex: bidi controls and zero-width characters
# Bidi: U+202A-U+202E, U+2066-U+2069, U+200E, U+200F
# Zero-width: U+200B-U+200D, U+2060, U+FEFF
_HIDDEN_UNICODE_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069\u200E\u200F\u200B-\u200D\u2060\uFEFF]")

# Tag-like patterns in diagnostic text
_TAG_PATTERN_RE = re.compile(r"<[A-Za-z/!][^>]*>?")

# Dangerous URI schemes
_DANGEROUS_SCHEME_RE = re.compile(r"(?:javascript|vbscript|data:text/html|file):", re.IGNORECASE)

# Spoofed compiler status phrases
_SPOOFED_STATUS_RE = re.compile(
    r"\b(?:compilation successful|compiled successfully|no errors|0 errors|security scan clean|no issues detected|all checks passed)\b",
    re.IGNORECASE,
)

# Terminal escape characters and control sequences
_TERMINAL_ESCAPE_RE = re.compile(r"(?:\x1B\[[0-?]*[ -/]*[@-~]|\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)|\x1B|[\r\b])")


class OutputGuard(GuardAgent):
    """
    Guards output rendered to the user:
    - In COMPILER_OUTPUT and AI_RESPONSE: detects HTML/markup tags, dangerous URL schemes,
      terminal escapes (\r, \x1b, \b), spoofed compiler status, and hidden unicode.
    - In USER_SOURCE: detects hidden unicode (Trojan Source) and reports line and token context.
    """

    name = "OutputGuard"
    handles = {InputKind.COMPILER_OUTPUT, InputKind.AI_RESPONSE, InputKind.USER_SOURCE}
    agent_type = "attack"

    def quick_match(self, ctx: GuardContext) -> bool:
        payload = ctx.payload or ""
        if ctx.kind == InputKind.USER_SOURCE:
            # Check for hidden unicode or non-ASCII
            return any(ord(c) > 127 for c in payload)

        if "<" in payload or "\x1b" in payload or "\r" in payload or "\b" in payload:
            return True
        if any(ord(c) > 127 for c in payload):
            return True
        if _SPOOFED_STATUS_RE.search(payload):
            return True
        if _DANGEROUS_SCHEME_RE.search(payload):
            return True
        return False

    def analyze(self, ctx: GuardContext) -> list[Finding]:
        findings: list[Finding] = []
        payload = ctx.payload or ""

        # USER_SOURCE: hidden-character check only
        if ctx.kind == InputKind.USER_SOURCE:
            lines = payload.splitlines()
            lex_state: dict[str, Any] = {}
            for line_idx, line in enumerate(lines, start=1):
                matches = list(_HIDDEN_UNICODE_RE.finditer(line))
                if not matches:
                    classify_line_contexts(line, lex_state)
                    continue

                contexts = classify_line_contexts(line, lex_state)
                for m in matches:
                    col = m.start()
                    char = m.group(0)
                    ctx_tag = contexts[col] if col < len(contexts) else "code"
                    char_code = f"U+{ord(char):04X}"
                    findings.append(
                        Finding(
                            agents=[self.name],
                            origin="attack",
                            category="hidden_unicode",
                            severity="Medium",
                            title="Hidden Unicode (Trojan Source)",
                            description=(
                                f"Hidden bidirectional control or zero-width character ({char_code}) "
                                f"detected inside a {ctx_tag} at line {line_idx}."
                            ),
                            recommendation="Remove invisible or direction-altering Unicode characters.",
                            line=line_idx,
                            column=col + 1,
                            evidence=safe_text(f"{char_code} in {ctx_tag}"),
                            action="warn",
                            confidence=1.0,
                            blocks_on=set(),
                        )
                    )
            return findings

        # COMPILER_OUTPUT and AI_RESPONSE: full checks
        # 1. display_injection
        has_scheme = _DANGEROUS_SCHEME_RE.search(payload)
        tag_match = _TAG_PATTERN_RE.search(payload)
        if has_scheme or tag_match:
            severity = "High" if has_scheme else "Medium"
            sample = ""
            if has_scheme:
                sample = has_scheme.group(0)
            elif tag_match:
                sample = tag_match.group(0)
            findings.append(
                Finding(
                    agents=[self.name],
                    origin="attack",
                    category="display_injection",
                    severity=severity,
                    title="Display Markup Injection",
                    description=(
                        f"Potentially malicious HTML tags or dangerous URL schemes detected in {ctx.kind.value}."
                    ),
                    recommendation="Ensure all dynamic diagnostic and AI output is escaped before rendering.",
                    line=1,
                    column=1,
                    evidence=safe_text(redact(sample), limit=100),
                    action="warn",
                    confidence=0.95,
                    blocks_on=set(),
                )
            )

        # 2. terminal_escape
        term_match = _TERMINAL_ESCAPE_RE.search(payload)
        if term_match:
            findings.append(
                Finding(
                    agents=[self.name],
                    origin="attack",
                    category="terminal_escape",
                    severity="Medium",
                    title="Terminal Control / Escape Sequence",
                    description="ANSI escape sequences or overwriting carriage returns detected in output text.",
                    recommendation="Strip escape codes and control characters before terminal display.",
                    line=1,
                    column=1,
                    evidence=safe_text("terminal escape sequence", limit=100),
                    action="warn",
                    confidence=0.95,
                    blocks_on=set(),
                )
            )

        # 3. spoofed_status
        status_match = _SPOOFED_STATUS_RE.search(payload)
        if status_match:
            findings.append(
                Finding(
                    agents=[self.name],
                    origin="attack",
                    category="spoofed_status",
                    severity="Medium",
                    title="Spoofed Diagnostic Status",
                    description=f"Diagnostic output contains simulated clean status text: '{status_match.group(0)}'.",
                    recommendation="Verify compiler return codes rather than trusting unvalidated diagnostic text.",
                    line=1,
                    column=1,
                    evidence=safe_text(status_match.group(0), limit=100),
                    action="warn",
                    confidence=0.90,
                    blocks_on=set(),
                )
            )

        # 4. hidden_unicode (for diagnostic / AI text)
        uni_match = _HIDDEN_UNICODE_RE.search(payload)
        if uni_match:
            char = uni_match.group(0)
            findings.append(
                Finding(
                    agents=[self.name],
                    origin="attack",
                    category="hidden_unicode",
                    severity="Medium",
                    title="Hidden Unicode in Output",
                    description=f"Hidden bidirectional control or zero-width character (U+{ord(char):04X}) detected in output.",
                    recommendation="Sanitize Unicode text to remove zero-width and bidirectional controls.",
                    line=1,
                    column=1,
                    evidence=safe_text(f"U+{ord(char):04X}"),
                    action="warn",
                    confidence=1.0,
                    blocks_on=set(),
                )
            )

        return findings
