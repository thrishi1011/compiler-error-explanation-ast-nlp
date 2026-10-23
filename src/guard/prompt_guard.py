"""
prompt_guard.py
---------------
PromptGuard agent for detecting prompt injection, role hijacking, policy bypass
requests, and exfiltration attempts before text is sent to an external AI model.
Only activates when purpose == "ai_send", adding zero overhead to compile/run checks.
Deterministic Python, standard library only.
"""

from __future__ import annotations

import os
from typing import Any, List

from .base import GuardAgent, GuardContext
from .lexutil import classify_line_contexts
from .models import Finding, InputKind
from .output_safe import safe_text
from .promptsafe import InjectionHit, scan_injection
from .redact import redact


_RULE_TO_CATEGORY = {
    "override_instructions": "prompt_injection",
    "role_hijack": "prompt_injection",
    "disable_controls": "policy_bypass_request",
    "mark_safe": "policy_bypass_request",
    "secret_request": "secret_exfiltration_request",
    "hidden_prompt_unicode": "hidden_prompt_unicode",
    "encoded_payload": "encoded_payload",
    "role_marker": "role_marker",
}


class PromptGuard(GuardAgent):
    name = "PromptGuard"
    agent_type = "attack"
    handles = {
        InputKind.USER_SOURCE,
        InputKind.COMPILER_OUTPUT,
        InputKind.USER_HINT,
    }

    def quick_match(self, ctx: GuardContext) -> bool:
        """
        Only acts when purpose is 'ai_send'. Returns False for any other purpose
        (e.g. 'compile', 'run', 'display') so normal operations incur no cost.
        """
        if ctx.purpose != "ai_send":
            return False
        payload = ctx.payload or ""
        if not payload:
            return False
        hits = scan_injection(payload)
        return len(hits) > 0

    def analyze(self, ctx: GuardContext) -> List[Finding]:
        if ctx.purpose != "ai_send":
            return []

        payload = ctx.payload or ""
        if not payload:
            return []

        hits = scan_injection(payload)
        if not hits:
            return []

        findings: List[Finding] = []
        lines = payload.splitlines()

        # Classify line contexts for USER_SOURCE
        line_contexts: List[str] = []
        if ctx.kind == InputKind.USER_SOURCE:
            state = {"in_block_comment": False, "raw_delim": None}
            for line in lines:
                char_ctxs = classify_line_contexts(line, state)
                # Determine primary context for this line
                if "comment" in char_ctxs:
                    primary = "comment"
                elif "string" in char_ctxs:
                    primary = "string literal"
                else:
                    primary = "code"
                line_contexts.append(primary)

        for hit in hits:
            line_no = payload[:hit.start].count("\n") + 1
            category = _RULE_TO_CATEGORY.get(hit.rule, "prompt_injection")

            line_text = lines[line_no - 1] if 0 < line_no <= len(lines) else payload[:100]
            context_type = ""
            if ctx.kind == InputKind.USER_SOURCE and 0 < line_no <= len(line_contexts):
                context_type = line_contexts[line_no - 1]

            # In USER_HINT, all injection hits are treated as High severity attack instructions
            if ctx.kind == InputKind.USER_HINT:
                severity = "High"
                blocks_on = {"ai_send"}
                action = "block"
            else:
                if hit.severity == "High":
                    severity = "High"
                    blocks_on = {"ai_send"}
                    action = "block"
                else:
                    severity = "Medium"
                    blocks_on = set()
                    action = "warn"

            details = {
                "rule": hit.rule,
                "hit_kind": hit.kind,
            }
            if context_type:
                details["context_type"] = context_type

            desc = f"Prompt injection / policy bypass attempt detected ({hit.rule})"
            if context_type:
                desc += f" in {context_type}"

            evidence_str = safe_text(redact(line_text.strip()[:140]))

            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category=category,
                severity=severity,
                title=f"Prompt injection: {category.replace('_', ' ').title()}",
                description=desc,
                recommendation="Do not send adversarial directives or instructions to the AI model.",
                line=line_no,
                evidence=evidence_str,
                action=action,
                blocks_on=blocks_on,
                details=details,
            ))

        return findings
