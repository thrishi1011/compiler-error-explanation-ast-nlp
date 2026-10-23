from dataclasses import dataclass
from typing import Any
from .models import Finding, InputKind, Verdict
from .supervisor import get_supervisor


@dataclass
class AiSendResult:
    blocked: bool
    reason: str
    verdicts: list[Verdict]


def check_compile(
    source: str,
    *,
    source_dir: str | None = None,
    file_name: str | None = None,
    fast: bool = False,
) -> Verdict:
    """
    Checks user source code before compile or syntax checking.
    When fast=True, skips VulnGuard (for live syntax checking hot paths).
    Returns the security Verdict.
    """
    meta: dict[str, Any] = {}
    if source_dir:
        meta["source_dir"] = source_dir
    if file_name:
        meta["file_name"] = file_name

    supervisor = get_supervisor()
    return supervisor.review(
        kind=InputKind.USER_SOURCE,
        payload=source or "",
        purpose="compile",
        meta=meta,
        include_vulnerability=not fast,
    )


def check_patch(
    original: str,
    patched: str,
    *,
    origin: str,
    meta: dict[str, Any] | None = None,
) -> Verdict:
    """
    Checks a proposed code patch (AI or offline rule) before application.
    Returns the security Verdict (blocks if any High/Critical patch findings).
    """
    combined_meta: dict[str, Any] = {"original": original, "origin": origin}
    if meta:
        combined_meta.update(meta)

    supervisor = get_supervisor()
    return supervisor.review(
        kind=InputKind.PATCH,
        payload=patched or "",
        purpose="patch",
        meta=combined_meta,
        include_vulnerability=False,
    )


def check_ai_send(
    *,
    source: str | None = None,
    hint: str | None = None,
    errors_text: str | None = None,
) -> AiSendResult:
    """
    Reviews each non-empty part (USER_SOURCE, USER_HINT, COMPILER_OUTPUT)
    with purpose='ai_send' and include_vulnerability=False before sending to an LLM.
    Returns AiSendResult with overall blocked status, descriptive reason, and verdicts.
    """
    supervisor = get_supervisor()
    verdicts: list[Verdict] = []
    blocked = False
    reason = ""

    parts: list[tuple[str, InputKind, str | None]] = [
        ("source", InputKind.USER_SOURCE, source),
        ("hint", InputKind.USER_HINT, hint),
        ("compiler output", InputKind.COMPILER_OUTPUT, errors_text),
    ]

    for part_name, kind, text in parts:
        if not text:
            continue
        v = supervisor.review(
            kind=kind,
            payload=text,
            purpose="ai_send",
            include_vulnerability=False,
        )
        verdicts.append(v)
        if v.blocked and not blocked:
            blocked = True
            # Find the primary blocking finding
            blocking_f: Finding | None = None
            for f in v.findings:
                if f.action == "block" or (f.blocks_on and "ai_send" in f.blocks_on):
                    blocking_f = f
                    break
            if not blocking_f and v.findings:
                blocking_f = v.findings[0]

            agent_name = (blocking_f.agents[0] if blocking_f and blocking_f.agents else "SecurityLayer")
            category = blocking_f.category if blocking_f else "policy_violation"
            reason = f"blocked by {agent_name} ({category}) in {part_name}"

    return AiSendResult(blocked=blocked, reason=reason, verdicts=verdicts)
