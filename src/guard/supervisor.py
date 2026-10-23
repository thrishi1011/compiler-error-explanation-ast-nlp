from __future__ import annotations

import hashlib
import os
import time
import uuid
from typing import Any

from .base import GuardAgent, GuardContext
from .config import (
    ACTION_ORDER,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    get_risk_label,
)
from .exec_guard import ExecGuard
from .models import Finding, InputKind, Verdict
from .attack_log import log_verdict
from .output_guard import OutputGuard
from .endpoint_guard import EndpointGuard
from .redact import redact
from .resource_guard import ResourceGuard
from .vuln_guard import VulnGuard
from .secrets_guard import SecretsGuard
from .integrity_guard import IntegrityGuard
from .prompt_guard import PromptGuard
from .patch_guard import PatchGuard


class Supervisor:
    def __init__(self) -> None:
        self._agents: list[GuardAgent] = []

    @property
    def agents(self) -> list[GuardAgent]:
        """Return list of registered GuardAgents."""
        return list(self._agents)

    def register(self, agent: GuardAgent) -> None:
        """Register a GuardAgent."""
        # Replace if agent with same name exists, else append
        for i, a in enumerate(self._agents):
            if a.name == agent.name:
                self._agents[i] = agent
                return
        self._agents.append(agent)

    def review(
        self,
        kind: InputKind | str,
        payload: str,
        purpose: str = "analyze",
        meta: dict[str, Any] | None = None,
        full_scan: bool = False,
        include_vulnerability: bool = True,
    ) -> Verdict:
        """
        Main entry point for security review. Never raises.
        """
        t_start = time.perf_counter()
        meta = dict(meta or {})
        payload_str = payload or ""

        if isinstance(kind, str):
            try:
                kind_enum = InputKind(kind)
            except ValueError:
                kind_enum = kind  # type: ignore[assignment]
        else:
            kind_enum = kind

        # Step 1: Filter candidate agents by handled kind
        candidate_agents = [a for a in self._agents if kind_enum in getattr(a, "handles", set())]
        if not include_vulnerability:
            candidate_agents = [a for a in candidate_agents if a.name != "VulnGuard"]

        # In Phase 1, only USER_SOURCE has agents. If none match, return clean allow verdict.
        if not candidate_agents:
            total_ms = (time.perf_counter() - t_start) * 1000.0
            return Verdict(
                findings=[],
                risk_score=0,
                risk_label="Clean",
                action="allow",
                blocked=False,
                routing=[],
                timings_ms={},
                total_ms=round(total_ms, 3),
                kind=kind_enum,
                purpose=purpose,
            )

        ctx = GuardContext(
            kind=kind_enum if isinstance(kind_enum, InputKind) else InputKind.USER_SOURCE,
            payload=payload_str,
            purpose=purpose,
            meta=meta,
        )

        routing: list[dict[str, str]] = []
        timings_ms: dict[str, float] = {}
        raw_findings: list[Finding] = []

        # Step 2: Routing via quick_match or full_scan
        for agent in candidate_agents:
            should_run = False
            reason = ""

            if full_scan:
                should_run = True
                reason = "full_scan enabled"
            else:
                try:
                    matched = agent.quick_match(ctx)
                    if matched:
                        should_run = True
                        reason = "quick_match signal triggered"
                except Exception as qm_err:
                    should_run = True
                    reason = f"quick_match error ({qm_err}), fallback to analyze"

            if not should_run:
                continue

            routing.append({"agent": agent.name, "reason": reason})

            # Execute analyze wrapped in try/except and timed
            t_agent_start = time.perf_counter()
            try:
                agent_findings = agent.analyze(ctx) or []
                raw_findings.extend(agent_findings)
            except Exception as crash_err:
                # Agent crash handling
                is_attack_agent = (getattr(agent, "agent_type", None) == "attack" or agent.name != "VulnGuard")
                crash_action = "block" if (purpose == "run" and is_attack_agent) else "warn"
                crash_finding = Finding(
                    id=uuid.uuid4().hex[:8],
                    agents=[agent.name],
                    origin="attack",
                    category="guard_error",
                    severity="Medium",
                    title=f"{agent.name} crash",
                    description=f"Agent {agent.name} failed during analysis: {crash_err}",
                    recommendation="Review agent error details and logs.",
                    line=None,
                    column=None,
                    evidence=redact(str(crash_err)),
                    action=crash_action,
                    confidence=1.0,
                )
                raw_findings.append(crash_finding)

            elapsed_agent = (time.perf_counter() - t_agent_start) * 1000.0
            timings_ms[agent.name] = round(elapsed_agent, 3)

        # Step 3: Merge duplicates with same (line, category)
        merged_findings = self._merge_findings(raw_findings)

        # Step 4: Calculate risk score and label
        risk_score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in merged_findings)
        risk_label = get_risk_label(risk_score)

        # Step 5: Policy by purpose and per-finding blocks_on
        blocked = False
        verdict_action = "allow"

        for f in merged_findings:
            if f.blocks_on is not None:
                should_block = (purpose in f.blocks_on)
            else:
                # Phase 1 default rule:
                if purpose == "run":
                    if f.category == "guard_error" and f.origin == "attack":
                        should_block = True
                    elif f.origin == "attack" and f.severity in ("Critical", "High"):
                        should_block = True
                    else:
                        should_block = False
                else:
                    should_block = False

            if should_block:
                f.action = "block"
                blocked = True
            else:
                f.action = "warn" if (f.action == "warn" or f.severity in ("Critical", "High", "Medium")) else "allow"

        # Determine overall verdict action
        if blocked:
            verdict_action = "block"
        elif any(f.action == "warn" for f in merged_findings):
            verdict_action = "warn"
        else:
            verdict_action = "allow"

        total_ms = (time.perf_counter() - t_start) * 1000.0

        verdict = Verdict(
            findings=merged_findings,
            risk_score=risk_score,
            risk_label=risk_label,
            action=verdict_action,
            blocked=blocked,
            routing=routing,
            timings_ms=timings_ms,
            total_ms=round(total_ms, 3),
            kind=kind_enum,
            purpose=purpose,
        )

        # Step 6: Log verdict
        try:
            payload_sha256 = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
            meta["payload_sha256"] = payload_sha256
            log_verdict(verdict, meta)
        except Exception:
            pass

        return verdict

    def _merge_findings(self, findings: list[Finding]) -> list[Finding]:
        if not findings:
            return []

        grouped: dict[tuple[int | None, str], list[Finding]] = {}
        for f in findings:
            key = (f.line, f.category)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(f)

        allow_system_calls = os.environ.get("ALLOW_SYSTEM_CALLS") == "1"
        allow_assembly = os.environ.get("ALLOW_ASSEMBLY") == "1"
        allow_sys_includes = os.environ.get("ALLOW_SYS_INCLUDES") == "1"

        merged: list[Finding] = []
        for (line, cat), group in grouped.items():
            if len(group) == 1:
                f = group[0]
                if cat == "process_execution" and allow_system_calls:
                    f.severity = "Low"
                    f.action = "warn"
                    if "permitted by policy toggle" not in f.description:
                        f.description += " (permitted by policy toggle)"
                elif cat == "inline_assembly" and allow_assembly:
                    f.severity = "Low"
                    f.action = "warn"
                    if "permitted by policy toggle" not in f.description:
                        f.description += " (permitted by policy toggle)"
                elif cat == "unsafe_include" and allow_sys_includes:
                    f.severity = "Low"
                    f.action = "warn"
                    if "permitted by policy toggle" not in f.description:
                        f.description += " (permitted by policy toggle)"
                f.evidence = redact(f.evidence)
                merged.append(f)
                continue

            # Pick highest severity
            best_sev_finding = min(group, key=lambda item: SEVERITY_ORDER.get(item.severity, 99))

            # Combine agents uniquely and stably
            all_agents = sorted(list({a for item in group for a in item.agents}))

            # If any finding has origin "attack", merged origin is "attack"
            has_attack = any(item.origin == "attack" for item in group)
            merged_origin = "attack" if has_attack else "vulnerability"

            # Merge evidence: pick non-empty evidence, preferably from highest severity
            chosen_evidence = best_sev_finding.evidence or ""
            if not chosen_evidence:
                for item in group:
                    if item.evidence:
                        chosen_evidence = item.evidence
                        break

            # Confidence
            max_conf = max(item.confidence for item in group)

            # Check permission toggles
            allow_system_calls = os.environ.get("ALLOW_SYSTEM_CALLS") == "1"
            allow_assembly = os.environ.get("ALLOW_ASSEMBLY") == "1"
            allow_sys_includes = os.environ.get("ALLOW_SYS_INCLUDES") == "1"

            merged_severity = best_sev_finding.severity
            merged_desc = best_sev_finding.description
            merged_action = best_sev_finding.action

            if cat == "process_execution" and allow_system_calls:
                merged_severity = "Low"
                merged_action = "warn"
                if "permitted by policy toggle" not in merged_desc:
                    merged_desc += " (permitted by policy toggle)"
            elif cat == "inline_assembly" and allow_assembly:
                merged_severity = "Low"
                merged_action = "warn"
                if "permitted by policy toggle" not in merged_desc:
                    merged_desc += " (permitted by policy toggle)"
            elif cat == "unsafe_include" and allow_sys_includes:
                merged_severity = "Low"
                merged_action = "warn"
                if "permitted by policy toggle" not in merged_desc:
                    merged_desc += " (permitted by policy toggle)"

            blocks_on_sets = [item.blocks_on for item in group if item.blocks_on is not None]
            merged_blocks_on = set().union(*blocks_on_sets) if blocks_on_sets else None

            merged_f = Finding(
                id=best_sev_finding.id,
                agents=all_agents,
                origin=merged_origin,
                category=cat,
                severity=merged_severity,
                title=best_sev_finding.title,
                description=merged_desc,
                recommendation=best_sev_finding.recommendation,
                line=line,
                column=best_sev_finding.column,
                evidence=redact(chosen_evidence),
                action=merged_action,
                confidence=max_conf,
                blocks_on=merged_blocks_on,
                details=dict(best_sev_finding.details or {}),
            )
            merged.append(merged_f)

        return merged


_SUPERVISOR_SINGLETON: Supervisor | None = None


def get_supervisor() -> Supervisor:
    """Returns the singleton Supervisor initialized with registered agents."""
    global _SUPERVISOR_SINGLETON
    if _SUPERVISOR_SINGLETON is None:
        sup = Supervisor()
        sup.register(ExecGuard())
        sup.register(VulnGuard())
        sup.register(ResourceGuard())
        sup.register(OutputGuard())
        sup.register(EndpointGuard())
        sup.register(SecretsGuard())
        sup.register(IntegrityGuard())
        sup.register(PromptGuard())
        sup.register(PatchGuard())
        _SUPERVISOR_SINGLETON = sup
    return _SUPERVISOR_SINGLETON


def review(
    kind: InputKind | str,
    payload: str,
    purpose: str = "analyze",
    meta: dict[str, Any] | None = None,
    full_scan: bool = False,
    include_vulnerability: bool = True,
) -> Verdict:
    """Convenience helper delegating to the singleton Supervisor."""
    return get_supervisor().review(
        kind=kind,
        payload=payload,
        purpose=purpose,
        meta=meta,
        full_scan=full_scan,
        include_vulnerability=include_vulnerability,
    )
