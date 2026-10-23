from __future__ import annotations

import os
import re
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .base import GuardAgent, GuardContext
from .models import Finding, InputKind
from .redact import redact

try:
    import security_analyzer
except ImportError:
    _src = str(Path(__file__).resolve().parent.parent)
    if _src not in sys.path:
        sys.path.insert(0, _src)
    import security_analyzer


def _to_snake_case(text: str) -> str:
    cleaned = re.sub(r"[^\w\s-]", "", text)
    snake = re.sub(r"[\s\-_/]+", "_", cleaned).strip("_").lower()
    if snake in ("command_injection", "process_execution"):
        return "process_execution"
    return snake


class VulnGuard(GuardAgent):
    name = "VulnGuard"
    handles = {InputKind.USER_SOURCE}

    def quick_match(self, ctx: GuardContext) -> bool:
        """VulnGuard is always active for source code."""
        return True

    def analyze(self, ctx: GuardContext) -> list[Finding]:
        meta = ctx.meta or {}
        existing_path = meta.get("file_path")
        if not existing_path and "source_dir" in meta and "file_name" in meta:
            cand = os.path.join(meta["source_dir"], meta["file_name"])
            if os.path.isfile(cand):
                existing_path = cand

        temp_path: str | None = None
        if existing_path and os.path.isfile(existing_path):
            target_path = existing_path
        else:
            fd, temp_path = tempfile.mkstemp(suffix=".cpp", prefix="vulnguard_")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(ctx.payload or "")
            target_path = temp_path

        findings: list[Finding] = []
        try:
            sec_findings = security_analyzer.analyze(target_path, [])
            payload_lines = (ctx.payload or "").splitlines()

            for sf in sec_findings:
                if getattr(sf, "source", None) != "static_scan":
                    continue

                line_num = sf.line
                if line_num is not None and 1 <= line_num <= len(payload_lines):
                    raw_ev = payload_lines[line_num - 1].strip()
                else:
                    raw_ev = sf.description

                cat = _to_snake_case(sf.vulnerability_type)
                # VulnGuard findings never block, they only warn (or allow if Low)
                act = "warn" if sf.severity in ("Critical", "High", "Medium") else "allow"

                findings.append(
                    Finding(
                        id=uuid.uuid4().hex[:8],
                        agents=["VulnGuard"],
                        origin="vulnerability",
                        category=cat,
                        severity=sf.severity,
                        title=sf.vulnerability_type,
                        description=sf.description,
                        recommendation=sf.recommendation,
                        line=sf.line,
                        column=sf.column,
                        evidence=redact(raw_ev),
                        action=act,
                        confidence=1.0,
                    )
                )
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

        return findings
