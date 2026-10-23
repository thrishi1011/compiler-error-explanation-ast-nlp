from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import DEFAULT_LOG_PATH, LOG_ROTATION_BYTES
from .models import Verdict

_LOG_LOCK = threading.Lock()
_RECENT_VERDICT_LOGS: dict[tuple[str, str, str], float] = {}


def log_verdict(verdict: Verdict, meta: dict[str, Any] | None = None) -> None:
    """
    Appends a JSON line entry to the attack log only if the verdict contains at least
    one finding with origin="attack" or blocked=True.
    Suppresses duplicate (kind, purpose, payload_sha256) within 60 seconds.
    Rotates to .1 when size exceeds LOG_ROTATION_BYTES.
    Never throws an exception.
    """
    if not verdict or not verdict.findings:
        return

    # A1: Log only if at least one finding has origin="attack" or verdict.blocked is True
    has_attack = any(getattr(f, "origin", "") == "attack" for f in verdict.findings)
    if not (has_attack or verdict.blocked):
        return

    try:
        log_path_str = os.environ.get("GUARD_LOG_PATH", DEFAULT_LOG_PATH)
        log_path = Path(log_path_str)
        meta = meta or {}

        kind_str = str(verdict.kind.value if hasattr(verdict.kind, "value") else verdict.kind)
        purpose_str = str(verdict.purpose)
        payload_sha256 = meta.get("payload_sha256", "")

        now_ts = time.time()
        dedupe_key = (str(log_path), kind_str, purpose_str, payload_sha256)

        with _LOG_LOCK:
            global _RECENT_VERDICT_LOGS
            # A1: Deduplicate identical logs within 60 seconds
            if dedupe_key in _RECENT_VERDICT_LOGS:
                if (now_ts - _RECENT_VERDICT_LOGS[dedupe_key]) < 60.0:
                    return
            _RECENT_VERDICT_LOGS[dedupe_key] = now_ts

            if len(_RECENT_VERDICT_LOGS) > 1000:
                cutoff = now_ts - 120.0
                _RECENT_VERDICT_LOGS = {k: t for k, t in _RECENT_VERDICT_LOGS.items() if t >= cutoff}

            findings_data = [
                {
                    "agents": list(f.agents),
                    "category": f.category,
                    "severity": f.severity,
                    "line": f.line,
                    "evidence": f.evidence,
                }
                for f in verdict.findings
            ]

            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "kind": kind_str,
                "purpose": purpose_str,
                "action": verdict.action,
                "risk_score": verdict.risk_score,
                "file_name": meta.get("file_name", "unknown"),
                "payload_sha256": payload_sha256,
                "findings": findings_data,
                "timings": verdict.timings_ms,
            }

            line = json.dumps(entry) + "\n"

            log_path.parent.mkdir(parents=True, exist_ok=True)

            if log_path.exists() and log_path.stat().st_size >= LOG_ROTATION_BYTES:
                rotated = log_path.parent / f"{log_path.name}.1"
                try:
                    if rotated.exists():
                        rotated.unlink()
                    log_path.rename(rotated)
                except Exception:
                    pass

            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line)

    except Exception:
        # Logging failures must be silent
        pass


def log_event(event_type: str, details: dict[str, Any]) -> None:
    """
    Appends a structured event line with an event field to the attack log.
    Never throws an exception.
    """
    try:
        log_path_str = os.environ.get("GUARD_LOG_PATH", DEFAULT_LOG_PATH)
        log_path = Path(log_path_str)

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "details": details,
        }

        line = json.dumps(entry) + "\n"

        with _LOG_LOCK:
            log_path.parent.mkdir(parents=True, exist_ok=True)

            if log_path.exists() and log_path.stat().st_size >= LOG_ROTATION_BYTES:
                rotated = log_path.parent / f"{log_path.name}.1"
                try:
                    if rotated.exists():
                        rotated.unlink()
                    log_path.rename(rotated)
                except Exception:
                    pass

            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line)

    except Exception:
        # Logging failures must be silent
        pass
