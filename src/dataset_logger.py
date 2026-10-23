"""
dataset_logger.py
-----------------
Quarantines newly observed compiler errors into append-only pending training store
(data/pending_training.jsonl) after security review by IntegrityGuard.
Never writes directly to data/training_data.json.
Deterministic Python, standard library only.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import threading
from typing import Any, Optional

from error_normalizer import normalize_error
from guard.attack_log import log_event
from guard.models import InputKind
from guard.supervisor import review

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_RUN_COUNT: int = 0
_LOCK = threading.Lock()


def get_run_count() -> int:
    return _RUN_COUNT


def reset_run_count() -> None:
    global _RUN_COUNT
    _RUN_COUNT = 0


def log_example(error: Any, source_text: Optional[str] = None) -> None:
    """
    Quarantines an error example into data/pending_training.jsonl.
    Blocks if IntegrityGuard or supervisor detects poisoning or abuse.
    """
    global _RUN_COUNT

    raw_msg = getattr(error, "message", "") or ""
    cat = getattr(error, "category", "") or "other"
    try:
        conf = float(getattr(error, "confidence", 1.0) or 1.0)
    except Exception:
        conf = 1.0

    # Review via supervisor
    verdict = review(
        InputKind.DATASET_ENTRY,
        raw_msg,
        purpose="dataset",
        meta={
            "category": cat,
            "confidence": conf,
            "source_text": source_text or "",
            "run_count": _RUN_COUNT,
        },
    )

    if verdict.blocked:
        categories = [
            f.category for f in verdict.findings
            if f.action == "block" or (f.blocks_on and "dataset" in f.blocks_on)
        ]
        log_event("dataset_rejected", {
            "categories": categories,
            "message": raw_msg[:120],
        })
        return

    _RUN_COUNT += 1

    # Normalize error message
    dataset_message, _ = normalize_error(raw_msg)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "message": dataset_message,
        "raw_message": raw_msg,
        "category": cat,
        "confidence": conf,
        "status": "pending",
    }

    pending_path = os.environ.get("GUARD_PENDING_PATH") or os.path.join(DATA_DIR, "pending_training.jsonl")
    os.makedirs(os.path.dirname(os.path.abspath(pending_path)), exist_ok=True)

    with _LOCK:
        with open(pending_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()