"""
integrity.py
------------
Public API for querying ML model file integrity status.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, Optional

from .models import InputKind
from .supervisor import review


def model_status(model_path: Optional[str | Path] = None) -> Dict[str, Any]:
    """
    Checks the status and cryptographic validity of a model file.
    Returns:
        {"ok": bool, "reason": str, "sha256": str | None}
    """
    project_root = Path(__file__).resolve().parent.parent.parent
    data_dir_env = os.environ.get("GUARD_DATA_DIR")
    data_dir = Path(data_dir_env).resolve() if data_dir_env else (project_root / "data").resolve()

    if model_path is None:
        target = data_dir / "error_classifier.joblib"
    else:
        target = Path(model_path).resolve()

    actual_sha256: Optional[str] = None
    if target.exists() and target.is_file():
        try:
            sha = hashlib.sha256()
            with open(target, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    sha.update(chunk)
            actual_sha256 = sha.hexdigest()
        except Exception:
            actual_sha256 = None

    verdict = review(InputKind.MODEL_FILE, str(target), purpose="model_load")
    if verdict.blocked:
        blocking = [
            f for f in verdict.findings
            if f.action == "block" or (f.blocks_on and "model_load" in f.blocks_on)
        ]
        reason = blocking[0].category if blocking else "rejected"
        return {"ok": False, "reason": reason, "sha256": actual_sha256}

    return {"ok": True, "reason": "valid", "sha256": actual_sha256}
