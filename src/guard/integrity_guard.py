"""
integrity_guard.py
------------------
IntegrityGuard agent for detecting:
1. Dataset entry poisoning (purpose="dataset", blocks_on={"dataset"}):
   - dataset_directive_message: compiler message extracted from #error / #warning directive in source
   - dataset_bad_category: invalid / non-canonical diagnostic category
   - dataset_bad_message: empty, too long (>300 chars), non-printable/control chars, or path separators
   - dataset_secret: secret patterns found in compiler message
   - dataset_rate_limit: run_count >= 50
   - dataset_store_too_large: pending store exceeds 5 MB
2. Model file integrity (purpose="model_load", blocks_on={"model_load"}):
   - model_outside_data_dir: model file not inside project data directory
   - model_too_large: model file exceeds 200 MB
   - model_manifest_missing: manifest missing or entry missing
   - model_hash_mismatch: SHA-256 or size does not match manifest entry

Deterministic Python, standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, List

from .base import GuardAgent, GuardContext
from .models import Finding, InputKind
from .secrets import mask_secrets, scan_secrets


CANONICAL_CATEGORIES = {
    "syntax_error",
    "name_resolution",
    "missing_include",
    "type_error",
    "return_type_error",
    "redefinition",
    "access_error",
    "linker_error",
    "other",
}

DIRECTIVE_RE = re.compile(
    r'^\s*#\s*(?:error|warning)\s+(.*?)$',
    re.MULTILINE | re.IGNORECASE
)

FILE_PATH_IN_MSG_RE = re.compile(
    r'(?:[a-zA-Z]:[/\\]|[/\\]Users[/\\]|[/\\]home[/\\])',
    re.IGNORECASE
)


class IntegrityGuard(GuardAgent):
    name = "IntegrityGuard"
    agent_type = "attack"
    handles = {
        InputKind.DATASET_ENTRY,
        InputKind.MODEL_FILE,
    }

    def quick_match(self, ctx: GuardContext) -> bool:
        """quick_match is True when kind and purpose match dataset or model_load."""
        if ctx.kind == InputKind.DATASET_ENTRY and ctx.purpose == "dataset":
            return True
        if ctx.kind == InputKind.MODEL_FILE and ctx.purpose == "model_load":
            return True
        return False

    def analyze(self, ctx: GuardContext) -> List[Finding]:
        if ctx.kind == InputKind.DATASET_ENTRY and ctx.purpose == "dataset":
            return self._check_dataset_entry(ctx)
        elif ctx.kind == InputKind.MODEL_FILE and ctx.purpose == "model_load":
            return self._check_model_file(ctx)
        return []

    def _check_dataset_entry(self, ctx: GuardContext) -> List[Finding]:
        findings: List[Finding] = []
        msg = ctx.payload or ""
        meta = ctx.meta or {}

        # 1. dataset_directive_message
        source_text = meta.get("source_text") or ""
        if source_text and msg:
            norm_msg = re.sub(r"\s+", " ", msg.strip()).strip().lower()
            for m in DIRECTIVE_RE.finditer(source_text):
                dir_raw = m.group(1).strip().strip("\"'")
                norm_dir = re.sub(r"\s+", " ", dir_raw).strip().lower()
                if norm_dir and (norm_msg == norm_dir or norm_msg in norm_dir or norm_dir in norm_msg):
                    findings.append(Finding(
                        agents=[self.name],
                        origin="attack",
                        category="dataset_directive_message",
                        severity="High",
                        title="Dataset poisoning: attacker directive message",
                        description="Diagnostic message originates from a source #error or #warning directive.",
                        recommendation="Refuse to log attacker-controlled compiler directives into dataset.",
                        evidence=mask_secrets(msg[:120]),
                        action="block",
                        blocks_on={"dataset"},
                        details={"directive": norm_dir},
                    ))
                    break

        # 2. dataset_bad_category
        cat = meta.get("category")
        if cat not in CANONICAL_CATEGORIES:
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="dataset_bad_category",
                severity="High",
                title=f"Dataset poisoning: invalid category '{cat}'",
                description=f"Category '{cat}' is not one of the 9 canonical diagnostic categories.",
                recommendation="Provide a valid canonical category.",
                evidence=mask_secrets(str(cat)),
                action="block",
                blocks_on={"dataset"},
                details={"category": cat},
            ))

        # 3. dataset_bad_message
        bad_msg = False
        reason = ""
        if not msg or not msg.strip():
            bad_msg = True
            reason = "empty message"
        elif len(msg) > 300:
            bad_msg = True
            reason = f"message too long ({len(msg)} > 300 chars)"
        else:
            # Check non-printable or non-ASCII control characters
            for ch in msg:
                code = ord(ch)
                if (code < 32 and ch not in ("\t", "\n", "\r")) or code > 126:
                    bad_msg = True
                    reason = f"non-printable or non-ASCII control character: U+{code:04X}"
                    break
            if not bad_msg and FILE_PATH_IN_MSG_RE.search(msg):
                bad_msg = True
                reason = "message contains file path with drive or home directory"

        if bad_msg:
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="dataset_bad_message",
                severity="High",
                title=f"Dataset poisoning: bad message format ({reason})",
                description=f"Message fails structure check: {reason}",
                recommendation="Ensure dataset messages are concise, clean ASCII strings without paths.",
                evidence=mask_secrets(msg[:120]),
                action="block",
                blocks_on={"dataset"},
                details={"reason": reason},
            ))

        # 4. dataset_secret
        if msg:
            hits = scan_secrets(msg)
            if hits:
                findings.append(Finding(
                    agents=[self.name],
                    origin="attack",
                    category="dataset_secret",
                    severity="High",
                    title="Dataset poisoning: secret token in message",
                    description="Secret pattern or sensitive credential found in dataset entry message.",
                    recommendation="Do not log entries containing tokens or credentials into dataset.",
                    evidence="[REDACTED:secret]",
                    action="block",
                    blocks_on={"dataset"},
                    details={"hits": len(hits)},
                ))

        # 5. dataset_rate_limit
        run_count = int(meta.get("run_count", 0))
        if run_count >= 50:
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="dataset_rate_limit",
                severity="High",
                title="Dataset poisoning: rate limit reached",
                description=f"Accepted entries in this session ({run_count}) reached or exceeded limit (50).",
                recommendation="Restart process or throttle dataset logging.",
                evidence=f"run_count={run_count}",
                action="block",
                blocks_on={"dataset"},
                details={"run_count": run_count},
            ))

        # 6. dataset_store_too_large
        project_root = Path(__file__).resolve().parent.parent.parent
        data_dir_env = os.environ.get("GUARD_DATA_DIR")
        data_dir = Path(data_dir_env).resolve() if data_dir_env else (project_root / "data").resolve()
        pending_path = os.environ.get("GUARD_PENDING_PATH") or str(data_dir / "pending_training.jsonl")

        if os.path.exists(pending_path):
            try:
                if os.path.getsize(pending_path) > 5 * 1024 * 1024:
                    findings.append(Finding(
                        agents=[self.name],
                        origin="attack",
                        category="dataset_store_too_large",
                        severity="High",
                        title="Dataset store too large",
                        description=f"Pending training store exceeds maximum size (5 MB): {pending_path}",
                        recommendation="Review and purge pending training records before logging more.",
                        evidence=f"size={os.path.getsize(pending_path)}",
                        action="block",
                        blocks_on={"dataset"},
                        details={"path": pending_path, "size": os.path.getsize(pending_path)},
                    ))
            except Exception:
                pass

        return findings

    def _check_model_file(self, ctx: GuardContext) -> List[Finding]:
        findings: List[Finding] = []
        raw_path = ctx.payload or ""
        if not raw_path:
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="model_manifest_missing",
                severity="High",
                title="Model file path missing",
                description="Empty model path provided for verification.",
                recommendation="Provide valid model file path.",
                evidence="",
                action="block",
                blocks_on={"model_load"},
            ))
            return findings

        project_root = Path(__file__).resolve().parent.parent.parent
        data_dir_env = os.environ.get("GUARD_DATA_DIR")
        data_dir = Path(data_dir_env).resolve() if data_dir_env else (project_root / "data").resolve()
        model_path = Path(raw_path).resolve()

        # 1. model_outside_data_dir
        try:
            inside = model_path.is_relative_to(data_dir)
        except AttributeError:
            inside = str(model_path).lower().startswith(str(data_dir).lower())

        if not inside:
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="model_outside_data_dir",
                severity="High",
                title="Model file outside data directory",
                description=f"Model file '{model_path}' is not within authorized data directory '{data_dir}'.",
                recommendation="Place ML models inside project data directory.",
                evidence=str(model_path),
                action="block",
                blocks_on={"model_load"},
                details={"model_path": str(model_path), "data_dir": str(data_dir)},
            ))
            return findings

        # 2. model_too_large
        if model_path.exists():
            try:
                sz = model_path.stat().st_size
                if sz > 200 * 1024 * 1024:
                    findings.append(Finding(
                        agents=[self.name],
                        origin="attack",
                        category="model_too_large",
                        severity="High",
                        title="Model file too large",
                        description=f"Model file size ({sz} bytes) exceeds maximum limit of 200 MB.",
                        recommendation="Verify model architecture and file contents.",
                        evidence=f"size={sz}",
                        action="block",
                        blocks_on={"model_load"},
                        details={"size": sz},
                    ))
                    return findings
            except Exception:
                pass

        # 3. model_manifest_missing
        manifest_path = data_dir / "model_manifest.json"
        if not manifest_path.exists() or not model_path.exists():
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="model_manifest_missing",
                severity="High",
                title="Model manifest or model file missing",
                description=f"Manifest '{manifest_path}' or model file '{model_path}' not found.",
                recommendation="Ensure model_manifest.json exists and contains entry for this model.",
                evidence=str(manifest_path),
                action="block",
                blocks_on={"model_load"},
                details={"manifest_path": str(manifest_path)},
            ))
            return findings

        manifest_data = {}
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
        except Exception:
            manifest_data = {}

        entry = manifest_data.get(model_path.name)
        if not entry or not isinstance(entry, dict):
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="model_manifest_missing",
                severity="High",
                title=f"No manifest entry for model '{model_path.name}'",
                description=f"Model manifest does not contain an entry for '{model_path.name}'.",
                recommendation="Run python tools/sign_model.py to sign the model.",
                evidence=model_path.name,
                action="block",
                blocks_on={"model_load"},
                details={"model_name": model_path.name},
            ))
            return findings

        # 4. model_hash_mismatch
        expected_sha256 = entry.get("sha256", "")
        expected_size = entry.get("size", None)

        sha = hashlib.sha256()
        actual_size = 0
        try:
            with open(model_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    actual_size += len(chunk)
                    sha.update(chunk)
        except Exception as e:
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="model_hash_mismatch",
                severity="High",
                title="Cannot read model file",
                description=f"Error reading model file: {e}",
                recommendation="Check file permissions and integrity.",
                evidence=str(e),
                action="block",
                blocks_on={"model_load"},
            ))
            return findings

        actual_sha256 = sha.hexdigest()
        if (
            actual_size != expected_size
            or actual_sha256.lower() != str(expected_sha256).lower()
        ):
            findings.append(Finding(
                agents=[self.name],
                origin="attack",
                category="model_hash_mismatch",
                severity="High",
                title="Model SHA-256 hash or size mismatch",
                description="Model file checksum or size does not match the signed manifest entry.",
                recommendation="If you replaced the model on purpose, run: python tools/sign_model.py",
                evidence=f"expected={expected_sha256}, actual={actual_sha256}",
                action="block",
                blocks_on={"model_load"},
                details={
                    "expected_sha256": expected_sha256,
                    "actual_sha256": actual_sha256,
                    "expected_size": expected_size,
                    "actual_size": actual_size,
                },
            ))

        return findings
