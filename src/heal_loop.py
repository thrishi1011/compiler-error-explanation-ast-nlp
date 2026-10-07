"""
heal_loop.py
------------
Orchestrates the auto-healing pipeline.

Flow:
  1. Compile  → parse errors
  2. Classify each error
  3. Call auto_healer.attempt_fix() for the first fixable error
  4. Write patched source  →  show diff
  5. Recompile  →  if clean, done ✅
  6. After MAX_ATTEMPTS failures  →  emit give_up signal

Signals emitted (for the GUI):
  - attempt_started(attempt_no: int, error: dict)
  - diff_ready(attempt_no: int, diff_html: str)
  - compile_clean()
  - give_up(history: list[dict])
  - error_signal(message: str)
"""

import json
import os
import sys
import subprocess
import re
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

from auto_healer import attempt_fix, UNFIXABLE_CATEGORIES
from diff_viewer import compute_diff, format_diff_html, has_changes
from healing_suggester import suggest_failed_heal
import time
try:
    from codecarbon import EmissionsTracker
    HAS_CODECARBON = True
except ImportError:
    HAS_CODECARBON = False

MAX_ATTEMPTS = 10

# ── GCC error pattern ────────────────────────────────────────────────────────
_ERR_PATTERN = re.compile(
    r"^(.+?):(\d+):(\d+):\s*(error|warning):\s*(.*)$"
)


def _compile(file_path: str) -> tuple[list[dict], str]:
    """
    Run g++ and return (error_list, raw_stderr).
    Each error dict has: file, line, column, type, message, raw.
    """
    from compiler_runner import _sanitize_input
    if not _sanitize_input(file_path):
        return [{
            "file": file_path,
            "line": 1,
            "column": 1,
            "type": "error",
            "message": "Security Error: Malicious command injection or forbidden system call detected.",
            "raw": "error: Malicious command injection or forbidden system call detected.",
            "category": "security_violation",
            "confidence": 1.0
        }], "error: Malicious code blocked"

    res = subprocess.run(
        ["g++", "-std=c++17", "-Wall", file_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    errors = []
    for line in res.stderr.splitlines():
        m = _ERR_PATTERN.match(line.strip())
        if m:
            errors.append({
                "file":    m.group(1),
                "line":    int(m.group(2)),
                "column":  int(m.group(3)),
                "type":    m.group(4),
                "message": m.group(5),
                "raw":     line,
            })
    return errors, res.stderr


def _pre_scan(source: str) -> list[dict]:
    """
    Catch a small set of obvious issues before compile diagnostics.
    Returns synthetic diagnostics in the same shape as compiler errors.
    """
    errors = []
    lines = source.splitlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        if re.search(r"\bint\b.*=\s*2147483647\b", stripped):
            errors.append({
                "file": "source",
                "line": i,
                "column": 0,
                "type": "warning",
                "message": "integer overflow: value at INT_MAX, addition will overflow",
                "raw": line,
                "category": "integer_overflow",
                "confidence": 1.0,
            })

        if re.search(r"if\s*\([^=!<>]*(?<![=!<>])=(?!=)[^)]*\)", stripped):
            if not re.search(r"if\s*\(.*==.*\)", stripped):
                errors.append({
                    "file": "source",
                    "line": i,
                    "column": 0,
                    "type": "warning",
                    "message": "assignment used as truth value in if condition",
                    "raw": line,
                    "category": "syntax_error",
                    "confidence": 1.0,
                })

        if re.search(r"/\s*0\b", stripped):
            errors.append({
                "file": "source",
                "line": i,
                "column": 0,
                "type": "warning",
                "message": "division by zero: literal 0 used as divisor",
                "raw": line,
                "category": "division_by_zero",
                "confidence": 1.0,
            })

        zero_assign = re.search(r"\bint\s+([A-Za-z_]\w*)\s*=\s*0\s*;", stripped)
        if zero_assign:
            var = zero_assign.group(1)
            guard_pattern = re.compile(rf"if\s*\(\s*{re.escape(var)}\s*==\s*0\s*\)")
            if guard_pattern.search(source):
                continue
            for j, future_line in enumerate(lines[i:], start=i + 1):
                future_stripped = future_line.strip()
                if future_stripped.startswith("//"):
                    continue
                if re.search(rf"/\s*{re.escape(var)}\b", future_line):
                    errors.append({
                        "file": "source",
                        "line": j,
                        "column": 0,
                        "type": "warning",
                        "message": f"division by zero: '{var}' is 0",
                        "raw": future_line,
                        "category": "division_by_zero",
                        "confidence": 0.9,
                    })
                    break

    return errors


def _classify_errors(errors: list[dict], classifier) -> list[dict]:
    """Attach 'category' to each error using the ML classifier."""
    for e in errors:
        if e.get("category"):
            e["confidence"] = round(float(e.get("confidence", 1.0)), 3)
            continue
        cat, conf = classifier.predict(e["message"])
        e["category"] = cat or "other"
        e["confidence"] = round(conf, 3)
    return errors


def _pick_fix_target(issues: list[dict]) -> Optional[dict]:
    """
    Prefer real errors, but allow fixable warnings such as uninitialized
    variables when there are no patchable hard errors.
    """
    for issue_type in ("error", "warning"):
        for issue in issues:
            if issue["type"] != issue_type:
                continue
            if issue.get("category") in UNFIXABLE_CATEGORIES:
                continue
            return issue
    return None


def create_heal_backup(file_path: str) -> Optional[str]:
    """
    Save original file to data/heal_backups/<name>_<timestamp>.cpp before any patches are applied.
    Returns the path to the backup file.
    """
    try:
        if not os.path.exists(file_path):
            return None
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        backup_dir = os.path.join(project_root, "data", "heal_backups")
        os.makedirs(backup_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(file_path))[0]
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"{base}_{timestamp}.cpp")
        with open(file_path, "r", encoding="utf-8") as sf:
            content = sf.read()
        with open(backup_path, "w", encoding="utf-8") as df:
            df.write(content)
        return backup_path
    except Exception:
        return None


class HealWorker(QThread):
    """
    QThread that runs the full heal loop asynchronously.
    Connect to its signals to receive live updates.
    """
    attempt_started = pyqtSignal(int, dict)          # (attempt_no, error)
    diff_ready      = pyqtSignal(int, str, str)       # (attempt_no, diff_html, label)
    compile_clean   = pyqtSignal(str)                 # label: "Healed by AI (Gemini)", etc.
    give_up         = pyqtSignal(list)                # history list
    error_signal    = pyqtSignal(str)                 # fatal/internal errors
    hint_required   = pyqtSignal(int, dict, list)     # (attempt_no, error, history)
    lines_fixed     = pyqtSignal(list)                # [line_no, ...]
    telemetry_ready = pyqtSignal(list)                # list[dict]
    backup_created  = pyqtSignal(str)                 # backup_path
    status_update   = pyqtSignal(str)                 # status text update
    info_message    = pyqtSignal(str)                 # card info message

    def __init__(self, file_path: str, classifier, hint: Optional[str] = None, enable_ai: bool = False):
        super().__init__()
        self.file_path  = file_path
        self.classifier = classifier
        self.hint       = hint          # optional user guidance from previous round
        self.enable_ai  = enable_ai
        self.last_backup_path: Optional[str] = None


    def run(self):
        try:
            telemetry = self._heal()
            self.telemetry_ready.emit(telemetry)
        except Exception as exc:
            self.error_signal.emit(str(exc))

    def _attach_failure_suggestion(self, history: list[dict], error: dict, source: str) -> None:
        if not error:
            return
        error["suggestion"] = suggest_failed_heal(error, source, history)

    def _heal(self) -> list[dict]:
        # 1. Back up the original file before any modification
        self.last_backup_path = create_heal_backup(self.file_path)
        if self.last_backup_path:
            self.backup_created.emit(self.last_backup_path)

        # Read current source
        with open(self.file_path, "r", encoding="utf-8") as f:
            source = f.read()

        from heal_engine import heal_until_clean

        def on_event(ev_type: str, data: dict):
            if ev_type == "status_update":
                self.status_update.emit(data.get("text", ""))
            elif ev_type == "attempt_started":
                self.attempt_started.emit(data.get("attempt", 1), data.get("target", {}))
            elif ev_type == "diff_ready":
                self.diff_ready.emit(data.get("attempt", 1), data.get("diff_html", ""), data.get("label", ""))
            elif ev_type == "lines_fixed":
                self.lines_fixed.emit(data.get("lines", []))
            elif ev_type == "info_message":
                self.info_message.emit(data.get("text", ""))

        result = heal_until_clean(
            source=source,
            classifier=self.classifier,
            hint=self.hint or "",
            use_ai=self.enable_ai,
            on_event=on_event,
        )

        # Write final code back to file
        with open(self.file_path, "w", encoding="utf-8") as f:
            f.write(result.code)

        telemetry = []
        for rnd in result.rounds:
            telemetry.append({
                "attempt": rnd.get("round_no", 1),
                "method": rnd.get("method", ""),
                "category": "auto_heal",
                "duration": rnd.get("seconds", 0.0),
                "emissions": 0.0,
                "success": rnd.get("errors_after", 0) == 0,
            })

        if result.clean:
            self.compile_clean.emit(result.message)
        else:
            history = []
            if self.hint:
                history.append({"type": "hint", "text": self.hint})
            for att in result.attempts:
                history.append(att)
            last_err = None
            for att in reversed(result.attempts):
                if att.get("target_error"):
                    last_err = att["target_error"]
                    break
                elif att.get("error"):
                    last_err = att["error"]
                    break
            self._attach_failure_suggestion(history, last_err, result.code)
            self.give_up.emit(history)

        return telemetry
