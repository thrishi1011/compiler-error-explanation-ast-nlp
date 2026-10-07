"""
heal_engine.py
--------------
Unified core self-healing engine used by both desktop (HealWorker / GUI)
and web IDE (web_server.py).

Guarantees:
1. Multi-round healing up to max_rounds (default 5, configurable via HEAL_MAX_ROUNDS).
2. AI heal (Gemini -> Groq) with validation + compiler feedback retry when online/available.
3. Automatic offline fallback (classifier + rule-based auto_healer, up to 10 attempts)
   on API problem, rate-limit, rejection, or when AI is disabled.
4. Error regression detection: reverts changes if a round makes compiler error count worse.
5. Exact duplicate #include and 'using namespace std;' removal after heal.
6. Structured return: code, status ("healed", "partially_healed", "nothing_changed"),
   rounds list, attempts list, and descriptive user-facing message.
"""

import os
import re
import sys
import time
import hashlib
import tempfile
import subprocess
from typing import Optional, List, Dict, Tuple, Any, Callable

# Ensure src/ in path
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from compiler_runner import _sanitize_code
from error_parser import parse_errors
from error_explainer import enrich_error
from auto_healer import attempt_fix, UNFIXABLE_CATEGORIES, clean_duplicate_headers
from diff_viewer import compute_diff, format_diff_html, has_changes
import llm_client
from ai_healer import attempt_ai_heal

try:
    from codecarbon import EmissionsTracker
    HAS_CODECARBON = True
except ImportError:
    HAS_CODECARBON = False


_ERR_PATTERN = re.compile(
    r"^(.+?):(\d+):(\d+):\s*(error|warning|fatal error):\s*(.*)$"
)


def compile_source(source: str) -> Tuple[List[dict], List[dict], str]:
    """
    Compile C++ code with g++ -std=c++17 -Wall.
    Returns (errors_list, warnings_list, raw_stderr).
    Each item is a dict with file, line, column, type, message, raw.
    """
    if not _sanitize_code(source):
        sec_err = [{
            "file": "<user_code>",
            "line": 1,
            "column": 1,
            "type": "error",
            "message": "Security Error: Malicious command injection or forbidden system call detected.",
            "raw": "error: Malicious code blocked",
            "category": "security_violation",
            "confidence": 1.0,
        }]
        return sec_err, [], "error: Malicious code blocked"

    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as tmp:
        tmp_path = tmp.name
        tmp.write(source)

    try:
        res = subprocess.run(
            ["g++", "-std=c++17", "-Wall", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        errors = []
        warnings = []
        for line in res.stderr.splitlines():
            m = _ERR_PATTERN.match(line.strip())
            if m:
                item = {
                    "file": "<user_code>",
                    "line": int(m.group(2)),
                    "column": int(m.group(3)),
                    "type": "error" if "error" in m.group(4) else "warning",
                    "message": m.group(5),
                    "raw": line.strip(),
                }
                if item["type"] == "error":
                    errors.append(item)
                else:
                    warnings.append(item)
        return errors, warnings, res.stderr
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _classify_error_list(errors: List[dict], classifier) -> List[dict]:
    """Attach category and confidence to errors using the classifier."""
    if not classifier:
        return errors
    for e in errors:
        if not e.get("category"):
            try:
                cat, conf = classifier.predict(e.get("message", ""))
                e["category"] = cat or "other"
                e["confidence"] = round(float(conf), 3)
            except Exception:
                e["category"] = "other"
                e["confidence"] = 0.5
    return errors


def pick_offline_target(issues: List[dict], source: str) -> Optional[dict]:
    """
    Pick a target issue to fix.
    Prefers errors over warnings.
    Only picks a warning if an actual fix rule exists for it in auto_healer.
    """
    # 1. First scan hard errors
    for issue in issues:
        if issue.get("type") == "error":
            if issue.get("category") not in UNFIXABLE_CATEGORIES:
                return issue

    # 2. If only warnings remain, test if a rule exists by seeing if attempt_fix changes code
    for issue in issues:
        if issue.get("type") == "warning":
            if issue.get("category") in UNFIXABLE_CATEGORIES:
                continue
            test_patch = attempt_fix(source, issue)
            if test_patch is not None and test_patch != source:
                return issue

    return None


class HealResult:
    def __init__(
        self,
        code: str,
        status: str,
        clean: bool,
        rounds: List[dict],
        message: str,
        total_duration: float = 0.0,
        total_emissions: float = 0.0,
        attempts: Optional[List[dict]] = None,
        initial_errors: int = 0,
        remaining_errors: int = 0,
        first_error: Optional[str] = None,
    ):
        self.code = code
        self.status = status          # "healed", "partially_healed", "nothing_changed"
        self.clean = clean            # True iff 0 g++ errors
        self.rounds = rounds
        self.message = message
        self.total_duration = total_duration
        self.total_emissions = total_emissions
        self.attempts = attempts if attempts is not None else []
        self.initial_errors = initial_errors
        self.remaining_errors = remaining_errors
        self.first_error = first_error

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "healed_code": self.code,
            "status": self.status,
            "clean": self.clean,
            "rounds": self.rounds,
            "attempts": self.attempts,
            "message": self.message,
            "total_duration": self.total_duration,
            "total_emissions": self.total_emissions,
            "initial_errors": self.initial_errors,
            "remaining_errors": self.remaining_errors,
            "first_error": self.first_error,
        }


def heal_until_clean(
    source: str,
    classifier=None,
    max_rounds: Optional[int] = None,
    hint: str = "",
    use_ai: Optional[bool] = None,
    on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> HealResult:
    """
    Main multi-round healing loop.
    Returns HealResult with status, rounds breakdown, and message.
    """
    start_time = time.time()
    if classifier is None:
        try:
            from error_classifier import get_default_classifier
            classifier = get_default_classifier()
        except Exception:
            classifier = None

    if max_rounds is None:
        try:
            max_rounds = int(os.environ.get("HEAL_MAX_ROUNDS", "5"))
        except ValueError:
            max_rounds = 5

    def emit(event_type: str, data: dict):
        if on_event:
            try:
                on_event(event_type, data)
            except Exception:
                pass

    current_source = source
    rounds_history: List[dict] = []
    all_attempts_flat: List[dict] = []
    seen_error_keys = set()
    initial_compile = True
    initial_error_count = 0

    # Initialize tracker if telemetry enabled and init takes < 1s
    tracker = None
    if os.environ.get("ENABLE_TELEMETRY", "1") != "0" and HAS_CODECARBON:
        try:
            t0 = time.time()
            tracker = EmissionsTracker(
                project_name="self_healing_compiler",
                measure_power_secs=1,
                log_level="error",
                save_to_file=False,
            )
            tracker.start()
            if time.time() - t0 > 1.0:
                # Took too long to initialize, do not wait on it
                tracker.stop()
                tracker = None
        except Exception:
            tracker = None

    # Check if AI is allowed and available
    g_key = llm_client.get_gemini_key()
    gr_key = llm_client.get_groq_key()
    keys_present = bool(g_key or gr_key)
    ai_allowed = (use_ai if use_ai is not None else True) and keys_present

    last_failure_reason = ""
    consecutive_no_change = 0
    prev_round_sig = None

    try:
        for round_no in range(1, max_rounds + 1):
            round_start_time = time.time()

            # 1. Compile current source
            errors, warnings, raw_stderr = compile_source(current_source)
            if initial_compile:
                initial_error_count = len(errors)
                initial_compile = False

            # If zero hard errors, we are done!
            if len(errors) == 0:
                msg = f"Compiles with {len(warnings)} warning(s)" if warnings else "Compiles cleanly with 0 errors"
                current_source = clean_duplicate_headers(current_source)
                emit("status_update", {"text": f"STATUS: ● HEALED ✅ ({msg})"})
                duration = time.time() - start_time
                emissions = 0.0
                if tracker:
                    try: emissions = tracker.stop() or 0.0
                    except: pass
                return HealResult(
                    code=current_source,
                    status="healed",
                    clean=True,
                    rounds=rounds_history,
                    attempts=all_attempts_flat,
                    message=msg,
                    total_duration=round(duration, 3),
                    total_emissions=round(emissions, 6),
                    initial_errors=initial_error_count,
                    remaining_errors=0,
                )

            current_sig = (hashlib.sha256(current_source.encode("utf-8")).hexdigest(), tuple(e["message"] for e in errors))
            if prev_round_sig == current_sig:
                consecutive_no_change += 1
                if consecutive_no_change >= 2:
                    last_failure_reason = "No progress after two consecutive rounds with identical errors"
                    break
            else:
                consecutive_no_change = 0
            prev_round_sig = current_sig

            errors_before = len(errors)
            round_applied = False
            round_method = ""
            round_model = None
            candidate_code = None

            # 2. Try AI attempt if allowed
            g_avail, _ = llm_client._GEMINI_STATE.is_available()
            gr_avail, _ = llm_client._GROQ_STATE.is_available()
            can_try_ai = ai_allowed and (g_avail or gr_avail)

            if can_try_ai:
                provider_label = "Gemini" if g_avail else "Groq"
                emit("status_update", {"text": f"Round {round_no}/{max_rounds} - AI ({provider_label})"})
                ai_code, provider, changes, status_desc = attempt_ai_heal(
                    current_source, errors, hint=hint
                )
                if ai_code:
                    # Validate compile improvement
                    ai_errors, _, _ = compile_source(ai_code)
                    if len(ai_errors) < errors_before:
                        candidate_code = ai_code
                        round_applied = True
                        round_method = f"AI ({provider.capitalize() if provider else 'AI'})"
                        round_model = provider
                    else:
                        last_failure_reason = f"AI heal did not reduce error count ({len(ai_errors)} >= {errors_before})"
                        emit("info_message", {"text": f"Round {round_no}: AI fix rejected (errors not reduced). Falling back to offline rules."})
                else:
                    last_failure_reason = status_desc
                    emit("info_message", {"text": f"Round {round_no}: {status_desc}. Using offline rules."})

            # 3. If AI was not used or did not reduce errors, run offline loop on current_source
            if not round_applied:
                emit("status_update", {"text": f"Round {round_no}/{max_rounds} - offline rules"})
                offline_source = current_source
                offline_attempts_count = 0
                max_offline_attempts = 10

                for off_att in range(1, max_offline_attempts + 1):
                    off_errors, off_warnings, _ = compile_source(offline_source)
                    if len(off_errors) == 0:
                        offline_source = clean_duplicate_headers(offline_source)
                        break

                    all_issues = off_errors + off_warnings
                    _classify_error_list(all_issues, classifier)
                    target = pick_offline_target(all_issues, offline_source)
                    if not target:
                        last_failure_reason = f"no rule for error type '{off_errors[0].get('category', 'unknown')}'"
                        break

                    line_no = target.get("line")
                    lines = offline_source.splitlines()
                    line_text = lines[line_no - 1].strip() if line_no and 1 <= line_no <= len(lines) else ""
                    error_key = (target.get("message"), line_no, line_text)
                    if error_key in seen_error_keys:
                        last_failure_reason = f"repeated error hit: {target.get('message')}"
                        break
                    seen_error_keys.add(error_key)

                    emit("attempt_started", {"attempt": len(all_attempts_flat) + 1, "target": target})
                    patched = attempt_fix(offline_source, target)
                    if patched is None or patched == offline_source:
                        all_attempts_flat.append({
                            "attempt_no": len(all_attempts_flat) + 1,
                            "target_error": target,
                            "diff_html": "",
                            "reason": "no_patch_available",
                        })
                        continue

                    # Check that patch didn't make errors worse
                    test_errors, _, _ = compile_source(patched)
                    if len(test_errors) > len(off_errors):
                        # Revert this patch
                        all_attempts_flat.append({
                            "attempt_no": len(all_attempts_flat) + 1,
                            "target_error": target,
                            "diff_html": "",
                            "reason": "patch_increased_errors_reverted",
                        })
                        continue

                    diff = compute_diff(offline_source, patched)
                    diff_html = format_diff_html(diff) if has_changes(diff) else ""
                    fixed_lines = [d.line_no_new for d in diff if d.kind == "+" and d.line_no_new is not None]
                    emit("diff_ready", {"attempt": len(all_attempts_flat) + 1, "diff_html": diff_html, "label": "offline rules"})
                    emit("lines_fixed", {"lines": fixed_lines})

                    all_attempts_flat.append({
                        "attempt_no": len(all_attempts_flat) + 1,
                        "target_error": target,
                        "diff_html": diff_html,
                        "patch": patched,
                    })

                    offline_source = patched
                    offline_attempts_count += 1

                # If offline loop improved code (errors decreased or did not get worse while fixing statements):
                off_final_errors, _, _ = compile_source(offline_source)
                if offline_source != current_source and len(off_final_errors) <= errors_before:
                    candidate_code = offline_source
                    round_applied = True
                    round_method = "offline rules"
                else:
                    last_failure_reason = last_failure_reason or "offline rules could not resolve remaining errors"

            # 4. Evaluate round results
            if round_applied and candidate_code is not None:
                new_errors, new_warnings, _ = compile_source(candidate_code)
                errors_after = len(new_errors)
                round_duration = time.time() - round_start_time

                diff = compute_diff(current_source, candidate_code)
                diff_html = format_diff_html(diff) if has_changes(diff) else ""

                rounds_history.append({
                    "round_no": round_no,
                    "method": round_method,
                    "model": round_model,
                    "errors_before": errors_before,
                    "errors_after": errors_after,
                    "seconds": round(round_duration, 3),
                    "diff_html": diff_html,
                })

                current_source = candidate_code

                if errors_after == 0:
                    msg = f"Compiles with {len(new_warnings)} warning(s)" if new_warnings else "Compiles cleanly with 0 errors"
                    current_source = clean_duplicate_headers(current_source)
                    emit("status_update", {"text": f"STATUS: ● HEALED ✅ ({msg})"})
                    duration = time.time() - start_time
                    emissions = 0.0
                    if tracker:
                        try: emissions = tracker.stop() or 0.0
                        except: pass
                    return HealResult(
                        code=current_source,
                        status="healed",
                        clean=True,
                        rounds=rounds_history,
                        attempts=all_attempts_flat,
                        message=msg,
                        total_duration=round(duration, 3),
                        total_emissions=round(emissions, 6),
                        initial_errors=initial_error_count,
                        remaining_errors=0,
                    )
            else:
                # Neither AI nor offline rules made progress
                rounds_history.append({
                    "round_no": round_no,
                    "method": "no progress",
                    "model": None,
                    "errors_before": errors_before,
                    "errors_after": errors_before,
                    "seconds": round(time.time() - round_start_time, 3),
                    "diff_html": "",
                })
                break

    finally:
        if tracker:
            try: tracker.stop()
            except: pass

    # 5. Final status calculation
    current_source = clean_duplicate_headers(current_source)
    final_errors, final_warnings, _ = compile_source(current_source)
    total_duration = round(time.time() - start_time, 3)

    if len(final_errors) == 0:
        status = "healed"
        msg = f"Compiles with {len(final_warnings)} warning(s)" if final_warnings else "Compiles cleanly with 0 errors"
    elif len(final_errors) < initial_error_count:
        status = "partially_healed"
        first = final_errors[0]
        first_line_info = f"line {first.get('line', '?')}: {first.get('message', '')}"
        msg = f"Partially healed ({len(final_errors)} errors left; {first_line_info})"
    else:
        status = "nothing_changed"
        first_line_info = f"line {final_errors[0].get('line', '?')}: {final_errors[0].get('message', '')}" if final_errors else ""
        msg = f"Nothing changed: {last_failure_reason or first_line_info or 'unfixable error'}"

    emit("status_update", {"text": f"STATUS: ● {status.upper().replace('_', ' ')}"})

    return HealResult(
        code=current_source,
        status=status,
        clean=(len(final_errors) == 0),
        rounds=rounds_history,
        attempts=all_attempts_flat,
        message=msg,
        total_duration=total_duration,
        total_emissions=0.0,
        initial_errors=initial_error_count,
        remaining_errors=len(final_errors),
        first_error=final_errors[0].get("message") if final_errors else None,
    )
