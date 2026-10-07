#!/usr/bin/env python3
"""
tools/heal_stress_check.py
---------------------------
Stress and reliability check for self-healing in both desktop (HealWorker)
and web IDE paths.
Supports:
  --reproduce : Reproduces items 1, 7, and 13 before fixes.
  (default)   : Full stress test in ONE process.
"""

import os
import sys
import json
import tempfile
import subprocess
import time
from typing import Optional, List, Tuple
from unittest.mock import patch, MagicMock

# Setup paths
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TOOLS_DIR)
_SRC_DIR = os.path.join(_PROJECT_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from PyQt6.QtCore import QCoreApplication
import llm_client
from llm_client import LLMResult, reset_client_state
from error_classifier import get_default_classifier
from heal_loop import HealWorker
import web_server
from web_server import CompilerWebHandler

# Test programs
PROG_5_ERRORS = """#include <iostream>
using namespace std;
int main() {
    int a = 10
    int b = 20
    int c = a + b
    cout << "Sum: " << c << endl
    return 0
}
"""

PROG_REPEATED_MESSAGES = """#include <iostream>
using namespace std;
int main() {
    int x = 1
    int y = 2
    int z = 3
    return 0;
}
"""

PROG_LEFTOVER_WARNING = """#include <iostream>
using namespace std;
int main() {
    unsigned int u = 10;
    int s = -5;
    if (s < u) {
        cout << "ok" << endl;
    }
    return 0;
}
"""

def compile_check(code: str) -> Tuple[bool, int, str]:
    """Compile with g++ -std=c++17 -Wall and return (clean, error_count, first_error)."""
    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as tmp:
        tmp_path = tmp.name
        tmp.write(code)
    try:
        res = subprocess.run(
            ["g++", "-std=c++17", "-Wall", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        errors = [l.strip() for l in res.stderr.splitlines() if ": error:" in l or ": fatal error:" in l]
        warnings = [l.strip() for l in res.stderr.splitlines() if ": warning:" in l]
        first_err = errors[0] if errors else (warnings[0] if warnings else "")
        return (len(errors) == 0, len(errors), first_err)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


class DummyWebHandler(CompilerWebHandler):
    def __init__(self):
        self.response_data = None
    def _send_json(self, data, status=200):
        self.response_data = data


def run_full_stress_test():
    print("=" * 85)
    print("RUNNING FULL HEAL STRESS & RELIABILITY CHECK (ONE PROCESS)")
    print("=" * 85)

    app = QCoreApplication.instance() or QCoreApplication([])
    clf = get_default_classifier()

    # Scripted mock responses for AI
    fixed_code_1 = """#include <iostream>
using namespace std;
int main() {
    int a = 10;
    int b = 20;
    int c = a + b;
    cout << "Sum: " << c << endl;
    return 0;
}
"""
    success_json = json.dumps({"code": fixed_code_1, "changes": ["added semicolons"]})

    # Test cases definition: (name, code, mock_behavior)
    scenarios = [
        ("Run 1: 5+ errors [Mock AI Success]", PROG_5_ERRORS, "success"),
        ("Run 2: Repeated identical errors [Mock AI 429]", PROG_REPEATED_MESSAGES, "429"),
        ("Run 3: Leftover warning only [Mock AI Malformed JSON]", PROG_LEFTOVER_WARNING, "malformed"),
    ]

    all_passed = True

    for run_idx, (name, code, mock_mode) in enumerate(scenarios, 1):
        print(f"\n>>> {name}")
        reset_client_state()

        def make_mock_post(mode):
            def _mock_post(url, headers, payload, timeout):
                if mode == "success":
                    resp_dict = {
                        "candidates": [{"content": {"parts": [{"text": success_json}]}}]
                    }
                    return 200, json.dumps(resp_dict), {}
                elif mode == "429":
                    return 429, "rate limit exceeded per minute", {"retry-after": "5"}
                elif mode == "malformed":
                    resp_dict = {
                        "candidates": [{"content": {"parts": [{"text": "this is not valid json {"}]}}]
                    }
                    return 200, json.dumps(resp_dict), {}
                return 500, "Internal error", {}
            return _mock_post

        with patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_g_key", "GROQ_API_KEY": "dummy_gr_key"}), \
             patch("llm_client._http_post", side_effect=make_mock_post(mock_mode)):

            # 1. Desktop path test
            with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as tmp:
                tmp_path = tmp.name
                tmp.write(code)

            try:
                worker = HealWorker(tmp_path, clf, enable_ai=True)
                clean_signals = []
                give_up_signals = []
                worker.compile_clean.connect(lambda msg: clean_signals.append(msg))
                worker.give_up.connect(lambda hist: give_up_signals.append(hist))
                telemetry = worker._heal()

                with open(tmp_path, "r", encoding="utf-8") as rf:
                    final_desk_code = rf.read()
                clean_gpp, err_count, msg = compile_check(final_desk_code)
                method_used = telemetry[0].get("method", "offline") if telemetry else "offline rules"
                rounds_count = len(telemetry)

                desk_pass = clean_gpp
                status_msg = clean_signals[0] if clean_signals else (f"give_up ({len(give_up_signals)})" if give_up_signals else "unknown")
                print(f"  [Desktop] Rounds: {rounds_count} | Method: {method_used} | Final G++: {'0 errors (CLEAN)' if clean_gpp else f'{err_count} errors'} | Status: {status_msg}")
                if not desk_pass:
                    all_passed = False
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

            # 2. Web handler test
            handler = DummyWebHandler()
            handler.handle_heal(code)
            res = handler.response_data or {}
            final_web_code = res.get("healed_code", code)
            clean_gpp_web, err_count_web, msg_web = compile_check(final_web_code)
            web_clean_flag = res.get("clean", False)
            web_rounds = len(res.get("rounds", []))
            web_method = res.get("rounds", [{}])[0].get("method", "offline rules") if res.get("rounds") else "offline rules"
            web_msg = res.get("message", "")

            web_pass = clean_gpp_web and web_clean_flag
            print(f"  [Web IDE] Rounds: {web_rounds} | Method: {web_method} | Final G++: {'0 errors (CLEAN)' if clean_gpp_web else f'{err_count_web} errors'} | Status: {web_msg}")
            if not web_pass:
                all_passed = False

    # 4. Offline-only run per path
    print("\n>>> Run 4: Offline-only baseline (AI disabled) on multi-error code")
    reset_client_state()
    with patch.dict(os.environ, {"GEMINI_API_KEY": "", "GROQ_API_KEY": ""}):
        with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as tmp:
            tmp_path = tmp.name
            tmp.write(PROG_5_ERRORS)

        try:
            worker = HealWorker(tmp_path, clf, enable_ai=False)
            worker._heal()
            with open(tmp_path, "r", encoding="utf-8") as rf:
                code_off = rf.read()
            clean_off, err_off, msg_off = compile_check(code_off)
            print(f"  [Desktop Offline] Final G++: {'0 errors (CLEAN)' if clean_off else f'{err_off} errors'} | Clean: {clean_off}")
            if not clean_off:
                all_passed = False
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        handler = DummyWebHandler()
        handler.handle_heal(PROG_5_ERRORS)
        res_off = handler.response_data or {}
        clean_web_off, err_web_off, _ = compile_check(res_off.get("healed_code", ""))
        print(f"  [Web IDE Offline] Final G++: {'0 errors (CLEAN)' if clean_web_off else f'{err_web_off} errors'} | Clean: {res_off.get('clean')}")
        if not clean_web_off or not res_off.get("clean"):
            all_passed = False

    print("\n" + "=" * 85)
    if all_passed:
        print("ALL STRESS TESTS PASSED SUCCESSFULLY [OK]")
    else:
        print("SOME TESTS FAILED [FAIL]")
    print("=" * 85)
    return all_passed


def reproduce_issues():
    """Reproduce items 1, 7, and 13 on current files before fixes."""
    print("=" * 80)
    print("REPRODUCING ISSUES 1, 7, 13 (BEFORE FIXES)")
    print("=" * 80)

    # ── Item 1: Web IDE repeated identical error messages ──
    print("\n--- Test 1 (Item 1): Web IDE repeated identical error messages ---")
    handler = DummyWebHandler()
    handler.handle_heal(PROG_REPEATED_MESSAGES)
    res1 = handler.response_data
    attempts1 = len(res1.get("attempts", [])) if res1 else 0
    clean1 = res1.get("clean", False) if res1 else False
    final_clean1, err_count1, first_err1 = compile_check(res1.get("healed_code", PROG_REPEATED_MESSAGES))
    print(f"Result: clean={clean1}, attempts={attempts1}, remaining_errors={err_count1}")
    print(f"First error: {first_err1}")
    if not clean1 and attempts1 == 1:
        print("FAIL (Item 1 Confirmed): Web IDE broke after 1 attempt because duplicate error message hit seen_errors!")

    # ── Item 7: Desktop _pick_fix_target picks warning with no rule ──
    print("\n--- Test 2 (Item 7): Desktop path with leftover warning (-Wsign-compare) ---")
    app = QCoreApplication.instance() or QCoreApplication([])
    clf = get_default_classifier()
    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as tmp:
        tmp_path = tmp.name
        tmp.write(PROG_LEFTOVER_WARNING)

    worker = HealWorker(tmp_path, clf, enable_ai=False)
    events = []
    worker.compile_clean.connect(lambda msg: events.append(("clean", msg)))
    worker.give_up.connect(lambda hist: events.append(("give_up", hist)))

    try:
        worker._heal()
    except Exception as e:
        events.append(("error", str(e)))

    clean_gpp, err_count, msg = compile_check(PROG_LEFTOVER_WARNING)
    print(f"G++ compile of source: 0 errors (clean={clean_gpp}, msg='{msg}')")
    print(f"Worker emitted: {[e[0] for e in events]}")
    if any(e[0] == "give_up" for e in events) and clean_gpp:
        print("FAIL (Item 7 Confirmed): HealWorker called give_up despite code compiling with 0 errors!")

    if os.path.exists(tmp_path):
        os.remove(tmp_path)

    # ── Item 13: 429 Retry-After parsing ──
    print("\n--- Test 3 (Item 13): 429 Retry-After parsing and provider cooldown ---")
    cooldown = llm_client._parse_retry_after({"retry-after": "120"}, "rate limit exceeded per minute")
    print(f"Parsed cooldown for retry-after 120s: {cooldown}s")
    if cooldown > 60.0:
        print(f"FAIL (Item 13 Confirmed): Per-minute 429 paused provider for {cooldown}s (> 60s max)!")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    if "--reproduce" in sys.argv:
        reproduce_issues()
    else:
        success = run_full_stress_test()
        sys.exit(0 if success else 1)
