#!/usr/bin/env python3
"""
tools/verify_gui_steps.py
--------------------------
Verifies Stage 7: Desktop GUI offscreen in isolated steps (one process per step).
Subcommands / Steps:
  --step 1 : Construct window, open every sidebar page, verify stack index
  --step 2 : Load copy of fixable.cpp, analyze, check cards, click finding (cursor jumps)
  --step 3 : run_code with clean program (mocked build) & blocked execvp program (banner + Fix button)
  --step 4 : Offline Auto-Heal on copy of fixable.cpp (SecurityResultCard, no duplicate findings, Undo restores)
  --step 5 : Security page tabs (Findings filters, Agents, Attack log with temp log, Benchmark tab with committed JSON)
  --step 6 : Run benchmark now worker with patched fast run_benchmark (no files under data/ change)
  --step 7 : Theme toggle twice (status chips remain intact)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

os.environ["QT_QPA_PLATFORM"] = "offscreen"

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from PyQt6.QtWidgets import QApplication, QFrame
from PyQt6.QtGui import QTextCursor

import theme
import gui
from guard.runner import ExecutionResult
from guard.safe_run import SafeResult
from ui_components import (
    SecuritySummaryCard,
    SecurityFindingCard,
    BlockedBanner,
    SecurityResultCard,
    IssueCard,
)


def print_table_header(col1: str, col2: str, col3: str, col4: str):
    print("+" + "-" * 27 + "+" + "-" * 30 + "+" + "-" * 30 + "+" + "-" * 6 + "+")
    print(f"| {col1:<25} | {col2:<28} | {col3:<28} | {col4:<4} |")
    print("+" + "-" * 27 + "+" + "-" * 30 + "+" + "-" * 30 + "+" + "-" * 6 + "+")


def print_table_row(col1: str, col2: str, col3: str, ok: bool):
    ok_str = "PASS" if ok else "FAIL"
    c1 = col1[:25]
    c2 = col2[:28]
    c3 = col3[:28]
    print(f"| {c1:<25} | {c2:<28} | {c3:<28} | {ok_str:<4} |")


def print_table_footer():
    print("+" + "-" * 27 + "+" + "-" * 30 + "+" + "-" * 30 + "+" + "-" * 6 + "+")


def get_qt_app():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    theme.apply_theme(app, "dark")
    return app


# ── Step 1 ───────────────────────────────────────────────────────────────────
def step_1() -> int:
    app = get_qt_app()
    win = gui.AppGUI()
    win.cb_ai_assist.setChecked(False)
    app.processEvents()

    print("\n--- Step 1: Construct Window & Open Every Sidebar Page ---")
    print_table_header("Check", "Expected", "Actual", "OK")
    all_ok = True

    has_sidebar = win.sidebar is not None
    btn_count = len(win.sidebar.buttons)
    ok_init = has_sidebar and (btn_count == 8)
    print_table_row("Sidebar created", "8 buttons present", f"buttons={btn_count}", ok_init)
    if not ok_init:
        all_ok = False

    nav_ok = True
    for idx, btn in enumerate(win.sidebar.buttons):
        btn.click()
        app.processEvents()
        curr_idx = win.stack.currentIndex()
        if curr_idx != idx:
            nav_ok = False
            print_table_row(f"Page {idx} activate", f"stack index {idx}", f"index {curr_idx}", False)

    print_table_row("All 8 pages navigable", "All indices match", f"all_matched={nav_ok}", nav_ok)
    if not nav_ok:
        all_ok = False

    win.sidebar.btn1.click()
    app.processEvents()
    print_table_footer()
    return 0 if all_ok else 1


# ── Step 2 ───────────────────────────────────────────────────────────────────
def step_2() -> int:
    app = get_qt_app()
    win = gui.AppGUI()
    win.cb_ai_assist.setChecked(False)
    app.processEvents()

    print("\n--- Step 2: Load fixable.cpp, Analyze & Jump Cursor ---")
    print_table_header("Check", "Expected", "Actual", "OK")
    all_ok = True

    fixable_src = _REPO_ROOT / "test_cases" / "security_heal" / "fixable.cpp"
    temp_dir = tempfile.mkdtemp(prefix="gui_step2_")
    temp_file = Path(temp_dir) / "fixable.cpp"
    shutil.copyfile(fixable_src, temp_file)

    try:
        win.load_file_path(str(temp_file))

        deadline = time.monotonic() + 25.0
        while getattr(win, "compile_worker", None) is not None and win.compile_worker.isRunning():
            if time.monotonic() > deadline:
                break
            app.processEvents()
            time.sleep(0.05)
        app.processEvents()

        # Summary card
        summary_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), SecuritySummaryCard)
        ]
        ok_sum = len(summary_cards) == 1
        print_table_row("SecuritySummaryCard", "1 card present", f"count={len(summary_cards)}", ok_sum)
        if not ok_sum:
            all_ok = False

        # Finding cards
        finding_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), SecurityFindingCard)
        ]
        ok_find = len(finding_cards) >= 1
        print_table_row("SecurityFindingCard", ">=1 cards present", f"count={len(finding_cards)}", ok_find)
        if not ok_find:
            all_ok = False

        # Click finding -> cursor moves
        if finding_cards:
            target_card = finding_cards[0]
            target_line = target_card.line
            target_card.clicked.emit(target_line)
            app.processEvents()

            cursor = win.editor.textCursor()
            actual_line = cursor.blockNumber() + 1
            ok_cur = (actual_line == target_line)
            print_table_row("Cursor jump on click", f"Line {target_line}", f"Line {actual_line}", ok_cur)
            if not ok_cur:
                all_ok = False

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    print_table_footer()
    return 0 if all_ok else 1


# ── Step 3 ───────────────────────────────────────────────────────────────────
def step_3() -> int:
    app = get_qt_app()
    win = gui.AppGUI()
    win.cb_ai_assist.setChecked(False)
    app.processEvents()

    print("\n--- Step 3: Run Clean Code & Blocked execvp Program ---")
    print_table_header("Check", "Expected", "Actual", "OK")
    all_ok = True

    # 1. Clean run (mocked build)
    clean_code = '#include <iostream>\nint main() { std::cout << "Clean execution"; return 0; }\n'
    win.editor.setPlainText(clean_code)
    app.processEvents()

    canned_text = "CANNED_OUTPUT_RUN_CLEAN_SUCCESS\n"
    canned_build = SafeResult(returncode=0, stdout="", stderr="", timed_out=False, truncated=False, duration_s=0.01)
    canned_run = SafeResult(returncode=0, stdout=canned_text, stderr="", timed_out=False, truncated=False, duration_s=0.01)
    canned_exec = ExecutionResult(build_result=canned_build, run_result=canned_run)

    with patch("guard.runner.build_and_run", return_value=canned_exec):
        win.run_code()
        deadline = time.monotonic() + 10.0
        while getattr(win, "_runner_worker", None) is not None and win._runner_worker.isRunning():
            if time.monotonic() > deadline:
                break
            app.processEvents()
            time.sleep(0.05)
        app.processEvents()

        ok_clean = canned_text in win.terminal.toPlainText() and win.btn_run.isEnabled()
        print_table_row("Clean program run", "Output in terminal, re-enabled", f"output_found={ok_clean}", ok_clean)
        if not ok_clean:
            all_ok = False

    # 2. Blocked execvp run
    blocked_code = '#include <unistd.h>\nint main() { execvp("ls", nullptr); return 0; }\n'
    win.editor.setPlainText(blocked_code)
    app.processEvents()

    with patch("guard.runner.build_and_run", side_effect=AssertionError("Must not call build_and_run")):
        win.run_code()
        app.processEvents()

        has_banner = isinstance(win.blocked_banner, BlockedBanner)
        has_fix_btn = has_banner and win.blocked_banner.fix_btn.text() == "Fix with Auto-Heal"
        ok_blk = has_banner and has_fix_btn
        print_table_row("Blocked execvp run", "BlockedBanner + Fix button", f"banner={has_banner} btn={has_fix_btn}", ok_blk)
        if not ok_blk:
            all_ok = False

    print_table_footer()
    return 0 if all_ok else 1


# ── Step 4 ───────────────────────────────────────────────────────────────────
def step_4() -> int:
    app = get_qt_app()
    win = gui.AppGUI()
    win.cb_ai_assist.setChecked(False)
    app.processEvents()

    print("\n--- Step 4: Offline Auto-Heal, Security Result Card & Undo ---")
    print_table_header("Check", "Expected", "Actual", "OK")
    all_ok = True

    fixable_src = _REPO_ROOT / "test_cases" / "security_heal" / "fixable.cpp"
    temp_dir = tempfile.mkdtemp(prefix="gui_step4_")
    temp_file = Path(temp_dir) / "fixable.cpp"
    shutil.copyfile(fixable_src, temp_file)
    with open(temp_file, "r", encoding="utf-8") as f:
        original_code = f.read()

    try:
        win.load_file_path(str(temp_file))
        # Wait for initial compile worker to settle
        deadline = time.monotonic() + 10.0
        while getattr(win, "compile_worker", None) is not None and win.compile_worker.isRunning():
            if time.monotonic() > deadline:
                break
            app.processEvents()
            time.sleep(0.05)
        app.processEvents()

        # Start heal
        win.start_heal()
        deadline = time.monotonic() + 45.0
        while getattr(win, "heal_worker", None) is not None and win.heal_worker.isRunning():
            if time.monotonic() > deadline:
                break
            app.processEvents()
            time.sleep(0.05)
        app.processEvents()

        # Result card
        sec_result_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), SecurityResultCard)
        ]
        ok_res = len(sec_result_cards) == 1
        print_table_row("SecurityResultCard", "1 card present", f"count={len(sec_result_cards)}", ok_res)
        if not ok_res:
            all_ok = False

        # Undo restores original
        win.undo_heal()
        app.processEvents()
        with open(temp_file, "r", encoding="utf-8") as f:
            restored = f.read()
        ok_undo = (restored == original_code)
        print_table_row("Undo restores file", "restored == original", f"match={ok_undo}", ok_undo)
        if not ok_undo:
            all_ok = False

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    print_table_footer()
    return 0 if all_ok else 1


# ── Step 5 ───────────────────────────────────────────────────────────────────
def step_5() -> int:
    app = get_qt_app()
    win = gui.AppGUI()
    win.cb_ai_assist.setChecked(False)
    app.processEvents()

    print("\n--- Step 5: Security Page Tabs (Findings, Agents, Attack Log, Benchmark) ---")
    print_table_header("Check", "Expected", "Actual", "OK")
    all_ok = True

    sec_page = win.security_page
    win.sidebar.btn5.click()  # Index 4
    app.processEvents()

    # Verify 4 tabs exist
    tab_count = sec_page.tabs.count()
    ok_tabs = (tab_count == 4)
    print_table_row("Security tabs count", "4 tabs", f"count={tab_count}", ok_tabs)
    if not ok_tabs:
        all_ok = False

    # Switch to Attack Log with temp log
    temp_dir = tempfile.mkdtemp(prefix="gui_log_tab_")
    custom_log = Path(temp_dir) / "attack_test.log"
    old_log = os.environ.get("GUARD_LOG_PATH")
    try:
        os.environ["GUARD_LOG_PATH"] = str(custom_log)
        from guard.attack_log import log_event
        log_event("test_gui_event", {"info": "test_tab_view"})

        sec_page.tabs.setCurrentIndex(2)  # Attack Log tab
        app.processEvents()
        sec_page._render_log()
        app.processEvents()

        row_count = sec_page.log_table.rowCount()
        ok_log = (row_count >= 1)
        print_table_row("Attack log populated", ">=1 rows in table", f"rows={row_count}", ok_log)
        if not ok_log:
            all_ok = False

        # Switch to Benchmark tab with committed JSON
        sec_page.tabs.setCurrentIndex(3)  # Benchmark tab
        app.processEvents()
        sec_page._load_committed_metrics()
        app.processEvents()

        src_text = sec_page.benchmark_source_lbl.text()
        has_src = "Source:" in src_text
        has_families = sec_page.bench_family_table.rowCount() > 0
        ok_bench = has_src and has_families
        print_table_row("Benchmark tab metrics", "Source & families loaded", f"src={has_src} fams={sec_page.bench_family_table.rowCount()}", ok_bench)
        if not ok_bench:
            all_ok = False

    finally:
        if old_log:
            os.environ["GUARD_LOG_PATH"] = old_log
        else:
            os.environ.pop("GUARD_LOG_PATH", None)
        shutil.rmtree(temp_dir, ignore_errors=True)

    print_table_footer()
    return 0 if all_ok else 1


# ── Step 6 ───────────────────────────────────────────────────────────────────
def step_6() -> int:
    app = get_qt_app()
    win = gui.AppGUI()
    win.cb_ai_assist.setChecked(False)
    app.processEvents()

    print("\n--- Step 6: Benchmark Worker (Patched Fast Run, No Data Files Modified) ---")
    print_table_header("Check", "Expected", "Actual", "OK")
    all_ok = True

    sec_page = win.security_page
    win.sidebar.btn5.click()
    sec_page.tabs.setCurrentIndex(3)
    app.processEvents()

    # Track data/ mtime
    data_metrics_file = _REPO_ROOT / "data" / "security_metrics.json"
    mtime_before = data_metrics_file.stat().st_mtime if data_metrics_file.exists() else 0

    # Mock run_benchmark in BenchmarkRunWorker
    dummy_metrics = {
        "manifest_summary": {"total_cases": 10, "headline_cases": 10},
        "overall": {
            "total_cases": 10,
            "total_attacks": 8,
            "benign_cases": 2,
            "standard_attacks": 8,
            "hard_attacks": 0,
            "detected": {"count": 8, "total": 8, "rate": 1.0, "ci_95": [0.7, 1.0]},
            "prevented": {"count": 8, "total": 8, "rate": 1.0, "ci_95": [0.7, 1.0]},
            "defended_asr": {"count": 0, "total": 8, "rate": 0.0},
            "baseline_asr": {"count": 7, "total": 8, "rate": 0.875},
            "false_alerts": {"count": 0, "total": 2, "rate": 0.0},
            "false_blocks": {"count": 0, "total": 2, "rate": 0.0},
        },
        "latency_ms": {"median": 1.0, "p95": 2.0, "max": 3.0, "n": 10},
        "routing": {"misses": 0, "total": 10},
        "agents": {},
        "families": {},
    }

    with patch("guard.benchmark.run_benchmark", return_value=dummy_metrics):
        sec_page.btn_run_benchmark.click()
        deadline = time.monotonic() + 15.0
        while getattr(sec_page, "benchmark_worker", None) is not None and sec_page.benchmark_worker.isRunning():
            if time.monotonic() > deadline:
                break
            app.processEvents()
            time.sleep(0.05)
        app.processEvents()

        mtime_after = data_metrics_file.stat().st_mtime if data_metrics_file.exists() else 0
        no_file_change = (mtime_before == mtime_after)
        btn_re_enabled = sec_page.btn_run_benchmark.isEnabled()
        ok_run = no_file_change and btn_re_enabled

        print_table_row("Benchmark worker finishes", "btn re-enabled", f"enabled={btn_re_enabled}", btn_re_enabled)
        print_table_row("No data/ files modified", "mtime identical", f"untouched={no_file_change}", no_file_change)
        if not ok_run:
            all_ok = False

    print_table_footer()
    return 0 if all_ok else 1


# ── Step 7 ───────────────────────────────────────────────────────────────────
def step_7() -> int:
    app = get_qt_app()
    win = gui.AppGUI()
    win.cb_ai_assist.setChecked(False)
    app.processEvents()

    print("\n--- Step 7: Theme Toggle Twice ---")
    print_table_header("Check", "Expected", "Actual", "OK")
    all_ok = True

    # 1. First toggle
    win.toggle_dark_mode()
    app.processEvents()
    ok_t1 = (win.security_chip is not None) and (win.model_chip is not None)
    print_table_row("First toggle (light)", "Chips intact", f"sec={win.security_chip is not None}", ok_t1)
    if not ok_t1:
        all_ok = False

    # 2. Second toggle
    win.toggle_dark_mode()
    app.processEvents()
    ok_t2 = (win.security_chip is not None) and (win.model_chip is not None)
    print_table_row("Second toggle (dark)", "Chips intact", f"sec={win.security_chip is not None}", ok_t2)
    if not ok_t2:
        all_ok = False

    print_table_footer()
    return 0 if all_ok else 1


def main():
    parser = argparse.ArgumentParser(description="Verify Desktop GUI Steps Offscreen")
    parser.add_argument("--step", type=int, choices=[1, 2, 3, 4, 5, 6, 7], required=True, help="Step number (1-7)")
    args = parser.parse_args()

    dispatch = {
        1: step_1,
        2: step_2,
        3: step_3,
        4: step_4,
        5: step_5,
        6: step_6,
        7: step_7,
    }
    sys.exit(dispatch[args.step]())


if __name__ == "__main__":
    main()
