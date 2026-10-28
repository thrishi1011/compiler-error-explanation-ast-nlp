"""
tests/test_gui_clickthrough.py
------------------------------
Offscreen click-through test exercising AppGUI workflows:
  1. Construct AppGUI, click every sidebar button in turn, verify stack index changes without exception.
  2. Load test_cases/security_heal/fixable.cpp, compile/analyze, assert SecuritySummaryCard,
     SecurityFindingCard, no duplicate IssueCard, footer counts match compiler diagnostics.
  3. Simulate click on first SecurityFindingCard, assert cursor line jump and card selection,
     and assert tolerance for cards without set_selected.
  4. Toggle dark mode twice, verify status chips remain intact.
  5. run_code on clean code with patched build_and_run; verify terminal output and run button.
     run_code on blocked code; assert BlockedBanner and Fix with Auto-Heal button.
  6. Real offline Auto-Heal on fixable.cpp copy: assert SecurityResultCard headline,
     no duplicate security findings in IssueCards, and undo_heal restores original file.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PyQt6.QtWidgets import QApplication, QFrame
from PyQt6.QtGui import QTextCursor

from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _PROJECT_ROOT / "src"
for p in (str(_SRC_DIR), str(_PROJECT_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import theme
from guard.runner import ExecutionResult
from guard.safe_run import SafeResult
import gui
from ui_components import (
    SecuritySummaryCard,
    SecurityFindingCard,
    BlockedBanner,
    SecurityResultCard,
    IssueCard,
)


class TestGuiClickthrough(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)
        theme.apply_theme(cls.app, "dark")

    def test_full_gui_clickthrough(self):
        import faulthandler
        faulthandler.dump_traceback_later(90, exit=True)
        start_time = time.monotonic()
        app = self.app

        # ── Step 1: Construct AppGUI & Sidebar Navigation ─────────────────────
        win = gui.AppGUI()
        # Disable AI assist to ensure 100% offline execution
        win.cb_ai_assist.setChecked(False)
        app.processEvents()

        self.assertIsNotNone(win.sidebar, "Sidebar must exist")
        self.assertEqual(len(win.sidebar.buttons), 8, "Sidebar must have 8 navigation buttons")

        for idx, btn in enumerate(win.sidebar.buttons):
            btn.click()
            app.processEvents()
            self.assertEqual(
                win.stack.currentIndex(),
                idx,
                f"Sidebar button {idx} ('{btn.text()}') did not activate stack index {idx}",
            )

        # Return to Editor page (index 0)
        win.sidebar.btn1.click()
        app.processEvents()
        self.assertEqual(win.stack.currentIndex(), 0, "Must be back on Editor page")

        # ── Step 2: Load fixable.cpp, compile/analyze, assert cards ───────────
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        fixable_src = os.path.join(repo_root, "test_cases", "security_heal", "fixable.cpp")
        self.assertTrue(os.path.exists(fixable_src), f"Missing test case: {fixable_src}")

        temp_dir = tempfile.mkdtemp(prefix="gui_test_")
        temp_file = os.path.join(temp_dir, "fixable.cpp")
        shutil.copyfile(fixable_src, temp_file)

        with open(temp_file, "r", encoding="utf-8") as f:
            original_code = f.read()

        win.load_file_path(temp_file)
        win.analyze()

        # Wait up to 20 seconds for CompilerWorker
        deadline = time.monotonic() + 20.0
        while getattr(win, "compile_worker", None) is not None and win.compile_worker.isRunning():
            if time.monotonic() > deadline:
                self.fail("Timeout (20s) waiting for compile_worker to finish analysis")
            app.processEvents()
            time.sleep(0.05)
        app.processEvents()

        # Assert SecuritySummaryCard exists
        summary_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), SecuritySummaryCard)
        ]
        self.assertEqual(len(summary_cards), 1, "Exactly one SecuritySummaryCard must be present")

        # Assert at least one SecurityFindingCard exists
        finding_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), SecurityFindingCard)
        ]
        self.assertGreaterEqual(
            len(finding_cards), 1, "At least one SecurityFindingCard must be present for fixable.cpp"
        )

        # Assert no security-derived diagnostic appears as an IssueCard
        issue_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), IssueCard)
        ]
        for ic in issue_cards:
            origin = getattr(ic.err, "origin", None) if hasattr(ic.err, "origin") else ic.err.get("origin")
            self.assertNotEqual(origin, "security", "Security findings must not appear as compiler IssueCard")

        # Assert footer counts equal compiler diagnostics
        compiler_errors = [ic for ic in issue_cards if (getattr(ic.err, "error_type", None) or ic.err.get("type")) == "error"]
        self.assertEqual(win.errors_count, len(compiler_errors), "Footer error count must equal compiler diagnostics only")

        # ── Step 3: Card Selection & set_selected Tolerance ───────────────────
        target_card = finding_cards[0]
        target_line = target_card.line
        self.assertIsNotNone(target_line, "Finding card must have a line number")

        # Simulate click on first SecurityFindingCard
        target_card.clicked.emit(target_line)
        app.processEvents()

        cursor = win.editor.textCursor()
        self.assertEqual(
            cursor.blockNumber() + 1,
            target_line,
            f"Editor cursor should jump to finding line {target_line}",
        )
        self.assertEqual(
            target_card.property("selected"),
            "true",
            "Target card property 'selected' must be 'true'",
        )

        # Unit assertion: _on_issue_clicked tolerates cards without set_selected method
        dummy_card = QFrame()
        self.assertFalse(hasattr(dummy_card, "set_selected"))
        win.issue_cards.append(dummy_card)
        try:
            # Should not raise AttributeError
            win._on_issue_clicked(target_line)
            app.processEvents()
        finally:
            if dummy_card in win.issue_cards:
                win.issue_cards.remove(dummy_card)

        # ── Step 4: Theme Toggle ──────────────────────────────────────────────
        win.toggle_dark_mode()
        app.processEvents()
        self.assertIsNotNone(win.security_chip, "Security chip must remain present after theme toggle")
        self.assertIsNotNone(win.model_chip, "Model chip must remain present after theme toggle")

        win.toggle_dark_mode()
        app.processEvents()
        self.assertIsNotNone(win.security_chip, "Security chip must remain present after second theme toggle")
        self.assertIsNotNone(win.model_chip, "Model chip must remain present after second theme toggle")

        # ── Step 5: run_code with Canned Output and Blocked Banner ────────────
        clean_code = '#include <iostream>\nint main() { std::cout << "Clean execution"; return 0; }\n'
        win.editor.setPlainText(clean_code)
        app.processEvents()

        canned_text = "CANNED_TEST_OUTPUT_EXECUTION_SUCCESS\n"
        canned_build = SafeResult(returncode=0, stdout="", stderr="", timed_out=False, truncated=False, duration_s=0.01)
        canned_run = SafeResult(returncode=0, stdout=canned_text, stderr="", timed_out=False, truncated=False, duration_s=0.01)
        canned_exec = ExecutionResult(build_result=canned_build, run_result=canned_run)

        with patch("guard.runner.build_and_run", return_value=canned_exec):
            win.run_code()
            deadline = time.monotonic() + 10.0
            while getattr(win, "_runner_worker", None) is not None and win._runner_worker.isRunning():
                if time.monotonic() > deadline:
                    self.fail("Timeout (10s) waiting for RunnerWorker")
                app.processEvents()
                time.sleep(0.05)
            app.processEvents()

            self.assertIn(canned_text, win.terminal.toPlainText(), "Terminal must contain canned output")
            self.assertTrue(win.btn_run.isEnabled(), "Run button must be re-enabled after run finishes")

        # Test blocked run code
        blocked_code = '#include <unistd.h>\nint main() { execvp("ls", nullptr); return 0; }\n'
        win.editor.setPlainText(blocked_code)
        app.processEvents()

        with patch(
            "guard.runner.build_and_run",
            side_effect=AssertionError("build_and_run should NOT be called when execution is blocked"),
        ):
            win.run_code()
            app.processEvents()

            self.assertIsNotNone(win.blocked_banner, "BlockedBanner must appear when execution is blocked")
            self.assertIsInstance(win.blocked_banner, BlockedBanner)
            self.assertIsNotNone(win.blocked_banner.fix_btn, "BlockedBanner must have a Fix button")
            self.assertEqual(win.blocked_banner.fix_btn.text(), "Fix with Auto-Heal")

        # ── Step 6: Real Offline Auto-Heal on fixable.cpp ─────────────────────
        # Restore fixable.cpp content to temp file
        shutil.copyfile(fixable_src, temp_file)
        win.load_file_path(temp_file)
        win.analyze()

        # Settle any compile worker triggered by load_file_path
        deadline = time.monotonic() + 10.0
        while getattr(win, "compile_worker", None) is not None and win.compile_worker.isRunning():
            if time.monotonic() > deadline:
                break
            app.processEvents()
            time.sleep(0.05)
        app.processEvents()

        # Start real offline auto-heal
        win.start_heal()

        deadline = time.monotonic() + 40.0
        while getattr(win, "heal_worker", None) is not None and win.heal_worker.isRunning():
            if time.monotonic() > deadline:
                self.fail("Timeout (40s) waiting for heal_worker to complete")
            app.processEvents()
            time.sleep(0.05)
        app.processEvents()

        # Assert SecurityResultCard appears with formatted headline
        sec_result_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), SecurityResultCard)
        ]
        self.assertEqual(len(sec_result_cards), 1, "Expected exactly one SecurityResultCard after Auto-Heal")
        sec_card = sec_result_cards[0]

        headline = sec_card.view.get("headline", "")
        self.assertRegex(
            headline,
            r"^Security:\s+\w+(\s+\w+)?\s+\(\d+\)\s+->\s+\w+(\s+\w+)?\s+\(\d+\)",
            f"Headline must match pattern 'Security: <label> (<n>) -> <label> (<n>)', got: '{headline}'",
        )

        # Assert no remaining security finding is shown twice (intersection between SecurityResultCard and IssueCards is empty)
        remaining_findings = sec_card.view.get("remaining", [])
        sec_rem_tuples = set()
        for rf in remaining_findings:
            cat = rf.get("category", "")
            line = rf.get("line")
            sec_rem_tuples.add((cat, line))

        post_heal_issue_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), IssueCard)
        ]
        issue_tuples = set()
        for ic in post_heal_issue_cards:
            cat = getattr(ic.err, "category", "") if hasattr(ic.err, "category") else ic.err.get("category", "")
            line = getattr(ic.err, "line", None) if hasattr(ic.err, "line") else ic.err.get("line")
            issue_tuples.add((cat, line))

        overlap = sec_rem_tuples & issue_tuples
        self.assertEqual(overlap, set(), f"Remaining security findings must not be duplicated as IssueCards: {overlap}")

        # Assert undo_heal restores original file content
        win.undo_heal()
        app.processEvents()

        with open(temp_file, "r", encoding="utf-8") as f:
            restored_code = f.read()
        self.assertEqual(restored_code, original_code, "undo_heal must restore original file content")

        # Cleanup temp directory
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

        total_duration = time.monotonic() - start_time
        self.assertLess(total_duration, 60.0, f"Full clickthrough test must finish in under 60s (took {total_duration:.2f}s)")


if __name__ == "__main__":
    unittest.main()
