import os
import sys
import tempfile
import unittest

# Ensure src is on path
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TOOLS_DIR)
_SRC_DIR = os.path.join(_PROJECT_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer

# Initialize QApplication once
app = QApplication.instance()
if app is None:
    app = QApplication([])

import gui

class TestGuiFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a temporary workspace file
        cls.win = gui.AppGUI()

    def test_01_sidebar_buttons_and_labels(self):
        """Verify all 8 sidebar buttons have modern icons and clear descriptive labels."""
        sidebar = self.win.sidebar
        self.assertEqual(len(sidebar.buttons), 8)
        
        expected_labels = [
            "💻  Code Editor",
            "🌳  AST Explorer",
            "⚡  Energy Metrics",
            "🔄  Call Graph",
            "🛡️  Security Scan",
            "🔀  Control Flow",
            "🧠  Second Opinion",
            "📊  Benchmark",
        ]
        
        for idx, (btn, expected_label) in enumerate(zip(sidebar.buttons, expected_labels)):
            self.assertEqual(btn.text(), expected_label, f"Button {idx} label mismatch")
            self.assertTrue(len(btn.toolTip()) > 5, f"Button {idx} missing descriptive tooltip")

    def test_02_sidebar_navigation_and_active_state(self):
        """Verify clicking sidebar buttons switches pages and updates active state."""
        sidebar = self.win.sidebar
        stack = self.win.stack
        
        # Test switching to each page
        for page_idx in range(8):
            sidebar.buttons[page_idx].click()
            app.processEvents()
            self.assertEqual(stack.currentIndex(), page_idx, f"Page index {page_idx} not active")
            self.assertTrue(sidebar.buttons[page_idx].is_active, f"Button {page_idx} not marked active")
            # All other buttons should not be active
            for other_idx, other_btn in enumerate(sidebar.buttons):
                if other_idx != page_idx:
                    self.assertFalse(other_btn.is_active, f"Button {other_idx} should not be active")

        # Switch back to editor (page 0)
        sidebar.btn1.click()
        app.processEvents()
        self.assertEqual(stack.currentIndex(), 0)

    def test_03_compilation_and_execution_with_stdin(self):
        """Verify compile and run with user input 23 produces 23 on output screen."""
        code = """#include <iostream>
using namespace std;
int main(){
    int a;
    cin >> a;
    cout << a;
}
"""
        test_cpp = os.path.join(_PROJECT_ROOT, "test_user_io.cpp")
        with open(test_cpp, "w", encoding="utf-8") as f:
            f.write(code)

        self.win.file_path = test_cpp
        self.win.file_name = "test_user_io.cpp"
        self.win.editor.setPlainText(code)
        self.win.input_area.setPlainText("23")

        # Compile and run
        self.win.run_code()
        
        # Wait for QProcess to finish
        if hasattr(self.win, "process") and self.win.process:
            self.win.process.waitForFinished(4000)
            app.processEvents()

        output_text = self.win.terminal.toPlainText()
        print("\nCaptured output text in terminal:", repr(output_text))

        self.assertIn("23", output_text, "Terminal should contain '23'")
        self.assertNotIn("a.out' not found", output_text, "Should not complain about missing a.out")

        # Cleanup
        if os.path.exists(test_cpp):
            os.remove(test_cpp)
        for exe_name in ["a.exe", "a.out"]:
            if os.path.exists(exe_name):
                try:
                    os.remove(exe_name)
                except OSError:
                    pass

if __name__ == "__main__":
    unittest.main()
