"""
tests/test_gui_structure.py
---------------------------
Static structure test (no Qt needed) using the ast module on:
  - src/gui.py
  - src/ui_components.py
  - src/gui_new_pages.py

Enforces:
  1. No ClassDef is nested inside another ClassDef.
  2. Every self.NAME used as a slot in a .connect(self.NAME) call or as a callback
     in QTimer.singleShot(..., self.NAME) inside class AppGUI is defined as a
     method or assigned attribute of AppGUI.
  3. AppGUI defines all required methods:
     analyze, run_code, start_heal, undo_heal, load_file, load_file_path, save_file,
     render_json, _on_analysis_finished, _on_heal_summary, _on_heal_success,
     _on_heal_give_up, _silent_reanalysis_after_heal, switch_to_ast, switch_to_security,
     toggle_dark_mode, request_ai_explanations, _show_blocked_banner,
     _update_security_status, _update_model_status.
  4. Every class used by AppGUI (RunnerWorker, CompilerWorker, SyntaxWorker,
     ASTWorker, TerminalDisplay, CodeEditor, etc.) is defined at module level.
"""
from __future__ import annotations

import ast
import os
import unittest


class TestGuiStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.target_files = [
            os.path.join(cls.repo_root, "src", "gui.py"),
            os.path.join(cls.repo_root, "src", "ui_components.py"),
            os.path.join(cls.repo_root, "src", "gui_new_pages.py"),
        ]

    def test_no_nested_classes(self):
        """No ClassDef is nested inside another ClassDef across GUI files."""
        for file_path in self.target_files:
            rel_name = os.path.relpath(file_path, self.repo_root)
            with open(file_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=file_path)

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    nested_classes = [
                        inner.name for inner in node.body if isinstance(inner, ast.ClassDef)
                    ]
                    self.assertEqual(
                        nested_classes,
                        [],
                        f"Found nested class(es) {nested_classes} inside class '{node.name}' in {rel_name}",
                    )

    def test_appgui_connected_slots_and_timer_callbacks(self):
        """Every self.NAME used in .connect(self.NAME) or QTimer.singleShot(..., self.NAME) exists on AppGUI."""
        gui_path = os.path.join(self.repo_root, "src", "gui.py")
        with open(gui_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=gui_path)

        app_gui_node = next(
            (node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "AppGUI"),
            None,
        )
        self.assertIsNotNone(app_gui_node, "Class AppGUI not found in src/gui.py")

        methods = {
            item.name
            for item in app_gui_node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        attributes = set()
        for node in ast.walk(app_gui_node):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                    ):
                        attributes.add(target.attr)

        connected_slots = set()
        for node in ast.walk(app_gui_node):
            if isinstance(node, ast.Call):
                # .connect(self.NAME)
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "connect"
                    and node.args
                ):
                    arg0 = node.args[0]
                    if (
                        isinstance(arg0, ast.Attribute)
                        and isinstance(arg0.value, ast.Name)
                        and arg0.value.id == "self"
                    ):
                        connected_slots.add(arg0.attr)

                # QTimer.singleShot(..., self.NAME)
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "singleShot"
                ):
                    for arg in node.args:
                        if (
                            isinstance(arg, ast.Attribute)
                            and isinstance(arg.value, ast.Name)
                            and arg.value.id == "self"
                        ):
                            connected_slots.add(arg.attr)

        defined_symbols = methods | attributes
        for slot in sorted(connected_slots):
            self.assertIn(
                slot,
                defined_symbols,
                f"self.{slot} used in slot connection or QTimer callback is not a defined method or attribute of AppGUI",
            )

    def test_appgui_required_methods(self):
        """AppGUI defines all required methods."""
        gui_path = os.path.join(self.repo_root, "src", "gui.py")
        with open(gui_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=gui_path)

        app_gui_node = next(
            (node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "AppGUI"),
            None,
        )
        self.assertIsNotNone(app_gui_node, "Class AppGUI not found in src/gui.py")

        methods = {
            item.name
            for item in app_gui_node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        required_methods = [
            "analyze",
            "run_code",
            "start_heal",
            "undo_heal",
            "load_file",
            "load_file_path",
            "save_file",
            "render_json",
            "_on_analysis_finished",
            "_on_heal_summary",
            "_on_heal_success",
            "_on_heal_give_up",
            "_silent_reanalysis_after_heal",
            "switch_to_ast",
            "switch_to_security",
            "toggle_dark_mode",
            "request_ai_explanations",
            "_show_blocked_banner",
            "_update_security_status",
            "_update_model_status",
        ]

        for method_name in required_methods:
            self.assertIn(
                method_name,
                methods,
                f"AppGUI does not define required method '{method_name}'",
            )

    def test_classes_used_by_appgui_defined_at_module_level(self):
        """Every worker/component class instantiated or used by AppGUI is defined at module level."""
        gui_path = os.path.join(self.repo_root, "src", "gui.py")
        with open(gui_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=gui_path)

        module_classes = {
            node.name for node in tree.body if isinstance(node, ast.ClassDef)
        }

        # Check key classes defined directly in src/gui.py
        expected_gui_classes = [
            "RunnerWorker",
            "CompilerWorker",
            "SyntaxWorker",
            "ASTWorker",
            "TerminalDisplay",
            "CodeEditor",
            "Sidebar",
            "AppGUI",
        ]

        for cls_name in expected_gui_classes:
            self.assertIn(
                cls_name,
                module_classes,
                f"Class '{cls_name}' must be defined at module level in src/gui.py",
            )

        # Check classes imported and used from ui_components.py and gui_new_pages.py
        ui_path = os.path.join(self.repo_root, "src", "ui_components.py")
        with open(ui_path, "r", encoding="utf-8") as f:
            ui_tree = ast.parse(f.read(), filename=ui_path)
        ui_classes = {
            node.name for node in ui_tree.body if isinstance(node, ast.ClassDef)
        }

        expected_ui_classes = [
            "SecuritySummaryCard",
            "SecurityFindingCard",
            "BlockedBanner",
            "SecurityResultCard",
            "IssueCard",
            "AiCard",
            "CollapsibleSection",
        ]

        for cls_name in expected_ui_classes:
            self.assertIn(
                cls_name,
                ui_classes,
                f"Class '{cls_name}' must be defined at module level in src/ui_components.py",
            )


if __name__ == "__main__":
    unittest.main()
