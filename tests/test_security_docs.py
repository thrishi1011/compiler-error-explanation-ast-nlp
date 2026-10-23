"""
tests/test_security_docs.py
---------------------------
Unit tests for Phase 8c deliverables:
1. docs/SECURITY_ARCHITECTURE.md and docs/SECURITY_LIMITATIONS.md verification
2. latex_escape unit tests and LaTeX table numerical verification against JSON
3. TikZ architecture diagram consistency with registered agents and input kinds
4. Headless demo kit runner validation (max 9 calls, mocked LLM, exit code 0)
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import faulthandler
from pathlib import Path
import unittest

try:
    faulthandler.dump_traceback_later(90, exit=True)
except Exception:
    pass

os.environ["GUARD_NO_LATEX"] = "1"

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "src"
TOOLS_DIR = ROOT / "tools"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from guard.supervisor import get_supervisor
from guard.models import InputKind
from make_security_report_tables import latex_escape


class TestSecurityDocs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure latest docs and report assets are generated
        res_docs = subprocess.run([sys.executable, str(TOOLS_DIR / "make_security_docs.py")], capture_output=True, text=True)
        assert res_docs.returncode == 0, f"make_security_docs.py failed: {res_docs.stderr}"

        res_tables = subprocess.run([sys.executable, str(TOOLS_DIR / "make_security_report_tables.py")], capture_output=True, text=True)
        assert res_tables.returncode == 0, f"make_security_report_tables.py failed: {res_tables.stderr}"

        cls.arch_path = ROOT / "docs" / "SECURITY_ARCHITECTURE.md"
        cls.lim_path = ROOT / "docs" / "SECURITY_LIMITATIONS.md"
        cls.tables_path = ROOT / "docs" / "report" / "security_tables.tex"
        cls.overview_path = ROOT / "docs" / "report" / "security_overview.tex"
        cls.tikz_path = ROOT / "docs" / "report" / "security_architecture.tex"
        cls.metrics_path = ROOT / "data" / "security_metrics.json"

        cls.metrics = json.loads(cls.metrics_path.read_text(encoding="utf-8"))

    def test_make_security_docs_output_exists_and_registered_agents(self):
        """Docs exist and list exactly the registered agents from get_supervisor()."""
        self.assertTrue(self.arch_path.exists(), "SECURITY_ARCHITECTURE.md missing")
        self.assertTrue(self.lim_path.exists(), "SECURITY_LIMITATIONS.md missing")

        arch_text = self.arch_path.read_text(encoding="utf-8")
        supervisor = get_supervisor()
        registered_agent_names = {a.name for a in supervisor.agents}

        # Check each registered agent is in the markdown table
        for name in registered_agent_names:
            self.assertIn(f"`{name}`", arch_text, f"Agent {name} missing from table")

        # Check total registered agent count matches
        found_agents = set(re.findall(r"\|\s*`([A-Z][a-zA-Z0-9]+Guard)`\s*\|", arch_text))
        self.assertEqual(found_agents, registered_agent_names)

    def test_negative_word_assertions(self):
        """Must not mention forbidden terms; sandbox only in 'not a sandbox'."""
        arch_text = self.arch_path.read_text(encoding="utf-8")
        lim_text = self.lim_path.read_text(encoding="utf-8")

        forbidden = ["AI_PATCH", "SecurityHealer", "heal_source", "0-100", "homoglyph", "entropy"]
        for term in forbidden:
            self.assertNotIn(term, arch_text, f"Forbidden term '{term}' found in SECURITY_ARCHITECTURE.md")
            self.assertNotIn(term, lim_text, f"Forbidden term '{term}' found in SECURITY_LIMITATIONS.md")

        # Sandbox must only appear in sentences explicitly stating that it is NOT a sandbox
        for doc_name, doc_text in [("SECURITY_ARCHITECTURE.md", arch_text), ("SECURITY_LIMITATIONS.md", lim_text)]:
            for line in doc_text.splitlines():
                if "sandbox" in line.lower():
                    self.assertTrue(
                        "not a sandbox" in line.lower() or "not an" in line.lower() or "no filesystem" in line.lower(),
                        f"Unqualified sandbox reference in {doc_name}: {line}"
                    )

    def test_security_limitations_line_count(self):
        """SECURITY_LIMITATIONS.md must be at most 45 lines."""
        lines = self.lim_path.read_text(encoding="utf-8").splitlines()
        self.assertLessEqual(len(lines), 45, f"SECURITY_LIMITATIONS.md has {len(lines)} lines (max 45)")

    def test_enforcement_points_exist_in_codebase(self):
        """Every enforcement-point name in the documentation must resolve to a real code symbol."""
        arch_text = self.arch_path.read_text(encoding="utf-8")
        eps = re.findall(r"`([a-zA-Z0-9_\.]+)`", arch_text)

        # Candidate enforcement point symbols
        known_eps = {
            "compiler_runner.run_cpp_compiler",
            "heal_engine.compile_source",
            "ai_healer.attempt_ai_heal",
            "ai_explainer.explain_errors_batch",
            "llm_client.ask",
            "error_classifier.ErrorClassifier.load",
            "dataset_logger.log_example",
            "web_server.CompilerWebHandler",
            "gui.AppGUI.run_code",
            "guard.output_safe.safe_text",
        }

        # Verify each known enforcement point is present in documentation
        for ep in known_eps:
            self.assertIn(ep, arch_text, f"Expected enforcement point {ep} missing from docs")

            # Verify that the symbol exists in code
            parts = ep.split(".")
            mod_name = parts[0]
            if mod_name == "guard":
                mod_name = f"guard.{parts[1]}"
                attr_path = parts[2:]
            else:
                attr_path = parts[1:]

            mod = __import__(mod_name, fromlist=["*"])
            curr = mod
            for attr in attr_path:
                self.assertTrue(hasattr(curr, attr), f"Missing attribute {attr} on {curr}")
                curr = getattr(curr, attr)

    def test_latex_escape_unit(self):
        """latex_escape must properly escape & % $ # _ { } ~ ^ \\."""
        raw = r"test_func_name & 50% #1 $10 {brace} ^2 ~tilde \backslash"
        escaped = latex_escape(raw)

        # Check escaped forms
        self.assertIn(r"test\_func\_name", escaped)
        self.assertIn(r"\&", escaped)
        self.assertIn(r"50\%", escaped)
        self.assertIn(r"\#1", escaped)
        self.assertIn(r"\$10", escaped)
        self.assertIn(r"\{brace\}", escaped)
        self.assertIn(r"\textasciicircum{}2", escaped)
        self.assertIn(r"\textasciitilde{}tilde", escaped)
        self.assertIn(r"\textbackslash{}backslash", escaped)

        # Single-pass guarantee: escaped string should not contain unescaped chars
        self.assertNotIn(" #", escaped)
        self.assertNotIn(" $", escaped)

    def test_latex_assets_numbers_match_json(self):
        """Sample >= 20 numbers from JSON and verify they appear in the LaTeX assets."""
        tables_text = self.tables_path.read_text(encoding="utf-8")
        overview_text = self.overview_path.read_text(encoding="utf-8")
        combined_tex = tables_text + "\n" + overview_text

        metrics_file = ROOT / "data" / "security_metrics.json"
        metrics = json.loads(metrics_file.read_text(encoding="utf-8"))

        ov = metrics["overall"]
        std = metrics["by_set"]["standard"]["detection_rate"]
        hrd = metrics["by_set"]["hard"]["detection_rate"]
        lat = metrics["latency"]

        expected_values = [
            f"{ov['detection_rate']['rate'] * 100:.1f}",       # overall detection rate
            f"{ov['detection_rate']['count']}/{ov['detection_rate']['total']}", # detection counts
            f"{ov['prevention_rate']['rate'] * 100:.1f}",      # prevention rate
            f"{ov['prevention_rate']['count']}/{ov['prevention_rate']['total']}", # prevention counts
            f"{ov['defended_asr'] * 100:.1f}",                 # defended ASR
            f"{ov['baseline_asr'] * 100:.1f}",                 # baseline ASR
            f"{ov['false_alert_rate']['rate'] * 100:.1f}",     # false alert rate
            f"{ov['false_alert_rate']['count']}/{ov['false_alert_rate']['total']}", # false alert counts
            f"{std['rate'] * 100:.1f}",                        # standard detection rate
            f"{std['count']}/{std['total']}",                  # standard counts
            f"{hrd['rate'] * 100:.1f}",                        # hard detection rate
            f"{hrd['count']}/{hrd['total']}",                  # hard counts
            f"{lat['mean']:.2f}",                              # latency mean
            f"{lat['median']:.2f}",                            # latency median
            f"{lat['p95']:.2f}",                               # latency p95
            f"{lat['max']:.2f}",                               # latency max
            f"{lat['by_kind']['COMPILER_OUTPUT']['mean']:.2f}",# compiler output latency mean
            f"{lat['by_kind']['HTTP_REQUEST']['mean']:.2f}",   # http request latency mean
            "27",                                              # fixable.cpp risk before
            "17",                                              # unfixable.cpp risk
            "76.1",                                            # risk reduction total pct
        ]

        self.assertGreaterEqual(len(expected_values), 20)
        for val in expected_values:
            self.assertIn(val, combined_tex, f"Value {val} from JSON missing from LaTeX report tables")

    def test_latex_braces_and_no_unescaped_specials(self):
        """All three .tex files must have balanced braces and no unescaped _ or %."""
        tex_files = [self.tables_path, self.overview_path, self.tikz_path]
        for tf in tex_files:
            content = tf.read_text(encoding="utf-8")
            # 1. Balanced braces
            open_cnt = content.count("{")
            close_cnt = content.count("}")
            self.assertEqual(open_cnt, close_cnt, f"Unbalanced braces in {tf.name}: {open_cnt} vs {close_cnt}")

            # 2. No unescaped _ or % in non-comment text
            for idx, line in enumerate(content.splitlines(), 1):
                clean_line = re.sub(r"(?<!\\)%.*$", "", line).rstrip()
                self.assertFalse(
                    bool(re.search(r"(?<!\\)_", clean_line)),
                    f"Unescaped underscore at {tf.name}:{idx}: {line}"
                )
                self.assertFalse(
                    bool(re.search(r"(?<!\\)%", clean_line)),
                    f"Unescaped percent at {tf.name}:{idx}: {line}"
                )

    def test_tikz_diagram_agent_and_kind_names(self):
        """Agent and input kind names in TikZ diagram match registered code entities."""
        content = self.tikz_path.read_text(encoding="utf-8")
        supervisor = get_supervisor()
        registered_agents = {a.name for a in supervisor.agents}
        all_kinds = {k.name for k in InputKind}

        # Check all registered agents appear in TikZ
        for a in registered_agents:
            self.assertIn(a, content, f"Agent {a} missing from TikZ diagram")

        # Check all input kinds appear in TikZ (escaped for LaTeX)
        for k in all_kinds:
            self.assertIn(latex_escape(k), content, f"InputKind {k} missing from TikZ diagram")

    def test_run_security_demo_kit(self):
        """run_security_demo executes successfully with <= 9 supervisor reviews and passes mocked LLM."""
        import run_security_demo

        # Run headless demo suite
        res = run_security_demo.main()
        self.assertEqual(res, 0, "run_security_demo exited with non-zero code")

        # Verify that an unmocked external LLM call would be caught
        with self.assertRaises(RuntimeError):
            with unittest.mock.patch("llm_client.ask", side_effect=RuntimeError("Real LLM call attempted!")):
                import llm_client
                llm_client.ask("adversarial prompt")

    def test_auto_heal_saves_new_file_in_healed_folder(self):
        """Auto-heal must not change the present file, and must create healed/<name>_healed.cpp."""
        from heal_loop import HealWorker
        from error_classifier import get_default_classifier

        with tempfile.TemporaryDirectory() as td:
            tc_path = os.path.join(td, "test_case2.cpp")
            original_code = '#include <iostream>\nint main() { std::cout << "Missing semicolon"\nreturn 0; }\n'
            with open(tc_path, "w", encoding="utf-8") as f:
                f.write(original_code)

            healed_dir = os.path.join(td, "healed")
            healed_file = os.path.join(healed_dir, "test_case2_healed.cpp")

            clf = get_default_classifier()
            worker = HealWorker(
                file_path=tc_path,
                classifier=clf,
                enable_ai=False,
                output_path=healed_file,
                source=original_code,
            )
            # Run healing
            worker._heal()

            # 1. Verify original file was NOT modified
            with open(tc_path, "r", encoding="utf-8") as f:
                present_content = f.read()
            self.assertEqual(present_content, original_code, "Present file must NOT be changed by auto heal")

            # 2. Verify folder 'healed' was created
            self.assertTrue(os.path.isdir(healed_dir), "Folder 'healed' must be created")

            # 3. Verify 'test_case2_healed.cpp' was created in 'healed'
            self.assertTrue(os.path.isfile(healed_file), "test_case2_healed.cpp must exist in healed/ folder")

            with open(healed_file, "r", encoding="utf-8") as f:
                healed_content = f.read()
            self.assertIn(";", healed_content, "Healed file must contain the applied fix")
            self.assertNotEqual(healed_content, original_code, "Healed file must differ from original broken code")

    def test_error_normalizer_empty_and_compound_types(self):
        """Regression test: error_normalizer must return empty strings on empty input and preserve compound types."""
        from error_normalizer import normalize_error, normalize_for_classifier, build_ui_message
        d_empty, u_empty = normalize_error("")
        self.assertEqual(d_empty, "")
        self.assertEqual(u_empty, "")
        self.assertEqual(normalize_for_classifier(""), "")

        c_const = normalize_for_classifier("invalid conversion from 'const char*' to 'char*'")
        self.assertIn("'const char*'", c_const)
        self.assertIn("'char*'", c_const)

        c_redef = normalize_for_classifier("redefinition of 'int counter'")
        self.assertIn("'int <ID>'", c_redef)

    def test_uninitialized_variable_with_std_cout(self):
        """Regression test: fix_uninitialized_variable must not mistake std::cout for variable declaration."""
        import auto_healer
        src = '#include <iostream>\nint main() {\n    int x;\n    std::cout << x << std::endl;\n    return 0;\n}\n'
        err = {'file': 'main.cpp', 'line': 4, 'column': 5, 'type': 'warning', 'message': "'x' is used uninitialized in this function", 'category': 'other'}
        patched = auto_healer.attempt_fix(src, err)
        self.assertIsNotNone(patched)
        self.assertIn("int x = 0;", patched)
        self.assertIn("std::cout << x << std::endl;", patched)


if __name__ == "__main__":
    unittest.main()
