"""
tests/test_guard_phase8a.py
---------------------------
Phase 8a test suite for the security UI integration:
1. Pure view-model tests (security_view.py)
   - build_security_summary for Clean, Moderate, and High Risk
   - finding_view for attack vs vulnerability, action labels, detected_by text
   - sort_findings ordering (severity then line)
   - heal_security_view with synthetic dict and with None
   - blocked_banner_view
2. Category coverage:
   - every expected_category in security_bench/manifest.json
   - every category string a guard agent emits
   - unknown category fallback (never raises)
3. JSON feed & CLI:
   - python src/main.py -j produces guard block and origin == 'security' on static findings
   - web_server handle_compile produces guard block
4. Plain text protection:
   - findings with <b>x</b> and <img src=x> are not rendered as HTML; plain text format verified
5. GUI offscreen test 1:
   - render_json with guard block, verify summary card, finding cards, no duplicate diagnostics, footer counts, theme switching
6. GUI offscreen test 2:
   - _on_heal_summary with security dict verifies SecurityResultCard headline
   - blocked banner path verifies banner and fix button
"""

from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

# Ensure src/ and root are in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _PROJECT_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Set Qt offscreen mode before importing any Qt components
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from security_view import (
    CATEGORY_TITLES,
    CATEGORY_WHY,
    get_category_title,
    get_category_why,
    build_security_summary,
    finding_view,
    sort_findings,
    heal_security_view,
    blocked_banner_view,
    review_source_guard,
)


class TestSecurityViewModel(unittest.TestCase):
    """1. Pure view-model tests (no Qt)."""

    def test_build_security_summary_clean(self):
        clean_guard = {
            "risk_score": 0,
            "risk_label": "Clean",
            "blocked_purposes": [],
            "findings": [],
            "agents_run": ["ExecGuard", "VulnGuard"],
            "total_ms": 1.2,
        }
        res = build_security_summary(clean_guard)
        self.assertEqual(res["level"], "Clean")
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["tone"], "ok")
        self.assertEqual(res["total"], 0)
        self.assertEqual(res["counts"]["Critical"], 0)
        self.assertEqual(res["counts"]["High"], 0)
        self.assertEqual(res["counts"]["Medium"], 0)
        self.assertEqual(res["counts"]["Low"], 0)
        self.assertIn("Clean", res["headline"])

    def test_build_security_summary_moderate(self):
        mod_guard = {
            "risk_score": 25,
            "risk_label": "Moderate",
            "blocked_purposes": [],
            "findings": [
                {"severity": "High", "agents": ["VulnGuard"]},
                {"severity": "Medium", "agents": ["ExecGuard"]},
                {"severity": "Medium", "agents": ["VulnGuard"]},
                {"severity": "Low", "agents": ["ResourceGuard"]},
            ],
            "agents_run": ["ExecGuard", "VulnGuard", "ResourceGuard"],
            "total_ms": 2.5,
        }
        res = build_security_summary(mod_guard)
        self.assertEqual(res["level"], "Moderate")
        self.assertEqual(res["score"], 25)
        self.assertEqual(res["tone"], "warn")
        self.assertEqual(res["total"], 4)
        self.assertEqual(res["counts"]["High"], 1)
        self.assertEqual(res["counts"]["Medium"], 2)
        self.assertEqual(res["counts"]["Low"], 1)
        self.assertEqual(res["agents"], ["ExecGuard", "ResourceGuard", "VulnGuard"])
        self.assertIn("Moderate risk, 4 findings", res["headline"])
        self.assertIn("ExecGuard", res["headline"])
        self.assertIn("VulnGuard", res["headline"])

    def test_build_security_summary_high_risk(self):
        high_guard = {
            "risk_score": 60,
            "risk_label": "High Risk",
            "blocked_purposes": ["compile", "run"],
            "findings": [
                {"severity": "Critical", "agents": ["ExecGuard"]},
                {"severity": "High", "agents": ["PromptGuard"]},
            ],
            "agents_run": ["ExecGuard", "PromptGuard"],
            "total_ms": 3.1,
        }
        res = build_security_summary(high_guard)
        self.assertEqual(res["level"], "High Risk")
        self.assertEqual(res["score"], 60)
        self.assertEqual(res["tone"], "error")
        self.assertEqual(res["counts"]["Critical"], 1)
        self.assertEqual(res["counts"]["High"], 1)
        self.assertEqual(res["blocked_purposes"], ["compile", "run"])

    def test_finding_view_attack_vs_vulnerability(self):
        # Attack finding
        att_finding = {
            "id": "a1",
            "origin": "attack",
            "category": "process_execution",
            "severity": "High",
            "agents": ["ExecGuard"],
            "line": 12,
            "description": "system() call detected",
            "recommendation": "Avoid system execution",
            "action": "block",
            "blocks_on": ["run"],
            "evidence": "system(\"rm -rf /\");",
        }
        view_att = finding_view(att_finding, current_purposes=["run"])
        self.assertEqual(view_att["title"], "Process execution")
        self.assertEqual(view_att["severity"], "High")
        self.assertEqual(view_att["tone"], "error")
        self.assertEqual(view_att["line"], 12)
        self.assertEqual(view_att["detected_by"], "Detected by ExecGuard")
        self.assertEqual(view_att["kind_label"], "Attack on the tool")
        self.assertEqual(view_att["action_label"], "BLOCKED")
        self.assertEqual(view_att["what"], "system() call detected")
        self.assertIn("execution", view_att["why"].lower())
        self.assertEqual(view_att["how"], "Avoid system execution")

        # Vulnerability finding
        vuln_finding = {
            "id": "v1",
            "origin": "vulnerability",
            "category": "unsafe_string_function",
            "severity": "Medium",
            "agents": ["VulnGuard"],
            "line": 4,
            "description": "strcpy usage detected",
            "recommendation": "Use std::string",
            "action": "warn",
            "blocks_on": [],
            "evidence": "strcpy(dst, src);",
        }
        view_vuln = finding_view(vuln_finding, current_purposes=["run"])
        self.assertEqual(view_vuln["title"], "Unsafe string function")
        self.assertEqual(view_vuln["severity"], "Medium")
        self.assertEqual(view_vuln["tone"], "warn")
        self.assertEqual(view_vuln["detected_by"], "Detected by VulnGuard")
        self.assertEqual(view_vuln["kind_label"], "Weakness in your code")
        self.assertEqual(view_vuln["action_label"], "WARNING")

        # Low severity finding -> INFO action label
        low_finding = {
            "origin": "vulnerability",
            "category": "potential_memory_leak",
            "severity": "Low",
            "action": "warn",
            "blocks_on": [],
        }
        view_low = finding_view(low_finding)
        self.assertEqual(view_low["action_label"], "INFO")
        self.assertEqual(view_low["tone"], "muted")

    def test_sort_findings_order(self):
        findings = [
            {"severity": "Low", "line": 2},
            {"severity": "Critical", "line": 50},
            {"severity": "High", "line": 10},
            {"severity": "Critical", "line": 5},
            {"severity": "Medium", "line": 1},
        ]
        sorted_f = sort_findings(findings)
        # Critical lines 5 then 50, then High line 10, Medium line 1, Low line 2
        self.assertEqual(
            [(f["severity"], f["line"]) for f in sorted_f],
            [
                ("Critical", 5),
                ("Critical", 50),
                ("High", 10),
                ("Medium", 1),
                ("Low", 2),
            ],
        )

    def test_heal_security_view_synthetic_and_none(self):
        # When security is None or empty
        self.assertIsNone(heal_security_view(None))
        self.assertIsNone(heal_security_view({}))

        # With synthetic security dict
        synthetic_sec = {
            "risk_before": 27,
            "risk_after": 0,
            "label_before": "Moderate",
            "label_after": "Clean",
            "outcomes": [
                {
                    "finding_id": "f1",
                    "category": "buffer_overflow",
                    "severity": "High",
                    "line": 8,
                    "agents": ["VulnGuard"],
                    "status": "fixed",
                },
                {
                    "finding_id": "f2",
                    "category": "process_execution",
                    "severity": "High",
                    "line": 20,
                    "agents": ["ExecGuard"],
                    "status": "suggested",
                },
                {
                    "finding_id": "f3",
                    "category": "destructive_file_op",
                    "severity": "Medium",
                    "line": 30,
                    "agents": ["ExecGuard"],
                    "status": "skipped_behavior",
                },
                {
                    "finding_id": "f4",
                    "category": "hardcoded_secret",
                    "severity": "Medium",
                    "line": 40,
                    "agents": ["SecretsGuard"],
                    "status": "rejected",
                },
            ],
            "applied": [
                {
                    "finding_category": "buffer_overflow",
                    "line": 8,
                    "safety_class": "auto",
                    "description": "bounds check",
                    "before": "char b[8];",
                    "after": "std::string b;",
                }
            ],
            "suggestions": [
                {
                    "finding_category": "process_execution",
                    "line": 20,
                    "description": "Remove system calls",
                }
            ],
            "findings_after": [
                {
                    "category": "hardcoded_secret",
                    "severity": "Medium",
                    "line": 40,
                    "agents": ["SecretsGuard"],
                }
            ],
        }
        view = heal_security_view(synthetic_sec)
        self.assertIsNotNone(view)
        self.assertEqual(view["headline"], "Security: Moderate (27) -> Clean (0)")
        self.assertEqual(view["tone"], "ok")
        self.assertEqual(view["counts"]["fixed"], 1)
        self.assertEqual(view["counts"]["suggested"], 1)
        self.assertEqual(view["counts"]["skipped"], 1)
        self.assertEqual(view["counts"]["rejected"], 1)
        self.assertEqual(view["counts"]["remaining"], 1)
        self.assertEqual(len(view["applied"]), 1)
        self.assertEqual(view["applied"][0]["detected_by"], "Detected by VulnGuard")
        self.assertEqual(len(view["suggestions"]), 1)
        self.assertEqual(view["suggestions"][0]["detected_by"], "Detected by ExecGuard")
        self.assertEqual(len(view["remaining"]), 1)

    def test_blocked_banner_view(self):
        findings = [
            {
                "id": "b1",
                "category": "process_execution",
                "severity": "High",
                "agents": ["ExecGuard"],
                "line": 7,
                "action": "block",
            }
        ]
        res_run = blocked_banner_view(findings, purpose="run")
        self.assertEqual(res_run["title"], "Run blocked by the security layer")
        self.assertEqual(res_run["purpose"], "run")
        self.assertEqual(len(res_run["findings"]), 1)
        self.assertEqual(res_run["findings"][0]["action_label"], "BLOCKED")

        res_compile = blocked_banner_view(findings, purpose="compile")
        self.assertEqual(res_compile["title"], "Compile blocked by the security layer")


class TestCategoryCoverage(unittest.TestCase):
    """2. Category coverage tests across manifest and guards."""

    def test_manifest_category_coverage(self):
        manifest_path = _PROJECT_ROOT / "security_bench" / "manifest.json"
        self.assertTrue(manifest_path.exists())
        with open(manifest_path, "r", encoding="utf-8") as f:
            cases = json.load(f)

        missing_titles = []
        missing_why = []
        for c in cases:
            cat = c.get("expected_category")
            if cat:
                if cat not in CATEGORY_TITLES:
                    missing_titles.append(cat)
                if cat not in CATEGORY_WHY:
                    missing_why.append(cat)

        self.assertEqual(missing_titles, [], f"Missing CATEGORY_TITLES for manifest categories: {missing_titles}")
        self.assertEqual(missing_why, [], f"Missing CATEGORY_WHY for manifest categories: {missing_why}")

    def test_guard_agents_category_coverage(self):
        guard_files = glob.glob(str(_SRC_DIR / "guard" / "*_guard.py"))
        agent_cats = set()
        for gf in guard_files:
            with open(gf, "r", encoding="utf-8") as f:
                content = f.read()
            for m in re.finditer(r'category\s*=\s*[\'"]([^\'"]+)[\'"]', content):
                agent_cats.add(m.group(1))

        missing_titles = [cat for cat in agent_cats if cat not in CATEGORY_TITLES]
        missing_why = [cat for cat in agent_cats if cat not in CATEGORY_WHY]
        self.assertEqual(missing_titles, [], f"Missing CATEGORY_TITLES for agent categories: {missing_titles}")
        self.assertEqual(missing_why, [], f"Missing CATEGORY_WHY for agent categories: {missing_why}")

    def test_unknown_category_fallback_never_raises(self):
        title = get_category_title("some_exotic_new_attack_pattern")
        self.assertEqual(title, "Some Exotic New Attack Pattern")

        why = get_category_why("some_exotic_new_attack_pattern")
        self.assertIsInstance(why, str)
        self.assertTrue(len(why) > 10)

        # None/empty
        self.assertIsInstance(get_category_title(""), str)
        self.assertIsInstance(get_category_why(""), str)


class TestJsonFeedAndCli(unittest.TestCase):
    """3. JSON feed in main.py and web_server.py."""

    def test_main_json_feed(self):
        code = '#include <cstring>\nint main() { char b[8]; strcpy(b, "abc"); return 0; }\n'
        with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as tf:
            tf.write(code)
            tmp_path = tf.name

        try:
            main_script = _SRC_DIR / "main.py"
            proc = subprocess.run(
                [sys.executable, str(main_script), tmp_path, "-j"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            # Must output valid JSON
            out_str = proc.stdout.strip()
            first_brace = out_str.find("{")
            last_brace = out_str.rfind("}")
            self.assertNotEqual(first_brace, -1)
            self.assertNotEqual(last_brace, -1)
            data = json.loads(out_str[first_brace:last_brace + 1])

            # Old keys preserved
            for k in ("status", "file", "error_count", "warning_count", "errors", "security_findings", "security_report"):
                self.assertIn(k, data)

            # New guard block present
            self.assertIn("guard", data)
            guard = data["guard"]
            self.assertIn("risk_label", guard)
            self.assertIn("risk_score", guard)
            self.assertIn("blocked_purposes", guard)
            self.assertIsInstance(guard["blocked_purposes"], list)
            self.assertIn("findings", guard)
            self.assertIn("agents_run", guard)
            self.assertIn("total_ms", guard)

            # VulnGuard found the unsafe string function
            vg_findings = [f for f in guard["findings"] if "VulnGuard" in f.get("agents", [])]
            self.assertTrue(len(vg_findings) >= 1)

            # Check that diagnostics derived from static findings carry origin == "security"
            sec_diagnostics = [e for e in data["errors"] if e.get("origin") == "security"]
            self.assertTrue(len(sec_diagnostics) >= 1)

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_web_server_handle_compile_guard_block(self):
        import web_server
        server = ThreadingHTTPServer(("127.0.0.1", 0), web_server.CompilerWebHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        time.sleep(0.05)

        try:
            conn = HTTPConnection("127.0.0.1", port, timeout=10)
            req_body = json.dumps({"code": "int main() { return 0; }"}).encode("utf-8")
            conn.request(
                "POST",
                "/api/compile",
                body=req_body,
                headers={
                    "Host": f"127.0.0.1:{port}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(req_body)),
                    "X-Guard-Token": web_server.SESSION_TOKEN,
                },
            )
            res = conn.getresponse()
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertIn("guard", data)
            self.assertEqual(data["guard"]["risk_label"], "Clean")
            self.assertIsInstance(data["guard"]["blocked_purposes"], list)
            conn.close()
        finally:
            server.shutdown()
            server.server_close()


class TestPlainTextRendering(unittest.TestCase):
    """4. Plain text protection against HTML injection."""

    def test_finding_with_html_tags(self):
        f = {
            "origin": "attack",
            "category": "display_injection",
            "severity": "High",
            "agents": ["OutputGuard"],
            "description": "Crafted error message: <b>x</b> and <img src=x onerror=alert(1)>",
            "evidence": "#error <b>x</b> <script>alert(1)</script>",
            "recommendation": "Do not interpolate raw HTML into <b>labels</b>",
        }
        fv = finding_view(f)
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
        from ui_components import SecurityFindingCard, plain_label

        app = QApplication.instance() or QApplication(sys.argv or [""])
        card = SecurityFindingCard(fv)

        # Inspect all QLabels in the card: must use PlainText format
        labels = card.findChildren(plain_label().__class__)
        for lbl in labels:
            self.assertEqual(
                lbl.textFormat(),
                Qt.TextFormat.PlainText,
                f"Label '{lbl.text()}' should have PlainText textFormat",
            )


class TestGuiOffscreen(unittest.TestCase):
    """5 & 6. GUI offscreen tests."""

    @classmethod
    def setUpClass(cls):
        from PyQt6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication(sys.argv or [""])

    def test_gui_render_json_with_guard_block_and_theme_switch(self):
        import gui
        import theme
        from ui_components import SecuritySummaryCard, SecurityFindingCard, IssueCard

        win = gui.AppGUI()
        synthetic_data = {
            "status": "error",
            "file": "test.cpp",
            "error_count": 1,
            "warning_count": 0,
            "errors": [
                {
                    "file": "test.cpp",
                    "line": 5,
                    "column": 1,
                    "type": "error",
                    "error_type": "error",
                    "message": "expected ';' before '}' token",
                },
                # Duplicate static security finding promoted to diagnostic
                {
                    "file": "test.cpp",
                    "line": 10,
                    "column": 1,
                    "type": "error",
                    "error_type": "error",
                    "message": "Dangerous process execution",
                    "origin": "security",
                },
            ],
            "guard": {
                "risk_score": 15,
                "risk_label": "High Risk",
                "blocked_purposes": ["run"],
                "findings": [
                    {
                        "id": "f1",
                        "agents": ["ExecGuard"],
                        "origin": "attack",
                        "category": "process_execution",
                        "severity": "High",
                        "title": "Process execution",
                        "description": "system call detected",
                        "recommendation": "Avoid system calls",
                        "line": 10,
                        "column": 1,
                        "evidence": "system(\"ls\")",
                        "action": "block",
                        "blocks_on": ["run"],
                    },
                    {
                        "id": "f2",
                        "agents": ["VulnGuard"],
                        "origin": "vulnerability",
                        "category": "unsafe_string_function",
                        "severity": "Medium",
                        "title": "Unsafe string function",
                        "description": "strcpy usage detected",
                        "recommendation": "Use strncpy or std::string",
                        "line": 15,
                        "column": 1,
                        "evidence": "strcpy(a, b)",
                        "action": "warn",
                        "blocks_on": [],
                    },
                ],
                "agents_run": ["ExecGuard", "VulnGuard"],
                "total_ms": 1.25,
            },
        }

        # Render JSON
        win.render_json(synthetic_data, "")

        # Assert summary card exists
        summary_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), SecuritySummaryCard)
        ]
        self.assertEqual(len(summary_cards), 1)

        # Assert exactly two finding cards exist
        finding_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), SecurityFindingCard)
        ]
        self.assertEqual(len(finding_cards), 2)

        # Assert security-derived diagnostic is NOT duplicated as an IssueCard
        issue_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), IssueCard)
        ]
        self.assertEqual(len(issue_cards), 1)
        self.assertEqual(issue_cards[0].err.get("message"), "expected ';' before '}' token")

        # Footer counts equal compiler diagnostics (1 error, 0 warnings)
        self.assertEqual(win.errors_count, 1)
        self.assertEqual(win.warnings_count, 0)

        # Problems badge count: compiler errors (1) + security findings (2) = 3
        self.assertEqual(win.problems_count_badge.text(), "3")

        # Theme switching without exception
        theme.apply_theme(self.app, "light")
        theme.apply_theme(self.app, "dark")

    def test_gui_on_heal_summary_and_blocked_banner(self):
        import gui
        from ui_components import SecurityResultCard, BlockedBanner

        win = gui.AppGUI()
        synthetic_heal_summary = {
            "clean": True,
            "rounds": [{"round_no": 1, "method": "healed buffer_overflow", "seconds": 0.04}],
            "total_duration": 0.04,
            "message": "Compiles OK",
            "security": {
                "risk_before": 27,
                "risk_after": 0,
                "label_before": "Moderate",
                "label_after": "Clean",
                "outcomes": [
                    {
                        "finding_id": "f1",
                        "category": "buffer_overflow",
                        "severity": "High",
                        "line": 8,
                        "agents": ["VulnGuard"],
                        "status": "fixed",
                    }
                ],
                "applied": [
                    {
                        "finding_category": "buffer_overflow",
                        "line": 8,
                        "safety_class": "auto",
                        "description": "bounds check",
                        "before": "char b[8];",
                        "after": "std::string b;",
                    }
                ],
                "suggestions": [],
                "findings_after": [],
            },
        }

        # 1. Test _on_heal_summary with security result card
        win._on_heal_summary(synthetic_heal_summary)
        sec_result_cards = [
            win.error_cards_layout.itemAt(i).widget()
            for i in range(win.error_cards_layout.count())
            if isinstance(win.error_cards_layout.itemAt(i).widget(), SecurityResultCard)
        ]
        self.assertEqual(len(sec_result_cards), 1)
        self.assertEqual(sec_result_cards[0].view["headline"], "Security: Moderate (27) -> Clean (0)")
        self.assertIn("Clean (0)", win.security_chip.text())

        # 2. Test blocked banner
        blocking_findings = [
            {
                "id": "b1",
                "category": "process_execution",
                "title": "Process execution",
                "severity": "High",
                "agents": ["ExecGuard"],
                "line": 9,
                "action": "block",
            }
        ]
        win._show_blocked_banner(blocking_findings, purpose="run")
        self.assertIsNotNone(win.blocked_banner)
        self.assertIsInstance(win.blocked_banner, BlockedBanner)
        self.assertIsNotNone(win.blocked_banner.fix_btn)
        self.assertEqual(win.blocked_banner.fix_btn.text(), "Fix with Auto-Heal")


if __name__ == "__main__":
    unittest.main()
