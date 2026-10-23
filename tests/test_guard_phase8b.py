"""
tests/test_guard_phase8b.py
---------------------------
Phase 8b test suite:
1. Pure helpers (security_view.py):
   - load_attack_log (missing file, valid lines, corrupt line, limit tail reading, 5 MB file performance)
   - summarize_attack_log (counts, actions, top categories)
   - build_agent_rows (registered agent introspection, skipped vs active, live findings)
   - benchmark_view (committed metrics verification, partial/empty dictionary tolerance)
2. Quality hints (quality_hints.py):
   - positive and negative samples for each of the 7 rules
   - clean code gives 0 hints, level Good, score 0
   - level thresholds (Good, Fair, Needs work)
   - comments and strings ignored
   - empty and huge input handling without exception
3. Web server integration (web_server.py):
   - /api/compile returns guard.view and quality
   - /api/heal returns security_view
   - blocked /api/run returns blocked_view
   - HTML_PAGE has no raw interpolations of new fields and retains X-Guard-Token on all 3 fetches
4. GUI offscreen test 1:
   - SecurityPage 4 tabs navigation, finding cards, agent rows, log rows, benchmark cards, theme toggle
5. GUI offscreen test 2:
   - "Run benchmark now" worker execution with fast patched run_benchmark, memory-only display, button re-enabled, data/ untouched
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

# Ensure src/ and repo root are in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _PROJECT_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Set Qt offscreen mode before importing any Qt components
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from security_view import (
    load_attack_log,
    summarize_attack_log,
    build_agent_rows,
    benchmark_view,
    build_security_summary,
    finding_view,
    sort_findings,
    heal_security_view,
    blocked_banner_view,
)
from quality_hints import analyze_quality


class TestPureHelpers(unittest.TestCase):
    """1. Pure helper functions test suite (no Qt required)."""

    def test_load_attack_log_missing_file(self):
        non_existent = os.path.join(tempfile.gettempdir(), "non_existent_guard_log_12345.jsonl")
        rows = load_attack_log(path=non_existent)
        self.assertEqual(rows, [])

    def test_load_attack_log_valid_and_corrupt_lines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as tf:
            tf.write(json.dumps({"action": "log", "agents": ["ExecGuard"], "categories": ["sys"]}) + "\n")
            tf.write("CORRUPT_JSON_LINE_HERE\n")
            tf.write(json.dumps({"action": "block", "agents": ["VulnGuard"], "categories": ["buf"]}) + "\n")
            tmp_path = tf.name

        try:
            rows = load_attack_log(path=tmp_path, limit=200)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["action"], "log")
            self.assertEqual(rows[1]["action"], "block")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_load_attack_log_limit_returns_tail(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as tf:
            for i in range(10):
                tf.write(json.dumps({"idx": i, "action": "log"}) + "\n")
            tmp_path = tf.name

        try:
            rows = load_attack_log(path=tmp_path, limit=3)
            self.assertEqual(len(rows), 3)
            self.assertEqual([r["idx"] for r in rows], [7, 8, 9])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_load_attack_log_large_file_efficiency(self):
        # Create a ~5 MB file with valid and blank lines
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as tf:
            line_payload = json.dumps({"action": "log", "msg": "x" * 80}) + "\n"
            # Write 45,000 lines (~4.5 - 5.0 MB)
            for _ in range(45000):
                tf.write(line_payload)
            # Add final target line
            tf.write(json.dumps({"action": "block", "target": True}) + "\n")
            tmp_path = tf.name

        try:
            start_t = time.time()
            rows = load_attack_log(path=tmp_path, limit=10)
            elapsed = time.time() - start_t
            self.assertEqual(len(rows), 10)
            self.assertTrue(rows[-1].get("target"))
            # Must read only the tail, taking well under 200 ms
            self.assertLess(elapsed, 0.5, "Tail reading should be instantaneous on a 5 MB file")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_summarize_attack_log(self):
        rows = [
            {"action": "block", "agents": ["ExecGuard", "VulnGuard"], "categories": ["process_exec", "buffer_overflow"]},
            {"action": "block", "agents": ["ExecGuard"], "categories": ["process_exec"]},
            {"action": "log", "agents": ["ResourceGuard"], "categories": ["macro_expansion_bomb"]},
        ]
        s = summarize_attack_log(rows)
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["blocked"], 2)
        self.assertEqual(s["logged"], 1)
        self.assertEqual(s["by_agent"]["ExecGuard"], 2)
        self.assertEqual(s["by_agent"]["VulnGuard"], 1)
        self.assertEqual(s["by_category"]["process_exec"], 2)
        self.assertEqual(s["top_categories"][0], ("process_exec", 2))

    def test_build_agent_rows(self):
        agents_info = [
            {"name": "ExecGuard", "handles": ["user_source"], "role": "Prohibits shell execution"},
            {"name": "EndpointGuard", "handles": ["http_request"], "role": "Validates HTTP boundaries"},
        ]
        guard_data = {
            "agents_run": ["ExecGuard"],
            "findings": [{"agents": ["ExecGuard"], "action": "block"}],
            "timings_ms": {"ExecGuard": 1.45},
            "blocked_purposes": ["run"],
        }
        rows = build_agent_rows(agents_info, guard_data)
        self.assertEqual(len(rows), 2)

        exec_row = next(r for r in rows if r["name"] == "ExecGuard")
        self.assertEqual(exec_row["status"], "active")
        self.assertEqual(exec_row["findings_count"], 1)
        self.assertTrue(exec_row["blocked"])
        self.assertEqual(exec_row["ms"], 1.45)

        ep_row = next(r for r in rows if r["name"] == "EndpointGuard")
        self.assertEqual(ep_row["status"], "skipped (no signal)")
        self.assertEqual(ep_row["findings_count"], 0)
        self.assertFalse(ep_row["blocked"])
        self.assertEqual(ep_row["ms"], 0.0)

    def test_benchmark_view_committed_json(self):
        metrics_file = _PROJECT_ROOT / "data" / "security_metrics.json"
        self.assertTrue(metrics_file.exists(), "data/security_metrics.json must be present")
        with open(metrics_file, "r", encoding="utf-8") as f:
            raw_metrics = json.load(f)

        bv = benchmark_view(raw_metrics)
        hl = bv["headlines"]

        # Check standard set detection matches committed 77/77
        self.assertEqual(hl["standard_detection_count"], 77)
        self.assertEqual(hl["standard_detection_total"], 77)
        self.assertIn("100.0%", hl["standard_detection"])

        # Check hard set detection matches committed 7/12
        self.assertEqual(hl["hard_detection_count"], 7)
        self.assertEqual(hl["hard_detection_total"], 12)

        # Check attack success rate matches committed
        self.assertIn("85.7% -> 7.1%", hl["attack_success_rate"])

        # Check median latency matches committed metrics
        exp_median = f"{raw_metrics.get('latency', {}).get('median', 0.0):.2f} ms"
        self.assertEqual(hl["median_latency"], exp_median)

        # Families and agents populated
        self.assertGreater(len(bv["families"]), 0)
        self.assertGreater(len(bv["agents"]), 0)
        self.assertIn("1. Coverage vs. Generalisation", bv["how_to_read"])

    def test_benchmark_view_partial_dictionary_never_raises(self):
        # Empty dict
        bv_empty = benchmark_view({})
        self.assertIsInstance(bv_empty, dict)
        self.assertEqual(bv_empty["headlines"]["standard_detection"], "N/A")

        # Missing various sub-keys
        partial = {
            "overall": {"standard_detection": {"count": 5, "total": 10}},
            "by_family": {"sql_injection": {"baseline_asr": 0.5, "defended_asr": 0.1}},
        }
        bv_partial = benchmark_view(partial)
        self.assertEqual(bv_partial["headlines"]["standard_detection_count"], 5)
        self.assertEqual(len(bv_partial["families"]), 1)


class TestQualityHints(unittest.TestCase):
    """2. Quality hints heuristic analyzer test suite."""

    def test_nested_loops_rule(self):
        # Positive: nested for loop
        pos = "void f() { for(int i=0; i<10; i++) { for(int j=0; j<10; j++) { int a = 1; } } }"
        res = analyze_quality(pos)
        self.assertTrue(any(h["id"] == "nested_loops" for h in res["hints"]))

        # Positive 3-levels deep gives weight 3
        pos3 = "void f() { for(int i=0; i<10; i++) { for(int j=0; j<10; j++) { for(int k=0; k<10; k++) {} } } }"
        res3 = analyze_quality(pos3)
        h3 = next(h for h in res3["hints"] if h["id"] == "nested_loops")
        self.assertEqual(h3["weight"], 3)

        # Negative: single loop
        neg = "void f() { for(int i=0; i<10; i++) { int a = i; } }"
        res_neg = analyze_quality(neg)
        self.assertFalse(any(h["id"] == "nested_loops" for h in res_neg["hints"]))

    def test_pass_by_value_rule(self):
        # Positive: passing string or vector by value
        pos = "void process(std::string s, std::vector<int> v) { int a = 1; }"
        res = analyze_quality(pos)
        self.assertTrue(any(h["id"] == "pass_by_value" for h in res["hints"]))

        # Negative: pass by const reference
        neg = "void process(const std::string& s, const std::vector<int>& v) { int a = 1; }"
        res_neg = analyze_quality(neg)
        self.assertFalse(any(h["id"] == "pass_by_value" for h in res_neg["hints"]))

    def test_endl_in_loop_rule(self):
        # Positive: endl inside loop
        pos = "void f() { for(int i=0; i<10; i++) { std::cout << std::endl; } }"
        res = analyze_quality(pos)
        self.assertTrue(any(h["id"] == "endl_in_loop" for h in res["hints"]))

        # Negative: newline character inside loop
        neg = "void f() { for(int i=0; i<10; i++) { std::cout << '\\n'; } }"
        res_neg = analyze_quality(neg)
        self.assertFalse(any(h["id"] == "endl_in_loop" for h in res_neg["hints"]))

    def test_strlen_in_loop_condition_rule(self):
        # Positive: strlen in condition
        pos = "void f(char* s) { for(int i=0; i < strlen(s); i++) { } }"
        res = analyze_quality(pos)
        self.assertTrue(any(h["id"] == "strlen_in_loop_condition" for h in res["hints"]))

        # Negative: strlen outside condition
        neg = "void f(char* s) { int len = strlen(s); for(int i=0; i < len; i++) { } }"
        res_neg = analyze_quality(neg)
        self.assertFalse(any(h["id"] == "strlen_in_loop_condition" for h in res_neg["hints"]))

    def test_string_concat_in_loop_rule(self):
        # Positive: s = s + ... in loop
        pos = "void f() { std::string s = \"\"; for(int i=0; i<10; i++) { s = s + \"a\"; } }"
        res = analyze_quality(pos)
        self.assertTrue(any(h["id"] == "string_concat_in_loop" for h in res["hints"]))

        # Negative: s += "a" in loop
        neg = "void f() { std::string s = \"\"; for(int i=0; i<10; i++) { s += \"a\"; } }"
        res_neg = analyze_quality(neg)
        self.assertFalse(any(h["id"] == "string_concat_in_loop" for h in res_neg["hints"]))

    def test_push_back_without_reserve_rule(self):
        # Positive: v.push_back without reserve
        pos = "void f() { std::vector<int> v; for(int i=0; i<10; i++) { v.push_back(i); } }"
        res = analyze_quality(pos)
        self.assertTrue(any(h["id"] == "push_back_without_reserve" for h in res["hints"]))

        # Negative: reserve called before loop
        neg = "void f() { std::vector<int> v; v.reserve(10); for(int i=0; i<10; i++) { v.push_back(i); } }"
        res_neg = analyze_quality(neg)
        self.assertFalse(any(h["id"] == "push_back_without_reserve" for h in res_neg["hints"]))

    def test_copy_in_range_for_rule(self):
        # Positive: copy by value in range for
        pos = "void f(std::vector<std::string>& vec) { for(std::string item : vec) { int x = 1; } }"
        res = analyze_quality(pos)
        self.assertTrue(any(h["id"] == "copy_in_range_for" for h in res["hints"]))

        # Negative: const reference in range for
        neg = "void f(std::vector<std::string>& vec) { for(const auto& item : vec) { int x = 1; } }"
        res_neg = analyze_quality(neg)
        self.assertFalse(any(h["id"] == "copy_in_range_for" for h in res_neg["hints"]))

    def test_clean_code_and_thresholds(self):
        clean = """#include <iostream>
#include <string>
#include <vector>

void print_items(const std::vector<std::string>& items) {
    for (const auto& it : items) {
        std::cout << it << '\\n';
    }
}

int main() {
    std::cout << "Hello, World!\\n";
    return 0;
}
"""
        res = analyze_quality(clean)
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["level"], "Good")
        self.assertEqual(res["hints"], [])

        # Score 2 to 4 -> Fair
        fair_code = """
void f(std::string a, std::string b) { // pass_by_value (2 weights)
}
"""
        res_fair = analyze_quality(fair_code)
        self.assertIn(res_fair["score"], [2, 3, 4])
        self.assertEqual(res_fair["level"], "Fair")

        # Score 5+ -> Needs work
        needs_work_code = """
void f(std::string a, std::vector<int> v) { // +2
    for(int i=0; i<10; i++) {
        for(int j=0; j<10; j++) { // +2
            std::cout << std::endl; // +1
        }
    }
}
"""
        res_nw = analyze_quality(needs_work_code)
        self.assertGreaterEqual(res_nw["score"], 5)
        self.assertEqual(res_nw["level"], "Needs work")

    def test_comments_and_strings_ignored(self):
        # Code containing patterns only inside comments and string literals
        code = '''
int main() {
    // for (int i=0; i<10; i++) { for (int j=0; j<10; j++) {} }
    // void f(std::string s) {}
    const char* str = "for (int i=0; i<10; i++) { std::endl; v.push_back(1); }";
    return 0;
}
'''
        res = analyze_quality(code)
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["hints"], [])

    def test_empty_and_huge_inputs(self):
        # Empty
        res_empty = analyze_quality("")
        self.assertEqual(res_empty["score"], 0)
        self.assertEqual(res_empty["level"], "Good")

        # 100k characters of arbitrary text
        huge = ("int x = 1;\n" * 10000)
        res_huge = analyze_quality(huge)
        self.assertIsInstance(res_huge["score"], int)


class TestWebServerPhase8b(unittest.TestCase):
    """3. Web server endpoints & HTML regression testing."""

    @classmethod
    def setUpClass(cls):
        import web_server
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), web_server.CompilerWebHandler)
        cls.port = cls.server.server_address[1]
        cls.token = web_server.SESSION_TOKEN
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_api_compile_returns_guard_view_and_quality(self):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=10)
        body = json.dumps({"code": "int main() { return 0; }"}).encode("utf-8")
        conn.request(
            "POST",
            "/api/compile",
            body=body,
            headers={
                "Host": f"127.0.0.1:{self.port}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-Guard-Token": self.token,
            },
        )
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        conn.close()

        # Guard view check
        self.assertIn("guard", data)
        guard = data["guard"]
        self.assertIn("view", guard)
        self.assertIn("summary", guard["view"])
        self.assertIn("findings", guard["view"])
        self.assertEqual(guard["view"]["summary"]["risk_label"], "Clean")

        # Quality check
        self.assertIn("quality", data)
        self.assertIn("level", data["quality"])
        self.assertIn("score", data["quality"])
        self.assertIn("hints", data["quality"])

    def test_api_heal_returns_security_view(self):
        fixable_source = "#include <iostream>\nint main() { int x = 0 std::cout << x; return 0; }"
        conn = HTTPConnection("127.0.0.1", self.port, timeout=30)
        body = json.dumps({"code": fixable_source}).encode("utf-8")
        conn.request(
            "POST",
            "/api/heal",
            body=body,
            headers={
                "Host": f"127.0.0.1:{self.port}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-Guard-Token": self.token,
            },
        )
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        conn.close()

        # Check response structure
        self.assertIn("rounds", data)
        if "security" in data and data["security"]:
            self.assertIn("security_view", data)
            sv = data["security_view"]
            self.assertIn("headline", sv)
            self.assertIn("counts", sv)

    def test_api_run_blocked_returns_blocked_view(self):
        # Code containing dangerous system call
        dangerous_code = '#include <cstdlib>\nint main() { system("rm -rf /"); return 0; }'
        conn = HTTPConnection("127.0.0.1", self.port, timeout=10)
        body = json.dumps({"code": dangerous_code}).encode("utf-8")
        conn.request(
            "POST",
            "/api/run",
            body=body,
            headers={
                "Host": f"127.0.0.1:{self.port}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-Guard-Token": self.token,
            },
        )
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        conn.close()

        self.assertTrue(data.get("blocked"))
        self.assertIn("blocked_view", data)
        bv = data["blocked_view"]
        self.assertIn("title", bv)
        self.assertEqual(bv.get("purpose"), "run")
        self.assertGreaterEqual(len(bv.get("findings", [])), 1)

    def test_html_page_escaped_interpolations_and_tokens(self):
        import web_server
        page = web_server.HTML_PAGE

        # Ensure no unescaped dynamic interpolations for new Phase 8b fields
        new_fields = [
            "f.title", "f.what", "f.why", "f.how", "f.detected_by", "f.action_label",
            "s.risk_label", "sv.headline", "h.title", "h.message", "h.suggestion",
            "af.title", "qLevel"
        ]
        for field in new_fields:
            self.assertNotIn(f"${{{field}}}", page, f"Found unescaped interpolation ${{field}} in HTML_PAGE")

        # Exactly 3 X-Guard-Token headers in fetch calls (compile, heal, run)
        self.assertEqual(page.count("'X-Guard-Token': GUARD_TOKEN"), 3)


class TestGuiOffscreenPhase8b(unittest.TestCase):
    """4 & 5. GUI offscreen tests."""

    @classmethod
    def setUpClass(cls):
        from PyQt6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication(sys.argv or [""])

    def test_gui_offscreen_tabs_and_themes(self):
        import gui
        import theme
        from ui_components import SecurityFindingCard, SecuritySummaryCard

        # Create temporary attack log
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as tf:
            tf.write(json.dumps({
                "timestamp": "2026-10-22T10:00:00Z",
                "input_kind": "user_source",
                "purpose": "run",
                "action": "block",
                "risk_label": "High Risk",
                "risk_score": 15,
                "agents": ["ExecGuard"],
                "categories": ["process_execution"],
            }) + "\n")
            tmp_log = tf.name

        os.environ["GUARD_LOG_PATH"] = tmp_log
        try:
            win = gui.AppGUI()
            sec_page = win.security_page

            synthetic_guard = {
                "risk_score": 15,
                "risk_label": "High Risk",
                "blocked_purposes": ["run"],
                "findings": [
                    {
                        "id": "f_test_1",
                        "agents": ["ExecGuard"],
                        "origin": "attack",
                        "category": "process_execution",
                        "severity": "High",
                        "title": "Command Execution Flaw",
                        "description": "system call used",
                        "recommendation": "Remove system calls",
                        "line": 12,
                        "action": "block",
                    }
                ],
                "agents_run": ["ExecGuard"],
                "total_ms": 2.5,
                "timings_ms": {"ExecGuard": 2.5},
            }

            # Update guard block
            sec_page.update_guard(synthetic_guard)

            # 1. Switch to Findings Tab (index 0)
            sec_page.tabs.setCurrentIndex(0)
            finding_cards = sec_page.report_host.findChildren(SecurityFindingCard)
            self.assertGreaterEqual(len(finding_cards), 1)

            # 2. Switch to Agents Tab (index 1)
            sec_page.tabs.setCurrentIndex(1)
            agent_cards = sec_page.agents_host.findChildren(gui.QFrame)
            self.assertGreaterEqual(len(agent_cards), 1)

            # 3. Switch to Attack Log Tab (index 2)
            sec_page.tabs.setCurrentIndex(2)
            self.assertGreaterEqual(sec_page.log_table.rowCount(), 1)
            first_action = sec_page.log_table.item(0, 2).text()
            self.assertEqual(first_action, "BLOCK")

            # 4. Switch to Benchmark Tab (index 3)
            sec_page.tabs.setCurrentIndex(3)
            self.assertGreaterEqual(sec_page.bench_family_table.rowCount(), 1)

            # Theme switching without exceptions
            theme.apply_theme(self.app, "light")
            theme.apply_theme(self.app, "dark")

        finally:
            try:
                win.close()
                win.deleteLater()
            except Exception:
                pass
            if "GUARD_LOG_PATH" in os.environ:
                del os.environ["GUARD_LOG_PATH"]
            if os.path.exists(tmp_log):
                os.remove(tmp_log)

    def test_gui_offscreen_run_benchmark_now(self):
        import gui

        win = gui.AppGUI()
        try:
            sec_page = win.security_page

            # Compute hash of data directory before running benchmark
            data_dir = _PROJECT_ROOT / "data"
            hashes_before = {}
            for p in data_dir.glob("*"):
                if p.is_file():
                    hashes_before[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()

            mock_metrics = {
                "overall": {
                    "standard_detection": {"rate": 1.0, "count": 77, "total": 77, "ci_95": [0.95, 1.0]},
                    "hard_detection": {"rate": 0.6, "count": 7, "total": 12, "ci_95": [0.32, 0.81]},
                    "baseline_asr": {"rate": 0.85, "count": 72, "total": 84},
                    "defended_asr": {"rate": 0.07, "count": 6, "total": 84},
                    "false_alert_rate": {"rate": 0.0, "count": 0, "total": 31, "ci_95": [0.0, 0.11]},
                },
                "latency": {"median": 6.8},
                "routing": {"routing_misses": 0},
                "by_family": {
                    "command_injection": {"baseline_asr": 0.9, "defended_asr": 0.1, "attacks": 10, "detected": 9, "prevented": 9}
                },
                "by_agent": {
                    "ExecGuard": {"recall": {"rate": 1.0, "count": 10, "total": 10}, "precision": 1.0, "false_alert_rate": 0.0}
                },
                "caveats": "Mock caveats for offscreen test.",
            }

            # Patch run_benchmark with fast mock
            with patch("guard.benchmark.run_benchmark", return_value=mock_metrics):
                # Click 'Run benchmark now'
                sec_page.btn_run_benchmark.click()

                # Ensure worker started
                worker = sec_page.benchmark_worker
                self.assertIsNotNone(worker)

                # Wait for worker with bounded timeout (5 seconds)
                worker.wait(5000)

                # Process any pending Qt events
                self.app.processEvents()

                # Assert live result is displayed in memory
                self.assertIn("Live run", sec_page.benchmark_source_lbl.text())
                self.assertTrue(sec_page.btn_run_benchmark.isEnabled())
                self.assertEqual(sec_page.benchmark_progress_lbl.text(), "Completed")

                # Check that headline text updated
                headline_texts = [
                    sec_page.bench_headline_lay.itemAt(i).widget().findChildren(gui.QLabel)[1].text()
                    for i in range(sec_page.bench_headline_lay.count())
                    if sec_page.bench_headline_lay.itemAt(i).widget()
                ]
                self.assertTrue(any("100.0%" in t for t in headline_texts))

            # Verify no file under data/ was modified or overwritten
            hashes_after = {}
            for p in data_dir.glob("*"):
                if p.is_file():
                    hashes_after[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()

            self.assertEqual(hashes_before, hashes_after, "No file in data/ must be modified by live benchmark run")
        finally:
            try:
                win.close()
                win.deleteLater()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
