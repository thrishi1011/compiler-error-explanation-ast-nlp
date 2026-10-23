"""
test_guard_phase3.py
--------------------
Phase 3 tests for the compiler error explainer agentic-AI security layer.
Tests:
- safe_text and html_text output sanitization
- OutputGuard detections, non-triggers, and purpose='display'
- build_compiler_html pure formatting
- EndpointGuard HTTP validation (headers and body stages)
- ConcurrencyLimiter and RateLimiter
- Live server integration (security headers, token requirement, limits)
- Web page HTML_PAGE interpolation and token audit
"""

from __future__ import annotations

import hmac
import json
import os
import shutil
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

from guard import (
    InputKind,
    Finding,
    Supervisor,
    get_supervisor,
)
from guard.base import GuardContext
from guard.output_safe import safe_text, html_text
from guard.limiter import ConcurrencyLimiter, RateLimiter, Busy
from guard.config import (
    ENDPOINT_MAX_BODY,
    ENDPOINT_MAX_CODE_CHARS,
    ENDPOINT_RATE,
    ENDPOINT_CONCURRENCY,
    SOCKET_TIMEOUT_SECONDS,
)
from guard.output_guard import OutputGuard
from guard.endpoint_guard import EndpointGuard
from ui_text import build_compiler_html
import web_server


class TestGuardPhase3(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.log_file = Path(cls.temp_dir.name) / "test_attack_log_p3.jsonl"
        os.environ["GUARD_LOG_PATH"] = str(cls.log_file)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    # ── 1. safe_text / html_text ──────────────────────────────────────────────

    def test_safe_text_and_html_text(self):
        # Total function safety: None, numbers, non-strings
        self.assertEqual(safe_text(None), "")
        self.assertEqual(safe_text(123), "123")
        self.assertEqual(html_text(None), "")
        self.assertEqual(html_text(456), "456")

        # Strip ANSI CSI and OSC escape sequences
        ansi_sample = "\x1b[31;1mRed Error\x1b[0m\x1b]0;Title\x07Text"
        self.assertEqual(safe_text(ansi_sample), "Red ErrorText")

        # Strip C0 controls except \n and \t
        c0_sample = "Line 1\x00\x01\x07\tLine\x0b2\r\nLine 3"
        cleaned_c0 = safe_text(c0_sample)
        self.assertIn("\n", cleaned_c0)
        self.assertIn("\t", cleaned_c0)
        self.assertNotIn("\x00", cleaned_c0)
        self.assertNotIn("\x01", cleaned_c0)
        self.assertNotIn("\r", cleaned_c0)

        # Strip Bidirectional controls and zero-width characters
        # U+202E (RLO), U+200B (ZWSP), U+FEFF (BOM)
        bidi_sample = "int main() {\u202E reverse \u200B zero \uFEFF bom }"
        cleaned_bidi = safe_text(bidi_sample)
        self.assertNotIn("\u202E", cleaned_bidi)
        self.assertNotIn("\u200B", cleaned_bidi)
        self.assertNotIn("\uFEFF", cleaned_bidi)
        self.assertEqual(cleaned_bidi, "int main() { reverse  zero  bom }")

        # Length capping
        long_str = "A" * 2500
        capped = safe_text(long_str, limit=100)
        self.assertEqual(len(capped), 103)
        self.assertTrue(capped.endswith("..."))

        # html_text escaping
        xss_sample = '<img src=x onerror=alert(1)> & "quotes" \'single\''
        safe_html = html_text(xss_sample)
        self.assertIn("&lt;img", safe_html)
        self.assertNotIn("<img", safe_html)
        self.assertIn("&amp;", safe_html)
        self.assertIn("&quot;", safe_html)
        self.assertIn("&#x27;", safe_html)

    # ── 2. OutputGuard ────────────────────────────────────────────────────────

    def test_output_guard_detections(self):
        agent = OutputGuard()

        # 1. Markup: <b>fake</b> (Medium)
        ctx = GuardContext(kind=InputKind.COMPILER_OUTPUT, payload="<b>fake</b>")
        findings = agent.analyze(ctx)
        self.assertTrue(any(f.category == "display_injection" and f.severity == "Medium" for f in findings))

        # 2. Markup: <span style="color:green">Compilation successful</span>
        ctx = GuardContext(kind=InputKind.COMPILER_OUTPUT, payload='<span style="color:green">Compilation successful</span>')
        findings = agent.analyze(ctx)
        self.assertTrue(any(f.category == "display_injection" for f in findings))
        self.assertTrue(any(f.category == "spoofed_status" for f in findings))

        # 3. Dangerous scheme: javascript:alert(1) (High)
        ctx = GuardContext(kind=InputKind.AI_RESPONSE, payload="Check out <a href='javascript:alert(1)'>link</a>")
        findings = agent.analyze(ctx)
        self.assertTrue(any(f.category == "display_injection" and f.severity == "High" for f in findings))

        # 4. ANSI escape sequence (Medium terminal_escape)
        ctx = GuardContext(kind=InputKind.COMPILER_OUTPUT, payload="\x1b[32mAll Good\x1b[0m")
        findings = agent.analyze(ctx)
        self.assertTrue(any(f.category == "terminal_escape" for f in findings))

        # 5. Spoofed status phrase: '0 errors'
        ctx = GuardContext(kind=InputKind.COMPILER_OUTPUT, payload="Finished with 0 errors and 0 warnings")
        findings = agent.analyze(ctx)
        self.assertTrue(any(f.category == "spoofed_status" for f in findings))

        # 6. Trojan source U+202E in USER_SOURCE inside comment
        code_comment = "// \u202E Check admin check\nint main() { return 0; }"
        ctx = GuardContext(kind=InputKind.USER_SOURCE, payload=code_comment)
        findings = agent.analyze(ctx)
        bidi_findings = [f for f in findings if f.category == "hidden_unicode"]
        self.assertEqual(len(bidi_findings), 1)
        self.assertEqual(bidi_findings[0].line, 1)
        self.assertIn("comment", bidi_findings[0].description.lower())

        # Check blocks_on and origin
        for f in findings:
            self.assertEqual(f.origin, "attack")
            self.assertEqual(f.blocks_on, set())

    def test_output_guard_non_triggers(self):
        agent = OutputGuard()

        # Ordinary compiler diagnostic
        normal_diag1 = "source.cpp:5:10: error: expected ';' before 'return'"
        ctx1 = GuardContext(kind=InputKind.COMPILER_OUTPUT, payload=normal_diag1)
        self.assertFalse(agent.quick_match(ctx1))
        self.assertEqual(agent.analyze(ctx1), [])

        normal_diag2 = "source.cpp:12:5: error: 'x' was not declared in this scope"
        ctx2 = GuardContext(kind=InputKind.COMPILER_OUTPUT, payload=normal_diag2)
        self.assertFalse(agent.quick_match(ctx2))
        self.assertEqual(agent.analyze(ctx2), [])

        # Normal non-ASCII text (e.g. accented letters in string literal "héllo")
        code_accent = 'const char* s = "héllo world";\nint main() { return 0; }'
        ctx3 = GuardContext(kind=InputKind.USER_SOURCE, payload=code_accent)
        findings = agent.analyze(ctx3)
        self.assertEqual(findings, [])

    # ── 3. build_compiler_html ────────────────────────────────────────────────

    def test_build_compiler_html_sanitization(self):
        malicious_errors = [
            {
                "file": '<img src=x onerror=alert(1)>.cpp',
                "type": 'error<b>fake</b>',
                "line": 4,
                "column": 2,
                "message": 'Found error <script>alert(1)</script> \x1b[31mRed\x1b[0m \u202E reversed',
                "context": {
                    "lines": [
                        'int a = 1; <a href="javascript:alert(1)">click</a>',
                        'int b = 2;\x00',
                    ],
                    "start_line": 3,
                },
            }
        ]
        html_out = build_compiler_html(malicious_errors)
        self.assertNotIn("<img", html_out)
        self.assertNotIn("<b>fake</b>", html_out)
        self.assertNotIn("<script>", html_out)
        self.assertNotIn("\x1b", html_out)
        self.assertNotIn("\u202E", html_out)
        self.assertNotIn('href="javascript:', html_out)
        self.assertIn("&lt;img", html_out)
        self.assertIn("&lt;script&gt;", html_out)

    # ── 4. EndpointGuard (Agent only) ─────────────────────────────────────────

    def test_endpoint_guard_agent(self):
        agent = EndpointGuard()
        sentinel_token = "secret_session_token_12345"

        # Valid request passes
        ctx_ok = GuardContext(
            kind=InputKind.HTTP_REQUEST,
            payload="",
            meta={
                "method": "POST",
                "path": "/api/compile",
                "headers": {
                    "host": "localhost:8000",
                    "origin": "http://localhost:8000",
                    "content-type": "application/json; charset=utf-8",
                    "content-length": "100",
                    "x-guard-token": sentinel_token,
                },
                "server_port": 8000,
                "expected_token": sentinel_token,
                "stage": "headers",
            },
        )
        self.assertEqual(agent.analyze(ctx_ok), [])

        # Headers stage failures
        test_cases_headers = [
            ({"host": "evil.com"}, "bad_host", 403),
            ({"origin": "https://evil.example"}, "bad_origin", 403),
            ({"origin": "null"}, "bad_origin", 403),
            ({"sec-fetch-site": "cross-site"}, "cross_site_request", 403),
            ({"sec-fetch-dest": "iframe"}, "cross_site_request", 403),
            ({"content-type": "text/plain"}, "bad_content_type", 415),
            ({"content-length": None}, "missing_length", 411),
            ({"content-length": "-5"}, "bad_length", 400),
            ({"content-length": "abc"}, "bad_length", 400),
            ({"content-length": str(ENDPOINT_MAX_BODY + 1)}, "body_too_large", 413),
            ({"transfer-encoding": "chunked"}, "unsupported_encoding", 400),
            ({"x-guard-token": None}, "bad_token", 403),
            ({"x-guard-token": "wrong_token"}, "bad_token", 403),
        ]

        for override, expected_cat, expected_status in test_cases_headers:
            base_headers = {
                "host": "localhost:8000",
                "origin": "http://localhost:8000",
                "content-type": "application/json",
                "content-length": "50",
                "x-guard-token": sentinel_token,
            }
            for k, v in override.items():
                if v is None:
                    base_headers.pop(k, None)
                else:
                    base_headers[k] = v

            ctx = GuardContext(
                kind=InputKind.HTTP_REQUEST,
                payload="",
                meta={
                    "method": "POST",
                    "path": "/api/compile",
                    "headers": base_headers,
                    "server_port": 8000,
                    "expected_token": sentinel_token,
                    "stage": "headers",
                },
            )
            findings = agent.analyze(ctx)
            self.assertTrue(len(findings) > 0, f"Expected finding for {override}")
            f = findings[0]
            self.assertEqual(f.category, expected_cat)
            self.assertEqual(f.details.get("http_status"), expected_status)
            self.assertEqual(f.blocks_on, {"request"})
            self.assertEqual(f.origin, "attack")
            # Sentinel token must not appear in finding title, description, or evidence
            self.assertNotIn(sentinel_token, f.title)
            self.assertNotIn(sentinel_token, f.description)
            self.assertNotIn(sentinel_token, f.evidence)

        # Body stage failures
        test_cases_body = [
            ("not valid json", "bad_json", 400),
            ("[1, 2, 3]", "bad_json", 400),
            (json.dumps({"no_code": 1}), "bad_body", 400),
            (json.dumps({"code": 1234}), "bad_body", 400),
            (json.dumps({"code": "x" * (ENDPOINT_MAX_CODE_CHARS + 1)}), "bad_body", 400),
            (json.dumps({"code": "int main() {\0}"}), "bad_body", 400),
        ]

        for payload, expected_cat, expected_status in test_cases_body:
            ctx = GuardContext(
                kind=InputKind.HTTP_REQUEST,
                payload=payload,
                meta={
                    "method": "POST",
                    "path": "/api/compile",
                    "headers": {"host": "localhost:8000"},
                    "server_port": 8000,
                    "expected_token": sentinel_token,
                    "stage": "body",
                },
            )
            findings = agent.analyze(ctx)
            self.assertTrue(len(findings) > 0, f"Expected finding for body: {payload[:30]}")
            f = findings[0]
            self.assertEqual(f.category, expected_cat)
            self.assertEqual(f.details.get("http_status"), expected_status)
            self.assertEqual(f.blocks_on, {"request"})

    # ── 5. ConcurrencyLimiter and RateLimiter ─────────────────────────────────

    def test_limiters(self):
        # ConcurrencyLimiter(2)
        c_lim = ConcurrencyLimiter(2)
        self.assertTrue(c_lim.try_acquire())
        self.assertTrue(c_lim.try_acquire())
        self.assertFalse(c_lim.try_acquire())
        c_lim.release()
        self.assertTrue(c_lim.try_acquire())
        c_lim.release()
        c_lim.release()

        # Context manager raising Busy
        with c_lim:
            with c_lim:
                with self.assertRaises(Busy):
                    with c_lim:
                        pass

        # RateLimiter with injectable clock
        current_time = 1000.0

        def fake_clock():
            return current_time

        r_lim = RateLimiter(max_events=3, window_seconds=10.0, clock=fake_clock)
        self.assertTrue(r_lim.allow())
        self.assertTrue(r_lim.allow())
        self.assertTrue(r_lim.allow())
        self.assertFalse(r_lim.allow())

        # Advance clock within window
        current_time = 1005.0
        self.assertFalse(r_lim.allow())

        # Advance clock past window
        current_time = 1011.0
        self.assertTrue(r_lim.allow())

    # ── 6. Live Server Integration ────────────────────────────────────────────

    def test_live_server(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), web_server.CompilerWebHandler)
        server.daemon_threads = True
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            # Request 1: GET /
            conn = HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/", headers={"Host": f"127.0.0.1:{port}"})
            res = conn.getresponse()
            self.assertEqual(res.status, 200)
            body = res.read().decode("utf-8")
            self.assertIn(web_server.SESSION_TOKEN, body)
            self.assertIn("Content-Security-Policy", res.headers)
            self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(res.headers.get("X-Frame-Options"), "DENY")
            self.assertIsNone(res.headers.get("Access-Control-Allow-Origin"))
            conn.close()

            # Request 2: POST /api/compile without token -> 403
            conn = HTTPConnection("127.0.0.1", port, timeout=10)
            req_body = json.dumps({"code": "int main(){return 0;}"})
            conn.request(
                "POST",
                "/api/compile",
                body=req_body,
                headers={
                    "Host": f"127.0.0.1:{port}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(req_body)),
                },
            )
            res = conn.getresponse()
            self.assertEqual(res.status, 403)
            data = json.loads(res.read().decode("utf-8"))
            self.assertEqual(data.get("agent"), "EndpointGuard")
            self.assertEqual(data.get("category"), "bad_token")
            conn.close()

            # Request 3: POST with token and Content-Type: text/plain -> 415
            conn = HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request(
                "POST",
                "/api/compile",
                body=req_body,
                headers={
                    "Host": f"127.0.0.1:{port}",
                    "Content-Type": "text/plain",
                    "Content-Length": str(len(req_body)),
                    "X-Guard-Token": web_server.SESSION_TOKEN,
                },
            )
            res = conn.getresponse()
            self.assertEqual(res.status, 415)
            data = json.loads(res.read().decode("utf-8"))
            self.assertEqual(data.get("category"), "bad_content_type")
            conn.close()

            # Request 4: POST with token and Content-Length: 10000000 (send no body) -> 413
            conn = HTTPConnection("127.0.0.1", port, timeout=10)
            conn.putrequest("POST", "/api/compile")
            conn.putheader("Host", f"127.0.0.1:{port}")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", "10000000")
            conn.putheader("X-Guard-Token", web_server.SESSION_TOKEN)
            conn.endheaders()
            res = conn.getresponse()
            self.assertEqual(res.status, 413)
            data = json.loads(res.read().decode("utf-8"))
            self.assertEqual(data.get("category"), "body_too_large")
            conn.close()

            # Request 5: POST with token and valid body -> 200
            conn = HTTPConnection("127.0.0.1", port, timeout=10)
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
            self.assertIn("status", data)
            conn.close()

        finally:
            server.shutdown()
            server.server_close()

    # ── 7. Web page regression ────────────────────────────────────────────────

    def test_web_page_regression(self):
        page = web_server.HTML_PAGE
        # Raw interpolations audit
        self.assertNotIn("${err.type}", page)
        self.assertNotIn("${err.ast_node}", page)
        self.assertNotIn("${f.severity}", page)
        self.assertNotIn("${f.title}", page)
        self.assertNotIn("${f.what}", page)
        self.assertNotIn("${f.why}", page)
        self.assertNotIn("${f.how}", page)
        self.assertNotIn("${f.detected_by}", page)
        self.assertNotIn("${f.action_label}", page)
        self.assertNotIn("${s.risk_label}", page)
        self.assertNotIn("${sv.headline}", page)
        self.assertNotIn("${h.title}", page)
        self.assertNotIn("${h.message}", page)
        self.assertNotIn("${h.suggestion}", page)

        # X-Guard-Token header present in fetch calls
        self.assertEqual(page.count("'X-Guard-Token': GUARD_TOKEN"), 3)

        # escapeHtml includes single quote replacement
        self.assertIn(".replace(/'/g, '&#39;')", page)


if __name__ == "__main__":
    unittest.main()
