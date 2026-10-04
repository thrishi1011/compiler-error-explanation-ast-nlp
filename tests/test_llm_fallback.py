"""
test_llm_fallback.py
---------------------
Comprehensive tests for LLM client fallback, circuit breakers, security redaction,
AI heal validation, and offscreen GUI smoke testing.
All tests use mocks only: no network, no real keys.
"""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

# Setup paths
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC_DIR = os.path.join(_PROJECT_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import llm_client
from llm_client import LLMResult, reset_client_state, strip_markdown_fences
from ai_healer import validate_ai_code, extract_ai_heal_code, attempt_ai_heal


class TestLLMClientFallback(unittest.TestCase):
    def setUp(self):
        reset_client_state()

    def tearDown(self):
        reset_client_state()

    @patch.dict(os.environ, {"GEMINI_API_KEY": "", "GROQ_API_KEY": ""}, clear=True)
    def test_no_keys_gives_offline(self):
        """When no keys are configured, llm_client returns None immediately without network calls."""
        with patch("llm_client._http_post") as mock_post:
            res = llm_client.ask(
                system="system prompt",
                prompt="test prompt",
                kind="explain"
            )
            mock_post.assert_not_called()
            self.assertIsNone(res.text)
            self.assertIsNone(res.provider)
            self.assertTrue("No active LLM" in res.error or "No API keys" in res.error)
            status_str = llm_client.status()
            self.assertIn("offline", status_str)

    @patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_gemini_key", "GROQ_API_KEY": "dummy_groq_key"})
    def test_gemini_ok_means_gemini_used(self):
        """When Gemini returns 200 OK, Gemini's response is used."""
        gemini_response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": '{"explanation": "Gemini explanation", "fix": ";", "why": "Need ;"}'}
                        ]
                    }
                }
            ]
        }
        with patch("llm_client._http_post") as mock_post:
            mock_post.return_value = (200, json.dumps(gemini_response), {})
            res = llm_client.ask(
                system="system prompt",
                prompt="test prompt",
                kind="explain"
            )
            self.assertEqual(res.provider, "gemini")
            self.assertIn("Gemini explanation", res.text)
            self.assertIsNone(res.error)
            # Only Gemini called, not Groq
            self.assertEqual(mock_post.call_count, 1)

    @patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_gemini_key", "GROQ_API_KEY": "dummy_groq_key"})
    def test_gemini_429_moves_to_groq_and_cooldown(self):
        """When Gemini returns 429, Gemini enters cooldown and Groq is used as backup."""
        groq_response = {
            "choices": [
                {
                    "message": {
                        "content": '{"explanation": "Groq explanation", "fix": ";", "why": "Need ;"}'
                    }
                }
            ]
        }

        def mock_post_side_effect(url, headers, data, timeout):
            if "generativelanguage" in url:
                return (429, "Resource exhausted / quota limit reached", {"retry-after": "60"})
            else:
                return (200, json.dumps(groq_response), {})

        with patch("llm_client._http_post", side_effect=mock_post_side_effect) as mock_post:
            res = llm_client.ask(
                system="system prompt",
                prompt="test prompt",
                kind="explain"
            )
            self.assertEqual(res.provider, "groq")
            self.assertIn("Groq explanation", res.text)
            # Gemini is now in cooldown
            g_avail, g_reason = llm_client._GEMINI_STATE.is_available()
            self.assertFalse(g_avail)
            self.assertIn("cooldown", g_reason)

    @patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_gemini_key", "GROQ_API_KEY": "dummy_groq_key"})
    def test_both_429_returns_none_and_no_network_during_cooldown(self):
        """When both return 429, ask() returns None, and subsequent calls make 0 network calls during cooldown."""
        def mock_post_both_429(url, headers, data, timeout):
            return (429, "Rate limit exceeded", {"retry-after": "60"})

        with patch("llm_client._http_post", side_effect=mock_post_both_429) as mock_post:
            # First call exhausts both
            res = llm_client.ask(
                system="system prompt",
                prompt="test prompt 1",
                kind="explain"
            )
            self.assertIsNone(res.text)
            self.assertIsNone(res.provider)
            self.assertIn("429", res.error)

            call_count_after_first = mock_post.call_count

            # Second call during cooldown: must return None immediately with NO network calls
            res2 = llm_client.ask(
                system="system prompt",
                prompt="test prompt 2",
                kind="explain"
            )
            self.assertIsNone(res2.text)
            self.assertEqual(mock_post.call_count, call_count_after_first)
            status_str = llm_client.status()
            self.assertIn("offline", status_str)

    @patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_gemini_key", "GROQ_API_KEY": "dummy_groq_key"})
    def test_timeout_retry_and_fallback(self):
        """Timeout triggers at most 1 retry per provider, then moves to next provider."""
        call_urls = []

        def mock_post_timeout(url, headers, data, timeout):
            call_urls.append(url)
            if "generativelanguage" in url:
                return (408, "Read timeout", {})
            else:
                groq_resp = {"choices": [{"message": {"content": "ok from groq"}}]}
                return (200, json.dumps(groq_resp), {})

        with patch("llm_client._http_post", side_effect=mock_post_timeout) as mock_post:
            res = llm_client.ask(
                system="system prompt",
                prompt="test prompt timeout",
                kind="explain"
            )
            # Gemini had initial call + 1 retry (total 2 calls), then fell back to Groq (1 call)
            gemini_calls = sum(1 for u in call_urls if "generativelanguage" in u)
            groq_calls = sum(1 for u in call_urls if "groq" in u)
            self.assertEqual(gemini_calls, 2)
            self.assertEqual(groq_calls, 1)
            self.assertEqual(res.provider, "groq")
            self.assertEqual(res.text, "ok from groq")

    @patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_gemini_key", "GROQ_API_KEY": "dummy_groq_key"})
    def test_401_disables_provider_for_session(self):
        """HTTP 401 disables the provider for the session so it is never called again."""
        call_urls = []

        def mock_post_401(url, headers, data, timeout):
            call_urls.append(url)
            if "generativelanguage" in url:
                return (401, "API_KEY_INVALID", {})
            else:
                return (200, json.dumps({"choices": [{"message": {"content": "groq success"}}]},), {})

        with patch("llm_client._http_post", side_effect=mock_post_401) as mock_post:
            res1 = llm_client.ask(system="s", prompt="p1", kind="explain")
            self.assertEqual(res1.provider, "groq")

            # Check that Gemini is marked disabled
            g_avail, g_reason = llm_client._GEMINI_STATE.is_available()
            self.assertFalse(g_avail)
            self.assertIn("disabled", g_reason)

            # Second call: Gemini should be skipped entirely
            call_urls.clear()
            res2 = llm_client.ask(system="s", prompt="p2", kind="explain")
            self.assertEqual(res2.provider, "groq")
            self.assertTrue(all("generativelanguage" not in u for u in call_urls))

    @patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_gemini_key", "GROQ_API_KEY": "dummy_groq_key"})
    def test_malformed_json_moves_to_next_provider(self):
        """When Gemini returns malformed/unparseable response, Groq is called."""
        def mock_post_malformed(url, headers, data, timeout):
            if "generativelanguage" in url:
                return (200, "THIS IS NOT VALID JSON AT ALL {{{{", {})
            else:
                return (200, json.dumps({"choices": [{"message": {"content": "groq rescued"}}]}), {})

        with patch("llm_client._http_post", side_effect=mock_post_malformed):
            res = llm_client.ask(system="s", prompt="p", kind="explain")
            self.assertEqual(res.provider, "groq")
            self.assertEqual(res.text, "groq rescued")

    @patch.dict(os.environ, {
        "GEMINI_API_KEY": "AIzaSySUPER_SECRET_GEMINI_KEY_XYZ999",
        "GROQ_API_KEY": "gsk_SUPER_SECRET_GROQ_KEY_1234567890ABCDEF"
    })
    def test_key_string_never_appears_in_status_or_error(self):
        """API keys must be strictly redacted from any status, error, or log strings."""
        gemini_secret = os.environ["GEMINI_API_KEY"]
        groq_secret = os.environ["GROQ_API_KEY"]

        def mock_post_leak_keys(url, headers, data, timeout):
            # Simulate an error response containing the raw keys
            leak_msg = f"Error for key {gemini_secret} and groq key {groq_secret}"
            return (500, leak_msg, {})

        with patch("llm_client._http_post", side_effect=mock_post_leak_keys):
            res = llm_client.ask(system="s", prompt="leak_test", kind="explain")
            self.assertNotIn(gemini_secret, res.error or "")
            self.assertNotIn(groq_secret, res.error or "")
            status_text = llm_client.status()
            self.assertNotIn(gemini_secret, status_text)
            self.assertNotIn(groq_secret, status_text)

    @patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_gemini_key", "GROQ_API_KEY": "dummy_groq_key"})
    def test_gemini_model_cascade_3_8_to_3_7_to_3_5(self):
        """Gemini cascades from 3.8 to 3.7 to 3.5 when earlier models return 404."""
        called_models = []

        def mock_cascade(url, headers, data, timeout):
            for m in ["gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.5-flash"]:
                if m in url:
                    called_models.append(m)
                    if m == "gemini-3.5-flash":
                        resp = {"candidates": [{"content": {"parts": [{"text": "{\"ok\": true}"}]}}]}
                        return (200, json.dumps(resp), {})
                    else:
                        return (404, f"Model {m} not found", {})
            return (404, "Not found", {})

        with patch("llm_client._http_post", side_effect=mock_cascade):
            res = llm_client.ask(system="s", prompt="cascade test", kind="explain")
            self.assertEqual(res.provider, "gemini")
            self.assertEqual(called_models, ["gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.5-flash"])

    @patch.dict(os.environ, {"GEMINI_API_KEY": "", "GROQ_API_KEY": "dummy_groq_key"})
    def test_groq_model_cascade_3_1_to_3_0(self):
        """Groq cascades from llama-3.1 to llama3.0 (llama3-8b-8192) when 3.1 returns 404."""
        called_models = []

        def mock_groq_cascade(url, headers, data, timeout):
            model = data.get("model", "")
            called_models.append(model)
            if model == "llama3-8b-8192":
                return (200, json.dumps({"choices": [{"message": {"content": "{\"ok\": true}"}}]}), {})
            return (404, f"Model {model} not found", {})

        with patch("llm_client._http_post", side_effect=mock_groq_cascade):
            res = llm_client.ask(system="s", prompt="groq cascade test", kind="explain")
            self.assertEqual(res.provider, "groq")
            self.assertEqual(called_models, ["llama-3.1-8b-instant", "llama3-8b-8192"])


class TestHealValidation(unittest.TestCase):
    def test_sanitize_code_rejects_system_call(self):
        """AI code containing system(...) or forbidden calls is rejected by validate_ai_code."""
        original = "#include <iostream>\nint main() {\n    std::cout << \"Hello\" << std::endl;\n    return 0;\n}"
        malicious_fixed = "#include <iostream>\n#include <cstdlib>\nint main() {\n    system(\"rm -rf /\");\n    return 0;\n}"
        is_valid, reason, _ = validate_ai_code(original, malicious_fixed)
        self.assertFalse(is_valid)
        self.assertIn("Security check failed", reason)

    def test_short_stub_rejected_for_large_file(self):
        """A 5-line stub for a 200-line file is rejected (length < 60%)."""
        original = "// Big file\n" + "\n".join([f"int x_{i} = {i};" for i in range(200)]) + "\nint main() { return 0; }"
        stub = "int main() {\n    return 0;\n}"
        is_valid, reason, _ = validate_ai_code(original, stub)
        self.assertFalse(is_valid)
        self.assertIn("length too short", reason)

    def test_valid_fixed_code_accepted(self):
        """Valid fixed C++ code that compiles with zero errors is accepted."""
        original = "#include <iostream>\nint main() {\n    std::cout << \"Hello\" << std::endl\n    return 0;\n}"
        fixed = "#include <iostream>\nint main() {\n    std::cout << \"Hello\" << std::endl;\n    return 0;\n}"
        is_valid, reason, err = validate_ai_code(original, fixed)
        self.assertTrue(is_valid, f"Validation failed: {reason} (g++: {err})")

    def test_non_compiling_ai_code_triggers_retry_and_fallback(self):
        """When AI returns code that does not compile, attempt_ai_heal retries once and falls back."""
        original = "#include <iostream>\nint main() {\n    std::cout << \"Hello\"\n    return 0;\n}"
        broken_ai_fix = json.dumps({
            "code": "#include <iostream>\nint main() {\n    std::cout << UNKNOWN_SYMBOL;\n    return 0;\n}",
            "changes": ["broken fix"]
        })

        mock_ask_result = LLMResult(text=broken_ai_fix, provider="gemini", error=None)

        with patch("llm_client.ask", return_value=mock_ask_result) as mock_ask:
            candidate_code, provider, changes, status_msg = attempt_ai_heal(
                original,
                [{"line": 3, "message": "expected ';' before 'return'"}]
            )
            # Both attempts (initial + retry) should have been called
            self.assertEqual(mock_ask.call_count, 2)
            # Candidate code should be None (rejected), triggering offline fallback
            self.assertIsNone(candidate_code)
            self.assertIn("validation failed", status_msg)


class TestOffscreenGUISmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        from PyQt6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([sys.argv[0], "-platform", "offscreen"])

    def test_gui_offscreen_pages_and_paths(self):
        """Offscreen GUI smoke test: loads test case, opens all 6 pages, runs analyze & heal paths."""
        from gui import AppGUI
        gui = AppGUI()
        self.assertIsNotNone(gui)

        test_file = os.path.join(_PROJECT_ROOT, "test_cases", "syntax_error.cpp")
        self.assertTrue(os.path.exists(test_file))

        # 1. Load file
        gui.file_path = test_file
        gui.file_name = os.path.basename(test_file)
        with open(test_file, "r", encoding="utf-8") as f:
            gui.editor.setPlainText(f.read())

        # 2. Confirm AST, Security, Call Graph, CFG, Second Opinion, Benchmark pages open without exceptions
        gui.switch_to_ast()
        self.assertEqual(gui.stack.currentIndex(), 1)

        gui.switch_to_call_graph()
        self.assertEqual(gui.stack.currentIndex(), 3)

        gui.switch_to_security()
        self.assertEqual(gui.stack.currentIndex(), 4)

        gui.switch_to_cfg()
        self.assertEqual(gui.stack.currentIndex(), 5)

        gui._btn_second_opinion.click()
        self.assertEqual(gui.stack.currentIndex(), 6)

        gui._btn_benchmark.click()
        self.assertEqual(gui.stack.currentIndex(), 7)

        # 3. Switch back to editor
        gui.sidebar.btn1.click()
        self.assertEqual(gui.stack.currentIndex(), 0)

        # 4. Verify AI status label and assist checkbox
        self.assertTrue(hasattr(gui, "cb_ai_assist"))
        self.assertTrue(hasattr(gui, "ai_status_label"))

    @patch.dict(os.environ, {"ENABLE_LLM": "0"})
    def test_gui_analyze_and_heal_offline(self):
        """Run analyze and heal with ENABLE_LLM=0."""
        import tempfile, shutil
        from gui import AppGUI
        gui = AppGUI()
        test_file = os.path.join(_PROJECT_ROOT, "test_cases", "syntax_error.cpp")
        fd, tmp_cpp = tempfile.mkstemp(suffix=".cpp")
        os.close(fd)
        shutil.copyfile(test_file, tmp_cpp)
        try:
            gui.file_path = tmp_cpp
            gui.file_name = os.path.basename(tmp_cpp)
            with open(tmp_cpp, "r", encoding="utf-8") as f:
                gui.editor.setPlainText(f.read())

            gui.analyze()
            if hasattr(gui, "compile_worker") and gui.compile_worker:
                gui.compile_worker.wait(8000)

            gui.start_heal()
            if hasattr(gui, "heal_worker") and gui.heal_worker:
                gui.heal_worker.wait(15000)
        finally:
            if os.path.exists(tmp_cpp):
                try:
                    os.remove(tmp_cpp)
                except OSError:
                    pass

    def test_gui_analyze_and_heal_mocked_llm(self):
        """Run analyze and heal with a mocked LLM."""
        import tempfile, shutil
        from gui import AppGUI
        gui = AppGUI()
        gui.cb_ai_assist.setChecked(True)
        test_file = os.path.join(_PROJECT_ROOT, "test_cases", "syntax_error.cpp")
        fd, tmp_cpp = tempfile.mkstemp(suffix=".cpp")
        os.close(fd)
        shutil.copyfile(test_file, tmp_cpp)
        try:
            gui.file_path = tmp_cpp
            gui.file_name = os.path.basename(tmp_cpp)
            with open(tmp_cpp, "r", encoding="utf-8") as f:
                gui.editor.setPlainText(f.read())

            fixed_code = "#include <iostream>\nint main() {\n    std::cout << \"Hello World\\n\";\n    return 0;\n}"
            mock_heal_resp = json.dumps({
                "code": fixed_code,
                "changes": ["added semicolon"]
            })
            with patch("llm_client.ask", return_value=LLMResult(text=mock_heal_resp, provider="gemini", error=None)), \
                 patch("llm_client.get_gemini_key", return_value="dummy_key"):
                gui.analyze()
                if hasattr(gui, "compile_worker") and gui.compile_worker:
                    gui.compile_worker.wait(8000)

                gui.start_heal()
                if hasattr(gui, "heal_worker") and gui.heal_worker:
                    gui.heal_worker.wait(15000)
        finally:
            if os.path.exists(tmp_cpp):
                try:
                    os.remove(tmp_cpp)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
