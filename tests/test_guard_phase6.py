import io
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure src in path
_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import security_healer
from security_healer import (
    Fix,
    Outcome,
    SecurityHealResult,
    find_char_array_size,
    get_recipe,
    register_recipe,
    heal_security,
)
from guard import get_supervisor, InputKind
from guard.gates import check_patch
import heal_engine
import llm_client


class TestSecurityHealerPhase6(unittest.TestCase):

    # ── 1. find_char_array_size helper ─────────────────────────────────────────

    def test_find_char_array_size_literal(self):
        source = """
        void foo() {
            char buf[16];
            strcpy(buf, "test");
        }
        """
        size = find_char_array_size(source, "buf", 4)
        self.assertEqual(size, 16)

    def test_find_char_array_size_define_and_const(self):
        source = """
        #define BUF_SIZE 64
        const int OTHER_SIZE = 32;
        void foo() {
            char a[BUF_SIZE];
            char b[OTHER_SIZE];
            strcpy(a, "x");
            strcpy(b, "y");
        }
        """
        self.assertEqual(find_char_array_size(source, "a", 7), 64)
        self.assertEqual(find_char_array_size(source, "b", 8), 32)

    def test_find_char_array_size_pointers_and_params(self):
        source = """
        void foo(char* p, char buf[16]) {
            char* dyn = new char[32];
            std::string s;
            strcpy(p, "x");
        }
        """
        self.assertIsNone(find_char_array_size(source, "p", 5))
        self.assertIsNone(find_char_array_size(source, "dyn", 5))
        self.assertIsNone(find_char_array_size(source, "s", 5))

    # ── 2. Auto Recipes Validation ─────────────────────────────────────────────

    def test_recipe_unsafe_string_strcpy(self):
        source = """#include <cstdio>\n#include <cstring>\nvoid f(const char* s) {\n    char buf[16];\n    strcpy(buf, s);\n}\n"""
        res = heal_security(source)
        self.assertIn("snprintf(buf, sizeof(buf), \"%s\", s);", res.source_after)
        self.assertLessEqual(res.risk_after, res.risk_before)
        # PatchGuard check
        pv = check_patch(source, res.source_after, origin="security_fix")
        self.assertFalse(pv.blocked)

    def test_recipe_unbounded_input_scanf(self):
        source = """#include <cstdio>\nvoid f() {\n    char name[32];\n    scanf("%s", name);\n}\n"""
        res = heal_security(source)
        self.assertIn('scanf("%31s", name);', res.source_after)
        self.assertLessEqual(res.risk_after, res.risk_before)

    def test_recipe_format_string(self):
        source = """#include <cstdio>\nvoid f(const char* msg) {\n    printf(msg);\n}\n"""
        res = heal_security(source)
        self.assertIn('printf("%s", msg);', res.source_after)
        self.assertLessEqual(res.risk_after, res.risk_before)

    def test_recipe_double_free(self):
        source = """void f() {\n    int* p = new int(1);\n    delete p;\n    delete p;\n}\n"""
        res = heal_security(source)
        self.assertIn("p = nullptr;", res.source_after)
        self.assertLessEqual(res.risk_after, res.risk_before)

    def test_recipe_use_after_free(self):
        source = """#include <cstdio>\nvoid f() {\n    int* p = new int(1);\n    delete p;\n    printf("%d", *p);\n}\n"""
        res = heal_security(source)
        lines = res.source_after.splitlines()
        del_idx = next(i for i, l in enumerate(lines) if "delete p;" in l)
        print_idx = next(i for i, l in enumerate(lines) if "printf" in l)
        self.assertGreater(del_idx, print_idx)

    def test_recipe_uninitialized_variable(self):
        source = """int f() {\n    int total;\n    return total + 1;\n}\n"""
        res = heal_security(source)
        self.assertIn("int total = 0;", res.source_after)

    def test_recipe_potential_memory_leak(self):
        source = """#include <cstdlib>\n#include <cstdio>\nvoid f() {\n    char* tmp = (char*)malloc(64);\n    printf("%s", tmp);\n}\n"""
        res = heal_security(source)
        self.assertIn("free(tmp);", res.source_after)

    def test_recipe_command_injection(self):
        source = """#include <cstdlib>\nvoid f() {\n    system("ls");\n}\n"""
        res = heal_security(source)
        self.assertIn("// [removed by security healer: system call]", res.source_after)

    def test_recipe_sensitive_include(self):
        source = """#include "../.env"\n#include <iostream>\nint main() { return 0; }\n"""
        res = heal_security(source)
        self.assertIn("// [include removed by security healer:", res.source_after)

    def test_recipe_hidden_unicode(self):
        source = 'int main() { const char* s = "\u202Ereversed"; return 0; }\n'
        res = heal_security(source)
        self.assertNotIn("\u202E", res.source_after)

    # ── 3. Preconditions & Suggestions ─────────────────────────────────────────

    def test_precondition_strcpy_pointer_param(self):
        source = """#include <cstring>\nvoid f(char* dest, const char* src) {\n    strcpy(dest, src);\n}\n"""
        res = heal_security(source)
        self.assertEqual(res.source_before, res.source_after)
        self.assertTrue(any(o.status == "suggested" for o in res.outcomes))
        self.assertTrue(len(res.suggestions) > 0)

    def test_precondition_format_string_literal_untouched(self):
        source = """#include <cstdio>\nvoid f() {\n    printf("hello world\\n");\n}\n"""
        res = heal_security(source)
        self.assertEqual(res.source_before, res.source_after)
        self.assertEqual(len(res.applied), 0)

    def test_precondition_uaf_with_branch_produces_suggestion(self):
        source = """#include <cstdio>\nvoid f(int x) {\n    int* p = new int(1);\n    delete p;\n    if (x > 0) {\n        printf("%d", *p);\n    }\n}\n"""
        res = heal_security(source)
        self.assertEqual(res.source_before, res.source_after)
        self.assertTrue(any(o.status == "suggested" for o in res.outcomes))

    # ── 4. Safety Classes ──────────────────────────────────────────────────────

    def test_safety_class_auto_notice_default_skipped(self):
        source = """void f(int d) {\n    int a = 10 / d;\n}\n"""
        res = heal_security(source, allow_behavior_changes=False)
        self.assertEqual(res.source_before, res.source_after)
        div_outcome = next((o for o in res.outcomes if o.category == "division_by_zero"), None)
        if div_outcome:
            self.assertEqual(div_outcome.status, "skipped_behavior")

    def test_safety_class_auto_notice_applied_when_allowed(self):
        source = """void f(int d) {\n    int a = 10 / d;\n}\n"""
        res = heal_security(source, allow_behavior_changes=True)
        div_outcome = next((o for o in res.outcomes if o.category == "division_by_zero"), None)
        if div_outcome and div_outcome.status == "fixed":
            self.assertIn("!= 0 ?", res.source_after)

    def test_safety_class_suggest_never_changes_code(self):
        source = """#include <cstdlib>\nvoid f() {\n    int token = rand();\n}\n"""
        res = heal_security(source, allow_behavior_changes=True)
        self.assertEqual(res.source_before, res.source_after)
        rand_o = next((o for o in res.outcomes if o.category == "weak_randomness"), None)
        self.assertIsNotNone(rand_o)
        self.assertEqual(rand_o.status, "suggested")

    # ── 5. Rollback on Validation Failure ──────────────────────────────────────

    def test_rollback_on_failed_compile(self):
        source = """#include <cstring>\nvoid f() { char buf[16]; strcpy(buf, "hi"); }\n"""
        original_recipe = get_recipe("unsafe_string_function")
        try:
            # Register broken recipe that introduces syntax error
            def broken_apply(src, fnd):
                return Fix(
                    finding_category=fnd.category,
                    line=fnd.line,
                    safety_class="auto",
                    description="broken fix",
                    before="strcpy",
                    after="SYNTAX ERROR !!!",
                    new_source=src.replace("strcpy", "SYNTAX ERROR !!!"),
                )

            register_recipe(
                "unsafe_string_function",
                "auto",
                broken_apply,
                original_recipe.suggest,
            )
            res = heal_security(source)
            self.assertEqual(res.source_before, res.source_after)
            rej = next((o for o in res.outcomes if o.status == "rejected"), None)
            self.assertIsNotNone(rej)
            self.assertIn("compile_errors_increased", rej.reason)
        finally:
            if original_recipe:
                register_recipe(
                    original_recipe.category,
                    original_recipe.safety_class,
                    original_recipe.apply,
                    original_recipe.suggest,
                )

    # ── 6. Samples Tests ───────────────────────────────────────────────────────

    def test_sample_fixable_cpp(self):
        fixable_path = _ROOT / "test_cases" / "security_heal" / "fixable.cpp"
        source = fixable_path.read_text(encoding="utf-8")
        res = heal_security(source)
        self.assertTrue(res.improved)
        self.assertLess(res.risk_after, res.risk_before)
        fixed_outcomes = [o for o in res.outcomes if o.status == "fixed"]
        self.assertGreaterEqual(len(fixed_outcomes), 5)
        for o in fixed_outcomes:
            self.assertTrue(len(o.agents) > 0)

    def test_sample_unfixable_cpp(self):
        unfixable_path = _ROOT / "test_cases" / "security_heal" / "unfixable.cpp"
        source = unfixable_path.read_text(encoding="utf-8")
        res = heal_security(source, allow_behavior_changes=False)
        self.assertEqual(res.source_before, res.source_after)
        self.assertTrue(all(o.status in ("suggested", "skipped_behavior", "manual") for o in res.outcomes))

    def test_sample_clean_cpp(self):
        clean_path = _ROOT / "test_cases" / "security_heal" / "clean.cpp"
        source = clean_path.read_text(encoding="utf-8")
        res = heal_security(source)
        self.assertEqual(res.source_before, res.source_after)
        self.assertEqual(len(res.applied), 0)
        self.assertLessEqual(res.risk_before, 10)

    # ── 7. Integration: heal_until_clean with blocked include & fixable ────────

    def test_heal_engine_blocked_include_unblocking(self):
        source = """#include "../.env"\n#include <iostream>\nint main() { std::cout << "OK\\n"; return 0; }\n"""
        res = heal_engine.heal_until_clean(source, use_ai=False)
        self.assertTrue(res.clean)
        self.assertIn("// [include removed by security healer: sensitive_include]", res.code)

    def test_heal_engine_fixable_integration(self):
        fixable_path = _ROOT / "test_cases" / "security_heal" / "fixable.cpp"
        source = fixable_path.read_text(encoding="utf-8")
        res = heal_engine.heal_until_clean(source, use_ai=False)
        res_dict = res.to_dict()
        self.assertIn("security", res_dict)
        sec = res_dict["security"]
        self.assertIsNotNone(sec)
        self.assertGreater(sec["risk_before"], sec["risk_after"])
        self.assertTrue(sec["improved"])
        self.assertGreaterEqual(len(sec["applied"]), 5)

    # ── 8. Follow-ups A1 & A2 ──────────────────────────────────────────────────

    def test_a1_medium_secret_allowed_high_refused(self):
        # Medium credential assignment (warn, allowed)
        with patch("llm_client._call_gemini", return_value=("clean code", None, False, False)):
            with patch("llm_client.get_gemini_key", return_value="dummy_key"):
                res_med = llm_client.ask(
                    system="system prompt",
                    prompt='void auth() { const char* password = "UserProvidedPassword123"; }\n',
                )
                self.assertEqual(res_med.text, "clean code")

        # High secret key (AIza... Google API key) -> refused
        high_prompt = 'void auth() { const char* key = "AIzaSyD-1234567890abcdefghijklmnopqr"; }\n'
        with patch("llm_client._http_post") as mock_post:
            res_high = llm_client.ask(
                system="system prompt",
                prompt=high_prompt,
            )
            mock_post.assert_not_called()
            self.assertIsNone(res_high.text)
            self.assertIn("secret was found in the prompt", res_high.error)


if __name__ == "__main__":
    unittest.main()
