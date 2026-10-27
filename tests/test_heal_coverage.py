import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure src in sys.path
_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import security_healer
from security_healer import heal_security, get_recipe, register_recipe, Fix
from guard.gates import check_patch


def compile_check(code: str, timeout: int = 15) -> bool:
    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as f:
        f.write(code)
        path = f.name
    try:
        res = subprocess.run(["g++", "-fsyntax-only", path], capture_output=True, timeout=timeout)
        return res.returncode == 0
    except Exception:
        return False
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


class TestHealCoverage(unittest.TestCase):

    def setUp(self):
        self.test_all_path = _ROOT / "test_all_security.cpp"
        self.assertTrue(self.test_all_path.exists())
        self.orig_source = self.test_all_path.read_text(encoding="utf-8")

    def test_default_settings_test_all_security(self):
        """Test default healing on test_all_security.cpp."""
        res = heal_security(self.orig_source, allow_behavior_changes=False)

        # 1. stopped_reason == "completed"
        self.assertEqual(res.stopped_reason, "completed")

        # 2. Key categories are fixed
        fixed_cats = {o.category for o in res.outcomes if o.status == "fixed"}
        expected_fixed = [
            "buffer_overflow",
            "unsafe_string_function",
            "unbounded_input",
            "double_free",
            "use_after_free",
            "integer_overflow",
            "potential_memory_leak",
            "uninitialized_variable",
            "format_string_vulnerability",
            "process_execution",
        ]
        for cat in expected_fixed:
            self.assertIn(cat, fixed_cats, f"Expected {cat} to be fixed")

        # Check all string functions (strcpy user_input, strcat _suffix, sprintf, strcpy hunter2)
        applied_descs = [a.description.lower() for a in res.applied]
        self.assertTrue(any("strcat" in d for d in applied_descs), "strcat not applied")
        self.assertTrue(any("sprintf" in d for d in applied_descs), "sprintf not applied")

        # 3. Behavior-changing and suggestion categories NOT changed
        for o in res.outcomes:
            if o.category in ("weak_randomness", "signed_unsigned_mismatch"):
                self.assertEqual(o.status, "skipped_behavior")
                self.assertIn('Enable "Allow behaviour-changing security fixes"', o.reason)
            elif o.category in ("unsafe_memory_copy", "unsafe_pointer_arithmetic"):
                self.assertEqual(o.status, "suggested")

        # 4. Compiles
        self.assertTrue(compile_check(res.source_after, timeout=15), "Default healed source does not compile")

        # 5. Risk after is lower than before
        self.assertLess(res.risk_after, res.risk_before)

        # 6. Only expected categories remain
        rem_cats = {f.get("category") if isinstance(f, dict) else f.category for f in res.findings_after}
        allowed_rem = {
            "weak_randomness",
            "signed_unsigned_mismatch",
            "unsafe_memory_copy",
            "unsafe_pointer_arithmetic",
            "unresolved_security_debt",
            "disabled_safety_check",
        }
        self.assertTrue(rem_cats.issubset(allowed_rem), f"Unexpected remaining categories: {rem_cats - allowed_rem}")

    def test_allow_behavior_changes_test_all_security(self):
        """Test healing on test_all_security.cpp with allow_behavior_changes=True."""
        res = heal_security(self.orig_source, allow_behavior_changes=True)

        self.assertEqual(res.stopped_reason, "completed")
        fixed_cats = {o.category for o in res.outcomes if o.status == "fixed"}
        self.assertIn("weak_randomness", fixed_cats)
        self.assertIn("signed_unsigned_mismatch", fixed_cats)

        # random header included
        self.assertIn("<random>", res.source_after)

        # Compiles
        self.assertTrue(compile_check(res.source_after, timeout=15), "Behavior-healed source does not compile")

        # Only suggestion-only categories remain
        rem_cats = {f.get("category") if isinstance(f, dict) else f.category for f in res.findings_after}
        self.assertNotIn("weak_randomness", rem_cats)
        self.assertNotIn("signed_unsigned_mismatch", rem_cats)

    def test_per_recipe_samples(self):
        """Before and after samples for each new/relaxed fix, compiling and accepted by PatchGuard."""
        cases = [
            (
                "strcpy literal",
                '#include <cstdio>\n#include <cstring>\nvoid f() {\n    char buf[32];\n    strcpy(buf, "secret_pw");\n}\n',
                'snprintf(buf, sizeof(buf), "%s", "secret_pw");',
                False,
            ),
            (
                "strcat literal",
                '#include <cstdio>\n#include <cstring>\nvoid f() {\n    char buf[32] = "hi";\n    strcat(buf, "_suffix");\n}\n',
                'strncat(buf, "_suffix", sizeof(buf) - strlen(buf) - 1);',
                False,
            ),
            (
                "scanf with trailing comment",
                '#include <cstdio>\nvoid f() {\n    char username[32];\n    scanf("%s", username); // note\n}\n',
                'scanf("%31s", username);',
                False,
            ),
            (
                "use-after-free",
                '#include <cstdio>\nvoid f() {\n    int* q = new int(99);\n    delete q;\n    *q = 7;\n}\n',
                '*q = 7;\n    delete q;',
                False,
            ),
            (
                "count * 1024",
                '#include <cstdlib>\n#include <cstddef>\nvoid f(int count) {\n    size_t alloc_size = count * 1024;\n    void* m = malloc(alloc_size);\n    free(m);\n}\n',
                'static_cast<size_t>(count) * 1024',
                False,
            ),
            (
                "rand",
                '#include <cstdlib>\nvoid f() {\n    int secret = rand();\n    (void)secret;\n}\n',
                'static_cast<int>(std::random_device{}() & 0x7fffffff)',
                True,
            ),
            (
                "sign compare",
                '#include <cstdio>\nvoid f(int n) {\n    unsigned int u = 10;\n    if (n < u) {\n        printf("less\\n");\n    }\n}\n',
                'static_cast<long long>(n) < static_cast<long long>(u)',
                True,
            ),
        ]

        for name, before_src, expected_sub, allow_behav in cases:
            with self.subTest(recipe=name):
                res = heal_security(before_src, allow_behavior_changes=allow_behav)
                self.assertIn(
                    expected_sub,
                    res.source_after,
                    f"Sample '{name}' did not produce expected replacement '{expected_sub}'",
                )
                self.assertTrue(
                    compile_check(res.source_after, timeout=15),
                    f"Sample '{name}' healed code did not compile",
                )
                pg_verdict = check_patch(before_src, res.source_after, origin="security_fix")
                self.assertFalse(
                    pg_verdict.blocked,
                    f"Sample '{name}' patch rejected by PatchGuard: {getattr(pg_verdict, 'findings', [])}",
                )

    def test_clean_and_unfixable(self):
        """Clean code is untouched; unfixable.cpp maintains outcomes."""
        clean_path = _ROOT / "test_cases" / "security_heal" / "clean.cpp"
        if clean_path.exists():
            clean_src = clean_path.read_text(encoding="utf-8")
            res_clean = heal_security(clean_src)
            self.assertEqual(res_clean.source_before, res_clean.source_after)
            self.assertEqual(len(res_clean.applied), 0)

        unfixable_path = _ROOT / "test_cases" / "security_heal" / "unfixable.cpp"
        if unfixable_path.exists():
            unfixable_src = unfixable_path.read_text(encoding="utf-8")
            # Default run: weak_randomness skipped_behavior, others suggested
            res_unf = heal_security(unfixable_src, allow_behavior_changes=False)
            self.assertEqual(res_unf.stopped_reason, "completed")
            self.assertTrue(compile_check(res_unf.source_after, timeout=15))

    def test_round_limit(self):
        """Synthetic source with 25 findings heals all with default, stops early with max_rounds=3."""
        lines = ["#include <cstdio>", "void test_all() {"]
        for i in range(25):
            lines.append(f"    char b{i}[32];")
            lines.append(f"    gets(b{i});")
        lines.append("}")
        synth_source = "\n".join(lines) + "\n"

        # Default settings: max_rounds adapts to min(60, max(10, 25+5)) = 30 -> all healed
        res_full = heal_security(synth_source)
        self.assertEqual(res_full.stopped_reason, "completed")
        self.assertEqual(len(res_full.applied), 25)

        # Constrained max_rounds=3
        res_lim = heal_security(synth_source, max_rounds=3)
        self.assertEqual(res_lim.stopped_reason, "round_limit")
        self.assertEqual(len(res_lim.applied), 3)
        not_attempted = [o for o in res_lim.outcomes if o.status == "not_attempted"]
        self.assertGreaterEqual(len(not_attempted), 20)
        self.assertIn("Round limit reached", not_attempted[0].reason)

    def test_termination_on_rejection(self):
        """A patch that always fails validation finishes quickly with rejected, never loops."""
        source = '#include <cstring>\nvoid f() {\n    char buf[16];\n    strcpy(buf, "test");\n}\n'
        orig_recipe = get_recipe("unsafe_string_function")
        try:
            # Register a recipe that produces invalid code failing compilation
            def broken_apply(src, fnd):
                return Fix(
                    finding_category=fnd.category,
                    line=fnd.line,
                    safety_class="auto",
                    description="broken fix",
                    before="strcpy",
                    after="!!! SYNTAX ERROR !!!",
                    new_source=src.replace("strcpy", "!!! SYNTAX ERROR !!!"),
                )

            register_recipe(
                "unsafe_string_function",
                "auto",
                broken_apply,
                orig_recipe.suggest if orig_recipe else lambda s, f: None,
            )

            res = heal_security(source, max_rounds=5)
            self.assertEqual(res.source_before, res.source_after)
            self.assertEqual(len(res.applied), 0)
            rejected = [o for o in res.outcomes if o.status == "rejected"]
            self.assertEqual(len(rejected), 1)
            self.assertEqual(res.stopped_reason, "completed")
        finally:
            if orig_recipe:
                register_recipe(
                    orig_recipe.category,
                    orig_recipe.safety_class,
                    orig_recipe.apply,
                    orig_recipe.suggest,
                )


if __name__ == "__main__":
    unittest.main()
