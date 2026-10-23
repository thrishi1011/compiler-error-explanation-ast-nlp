"""
test_guard_phase2.py
--------------------
Phase 2 tests for the compiler error explainer agentic-AI security layer.
Tests:
- Safe subprocess runner (timeouts, output caps, env scrubbing, cmd validation)
- ResourceGuard detections and non-triggers
- Compile-time security blocking at compile sites
- Attack log noise reduction & deduplication (A1)
- Verified build-and-run temp directory isolation (A2)
- Per-finding blocking rule & include_vulnerability flag (A3)
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root and src to sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _PROJECT_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from guard import (
    Finding,
    InputKind,
    Supervisor,
    Verdict,
    get_supervisor,
    scrubbed_env,
    check_compile,
    safe_run,
    SafeResult,
    build_and_run,
)
from guard.base import GuardAgent, GuardContext
from guard.resource_guard import ResourceGuard
import compiler_runner
import heal_engine


class TestGuardPhase2(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.log_file = Path(cls.temp_dir.name) / "test_attack_log_p2.jsonl"
        os.environ["GUARD_LOG_PATH"] = str(cls.log_file)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()
        os.environ.pop("GUARD_LOG_PATH", None)

    def setUp(self) -> None:
        self.supervisor = get_supervisor()
        if self.log_file.exists():
            self.log_file.unlink()

    # ── Part B: safe_run Tests ───────────────────────────────────────────────

    def test_safe_run_normal_stdout(self):
        cmd = [sys.executable, "-c", "print('hello_safe_run')"]
        res = safe_run(cmd, kind="compile")
        self.assertEqual(res.returncode, 0)
        self.assertIn("hello_safe_run", res.stdout)
        self.assertFalse(res.timed_out)
        self.assertFalse(res.truncated)
        self.assertGreaterEqual(res.duration_s, 0.0)

    def test_safe_run_timeout(self):
        t0 = time.time()
        res = safe_run([sys.executable, "-c", "while True: pass"], kind="run", timeout=1.0)
        duration = time.time() - t0
        self.assertTrue(res.timed_out)
        self.assertLess(duration, 5.0)

    def test_safe_run_truncated(self):
        cmd = [sys.executable, "-c", "import sys; sys.stdout.write('A' * 200000); sys.stdout.flush()"]
        res = safe_run(cmd, kind="run", timeout=5.0, max_output_bytes=50000)
        self.assertTrue(res.truncated)
        self.assertLessEqual(len(res.stdout), 60000)

    def test_safe_run_env_scrubbing(self):
        os.environ["GEMINI_API_KEY"] = "super_secret_test_key_xyz"
        try:
            cmd = [sys.executable, "-c", "import os; print(os.environ.get('GEMINI_API_KEY'))"]
            res = safe_run(cmd, kind="run", timeout=5.0)
            self.assertIn("None", res.stdout.strip())
        finally:
            os.environ.pop("GEMINI_API_KEY", None)

    def test_safe_run_requires_list_cmd(self):
        with self.assertRaises(AssertionError):
            safe_run("python -c print(1)", kind="run")

    # ── Part C: ResourceGuard Detection Tests ─────────────────────────────────

    def test_resource_guard_special_file_include_dev_zero(self):
        code = '#include "/dev/zero"\nint main() { return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="compile")
        self.assertTrue(verdict.blocked)
        matching = [f for f in verdict.findings if f.category == "special_file_include"]
        self.assertTrue(len(matching) > 0)
        self.assertEqual(matching[0].severity, "High")
        self.assertEqual(matching[0].blocks_on, {"compile", "run"})

    def test_resource_guard_special_file_include_unc(self):
        code = '#include "\\\\server\\share\\x.h"\nint main() { return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="compile")
        self.assertTrue(verdict.blocked)
        matching = [f for f in verdict.findings if f.category == "special_file_include"]
        self.assertTrue(len(matching) > 0)

    def test_resource_guard_special_file_include_con(self):
        code = '#include "CON"\nint main() { return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="compile")
        self.assertTrue(verdict.blocked)
        matching = [f for f in verdict.findings if f.category == "special_file_include"]
        self.assertTrue(len(matching) > 0)

    def test_resource_guard_macro_expansion_bomb(self):
        bomb = """
#define A(x) x x x x x x x x
#define B(x) A(A(x))
#define C(x) B(B(x))
#define D(x) C(C(x))
int a[] = { D(D(1)) };
int main(){}
"""
        verdict = self.supervisor.review(InputKind.USER_SOURCE, bomb, purpose="compile")
        self.assertTrue(verdict.blocked)
        matching = [f for f in verdict.findings if f.category == "macro_expansion_bomb"]
        self.assertTrue(len(matching) > 0)
        self.assertEqual(matching[0].severity, "High")
        self.assertEqual(matching[0].blocks_on, {"compile", "run"})

    def test_resource_guard_huge_allocation_array(self):
        code = "int big[1000000000];\nint main() { return 0; }"
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        matching = [f for f in verdict.findings if f.category == "huge_allocation"]
        self.assertTrue(len(matching) > 0)
        self.assertEqual(matching[0].blocks_on, {"run"})

    def test_resource_guard_huge_allocation_vector(self):
        code = "#include <vector>\nint main() { std::vector<int> v(2000000000); return 0; }"
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        matching = [f for f in verdict.findings if f.category == "huge_allocation"]
        self.assertTrue(len(matching) > 0)

    def test_resource_guard_possible_infinite_loop_warning(self):
        code = "int main() { while(true){} return 0; }"
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        # Medium finding with blocks_on=set() must not block
        self.assertFalse(verdict.blocked)
        matching = [f for f in verdict.findings if f.category == "possible_infinite_loop"]
        self.assertTrue(len(matching) > 0)
        self.assertEqual(matching[0].severity, "Medium")
        self.assertEqual(matching[0].blocks_on, set())

    # ── Part C: ResourceGuard Non-Triggers ─────────────────────────────────────

    def test_resource_guard_non_triggers(self):
        non_triggers = [
            "#define SQUARE(x) ((x)*(x))\nint main() { return SQUARE(5); }",
            "#define MAX(a,b) ((a)>(b)?(a):(b))\nint main() { return MAX(1, 2); }",
            "int dp[100005];\nint main() { return dp[0]; }",
            "int main() { while(true) { if (1) break; } return 0; }",
            '#include <fstream>\nint main() { std::ifstream in("input.txt"); return 0; }',
        ]
        for src in non_triggers:
            verdict = self.supervisor.review(InputKind.USER_SOURCE, src, purpose="compile")
            rg_findings = [f for f in verdict.findings if "ResourceGuard" in f.agents]
            self.assertEqual(
                len(rg_findings),
                0,
                f"Unexpected ResourceGuard findings for non-trigger snippet: {rg_findings}",
            )

    def test_resource_guard_normal_100_line_program(self):
        lines = ["#include <iostream>", "#include <vector>", "int main() {"]
        lines.append("    std::vector<int> numbers;")
        for i in range(80):
            lines.append(f"    numbers.push_back({i});")
        lines.append("    int sum = 0;")
        for i in range(10):
            lines.append(f"    sum += numbers[{i}];")
        lines.append("    std::cout << sum << std::endl;")
        lines.append("    return 0;")
        lines.append("}")
        code = "\n".join(lines)

        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="compile")
        self.assertFalse(verdict.blocked)
        rg_findings = [f for f in verdict.findings if "ResourceGuard" in f.agents]
        self.assertEqual(len(rg_findings), 0)

    # ── Part D: Compile-Time Blocking Enforcement ────────────────────────────

    def test_blocking_enforced_compiler_runner(self):
        with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as tmp:
            tmp.write('#include "/dev/zero"\nint main() { return 0; }')
            tmp_path = tmp.name

        try:
            with patch("compiler_runner.safe_run") as mock_safe_run:
                mock_safe_run.side_effect = AssertionError("safe_run should NOT be called when blocked!")
                out = compiler_runner.run_cpp_compiler(tmp_path)
                mock_safe_run.assert_not_called()
                self.assertTrue(isinstance(out, list))
                self.assertTrue(len(out) > 0)
                self.assertIn("Security Error: blocked by ResourceGuard (special_file_include)", out[0]["message"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_blocking_enforced_heal_engine(self):
        code = '#include "/dev/zero"\nint main() { return 0; }'
        with patch("heal_engine.safe_run") as mock_safe_run:
            mock_safe_run.side_effect = AssertionError("safe_run should NOT be called when blocked!")
            errors, warnings, output = heal_engine.compile_source(code, syntax_only=True)
            self.assertTrue(len(errors) > 0)
            self.assertIn("Security Error: blocked by ResourceGuard (special_file_include)", output)
            mock_safe_run.assert_not_called()

    # ── Part A1: Attack Log Noise Reduction & Dedup ───────────────────────────

    def test_attack_log_noise_vuln_only_not_logged(self):
        # A vulnerability-only verdict (e.g. from VulnGuard with no attack finding and not blocked)
        # Should not write to attack_log
        vuln_finding = Finding(
            category="memory_leak",
            severity="Low",
            confidence=0.8,
            line=1,
            column=1,
            evidence="malloc without free",
            agents=["VulnGuard"],
            origin="vulnerability",
            action="warn",
            blocks_on=None,
        )
        verdict = Verdict(
            action="warn",
            blocked=False,
            findings=[vuln_finding],
            routing=[{"agent": "VulnGuard", "reason": "quick_match"}],
            timings_ms={"VulnGuard": 5.0},
            total_ms=5.0,
            risk_score=10,
            purpose="compile",
        )

        from guard.attack_log import log_verdict
        log_verdict(verdict, meta={"payload_sha256": "dummy_sha"})
        if self.log_file.exists():
            lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 0)

    def test_attack_log_dedup_within_60_seconds(self):
        code = '#include <unistd.h>\nint main() { execl("/bin/sh", "sh", NULL); return 0; }'
        # First review
        verdict1 = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict1.blocked)
        lines1 = self.log_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines1), 1)

        # Immediate second review (within 60s)
        verdict2 = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict2.blocked)
        lines2 = self.log_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines2), 1, "Duplicate review within 60s should not add another line")

    # ── Part A3: Per-Finding Blocking & include_vulnerability ─────────────────

    def test_blocks_on_compile_only(self):
        class CompileOnlyAgent(GuardAgent):
            name = "CompileOnlyAgent"
            handles = {InputKind.USER_SOURCE}

            def quick_match(self, ctx: GuardContext) -> bool:
                return True

            def analyze(self, ctx: GuardContext) -> list[Finding]:
                return [
                    Finding(
                        category="compile_bomb",
                        severity="High",
                        confidence=0.9,
                        line=1,
                        column=1,
                        evidence="bomb",
                        agents=[self.name],
                        origin="attack",
                        blocks_on={"compile"},
                    )
                ]

        sup = Supervisor()
        sup.register(CompileOnlyAgent())

        # purpose="compile" should block
        v_compile = sup.review(InputKind.USER_SOURCE, "int main(){}", purpose="compile")
        self.assertTrue(v_compile.blocked)
        self.assertEqual(v_compile.action, "block")

        # purpose="run" should NOT block
        v_run = sup.review(InputKind.USER_SOURCE, "int main(){}", purpose="run")
        self.assertFalse(v_run.blocked)
        self.assertEqual(v_run.action, "warn")

    def test_include_vulnerability_skips_vulnguard(self):
        code = '#include <string.h>\nint main() { char buf[4]; strcpy(buf, "toolong"); return 0; }'
        # With include_vulnerability=False
        v_fast = self.supervisor.review(
            InputKind.USER_SOURCE,
            code,
            purpose="compile",
            include_vulnerability=False,
        )
        routed_agents = [r["agent"] for r in v_fast.routing]
        self.assertNotIn("VulnGuard", routed_agents)

        # With check_compile fast=True
        v_check = check_compile(code, fast=True)
        check_agents = [r["agent"] for r in v_check.routing]
        self.assertNotIn("VulnGuard", check_agents)

    # ── Part A2: build_and_run reviewed code isolation ────────────────────────

    def test_build_and_run_reviewed_code(self):
        code = 'int main() { return 0; }'
        created_dirs = []

        real_safe_run = safe_run
        def mock_sr(cmd, *args, **kwargs):
            cwd = kwargs.get("cwd")
            if cwd and cwd not in created_dirs:
                created_dirs.append(cwd)
            src_file = os.path.join(cwd, "main.cpp")
            with open(src_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertEqual(content, code)
            return SafeResult(returncode=0, stdout="test_out", stderr="", timed_out=False, truncated=False, duration_s=0.1)

        with patch("guard.runner.safe_run", side_effect=mock_sr):
            res = build_and_run(code, timeout=5)
            self.assertTrue(res.compiled_ok)
            self.assertIsNotNone(res.run_result)
            self.assertEqual(res.run_result.stdout, "test_out")

        # Verify that all created temporary directories were cleaned up
        for d in created_dirs:
            self.assertFalse(os.path.exists(d), f"Temp dir {d} was not cleaned up!")

    def test_safe_run_grandchild_timeout_descendant_termination(self):
        """A child process that starts a grandchild sleeping 60 seconds with inherited output; safe_run(timeout=2) must return within 8 seconds with timed_out=True."""
        child_code = (
            "import subprocess, sys, time; "
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
            "time.sleep(60)"
        )
        t0 = time.monotonic()
        res = safe_run([sys.executable, "-c", child_code], kind="syntax", timeout=2.0)
        elapsed = time.monotonic() - t0
        self.assertTrue(res.timed_out, "safe_run must report timed_out=True")
        self.assertLess(elapsed, 8.0, f"safe_run must return within 8s, took {elapsed:.2f}s")


if __name__ == "__main__":
    unittest.main()
