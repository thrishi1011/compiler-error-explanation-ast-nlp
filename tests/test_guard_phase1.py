"""
test_guard_phase1.py
--------------------
Phase 1 tests for the compiler error explainer agentic-AI security layer.
Tests Supervisor, ExecGuard, VulnGuard adapter, environment scrubbing,
attack logging, and CLI runner.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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
)
from guard.base import GuardAgent, GuardContext
from guard.exec_guard import ExecGuard
from guard.vuln_guard import VulnGuard


class TestGuardPhase1(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.log_file = Path(cls.temp_dir.name) / "test_attack_log.jsonl"
        os.environ["GUARD_LOG_PATH"] = str(cls.log_file)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()
        os.environ.pop("GUARD_LOG_PATH", None)

    def setUp(self) -> None:
        self.supervisor = get_supervisor()

    # ── 1. Attack Cases ──────────────────────────────────────────────────────────

    def test_attack_execvp(self):
        code = '#include <unistd.h>\nint main() { char* args[] = {"/bin/sh", NULL}; execvp(args[0], args); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "process_execution" and f.origin == "attack" for f in verdict.findings))

    def test_attack_execl(self):
        code = '#include <unistd.h>\nint main() { execl("/bin/sh", "sh", NULL); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "process_execution" and f.origin == "attack" for f in verdict.findings))

    def test_attack_popen(self):
        code = '#include <stdio.h>\nint main() { FILE* f = popen("whoami", "r"); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "process_execution" and f.origin == "attack" for f in verdict.findings))

    def test_attack_posix_spawn(self):
        code = '#include <spawn.h>\nint main() { pid_t pid; posix_spawn(&pid, "/bin/ls", NULL, NULL, NULL, NULL); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "process_execution" and f.origin == "attack" for f in verdict.findings))

    def test_attack_asm_nop(self):
        code = 'int main() { asm("nop"); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "inline_assembly" and f.origin == "attack" for f in verdict.findings))

    def test_attack_under_asm_nop(self):
        code = 'int main() { __asm("nop"); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "inline_assembly" and f.origin == "attack" for f in verdict.findings))

    def test_attack_dlsym(self):
        code = '#include <dlfcn.h>\nint main() { void* h = dlsym(RTLD_DEFAULT, "system"); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "dynamic_loading" and f.origin == "attack" for f in verdict.findings))

    def test_attack_sys_socket_include(self):
        code = '#include <sys/socket.h>\nint main() { return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "network_access" and f.origin == "attack" for f in verdict.findings))

    def test_attack_fopen_sensitive_path(self):
        code = '#include <stdio.h>\nint main() { FILE* f = fopen("/etc/passwd", "r"); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "sensitive_file_access" and f.origin == "attack" for f in verdict.findings))

    def test_attack_getenv_secret_key(self):
        code = '#include <cstdlib>\nint main() { const char* k = getenv("GEMINI_API_KEY"); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "secret_env_access" and f.origin == "attack" for f in verdict.findings))

    def test_attack_local_header_include(self):
        with tempfile.TemporaryDirectory() as src_dir:
            header_file = Path(src_dir) / "evil.h"
            header_file.write_text('#include <cstdlib>\ninline void pwn() { system("id"); }\n', encoding="utf-8")

            main_code = '#include "evil.h"\nint main() { pwn(); return 0; }'
            verdict = self.supervisor.review(
                InputKind.USER_SOURCE,
                main_code,
                purpose="run",
                meta={"source_dir": src_dir, "file_name": "main.cpp"},
            )
            self.assertTrue(verdict.blocked)
            self.assertEqual(verdict.action, "block")
            matching = [f for f in verdict.findings if f.category == "process_execution"]
            self.assertTrue(len(matching) > 0)
            self.assertEqual(matching[0].line, 1)  # Reported on include line in main file
            self.assertIn("evil.h", matching[0].evidence)

    def test_attack_define_alias(self):
        code = '#define RUN system\nint main() { RUN("id"); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category in ("obfuscation", "process_execution") for f in verdict.findings))

    def test_attack_token_pasting(self):
        code = '#define CALL(a) sys ## tem("id")\nint main() { CALL(1); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.action, "block")
        self.assertTrue(any(f.category == "obfuscation" for f in verdict.findings))

    # ── 2. Benign Programs ───────────────────────────────────────────────────────

    def test_benign_hello_world(self):
        code = '#include <iostream>\nint main() { std::cout << "Hello, world!" << std::endl; return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.action, "allow")
        self.assertEqual(len([f for f in verdict.findings if f.origin == "attack"]), 0)

    def test_benign_ifstream_relative(self):
        code = '#include <fstream>\n#include <string>\nint main() { std::ifstream in("input.txt"); std::string s; in >> s; return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.action, "allow")
        self.assertEqual(len([f for f in verdict.findings if f.origin == "attack"]), 0)

    def test_benign_vector_sort(self):
        code = '#include <vector>\n#include <algorithm>\nint main() { std::vector<int> v = {3, 1, 2}; std::sort(v.begin(), v.end()); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.action, "allow")
        self.assertEqual(len([f for f in verdict.findings if f.origin == "attack"]), 0)

    def test_benign_function_execute_variable_executor(self):
        code = 'void execute() {}\nint main() { int executor = 1; execute(); return executor; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.action, "allow")
        self.assertEqual(len([f for f in verdict.findings if f.origin == "attack"]), 0)

    def test_benign_my_system_function(self):
        code = 'void my_system() {}\nint main() { my_system(); return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.action, "allow")
        self.assertEqual(len([f for f in verdict.findings if f.origin == "attack"]), 0)

    def test_benign_commented_system_call(self):
        code = '// system("ls");\n/* system("rm -rf /"); */\nint main() { return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.action, "allow")
        self.assertEqual(len([f for f in verdict.findings if f.origin == "attack"]), 0)

    def test_benign_string_literal_system(self):
        code = '#include <iostream>\nint main() { std::cout << "do not call system("; return 0; }'
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.action, "allow")
        self.assertEqual(len([f for f in verdict.findings if f.origin == "attack"]), 0)

    # ── 3. Permission Toggle ────────────────────────────────────────────────────

    def test_allow_system_calls_toggle(self):
        code = '#include <cstdlib>\nint main() { system("echo hi"); return 0; }'
        orig = os.environ.get("ALLOW_SYSTEM_CALLS")
        try:
            os.environ["ALLOW_SYSTEM_CALLS"] = "1"
            verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
            self.assertFalse(verdict.blocked)
            self.assertEqual(verdict.action, "warn")
            low_proc_findings = [f for f in verdict.findings if f.category == "process_execution"]
            self.assertTrue(len(low_proc_findings) > 0)
            self.assertEqual(low_proc_findings[0].severity, "Low")
            self.assertEqual(low_proc_findings[0].action, "warn")
            self.assertIn("permitted by policy toggle", low_proc_findings[0].description)
        finally:
            if orig is not None:
                os.environ["ALLOW_SYSTEM_CALLS"] = orig
            else:
                os.environ.pop("ALLOW_SYSTEM_CALLS", None)

    # ── 4. Routing, Merge, and Quick-Match Equivalence ──────────────────────────

    def test_routing_and_merge_gets_and_system(self):
        code = (
            '#include <cstdio>\n#include <cstdlib>\n'
            'int main() {\n'
            '    char buf[10];\n'
            '    gets(buf);\n'
            '    system("x");\n'
            '    return 0;\n'
            '}\n'
        )
        verdict = self.supervisor.review(InputKind.USER_SOURCE, code, purpose="run")
        self.assertTrue(verdict.blocked)

        # gets(buf) from VulnGuard
        buf_overflow = [f for f in verdict.findings if f.category == "buffer_overflow"]
        self.assertTrue(len(buf_overflow) > 0)
        self.assertIn("VulnGuard", buf_overflow[0].agents)
        self.assertEqual(buf_overflow[0].origin, "vulnerability")

        # system("x") merged between ExecGuard and VulnGuard
        proc_exec = [f for f in verdict.findings if f.category == "process_execution"]
        self.assertTrue(len(proc_exec) > 0)
        self.assertIn("ExecGuard", proc_exec[0].agents)
        self.assertIn("VulnGuard", proc_exec[0].agents)
        self.assertEqual(proc_exec[0].origin, "attack")
        self.assertEqual(proc_exec[0].action, "block")

    def test_full_scan_equals_quick_match_for_all_attack_samples(self):
        samples = [
            'int main() { char* a[] = {NULL}; execvp("a", a); return 0; }',
            'int main() { execl("a", "b", NULL); return 0; }',
            'int main() { popen("a", "r"); return 0; }',
            'int main() { posix_spawn(NULL, "a", NULL, NULL, NULL, NULL); return 0; }',
            'int main() { asm("nop"); return 0; }',
            'int main() { __asm("nop"); return 0; }',
            'int main() { dlsym(0, "system"); return 0; }',
            '#include <sys/socket.h>\nint main() { return 0; }',
            'int main() { fopen("/etc/passwd", "r"); return 0; }',
            'int main() { getenv("GEMINI_API_KEY"); return 0; }',
            '#define RUN system\nint main() { RUN("x"); return 0; }',
            '#define P sys ## tem\nint main() { P("x"); return 0; }',
        ]

        for s in samples:
            routed_v = self.supervisor.review(InputKind.USER_SOURCE, s, purpose="run", full_scan=False)
            full_v = self.supervisor.review(InputKind.USER_SOURCE, s, purpose="run", full_scan=True)

            self.assertEqual(routed_v.blocked, full_v.blocked, f"Blocked mismatch for sample: {s}")
            self.assertEqual(len(routed_v.findings), len(full_v.findings), f"Count mismatch for: {s}")

            routed_cats = sorted(f.category for f in routed_v.findings)
            full_cats = sorted(f.category for f in full_v.findings)
            self.assertEqual(routed_cats, full_cats, f"Categories mismatch for: {s}")

    # ── 5. Log Hygiene ──────────────────────────────────────────────────────────

    def test_log_hygiene(self):
        secret_val = "AIzaSyABCDEF12345678901234567890"
        raw_code = f'int main() {{\n    // KEY={secret_val}\n    getenv("GEMINI_API_KEY");\n    return 0;\n}}'

        # Record file size before review
        prev_lines = []
        if self.log_file.exists():
            prev_lines = self.log_file.read_text(encoding="utf-8").splitlines()

        verdict = self.supervisor.review(
            InputKind.USER_SOURCE,
            raw_code,
            purpose="run",
            meta={"file_name": "secret_test.cpp"},
        )
        self.assertTrue(verdict.blocked)

        self.assertTrue(self.log_file.exists())
        current_lines = self.log_file.read_text(encoding="utf-8").splitlines()
        self.assertGreater(len(current_lines), len(prev_lines))

        last_entry = json.loads(current_lines[-1])
        self.assertIn("payload_sha256", last_entry)
        self.assertTrue(len(last_entry["payload_sha256"]) == 64)

        # Ensure full source text is NOT in the log entry
        self.assertNotIn("int main() {", current_lines[-1])
        # Ensure secret value is NOT in the log entry
        self.assertNotIn(secret_val, current_lines[-1])

    # ── 6. Fail-Closed / Never Raises on Broken Agent ────────────────────────────

    def test_never_raises_on_broken_agent(self):
        class BrokenAgent(GuardAgent):
            name = "BrokenAgent"
            handles = {InputKind.USER_SOURCE}

            def quick_match(self, ctx: GuardContext) -> bool:
                return True

            def analyze(self, ctx: GuardContext) -> list[Finding]:
                raise RuntimeError("Deliberate internal agent explosion!")

        sup = Supervisor()
        sup.register(BrokenAgent())

        # Under purpose="run", crash of attack agent must block (fail closed)
        verdict_run = sup.review(InputKind.USER_SOURCE, "int main() { return 0; }", purpose="run")
        self.assertTrue(verdict_run.blocked)
        self.assertEqual(verdict_run.action, "block")
        self.assertTrue(any(f.category == "guard_error" and f.severity == "Medium" for f in verdict_run.findings))

        # Under purpose="analyze", it only warns
        verdict_analyze = sup.review(InputKind.USER_SOURCE, "int main() { return 0; }", purpose="analyze")
        self.assertFalse(verdict_analyze.blocked)
        self.assertEqual(verdict_analyze.action, "warn")

    # ── 7. Environment Scrubbing ─────────────────────────────────────────────────

    def test_scrubbed_env(self):
        mock_env = {
            "PATH": "C:\\Windows\\System32;/usr/bin",
            "HOME": "/home/user",
            "GEMINI_API_KEY": "secret_gemini",
            "GROQ_API_KEY": "secret_groq",
            "AWS_SECRET_ACCESS_KEY": "secret_aws",
            "AWS_REGION": "us-west-2",
            "USER_PASSWORD": "mypassword",
            "GITHUB_TOKEN": "ghp_1234567890",
            "DB_PASSWD": "123",
            "MY_CREDENTIAL": "cred",
        }

        cleaned = scrubbed_env(mock_env)
        self.assertIn("PATH", cleaned)
        self.assertIn("HOME", cleaned)
        self.assertNotIn("GEMINI_API_KEY", cleaned)
        self.assertNotIn("GROQ_API_KEY", cleaned)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", cleaned)
        self.assertNotIn("AWS_REGION", cleaned)
        self.assertNotIn("USER_PASSWORD", cleaned)
        self.assertNotIn("GITHUB_TOKEN", cleaned)
        self.assertNotIn("DB_PASSWD", cleaned)
        self.assertNotIn("MY_CREDENTIAL", cleaned)

    # ── 8. Non-USER_SOURCE Kind Passes Cleanly ───────────────────────────────────

    def test_non_user_source_kind_allows(self):
        for k in [
            InputKind.COMPILER_OUTPUT,
            InputKind.AI_RESPONSE,
            InputKind.USER_HINT,
            InputKind.PATCH,
            InputKind.HTTP_REQUEST,
            InputKind.MODEL_FILE,
            InputKind.DATASET_ENTRY,
        ]:
            verdict = self.supervisor.review(k, "system('rm -rf /');", purpose="run")
            self.assertFalse(verdict.blocked)
            self.assertEqual(verdict.action, "allow")
            self.assertEqual(len(verdict.findings), 0)


if __name__ == "__main__":
    unittest.main()
