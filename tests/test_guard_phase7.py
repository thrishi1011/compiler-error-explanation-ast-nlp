"""
tests/test_guard_phase7.py
--------------------------
Phase 7 tests:
- Part A: Real before/after diffs in Fix, self-referencing auto Gate V5, security_analyzer regression
- Manifest integrity & coverage
- Benchmark execution: timing, metrics, isolation, zero attack execution/compilation
- Healing evaluation
- CLI outputs (JSON, Markdown, CSV)
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from guard.benchmark import baseline_allows, baseline_eval, run_benchmark, wilson_interval
from guard.models import Finding, InputKind
from security_healer import Fix, Outcome, get_recipe, heal_security, register_recipe
import security_analyzer


class TestPhase7PartA(unittest.TestCase):
    """Part A follow-ups: Fix before/after diffs, Gate V5, and analyzer regression."""

    def test_a1_real_diff_pairs(self):
        fixable_path = _ROOT / "test_cases" / "security_heal" / "fixable.cpp"
        src = fixable_path.read_text(encoding="utf-8")
        res = heal_security(src)

        # 1. uninitialized_variable: before has 'int total;', after has 'int total = 0;'
        uninit_fix = next((f for f in res.applied if f.finding_category == "uninitialized_variable"), None)
        self.assertIsNotNone(uninit_fix)
        self.assertIn("int total;", uninit_fix.before)
        self.assertIn("int total = 0;", uninit_fix.after)

        # 2. potential_memory_leak: before is empty, after has free(tmp);
        leak_fix = next((f for f in res.applied if f.finding_category == "potential_memory_leak"), None)
        self.assertIsNotNone(leak_fix)
        self.assertEqual(leak_fix.before, "")
        self.assertIn("free(tmp);", leak_fix.after)

        # 3. double_free: before is empty, after has p = nullptr;
        df_fix = next((f for f in res.applied if f.finding_category == "double_free"), None)
        self.assertIsNotNone(df_fix)
        self.assertEqual(df_fix.before, "")
        self.assertIn("p = nullptr;", df_fix.after)

    def test_a2_gate_v5_self_referencing_auto(self):
        # Fake recipe turning 'x = x + 1;' into 'auto x = x + 1;'
        source = '#include <cstdio>\nvoid f() { int x = 0; x = x + 1; }\n'
        orig = get_recipe("integer_overflow")

        def bad_apply(src, fnd):
            new_src = src.replace("x = x + 1;", "auto x = x + 1;")
            return Fix(
                finding_category=fnd.category,
                line=fnd.line,
                safety_class="auto",
                description="bad self-referencing auto",
                before="x = x + 1;",
                after="auto x = x + 1;",
                new_source=new_src,
            )

        try:
            register_recipe("integer_overflow", "auto", bad_apply, orig.suggest if orig else None)
            fake_fnd = Finding(
                id="fake_01",
                agents=["VulnGuard"],
                origin="attack",
                category="integer_overflow",
                severity="High",
                title="Integer Overflow",
                description="test",
                recommendation="fix",
                line=2,
            )
            # heal_security with source containing the target finding
            # We review a source where integer_overflow or the finding triggers
            res = heal_security(source)
            self.assertEqual(res.source_before, res.source_after)
            rej = [o for o in res.outcomes if o.status == "rejected"]
            # Either no candidate or rejected via V5
            if rej:
                self.assertTrue(
                    any("self_referencing_auto_declaration" in o.reason or "assignment_converted_to_declaration" in o.reason for o in rej)
                )
        finally:
            if orig:
                register_recipe(orig.category, orig.safety_class, orig.apply, orig.suggest)

    def test_a2_fixable_total_no_auto(self):
        fixable_path = _ROOT / "test_cases" / "security_heal" / "fixable.cpp"
        src = fixable_path.read_text(encoding="utf-8")
        res = heal_security(src)
        self.assertIn("int total = 0;", res.source_after)
        self.assertNotIn("auto total", res.source_after)

    def test_a3_analyzer_regression(self):
        """Verify current security_analyzer reports at least the categories from git before Phase 6."""
        all_sec_path = _ROOT / "test_all_security.cpp"
        secure_path = _ROOT / "test_secure.cpp"

        if not all_sec_path.exists() or not secure_path.exists():
            self.skipTest("Sample files missing for analyzer regression")

        # Frozen categories from HEAD (before Phase 6 changes)
        FROZEN_ALL_SECURITY = [
            'Buffer Overflow',
            'Command Injection',
            'Integer Overflow',
            'Potential Memory Leak',
            'Uninitialized Variable',
            'Unsafe Memory Copy',
            'Unsafe String Function',
            'Use After Free',
            'Weak Randomness',
        ]
        FROZEN_SECURE = [
            'Command Injection',
            'Integer Overflow',
            'Unsafe String Function',
            'Weak Randomness',
        ]

        curr_all = security_analyzer.analyze(str(all_sec_path), [])
        curr_all_cats = set(f.vulnerability_type for f in curr_all)

        curr_sec = security_analyzer.analyze(str(secure_path), [])
        curr_sec_cats = set(f.vulnerability_type for f in curr_sec)

        for expected in FROZEN_ALL_SECURITY:
            self.assertIn(expected, curr_all_cats, f"Category lost from test_all_security.cpp: {expected}")

        for expected in FROZEN_SECURE:
            self.assertIn(expected, curr_sec_cats, f"Category lost from test_secure.cpp: {expected}")


class TestPhase7Manifest(unittest.TestCase):
    """Manifest structure, integrity, and coverage verification."""

    @classmethod
    def setUpClass(cls):
        cls.manifest_path = _ROOT / "security_bench" / "manifest.json"
        cls.cases = json.loads(cls.manifest_path.read_text(encoding="utf-8"))

    def test_manifest_schema_and_uniqueness(self):
        seen_ids = set()
        required_fields = {"id", "label", "set", "family", "kind", "purpose", "notes"}
        valid_labels = {"attack", "benign"}
        valid_sets = {"standard", "hard"}
        valid_families = {
            "dangerous_execution", "resource_exhaustion", "sensitive_data_access",
            "display_injection", "endpoint_abuse", "dataset_poisoning",
            "model_tampering", "prompt_injection", "malicious_patch", "scanner_evasion"
        }
        valid_kinds = {
            "USER_SOURCE", "COMPILER_OUTPUT", "AI_RESPONSE", "USER_HINT",
            "PATCH", "HTTP_REQUEST", "DATASET_ENTRY", "MODEL_FILE"
        }
        valid_purposes = {
            "run", "compile", "ai_send", "patch", "request",
            "dataset", "model_load", "display", "analyze"
        }

        for c in self.cases:
            cid = c["id"]
            self.assertNotIn(cid, seen_ids, f"Duplicate case id: {cid}")
            seen_ids.add(cid)

            for f in required_fields:
                self.assertIn(f, c, f"Missing field {f} in case {cid}")

            self.assertIn(c["label"], valid_labels)
            self.assertIn(c["set"], valid_sets)
            self.assertIn(c["family"], valid_families)
            self.assertIn(c["kind"], valid_kinds)
            self.assertIn(c["purpose"], valid_purposes)

            if c["label"] == "attack":
                self.assertTrue(len(c.get("expected_agents", [])) > 0, f"Missing expected_agents in attack {cid}")
                self.assertTrue(bool(c.get("expected_category")), f"Missing expected_category in attack {cid}")
                self.assertIn(c.get("prevention"), {"block", "neutralize", "warn"})

    def test_coverage_minimums(self):
        std_attacks = [c for c in self.cases if c["label"] == "attack" and c["set"] == "standard"]
        hard_attacks = [c for c in self.cases if c["label"] == "attack" and c["set"] == "hard"]
        benign_cases = [c for c in self.cases if c["label"] == "benign"]

        self.assertGreaterEqual(len(std_attacks), 62, "Standard attacks must be >= 62")
        self.assertGreaterEqual(len(hard_attacks), 12, "Hard attacks must be >= 12")
        self.assertGreaterEqual(len(benign_cases), 30, "Benign cases must be >= 30")

        # Per family minimums on standard attacks
        counts = {}
        for c in std_attacks:
            counts[c["family"]] = counts.get(c["family"], 0) + 1

        self.assertGreaterEqual(counts.get("dangerous_execution", 0), 8)
        self.assertGreaterEqual(counts.get("resource_exhaustion", 0), 5)
        self.assertGreaterEqual(counts.get("sensitive_data_access", 0), 8)
        self.assertGreaterEqual(counts.get("display_injection", 0), 6)
        self.assertGreaterEqual(counts.get("endpoint_abuse", 0), 10)
        self.assertGreaterEqual(counts.get("dataset_poisoning", 0), 4)
        self.assertGreaterEqual(counts.get("model_tampering", 0), 3)
        self.assertGreaterEqual(counts.get("prompt_injection", 0), 8)
        self.assertGreaterEqual(counts.get("malicious_patch", 0), 10)

        # Benign twins: at least 2 per family
        benign_counts = {}
        for c in benign_cases:
            benign_counts[c["family"]] = benign_counts.get(c["family"], 0) + 1

        all_fams = {
            "dangerous_execution", "resource_exhaustion", "sensitive_data_access",
            "display_injection", "endpoint_abuse", "dataset_poisoning",
            "model_tampering", "prompt_injection", "malicious_patch", "scanner_evasion"
        }
        for fam in all_fams:
            self.assertGreaterEqual(benign_counts.get(fam, 0), 2, f"Fewer than 2 benign twins for family {fam}")

    def test_no_real_secrets(self):
        raw = self.manifest_path.read_text(encoding="utf-8")
        # Ensure only fake pattern tokens are present, no actual production credentials
        import re
        real_looking = re.findall(r"(?:AIzaSy[A-Za-z0-9_-]{33}|gsk_[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9_-]{48})", raw)
        for token in real_looking:
            self.assertTrue("FAKE" in token, f"Potentially real-looking secret without FAKE marker: {token}")


class TestPhase7BenchmarkRun(unittest.TestCase):
    """Execution properties: latency, metrics, isolation, and safety."""

    def test_benchmark_run_under_30s_and_metrics(self):
        real_subp_run = subprocess.run
        real_subp_popen = subprocess.Popen

        def safe_run_mock(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("cmd", [])
            if len(cmd) > 1 and cmd[1] == "--version":
                from guard.safe_run import SafeResult
                return SafeResult(stdout="g++ 11.2.0\n", stderr="", returncode=0, duration_s=0.01, peak_rss_bytes=1000)
            raise AssertionError(f"safe_run called unexpectedly on: {cmd}")

        def subp_run_mock(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
            if "g++" in cmd_str and "--version" not in cmd_str:
                raise AssertionError(f"Attack compilation attempted with: {cmd}")
            for dangerous in ("sh", "bash", "id", "rm"):
                if dangerous in cmd_str:
                    raise AssertionError(f"Attack execution attempted: {cmd}")
            return real_subp_run(*args, **kwargs)

        def subp_popen_mock(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
            if "g++" in cmd_str and "--version" not in cmd_str:
                raise AssertionError(f"Attack compilation attempted with: {cmd}")
            for dangerous in ("sh", "bash", "id", "rm"):
                if dangerous in cmd_str:
                    raise AssertionError(f"Attack execution attempted: {cmd}")
            return real_subp_popen(*args, **kwargs)

        with patch("guard.safe_run.safe_run", side_effect=safe_run_mock), \
             patch("subprocess.run", side_effect=subp_run_mock), \
             patch("subprocess.Popen", side_effect=subp_popen_mock):
            res = run_benchmark(with_heal=False)

        # 1. Timing
        self.assertLess(res["benchmark_seconds"], 30.0, "Benchmark took longer than 30s")

        # 2. Rates in [0, 1] and Wilson intervals contain point estimate
        ov = res["overall"]
        for rate_key in ("detection_rate", "attribution_rate", "prevention_rate", "false_alert_rate", "false_block_rate"):
            r_data = ov[rate_key]
            r = r_data["rate"]
            ci = r_data["ci_95"]
            self.assertGreaterEqual(r, 0.0)
            self.assertLessEqual(r, 1.0)
            self.assertLessEqual(ci[0], r + 1e-4)
            self.assertGreaterEqual(ci[1], r - 1e-4)

        # 3. Routing misses == 0
        self.assertEqual(res["routing"]["routing_misses"], 0)

        # 4. Standard set detection rate >= 0.95
        std_det = res["by_set"]["standard"]["detection_rate"]["rate"]
        self.assertGreaterEqual(std_det, 0.95, f"Standard detection rate {std_det} < 0.95")

        # 5. Benign block false positive == 0
        self.assertEqual(ov["false_block_rate"]["count"], 0)

        # 6. Defended ASR <= Baseline ASR for every family
        for fam, f_data in res["by_family"].items():
            self.assertLessEqual(
                f_data["defended_asr"],
                f_data["baseline_asr"] + 1e-6,
                f"Defended ASR exceeded baseline for family {fam}",
            )

    def test_isolation_no_data_pollution(self):
        attack_log = _ROOT / "data" / "attack_log.jsonl"
        manifest = _ROOT / "data" / "model_manifest.json"
        dotenv = _ROOT / ".env"

        hash_before = {}
        for p in (attack_log, manifest, dotenv):
            if p.exists():
                hash_before[p] = hashlib.sha256(p.read_bytes()).hexdigest()

        # Run benchmark
        run_benchmark(with_heal=False)

        for p, h in hash_before.items():
            self.assertTrue(p.exists())
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), h, f"{p} was modified by benchmark!")

    def test_heal_section_evaluation(self):
        res = run_benchmark(with_heal=True)
        heal = res.get("heal")
        self.assertIsNotNone(heal)
        totals = heal["totals"]

        self.assertGreater(totals["findings_before"], 0)
        self.assertGreater(totals["fix_rate"], 0.5)
        self.assertGreater(totals["risk_reduction_pct"], 50.0)

        # Sum of outcomes equals findings_before
        outcome_sum = totals["fixed"] + totals["suggested"] + totals["skipped"] + totals["rejected"]
        self.assertEqual(outcome_sum, totals["findings_before"])

        # clean.cpp has no applied fixes
        clean_file = next((f for f in heal["files"] if f["file"] == "clean.cpp"), None)
        self.assertIsNotNone(clean_file)
        self.assertEqual(clean_file["fixed"], 0)
        self.assertEqual(clean_file["findings_before"], 0)


class TestPhase7CLIOutputs(unittest.TestCase):
    """Validates CLI output files (JSON, Markdown, CSV)."""

    @classmethod
    def setUpClass(cls):
        cmd = [sys.executable, str(_ROOT / "tools" / "security_benchmark.py"), "--with-heal", "--quiet"]
        subprocess.check_call(cmd, cwd=str(_ROOT))

    def test_output_files_generated(self):
        json_p = _ROOT / "data" / "security_metrics.json"
        md_p = _ROOT / "data" / "security_metrics.md"
        csv_p = _ROOT / "data" / "security_cases.csv"

        self.assertTrue(json_p.exists())
        self.assertTrue(md_p.exists())
        self.assertTrue(csv_p.exists())

        # Markdown contents
        md_text = md_p.read_text(encoding="utf-8")
        self.assertIn("# Security Layer Benchmark Evaluation Report", md_text)
        self.assertIn("## 1. Metric Definitions", md_text)
        self.assertIn("## 10. Known Misses & Hard Evasions", md_text)

        # CSV rows
        csv_lines = [l for l in csv_p.read_text(encoding="utf-8").splitlines() if l.strip()]
        manifest_cases = json.loads((_ROOT / "security_bench" / "manifest.json").read_text(encoding="utf-8"))
        # Header + 1 row per case
        self.assertEqual(len(csv_lines), len(manifest_cases) + 1)

    def test_headline_numbers_match_csv(self):
        """Reads data/security_cases.csv, recomputes headline numbers and verifies match with security_metrics.json."""
        import csv
        csv_p = _ROOT / "data" / "security_cases.csv"
        json_p = _ROOT / "data" / "security_metrics.json"
        self.assertTrue(csv_p.exists())
        self.assertTrue(json_p.exists())

        metrics = json.loads(json_p.read_text(encoding="utf-8"))
        with open(csv_p, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # All attack rows
        attack_rows = [r for r in rows if r["label"] == "attack"]
        # Headline attacks exclude scanner_evasion (reported separately as scanner limitation)
        headline_attacks = [r for r in attack_rows if r["family"] != "scanner_evasion"]
        benign_rows = [r for r in rows if r["label"] == "benign" and r["family"] != "scanner_evasion"]

        std_attacks = [r for r in headline_attacks if r["set"] == "standard"]
        hard_attacks = [r for r in headline_attacks if r["set"] == "hard"]

        manifest_cases = {c["id"]: c for c in json.loads((_ROOT / "security_bench" / "manifest.json").read_text(encoding="utf-8"))}
        eval_attacks = [r for r in headline_attacks if manifest_cases[r["id"]].get("prevention") != "warn"]

        tot_detected = sum(int(r["detected"]) for r in headline_attacks)
        std_detected = sum(int(r["detected"]) for r in std_attacks)
        hard_detected = sum(int(r["detected"]) for r in hard_attacks)

        tot_prevented = sum(int(r["prevented"]) for r in eval_attacks)
        tot_b_allowed = sum(int(r["baseline_allowed"]) for r in eval_attacks)

        defended_asr = (len(eval_attacks) - tot_prevented) / len(eval_attacks) if eval_attacks else 0.0
        baseline_asr = tot_b_allowed / len(eval_attacks) if eval_attacks else 0.0

        # False alerts and false blocks
        tot_false_blocks = sum(int(r["blocked"]) for r in benign_rows)
        # Note: alert_fp is measured from non-zero attack findings on benign; with 0 false alerts in metrics, tot_false_alerts is 0
        tot_false_alerts = sum(1 for r in benign_rows if int(r["risk"]) > 0 or "ExecGuard" in r["agents_found"] or "PromptGuard" in r["agents_found"])

        # 1. Headline detected count
        self.assertEqual(metrics["overall"]["detection_rate"]["count"], tot_detected)
        self.assertEqual(metrics["overall"]["total_attacks"], len(headline_attacks))

        # 2. Standard and hard split
        self.assertEqual(metrics["overall"]["standard_attacks"], len(std_attacks))
        self.assertEqual(metrics["by_set"]["standard"]["detection_rate"]["count"], std_detected)
        self.assertEqual(metrics["overall"]["hard_attacks"], len(hard_attacks))
        self.assertEqual(metrics["by_set"]["hard"]["detection_rate"]["count"], hard_detected)

        # 3. Per-family counts
        for fam, f_data in metrics["by_family"].items():
            if fam == "scanner_evasion":
                continue
            fam_attacks = [r for r in headline_attacks if r["family"] == fam]
            fam_det = sum(int(r["detected"]) for r in fam_attacks)
            self.assertEqual(f_data["total_attacks"], len(fam_attacks))
            self.assertEqual(f_data["detection_rate"]["count"], fam_det)

        # 4. Prevented and ASR before and after
        self.assertEqual(metrics["overall"]["prevention_rate"]["count"], tot_prevented)
        self.assertAlmostEqual(metrics["overall"]["baseline_asr"], baseline_asr, places=4)
        self.assertAlmostEqual(metrics["overall"]["defended_asr"], defended_asr, places=4)

        # 5. False alerts and false blocks
        self.assertEqual(metrics["overall"]["false_alert_rate"]["count"], tot_false_alerts)
        self.assertEqual(metrics["overall"]["false_block_rate"]["count"], tot_false_blocks)

        # 6. len(known_misses) equals the number of headline attack rows with detected false
        headline_attacks_undetected = [r for r in headline_attacks if int(r["detected"]) == 0]
        self.assertEqual(len(metrics["known_misses"]), len(headline_attacks_undetected))

    def test_per_family_attack_counts_equal_manifest(self):
        """Test (a): per-family attack counts equal the manifest counts."""
        json_p = _ROOT / "data" / "security_metrics.json"
        metrics = json.loads(json_p.read_text(encoding="utf-8"))
        manifest = json.loads((_ROOT / "security_bench" / "manifest.json").read_text(encoding="utf-8"))

        manifest_family_counts: dict[str, int] = {}
        for c in manifest:
            if c["label"] == "attack":
                fam = c["family"]
                manifest_family_counts[fam] = manifest_family_counts.get(fam, 0) + 1

        for fam, f_data in metrics["by_family"].items():
            self.assertEqual(
                f_data["total_attacks"],
                manifest_family_counts.get(fam, 0),
                f"Attack count mismatch for family {fam}",
            )

    def test_per_family_asr_denominators_equal_eval_attacks(self):
        """Test (b): per-family ASR denominators equal count of attacks with prevention in block/neutralize."""
        json_p = _ROOT / "data" / "security_metrics.json"
        metrics = json.loads(json_p.read_text(encoding="utf-8"))
        manifest = json.loads((_ROOT / "security_bench" / "manifest.json").read_text(encoding="utf-8"))

        manifest_asr_counts: dict[str, int] = {}
        for c in manifest:
            if c["label"] == "attack" and c.get("prevention") in ("block", "neutralize"):
                fam = c["family"]
                manifest_asr_counts[fam] = manifest_asr_counts.get(fam, 0) + 1

        for fam, f_data in metrics["by_family"].items():
            self.assertEqual(
                f_data["asr_attacks"],
                manifest_asr_counts.get(fam, 0),
                f"ASR denominator mismatch for family {fam}",
            )

    def test_sum_over_families_equals_overall(self):
        """Test (c): sum over families equals overall numbers (excluding scanner_evasion)."""
        json_p = _ROOT / "data" / "security_metrics.json"
        metrics = json.loads(json_p.read_text(encoding="utf-8"))
        ov = metrics["overall"]

        sum_total_attacks = 0
        sum_std_attacks = 0
        sum_hard_attacks = 0
        sum_asr_attacks = 0
        sum_detected = 0
        sum_prevented = 0
        sum_baseline_prevented = 0
        sum_baseline_allowed = 0
        sum_benign = 0

        for fam, f_data in metrics["by_family"].items():
            if fam == "scanner_evasion":
                continue
            sum_total_attacks += f_data["total_attacks"]
            sum_std_attacks += f_data["standard_attacks"]
            sum_hard_attacks += f_data["hard_attacks"]
            sum_asr_attacks += f_data["asr_attacks"]
            sum_detected += f_data["detected"]
            sum_prevented += f_data["prevented"]
            sum_baseline_prevented += f_data["baseline_prevented"]
            sum_baseline_allowed += f_data["baseline_allowed"]
            sum_benign += f_data["benign_cases"]

        self.assertEqual(sum_total_attacks, ov["total_attacks"])
        self.assertEqual(sum_std_attacks, ov["standard_attacks"])
        self.assertEqual(sum_hard_attacks, ov["hard_attacks"])
        self.assertEqual(sum_asr_attacks, ov["asr_attacks"])
        self.assertEqual(sum_detected, ov["detection_rate"]["count"])
        self.assertEqual(sum_prevented, ov["prevention_rate"]["count"])
        self.assertEqual(sum_baseline_prevented, ov["baseline_prevented"])
        self.assertEqual(sum_baseline_allowed, ov["baseline_allowed"])
        self.assertEqual(sum_benign, ov["benign_cases"])

    def test_markdown_tables_match_json(self):
        """Test (d): every number in the Markdown tables (parsed) equals matching value in JSON."""
        import re
        json_p = _ROOT / "data" / "security_metrics.json"
        md_p = _ROOT / "data" / "security_metrics.md"
        metrics = json.loads(json_p.read_text(encoding="utf-8"))
        md_text = md_p.read_text(encoding="utf-8")

        # 1. Parse Results by Threat Family table
        fam_lines = []
        in_fam_table = False
        for line in md_text.splitlines():
            if line.startswith("## 3. Results by Threat Family"):
                in_fam_table = True
                continue
            if in_fam_table:
                if line.startswith("## ") and not line.startswith("## 3."):
                    break
                if line.strip().startswith("| `"):
                    fam_lines.append(line.strip())

        self.assertEqual(len(fam_lines), len(metrics["by_family"]))

        for line in fam_lines:
            parts = [p.strip() for p in line.split("|")[1:-1]]
            fam = parts[0].strip("`")
            self.assertIn(fam, metrics["by_family"])
            f_data = metrics["by_family"][fam]

            m = re.match(r"^(\d+)\s*\(\s*(\d+)\s*/\s*(\d+)\s*\)$", parts[1])
            self.assertIsNotNone(m, f"Could not parse attack counts: {parts[1]}")
            tot, std, hard = int(m.group(1)), int(m.group(2)), int(m.group(3))
            self.assertEqual(tot, f_data["total_attacks"])
            self.assertEqual(std, f_data["standard_attacks"])
            self.assertEqual(hard, f_data["hard_attacks"])

            asr_denom = int(parts[2])
            self.assertEqual(asr_denom, f_data["asr_attacks"])

            det = int(parts[3])
            self.assertEqual(det, f_data["detected"])

            prev = int(parts[4])
            self.assertEqual(prev, f_data["prevented"])

            b_prev = int(parts[5])
            self.assertEqual(b_prev, f_data["baseline_prevented"])

            b_asr = float(parts[6].rstrip("%"))
            self.assertEqual(b_asr, round(f_data["baseline_asr"] * 100.0, 1))

            d_asr = float(parts[7].replace("*", "").rstrip("%"))
            self.assertEqual(d_asr, round(f_data["defended_asr"] * 100.0, 1))

        # 2. Parse ASR Before vs After table
        asr_lines = []
        in_asr_table = False
        for line in md_text.splitlines():
            if line.startswith("## 4. Attack Success Rate"):
                in_asr_table = True
                continue
            if in_asr_table:
                if line.startswith("## ") and not line.startswith("## 4."):
                    break
                if line.strip().startswith("| `"):
                    asr_lines.append(line.strip())

        self.assertEqual(len(asr_lines), len(metrics["by_family"]))
        for line in asr_lines:
            parts = [p.strip() for p in line.split("|")[1:-1]]
            fam = parts[0].strip("`")
            f_data = metrics["by_family"][fam]
            self.assertEqual(int(parts[1]), f_data["asr_attacks"])
            self.assertEqual(float(parts[2].rstrip("%")), round(f_data["baseline_asr"] * 100.0, 1))
            self.assertEqual(float(parts[3].rstrip("%")), round(f_data["defended_asr"] * 100.0, 1))

        # 3. Parse Performance by Security Agent table
        ag_lines = []
        in_ag_table = False
        for line in md_text.splitlines():
            if line.startswith("## 5. Performance by Security Agent"):
                in_ag_table = True
                continue
            if in_ag_table:
                if line.startswith("## ") and not line.startswith("## 5."):
                    break
                if line.strip().startswith("| `"):
                    ag_lines.append(line.strip())

        self.assertEqual(len(ag_lines), len(metrics["by_agent"]))
        for line in ag_lines:
            parts = [p.strip() for p in line.split("|")[1:-1]]
            ag = parts[0].strip("`")
            a_data = metrics["by_agent"][ag]
            self.assertEqual(int(parts[1]), a_data["expected_cases"])
            m = re.search(r"\((\d+)/(\d+)\)", parts[2])
            self.assertIsNotNone(m)
            self.assertEqual(int(m.group(1)), a_data["detected_cases"])
            self.assertEqual(int(m.group(2)), a_data["expected_cases"])
            self.assertEqual(int(parts[4]), a_data["false_positives"])
            self.assertEqual(float(parts[5].rstrip("%")), round(a_data["precision"] * 100.0, 1))

        # 4. Parse Execution Latency by kind table
        lat_lines = []
        in_lat_table = False
        for line in md_text.splitlines():
            if line.startswith("## 7. Execution Latency"):
                in_lat_table = True
                continue
            if in_lat_table:
                if line.startswith("## ") and not line.startswith("## 7."):
                    break
                if line.strip().startswith("| `"):
                    lat_lines.append(line.strip())

        by_kind = metrics["latency"]["by_kind"]
        self.assertEqual(len(lat_lines), len(by_kind))
        for line in lat_lines:
            parts = [p.strip() for p in line.split("|")[1:-1]]
            kind = parts[0].strip("`")
            k_data = by_kind[kind]
            self.assertEqual(float(parts[1]), round(k_data["mean"], 2))
            self.assertEqual(float(parts[2]), round(k_data["median"], 2))
            self.assertEqual(float(parts[3]), round(k_data["p95"], 2))
            self.assertEqual(float(parts[4]), round(k_data["max"], 2))

    def test_json_and_csv_agree_per_family(self):
        """Test (e): the JSON and the CSV agree for every per-family value."""
        import csv
        json_p = _ROOT / "data" / "security_metrics.json"
        csv_p = _ROOT / "data" / "security_cases.csv"
        metrics = json.loads(json_p.read_text(encoding="utf-8"))

        with open(csv_p, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        manifest_map = {c["id"]: c for c in json.loads((_ROOT / "security_bench" / "manifest.json").read_text(encoding="utf-8"))}

        for fam, f_data in metrics["by_family"].items():
            fam_attack_rows = [r for r in rows if r["family"] == fam and r["label"] == "attack"]
            fam_std_rows = [r for r in fam_attack_rows if r["set"] == "standard"]
            fam_hard_rows = [r for r in fam_attack_rows if r["set"] == "hard"]
            fam_eval_rows = [r for r in fam_attack_rows if manifest_map[r["id"]].get("prevention") in ("block", "neutralize")]
            fam_benign_rows = [r for r in rows if r["family"] == fam and r["label"] == "benign"]

            # Counts
            self.assertEqual(f_data["total_attacks"], len(fam_attack_rows), f"CSV mismatch total_attacks for {fam}")
            self.assertEqual(f_data["standard_attacks"], len(fam_std_rows), f"CSV mismatch std_attacks for {fam}")
            self.assertEqual(f_data["hard_attacks"], len(fam_hard_rows), f"CSV mismatch hard_attacks for {fam}")
            self.assertEqual(f_data["asr_attacks"], len(fam_eval_rows), f"CSV mismatch asr_attacks for {fam}")
            self.assertEqual(f_data["benign_cases"], len(fam_benign_rows), f"CSV mismatch benign_cases for {fam}")

            # Detected & Prevented
            csv_detected = sum(int(r["detected"]) for r in fam_attack_rows)
            csv_prevented = sum(int(r["prevented"]) for r in fam_eval_rows)
            self.assertEqual(f_data["detected"], csv_detected, f"CSV mismatch detected for {fam}")
            self.assertEqual(f_data["prevented"], csv_prevented, f"CSV mismatch prevented for {fam}")

            # Baseline prevented & allowed
            csv_b_allowed = sum(int(r["baseline_allowed"]) for r in fam_eval_rows)
            csv_b_prev = len(fam_eval_rows) - csv_b_allowed
            self.assertEqual(f_data["baseline_allowed"], csv_b_allowed, f"CSV mismatch baseline_allowed for {fam}")
            self.assertEqual(f_data["baseline_prevented"], csv_b_prev, f"CSV mismatch baseline_prevented for {fam}")

            # ASR
            expected_b_asr = round(csv_b_allowed / len(fam_eval_rows), 4) if fam_eval_rows else 0.0
            expected_d_asr = round((len(fam_eval_rows) - csv_prevented) / len(fam_eval_rows), 4) if fam_eval_rows else 0.0
            self.assertAlmostEqual(f_data["baseline_asr"], expected_b_asr, places=4)
            self.assertAlmostEqual(f_data["defended_asr"], expected_d_asr, places=4)

    def test_known_misses_and_detected_not_prevented_identity(self):
        """Task 2: len(known_misses) + len(detected_not_prevented) == unprevented_block_neut + undetected_warn."""
        json_p = _ROOT / "data" / "security_metrics.json"
        metrics = json.loads(json_p.read_text(encoding="utf-8"))
        manifest = json.loads((_ROOT / "security_bench" / "manifest.json").read_text(encoding="utf-8"))

        known_misses = metrics["known_misses"]
        detected_not_prevented = metrics["detected_not_prevented"]
        lhs = len(known_misses) + len(detected_not_prevented)

        manifest_cases = {c["id"]: c for c in manifest}
        headline_attacks = [c for c in metrics["cases"] if c["label"] == "attack" and c["family"] != "scanner_evasion"]

        unprevented_block_neut = sum(
            1 for c in headline_attacks
            if manifest_cases[c["id"]].get("prevention") in ("block", "neutralize") and not c["prevented"]
        )
        undetected_warn = sum(
            1 for c in headline_attacks
            if manifest_cases[c["id"]].get("prevention") == "warn" and not c["detected"]
        )
        rhs = unprevented_block_neut + undetected_warn

        self.assertEqual(lhs, rhs, f"Identity failure: {lhs} != {rhs}")
        # Disjoint check
        miss_ids = {m["id"] for m in known_misses}
        dnp_ids = {p["id"] for p in detected_not_prevented}
        self.assertTrue(miss_ids.isdisjoint(dnp_ids), "known_misses and detected_not_prevented must be disjoint")

    def test_patch_baseline_execvp_allowed(self):
        """Task 3: Small patch adding execvp(...) is allowed by baseline."""
        orig_code = (
            "#include <unistd.h>\n"
            "int main() {\n"
            "    return 0;\n"
            "}\n"
        )
        fixed_code = (
            "#include <unistd.h>\n"
            "int main() {\n"
            "    char* args[] = {\"/bin/echo\", \"hi\", NULL};\n"
            "    execvp(args[0], args);\n"
            "    return 0;\n"
            "}\n"
        )
        case = {
            "kind": "PATCH",
            "purpose": "patch",
            "payload": fixed_code,
            "meta": {"original": orig_code},
        }
        allowed, reason = baseline_eval(case)
        self.assertTrue(allowed, f"execvp patch was unexpectedly blocked: {reason}")
        self.assertEqual(reason, "no defence")

    def test_patch_baseline_excessive_lines_blocked(self):
        """Task 3: Patch that changes more than the allowed line count is blocked by baseline."""
        orig_code = "\n".join([f"int x{i} = {i};" for i in range(10)]) + "\nint main() { return 0; }\n"
        new_lines = [f"int y{i} = {i * 2};" for i in range(25)] + ["int main() { return 0; }"]
        fixed_code = "\n".join(new_lines) + "\n"
        case = {
            "kind": "PATCH",
            "purpose": "patch",
            "payload": fixed_code,
            "meta": {"original": orig_code},
        }
        allowed, reason = baseline_eval(case)
        self.assertFalse(allowed, "Excessive line change patch should be blocked by baseline")
        self.assertEqual(reason, "validate_ai_code:line-count")

    def test_baseline_rules(self):
        """Validates that baseline_eval / baseline_allows enforces exact original project baseline rules."""
        # 1. popen(...) source is blocked by the baseline
        popen_case = {
            "kind": "USER_SOURCE",
            "purpose": "run",
            "payload": '#include <cstdio>\nint main() { FILE* f = popen("id", "r"); return 0; }',
        }
        allowed, reason = baseline_eval(popen_case)
        self.assertFalse(allowed)
        self.assertEqual(reason, "sanitizer:popen")
        self.assertFalse(baseline_allows(popen_case))

        # 2. #include <sys/socket.h> source is blocked by the baseline
        socket_case = {
            "kind": "USER_SOURCE",
            "purpose": "run",
            "payload": '#include <sys/socket.h>\nint main() { return 0; }',
        }
        allowed, reason = baseline_eval(socket_case)
        self.assertFalse(allowed)
        self.assertEqual(reason, "sanitizer:sys-include")
        self.assertFalse(baseline_allows(socket_case))

        # 3. #include "/dev/zero" is allowed by the baseline (sanitizer cannot see this)
        zero_case = {
            "kind": "USER_SOURCE",
            "purpose": "run",
            "payload": '#include "/dev/zero"\nint main() { return 0; }',
        }
        allowed, reason = baseline_eval(zero_case)
        self.assertTrue(allowed)
        self.assertEqual(reason, "no defence")
        self.assertTrue(baseline_allows(zero_case))

        # 4. macro bomb is allowed by the baseline
        bomb_case = {
            "kind": "USER_SOURCE",
            "purpose": "run",
            "payload": '#define A B B\n#define B C C\n#define C D D\nint main() { return 0; }',
        }
        allowed, reason = baseline_eval(bomb_case)
        self.assertTrue(allowed)
        self.assertEqual(reason, "no defence")
        self.assertTrue(baseline_allows(bomb_case))

        # 5. int big[1000000000]; is allowed by the baseline
        big_case = {
            "kind": "USER_SOURCE",
            "purpose": "run",
            "payload": 'int big[1000000000];\nint main() { return 0; }',
        }
        allowed, reason = baseline_eval(big_case)
        self.assertTrue(allowed)
        self.assertEqual(reason, "no defence")
        self.assertTrue(baseline_allows(big_case))

        # 6. execvp(...) is allowed by the baseline (compiler_runner only checks regex 'exec\\s*\\(')
        execvp_case = {
            "kind": "USER_SOURCE",
            "purpose": "run",
            "payload": '#include <unistd.h>\nint main() { char* a[] = {"/bin/ls", NULL}; execvp(a[0], a); return 0; }',
        }
        allowed, reason = baseline_eval(execvp_case)
        self.assertTrue(allowed)
        self.assertEqual(reason, "no defence")
        self.assertTrue(baseline_allows(execvp_case))

        # 7. Foreign-Origin HTTP case is blocked by the baseline
        foreign_origin_case = {
            "kind": "HTTP_REQUEST",
            "purpose": "request",
            "meta": {
                "method": "POST",
                "origin": "http://evil.com",
                "headers": {"content-type": "application/json"},
            },
        }
        allowed, reason = baseline_eval(foreign_origin_case)
        self.assertFalse(allowed)
        self.assertEqual(reason, "http:foreign-origin")
        self.assertFalse(baseline_allows(foreign_origin_case))

        # 8. Missing-token HTTP case is allowed by the baseline (original server had no auth token)
        missing_token_case = {
            "kind": "HTTP_REQUEST",
            "purpose": "request",
            "meta": {
                "method": "POST",
                "origin": "http://localhost:8000",
                "headers": {"content-type": "application/json"},
            },
        }
        allowed, reason = baseline_eval(missing_token_case)
        self.assertTrue(allowed)
        self.assertEqual(reason, "no defence")
        self.assertTrue(baseline_allows(missing_token_case))


if __name__ == "__main__":
    unittest.main()
