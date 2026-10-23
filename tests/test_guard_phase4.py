"""
test_guard_phase4.py
--------------------
Phase 4 tests for the compiler error explainer agentic-AI security layer.
Tests:
1. secrets.py: pattern scanning, masking, env_secret_values, safe_text/html_text masking.
2. SecretsGuard:
   - sensitive_include: blocking private includes, path traversal, absolute paths, escaping symlinks.
   - sensitive_include: non-blocking of benign headers (<iostream>, local helper.h, sub/util.h).
   - sensitive_include: ALLOW_EXTERNAL_INCLUDES=1 toggle behaviour.
   - sensitive_include: unknown source_dir behaviour.
   - hardcoded_secret, tool_secret_value, and personal_data_access categories.
3. Enforcement: run_cpp_compiler blocks sensitive include before safe_run.
4. pathsafe: is_safe_to_read, set_allowed_roots, get_source_context gating.
5. IntegrityGuard dataset: directive injection, bad category, bad message, secrets, rate limit, store size.
6. dataset_logger: append-only quarantine to pending_training.jsonl, no training_data.json writes, lock & corrupt line resilience.
7. Model integrity: manifest verification, tampering detection, data_dir restriction, ErrorClassifier refusing tampered model without implicit retraining, and tools/sign_model.py.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

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
    scan_secrets,
    mask_secrets,
    is_sensitive_name,
    env_secret_values,
    model_status,
)
from guard.base import GuardContext
from guard.output_safe import safe_text, html_text
from guard.pathsafe import set_allowed_roots, get_allowed_roots, is_safe_to_read
from guard.secrets_guard import SecretsGuard
from guard.integrity_guard import IntegrityGuard
from error_parser import get_source_context
import compiler_runner
import dataset_logger
from error_classifier import ErrorClassifier
from tools.sign_model import sign_model


class TestSecretsPatternsAndMasking(unittest.TestCase):
    def setUp(self):
        self.orig_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)

    def test_scan_secrets_all_patterns(self):
        test_cases = [
            ("AIzaSyD-9x9x9x9x9x9x9x9x9x9x123", "google_api_key", "High"),
            ("gsk_1234567890abcdef1234567890ab", "groq_api_key", "High"),
            ("sk-proj-1234567890abcdef1234567890", "openai_api_key", "High"),
            ("ghp_123456789012345678901234567890", "github_token", "High"),
            ("github_pat_11AAAAAAA0123456789012_abcdef123456", "github_pat", "High"),
            ("AKIAIOSFODNN7EXAMPLE", "aws_access_key", "High"),
            ("xoxb-1234567890-123456789012", "slack_token", "High"),
            ("-----BEGIN RSA PRIVATE KEY-----", "private_key", "High"),
            ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "jwt_token", "High"),
            ('api_key = "secret_value_12345"', "credential_assignment", "Medium"),
            ('token: "topsecretpassword_abc"', "credential_assignment", "Medium"),
        ]

        for text, expected_kind, expected_sev in test_cases:
            hits = scan_secrets(text)
            self.assertTrue(len(hits) >= 1, f"Pattern failed to match: {text}")
            hit = hits[0]
            self.assertEqual(hit.kind, expected_kind)
            self.assertEqual(hit.severity, expected_sev)

    def test_mask_secrets_removes_tokens(self):
        raw = "Error with key AIzaSyD-9x9x9x9x9x9x9x9x9x9x123 in request"
        masked = mask_secrets(raw)
        self.assertIn("[REDACTED:google_api_key]", masked)
        self.assertNotIn("AIzaSyD-9x9x9x9x9x9x9x9x9x9x123", masked)

        # None and non-string inputs
        self.assertEqual(mask_secrets(None), "")
        self.assertEqual(mask_secrets(42), "42")

    def test_env_secret_values_and_output_safe(self):
        os.environ["GEMINI_API_KEY"] = "gemini_super_secret_env_val_999"
        vals = env_secret_values(min_len=8)
        self.assertIn("gemini_super_secret_env_val_999", vals)

        leaked_text = "Compiler output leaked: gemini_super_secret_env_val_999"
        masked = mask_secrets(leaked_text)
        self.assertIn("[REDACTED:tool_secret]", masked)
        self.assertNotIn("gemini_super_secret_env_val_999", masked)

        # OutputSafe integration
        s_out = safe_text(leaked_text)
        self.assertIn("[REDACTED:tool_secret]", s_out)
        self.assertNotIn("gemini_super_secret_env_val_999", s_out)

        h_out = html_text(leaked_text)
        self.assertIn("[REDACTED:tool_secret]", h_out)
        self.assertNotIn("gemini_super_secret_env_val_999", h_out)

    def test_is_sensitive_name(self):
        self.assertTrue(is_sensitive_name("HF_TOKEN"))
        self.assertTrue(is_sensitive_name("AWS_ACCESS_KEY_ID"))
        self.assertTrue(is_sensitive_name("DB_PASSWORD"))
        self.assertTrue(is_sensitive_name("USER_CREDENTIAL"))
        self.assertFalse(is_sensitive_name("PATH"))
        self.assertFalse(is_sensitive_name("TEMP"))


class TestSecretsGuardIncludes(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.sub_dir = os.path.join(self.temp_dir, "sub")
        os.makedirs(self.sub_dir, exist_ok=True)
        self.guard = SecretsGuard()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        if "ALLOW_EXTERNAL_INCLUDES" in os.environ:
            del os.environ["ALLOW_EXTERNAL_INCLUDES"]

    def _review(self, code: str, source_dir: str | None = None, purpose: str = "compile"):
        ctx = GuardContext(
            kind=InputKind.USER_SOURCE,
            payload=code,
            purpose=purpose,
            meta={"source_dir": source_dir} if source_dir is not None else {},
        )
        return self.guard.analyze(ctx)

    def test_blocking_sensitive_includes(self):
        # 1. ../.env
        f1 = self._review('#include "../.env"', source_dir=self.temp_dir)
        self.assertTrue(any(f.category == "sensitive_include" and "compile" in f.blocks_on for f in f1))

        # 2. .env inside source_dir
        f2 = self._review('#include ".env"', source_dir=self.temp_dir)
        self.assertTrue(any(f.category == "sensitive_include" and "compile" in f.blocks_on for f in f2))

        # 3. /etc/passwd
        f3 = self._review('#include "/etc/passwd"', source_dir=self.temp_dir)
        self.assertTrue(any(f.category == "sensitive_include" and "compile" in f.blocks_on for f in f3))

        # 4. C:\Users\x\.ssh\id_rsa
        f4 = self._review('#include "C:\\\\Users\\\\x\\\\.ssh\\\\id_rsa"', source_dir=self.temp_dir)
        self.assertTrue(any(f.category == "sensitive_include" and "compile" in f.blocks_on for f in f4))

        # 5. </etc/shadow>
        f5 = self._review('#include </etc/shadow>', source_dir=self.temp_dir)
        self.assertTrue(any(f.category == "sensitive_include" and "compile" in f.blocks_on for f in f5))

        # 6. Escape source_dir via ../../x.txt
        f6 = self._review('#include "../../outside.h"', source_dir=self.sub_dir)
        self.assertTrue(any(f.category == "sensitive_include" and "compile" in f.blocks_on for f in f6))

        # 7. Symlink inside source_dir pointing outside
        outside_file = os.path.join(self.temp_dir, "outside_target.h")
        with open(outside_file, "w") as f:
            f.write("int x = 1;\n")
        symlink_path = os.path.join(self.sub_dir, "link_to_outside.h")
        try:
            os.symlink(outside_file, symlink_path)
            f7 = self._review('#include "link_to_outside.h"', source_dir=self.sub_dir)
            self.assertTrue(any(f.category == "sensitive_include" and "compile" in f.blocks_on for f in f7))
        except (OSError, NotImplementedError):
            pass  # Symlinks not permitted in this environment, skip gracefully

    def test_benign_includes_pass(self):
        # helper.h in same folder
        f1 = self._review('#include "helper.h"', source_dir=self.temp_dir)
        self.assertEqual(len(f1), 0)

        # <iostream>
        f2 = self._review('#include <iostream>', source_dir=self.temp_dir)
        self.assertEqual(len(f2), 0)

        # sub/util.h inside source_dir
        f3 = self._review('#include "sub/util.h"', source_dir=self.temp_dir)
        self.assertEqual(len(f3), 0)

    def test_allow_external_includes_toggle(self):
        os.environ["ALLOW_EXTERNAL_INCLUDES"] = "1"
        # Outside non-sensitive include is downgraded to Low/warn
        f1 = self._review('#include "../../outside_lib.h"', source_dir=self.sub_dir)
        sensitive_findings = [f for f in f1 if f.category == "sensitive_include"]
        self.assertEqual(len(sensitive_findings), 1)
        self.assertEqual(sensitive_findings[0].severity, "Low")
        self.assertEqual(sensitive_findings[0].action, "warn")
        self.assertEqual(len(sensitive_findings[0].blocks_on), 0)

        # .env is sensitive, so it MUST remain blocked even with toggle
        f2 = self._review('#include "../.env"', source_dir=self.sub_dir)
        env_findings = [f for f in f2 if f.category == "sensitive_include"]
        self.assertEqual(len(env_findings), 1)
        self.assertEqual(env_findings[0].severity, "High")
        self.assertEqual(env_findings[0].action, "block")
        self.assertIn("compile", env_findings[0].blocks_on)

    def test_unknown_source_dir_behaviour(self):
        # source_dir unknown: directory parts or .. block
        f_traversal = self._review('#include "../x.h"', source_dir=None)
        self.assertTrue(any(f.category == "sensitive_include" and "compile" in f.blocks_on for f in f_traversal))

        # plain filename passes
        f_plain = self._review('#include "x.h"', source_dir=None)
        self.assertEqual(len(f_plain), 0)


class TestSecretsGuardOtherCategories(unittest.TestCase):
    def setUp(self):
        self.guard = SecretsGuard()

    def test_hardcoded_secrets_and_personal_data(self):
        # High severity secret blocks ai_send
        ctx_secret = GuardContext(
            kind=InputKind.USER_SOURCE,
            payload='const char* k = "AIzaSyD-9x9x9x9x9x9x9x9x9x9x123";',
            purpose="ai_send",
        )
        f_sec = self.guard.analyze(ctx_secret)
        hardcoded = [f for f in f_sec if f.category == "hardcoded_secret"]
        self.assertTrue(len(hardcoded) >= 1)
        self.assertEqual(hardcoded[0].severity, "High")
        self.assertIn("ai_send", hardcoded[0].blocks_on)
        self.assertIn("[REDACTED:google_api_key]", hardcoded[0].evidence)
        self.assertNotIn("AIzaSyD", hardcoded[0].evidence)

        # Personal data access
        ctx_user = GuardContext(
            kind=InputKind.USER_SOURCE,
            payload='const char* u = getenv("USERNAME");',
            purpose="compile",
        )
        f_user = self.guard.analyze(ctx_user)
        pers = [f for f in f_user if f.category == "personal_data_access"]
        self.assertEqual(len(pers), 1)
        self.assertEqual(pers[0].severity, "Medium")
        self.assertEqual(pers[0].action, "warn")
        self.assertEqual(len(pers[0].blocks_on), 0)

        # Benign program
        ctx_benign = GuardContext(
            kind=InputKind.USER_SOURCE,
            payload='int main() { char password[64] = {0}; return 0; }',
            purpose="compile",
        )
        f_benign = self.guard.analyze(ctx_benign)
        self.assertEqual(len(f_benign), 0)


class TestCompilerEnforcement(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.src_file = os.path.join(self.temp_dir, "bad_include.cpp")
        with open(self.src_file, "w") as f:
            f.write('#include "../.env"\nint main() { return 0; }\n')

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_run_cpp_compiler_blocks_before_safe_run(self):
        with patch("guard.safe_run.safe_run") as mock_safe_run:
            mock_safe_run.side_effect = AssertionError("safe_run should NOT be called!")
            res = compiler_runner.run_cpp_compiler(self.src_file)
            mock_safe_run.assert_not_called()

            self.assertEqual(len(res), 1)
            self.assertIn("SecretsGuard", res[0]["message"])
            self.assertIn("sensitive_include", res[0]["message"])


class TestPathsafeAndSourceContext(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.src_file = os.path.join(self.temp_dir, "test.cpp")
        with open(self.src_file, "w") as f:
            f.write("int main() {\n  return 0;\n}\n")
        self.env_file = os.path.join(self.temp_dir, ".env")
        with open(self.env_file, "w") as f:
            f.write("SECRET=123\n")
        self.outside_dir = tempfile.mkdtemp()
        self.outside_file = os.path.join(self.outside_dir, "outside.cpp")
        with open(self.outside_file, "w") as f:
            f.write("int x = 42;\n")

        self.orig_roots = get_allowed_roots()
        set_allowed_roots([self.temp_dir])

    def tearDown(self):
        set_allowed_roots(self.orig_roots)
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        shutil.rmtree(self.outside_dir, ignore_errors=True)

    def test_is_safe_to_read(self):
        self.assertTrue(is_safe_to_read(self.src_file))
        self.assertFalse(is_safe_to_read(self.env_file))
        self.assertFalse(is_safe_to_read(self.outside_file))

    def test_get_source_context(self):
        lines = get_source_context(self.src_file, 1, context_lines=2)
        self.assertIsNotNone(lines)
        self.assertTrue(len(lines) > 0)

        # .env inside allowed root returns None
        self.assertIsNone(get_source_context(self.env_file, 1))

        # outside allowed root returns None
        self.assertIsNone(get_source_context(self.outside_file, 1))


class TestIntegrityGuardDataset(unittest.TestCase):
    def setUp(self):
        self.guard = IntegrityGuard()
        self.temp_dir = tempfile.mkdtemp()
        self.orig_pending = os.environ.get("GUARD_PENDING_PATH")
        self.pending_file = os.path.join(self.temp_dir, "test_pending.jsonl")
        os.environ["GUARD_PENDING_PATH"] = self.pending_file

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        if self.orig_pending:
            os.environ["GUARD_PENDING_PATH"] = self.orig_pending
        elif "GUARD_PENDING_PATH" in os.environ:
            del os.environ["GUARD_PENDING_PATH"]

    def _review(self, msg: str, category: str = "syntax_error", source: str = "", run_count: int = 0):
        ctx = GuardContext(
            kind=InputKind.DATASET_ENTRY,
            payload=msg,
            purpose="dataset",
            meta={
                "category": category,
                "confidence": 1.0,
                "source_text": source,
                "run_count": run_count,
            },
        )
        return self.guard.analyze(ctx)

    def test_dataset_rules(self):
        # 1. Directive message injection
        src = '#error undefined reference to "main"\nint x = 1;'
        f1 = self._review('undefined reference to "main"', source=src)
        self.assertTrue(any(f.category == "dataset_directive_message" for f in f1))

        # 2. Bad category
        f2 = self._review("expected ';'", category="unauthorized_cat")
        self.assertTrue(any(f.category == "dataset_bad_category" for f in f2))

        # 3. Bad message (400 chars)
        f3 = self._review("x" * 400)
        self.assertTrue(any(f.category == "dataset_bad_message" for f in f3))

        # 4. Bad message with path
        f4 = self._review("error in /home/user/code.cpp at line 5")
        self.assertTrue(any(f.category == "dataset_bad_message" for f in f4))

        # 5. Secret in message
        f5 = self._review("API failure with AIzaSyD-9x9x9x9x9x9x9x9x9x9x123")
        self.assertTrue(any(f.category == "dataset_secret" for f in f5))

        # 6. Rate limit
        f6 = self._review("expected ';'", run_count=51)
        self.assertTrue(any(f.category == "dataset_rate_limit" for f in f6))

        # 7. Store too large (> 5 MB)
        with open(self.pending_file, "wb") as f:
            f.write(b"x" * (6 * 1024 * 1024))
        f7 = self._review("expected ';'")
        self.assertTrue(any(f.category == "dataset_store_too_large" for f in f7))

        # Normal entry passes
        os.remove(self.pending_file)
        f_ok = self._review("expected ';'")
        self.assertEqual(len(f_ok), 0)


class TestDatasetLoggerQuarantine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.pending_file = os.path.join(self.temp_dir, "pending.jsonl")
        self.orig_pending = os.environ.get("GUARD_PENDING_PATH")
        os.environ["GUARD_PENDING_PATH"] = self.pending_file
        dataset_logger.reset_run_count()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        if self.orig_pending:
            os.environ["GUARD_PENDING_PATH"] = self.orig_pending
        elif "GUARD_PENDING_PATH" in os.environ:
            del os.environ["GUARD_PENDING_PATH"]

    def test_log_example_quarantine_and_resilience(self):
        class DummyError:
            message = "expected ';' before '}' token"
            category = "syntax_error"
            confidence = 0.99
            explanation = "Missing semicolon"
            suggestion = "Add ;"

        dataset_logger.log_example(DummyError())
        self.assertTrue(os.path.exists(self.pending_file))
        with open(self.pending_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        rec = json.loads(lines[0])
        self.assertEqual(rec["category"], "syntax_error")
        self.assertEqual(rec["status"], "pending")

        # Corrupt file line and ensure new writes succeed
        with open(self.pending_file, "a", encoding="utf-8") as f:
            f.write("{CORRUPTED_JSON_LINE\n")

        dataset_logger.log_example(DummyError())
        with open(self.pending_file, "r", encoding="utf-8") as f:
            new_lines = f.readlines()
        self.assertEqual(len(new_lines), 3)

        # Blocked entry writes nothing to pending file
        class BadError:
            message = "expected ';'"
            category = "malicious_injected_cat"
            confidence = 1.0

        dataset_logger.log_example(BadError())
        with open(self.pending_file, "r", encoding="utf-8") as f:
            post_block_lines = f.readlines()
        self.assertEqual(len(post_block_lines), 3)


class TestModelIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.orig_data_dir = os.environ.get("GUARD_DATA_DIR")
        os.environ["GUARD_DATA_DIR"] = self.temp_dir
        self.model_path = os.path.join(self.temp_dir, "error_classifier.joblib")
        with open(self.model_path, "wb") as f:
            f.write(b"FAKE_MODEL_BYTES_V1")
        self.manifest_path = os.path.join(self.temp_dir, "model_manifest.json")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        if self.orig_data_dir:
            os.environ["GUARD_DATA_DIR"] = self.orig_data_dir
        elif "GUARD_DATA_DIR" in os.environ:
            del os.environ["GUARD_DATA_DIR"]

    def test_model_signing_and_verification(self):
        sign_model(self.model_path, self.manifest_path)
        status = model_status(self.model_path)
        self.assertTrue(status["ok"])
        self.assertEqual(status["reason"], "valid")

        # Tampering: flip 1 byte
        with open(self.model_path, "wb") as f:
            f.write(b"FAKE_MODEL_BYTES_V2_TAMPERED")

        status_tampered = model_status(self.model_path)
        self.assertFalse(status_tampered["ok"])
        self.assertEqual(status_tampered["reason"], "model_hash_mismatch")

        # Missing manifest
        os.remove(self.manifest_path)
        status_missing = model_status(self.model_path)
        self.assertFalse(status_missing["ok"])
        self.assertEqual(status_missing["reason"], "model_manifest_missing")

        # Outside data directory
        outside_dir = tempfile.mkdtemp()
        try:
            outside_model = os.path.join(outside_dir, "model.joblib")
            with open(outside_model, "wb") as f:
                f.write(b"OUTSIDE_BYTES")
            status_outside = model_status(outside_model)
            self.assertFalse(status_outside["ok"])
            self.assertEqual(status_outside["reason"], "model_outside_data_dir")
        finally:
            shutil.rmtree(outside_dir, ignore_errors=True)

    def test_classifier_refuses_tampered_model(self):
        sign_model(self.model_path, self.manifest_path)
        # Tamper model
        with open(self.model_path, "wb") as f:
            f.write(b"CORRUPTED_BYTES")

        clf = ErrorClassifier(model_file=self.model_path)
        loaded = clf.load()
        self.assertFalse(loaded)
        self.assertIsNotNone(clf.last_load_error)
        self.assertIn("model_hash_mismatch", clf.last_load_error)

        with patch.object(clf, "train_and_save") as mock_train:
            mock_train.side_effect = AssertionError("train_and_save must not be called!")
            pred, conf = clf.predict("random unknown compiler message with no rule matches")
            self.assertIsNone(pred)
            self.assertEqual(conf, 0.0)
            mock_train.assert_not_called()


if __name__ == "__main__":
    unittest.main()
