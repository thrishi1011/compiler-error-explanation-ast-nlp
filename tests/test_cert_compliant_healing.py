import pytest
import sys
from pathlib import Path

_src_path = str(Path(__file__).resolve().parent.parent / "src")
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

from security_healer import Fix, CATEGORY_STANDARDS
from ai_explainer import build_batch_prompt, EXPLAIN_SYSTEM_PROMPT
from error_explainer import SECURITY_RULES


def test_fix_has_cwe_and_cert():
    fix = Fix(
        finding_category="unsafe_string_function",
        line=10,
        safety_class="auto",
        description="Replace gets with fgets",
        before="gets(buf);",
        after="fgets(buf, sizeof(buf), stdin);",
    )
    assert fix.cwe_id == "CWE-676"
    assert fix.cert_rule == "STR31-C"

    d = fix.to_dict()
    assert d["cwe_id"] == "CWE-676"
    assert d["cert_rule"] == "STR31-C"


def test_fix_categories_standard_coverage():
    test_cats = [
        ("buffer_overflow", "CWE-120", "ARR30-C"),
        ("double_free", "CWE-415", "MEM51-CPP"),
        ("command_injection", "CWE-78", "ENV33-C"),
        ("null_pointer_dereference", "CWE-476", "EXP34-C"),
        ("uninitialized_variable", "CWE-457", "EXP33-C"),
    ]
    for cat, expected_cwe, expected_cert in test_cats:
        fix = Fix(
            finding_category=cat,
            line=5,
            safety_class="auto",
            description="test fix",
            before="before();",
            after="after();",
        )
        assert fix.cwe_id == expected_cwe, f"Failed CWE for {cat}"
        assert fix.cert_rule == expected_cert, f"Failed CERT for {cat}"


def test_ai_explainer_prompt_enhancements():
    assert "SEI CERT C++" in EXPLAIN_SYSTEM_PROMPT
    assert "ARR30-C" in EXPLAIN_SYSTEM_PROMPT or "STR31-C" in EXPLAIN_SYSTEM_PROMPT

    mock_error = {
        "line": 15,
        "category": "buffer_overflow",
        "message": "warning: buffer overflow detected",
        "cwe_id": "CWE-120",
        "cert_rule": "ARR30-C",
    }
    prompt, indices = build_batch_prompt([mock_error], "char b[5]; gets(b);")
    assert "CWE-120" in prompt
    assert "ARR30-C" in prompt


def test_error_explainer_security_rules_standards():
    found_cwe = False
    found_cert = False
    for rule in SECURITY_RULES:
        if rule.get("cwe"):
            found_cwe = True
        if rule.get("cert"):
            found_cert = True
    assert found_cwe
    assert found_cert
