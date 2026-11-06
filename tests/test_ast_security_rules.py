import pytest
import os
import sys
import tempfile
from pathlib import Path

_src_path = str(Path(__file__).resolve().parent.parent / "src")
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

import ast_security_rules
import security_analyzer


def test_ast_macro_alias_detection():
    # Regular regex looks for 'gets('; here gets is hidden behind #define G gets
    code = """#include <cstdio>
#define G gets

int main() {
    char buffer[32];
    G(buffer);
    return 0;
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False) as f:
        f.write(code)
        path = f.name

    try:
        findings = ast_security_rules.analyze_ast(path, code)
        macro_findings = [f for f in findings if "G" in f.description or f.vulnerability_type == "Buffer Overflow"]
        assert len(macro_findings) > 0
        assert macro_findings[0].cwe_id == "CWE-120"
        assert macro_findings[0].cert_rule == "ARR30-C"
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_ast_array_bounds_detection():
    code = """#include <iostream>

int main() {
    int scores[5];
    scores[0] = 10;
    scores[4] = 20;
    scores[10] = 99; // Out of bounds
    return 0;
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False) as f:
        f.write(code)
        path = f.name

    try:
        findings = ast_security_rules.analyze_ast(path, code)
        oob = [f for f in findings if "scores" in f.description and f.line == 7]
        assert len(oob) > 0
        assert oob[0].vulnerability_type == "Buffer Overflow"
        assert oob[0].severity == "Critical"
        assert oob[0].cwe_id == "CWE-120"
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_ast_double_free_and_use_after_free():
    code = """#include <cstdlib>

int main() {
    int *ptr = (int*)malloc(sizeof(int));
    free(ptr);
    free(ptr); // Double free
    return 0;
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False) as f:
        f.write(code)
        path = f.name

    try:
        findings = ast_security_rules.analyze_ast(path, code)
        df = [f for f in findings if f.vulnerability_type == "Double Free"]
        assert len(df) > 0
        assert df[0].cwe_id == "CWE-415"
        assert df[0].cert_rule == "MEM51-CPP"
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_ast_integration_with_analyzer():
    code = """#include <cstdio>
#define G gets

int main() {
    char b[8];
    G(b);
    return 0;
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False) as f:
        f.write(code)
        path = f.name

    try:
        findings = security_analyzer.analyze(path, [])
        types = [f.vulnerability_type for f in findings]
        assert "Buffer Overflow" in types
    finally:
        if os.path.exists(path):
            os.remove(path)
