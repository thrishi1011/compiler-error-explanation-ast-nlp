import pytest
import os
import sys
import tempfile
import json
from pathlib import Path

_src_path = str(Path(__file__).resolve().parent.parent / "src")
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

import security_analyzer
from security_analyzer import (
    SecurityFinding,
    CWE_DEFINITIONS,
    CERT_DEFINITIONS,
    export_to_sarif,
    save_sarif,
    format_security_report,
    analyze,
)


def test_security_finding_cwe_cert_attributes():
    finding = SecurityFinding(
        file="main.cpp",
        line=10,
        column=5,
        severity="Critical",
        vulnerability_type="Buffer Overflow",
        description="Stack buffer overflow via gets",
        recommendation="Use fgets or std::string",
        source="static_scan",
        cwe_id="CWE-120",
        cwe_name="Classic Buffer Overflow",
        cwe_url="https://cwe.mitre.org/data/definitions/120.html",
        cert_rule="ARR30-C",
        cert_url="https://wiki.sei.cmu.edu/confluence/display/c/ARR30-C",
    )
    assert finding.cwe_id == "CWE-120"
    assert finding.cert_rule == "ARR30-C"
    d = finding.to_dict()
    assert d["cwe_id"] == "CWE-120"
    assert d["cert_rule"] == "ARR30-C"
    assert d["cwe_url"].startswith("https://cwe.mitre.org")


def test_cwe_and_cert_definitions_coverage():
    core_vulns = [
        "Buffer Overflow",
        "Format String Vulnerability",
        "Null Pointer Dereference",
        "Use After Free",
        "Double Free",
        "Integer Overflow",
        "Command Injection",
        "Uninitialized Memory",
        "Insecure Randomness",
    ]
    for vuln in core_vulns:
        assert vuln in CWE_DEFINITIONS, f"Missing CWE definition for {vuln}"
        assert vuln in CERT_DEFINITIONS, f"Missing CERT definition for {vuln}"
        cwe = CWE_DEFINITIONS[vuln]
        cert = CERT_DEFINITIONS[vuln]
        assert cwe["id"].startswith("CWE-")
        assert len(cert["rule"]) > 3


def test_automatic_cwe_cert_enrichment_on_scan():
    code = """#include <iostream>
#include <cstdio>
#include <cstdlib>

int main() {
    char buf[10];
    gets(buf);
    system("ls");
    int *p = (int*)malloc(sizeof(int));
    free(p);
    free(p);
    return 0;
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False) as f:
        f.write(code)
        path = f.name

    try:
        findings = analyze(path, [])
        assert len(findings) > 0
        vuln_types = [f.vulnerability_type for f in findings]
        cwe_ids = [f.cwe_id for f in findings if f.cwe_id]
        cert_rules = [f.cert_rule for f in findings if f.cert_rule]

        assert "CWE-120" in cwe_ids or "CWE-676" in cwe_ids
        assert "CWE-78" in cwe_ids
        assert "CWE-415" in cwe_ids
        assert "ENV33-C" in cert_rules
        assert "MEM51-CPP" in cert_rules
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_sarif_export():
    f1 = SecurityFinding(
        file="test.cpp",
        line=12,
        column=1,
        severity="High",
        vulnerability_type="Command Injection",
        description="Calls system()",
        recommendation="Use execve",
        source="static_scan",
        cwe_id="CWE-78",
        cwe_name="OS Command Injection",
        cert_rule="ENV33-C",
    )
    sarif = export_to_sarif([f1])
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "CWE-78"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 12

    with tempfile.NamedTemporaryFile("w", suffix=".sarif", delete=False) as f:
        sarif_file = f.name

    try:
        save_sarif([f1], sarif_file)
        assert os.path.isfile(sarif_file)
        with open(sarif_file, "r", encoding="utf-8") as rf:
            loaded = json.load(rf)
            assert loaded["version"] == "2.1.0"
    finally:
        if os.path.exists(sarif_file):
            os.remove(sarif_file)


def test_format_security_report_includes_cwe_cert():
    f1 = SecurityFinding(
        file="test.cpp",
        line=5,
        column=2,
        severity="Critical",
        vulnerability_type="Buffer Overflow",
        description="Vulnerable buffer",
        recommendation="Bounds check",
        source="static_scan",
        cwe_id="CWE-120",
        cert_rule="ARR30-C",
    )
    report = format_security_report([f1])
    assert "[CWE-120]" in report
    assert "[ARR30-C]" in report
    assert "[CRITICAL]" in report
