import pytest
import sys
from pathlib import Path

_src_path = str(Path(__file__).resolve().parent.parent / "src")
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

from guard.supervisor import get_supervisor, CAPEC_MAP
from guard.models import InputKind


def test_capec_map_coverage():
    assert "process_execution" in CAPEC_MAP
    assert CAPEC_MAP["process_execution"]["id"] == "CAPEC-88"
    assert "prompt_injection" in CAPEC_MAP
    assert CAPEC_MAP["prompt_injection"]["id"] == "CAPEC-690"
    assert "macro_expansion_bomb" in CAPEC_MAP
    assert CAPEC_MAP["macro_expansion_bomb"]["id"] == "CAPEC-197"


def test_supervisor_assigns_capec_id():
    sup = get_supervisor()
    payload = '#include <cstdlib>\nint main() { system("rm -rf /"); return 0; }'
    verdict = sup.review(InputKind.USER_SOURCE, payload, purpose="analyze")
    
    # Check if any finding has CAPEC-88
    found_capec = False
    for f in verdict.findings:
        if f.capec_id == "CAPEC-88":
            found_capec = True
            assert "capec_name" in f.details
            assert f.details["capec_id"] == "CAPEC-88"
    assert found_capec, "Failed to assign CAPEC-88 to process_execution finding"
