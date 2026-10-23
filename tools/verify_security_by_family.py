#!/usr/bin/env python3
"""
tools/verify_security_by_family.py
-----------------------------------
Verifies the security layer by family using static review (never compiles or runs attacks).
Filters security_bench/manifest.json by family into a temporary manifest,
calls run_benchmark(manifest_path=..., with_heal=False), and reports:
- detected count / rate
- prevented count / rate
- false alerts count / rate
- missed case ids
Also supports dedicated checks for safe_run, attack_log, and model_manifest.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from guard.benchmark import run_benchmark


def print_table_header(col1: str, col2: str, col3: str, col4: str):
    print("+" + "-" * 27 + "+" + "-" * 30 + "+" + "-" * 30 + "+" + "-" * 6 + "+")
    print(f"| {col1:<25} | {col2:<28} | {col3:<28} | {col4:<4} |")
    print("+" + "-" * 27 + "+" + "-" * 30 + "+" + "-" * 30 + "+" + "-" * 6 + "+")


def print_table_row(col1: str, col2: str, col3: str, ok: bool):
    ok_str = "PASS" if ok else "FAIL"
    c1 = col1[:25]
    c2 = col2[:28]
    c3 = col3[:28]
    print(f"| {c1:<25} | {c2:<28} | {c3:<28} | {ok_str:<4} |")


def print_table_footer():
    print("+" + "-" * 27 + "+" + "-" * 30 + "+" + "-" * 30 + "+" + "-" * 6 + "+")


def run_family_benchmark(families: list[str], manifest_path: Path) -> int:
    with open(manifest_path, "r", encoding="utf-8") as f:
        all_cases = json.load(f)

    # Filter by family
    fam_set = set(families)
    filtered = [c for c in all_cases if c.get("family") in fam_set]
    if not filtered:
        print(f"ERROR: No cases found in manifest for families: {families}")
        return 1

    temp_dir = tempfile.mkdtemp(prefix="sec_family_")
    temp_manifest = Path(temp_dir) / "manifest.json"

    try:
        with open(temp_manifest, "w", encoding="utf-8") as f:
            json.dump(filtered, f, indent=2)

        t0 = time.monotonic()
        metrics = run_benchmark(manifest_path=temp_manifest, with_heal=False)
        duration = time.monotonic() - t0

        cases_res = metrics.get("cases", [])
        attacks = [c for c in cases_res if c.get("label") == "attack"]
        benign = [c for c in cases_res if c.get("label") == "benign"]

        det_count = sum(1 for c in attacks if c.get("detected"))
        prev_count = sum(1 for c in attacks if c.get("prevented"))
        false_alerts = sum(1 for c in benign if c.get("false_alert"))
        missed_ids = [c.get("id") for c in attacks if not c.get("detected")]

        title = f"Family: {', '.join(families)}"
        print(f"\n--- {title} ({len(filtered)} cases: {len(attacks)} attacks, {len(benign)} benign) ---")
        print_table_header("Metric", "Expected", "Actual", "OK")

        # In standard benchmark, standard attacks are 100% detected; hard attacks may have known misses
        # Check that detected > 0 or all detected if only standard
        is_hard = any(c.get("set") == "hard" for c in attacks)
        exp_det = f">{len(attacks)//2}" if is_hard else f"{len(attacks)}/{len(attacks)}"
        ok_det = (det_count == len(attacks)) if not is_hard else (det_count >= len(attacks) // 2)
        print_table_row("Attacks Detected", exp_det, f"{det_count}/{len(attacks)}", ok_det)

        exp_prev = f">0" if attacks else "N/A"
        ok_prev = (prev_count > 0) if attacks else True
        print_table_row("Attacks Prevented", exp_prev, f"{prev_count}/{len(attacks)}", ok_prev)

        ok_fa = (false_alerts == 0)
        print_table_row("False Alerts (Benign)", "0", str(false_alerts), ok_fa)
        print_table_footer()

        print(f"Duration: {duration:.2f}s")
        if missed_ids:
            print(f"Missed Case IDs (Hard/Known): {', '.join(missed_ids)}")
        else:
            print("Missed Case IDs: None")

        return 0 if (ok_det and ok_prev and ok_fa) else 1
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def verify_phase2_saferun() -> int:
    from guard.safe_run import safe_run

    print("\n--- Phase 2: safe_run timeouts, output cap, env scrub & grandchild ---")
    print_table_header("Check", "Expected", "Actual", "OK")
    all_ok = True

    # 1. safe_run timeout
    t0 = time.monotonic()
    r_to = safe_run([sys.executable, "-c", "import time; time.sleep(10)"], kind="run", timeout=1.0)
    dur_to = time.monotonic() - t0
    ok_to = r_to.timed_out and (dur_to < 4.0)
    print_table_row("safe_run timeout", "timed_out=True <4s", f"timed_out={r_to.timed_out} ({dur_to:.2f}s)", ok_to)
    if not ok_to:
        all_ok = False

    # 2. Output cap (MAX_OUTPUT_BYTES = 64KB)
    r_cap = safe_run([sys.executable, "-c", "print('A' * 200000)"], kind="run", timeout=5.0, max_output_bytes=65536)
    ok_cap = len(r_cap.stdout.encode("utf-8")) <= 65536 and r_cap.truncated
    print_table_row("Output cap", "<=64KB, truncated=True", f"len={len(r_cap.stdout)} trunc={r_cap.truncated}", ok_cap)
    if not ok_cap:
        all_ok = False

    # 3. Environment scrub
    os.environ["SUPER_SECRET_LEAK"] = "forbidden_secret_value_123"
    r_env = safe_run([sys.executable, "-c", "import os; print('SECRET_IN_CHILD=' + os.environ.get('SUPER_SECRET_LEAK', 'NOT_FOUND'))"], kind="run", timeout=5.0)
    ok_env = "NOT_FOUND" in r_env.stdout
    print_table_row("Environment scrub", "SECRET_IN_CHILD=NOT_FOUND", r_env.stdout.strip()[:28], ok_env)
    if not ok_env:
        all_ok = False

    # 4. Grandchild termination test
    # A child process that starts a grandchild sleeping 60 seconds with inherited output; safe_run(timeout=2) must return within 8 seconds with timed_out=True.
    child_script = (
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "time.sleep(60)\n"
    )
    t0 = time.monotonic()
    r_gc = safe_run([sys.executable, "-c", child_script], kind="syntax", timeout=2.0)
    dur_gc = time.monotonic() - t0
    ok_gc = r_gc.timed_out and (dur_gc < 8.0)
    print_table_row("Grandchild bounded exit", "timed_out=True <8s", f"timed_out={r_gc.timed_out} ({dur_gc:.2f}s)", ok_gc)
    if not ok_gc:
        all_ok = False

    print_table_footer()
    return 0 if all_ok else 1


def verify_attack_log_isolation() -> int:
    from guard.attack_log import log_event, log_verdict
    from guard.supervisor import get_supervisor
    from guard.models import InputKind

    print("\n--- Attack Log Verification & Isolation ---")
    print_table_header("Check", "Expected", "Actual", "OK")
    all_ok = True

    temp_dir = tempfile.mkdtemp(prefix="guard_log_iso_")
    custom_log = Path(temp_dir) / "custom_attack.log"
    old_log_path = os.environ.get("GUARD_LOG_PATH")

    try:
        os.environ["GUARD_LOG_PATH"] = str(custom_log)

        # Review an attack input with sensitive tokens
        secret_token = "AKIAIOSFODNN7EXAMPLE_SECRET_TOKEN"
        malicious_input = f'#include <unistd.h>\n// Key: {secret_token}\nint main() {{ execvp("sh", nullptr); }}'

        verdict = get_supervisor().review(InputKind.USER_SOURCE, malicious_input, purpose="run")
        ok_block = verdict.blocked

        # Check log was created at custom path
        log_created = custom_log.exists()
        log_text = custom_log.read_text(encoding="utf-8") if log_created else ""

        # Verify no source text or secret in log
        no_secret = secret_token not in log_text
        no_source = 'execvp("sh", nullptr)' not in log_text

        ok_sec = log_created and no_secret and no_source
        print_table_row("Log Created & Isolated", "GUARD_LOG_PATH honored", f"created={log_created}", log_created)
        print_table_row("No Secret in Log", "Secret absent from log", f"absent={no_secret}", no_secret)
        print_table_row("No Source in Log", "Source absent from log", f"absent={no_source}", no_source)

        if not (log_created and no_secret and no_source):
            all_ok = False

    finally:
        if old_log_path is not None:
            os.environ["GUARD_LOG_PATH"] = old_log_path
        else:
            os.environ.pop("GUARD_LOG_PATH", None)
        shutil.rmtree(temp_dir, ignore_errors=True)

    print_table_footer()
    return 0 if all_ok else 1


def verify_model_manifest() -> int:
    from guard.integrity import model_status

    print("\n--- Model Manifest Integrity & Tamper Check ---")
    print_table_header("Check", "Expected", "Actual", "OK")
    all_ok = True

    # Current model check
    status = model_status()
    ok_curr = status.get("ok", False)
    print_table_row("Current Model Valid", "ok=True", f"ok={ok_curr} reason={status.get('reason')[:15]}", ok_curr)
    if not ok_curr:
        all_ok = False

    # Tamper check: 1-byte change in temporary model file
    model_path = _REPO_ROOT / "data" / "error_classifier.joblib"
    if not model_path.exists():
        model_path = _REPO_ROOT / "models" / "error_classifier.joblib"

    if model_path.exists():
        temp_dir = tempfile.mkdtemp(prefix="tamper_test_")
        temp_model = Path(temp_dir) / "error_classifier.joblib"
        data = bytearray(model_path.read_bytes())
        # Flip 1 byte
        data[100] = (data[100] + 1) % 256
        temp_model.write_bytes(data)

        tamper_res = model_status(temp_model)
        ok_tamper = not tamper_res.get("ok", False)
        print_table_row("Tampered Model Rejected", "rejected=True", f"accepted={tamper_res.get('ok')} reason={tamper_res.get('reason')[:15]}", ok_tamper)
        if not ok_tamper:
            all_ok = False
        shutil.rmtree(temp_dir, ignore_errors=True)

    print_table_footer()
    return 0 if all_ok else 1


def verify_git_clean() -> int:
    print("\n--- Git Status Cleanliness (.env and logs check) ---")
    print_table_header("Check", "Expected", "Actual", "OK")

    res = subprocess.run(["git", "status", "--short"], capture_output=True, text=True, cwd=_REPO_ROOT)
    lines = res.stdout.splitlines()

    env_staged = any(".env" in l for l in lines)
    log_staged = any(".log" in l for l in lines)

    ok_env = not env_staged
    ok_log = not log_staged

    print_table_row(".env not staged/tracked", "absent", f"staged={env_staged}", ok_env)
    print_table_row(".log files not staged", "absent", f"staged={log_staged}", ok_log)
    print_table_footer()

    return 0 if (ok_env and ok_log) else 1


def main():
    parser = argparse.ArgumentParser(description="Verify Security Layer by Family")
    parser.add_argument("--family", help="Comma-separated family names to verify")
    parser.add_argument("--check", choices=["phase2_saferun", "attack_log", "model_manifest", "git_clean"], help="Special check")
    parser.add_argument("--manifest", default=str(_REPO_ROOT / "security_bench" / "manifest.json"), help="Manifest path")

    args = parser.parse_args()

    if args.check == "phase2_saferun":
        sys.exit(verify_phase2_saferun())
    elif args.check == "attack_log":
        sys.exit(verify_attack_log_isolation())
    elif args.check == "model_manifest":
        sys.exit(verify_model_manifest())
    elif args.check == "git_clean":
        sys.exit(verify_git_clean())
    elif args.family:
        families = [f.strip() for f in args.family.split(",")]
        sys.exit(run_family_benchmark(families, Path(args.manifest)))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
