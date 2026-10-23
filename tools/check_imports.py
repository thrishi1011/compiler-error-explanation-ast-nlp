"""
tools/check_imports.py
-----------------------
Tests importing each module in its own isolated process with QT_QPA_PLATFORM=offscreen.
Reports import time and flags any that take > 10s or fail.
"""
import os
import sys
import time
import subprocess

guard_dir = os.path.join(os.path.abspath("src"), "guard")
guard_modules = ["guard"]
for fname in sorted(os.listdir(guard_dir)):
    if fname.endswith(".py") and not fname.startswith("__"):
        guard_modules.append(f"guard.{fname[:-3]}")

top_modules = [
    "security_healer",
    "security_view",
    "quality_hints",
    "error_parser",
    "error_normalizer",
    "error_classifier",
    "error_explainer",
    "ai_explainer",
    "ai_healer",
    "auto_healer",
    "heal_engine",
    "llm_client",
    "compiler_runner",
    "web_server",
    "gui",
]

modules = guard_modules + top_modules

env = os.environ.copy()
env["QT_QPA_PLATFORM"] = "offscreen"
env["PYTHONPATH"] = os.path.abspath("src")

slow_or_failed = []

for mod in modules:
    t0 = time.monotonic()
    res = subprocess.run(
        [sys.executable, "-c", f"import {mod}"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    elapsed = time.monotonic() - t0
    status = "OK" if res.returncode == 0 else f"FAIL (exit {res.returncode}): {res.stderr.strip()[:60]}"
    print(f"{mod:<28}: {elapsed:.2f}s [{status}]")
    if elapsed > 10.0 or res.returncode != 0:
        slow_or_failed.append((mod, elapsed, status))

if slow_or_failed:
    print(f"\nWARNING: {len(slow_or_failed)} module(s) slow or failed:")
    for mod, el, st in slow_or_failed:
        print(f"  {mod}: {el:.2f}s ({st})")
    sys.exit(1)
else:
    print("\nAll 36 modules imported successfully in under 10 seconds each.")
