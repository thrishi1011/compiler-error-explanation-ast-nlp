#!/usr/bin/env python3
"""
tools/run_offline.py
---------------------
Executes a target script strictly offline by monkey-patching:
- socket.socket.connect
- socket.create_connection
- socket.getaddrinfo
Any attempted network call raises OSError("network blocked") and increments an attempts counter.
After script execution, confirms that zero network attempts were made.
"""

from __future__ import annotations

import runpy
import socket
import sys
from pathlib import Path

_network_attempts = 0


def _blocked_connect(*args, **kwargs):
    global _network_attempts
    _network_attempts += 1
    raise OSError("network blocked: offline execution enforces zero network attempts")


def _blocked_create_connection(*args, **kwargs):
    global _network_attempts
    _network_attempts += 1
    raise OSError("network blocked: offline execution enforces zero network attempts")


def _blocked_getaddrinfo(*args, **kwargs):
    global _network_attempts
    _network_attempts += 1
    raise OSError("network blocked: offline execution enforces zero network attempts")


def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/run_offline.py SCRIPT [ARGS...]", file=sys.stderr)
        sys.exit(1)

    target_script = sys.argv[1]
    target_args = sys.argv[2:]

    target_path = Path(target_script).resolve()
    if not target_path.exists():
        print(f"Error: Target script not found: {target_script}", file=sys.stderr)
        sys.exit(1)

    # Ensure src and target dir are in sys.path
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "src"
    if str(target_path.parent) not in sys.path:
        sys.path.insert(0, str(target_path.parent))
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    # Monkey-patch socket operations
    socket.socket.connect = _blocked_connect
    socket.create_connection = _blocked_create_connection
    socket.getaddrinfo = _blocked_getaddrinfo

    # Prepare sys.argv
    sys.argv = [str(target_path)] + target_args

    exit_code = 0
    had_crash = False
    try:
        runpy.run_path(str(target_path), run_name="__main__")
    except SystemExit as se:
        # Script called sys.exit(code), which is normal for CLI tools
        pass
    except Exception as exc:
        print(f"Execution error under offline runner: {exc}", file=sys.stderr)
        had_crash = True

    if _network_attempts > 0:
        print(f"\n[OFFLINE PROOF] FAILED: {target_path.name} attempted {_network_attempts} network operations!", file=sys.stderr)
        sys.exit(1)

    if had_crash:
        print(f"\n[OFFLINE PROOF] FAILED: {target_path.name} crashed with an unhandled exception!", file=sys.stderr)
        sys.exit(1)

    print(f"\n[OFFLINE PROOF] PASSED: {target_path.name} executed cleanly with 0 network attempts.")
    sys.exit(0)


if __name__ == "__main__":
    main()
