#!/usr/bin/env python3
"""
tools/run_limited.py
--------------------
Timeout wrapper for process execution with process tree termination.
Standard library only, completely independent of guard.safe_run.

Usage:
    python tools/run_limited.py SECONDS -- COMMAND [ARGS...]

Exit codes:
    0   - Command completed successfully (exit code 0)
    1   - Command failed with non-zero exit code
    124 - Command timed out
"""

from __future__ import annotations

import os
import sys
import time
import subprocess
import tempfile
import signal


def kill_process_tree(pid: int) -> None:
    """Force kill a process and all of its descendants."""
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception:
            pass
    else:
        try:
            pgid = os.getpgid(pid)
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass


def main() -> int:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if len(sys.argv) < 4 or "--" not in sys.argv:
        print("Usage: python tools/run_limited.py SECONDS -- COMMAND [ARGS...]", file=sys.stderr)
        return 1

    idx = sys.argv.index("--")
    timeout_str = sys.argv[1]
    cmd = sys.argv[idx + 1 :]

    if not cmd:
        print("Error: No command specified after '--'", file=sys.stderr)
        return 1

    try:
        timeout = float(timeout_str)
    except ValueError:
        print(f"Error: Invalid timeout value '{timeout_str}'", file=sys.stderr)
        return 1

    if timeout > 600:
        print(f"Error: Timeout {timeout}s exceeds maximum allowed limit of 600s", file=sys.stderr)
        return 1
    if timeout > 300:
        print(f"Warning: Timeout {timeout}s exceeds 300s recommendation", file=sys.stderr)

    # Use a temporary file for output to prevent grandchild pipe inheritance hangs
    with tempfile.NamedTemporaryFile(mode="w+b", delete=False) as tmp_out:
        tmp_path = tmp_out.name

    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": open(tmp_path, "wb"),
        "stderr": subprocess.STDOUT,
    }

    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    start_time = time.monotonic()
    timed_out = False
    return_code: int = 0

    try:
        proc = subprocess.Popen(cmd, **kwargs)
    except Exception as exc:
        print(f"Error launching command: {exc}", file=sys.stderr)
        try:
            kwargs["stdout"].close()
            os.remove(tmp_path)
        except Exception:
            pass
        return 1

    # Close parent handle to stdout file
    try:
        kwargs["stdout"].close()
    except Exception:
        pass

    try:
        while True:
            ret = proc.poll()
            if ret is not None:
                return_code = ret
                break
            elapsed = time.monotonic() - start_time
            if elapsed >= timeout:
                timed_out = True
                kill_process_tree(proc.pid)
                # Wait briefly for process to terminate
                try:
                    proc.wait(timeout=2.0)
                except Exception:
                    pass
                return_code = 124
                break
            time.sleep(0.05)
    except KeyboardInterrupt:
        kill_process_tree(proc.pid)
        return_code = 130
    finally:
        duration = time.monotonic() - start_time

    # Read captured output
    lines = []
    try:
        with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        pass
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    # Print the last 60 lines of output
    tail_lines = lines[-60:] if len(lines) > 60 else lines
    for line in tail_lines:
        sys.stdout.write(line)
    if tail_lines and not tail_lines[-1].endswith("\n"):
        sys.stdout.write("\n")

    # Final summary line
    status = "TIMEOUT" if timed_out else ("PASS" if return_code == 0 else "FAIL")
    print(f"RESULT: {status} seconds={duration:.2f} exit={return_code}")

    if timed_out:
        return 124
    return 0 if return_code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
