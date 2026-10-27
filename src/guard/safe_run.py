from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any

from .attack_log import log_event
from .config import get_timeout_for_kind
from .envscrub import scrubbed_env


@dataclass
class SafeResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    duration_s: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "duration_s": self.duration_s,
        }


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Kills the entire process tree on Windows or POSIX."""
    if os.name == "nt":
        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) | 0x00000008
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
        except Exception:
            pass
        try:
            proc.kill()
        except Exception:
            pass
    else:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def safe_run(
    cmd: list[str],
    *,
    kind: str,
    timeout: float | None = None,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    max_output_bytes: int = 1_000_000,
    scrub_env: bool = True,
) -> SafeResult:
    """
    Executes a subprocess safely with process tree timeout, output capping,
    thread-based I/O to prevent deadlock, and environment scrubbing.

    cmd must be a list (never shell=True).
    Timeouts default by kind (compile 20, build 20, syntax 10, ast 20,
    ai_validate 10, analysis 60, run 5) and can be overridden via GUARD_TIMEOUT_<KIND>.
    """
    assert isinstance(cmd, list), f"cmd must be a list of strings, got {type(cmd)}"
    assert not isinstance(cmd, (str, bytes)), "cmd must be a list, never a string"

    actual_timeout = get_timeout_for_kind(kind, timeout)

    if scrub_env:
        effective_env = scrubbed_env(env)
    else:
        effective_env = os.environ.copy() if env is None else env

    popen_kwargs: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "cwd": cwd,
        "env": effective_env,
        "shell": False,
    }

    if input_text is not None:
        popen_kwargs["stdin"] = subprocess.PIPE
    else:
        popen_kwargs["stdin"] = subprocess.DEVNULL

    if os.name == "nt":
        if cmd and isinstance(cmd, (list, tuple)) and len(cmd) > 0 and isinstance(cmd[0], str):
            if cmd[0].lower().endswith("python.exe"):
                pyw = cmd[0][:-4] + "w.exe"
                if os.path.exists(pyw):
                    cmd = [pyw] + list(cmd[1:])
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) | 0x00000008
        popen_kwargs["creationflags"] = creationflags
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        popen_kwargs["startupinfo"] = startupinfo
    else:
        popen_kwargs["start_new_session"] = True

    t_start = time.perf_counter()
    timed_out = False
    truncated = False

    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except Exception as e:
        duration_s = time.perf_counter() - t_start
        return SafeResult(
            returncode=-1,
            stdout="",
            stderr=str(e),
            timed_out=False,
            truncated=False,
            duration_s=round(duration_s, 3),
        )

    # I/O buffers and locks
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_bytes = [0]
    stderr_bytes = [0]
    stop_event = threading.Event()

    def stream_reader(pipe, chunks_list, bytes_counter):
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    break
                chunks_list.append(chunk)
                bytes_counter[0] += len(chunk)
                if bytes_counter[0] > max_output_bytes:
                    nonlocal truncated
                    truncated = True
                    stop_event.set()
                    _kill_process_tree(proc)
                    break
        except Exception:
            pass
        finally:
            try:
                pipe.close()
            except Exception:
                pass

    t_out = threading.Thread(target=stream_reader, args=(proc.stdout, stdout_chunks, stdout_bytes), daemon=True)
    t_err = threading.Thread(target=stream_reader, args=(proc.stderr, stderr_chunks, stderr_bytes), daemon=True)
    t_out.start()
    t_err.start()

    # Writer thread for stdin
    if input_text is not None and proc.stdin:
        def stream_writer(pipe, text):
            try:
                pipe.write(text.encode("utf-8", errors="replace"))
                pipe.flush()
            except Exception:
                pass
            finally:
                try:
                    pipe.close()
                except Exception:
                    pass

        t_in = threading.Thread(target=stream_writer, args=(proc.stdin, input_text), daemon=True)
        t_in.start()

    # Wait for process with timeout
    try:
        proc.wait(timeout=actual_timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_tree(proc)
        try:
            proc.wait(timeout=2.0)
        except Exception:
            pass

    # Close parent pipe handles so reader threads cannot hang on open grandchild descriptors
    try:
        if proc.stdout and not proc.stdout.closed:
            proc.stdout.close()
    except Exception:
        pass
    try:
        if proc.stderr and not proc.stderr.closed:
            proc.stderr.close()
    except Exception:
        pass

    t_out.join(timeout=2.0)
    t_err.join(timeout=2.0)

    duration_s = time.perf_counter() - t_start

    stdout_str = b"".join(stdout_chunks).decode("utf-8", errors="replace")
    stderr_str = b"".join(stderr_chunks).decode("utf-8", errors="replace")

    # If output was truncated, ensure cap
    if truncated:
        if len(stdout_str.encode("utf-8")) > max_output_bytes:
            stdout_str = stdout_str[:max_output_bytes]
        if len(stderr_str.encode("utf-8")) > max_output_bytes:
            stderr_str = stderr_str[:max_output_bytes]

    # Log resource limit events
    if timed_out or truncated:
        cmd0 = os.path.basename(cmd[0]) if cmd else "unknown"
        log_event(
            "resource_limit",
            {
                "kind": kind,
                "cmd0": cmd0,
                "timeout": actual_timeout,
                "truncated": truncated,
                "duration_s": round(duration_s, 3),
            },
        )

    return SafeResult(
        returncode=proc.returncode if not timed_out else -1,
        stdout=stdout_str,
        stderr=stderr_str,
        timed_out=timed_out,
        truncated=truncated,
        duration_s=round(duration_s, 3),
    )
