from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import Any

from .envscrub import scrubbed_env
from .safe_run import SafeResult, safe_run


@dataclass
class ExecutionResult:
    build_result: SafeResult
    run_result: SafeResult | None

    @property
    def compiled_ok(self) -> bool:
        return self.build_result.returncode == 0 and not self.build_result.timed_out


def build_and_run(
    source: str,
    *,
    input_text: str | None = None,
    timeout: float | None = None,
) -> ExecutionResult:
    """
    Builds the reviewed C++ source in an isolated temporary directory using safe_run
    and executes it with scrubbed_env. Always cleans up the temporary directory.
    """
    temp_dir = tempfile.mkdtemp(prefix="run_")
    src_file = os.path.join(temp_dir, "main.cpp")
    exe_name = "main.exe" if os.name == "nt" else "main.out"
    exe_path = os.path.join(temp_dir, exe_name)

    try:
        with open(src_file, "w", encoding="utf-8") as f:
            f.write(source)

        build_res = safe_run(
            ["g++", "-std=c++17", "-O0", "-pipe", src_file, "-o", exe_path],
            kind="build",
            cwd=temp_dir,
        )

        if build_res.returncode != 0 or build_res.timed_out:
            return ExecutionResult(build_result=build_res, run_result=None)

        run_res = safe_run(
            [exe_path],
            kind="run",
            input_text=input_text,
            timeout=timeout,
            cwd=temp_dir,
            env=scrubbed_env(),
            scrub_env=True,
        )

        return ExecutionResult(build_result=build_res, run_result=run_res)

    finally:
        if os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
