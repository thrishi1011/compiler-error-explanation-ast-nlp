#!/usr/bin/env python3
"""
tools/build_report_assets.py
----------------------------
Orchestrates report generation:
1. Runs tools/make_security_docs.py
2. Runs tools/make_security_report_tables.py
3. If pdflatex is installed, compiles each .tex file in docs/report/ through safe_run
   (60s timeout, in a temporary directory).
4. If pdflatex is not found, prints 'pdflatex not found, .tex files written only'
   and exits cleanly with code 0.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from guard.safe_run import safe_run


def main() -> int:
    print("[1/3] Running tools/make_security_docs.py...")
    ret_docs = subprocess.run([sys.executable, str(ROOT / "tools" / "make_security_docs.py")], check=False)
    if ret_docs.returncode != 0:
        print("Error: make_security_docs.py failed.")
        return ret_docs.returncode

    print("[2/3] Running tools/make_security_report_tables.py...")
    ret_tables = subprocess.run([sys.executable, str(ROOT / "tools" / "make_security_report_tables.py")], check=False)
    if ret_tables.returncode != 0:
        print("Error: make_security_report_tables.py failed.")
        return ret_tables.returncode

    if os.environ.get("GUARD_NO_LATEX") == "1":
        print("GUARD_NO_LATEX=1 set, skipping pdflatex compilation")
        return 0

    print("[3/3] Checking for pdflatex compiler...")
    pdflatex_bin = shutil.which("pdflatex")
    if not pdflatex_bin:
        print("pdflatex not found, .tex files written only")
        return 0

    # Detect if MiKTeX to pass --disable-installer (never pass to TeX Live)
    is_miktex = False
    try:
        ver_res = subprocess.run(
            [pdflatex_bin, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
        )
        ver_text = (ver_res.stdout + " " + ver_res.stderr).lower()
        if "miktex" in ver_text:
            is_miktex = True
    except Exception:
        pass

    report_dir = ROOT / "docs" / "report"
    tex_files = ["security_architecture.tex", "security_tables.tex", "security_overview.tex"]

    all_compiled = True
    for tex_name in tex_files:
        tex_path = report_dir / tex_name
        if not tex_path.exists():
            continue

        print(f"Compiling {tex_name} with pdflatex...")
        with tempfile.TemporaryDirectory(prefix="latex_build_") as tmp_dir:
            # Copy source tex to temp directory
            tmp_tex = Path(tmp_dir) / tex_name
            shutil.copyfile(tex_path, tmp_tex)

            cmd = [
                pdflatex_bin,
                "-interaction=nonstopmode",
                "-halt-on-error",
            ]
            if is_miktex:
                cmd.append("--disable-installer")
            cmd.append(tex_name)

            res = safe_run(
                cmd,
                kind="analysis",
                timeout=60.0,
                cwd=tmp_dir,
                scrub_env=False,
            )

            out_pdf = Path(tmp_dir) / (tex_path.stem + ".pdf")
            if out_pdf.exists():
                dest_pdf = report_dir / out_pdf.name
                shutil.copyfile(out_pdf, dest_pdf)
                print(f"Successfully compiled: {dest_pdf.name}")
            else:
                print(f"Compilation finished without PDF output for {tex_name} (code: {res.returncode})")
                all_compiled = False

    return 0


if __name__ == "__main__":
    sys.exit(main())
