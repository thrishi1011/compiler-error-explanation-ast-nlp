import subprocess
import re
import os
import sys

from guard import check_compile, safe_run

def _get_dangerous_patterns(permissions: dict = None) -> list:
    if permissions is None:
        permissions = {
            "allow_system_calls": os.environ.get("ALLOW_SYSTEM_CALLS") == "1",
            "allow_assembly": os.environ.get("ALLOW_ASSEMBLY") == "1",
            "allow_sys_includes": os.environ.get("ALLOW_SYS_INCLUDES") == "1",
        }
    
    dangerous_patterns = []
    
    if not permissions.get("allow_system_calls", False):
        dangerous_patterns.extend([r'system\s*\(', r'exec\s*\(', r'popen\s*\(', r'fork\s*\('])
        
    if not permissions.get("allow_assembly", False):
        dangerous_patterns.extend([r'__asm__', r'shellcode'])
        
    if not permissions.get("allow_sys_includes", False):
        dangerous_patterns.extend([r'#include\s*[<"]\s*sys/'])

    return dangerous_patterns

def _strip_comments(source: str) -> str:
    cleaned = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    cleaned = re.sub(r'//.*$', '', cleaned, flags=re.MULTILINE)
    return cleaned

def _find_dangerous_line(source: str, permissions: dict = None) -> int:
    patterns = _get_dangerous_patterns(permissions)
    fallback_line = 1
    for idx, line in enumerate(source.splitlines(), start=1):
        code_part = re.sub(r'//.*$', '', line).strip()
        for pattern in patterns:
            if code_part and re.search(pattern, code_part):
                return idx
            elif re.search(pattern, line) and fallback_line == 1:
                fallback_line = idx
    return fallback_line

def _sanitize_code(source: str, permissions: dict = None) -> bool:
    clean_src = _strip_comments(source)
    for pattern in _get_dangerous_patterns(permissions):
        if re.search(pattern, clean_src):
            return False
    return True

def _sanitize_input(file_path: str, permissions: dict = None) -> bool:
    if not os.path.exists(file_path):
        return True
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        return _sanitize_code(f.read(), permissions)

def run_cpp_compiler(file_path, permissions=None):
    if not _sanitize_input(file_path, permissions):
        source_code = ""
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source_code = f.read()
        err_line = _find_dangerous_line(source_code, permissions) if source_code else 1
        return [{
            "file": file_path,
            "line": err_line,
            "column": 1,
            "type": "error",
            "origin": "security",
            "message": "Security Error: Malicious command injection or forbidden system call detected.",
            "raw": "error: Malicious command injection or forbidden system call detected."
        }]

    source_code = ""
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source_code = f.read()

    from guard import check_compile, safe_run
    verdict = check_compile(
        source_code,
        source_dir=os.path.dirname(os.path.abspath(file_path)),
        file_name=os.path.basename(file_path),
    )
    if verdict.blocked:
        blocking_f = next((f for f in verdict.findings if f.action == "block"), verdict.findings[0] if verdict.findings else None)
        agents_str = ", ".join(blocking_f.agents) if blocking_f else "ResourceGuard"
        cat = blocking_f.category if blocking_f else "security_violation"
        line_no = blocking_f.line if (blocking_f and blocking_f.line) else 1
        col_no = blocking_f.column if (blocking_f and blocking_f.column) else 1
        msg = f"Security Error: blocked by {agents_str} ({cat}) at line {line_no}"
        return [{
            "file": file_path,
            "line": line_no,
            "column": col_no,
            "type": "error",
            "message": msg,
            "raw": f"error: {msg}",
        }]

    try:
        exe_target = "a.exe" if (os.name == "nt" or sys.platform == "win32") else "a.out"
        if os.path.exists(exe_target):
            try:
                os.remove(exe_target)
            except OSError:
                pass
        res = safe_run(
            ["g++", "-std=c++17", "-Wall", "-Wextra", "-Wshadow", "-Wnull-dereference", file_path, "-o", exe_target],
            kind="compile",
        )
        if res.timed_out:
            t_s = int(res.duration_s)
            return [{
                "file": file_path,
                "line": 1,
                "column": 1,
                "type": "error",
                "message": f"Compilation timed out after {t_s} s (possible resource-exhaustion input)",
                "raw": f"error: Compilation timed out after {t_s} s (possible resource-exhaustion input)",
            }]

        errors=[]
        pattern=r"^(.+?):(\d+):(\d+):\s*(fatal error|error|warning):\s*(.*)$"

        for line in res.stderr.splitlines():
            match=re.match(pattern, line.strip())
            if match:
                etype = match.group(4).strip()
                if etype == "fatal error":
                    etype = "error"
                errors.append({
                    "file": match.group(1),
                    "line": int(match.group(2)),
                    "column": int(match.group(3)),
                    "type": etype,
                    "message": match.group(5).strip(),
                    "raw": line
                })
        return errors

    except FileNotFoundError:
        return[{
            "file":None,
            "line":None,
            "column":None,
            "type":"error",
            "message":"g++ compiler not found.",
            "raw":"g++ compiler not found."
        }]