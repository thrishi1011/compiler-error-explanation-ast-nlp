from __future__ import annotations

import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any

from .base import GuardAgent, GuardContext
from .config import (
    MAX_HEADER_BYTES,
    MAX_HEADER_COUNT,
    MAX_HEADER_DEPTH,
    MAX_SCAN_BYTES,
)
from .models import Finding, InputKind
from .redact import redact

try:
    from security_analyzer import _strip_code
except ImportError:
    _src = str(Path(__file__).resolve().parent.parent)
    if _src not in sys.path:
        sys.path.insert(0, _src)
    from security_analyzer import _strip_code

TRIGGER_TOKENS = (
    "system", "exec", "popen", "fork", "spawn", "asm", "dl", "Library", "GetProc",
    "socket", "getaddrinfo", "gethostby", "inet_", "WSA", "curl_",
    "fopen", "freopen", "open", "stream", "filesystem",
    "remove", "unlink", "rmdir", "rename",
    "getenv", "_dupenv", "GetEnvironment",
    "##", "#define", "constructor", "#pragma", "#include",
    "CreateProcess", "ShellExecute", "WinExec",
)

DANGEROUS_IDENTIFIERS = {
    "system", "popen", "exec", "execl", "execle", "execlp", "execv", "execve",
    "execvp", "execvpe", "fexecve", "posix_spawn", "posix_spawnp", "fork", "vfork",
    "CreateProcess", "CreateProcessA", "CreateProcessW",
    "ShellExecute", "ShellExecuteA", "ShellExecuteW", "WinExec",
    "dlopen", "dlsym", "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "socket", "getaddrinfo", "gethostbyname", "inet_addr", "WSAStartup", "curl_easy_init",
    "remove", "unlink", "rmdir", "rename", "remove_all",
    "getenv", "_dupenv_s", "GetEnvironmentVariable", "GetEnvironmentVariableA", "GetEnvironmentVariableW",
}

_PROCESS_EXEC_RE = re.compile(
    r"\b(?:system|popen|execlp|execle|execl|execvpe|execve|execvp|execv|fexecve|exec|"
    r"posix_spawnp|posix_spawn|vfork|fork|"
    r"CreateProcess[A-Za-z0-9_]*|ShellExecute[A-Za-z0-9_]*|WinExec)\s*\("
)

_ASM_RE = re.compile(r"\b(?:__asm__|__asm|_asm|asm)\b")

_DYNAMIC_LOAD_RE = re.compile(r"\b(?:dlopen|dlsym|LoadLibrary[A-Za-z0-9_]*|GetProcAddress)\s*\(")

_NETWORK_CALL_RE = re.compile(r"\b(?:socket|getaddrinfo|gethostbyname|inet_addr|WSAStartup|curl_easy_init)\s*\(")

_NETWORK_INCLUDE_RE = re.compile(
    r'#\s*include\s*[<"](?:sys/socket\.h|netinet/in\.h|arpa/inet\.h|winsock2\.h|curl/curl\.h)[>"]'
)

_FILE_OPEN_RE = re.compile(r"\b(?:fopen|freopen|open|ifstream|ofstream|fstream)\b|(?:::|\b)filesystem::")

_DESTRUCTIVE_FILE_RE = re.compile(r"\b(?:remove|unlink|rmdir|rename|remove_all)\s*\(")

_SECRET_ENV_RE = re.compile(r"\b(?:getenv|_dupenv_s|GetEnvironmentVariable[A-Za-z0-9_]*)\s*\(")

_STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"')

_STARTUP_ATTR_RE = re.compile(r"__attribute__\s*\(\s*\(\s*constructor\s*\)\s*\)")
_STARTUP_PRAGMA_RE = re.compile(r"#\s*pragma\s+.*?\b(?:startup|init_seg)\b")

_SYS_INCLUDE_RE = re.compile(r"#\s*include\s*<sys/([^>]+)>")
_UNISTD_INCLUDE_RE = re.compile(r"#\s*include\s*<unistd\.h>")
_LOCAL_INCLUDE_RE = re.compile(r'#\s*include\s*"([^"]+)"')

_DEFINE_ALIAS_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)")
_DEFINE_PASTE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*(?:\([^)]*\))?)\s+(.*##.*)$")


class ExecGuard(GuardAgent):
    name = "ExecGuard"
    handles = {InputKind.USER_SOURCE}

    def quick_match(self, ctx: GuardContext) -> bool:
        """Cheap signal check. Invariant: returns True if any trigger token is present."""
        if not ctx.payload:
            return False
        return any(token in ctx.payload for token in TRIGGER_TOKENS)

    def analyze(self, ctx: GuardContext) -> list[Finding]:
        source_dir_meta = ctx.meta.get("source_dir")
        source_dir = Path(source_dir_meta) if source_dir_meta else None
        header_counter = [0]
        visited_paths: set[Path] = set()

        return self._scan_source(
            payload=ctx.payload,
            source_dir=source_dir,
            depth=0,
            visited_paths=visited_paths,
            header_counter=header_counter,
        )

    def _scan_source(
        self,
        payload: str,
        source_dir: Path | None,
        depth: int,
        visited_paths: set[Path],
        header_counter: list[int],
    ) -> list[Finding]:
        # Enforce scan limit on payload
        if len(payload) > MAX_SCAN_BYTES:
            payload = payload[:MAX_SCAN_BYTES]

        allow_system_calls = os.environ.get("ALLOW_SYSTEM_CALLS") == "1"
        allow_assembly = os.environ.get("ALLOW_ASSEMBLY") == "1"
        allow_sys_includes = os.environ.get("ALLOW_SYS_INCLUDES") == "1"

        findings: list[Finding] = []
        raw_lines = payload.splitlines()
        state: dict[str, Any] = {"in_block_comment": False, "raw_delim": None}
        aliased_names: set[str] = set()

        for line_no, raw_line in enumerate(raw_lines, start=1):
            was_in_block_comment = bool(state.get("in_block_comment"))
            stripped_line = _strip_code(raw_line, state)
            is_in_block_comment = bool(state.get("in_block_comment"))

            # If entirely inside a block comment or line is empty after stripping comments/strings
            line_is_comment = (was_in_block_comment and is_in_block_comment) or raw_line.strip().startswith("//")

            # ── 1. Obfuscation ──────────────────────────────────────────────
            if not line_is_comment:
                # (a) #define NAME dangerous_identifier
                alias_match = _DEFINE_ALIAS_RE.match(raw_line)
                if alias_match:
                    macro_name, target_name = alias_match.group(1), alias_match.group(2)
                    if target_name in DANGEROUS_IDENTIFIERS:
                        aliased_names.add(macro_name)
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex[:8],
                                agents=["ExecGuard"],
                                origin="attack",
                                category="obfuscation",
                                severity="High",
                                title="Obfuscation: Dangerous Identifier Aliased",
                                description=f"Macro '{macro_name}' aliases dangerous identifier '{target_name}'.",
                                recommendation="Do not alias sensitive or execution-related system APIs.",
                                line=line_no,
                                column=None,
                                evidence=redact(raw_line),
                                action="block",
                                confidence=1.0,
                            )
                        )

                # (b) ## token pasting inside #define
                paste_match = _DEFINE_PASTE_RE.match(raw_line)
                if paste_match:
                    body = paste_match.group(2)
                    glued = re.sub(r"\s*##\s*", "", body)
                    is_dangerous_glue = any(d in glued for d in DANGEROUS_IDENTIFIERS)
                    findings.append(
                        Finding(
                            id=uuid.uuid4().hex[:8],
                            agents=["ExecGuard"],
                            origin="attack",
                            category="obfuscation",
                            severity="High" if is_dangerous_glue else "Medium",
                            title="Obfuscation: Macro Token Pasting",
                            description="Macro uses ## token pasting which can conceal dangerous function calls.",
                            recommendation="Avoid macro token concatenation for identifiers.",
                            line=line_no,
                            column=None,
                            evidence=redact(raw_line),
                            action="block" if is_dangerous_glue else "warn",
                            confidence=1.0,
                        )
                    )

            # ── 2. Process Execution ────────────────────────────────────────
            proc_match = _PROCESS_EXEC_RE.search(stripped_line)
            if proc_match or (aliased_names and any(re.search(rf"\b{re.escape(name)}\s*\(", stripped_line) for name in aliased_names)):
                desc = "Process execution or shell command invocation detected."
                if allow_system_calls:
                    sev = "Low"
                    act = "warn"
                    desc += " (permitted by policy toggle)"
                else:
                    sev = "High"
                    act = "block"

                findings.append(
                    Finding(
                        id=uuid.uuid4().hex[:8],
                        agents=["ExecGuard"],
                        origin="attack",
                        category="process_execution",
                        severity=sev,
                        title="Process Execution",
                        description=desc,
                        recommendation="Avoid spawning child processes or invoking shell commands.",
                        line=line_no,
                        column=None,
                        evidence=redact(raw_line),
                        action=act,
                        confidence=1.0,
                    )
                )

            # ── 3. Inline Assembly ──────────────────────────────────────────
            if _ASM_RE.search(stripped_line):
                desc = "Inline assembly statement detected."
                if allow_assembly:
                    sev = "Low"
                    act = "warn"
                    desc += " (permitted by policy toggle)"
                else:
                    sev = "High"
                    act = "block"

                findings.append(
                    Finding(
                        id=uuid.uuid4().hex[:8],
                        agents=["ExecGuard"],
                        origin="attack",
                        category="inline_assembly",
                        severity=sev,
                        title="Inline Assembly",
                        description=desc,
                        recommendation="Avoid low-level inline assembly instructions.",
                        line=line_no,
                        column=None,
                        evidence=redact(raw_line),
                        action=act,
                        confidence=1.0,
                    )
                )

            # ── 4. Dynamic Loading ──────────────────────────────────────────
            if _DYNAMIC_LOAD_RE.search(stripped_line):
                findings.append(
                    Finding(
                        id=uuid.uuid4().hex[:8],
                        agents=["ExecGuard"],
                        origin="attack",
                        category="dynamic_loading",
                        severity="High",
                        title="Dynamic Library Loading",
                        description="Dynamic module loading (dlopen/dlsym/LoadLibrary) detected.",
                        recommendation="Avoid runtime dynamic symbol resolution.",
                        line=line_no,
                        column=None,
                        evidence=redact(raw_line),
                        action="block",
                        confidence=1.0,
                    )
                )

            # ── 5. Network Access ───────────────────────────────────────────
            net_call = _NETWORK_CALL_RE.search(stripped_line)
            net_inc = _NETWORK_INCLUDE_RE.search(raw_line) if not line_is_comment else None
            if net_call or net_inc:
                findings.append(
                    Finding(
                        id=uuid.uuid4().hex[:8],
                        agents=["ExecGuard"],
                        origin="attack",
                        category="network_access",
                        severity="High",
                        title="Network Access",
                        description="Network socket API or network header include detected.",
                        recommendation="Network operations are restricted in code execution.",
                        line=line_no,
                        column=None,
                        evidence=redact(raw_line),
                        action="block",
                        confidence=1.0,
                    )
                )

            # ── 6. Sensitive File Access ────────────────────────────────────
            if _FILE_OPEN_RE.search(stripped_line):
                literals = _STRING_LITERAL_RE.findall(raw_line)
                for lit in literals:
                    is_abs = lit.startswith(("/", "\\")) or bool(re.match(r"^[a-zA-Z]:[/\\]", lit))
                    has_dotdot = ".." in lit
                    has_sensitive_name = any(
                        s in lit.lower()
                        for s in (".env", "id_rsa", "passwd", "shadow", ".ssh", ".aws", "credentials")
                    )
                    if is_abs or has_dotdot or has_sensitive_name:
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex[:8],
                                agents=["ExecGuard"],
                                origin="attack",
                                category="sensitive_file_access",
                                severity="High",
                                title="Sensitive File Access",
                                description=f"File open targeting sensitive, absolute, or traversing path: {lit}",
                                recommendation="Use restricted relative paths and avoid escaping directory bounds.",
                                line=line_no,
                                column=None,
                                evidence=redact(raw_line),
                                action="block",
                                confidence=1.0,
                            )
                        )
                        break

            # ── 7. Destructive File Op ──────────────────────────────────────
            if _DESTRUCTIVE_FILE_RE.search(stripped_line):
                literals = _STRING_LITERAL_RE.findall(raw_line)
                is_dangerous_destruct = any(
                    lit.startswith(("/", "\\")) or bool(re.match(r"^[a-zA-Z]:[/\\]", lit)) or ".." in lit
                    for lit in literals
                )
                findings.append(
                    Finding(
                        id=uuid.uuid4().hex[:8],
                        agents=["ExecGuard"],
                        origin="attack",
                        category="destructive_file_op",
                        severity="High" if is_dangerous_destruct else "Medium",
                        title="Destructive File Operation",
                        description="File deletion or modification API detected.",
                        recommendation="Ensure file operations are safe and bounded within working directory.",
                        line=line_no,
                        column=None,
                        evidence=redact(raw_line),
                        action="block" if is_dangerous_destruct else "warn",
                        confidence=1.0,
                    )
                )

            # ── 8. Secret Env Access ────────────────────────────────────────
            if _SECRET_ENV_RE.search(stripped_line):
                literals = _STRING_LITERAL_RE.findall(raw_line)
                if any(re.search(r"KEY|TOKEN|SECRET|PASSWORD|API", lit, re.IGNORECASE) for lit in literals):
                    findings.append(
                        Finding(
                            id=uuid.uuid4().hex[:8],
                            agents=["ExecGuard"],
                            origin="attack",
                            category="secret_env_access",
                            severity="High",
                            title="Secret Environment Access",
                            description="Environment variable read targeting sensitive credential name.",
                            recommendation="Do not read security tokens or API keys from environment.",
                            line=line_no,
                            column=None,
                            evidence=redact(raw_line),
                            action="block",
                            confidence=1.0,
                        )
                    )

            # ── 9. Startup Code ─────────────────────────────────────────────
            if not line_is_comment:
                if _STARTUP_ATTR_RE.search(raw_line) or _STARTUP_PRAGMA_RE.search(raw_line):
                    findings.append(
                        Finding(
                            id=uuid.uuid4().hex[:8],
                            agents=["ExecGuard"],
                            origin="attack",
                            category="startup_code",
                            severity="Medium",
                            title="Pre-Main Startup Code",
                            description="Startup constructor or pragma init_seg detected.",
                            recommendation="Avoid custom pre-main execution hooks.",
                            line=line_no,
                            column=None,
                            evidence=redact(raw_line),
                            action="warn",
                            confidence=1.0,
                        )
                    )

            # ── 10. Unsafe Includes ─────────────────────────────────────────
            if not line_is_comment:
                sys_inc_match = _SYS_INCLUDE_RE.search(raw_line)
                if sys_inc_match:
                    sub_header = sys_inc_match.group(1).lower()
                    if sub_header != "socket.h":  # Already covered under network_access
                        desc = f"Unsafe sys include <sys/{sys_inc_match.group(1)}> detected."
                        if allow_sys_includes:
                            sev = "Low"
                            act = "warn"
                            desc += " (permitted by policy toggle)"
                        else:
                            sev = "High"
                            act = "block"

                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex[:8],
                                agents=["ExecGuard"],
                                origin="attack",
                                category="unsafe_include",
                                severity=sev,
                                title="Unsafe System Include",
                                description=desc,
                                recommendation="Avoid platform-specific <sys/...> headers in portable code.",
                                line=line_no,
                                column=None,
                                evidence=redact(raw_line),
                                action=act,
                                confidence=1.0,
                            )
                        )

                if _UNISTD_INCLUDE_RE.search(raw_line):
                    findings.append(
                        Finding(
                            id=uuid.uuid4().hex[:8],
                            agents=["ExecGuard"],
                            origin="attack",
                            category="unsafe_include",
                            severity="Low",
                            title="Unsafe Include: unistd.h",
                            description="Include of <unistd.h> detected.",
                            recommendation="Use standard C++ alternatives where possible.",
                            line=line_no,
                            column=None,
                            evidence=redact(raw_line),
                            action="warn",
                            confidence=1.0,
                        )
                    )

            # ── 11. Local Headers Scanning ──────────────────────────────────
            if not line_is_comment:
                local_inc_match = _LOCAL_INCLUDE_RE.search(raw_line)
                if local_inc_match:
                    header_name = local_inc_match.group(1)
                    # Ignore absolute and '..' includes
                    is_abs = header_name.startswith(("/", "\\")) or bool(re.match(r"^[a-zA-Z]:[/\\]", header_name))
                    if not is_abs and ".." not in header_name and source_dir:
                        if depth < MAX_HEADER_DEPTH and header_counter[0] < MAX_HEADER_COUNT:
                            try:
                                resolved_source_dir = source_dir.resolve()
                                resolved_header_path = (resolved_source_dir / header_name).resolve()
                                if (
                                    resolved_header_path.is_relative_to(resolved_source_dir)
                                    and resolved_header_path.is_file()
                                    and resolved_header_path not in visited_paths
                                ):
                                    visited_paths.add(resolved_header_path)
                                    if resolved_header_path.stat().st_size <= MAX_HEADER_BYTES:
                                        header_counter[0] += 1
                                        header_code = resolved_header_path.read_text(
                                            encoding="utf-8", errors="ignore"
                                        )
                                        header_findings = self._scan_source(
                                            payload=header_code,
                                            source_dir=resolved_header_path.parent,
                                            depth=depth + 1,
                                            visited_paths=visited_paths,
                                            header_counter=header_counter,
                                        )
                                        for hf in header_findings:
                                            findings.append(
                                                Finding(
                                                    id=uuid.uuid4().hex[:8],
                                                    agents=["ExecGuard"],
                                                    origin=hf.origin,
                                                    category=hf.category,
                                                    severity=hf.severity,
                                                    title=hf.title,
                                                    description=f"{hf.description} (in header '{header_name}')",
                                                    recommendation=hf.recommendation,
                                                    line=line_no,
                                                    column=None,
                                                    evidence=redact(f"In header {header_name}: {hf.evidence}"),
                                                    action=hf.action,
                                                    confidence=hf.confidence,
                                                )
                                            )
                            except Exception:
                                pass

        return findings
