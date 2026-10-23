from __future__ import annotations

import ast
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any

from .base import GuardAgent, GuardContext
from .config import MAX_SCAN_BYTES
from .lexutil import strip_code
from .models import Finding, InputKind
from .redact import redact

_QUICK_MATCH_TOKENS = (
    "#define",
    "#include",
    "while",
    "for",
    "do",
    "[",
    "vector",
    "new",
    "malloc",
    "calloc",
    "resize",
)

_INCLUDE_RE = re.compile(r'#\s*include\s*[<"]([^>"]+)[>"]')

_WIN_DEV_NAMES = (
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

_LOOP_HEADER_RE = re.compile(
    r"\b(?:while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\))"
)

_DO_HEADER_RE = re.compile(r"\bdo\s*\{")

_LOOP_ESCAPE_RE = re.compile(
    r"\b(break|return|exit|abort|terminate|throw|goto|_Exit|quick_exit)\b"
)

# Safe AST node types for constant expression evaluation
_SAFE_NODES = (
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.Constant,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.LShift,
    ast.RShift,
    ast.BitOr,
    ast.BitAnd,
    ast.BitXor,
    ast.USub,
    ast.UAdd,
)

_TYPE_SIZES = {
    "char": 1,
    "int8_t": 1,
    "uint8_t": 1,
    "bool": 1,
    "short": 2,
    "int16_t": 2,
    "uint16_t": 2,
    "int": 4,
    "int32_t": 4,
    "uint32_t": 4,
    "float": 4,
    "unsigned": 4,
    "long": 8,
    "int64_t": 8,
    "uint64_t": 8,
    "double": 8,
    "size_t": 8,
}


def _safe_eval_expr(expr_str: str) -> int | None:
    """
    Safely evaluates a literal integer or constant expression (+ * << >> | & ^ -)
    using ast.parse with whitelisted node types. Never uses eval on arbitrary AST.
    """
    if not expr_str:
        return None
    # Strip C++ integer suffixes like 1000ULL, 50ul, 1u, etc.
    cleaned = re.sub(r"\b(0x[0-9a-fA-F]+|\d+)[uUlL]+\b", r"\1", expr_str.strip())
    try:
        tree = ast.parse(cleaned, mode="eval")
        for node in ast.walk(tree):
            if not isinstance(node, _SAFE_NODES):
                return None
        val = eval(compile(tree, filename="", mode="eval"), {"__builtins__": {}})
        if isinstance(val, (int, float)):
            return int(val)
    except Exception:
        return None
    return None


class ResourceGuard(GuardAgent):
    name = "ResourceGuard"
    handles = {InputKind.USER_SOURCE}

    def quick_match(self, ctx: GuardContext) -> bool:
        payload = ctx.payload or ""
        if len(payload.encode("utf-8", errors="ignore")) > MAX_SCAN_BYTES:
            return True
        for line in payload.splitlines():
            if len(line) > 100_000:
                return True
        return any(t in payload for t in _QUICK_MATCH_TOKENS)

    def analyze(self, ctx: GuardContext) -> list[Finding]:
        findings: list[Finding] = []
        payload = ctx.payload or ""
        raw_lines = payload.splitlines()

        # ── 1. Oversized Input ───────────────────────────────────────────────
        payload_bytes = len(payload.encode("utf-8", errors="ignore"))
        if payload_bytes > MAX_SCAN_BYTES:
            findings.append(
                Finding(
                    id=uuid.uuid4().hex[:8],
                    agents=["ResourceGuard"],
                    origin="attack",
                    category="oversized_input",
                    severity="High",
                    title="Oversized Source Input",
                    description=f"Source size ({payload_bytes} bytes) exceeds {MAX_SCAN_BYTES} bytes limit.",
                    recommendation="Reduce source code size before submission.",
                    line=1,
                    column=None,
                    evidence=redact(f"Source size: {payload_bytes} bytes"),
                    action="block",
                    confidence=1.0,
                    blocks_on={"compile", "run"},
                )
            )

        for line_no, rline in enumerate(raw_lines, start=1):
            if len(rline) > 100_000:
                findings.append(
                    Finding(
                        id=uuid.uuid4().hex[:8],
                        agents=["ResourceGuard"],
                        origin="attack",
                        category="oversized_input",
                        severity="Medium",
                        title="Oversized Source Line",
                        description=f"Line {line_no} length ({len(rline)} chars) exceeds 100,000 limit.",
                        recommendation="Format code to avoid excessively long lines.",
                        line=line_no,
                        column=None,
                        evidence=redact(rline[:80]),
                        action="warn",
                        confidence=1.0,
                        blocks_on=set(),
                    )
                )

        # ── 2. Special File Include ──────────────────────────────────────────
        state: dict[str, Any] = {"in_block_comment": False, "raw_delim": None}
        for line_no, raw_line in enumerate(raw_lines, start=1):
            was_in_comment = bool(state.get("in_block_comment"))
            _ = strip_code(raw_line, state)
            is_in_comment = bool(state.get("in_block_comment"))
            if was_in_comment or is_in_comment or raw_line.strip().startswith("//"):
                continue

            inc_match = _INCLUDE_RE.search(raw_line)
            if inc_match:
                inc_target = inc_match.group(1).strip()
                target_norm = inc_target.replace("\\", "/")

                # Check special include targets
                is_special = False
                if target_norm.startswith(("/dev/", "/proc/", "/sys/")):
                    is_special = True
                elif inc_target.startswith(("\\\\", "//")):  # UNC network share
                    is_special = True
                elif inc_target.lower().startswith(("\\\\.\\pipe", "//./pipe")):
                    is_special = True
                else:
                    base_name = os.path.splitext(os.path.basename(target_norm))[0].upper()
                    if base_name in _WIN_DEV_NAMES or inc_target.upper() in _WIN_DEV_NAMES:
                        is_special = True

                if is_special:
                    findings.append(
                        Finding(
                            id=uuid.uuid4().hex[:8],
                            agents=["ResourceGuard"],
                            origin="attack",
                            category="special_file_include",
                            severity="High",
                            title="Special File Include",
                            description=f"Inclusion of special device, OS virtual file, or network path: {inc_target}",
                            recommendation="Do not include system device nodes or UNC shares.",
                            line=line_no,
                            column=None,
                            evidence=redact(raw_line),
                            action="block",
                            confidence=1.0,
                            blocks_on={"compile", "run"},
                        )
                    )

        # ── 3. Macro Expansion Bomb ──────────────────────────────────────────
        bomb_finding = self._check_macro_expansion_bomb(raw_lines)
        if bomb_finding:
            findings.append(bomb_finding)

        # ── 4. Huge Allocation & Infinite Loop ───────────────────────────────
        findings.extend(self._check_huge_allocations_and_loops(raw_lines))

        return findings

    def _check_macro_expansion_bomb(self, raw_lines: list[str]) -> Finding | None:
        macros: dict[str, dict[str, Any]] = {}
        define_re = re.compile(
            r"^\s*#\s*define\s+([A-Za-z_]\w*)(?:\(([^)]*)\))?\s*(.*)$"
        )

        for line_no, line in enumerate(raw_lines, start=1):
            m = define_re.match(line)
            if not m:
                continue
            name = m.group(1)
            params_raw = m.group(2)
            body = m.group(3) or ""
            params = [p.strip() for p in params_raw.split(",") if p.strip()] if params_raw is not None else []

            # Parameter expansion multiplier: max occurrences of any single parameter in body
            param_mult = 1
            if params:
                param_mult = max((len(re.findall(rf"\b{re.escape(p)}\b", body)) for p in params), default=1)
                if param_mult < 1:
                    param_mult = 1

            macros[name] = {
                "params": params,
                "param_mult": param_mult,
                "body": body,
                "line": line_no,
                "raw": line,
            }

        if not macros:
            return None

        # Build reference graph
        ref_graph: dict[str, list[str]] = {}
        for name, info in macros.items():
            refs = []
            for other in macros:
                if other != name and re.search(rf"\b{re.escape(other)}\b", info["body"]):
                    # Count how many times 'other' is called/referenced
                    occurrences = len(re.findall(rf"\b{re.escape(other)}\b", info["body"]))
                    for _ in range(occurrences):
                        refs.append(other)
            ref_graph[name] = refs

        # Estimate growth and nesting depth
        max_growth = 1.0
        max_depth = 0
        max_fanout = 0

        def evaluate_chain(m_name: str, visited: set[str], current_depth: int) -> tuple[float, int]:
            if m_name in visited or current_depth > 20:
                return (1.0, current_depth)
            visited.add(m_name)

            m_info = macros[m_name]
            growth = float(m_info["param_mult"])
            deepest = current_depth

            sub_refs = ref_graph.get(m_name, [])
            for ref in sub_refs:
                sub_growth, sub_depth = evaluate_chain(ref, set(visited), current_depth + 1)
                growth *= sub_growth
                if sub_depth > deepest:
                    deepest = sub_depth

            return growth, deepest

        for m_name in macros:
            fanout = len(ref_graph.get(m_name, []))
            if fanout > max_fanout:
                max_fanout = fanout
            g, d = evaluate_chain(m_name, set(), 1)
            if g > max_growth:
                max_growth = g
            if d > max_depth:
                max_depth = d

        # Also inspect call sites in code (e.g. D(D(1)))
        full_text = "\n".join(raw_lines)
        for m_name in macros:
            # Check for nested calls like D(D(
            if re.search(rf"\b{re.escape(m_name)}\s*\(\s*{re.escape(m_name)}\b", full_text):
                max_growth *= 2.0

        if max_growth >= 1_000_000 or (max_depth >= 8 and max_fanout >= 4):
            return Finding(
                id=uuid.uuid4().hex[:8],
                agents=["ResourceGuard"],
                origin="attack",
                category="macro_expansion_bomb",
                severity="High",
                title="Macro Expansion Bomb Detected",
                description=f"Estimated macro expansion growth ({max_growth:.0f}x, depth {max_depth}) indicates a compiler exhaustion bomb.",
                recommendation="Avoid recursive or exponentially compounding macro definitions.",
                line=1,
                column=None,
                evidence=redact(f"Max growth factor: ~{max_growth:.0f}x"),
                action="block",
                confidence=1.0,
                blocks_on={"compile", "run"},
            )

        return None

    def _check_huge_allocations_and_loops(self, raw_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        state: dict[str, Any] = {"in_block_comment": False, "raw_delim": None}

        # Regex patterns for huge allocations
        array_re = re.compile(
            r"\b([A-Za-z_]\w*)\s+[A-Za-z_]\w*\s*\[\s*([^\]]+)\s*\]"
        )
        new_re = re.compile(
            r"\bnew\s+([A-Za-z_]\w*)\s*\[\s*([^\]]+)\s*\]"
        )
        vector_re = re.compile(
            r"\bvector\s*<\s*([A-Za-z_]\w*)\s*>\s+[A-Za-z_]\w*\s*\(\s*([^)]+)\s*\)"
        )
        resize_re = re.compile(
            r"\.resize\s*\(\s*([^)]+)\s*\)"
        )
        malloc_re = re.compile(
            r"\bmalloc\s*\(\s*([^)]+)\s*\)"
        )
        calloc_re = re.compile(
            r"\bcalloc\s*\(\s*([^,]+),\s*([^)]+)\s*\)"
        )

        full_stripped_lines: list[str] = []

        for line_no, raw_line in enumerate(raw_lines, start=1):
            was_in_comment = bool(state.get("in_block_comment"))
            stripped = strip_code(raw_line, state)
            is_in_comment = bool(state.get("in_block_comment"))
            full_stripped_lines.append(stripped)

            if was_in_comment or is_in_comment or raw_line.strip().startswith("//"):
                continue

            # ── Check Array Declarations ────────────────────────────────────
            for m in array_re.finditer(stripped):
                elem_type = m.group(1)
                size_expr = m.group(2)
                # Ignore dynamic/pointer declarations or common keywords
                if elem_type in ("return", "delete", "goto", "else", "case"):
                    continue
                num_elems = _safe_eval_expr(size_expr)
                if num_elems is not None:
                    unit_size = _TYPE_SIZES.get(elem_type, 4)
                    total_bytes = num_elems * unit_size
                    if num_elems >= (1 << 28) or total_bytes >= (1 << 30):
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex[:8],
                                agents=["ResourceGuard"],
                                origin="attack",
                                category="huge_allocation",
                                severity="High",
                                title="Excessive Stack Allocation",
                                description=f"Array dimension ({num_elems} elements, ~{total_bytes // (1024*1024)} MB) exceeds resource limits.",
                                recommendation="Avoid static/stack allocations exceeding 1 GiB or 2^28 elements.",
                                line=line_no,
                                column=None,
                                evidence=redact(raw_line),
                                action="block",
                                confidence=1.0,
                                blocks_on={"run"},
                            )
                        )

            # ── Check new T[N] ──────────────────────────────────────────────
            for m in new_re.finditer(stripped):
                elem_type = m.group(1)
                size_expr = m.group(2)
                num_elems = _safe_eval_expr(size_expr)
                if num_elems is not None:
                    unit_size = _TYPE_SIZES.get(elem_type, 4)
                    total_bytes = num_elems * unit_size
                    if num_elems >= (1 << 28) or total_bytes >= (1 << 30):
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex[:8],
                                agents=["ResourceGuard"],
                                origin="attack",
                                category="huge_allocation",
                                severity="High",
                                title="Excessive Heap Allocation",
                                description=f"new[] allocation ({num_elems} elements, ~{total_bytes // (1024*1024)} MB) exceeds resource limits.",
                                recommendation="Cap heap dynamic allocations under 1 GiB.",
                                line=line_no,
                                column=None,
                                evidence=redact(raw_line),
                                action="block",
                                confidence=1.0,
                                blocks_on={"run"},
                            )
                        )

            # ── Check vector<T> v(N) ────────────────────────────────────────
            for m in vector_re.finditer(stripped):
                elem_type = m.group(1)
                size_expr = m.group(2)
                num_elems = _safe_eval_expr(size_expr)
                if num_elems is not None:
                    unit_size = _TYPE_SIZES.get(elem_type, 4)
                    total_bytes = num_elems * unit_size
                    if num_elems >= (1 << 28) or total_bytes >= (1 << 30):
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex[:8],
                                agents=["ResourceGuard"],
                                origin="attack",
                                category="huge_allocation",
                                severity="High",
                                title="Excessive Vector Allocation",
                                description=f"std::vector size ({num_elems} elements, ~{total_bytes // (1024*1024)} MB) exceeds resource limits.",
                                recommendation="Bound std::vector capacity under 1 GiB.",
                                line=line_no,
                                column=None,
                                evidence=redact(raw_line),
                                action="block",
                                confidence=1.0,
                                blocks_on={"run"},
                            )
                        )

            # ── Check .resize(N) ────────────────────────────────────────────
            for m in resize_re.finditer(stripped):
                size_expr = m.group(1)
                num_elems = _safe_eval_expr(size_expr)
                if num_elems is not None:
                    total_bytes = num_elems * 4
                    if num_elems >= (1 << 28) or total_bytes >= (1 << 30):
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex[:8],
                                agents=["ResourceGuard"],
                                origin="attack",
                                category="huge_allocation",
                                severity="High",
                                title="Excessive Container Resize",
                                description=f"Container resize ({num_elems} elements) exceeds resource limits.",
                                recommendation="Bound container capacity under 1 GiB.",
                                line=line_no,
                                column=None,
                                evidence=redact(raw_line),
                                action="block",
                                confidence=1.0,
                                blocks_on={"run"},
                            )
                        )

            # ── Check malloc(N) ─────────────────────────────────────────────
            for m in malloc_re.finditer(stripped):
                size_expr = m.group(1)
                total_bytes = _safe_eval_expr(size_expr)
                if total_bytes is not None and (total_bytes >= (1 << 30) or total_bytes >= (1 << 28)):
                    findings.append(
                        Finding(
                            id=uuid.uuid4().hex[:8],
                            agents=["ResourceGuard"],
                            origin="attack",
                            category="huge_allocation",
                            severity="High",
                            title="Excessive Malloc Allocation",
                            description=f"malloc byte count (~{total_bytes // (1024*1024)} MB) exceeds 1 GiB.",
                            recommendation="Bound memory allocations under 1 GiB.",
                            line=line_no,
                            column=None,
                            evidence=redact(raw_line),
                            action="block",
                            confidence=1.0,
                            blocks_on={"run"},
                        )
                    )

            # ── Check calloc(count, size) ───────────────────────────────────
            for m in calloc_re.finditer(stripped):
                count_expr = m.group(1)
                size_expr = m.group(2)
                c_val = _safe_eval_expr(count_expr)
                s_val = _safe_eval_expr(size_expr)
                if c_val is not None and s_val is not None:
                    total_bytes = c_val * s_val
                    if c_val >= (1 << 28) or total_bytes >= (1 << 30):
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex[:8],
                                agents=["ResourceGuard"],
                                origin="attack",
                                category="huge_allocation",
                                severity="High",
                                title="Excessive Calloc Allocation",
                                description=f"calloc allocation (~{total_bytes // (1024*1024)} MB) exceeds 1 GiB.",
                                recommendation="Bound memory allocations under 1 GiB.",
                                line=line_no,
                                column=None,
                                evidence=redact(raw_line),
                                action="block",
                                confidence=1.0,
                                blocks_on={"run"},
                            )
                        )

        # ── 5. Possible Infinite Loop ────────────────────────────────────────
        full_code = "\n".join(full_stripped_lines)
        for m in _LOOP_HEADER_RE.finditer(full_code):
            start_pos = m.end()
            # Extract loop body (brace-matched or until semicolon)
            body = self._extract_body(full_code, start_pos)
            if body is not None and not _LOOP_ESCAPE_RE.search(body):
                line_no = full_code[:m.start()].count("\n") + 1
                findings.append(
                    Finding(
                        id=uuid.uuid4().hex[:8],
                        agents=["ResourceGuard"],
                        origin="attack",
                        category="possible_infinite_loop",
                        severity="Medium",
                        title="Possible Infinite Loop",
                        description="Infinite loop condition without apparent break, return, or exit.",
                        recommendation="Verify loop termination condition or add explicit exit.",
                        line=line_no,
                        column=None,
                        evidence=redact(raw_lines[line_no - 1] if line_no <= len(raw_lines) else "while(true)"),
                        action="warn",
                        confidence=1.0,
                        blocks_on=set(),
                    )
                )

        return findings

    def _extract_body(self, code: str, pos: int) -> str | None:
        idx = pos
        while idx < len(code) and code[idx].isspace():
            idx += 1
        if idx >= len(code):
            return None

        if code[idx] == "{":
            depth = 1
            start = idx + 1
            idx += 1
            while idx < len(code):
                ch = code[idx]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return code[start:idx]
                idx += 1
            return code[start:idx]
        else:
            # Single statement body until semicolon
            semi = code.find(";", idx)
            if semi != -1:
                return code[idx : semi + 1]
            return code[idx : idx + 100]
