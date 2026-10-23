"""
src/quality_hints.py
--------------------
Deterministic code quality inspection heuristics for C++ source code.
Lightweight, linear-time, comment- and string-literal aware checks.
Never raises; never modifies source code; produces advisory hints.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from guard.lexutil import strip_code


def analyze_quality(source: str) -> Dict[str, Any]:
    """
    Analyzes C++ source code for stylistic, algorithmic, and performance heuristics.
    Returns:
      {
        "level": "Good" | "Fair" | "Needs work",
        "score": int,
        "hints": list[dict]  # each with id, line, title, message, suggestion, weight
      }
    """
    if not source or not isinstance(source, str):
        return {"level": "Good", "score": 0, "hints": []}

    try:
        hints: List[Dict[str, Any]] = []
        raw_lines = source.splitlines()

        # Step 1: Strip comments and strings line by line while preserving line numbers
        stripped_lines: List[str] = []
        state: Dict[str, Any] = {}
        for line in raw_lines:
            stripped = strip_code(line, state)
            stripped_lines.append(stripped)

        full_code = "\n".join(stripped_lines)

        def get_line_number(pos: int) -> int:
            return full_code.count("\n", 0, pos) + 1

        # Rule 4: strlen in loop condition: for/while (... strlen(...) ...)
        loop_cond_strlen_re = re.compile(
            r"\b(?:for\s*\([^;]*;[^;]*|while\s*\([^)]*)\bstrlen\s*\("
        )

        # Rule 6: push_back without reserve pre-scan
        vector_decl_re = re.compile(r"\b(?:std::)?vector\s*<[^>]+>\s+([a-zA-Z_]\w*)")
        reserve_call_re = re.compile(r"\b([a-zA-Z_]\w*)\.reserve\s*\(")

        # Rule 7: copy in range-for: for (std::string x : ...) or for (vector<...> x : ...)
        range_for_copy_re = re.compile(
            r"\bfor\s*\(\s*(?:const\s+)?(?:std::)?(string|vector\s*<[^>]+>|map\s*<[^>]+>|set\s*<[^>]+>)\s+([a-zA-Z_]\w*)\s*:"
        )

        declared_vectors: Set[str] = set()
        reserved_vectors: Set[str] = set()
        for sline in stripped_lines:
            for m in vector_decl_re.finditer(sline):
                declared_vectors.add(m.group(1))
            for m in reserve_call_re.finditer(sline):
                reserved_vectors.add(m.group(1))

        # Check line-based rules: Rule 7 (copy_in_range_for), Rule 2 (pass_by_value), Rule 4 (strlen_in_loop_condition)
        func_param_re = re.compile(r"\b([a-zA-Z_]\w*)\s*\(([^)]*)\)")
        non_func_keywords = {"if", "for", "while", "switch", "catch", "return", "sizeof", "decltype"}

        for idx, sline in enumerate(stripped_lines, 1):
            # Check for range-for copy (Rule 7)
            for m_rf in range_for_copy_re.finditer(sline):
                type_name = m_rf.group(1)
                var_name = m_rf.group(2)
                hints.append({
                    "id": "copy_in_range_for",
                    "line": idx,
                    "title": "Copy in range-for loop",
                    "message": f"Range-based for loop copies '{var_name}' ({type_name}) by value.",
                    "suggestion": "Heuristic suggestion, not a proven problem. Use const auto& to avoid copying elements during iteration.",
                    "weight": 1,
                })

            # Check for function parameter pass_by_value (Rule 2)
            for m_func in func_param_re.finditer(sline):
                fname = m_func.group(1)
                if fname in non_func_keywords:
                    continue
                params_str = m_func.group(2)
                if not params_str.strip():
                    continue

                raw_params: List[str] = []
                cur_param: List[str] = []
                t_depth = 0
                for ch in params_str:
                    if ch == "<":
                        t_depth += 1
                    elif ch == ">":
                        t_depth = max(0, t_depth - 1)
                    if ch == "," and t_depth == 0:
                        raw_params.append("".join(cur_param).strip())
                        cur_param = []
                    else:
                        cur_param.append(ch)
                if cur_param:
                    raw_params.append("".join(cur_param).strip())

                for p in raw_params:
                    m_heavy = re.match(
                        r"^(?:const\s+)?(?:std::)?(string|vector\s*<[^>]+>|map\s*<[^>]+>|set\s*<[^>]+>|unordered_map\s*<[^>]+>|unordered_set\s*<[^>]+>)(.*)$",
                        p,
                    )
                    if m_heavy:
                        tname = m_heavy.group(1)
                        rest = m_heavy.group(2)
                        if "&" not in rest and "*" not in rest:
                            var_part = re.sub(r"=.*$", "", rest).strip()
                            var_match = re.search(r"([a-zA-Z_]\w*)$", var_part)
                            var_name = var_match.group(1) if var_match else "param"
                            hints.append({
                                "id": "pass_by_value",
                                "line": idx,
                                "title": "Heavy parameter passed by value",
                                "message": f"Parameter '{var_name}' of type '{tname}' is passed by value.",
                                "suggestion": "Heuristic suggestion, not a proven problem. Pass by const reference (const T&) to avoid copying overhead.",
                                "weight": 1,
                            })

            # Check for strlen in loop condition (Rule 4)
            if loop_cond_strlen_re.search(sline):
                hints.append({
                    "id": "strlen_in_loop_condition",
                    "line": idx,
                    "title": "strlen() in loop condition",
                    "message": "strlen() evaluated in loop condition can lead to O(N^2) complexity.",
                    "suggestion": "Heuristic suggestion, not a proven problem. Store the string length in a local variable before the loop.",
                    "weight": 2,
                })

        # Step 2: Loop tracking across full_code
        # Find all loop headers
        loops = []
        n_code = len(full_code)
        loop_header_re = re.compile(r"\b(for|while)\s*\(")

        for m_hdr in loop_header_re.finditer(full_code):
            start_pos = m_hdr.start()
            kw = m_hdr.group(1)

            # Check while preceded by '}'
            if kw == "while":
                preceding = full_code[:start_pos].rstrip()
                if preceding.endswith("}"):
                    continue

            # Skip header to matching ')'
            p_depth = 1
            rp = -1
            for k in range(m_hdr.end(), n_code):
                if full_code[k] == "(":
                    p_depth += 1
                elif full_code[k] == ")":
                    p_depth -= 1
                    if p_depth == 0:
                        rp = k
                        break

            if rp == -1:
                continue

            # Find body start and end
            body_start = -1
            body_end = -1
            is_braced = False

            # Scan after rp for first non-whitespace
            cur = rp + 1
            while cur < n_code and full_code[cur].isspace():
                cur += 1

            if cur < n_code:
                if full_code[cur] == "{":
                    is_braced = True
                    body_start = cur
                    b_depth = 1
                    for k in range(cur + 1, n_code):
                        if full_code[k] == "{":
                            b_depth += 1
                        elif full_code[k] == "}":
                            b_depth -= 1
                            if b_depth == 0:
                                body_end = k
                                break
                    if body_end == -1:
                        body_end = n_code - 1
                else:
                    body_start = cur
                    semi = full_code.find(";", cur)
                    body_end = semi if semi != -1 else n_code - 1

            loop_obj = {
                "id": len(loops),
                "start": start_pos,
                "line": get_line_number(start_pos),
                "body_start": body_start,
                "body_end": body_end,
                "body": full_code[body_start : body_end + 1] if body_start != -1 else "",
            }
            loops.append(loop_obj)

        # Check loop nesting (Rule 1: nested_loops)
        root_nested_hints: Dict[int, Dict[str, Any]] = {}
        for l_curr in loops:
            enclosing = [
                b
                for b in loops
                if b["body_start"] <= l_curr["start"] <= b["body_end"]
                and b["id"] != l_curr["id"]
            ]
            nesting_depth = len(enclosing) + 1
            if nesting_depth >= 2:
                root_id = enclosing[0]["id"]
                if root_id in root_nested_hints:
                    if nesting_depth >= 3:
                        root_nested_hints[root_id]["weight"] = 3
                        root_nested_hints[root_id]["message"] = (
                            f"Loop nested {nesting_depth} levels deep; possible cubic or exponential behaviour."
                        )
                else:
                    h_nest = {
                        "id": "nested_loops",
                        "line": l_curr["line"],
                        "title": "Nested loop",
                        "message": (
                            f"Loop nested {nesting_depth} levels deep; possible quadratic behaviour."
                        ),
                        "suggestion": (
                            "Heuristic suggestion, not a proven problem. Consider algorithmic improvements, index lookups, or flattening."
                        ),
                        "weight": 3 if nesting_depth >= 3 else 2,
                    }
                    hints.append(h_nest)
                    root_nested_hints[root_id] = h_nest

        # Check inside-loop rules (Rules 3, 5, 6) across loop bodies
        reported_endl_lines: Set[int] = set()
        reported_concat_lines: Set[int] = set()
        reported_push_back_vecs: Set[str] = set()

        str_concat_pattern = re.compile(r"\b([a-zA-Z_]\w*)\s*=\s*([^;=]+\+[^;=]+);")

        for l_curr in loops:
            b_text = l_curr["body"]
            b_start = l_curr["body_start"]
            if not b_text or b_start == -1:
                continue

            # Rule 3: endl_in_loop
            for m_endl in re.finditer(r"\b(?:std::)?endl\b", b_text):
                abs_pos = b_start + m_endl.start()
                ln = get_line_number(abs_pos)
                if ln not in reported_endl_lines:
                    reported_endl_lines.add(ln)
                    hints.append({
                        "id": "endl_in_loop",
                        "line": ln,
                        "title": "endl in loop",
                        "message": "std::endl inside a loop flushes the output stream on every iteration.",
                        "suggestion": "Heuristic suggestion, not a proven problem. Use '\\n' instead of endl to avoid unnecessary stream flushes.",
                        "weight": 1,
                    })

            # Rule 5: string_concat_in_loop
            for m_sc in str_concat_pattern.finditer(b_text):
                lhs = m_sc.group(1)
                rhs = m_sc.group(2)
                if re.search(rf"\b{re.escape(lhs)}\b", rhs):
                    abs_pos = b_start + m_sc.start()
                    ln = get_line_number(abs_pos)
                    if ln not in reported_concat_lines:
                        reported_concat_lines.add(ln)
                        hints.append({
                            "id": "string_concat_in_loop",
                            "line": ln,
                            "title": "String concatenation in loop",
                            "message": f"Repeated string concatenation via '{lhs} = ... + ...' inside loop.",
                            "suggestion": "Heuristic suggestion, not a proven problem. Use '+=' or call reserve() before the loop to avoid reallocations.",
                            "weight": 1,
                        })

            # Rule 6: push_back_without_reserve
            for m_pb in re.finditer(r"\b([a-zA-Z_]\w*)\.push_back\s*\(", b_text):
                vec_name = m_pb.group(1)
                if vec_name in declared_vectors and vec_name not in reserved_vectors:
                    if vec_name not in reported_push_back_vecs:
                        reported_push_back_vecs.add(vec_name)
                        abs_pos = b_start + m_pb.start()
                        ln = get_line_number(abs_pos)
                        hints.append({
                            "id": "push_back_without_reserve",
                            "line": ln,
                            "title": "push_back without reserve",
                            "message": f"'{vec_name}.push_back()' called inside loop without prior reserve().",
                            "suggestion": "Heuristic suggestion, not a proven problem. Call reserve() before the loop if final capacity is known.",
                            "weight": 1,
                        })

        # Compute total score and level
        total_score = sum(h["weight"] for h in hints)
        if total_score <= 1:
            level = "Good"
        elif total_score <= 4:
            level = "Fair"
        else:
            level = "Needs work"

        return {
            "level": level,
            "score": total_score,
            "hints": hints,
        }

    except Exception:
        # Never raise
        return {"level": "Good", "score": 0, "hints": []}
