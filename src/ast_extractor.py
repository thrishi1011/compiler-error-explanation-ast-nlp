import os
import re
import subprocess


ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
NODE_RE = re.compile(r"^(?:[|` -]*)?([A-Za-z_][A-Za-z0-9_]*)(?:\s+(.*))?$")
ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")

MAX_TREE_DEPTH = 9
MAX_DETAIL_LENGTH = 220

VISIBLE_NODES = {
    "TranslationUnitDecl",
    "IncludeDecl",
    "NamespaceDecl",
    "UsingDecl",
    "UsingDirectiveDecl",
    "TypedefDecl",
    "TypeAliasDecl",
    "CXXRecordDecl",
    "ClassTemplateDecl",
    "FunctionTemplateDecl",
    "FunctionDecl",
    "CXXMethodDecl",
    "CXXConstructorDecl",
    "CXXDestructorDecl",
    "FieldDecl",
    "VarDecl",
    "ParmVarDecl",
    "EnumDecl",
    "EnumConstantDecl",
    "CompoundStmt",
    "DeclStmt",
    "IfStmt",
    "ForStmt",
    "CXXForRangeStmt",
    "WhileStmt",
    "DoStmt",
    "SwitchStmt",
    "CaseStmt",
    "DefaultStmt",
    "ReturnStmt",
    "BreakStmt",
    "ContinueStmt",
    "BinaryOperator",
    "CompoundAssignOperator",
    "UnaryOperator",
    "ConditionalOperator",
    "CallExpr",
    "CXXOperatorCallExpr",
    "CXXMemberCallExpr",
    "CXXConstructExpr",
    "CXXNewExpr",
    "CXXDeleteExpr",
    "ArraySubscriptExpr",
    "MemberExpr",
    "DeclRefExpr",
    "RecoveryExpr",
    "IntegerLiteral",
    "FloatingLiteral",
    "CharacterLiteral",
    "StringLiteral",
    "CXXBoolLiteralExpr",
    "CXXNullPtrLiteralExpr",
}


def _ast_depth(line):
    marker = re.search(r"(?:\|-|`-)", line)
    if not marker:
        return 0
    return marker.start() // 2 + 1


def _node_parts(line):
    stripped = line.lstrip(" |`-")
    match = NODE_RE.match(stripped)
    if not match:
        return None, ""
    return match.group(1), match.group(2) or ""


def _is_user_location(line, file_path):
    filename = os.path.basename(file_path)
    absolute = os.path.abspath(file_path)
    return f"<{filename}:" in line or f"<{absolute}:" in line or f", {filename}:" in line


def _has_explicit_external_location(line, file_path):
    if _is_user_location(line, file_path):
        return False
    return bool(re.search(r"</|, /|<[A-Za-z]:", line))


def _has_relative_location(line):
    return "<line:" in line or "<col:" in line


def _trim_details(details):
    details = ADDRESS_RE.sub("", details)
    details = " ".join(details.split())
    if len(details) > MAX_DETAIL_LENGTH:
        details = details[: MAX_DETAIL_LENGTH - 3].rstrip() + "..."
    return details


def generate_fallback_ast_text(code: str, file_path: str = "file.cpp") -> str:
    """Generate clang-like AST dump text directly from C++ source."""
    filename = os.path.basename(file_path) if file_path else "file.cpp"
    lines = code.splitlines()
    out = [f"TranslationUnitDecl <{filename}:1:1> {filename}"]

    include_re = re.compile(r"^\s*#include\s+([<\"][^>\"]+[>\"])")
    using_re = re.compile(r"^\s*using\s+namespace\s+(\w+)\s*;")
    func_re = re.compile(r"^\s*(?:[\w:*&<>\[\]]+\s+)+(\w+)\s*\(([^)]*)\)\s*\{?")
    var_re = re.compile(r"^\s*(?:const\s+)?(int|float|double|char|bool|long|short|unsigned|string|auto)\s+([^;]+);")
    return_re = re.compile(r"^\s*return\s*(.*?);")
    io_re = re.compile(r"^\s*(cin|cout)\s*(<<|>>)\s*(.*?);")
    control_re = re.compile(r"^\s*(if|for|while|switch)\s*\((.*?)\)")

    in_func = False

    for line_idx, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        inc_m = include_re.match(line)
        if inc_m:
            out.append(f"|-IncludeDecl <{filename}:{line_idx}:1> {inc_m.group(1)}")
            continue

        using_m = using_re.match(line)
        if using_m:
            out.append(f"|-UsingDirectiveDecl <{filename}:{line_idx}:1> namespace {using_m.group(1)}")
            continue

        func_m = func_re.match(line)
        if func_m and not any(line.startswith(k) for k in ("return", "if", "for", "while", "cin", "cout")):
            fname = func_m.group(1)
            params = func_m.group(2).strip()
            out.append(f"|-FunctionDecl <{filename}:{line_idx}:1> {fname} '({params})'")
            out.append(f"| `-CompoundStmt <{filename}:{line_idx}:1>")
            in_func = True
            continue

        if in_func:
            if line == "}":
                in_func = False
                continue

            var_m = var_re.match(line)
            if var_m:
                vtype = var_m.group(1)
                vbody = var_m.group(2).strip()
                out.append(f"|   |-DeclStmt <{filename}:{line_idx}:5>")
                out.append(f"|   | `-VarDecl <{filename}:{line_idx}:9> {vbody} '{vtype}'")
                continue

            io_m = io_re.match(line)
            if io_m:
                out.append(f"|   |-CallExpr <{filename}:{line_idx}:5> '{line}'")
                continue

            ret_m = return_re.match(line)
            if ret_m:
                out.append(f"|   |-ReturnStmt <{filename}:{line_idx}:5> 'return {ret_m.group(1).strip()}'")
                continue

            ctrl_m = control_re.match(line)
            if ctrl_m:
                kw = ctrl_m.group(1).capitalize() + "Stmt"
                out.append(f"|   |-{kw} <{filename}:{line_idx}:5> '{ctrl_m.group(2).strip()}'")
                continue

            out.append(f"|   |-CallExpr <{filename}:{line_idx}:5> '{line}'")

    return "\n".join(out)


def build_source_ast(code: str, file_path: str = "file.cpp") -> list:
    """Build a complete AST node tree directly from C++ code without external binaries."""
    ast_text = generate_fallback_ast_text(code, file_path)
    return parse_ast_to_tree(ast_text, file_path)


def extract_ast(file_path, code=None):
    """Return a compact clang AST dump containing only user-file subtrees, with fallback."""
    filtered = []
    if file_path:
        cmd = [
            "clang++",
            "-Xclang",
            "-ast-dump",
            "-fsyntax-only",
            "-fno-color-diagnostics",
            file_path,
        ]

        active_depth = None
        user_file_context = False

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            for raw_line in process.stdout:
                line = ANSI_RE.sub("", raw_line.rstrip("\n"))
                if not line.strip():
                    continue

                depth = _ast_depth(line)
                if active_depth is not None and depth <= active_depth:
                    active_depth = None

                if _has_explicit_external_location(line, file_path):
                    user_file_context = False

                if _is_user_location(line, file_path):
                    user_file_context = True

                starts_user_subtree = _is_user_location(line, file_path) or (
                    user_file_context and _has_relative_location(line)
                )

                if active_depth is None and starts_user_subtree:
                    active_depth = depth

                if active_depth is not None:
                    filtered.append(line)
            process.wait()
        except (OSError, Exception):
            filtered = []

    if filtered:
        return "\n".join(filtered)

    # Fallback when clang++ is unavailable or output is empty
    try:
        source_code = code
        if not source_code and file_path and os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source_code = f.read()
        if source_code:
            return generate_fallback_ast_text(source_code, file_path or "file.cpp")
    except Exception:
        pass

    return None


def parse_ast_to_tree(ast_text, file_path=None):
    if not ast_text:
        return []

    root_nodes = []
    stack = []

    for line in ast_text.splitlines():
        if not line.strip():
            continue

        depth = _ast_depth(line)
        node_type, details = _node_parts(line)
        if not node_type:
            continue

        while stack and stack[-1][0] >= depth:
            stack.pop()

        if depth > MAX_TREE_DEPTH or node_type not in VISIBLE_NODES:
            continue

        node = {
            "type": node_type,
            "details": _trim_details(details),
            "children": [],
        }

        if stack:
            stack[-1][1]["children"].append(node)
        else:
            root_nodes.append(node)

        stack.append((depth, node))

    return root_nodes


def extract_node_near_line(ast_text, line_number):
    if not ast_text or line_number is None:
        return None

    fallback = None

    for line in ast_text.splitlines():
        node_type, _ = _node_parts(line)
        if not node_type or node_type not in VISIBLE_NODES:
            continue

        if f":{line_number}:" in line or f"line:{line_number}" in line:
            if "Expr" in node_type or "Stmt" in node_type or "Decl" in node_type:
                return node_type
            fallback = fallback or node_type

    return fallback
