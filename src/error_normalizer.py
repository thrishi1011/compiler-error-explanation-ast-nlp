"""
error_normalizer.py
====================
Compiler Error Normalization and Explanation Engine.

Produces TWO distinct outputs from a raw compiler error message:

1. DATASET OUTPUT  — abstract, semantic, consistent (for ML training)
2. USER OUTPUT     — concrete, readable, friendly (for GUI/CLI display)

Rules:
  - NEVER store raw compiler-specific tokens in the dataset if they can be generalized.
  - ALWAYS preserve meaning, not surface syntax.
  - Dataset = abstract + consistent
  - UI     = concrete + readable
"""

import re
from typing import Tuple

# ---------------------------------------------------------------------------
# Token normalization table
# Maps raw compiler tokens → abstract semantic labels (for dataset storage)
# ---------------------------------------------------------------------------
_TOKEN_MAP = [
    # Punctuation / syntax tokens
    (r"';'",              "statement terminator"),
    (r"'}'",              "closing brace"),
    (r"'{'",              "opening brace"),
    (r"'\)'",             "closing parenthesis"),
    (r"'\('",             "opening parenthesis"),
    (r"'\]'",             "closing bracket"),
    (r"'\['",             "opening bracket"),
    (r"':'",              "colon"),
    (r"','",              "comma"),
    (r"'>>'",             "right shift / closing template bracket"),

    # Type tokens
    (r"'(int|float|double|char|bool|long|short|unsigned|signed|void|auto)'",
                          "type"),

    # Identifier-class tokens
    (r"'[a-zA-Z_][a-zA-Z0-9_]*'",   "identifier"),

    # Operator tokens
    (r"'[+\-\*/%=<>!&|^~]+='?",     "operator"),
]


def _ui_token(token: str) -> str:
    """Return a readable article+name for a raw token, e.g. ';' → 'a ;'"""
    clean = token.strip("'\"")
    vowels = "aeiouAEIOU"
    article = "an" if clean and clean[0] in vowels else "a"
    return f"{article} '{clean}'"


def normalize_for_dataset(raw_message: str) -> str:
    """
    Convert a raw compiler error message into a generalized, semantic form
    suitable for dataset storage and ML training.

    Example:
        "expected ';' after expression"
        → "expected statement terminator after expression"
    """
    result = raw_message
    for pattern, replacement in _TOKEN_MAP:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    # Collapse extra whitespace
    result = re.sub(r" {2,}", " ", result).strip()
    return result


def build_ui_message(raw_message: str) -> str:
    """
    Convert a raw compiler error message into a human-readable sentence
    for display in the GUI or CLI.

    Example:
        "expected ';' after expression"
        → "The compiler expected a ';' after the expression."
    """
    msg = raw_message.strip()

    # ── pattern: expected '<token>' [after/before] <context> ──
    m = re.match(
        r"expected\s+('.*?')\s*(after|before)?\s*(.*)",
        msg,
        re.IGNORECASE,
    )
    if m:
        token_raw, prep, context = m.group(1), m.group(2), m.group(3).strip()
        token_ui = _ui_token(token_raw)
        if prep and context:
            return f"The compiler expected {token_ui} {prep} {context}."
        elif context:
            return f"The compiler expected {token_ui} ({context})."
        else:
            return f"The compiler expected {token_ui}."

    # ── pattern: '<token>' was not declared in this scope ──
    m = re.match(r"'(.+?)'\s+was not declared in this scope", msg, re.IGNORECASE)
    if m:
        return f"'{m.group(1)}' was used but has not been declared in this scope."

    # ── pattern: use of undeclared identifier ──
    m = re.match(r"use of undeclared identifier '(.+?)'", msg, re.IGNORECASE)
    if m:
        return f"The identifier '{m.group(1)}' was used before it was declared."

    # ── pattern: cannot convert / invalid conversion ──
    m = re.match(
        r"(cannot convert|invalid conversion)\s+(?:from\s+)?'(.+?)'\s+to\s+'(.+?)'",
        msg,
        re.IGNORECASE,
    )
    if m:
        return (
            f"A value of type '{m.group(2)}' cannot be used where "
            f"'{m.group(3)}' is required."
        )

    # ── pattern: no matching function for call to '<fn>' ──
    m = re.match(r"no matching function for call to '(.+?)'", msg, re.IGNORECASE)
    if m:
        return (
            f"No overload of '{m.group(1)}' matches the arguments you provided. "
            f"Check the function signature and argument types."
        )

    # ── pattern: redeclaration / redefinition ──
    m = re.match(r"(redeclaration|redefinition) of '(.+?)'", msg, re.IGNORECASE)
    if m:
        action = "declared again" if "redeclaration" in m.group(1).lower() else "defined again"
        return f"'{m.group(2)}' has already been {action} in this scope."

    # ── pattern: '<token>' has not been declared ──
    m = re.match(r"'(.+?)' has not been declared", msg, re.IGNORECASE)
    if m:
        return f"'{m.group(1)}' is referenced but has not been declared."

    # ── pattern: return-type mismatch ──
    if re.search(r"return.*type|cannot.*return", msg, re.IGNORECASE):
        return f"The return value does not match the function's declared return type."

    # ── fallback: capitalize and append period ──
    sentence = msg[0].upper() + msg[1:] if msg else msg
    if not sentence.endswith("."):
        sentence += "."
    return sentence


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

def normalize_error(raw_message: str) -> Tuple[str, str]:
    """
    Main entry point.

    Returns:
        (dataset_message, ui_message)

        dataset_message — abstract, semantic, suitable for training_data.json
        ui_message      — readable, friendly, suitable for GUI/CLI display
    """
    dataset_msg = normalize_for_dataset(raw_message)
    ui_msg = build_ui_message(raw_message)
    return dataset_msg, ui_msg


# ---------------------------------------------------------------------------
# ML Classifier Normalization Engine
# ---------------------------------------------------------------------------

_PRESERVED_CPP_TOKENS = {
    # Keywords & basic types
    "int", "float", "double", "char", "bool", "void", "auto", "long", "short",
    "unsigned", "signed", "const", "static", "return", "class", "struct",
    "private", "protected", "public", "virtual", "namespace", "template",
    "new", "delete", "nullptr", "true", "false", "if", "else", "for", "while",
    "do", "switch", "case", "default", "break", "continue", "goto", "operator",
    "sizeof", "typedef", "typename", "using", "constexpr", "enum", "union",
    "friend", "inline", "explicit", "mutable", "this", "throw", "try", "catch",
    "main", "argc", "argv", "std",
    # Standard library symbols & containers
    "cout", "cin", "cerr", "endl", "ostream", "istream", "printf", "scanf",
    "fprintf", "string", "getline", "vector", "map", "set", "unordered_map",
    "unordered_set", "list", "queue", "stack", "deque", "array", "pair",
    "tuple", "optional", "sort", "find", "max", "min", "reverse", "count",
    "fill", "copy", "abs", "sqrt", "pow", "ceil", "floor", "unique_ptr",
    "shared_ptr", "make_unique", "make_shared", "assert", "INT_MAX", "INT_MIN",
    "size_t", "NULL",
    # Punctuation & operators
    ";", "}", "{", ")", "(", "]", "[", ":", ",", ">>", "<<", "=", "+", "-",
    "*", "/", "%", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "!", "&",
    "|", "^", "~", "++", "--", "+=", "-=", "*=", "/=", "->", ".", "::",
}

_PREFIX_REGEX = re.compile(r'^(?:[A-Za-z]:)?[^:\r\n]+:\d+(?::\d+)?: (?:fatal )?(?:error|warning|note):\s*')

def normalize_for_classifier(raw_message: str) -> str:
    """
    Normalizes a compiler diagnostic for ML classification:
    - Strips file paths, line/column numbers, and 'error:' / 'warning:' prefixes
    - Strips memory/hex addresses (0x...)
    - Preserves C++ keywords, types, standard library symbols, operators, and [-W...] flags
    - Masks arbitrary user identifiers in quotes to '<ID>'
    - Masks raw numeric literals to '<NUM>'
    - Trims and collapses whitespace
    """
    if not raw_message:
        return ""

    # 1. Strip file/line/col prefix if present
    msg = _PREFIX_REGEX.sub("", raw_message.strip())

    # 2. Normalize linker error text
    if "undefined reference to" in msg:
        m = re.search(r"undefined reference to [\'`\"]?([^\'\"\n]+)[\'`\"]?", msg)
        if m:
            sym = m.group(1).split("(")[0]
            if sym in _PRESERVED_CPP_TOKENS:
                return f"undefined reference to '{sym}'"
            return "undefined reference to '<ID>'"
        return "undefined reference to '<ID>'"

    # 3. Strip hex addresses
    msg = re.sub(r"\b0x[0-9a-fA-F]+\b", "<ADDR>", msg)

    # 4. Process quoted tokens: preserve keywords/types/std symbols/punctuation/flags, mask user IDs
    def _replace_quoted(match):
        token = match.group(1).strip()
        # If token is a warning flag or contains std types, preserve
        if token.startswith("-W") or token.startswith("std::") or token in _PRESERVED_CPP_TOKENS:
            return f"'{token}'"
        # Check compound standard types like 'std::vector<int>'
        if any(std_sym in token for std_sym in ["vector", "string", "map", "set", "pair", "tuple", "ostream", "istream"]):
            return f"'{token}'"
        # Check if punctuation
        if token in _PRESERVED_CPP_TOKENS:
            return f"'{token}'"
        # Otherwise it's a user identifier / custom name
        return "'<ID>'"

    # Replace both 'token' and `token`
    msg = re.sub(r"['`]([^'`\n]+)['`]", _replace_quoted, msg)

    # 5. Mask numbers outside identifiers/flags
    msg = re.sub(r"(?<![A-Za-z0-9_-])\b\d+\b(?![A-Za-z0-9_-])", "<NUM>", msg)

    # 6. Collapse multiple spaces
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg

