"""
tools/mutate_and_compile.py
---------------------------
Applies realistic single mutations across 155 base programs in data/v2/base_programs/,
compiles them using real g++ (-std=c++17 -Wall -fsyntax-only) with a strict 20s timeout,
verifies categories against docs/label_definitions.md, deduplicates, and incrementally
appends valid records to data/v2/mutations.jsonl.

Features:
- Cap of 150 records per category
- Pure -fsyntax-only (skips linker mutations for speed)
- Realistic identifier pool (50 names)
- 3-minute hard time budget
- Incremental .jsonl append & resume
"""

import os
import re
import csv
import json
import time
import hashlib
import random
import argparse
import tempfile
import threading
import subprocess
from typing import List, Dict, Tuple, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_PROGRAMS_DIR = os.path.join(BASE_DIR, "data", "v2", "base_programs")
MANIFEST_PATH = os.path.join(BASE_DIR, "data", "v2", "manifest.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "v2", "mutations.jsonl")

# Realistic names pool (50 identifiers)
REALISTIC_NAMES = [
    "item_count", "buffer_ptr", "total_sum", "max_val", "cur_node",
    "prev_ptr", "step_count", "target_sum", "is_valid", "temp_score",
    "data_block", "result_code", "index_pos", "weight_val", "capacity_limit",
    "entry_record", "lookup_table", "calc_average", "process_batch", "validate_input",
    "init_state", "flush_buffer", "reset_metrics", "parse_header", "fetch_next",
    "elem_size", "status_flag", "min_cost", "delta_time", "read_cursor",
    "write_cursor", "active_flag", "max_depth", "node_degree", "edge_weight",
    "sample_rate", "matrix_dim", "hash_seed", "token_stream", "payload_len",
    "retry_limit", "batch_index", "window_size", "chunk_size", "offset_val",
    "scale_factor", "threshold_val", "peak_value", "cached_entry", "next_state"
]

# Standard library symbols mapping from auto_healer
_SYMBOL_TO_HEADER = {
    "cout": "iostream", "cin": "iostream", "cerr": "iostream",
    "endl": "iostream", "ostream": "iostream", "istream": "iostream",
    "printf": "cstdio", "scanf": "cstdio", "fprintf": "cstdio",
    "string": "string", "getline": "string",
    "vector": "vector", "map": "map", "set": "set",
    "unordered_map": "unordered_map", "unordered_set": "unordered_set",
    "list": "list", "queue": "queue", "stack": "stack",
    "deque": "deque", "array": "array", "pair": "utility",
    "tuple": "tuple", "optional": "optional",
    "sort": "algorithm", "find": "algorithm", "max": "algorithm",
    "min": "algorithm", "reverse": "algorithm", "count": "algorithm",
    "fill": "algorithm", "copy": "algorithm",
    "abs": "cmath", "sqrt": "cmath", "pow": "cmath",
    "ceil": "cmath", "floor": "cmath",
    "unique_ptr": "memory", "shared_ptr": "memory", "make_unique": "memory",
    "make_shared": "memory",
    "assert": "cassert", "INT_MAX": "climits", "INT_MIN": "climits",
    "size_t": "cstddef", "nullptr": "", "NULL": "cstdlib",
}

DIAG_REGEX = re.compile(r'^(?:[A-Za-z]:)?[^:\r\n]+:\d+(?::\d+)?: (?:fatal )?(error|warning|note): (.*)$')
LINKER_REGEX = re.compile(r'undefined reference to [\'`"]?([^\'"\n]+)[\'`"]?')

def verify_category_from_message(msg: str) -> Optional[str]:
    m_lower = msg.lower()

    if "undefined reference to" in msg or "ld returned 1 exit status" in msg:
        return "linker_error"

    if "no such file or directory" in m_lower or "did you forget to '#include" in m_lower or "expects \"filename\"" in m_lower:
        return "missing_include"
    
    if "is not a member of 'std'" in msg or "is not a member of std" in msg:
        return "missing_include"

    undeclared_match = re.search(r"['`]([a-zA-Z_0-9:]+)['`] was not declared in this scope", msg)
    if not undeclared_match:
        undeclared_match = re.search(r"use of undeclared identifier ['`]([a-zA-Z_0-9:]+)['`]", msg)
    if undeclared_match:
        sym = undeclared_match.group(1).split("::")[-1]
        if sym in _SYMBOL_TO_HEADER:
            return "missing_include"
        else:
            return "name_resolution"

    if (
        "is private within this context" in m_lower
        or "is protected within this context" in m_lower
        or "assignment of read-only" in m_lower
        or "discards qualifiers" in m_lower
    ):
        return "access_error"

    if (
        "[-wreturn-type]" in m_lower
        or "control reaches end of non-void function" in m_lower
        or "no return statement in function returning non-void" in m_lower
        or "return with a value, in function returning void" in m_lower
        or "return with no value, in function returning" in m_lower
        or "return-statement with no value" in m_lower
        or "'main' must return 'int'" in m_lower
        or "in return" in m_lower and ("cannot convert" in m_lower or "invalid conversion" in m_lower)
    ):
        return "return_type_error"

    if (
        "redefinition of" in m_lower
        or "redeclaration of" in m_lower
        or "conflicting declaration" in m_lower
        or "multiple definition of" in m_lower
    ):
        return "redefinition"

    if (
        "[-wunused-variable]" in m_lower
        or "[-wunused-but-set-variable]" in m_lower
        or "[-wunused-parameter]" in m_lower
        or "[-wsign-compare]" in m_lower
        or "[-wparentheses]" in m_lower
        or "[-wdiv-by-zero]" in m_lower
        or "[-wempty-body]" in m_lower
        or "division by zero" in m_lower
    ):
        return "other"

    if (
        "cannot convert" in m_lower
        or "invalid conversion" in m_lower
        or "invalid operands of types" in m_lower
        or "no matching function for call" in m_lower
        or "too few arguments to function" in m_lower
        or "too many arguments to function" in m_lower
        or "subscripted value is neither array nor pointer" in m_lower
        or "subscripted value is not an array" in m_lower
        or "cannot be used as a function" in m_lower
        or "invalid use of void" in m_lower
        or "no match for 'operator" in m_lower
        or "could not convert" in m_lower
        or "request for member" in m_lower and "in something not a structure" in m_lower
    ):
        return "type_error"

    if (
        "does not name a type" in m_lower
        or "is not a member of" in m_lower
        or "has no member named" in m_lower
        or "has not been declared" in m_lower
    ):
        return "name_resolution"

    if (
        "expected" in m_lower
        or "stray" in m_lower
        or "missing terminating" in m_lower
        or "unterminated" in m_lower
        or "expected primary-expression" in m_lower
        or "expected ';'" in m_lower
        or "expected '}'" in m_lower
        or "expected ')'" in m_lower
        or "expected unqualified-id" in m_lower
        or "expected initializer" in m_lower
        or "two or more data types in declaration specifiers" in m_lower
    ):
        return "syntax_error"

    return None

def extract_first_diagnostic(stderr: str) -> Tuple[Optional[str], Optional[str]]:
    lines = stderr.splitlines()
    for line in lines:
        line_s = line.strip()
        if not line_s:
            continue
        if "undefined reference to" in line_s:
            m = LINKER_REGEX.search(line_s)
            ref_name = m.group(1) if m else "symbol"
            return line_s, f"undefined reference to '{ref_name}'"
        m = DIAG_REGEX.match(line_s)
        if m:
            dtype = m.group(1)
            msg = m.group(2)
            if dtype in ("error", "warning"):
                return line_s, msg
    return None, None

def generate_mutations_for_program(prog_id: str, code: str) -> List[Dict]:
    mutants = []
    lines = code.splitlines(keepends=True)
    rng = random.Random(hash(prog_id) & 0xFFFFFFFF)

    def _add_mutant(target_cat: str, mtype: str, src: str):
        m_hash = hashlib.md5(src.encode("utf-8")).hexdigest()[:10]
        mut_id = f"{prog_id}_{target_cat}_{mtype}_{m_hash}"
        mutants.append({
            "mutant_id": mut_id,
            "program_id": prog_id,
            "target_cat": target_cat,
            "mutation_type": mtype,
            "source": src,
            "is_linker": False
        })

    # 1. SYNTAX_ERROR mutations
    semi_candidates = [i for i, l in enumerate(lines) if l.strip().endswith(";") and not l.strip().startswith("//")]
    for idx in rng.sample(semi_candidates, min(len(semi_candidates), 5)):
        mut_lines = list(lines)
        mut_lines[idx] = re.sub(r';\s*$', '\n', mut_lines[idx])
        _add_mutant("syntax_error", "delete_semicolon", "".join(mut_lines))

    for idx in rng.sample(semi_candidates, min(len(semi_candidates), 3)):
        mut_lines = list(lines)
        mut_lines[idx] = re.sub(r';\s*$', ':\n', mut_lines[idx])
        _add_mutant("syntax_error", "semicolon_to_colon", "".join(mut_lines))
        mut_lines2 = list(lines)
        mut_lines2[idx] = re.sub(r';\s*$', ',\n', mut_lines2[idx])
        _add_mutant("syntax_error", "semicolon_to_comma", "".join(mut_lines2))

    brace_candidates = [i for i, l in enumerate(lines) if "}" in l and not l.strip().startswith("//")]
    for idx in rng.sample(brace_candidates, min(len(brace_candidates), 3)):
        mut_lines = list(lines)
        mut_lines[idx] = mut_lines[idx].replace("}", "", 1)
        _add_mutant("syntax_error", "delete_closing_brace", "".join(mut_lines))

    paren_candidates = [i for i, l in enumerate(lines) if ")" in l and not l.strip().startswith("//")]
    for idx in rng.sample(paren_candidates, min(len(paren_candidates), 3)):
        mut_lines = list(lines)
        mut_lines[idx] = mut_lines[idx].replace(")", "", 1)
        _add_mutant("syntax_error", "delete_closing_paren", "".join(mut_lines))

    str_candidates = [i for i, l in enumerate(lines) if '"' in l and not l.strip().startswith("#include")]
    for idx in rng.sample(str_candidates, min(len(str_candidates), 2)):
        mut_lines = list(lines)
        last_q = mut_lines[idx].rfind('"')
        if last_q != -1:
            mut_lines[idx] = mut_lines[idx][:last_q] + mut_lines[idx][last_q+1:]
            _add_mutant("syntax_error", "unterminated_string", "".join(mut_lines))

    if len(lines) > 5:
        mut_lines = list(lines)
        mut_lines[5] = "@\n" + mut_lines[5]
        _add_mutant("syntax_error", "stray_char", "".join(mut_lines))

    # 2. MISSING_INCLUDE mutations
    include_candidates = [i for i, l in enumerate(lines) if l.strip().startswith("#include")]
    for idx in include_candidates:
        mut_lines = list(lines)
        del mut_lines[idx]
        _add_mutant("missing_include", "remove_include", "".join(mut_lines))

    for idx in rng.sample(include_candidates, min(len(include_candidates), 2)):
        mut_lines = list(lines)
        mut_lines[idx] = '#include <nonexistent_math_vector_lib.h>\n'
        _add_mutant("missing_include", "bad_include_name", "".join(mut_lines))

    using_candidates = [i for i, l in enumerate(lines) if "using namespace std;" in l]
    for idx in using_candidates:
        mut_lines = list(lines)
        del mut_lines[idx]
        _add_mutant("missing_include", "remove_using_namespace_std", "".join(mut_lines))

    main_idx = next((i for i, l in enumerate(lines) if "main(" in l), -1)
    for sym, hdr in [("std::queue<int> q_missing_inc;", "<queue>"),
                     ("std::tuple<int, int> tup_missing_inc;", "<tuple>"),
                     ("std::map<int, std::string> map_missing_inc;", "<map>"),
                     ("std::vector<double> vec_missing_inc;", "<vector>")]:
        if hdr not in code and main_idx != -1:
            mut_lines = list(lines)
            mut_lines.insert(main_idx + 2, f"    {sym}\n")
            _add_mutant("missing_include", "inject_unincluded_symbol", "".join(mut_lines))

    # 3. NAME_RESOLUTION mutations (Realistic names)
    var_decl_matches = []
    for i, l in enumerate(lines):
        m = re.search(r'\b(int|double|float|auto|long long|bool|char)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=', l)
        if m and m.group(2) not in ("main", "argc", "argv") and m.group(2) not in _SYMBOL_TO_HEADER:
            var_decl_matches.append((i, m.group(2)))

    for idx, var_name in rng.sample(var_decl_matches, min(len(var_decl_matches), 3)):
        r_name = rng.choice(REALISTIC_NAMES) + "_renamed"
        mut_lines = list(lines)
        mut_lines[idx] = re.sub(r'\b' + var_name + r'\b', r_name, mut_lines[idx], count=1)
        _add_mutant("name_resolution", "rename_var_decl", "".join(mut_lines))

    if main_idx != -1:
        r_var = rng.choice(REALISTIC_NAMES)
        r_fn = rng.choice(REALISTIC_NAMES)
        r_cls = rng.choice(REALISTIC_NAMES).title().replace("_", "") + "Handler"
        mut_lines = list(lines)
        mut_lines.insert(main_idx + 2, f"    {r_var} = 100;\n")
        _add_mutant("name_resolution", "reference_undeclared_var", "".join(mut_lines))
        mut_lines2 = list(lines)
        mut_lines2.insert(main_idx + 2, f"    {r_fn}(42);\n")
        _add_mutant("name_resolution", "call_undeclared_func", "".join(mut_lines2))
        mut_lines3 = list(lines)
        mut_lines3.insert(main_idx + 2, f"    {r_cls} my_obj_instance;\n")
        _add_mutant("name_resolution", "undeclared_type_instance", "".join(mut_lines3))

    member_candidates = [i for i, l in enumerate(lines) if "." in l or "->" in l]
    for idx in rng.sample(member_candidates, min(len(member_candidates), 2)):
        r_field = rng.choice(REALISTIC_NAMES)
        mut_lines = list(lines)
        mut_lines.insert(idx + 1, f"    auto nonexistent_m = auto_obj.{r_field};\n")
        _add_mutant("name_resolution", "nonexistent_member", "".join(mut_lines))

    # 4. TYPE_ERROR mutations
    if main_idx != -1:
        for stmt in ["int err_type_str = \"cannot_assign_string_to_int\";",
                     "int* err_ptr_conv = 42;",
                     "int err_op_plus = \"hello\" + 5;",
                     "int err_call_non = 10; err_call_non();",
                     "int err_subscript = 5; err_subscript[0] = 1;",
                     "double* d_ptr = nullptr; int i_val = d_ptr;"]:
            mut_lines = list(lines)
            mut_lines.insert(main_idx + 2, f"    {stmt}\n")
            _add_mutant("type_error", "incompatible_assignment", "".join(mut_lines))

    call_candidates = [i for i, l in enumerate(lines) if re.search(r'\b[a-zA-Z_][a-zA-Z0-9_]*\s*\([a-zA-Z0-9_, ]+\);', l) and not l.strip().startswith("//")]
    for idx in rng.sample(call_candidates, min(len(call_candidates), 3)):
        mut_lines = list(lines)
        mut_lines[idx] = re.sub(r'\(([^)]+)\)', '("invalid_str_arg", 999.99, "extra_arg")', mut_lines[idx])
        _add_mutant("type_error", "wrong_arg_types_call", "".join(mut_lines))

    # 5. RETURN_TYPE_ERROR mutations
    for idx, l in enumerate(lines):
        if "int main(" in l:
            mut_lines = list(lines)
            mut_lines[idx] = l.replace("int main(", "void main(")
            _add_mutant("return_type_error", "void_main", "".join(mut_lines))
            break

    non_void_func_returns = []
    for i, l in enumerate(lines):
        if l.strip().startswith("return ") and "main" not in l and i > 5:
            non_void_func_returns.append(i)
    for idx in rng.sample(non_void_func_returns, min(len(non_void_func_returns), 4)):
        mut_lines = list(lines)
        mut_lines[idx] = "// " + mut_lines[idx]
        _add_mutant("return_type_error", "delete_return_stmt", "".join(mut_lines))
        mut_lines2 = list(lines)
        mut_lines2[idx] = "    return;\n"
        _add_mutant("return_type_error", "empty_return_in_non_void", "".join(mut_lines2))
        mut_lines3 = list(lines)
        mut_lines3[idx] = '    return "completely_invalid_return_type_string";\n'
        _add_mutant("return_type_error", "return_wrong_type", "".join(mut_lines3))

    void_func_indices = [i for i, l in enumerate(lines) if l.strip().startswith("void ") and "{" in l]
    for idx in rng.sample(void_func_indices, min(len(void_func_indices), 3)):
        mut_lines = list(lines)
        mut_lines.insert(idx + 1, "    return 42;\n")
        _add_mutant("return_type_error", "return_val_in_void_func", "".join(mut_lines))

    # 6. REDEFINITION mutations
    if main_idx != -1:
        r_name1 = rng.choice(REALISTIC_NAMES)
        r_name2 = rng.choice(REALISTIC_NAMES)
        mut_lines = list(lines)
        mut_lines.insert(main_idx + 2, f"    int {r_name1} = 1;\n    int {r_name1} = 2;\n")
        _add_mutant("redefinition", "duplicate_var_decl", "".join(mut_lines))
        mut_lines2 = list(lines)
        mut_lines2.insert(main_idx + 2, f"    double {r_name2} = 1.0;\n    int {r_name2} = 2;\n")
        _add_mutant("redefinition", "conflicting_type_decl", "".join(mut_lines2))

    func_indices = [i for i, l in enumerate(lines) if re.match(r'^(?:void|int|bool|double)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(', l) and "main" not in l]
    for idx in rng.sample(func_indices, min(len(func_indices), 2)):
        depth = 0
        end_idx = idx
        for j in range(idx, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            if depth == 0 and "{" in "".join(lines[idx:j+1]):
                end_idx = j
                break
        if end_idx > idx:
            func_block = lines[idx:end_idx+1]
            mut_lines = list(lines)
            mut_lines[end_idx+1:end_idx+1] = ["\n"] + func_block
            _add_mutant("redefinition", "duplicate_func_def", "".join(mut_lines))

    # 7. ACCESS_ERROR mutations
    if main_idx != -1:
        r_ro1 = rng.choice(REALISTIC_NAMES)
        r_ro2 = rng.choice(REALISTIC_NAMES)
        for stmt in [f"const int {r_ro1} = 100; {r_ro1} = 200;",
                     f"const double {r_ro2} = 3.14159; {r_ro2} += 1.0;",
                     "const char ro_ch = 'A'; ro_ch = 'B';",
                     "const int ro_arr[3] = {1, 2, 3}; ro_arr[0] = 5;"]:
            mut_lines = list(lines)
            mut_lines.insert(main_idx + 2, f"    {stmt}\n")
            _add_mutant("access_error", "assign_to_const", "".join(mut_lines))

    if "class " in code and "private:" in code and main_idx != -1:
        mut_lines = list(lines)
        c_m = re.search(r'\bclass\s+([a-zA-Z_][a-zA-Z0-9_]*)', code)
        if c_m:
            c_name = c_m.group(1)
            mut_lines.insert(main_idx + 2, f"    {c_name} private_test_obj;\n    private_test_obj.balance = 9999;\n")
            _add_mutant("access_error", "access_private_member", "".join(mut_lines))

    # 8. OTHER (compiler warnings under -Wall) mutations
    if main_idx != -1:
        r_un = rng.choice(REALISTIC_NAMES)
        other_snippets = [
            (f"int {r_un} = 42;", "unused_variable"),
            ("int s_cmp_val = -1; unsigned int u_cmp_val = 10; if (s_cmp_val < u_cmp_val) {}", "signed_unsigned_compare"),
            ("int a_paren_warn = 0; int b_paren_warn = 1; if (a_paren_warn = b_paren_warn) {}", "parentheses_assignment"),
            ("int div_zero_warn = 100 / 0;", "division_by_zero"),
            ("int empty_body_flag = 1; if (empty_body_flag);", "empty_body"),
            ("int set_not_used_var = 10; set_not_used_var = 20;", "unused_but_set_variable"),
        ]
        for snippet, mtype in other_snippets:
            mut_lines = list(lines)
            mut_lines.insert(main_idx + 2, f"    {snippet}\n")
            _add_mutant("other", mtype, "".join(mut_lines))

    return mutants

def compile_mutant(mutant: Dict) -> Optional[Dict]:
    prog_id = mutant["program_id"]
    source = mutant["source"]

    with tempfile.NamedTemporaryFile(suffix=".cpp", delete=False, mode="w", encoding="utf-8") as f:
        f.write(source)
        src_path = f.name

    try:
        # All mutants use fast -fsyntax-only
        cmd = ["g++", "-std=c++17", "-Wall", "-fsyntax-only", src_path]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        raw_line, msg_first = extract_first_diagnostic(proc.stderr)

        if not msg_first:
            return None

        verified_cat = verify_category_from_message(msg_first)
        if not verified_cat:
            return None

        return {
            "mutant_id": mutant["mutant_id"],
            "program_id": prog_id,
            "mutation_type": mutant["mutation_type"],
            "target_cat": mutant["target_cat"],
            "category": verified_cat,
            "message_raw": raw_line,
            "message_first_line": msg_first,
            "exit_code": proc.returncode
        }
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None
    finally:
        if os.path.exists(src_path):
            try: os.remove(src_path)
            except: pass

def main():
    parser = argparse.ArgumentParser(description="Mutate and compile base programs using g++.")
    parser.add_argument("--workers", type=int, default=8, help="Number of parallel compiler workers.")
    parser.add_argument("--category_cap", type=int, default=150, help="Max records per category.")
    parser.add_argument("--max_time_sec", type=int, default=180, help="Max total execution time in seconds.")
    args = parser.parse_args()

    print("=== Step 2: Fast Top-Up Mutation Compilation ===")
    print(f"Workers: {args.workers} | Cap per category: {args.category_cap} | Max time: {args.max_time_sec}s")

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    completed_mutant_ids = set()
    prog_msg_seen = set()
    global_msg_counter = Counter()
    cat_counts = Counter()

    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    completed_mutant_ids.add(rec.get("mutant_id", ""))
                    prog_msg_seen.add((rec["program_id"], rec["message_first_line"], rec["category"]))
                    global_msg_counter[rec["message_first_line"]] += 1
                    cat_counts[rec["category"]] += 1
                except Exception:
                    pass
        print(f"Resuming: found {len(completed_mutant_ids)} existing valid mutants in {OUTPUT_PATH}.")

    # Load manifest
    manifest_programs = []
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            manifest_programs.append(row)

    all_mutants = []
    for row in manifest_programs:
        pid = row["program_id"]
        filepath = row["filepath"]
        if not os.path.exists(filepath):
            continue
        with open(filepath, "r", encoding="utf-8") as fp:
            code = fp.read()
        mutants = generate_mutations_for_program(pid, code)
        all_mutants.extend(mutants)

    rng = random.Random(42)
    rng.shuffle(all_mutants)

    def _should_include(m):
        if m["mutant_id"] in completed_mutant_ids:
            return False
        if cat_counts[m["target_cat"]] >= args.category_cap:
            return False
        return True

    pending_mutants = [m for m in all_mutants if _should_include(m)]
    print(f"Generated {len(all_mutants)} total mutants. Pending compilations needed: {len(pending_mutants)}.")

    total_to_run = len(pending_mutants)
    if total_to_run == 0:
        print("All target categories already reached cap!")
        print("\n--- Current Counts Per Category ---")
        for cat in sorted(cat_counts.keys()):
            print(f"  {cat:20s}: {cat_counts[cat]:5d}")
        return

    write_lock = threading.Lock()
    compiles_done = 0
    start_time = time.time()
    stop_early = False

    def _record_result(res: Optional[Dict]):
        nonlocal compiles_done
        if res:
            with write_lock:
                key = (res["program_id"], res["message_first_line"], res["category"])
                if key not in prog_msg_seen:
                    m_line = res["message_first_line"]
                    if global_msg_counter[m_line] < 15 and cat_counts[res["category"]] < args.category_cap:
                        prog_msg_seen.add(key)
                        global_msg_counter[m_line] += 1
                        cat_counts[res["category"]] += 1
                        with open(OUTPUT_PATH, "a", encoding="utf-8") as f_out:
                            f_out.write(json.dumps(res, ensure_ascii=False) + "\n")
                            f_out.flush()

    print(f"Starting compilation (max {args.max_time_sec}s)...")
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(compile_mutant, mut): mut for mut in pending_mutants}
        for future in as_completed(futures):
            compiles_done += 1
            res = future.result()
            _record_result(res)

            elapsed = time.time() - start_time
            if elapsed >= args.max_time_sec:
                print(f"\n[Time Budget Reached] Stopped at {elapsed:.1f}s.")
                stop_early = True
                for f in futures:
                    f.cancel()
                break

            if compiles_done % 200 == 0 or compiles_done == total_to_run:
                rate = compiles_done / elapsed if elapsed > 0 else 0
                remaining = (total_to_run - compiles_done) / rate if rate > 0 else 0
                pct = (compiles_done / total_to_run) * 100
                total_valid = sum(cat_counts.values())
                print(f"[Progress] {compiles_done}/{total_to_run} ({pct:5.1f}%) | "
                      f"Elapsed: {elapsed:5.1f}s | Rate: {rate:4.1f} c/s | Valid: {total_valid}",
                      flush=True)

    total_elapsed = time.time() - start_time
    print(f"\nTop-up completed in {total_elapsed:.1f}s.")
    print(f"Total records in {OUTPUT_PATH}: {sum(cat_counts.values())}")
    print("\n--- Counts Per Category ---")
    for cat in sorted(cat_counts.keys()):
        print(f"  {cat:20s}: {cat_counts[cat]:5d}")
    print("---------------------------")

if __name__ == "__main__":
    main()
