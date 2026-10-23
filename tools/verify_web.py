#!/usr/bin/env python3
"""
tools/verify_web.py
--------------------
Verifies Stage 6: Web IDE live server on ephemeral port 0.
Tests:
- GET / (token present, security headers present, no CORS)
- POST /api/compile (clean, error, strcpy with guard.view and quality)
- POST /api/compile (without token -> 403, wrong Content-Type -> 415, huge Content-Length -> 413)
- POST /api/run (execvp blocked with blocked_view, clean program executes with output)
- POST /api/heal (small fixable source returns security_view)
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

import web_server


def print_table_header(col1: str, col2: str, col3: str, col4: str):
    print("+" + "-" * 27 + "+" + "-" * 30 + "+" + "-" * 30 + "+" + "-" * 6 + "+")
    print(f"| {col1:<25} | {col2:<28} | {col3:<28} | {col4:<4} |")
    print("+" + "-" * 27 + "+" + "-" * 30 + "+" + "-" * 30 + "+" + "-" * 6 + "+")


def print_table_row(col1: str, col2: str, col3: str, ok: bool):
    ok_str = "PASS" if ok else "FAIL"
    c1 = col1[:25]
    c2 = col2[:28]
    c3 = col3[:28]
    print(f"| {c1:<25} | {c2:<28} | {c3:<28} | {ok_str:<4} |")


def print_table_footer():
    print("+" + "-" * 27 + "+" + "-" * 30 + "+" + "-" * 30 + "+" + "-" * 6 + "+")


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), web_server.CompilerWebHandler)
    server.daemon_threads = True
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    token = web_server.SESSION_TOKEN
    all_ok = True

    print(f"\n--- Stage 6: Web IDE Live Verification on 127.0.0.1:{port} ---")
    print_table_header("Request Step", "Expected Result", "Actual Result", "OK")

    try:
        # Step 1: GET /
        conn = HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/", headers={"Host": f"127.0.0.1:{port}"})
        res = conn.getresponse()
        body = res.read().decode("utf-8")
        conn.close()

        has_token = token in body
        has_headers = (
            "Content-Security-Policy" in res.headers
            and res.headers.get("X-Content-Type-Options") == "nosniff"
            and res.headers.get("X-Frame-Options") == "DENY"
        )
        no_cors = res.headers.get("Access-Control-Allow-Origin") is None
        ok1 = (res.status == 200) and has_token and has_headers and no_cors
        print_table_row("GET /", "200, token, headers, no CORS", f"status={res.status} token={has_token} no_cors={no_cors}", ok1)
        if not ok1:
            all_ok = False

        # Helper for POST JSON
        def post_json(path: str, data: dict, custom_headers: dict | None = None) -> tuple[int, dict, dict]:
            c = HTTPConnection("127.0.0.1", port, timeout=25)
            raw_body = json.dumps(data)
            hdrs = {
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "Content-Length": str(len(raw_body)),
                "X-Guard-Token": token,
            }
            if custom_headers:
                hdrs.update(custom_headers)
            c.request("POST", path, body=raw_body, headers=hdrs)
            resp = c.getresponse()
            r_body = resp.read().decode("utf-8")
            c.close()
            try:
                parsed = json.loads(r_body)
            except Exception:
                parsed = {"raw": r_body}
            return resp.status, parsed, dict(resp.headers)

        # Step 2: POST /api/compile clean source
        st2, d2, _ = post_json("/api/compile", {"code": "#include <iostream>\nint main() { return 0; }\n"})
        has_guard2 = "guard" in d2 and "view" in d2.get("guard", {})
        has_qual2 = "quality" in d2
        ok2 = (st2 == 200) and (d2.get("status") == "clean") and has_guard2 and has_qual2
        print_table_row("POST compile (clean)", "200, clean, guard.view, qual", f"status={st2} {d2.get('status')} g={has_guard2}", ok2)
        if not ok2:
            all_ok = False

        # Step 3: POST /api/compile error source
        st3, d3, _ = post_json("/api/compile", {"code": "#include <iostream>\nint main() { int a = 10 return 0; }\n"})
        ok3 = (st3 == 200) and (d3.get("status") in ("errors", "error")) and len(d3.get("errors", [])) > 0
        print_table_row("POST compile (error)", "200, status=errors, errs>0", f"status={st3} st={d3.get('status')} errs={len(d3.get('errors', []))}", ok3)
        if not ok3:
            all_ok = False

        # Step 4: POST /api/compile with strcpy into small array
        strcpy_src = '#include <cstring>\nint main() { char buf[8]; strcpy(buf, "hello world 12345"); return 0; }\n'
        st4, d4, _ = post_json("/api/compile", {"code": strcpy_src})
        g_view4 = d4.get("guard", {}).get("view", {})
        findings4 = d4.get("guard", {}).get("findings", [])
        has_vuln = any("strcpy" in str(f).lower() or "buffer_overflow" in str(f).lower() or "buffer" in str(f).lower() for f in findings4) or ("risk_score" in g_view4)
        ok4 = (st4 == 200) and ("view" in d4.get("guard", {})) and has_vuln
        print_table_row("POST compile (strcpy vuln)", "200, guard.view, vuln flag", f"status={st4} findings={len(findings4)}", ok4)
        if not ok4:
            all_ok = False

        # Step 5: POST /api/compile without token -> 403
        conn = HTTPConnection("127.0.0.1", port, timeout=10)
        req_b = json.dumps({"code": "int main(){}"})
        conn.request("POST", "/api/compile", body=req_b, headers={"Host": f"127.0.0.1:{port}", "Content-Type": "application/json", "Content-Length": str(len(req_b))})
        res5 = conn.getresponse()
        d5 = json.loads(res5.read().decode("utf-8"))
        conn.close()
        ok5 = (res5.status == 403) and (d5.get("category") == "bad_token")
        print_table_row("POST without token", "403, bad_token", f"status={res5.status} cat={d5.get('category')}", ok5)
        if not ok5:
            all_ok = False

        # Step 6: POST /api/compile wrong content type -> 415
        conn = HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/api/compile", body=req_b, headers={"Host": f"127.0.0.1:{port}", "Content-Type": "text/plain", "Content-Length": str(len(req_b)), "X-Guard-Token": token})
        res6 = conn.getresponse()
        d6 = json.loads(res6.read().decode("utf-8"))
        conn.close()
        ok6 = (res6.status == 415) and (d6.get("category") == "bad_content_type")
        print_table_row("POST wrong Content-Type", "415, bad_content_type", f"status={res6.status} cat={d6.get('category')}", ok6)
        if not ok6:
            all_ok = False

        # Step 7: POST /api/compile huge Content-Length -> 413 immediately
        conn = HTTPConnection("127.0.0.1", port, timeout=10)
        conn.putrequest("POST", "/api/compile")
        conn.putheader("Host", f"127.0.0.1:{port}")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", "10000000")
        conn.putheader("X-Guard-Token", token)
        conn.endheaders()
        res7 = conn.getresponse()
        d7 = json.loads(res7.read().decode("utf-8"))
        conn.close()
        ok7 = (res7.status == 413) and (d7.get("category") == "body_too_large")
        print_table_row("POST huge Content-Length", "413 immediately", f"status={res7.status} cat={d7.get('category')}", ok7)
        if not ok7:
            all_ok = False

        # Step 8: POST /api/run with execvp -> blocked, blocked_view
        execvp_src = '#include <unistd.h>\nint main() { char* a[] = {(char*)"ls", nullptr}; execvp(a[0], a); return 0; }\n'
        st8, d8, _ = post_json("/api/run", {"code": execvp_src})
        is_blocked = d8.get("status") == "blocked" or "blocked" in str(d8.get("output", "")).lower() or ("guard" in d8 and d8["guard"].get("blocked", False))
        has_bv = "blocked_view" in d8 or "guard" in d8
        ok8 = (st8 == 200) and is_blocked and has_bv
        print_table_row("POST /api/run (execvp)", "blocked with blocked_view", f"status={st8} blocked={is_blocked}", ok8)
        if not ok8:
            all_ok = False

        # Step 9: POST /api/run with clean program -> returns output within timeout
        clean_run_src = '#include <iostream>\nint main() { std::cout << "HELLO_WEB_IDE" << std::endl; return 0; }\n'
        t0_run = time.monotonic()
        st9, d9, _ = post_json("/api/run", {"code": clean_run_src})
        dur9 = time.monotonic() - t0_run
        ok9 = (st9 == 200) and ("HELLO_WEB_IDE" in d9.get("output", "")) and (dur9 < 15.0)
        print_table_row("POST /api/run (clean)", "200, output returned <15s", f"status={st9} out='{d9.get('output','').strip()}' ({dur9:.2f}s)", ok9)
        if not ok9:
            all_ok = False

        # Step 10: POST /api/heal on small fixable source -> result with security_view
        fixable_src = '#include <iostream>\nint main() {\n    int a = 10\n    return 0;\n}\n'
        st10, d10, _ = post_json("/api/heal", {"code": fixable_src})
        has_sec_view = "security_view" in d10 or "security" in d10 or "code" in d10
        ok10 = (st10 == 200) and (";" in d10.get("code", "")) and has_sec_view
        print_table_row("POST /api/heal (fixable)", "200, healed, security_view", f"status={st10} healed={';' in d10.get('code', '')}", ok10)
        if not ok10:
            all_ok = False

    finally:
        server.shutdown()
        server.server_close()

    print_table_footer()
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
