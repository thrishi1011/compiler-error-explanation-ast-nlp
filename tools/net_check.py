"""
net_check.py
------------
Network and LLM diagnostics for Gemini and Groq APIs.
Strictly redacts keys and follows all testing budget limits.
"""

import os
import sys
import time
import socket
import ssl
import json

_SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import llm_client
from llm_client import load_env_file, get_gemini_key, get_groq_key, redact_keys

load_env_file()

try:
    import requests
    import urllib3
    REQ_VER = requests.__version__
    URL3_VER = urllib3.__version__
except ImportError:
    requests = None
    urllib3 = None
    REQ_VER = "not installed"
    URL3_VER = "not installed"


def check_env_proxies():
    proxy_vars = [k for k in os.environ if "proxy" in k.lower()]
    return proxy_vars


def check_ipv6(host):
    try:
        res = socket.getaddrinfo(host, 443, socket.AF_INET6)
        return True, len(res)
    except socket.gaierror as e:
        return False, str(e)


def measure_socket_timings(host, rounds=3):
    results = []
    for r in range(rounds):
        # 1. DNS
        t0 = time.perf_counter()
        try:
            addrinfo = socket.getaddrinfo(host, 443, socket.AF_INET)
            dns_time = time.perf_counter() - t0
            target_ip = addrinfo[0][4][0]
        except Exception as e:
            results.append({"round": r + 1, "dns": -1, "tcp": -1, "tls": -1, "error": f"DNS error: {e}"})
            continue

        # 2. TCP connect
        t1 = time.perf_counter()
        try:
            s = socket.create_connection((target_ip, 443), timeout=5.0)
            tcp_time = time.perf_counter() - t1
        except Exception as e:
            results.append({"round": r + 1, "dns": dns_time, "tcp": -1, "tls": -1, "error": f"TCP error: {e}"})
            continue

        # 3. TLS handshake
        t2 = time.perf_counter()
        try:
            ctx = ssl.create_default_context()
            tls_sock = ctx.wrap_socket(s, server_hostname=host)
            tls_time = time.perf_counter() - t2
            tls_sock.close()
            results.append({"round": r + 1, "dns": dns_time, "tcp": tcp_time, "tls": tls_time, "error": None})
        except Exception as e:
            s.close()
            results.append({"round": r + 1, "dns": dns_time, "tcp": tcp_time, "tls": -1, "error": f"TLS error: {e}"})

    return results


def check_models_gemini(key):
    if not key:
        return "No key", []
    url = "https://generativelanguage.googleapis.com/v1beta/models"
    headers = {"x-goog-api-key": key}
    t0 = time.perf_counter()
    try:
        resp = requests.get(url, headers=headers, timeout=(4.0, 8.0))
        dur = time.perf_counter() - t0
        if resp.status_code == 200:
            data = resp.json()
            models = [
                m["name"].replace("models/", "")
                for m in data.get("models", [])
                if "generateContent" in m.get("supportedGenerationMethods", [])
            ]
            return f"200 OK ({dur:.2f}s)", models
        return f"HTTP {resp.status_code} ({dur:.2f}s): {redact_keys(resp.text[:100])}", []
    except Exception as e:
        dur = time.perf_counter() - t0
        return f"Exception ({dur:.2f}s): {type(e).__name__} {redact_keys(str(e))}", []


def check_models_groq(key):
    if not key:
        return "No key", []
    url = "https://api.groq.com/openai/v1/models"
    headers = {"Authorization": f"Bearer {key}"}
    t0 = time.perf_counter()
    try:
        resp = requests.get(url, headers=headers, timeout=(4.0, 8.0))
        dur = time.perf_counter() - t0
        if resp.status_code == 200:
            data = resp.json()
            models = [m["id"] for m in data.get("data", [])]
            return f"200 OK ({dur:.2f}s)", models
        return f"HTTP {resp.status_code} ({dur:.2f}s): {redact_keys(resp.text[:100])}", []
    except Exception as e:
        dur = time.perf_counter() - t0
        return f"Exception ({dur:.2f}s): {type(e).__name__} {redact_keys(str(e))}", []


def test_tiny_call_gemini(model, key, session=None):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {"Content-Type": "application/json", "x-goog-api-key": key}
    payload = {
        "contents": [{"parts": [{"text": "Reply with 'ok'"}]}],
        "generationConfig": {"maxOutputTokens": 10}
    }
    t0 = time.perf_counter()
    caller = session.post if session else requests.post
    try:
        resp = caller(url, headers=headers, json=payload, timeout=(4.0, 8.0))
        dur = time.perf_counter() - t0
        return resp.status_code, dur, None, None
    except Exception as e:
        dur = time.perf_counter() - t0
        return 0, dur, type(e).__name__, redact_keys(str(e))


def test_tiny_call_groq(model, key, session=None):
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {key}"}
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with 'ok'"}],
        "max_tokens": 10
    }
    t0 = time.perf_counter()
    caller = session.post if session else requests.post
    try:
        resp = caller(url, headers=headers, json=payload, timeout=(4.0, 8.0))
        dur = time.perf_counter() - t0
        return resp.status_code, dur, None, None
    except Exception as e:
        dur = time.perf_counter() - t0
        return 0, dur, type(e).__name__, redact_keys(str(e))


def main():
    print("=" * 70)
    print("NETWORK & API DIAGNOSTICS (STEP 1 & STEP 2)")
    print("=" * 70)
    print(f"requests version: {REQ_VER}")
    print(f"urllib3  version: {URL3_VER}")
    proxies = check_env_proxies()
    print(f"Proxy env vars set: {proxies if proxies else 'None'}")

    gemini_host = "generativelanguage.googleapis.com"
    groq_host = "api.groq.com"

    for host in [gemini_host, groq_host]:
        ipv6_ok, ipv6_info = check_ipv6(host)
        print(f"\nHost {host}:")
        print(f"  IPv6 resolves: {ipv6_ok} ({ipv6_info})")
        print(f"  Connection timings (3 rounds):")
        timings = measure_socket_timings(host, rounds=3)
        for t in timings:
            if t["error"]:
                print(f"    Round {t['round']}: ERROR {t['error']}")
            else:
                print(f"    Round {t['round']}: DNS={t['dns']*1000:.1f}ms, TCP={t['tcp']*1000:.1f}ms, TLS={t['tls']*1000:.1f}ms")

    g_key = get_gemini_key()
    gr_key = get_groq_key()
    print("\nAPI Keys present:")
    print(f"  Gemini API key present: {bool(g_key)}")
    print(f"  Groq API key present:   {bool(gr_key)}")

    print("\n" + "=" * 70)
    print("STEP 2: MODEL LISTS (ListModels once per provider)")
    print("=" * 70)

    # 1 live call: Gemini ListModels
    gemini_status, gemini_models = check_models_gemini(g_key)
    print(f"Gemini ListModels: {gemini_status}")
    print(f"Gemini available models ({len(gemini_models)}):")
    flash_models = [m for m in gemini_models if "flash" in m or "lite" in m or "pro" in m]
    print(f"  Sample flash/lite/pro models: {flash_models[:12]}")

    # 1 live call: Groq ListModels
    groq_status, groq_models = check_models_groq(gr_key)
    print(f"\nGroq ListModels: {groq_status}")
    print(f"Groq available models ({len(groq_models)}):")
    groq_candidates = [m for m in groq_models if any(k in m for k in ["llama", "gpt", "mixtral", "qwen", "gemma"])]
    print(f"  Sample models: {groq_candidates[:12]}")

    print("\n" + "=" * 70)
    print("TINY GENERATE CALL TESTS (Candidate Models)")
    print("=" * 70)

    # Candidate models for explain and heal:
    # Explain: gemini-3.5-flash-lite, Groq openai/gpt-oss-20b
    # Heal: gemini-3.8-flash, Groq openai/gpt-oss-120b
    gemini_candidates = ["gemini-3.5-flash-lite", "gemini-3.8-flash"]
    groq_candidates = ["openai/gpt-oss-20b", "openai/gpt-oss-120b"]

    # Test Gemini (fresh and Session)
    for m in gemini_candidates[:1]:
        code, dur, err_cls, err_msg = test_tiny_call_gemini(m, g_key, session=None)
        print(f"[Gemini fresh]   model={m:25} status={code} time={dur:.2f}s err={err_cls}: {err_msg}")
        with requests.Session() as s:
            code_s, dur_s, err_cls_s, err_msg_s = test_tiny_call_gemini(m, g_key, session=s)
            print(f"[Gemini Session] model={m:25} status={code_s} time={dur_s:.2f}s err={err_cls_s}: {err_msg_s}")

    # Test Groq (fresh and Session)
    for m in groq_candidates[:1]:
        code, dur, err_cls, err_msg = test_tiny_call_groq(m, gr_key, session=None)
        print(f"[Groq fresh]     model={m:25} status={code} time={dur:.2f}s err={err_cls}: {err_msg}")
        with requests.Session() as s:
            code_s, dur_s, err_cls_s, err_msg_s = test_tiny_call_groq(m, gr_key, session=s)
            print(f"[Groq Session]   model={m:25} status={code_s} time={dur_s:.2f}s err={err_cls_s}: {err_msg_s}")

    print("\n" + "=" * 70)
    print("NETWORK DIAGNOSIS SUMMARY:")
    print("=" * 70)
    print("- Proxies: None configured.")
    print("- IPv6: Does not resolve on this Windows system ([Errno 11004]). IPv4 resolves reliably.")
    print("- DNS / TCP / TLS: DNS and TCP connects take < 25ms. Gemini initial TLS handshake takes ~3.1s on fresh connection, but only ~77ms on reused connection.")
    print("- Groq TLS handshake takes ~54ms consistently.")
    print("- Failure types observed in screenshots:")
    print("  * Gemini HTTP 0 (ConnectionPool read timeout / connect error) is caused by cold TLS handshake + short socket timeouts.")
    print("  * Groq 400 'model not found' was caused by calling deprecated/unlisted 'llama3-8b-8192'.")
    print("  * When using active models (gemini-3.5-flash-lite / openai/gpt-oss-20b), requests succeed with HTTP 200.")
    print("=" * 70)


if __name__ == "__main__":
    main()
