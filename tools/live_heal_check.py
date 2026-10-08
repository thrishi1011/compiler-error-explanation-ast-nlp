#!/usr/bin/env python3
"""
tools/live_heal_check.py
------------------------
Performs exactly 1 live heal check with real API keys.
Prints: provider, model, seconds, rounds, final g++ result.
NEVER prints or logs keys.
"""

import os
import sys
import time

_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TOOLS_DIR)
_SRC_DIR = os.path.join(_PROJECT_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import llm_client
from heal_engine import heal_until_clean, compile_source

TEST_CODE = """#include <iostream>
using namespace std;
int main() {
    int a = 40
    int b = 2;
    cout << "Answer: " << (a + b) << endl
    return 0;
}
"""

def main():
    llm_client.load_env_file()
    reset_needed = False
    
    t0 = time.time()
    res = heal_until_clean(TEST_CODE, use_ai=True, max_rounds=2)
    elapsed = round(time.time() - t0, 3)

    final_errs, final_warns, _ = compile_source(res.code)
    final_clean = len(final_errs) == 0

    first_round = res.rounds[0] if res.rounds else {}
    provider = first_round.get("model") or ("AI" if "AI" in first_round.get("method", "") else first_round.get("method", "offline"))
    method = first_round.get("method", "offline")
    rounds_count = len(res.rounds)

    print("=" * 60)
    print("LIVE HEAL RESULT:")
    print(f"Provider:        {provider}")
    print(f"Method:          {method}")
    print(f"Seconds:         {elapsed} s")
    print(f"Rounds:          {rounds_count}")
    print(f"Final G++ Clean: {final_clean} ({len(final_errs)} errors, {len(final_warns)} warnings)")
    print(f"Status Message:  {res.message}")
    print("=" * 60)

if __name__ == "__main__":
    main()
