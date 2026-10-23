"""
tools/review_pending.py
-----------------------
Inspect quarantined pending training entries in data/pending_training.jsonl:
- Total count of pending entries
- Entry counts per category
- Top 20 most frequent messages

Retraining remains a manual step; pending entries are never automatically injected.
"""

from __future__ import annotations

import collections
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PENDING_FILE = os.environ.get("GUARD_PENDING_PATH") or os.path.join(PROJECT_ROOT, "data", "pending_training.jsonl")


def review_pending(file_path: str = PENDING_FILE) -> None:
    if not os.path.exists(file_path):
        print(f"No pending entries found: {file_path} does not exist.")
        return

    total = 0
    categories: collections.Counter = collections.Counter()
    messages: collections.Counter = collections.Counter()

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue

            total += 1
            cat = entry.get("category", "unknown")
            msg = entry.get("message") or entry.get("raw_message") or ""
            categories[cat] += 1
            if msg:
                messages[msg] += 1

    print("=" * 60)
    print("PENDING TRAINING DATASET REVIEW")
    print("=" * 60)
    print(f"Source file: {file_path}")
    print(f"Total pending entries: {total}")
    print("\nEntries per Category:")
    if not categories:
        print("  (None)")
    else:
        for cat, cnt in categories.most_common():
            print(f"  {cat:<25} : {cnt:>5}")

    print("\nTop 20 Most Frequent Messages:")
    if not messages:
        print("  (None)")
    else:
        for msg, cnt in messages.most_common(20):
            disp = (msg[:70] + "...") if len(msg) > 73 else msg
            print(f"  [{cnt:>3}x] {disp}")
    print("=" * 60)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else PENDING_FILE
    review_pending(target)
