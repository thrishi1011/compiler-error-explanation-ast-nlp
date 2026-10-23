"""
tools/sign_model.py
-------------------
Computes the SHA-256 cryptographic digest and byte size of an ML model file
(default: data/error_classifier.joblib) and writes or updates the signed entry in
data/model_manifest.json.

LIMITATION:
The manifest protects against an accidentally swapped, corrupted, or injected
model file. It does not protect against an attacker who possesses write access to
both the model file and data/model_manifest.json simultaneously.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("GUARD_DATA_DIR") or os.path.join(PROJECT_ROOT, "data")
DEFAULT_MODEL = os.path.join(DATA_DIR, "error_classifier.joblib")
MANIFEST_PATH = os.path.join(DATA_DIR, "model_manifest.json")


def sign_model(model_path: str = DEFAULT_MODEL, manifest_path: str = MANIFEST_PATH) -> dict:
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")

    sha = hashlib.sha256()
    size = 0
    with open(model_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            size += len(chunk)
            sha.update(chunk)

    sha256_hex = sha.hexdigest()
    model_name = os.path.basename(model_path)

    manifest_data = {}
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
        except Exception:
            manifest_data = {}

    entry = {
        "sha256": sha256_hex,
        "size": size,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    manifest_data[model_name] = entry

    os.makedirs(os.path.dirname(os.path.abspath(manifest_path)), exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    print(f"[sign_model] Signed {model_name}:")
    print(f"  SHA-256:   {sha256_hex}")
    print(f"  Size:      {size} bytes")
    print(f"  Manifest:  {manifest_path}")
    return entry


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL
    sign_model(target)
