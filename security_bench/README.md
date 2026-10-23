# Attack Benchmark Manifest

This directory contains the version-controlled manifest of labelled attack and benign test cases evaluating the security layer.

## Integrity Rules
1. Fixed & Deterministic: Cases are version-controlled; no randomness or dynamic timestamps.
2. Static Only: Attack samples are never compiled or executed; reviewed statically only.
3. No Cheating: Detectors are never tuned to pass benchmark cases; misses on hard set are reported.
4. Isolated: Runs use temporary directories; no real credentials, models, or `.env` are touched.

## Schema
Each case in `manifest.json` defines:
- `id`: Unique identifier (e.g., `exec_001`, `scan_001`).
- `label`: `"attack"` or `"benign"`.
- `set`: `"standard"` or `"hard"`.
- `family`: Threat family (9 attack families + `scanner_evasion` limitation family).
- `kind`: `InputKind` string (`USER_SOURCE`, `HTTP_REQUEST`, `PATCH`, `DATASET_ENTRY`, `MODEL_FILE`).
- `purpose`: Evaluation purpose (`run`, `compile`, `ai_send`, `patch`, `request`, `dataset`, `model_load`, `display`, `analyze`).
- `payload`: Input string or code (omitted for `MODEL_FILE`).
- `meta`: Metadata dict (headers, original patch, stage, etc.).
- `expected_agents`: List of expected agents (empty for benign).
- `expected_category`: Expected primary finding category.
- `expected_origin`: Optional finding origin (`"attack"` or `"vulnerability"`).
- `prevention`: Expected action: `"block"`, `"neutralize"`, or `"warn"`.
- `notes`: Short descriptive summary.
