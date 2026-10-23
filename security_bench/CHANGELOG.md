# Manifest Changelog: Category Label Alignments

The following 34 test cases in `security_bench/manifest.json` were corrected to align with the canonical finding category names emitted by each security detector. Because expected categories were corrected to the detector's specified names, category attribution is label-aligned and measures consistency rather than an independent metric.

| Case ID | Old (Erroneous) Expected Category | Corrected Expected Category | Detector / Rationale |
| :--- | :--- | :--- | :--- |
| `exec_009` | `process_execution` | `obfuscation` | `ExecGuard` emits `obfuscation` for macro token-pasting |
| `res_001` | `special_device_include` | `special_file_include` | `ResourceGuard` canonical category for `/dev/` includes |
| `res_002` | `unc_include` | `special_file_include` | `ResourceGuard` canonical category for UNC paths |
| `res_003` | `special_device_include` | `special_file_include` | `ResourceGuard` canonical category for Windows devices (`CON`, `NUL`) |
| `res_007` | `infinite_loop` | `possible_infinite_loop` | `ResourceGuard` canonical category for unbounded loops |
| `sec_003` | `special_file_include` | `sensitive_include` | `SecretsGuard` emits `sensitive_include` for `.env` includes |
| `sec_004` | `special_file_include` | `sensitive_include` | `SecretsGuard` emits `sensitive_include` for `/etc/shadow` |
| `sec_006` | `path_traversal_include` | `sensitive_include` | `SecretsGuard` emits `sensitive_include` for directory traversal |
| `sec_010` | `secret_leakage` | `hardcoded_secret` | `SecretsGuard` emits `hardcoded_secret` |
| `sec_011` | `secret_leakage` | `hardcoded_secret` | `SecretsGuard` emits `hardcoded_secret` |
| `disp_001` | `html_injection` | `display_injection` | `OutputGuard` canonical category for `<script>` tags |
| `disp_002` | `html_injection` | `display_injection` | `OutputGuard` canonical category for `<iframe>` tags |
| `disp_003` | `ansi_escape` | `terminal_escape` | `OutputGuard` canonical category for VT100 escapes |
| `disp_004` | `bidi_override` | `hidden_unicode` | `OutputGuard` canonical category for RTL/bidi overrides |
| `disp_005` | `spoofed_output` | `spoofed_status` | `OutputGuard` canonical category for status spoofing |
| `disp_006` | `untrusted_url` | `display_injection` | `OutputGuard` canonical category for javascript: URLs |
| `ep_014` | `bad_field_type` | `bad_body` | `EndpointGuard` emits `bad_body` for malformed payloads |
| `data_001` | `dataset_model_inconsistency` | `dataset_directive_message` | `IntegrityGuard` emits `dataset_directive_message` |
| `data_002` | `dataset_format_violation` | `dataset_bad_category` | `IntegrityGuard` emits `dataset_bad_category` |
| `data_003` | `dataset_format_violation` | `dataset_bad_message` | `IntegrityGuard` emits `dataset_bad_message` |
| `data_004` | `dataset_secret_leak` | `dataset_secret` | `IntegrityGuard` emits `dataset_secret` |
| `mod_002` | `model_missing_manifest` | `model_manifest_missing` | `IntegrityGuard` emits `model_manifest_missing` |
| `mod_003` | `model_path_traversal` | `model_outside_data_dir` | `IntegrityGuard` emits `model_outside_data_dir` |
| `prompt_004` | `prompt_injection` | `policy_bypass_request` | `PromptGuard` emits `policy_bypass_request` |
| `patch_004` | `patch_introduces_dangerous_code` | `patch_security_downgrade` | `PatchGuard` emits `patch_security_downgrade` |
| `patch_005` | `patch_introduces_dangerous_code` | `patch_security_downgrade` | `PatchGuard` emits `patch_security_downgrade` |
| `patch_006` | `patch_removes_safety_guard` | `patch_removes_guard` | `PatchGuard` emits `patch_removes_guard` |
| `patch_007` | `patch_removes_safety_guard` | `patch_removes_guard` | `PatchGuard` emits `patch_removes_guard` |
| `patch_008` | `patch_compiler_flag_override` | `patch_suppresses_diagnostics` | `PatchGuard` emits `patch_suppresses_diagnostics` |
| `patch_009` | `patch_secret_leak` | `patch_new_include` | `PatchGuard` emits `patch_new_include` |
| `patch_011` | `patch_data_marker` | `patch_marker_leak` | `PatchGuard` emits `patch_marker_leak` |
| `hard_009` | `prompt_injection` | `policy_bypass_request` | `PromptGuard` emits `policy_bypass_request` |
| `hard_010` | `prompt_injection` | `policy_bypass_request` | `PromptGuard` emits `policy_bypass_request` |
| `hard_011` | `patch_removes_safety_guard` | `patch_removes_guard` | `PatchGuard` emits `patch_removes_guard` |
