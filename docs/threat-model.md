# Siftsec Threat Model (STRIDE)

Siftsec scans untrusted AI model artifacts, MCP server configurations, and cloud/Kubernetes metadata. This document maps threats against the scanner itself to concrete mitigations and automated tests.

| Threat (STRIDE) | Attack Vector | Mitigation | Verified By |
| :--- | :--- | :--- | :--- |
| **Tampering / RCE** (Hostile Model Files) | Malicious `.pkl` / `.pt` `__reduce__` payloads | Static `pickletools.genops()` only; never `pickle.loads` or `torch.load` | `tests/test_local_scanners.py`, `tests/fuzz/test_local_fuzz.py` |
| **DoS / Resource Exhaustion** | Zip bombs in `.pt` / `.pth`, huge `safetensors` headers, 500 MB `config.json` | Cumulative uncompressed cap, compression ratio cap, bounded `f.read()` | `tests/test_local_scanners.py`, `tests/test_aibom_supply_chain.py` |
| **Tampering / Path Traversal** | Zip-slip (`../../etc/passwd`) or symlink escapes | Explicit `..` / absolute member rejection & `is_symlink()` skip | `tests/test_local_scanners.py` |
| **Information Disclosure** (Credentials) | AWS/API secrets leaked to stdout, logs, JSON, SARIF, or debug bundles | `redact()` in `BaseRule._build()`, logger `RedactingFilter`, redacted `--debug-bundle` | `tests/test_siftsec.py`, `tests/test_hardcore_stress_and_k8s.py` |
| **Tampering / Injection** (Reports) | Hostile resource names injecting shell/HCL/GFM/HTML/@mentions | `shlex.quote`, `json.dumps`, `escape_md()` (with newline/HTML/@mention neutralization) | `tests/unit/rules/test_aws_rules.py`, `test_fuzz_escape_md_blocks_html_tables_and_mentions` |
| **Information Disclosure** (Reports) | World-readable scan reports (`0644`) or partial writes | `atomic_write_secure()` (`0600` on POSIX, `os.fsync`, `os.replace`) | `tests/test_reporters_and_cli.py` |
| **Elevation of Privilege** (Plugins) | Untrusted third-party entry-point rule packs | `--no-plugins` opt-out, `siftsec plugins` inspection, AST purity tests | `tests/test_hardcore_stress_and_k8s.py` |
