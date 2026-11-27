# Migration Guide: `tensorguard` / `ai_spm` → `siftsec`

The project has been renamed from **`tensorguard` / `ai_spm`** to **`siftsec`** to reflect its role as a multi-scanner correlation and prioritization layer rather than a standalone ASPM scanner.

## Summary of Breaking Changes

| Item | Old (`tensorguard` / `ai_spm`) | New (`siftsec`) |
| :--- | :--- | :--- |
| **PyPI distribution** | `tensorguard` / `ai-spm` | `siftsec` |
| **Python import package** | `ai_spm` | `siftsec` |
| **CLI binary** | `tensorguard`, `ai-spm` | `siftsec` (both old aliases dropped) |
| **Rust crate & extension** | `tensorguard-core` / `ai_spm._tg_core` | `siftsec-core` / `siftsec._core` |
| **Rule IDs** | `AI-SPM-*` | `SIFTSEC-*` |
| **Config class** | `AISPMConfig` | `SiftsecConfig` |
| **Environment variables** | `AI_SPM_*` | `SIFTSEC_*` |

## Action Required

1. **Rule IDs (`AI-SPM-*` → `SIFTSEC-*`):**
   This is a breaking change for any saved SARIF baseline, diff file, or `.siftsec-suppressions.json` / `.tensorguard-suppressions.json` file. **Delete and regenerate** existing baselines and suppression files after upgrading.

2. **Environment Variables (`AI_SPM_*` → `SIFTSEC_*`):**
   Update any CI or shell environment overrides:
   - `AI_SPM_DEFAULT_FAIL_ON` → `SIFTSEC_DEFAULT_FAIL_ON`
   - `AI_SPM_APP_NAME` → `SIFTSEC_APP_NAME`
   - `AI_SPM_MAX_FILE_BYTES` → `SIFTSEC_MAX_FILE_BYTES`
   - Any other `AI_SPM_*` setting in `SiftsecConfig` → `SIFTSEC_*`

3. **CLI & Python Imports:**
   - Replace `tensorguard ...` and `ai-spm ...` invocations with `siftsec ...`.
   - Replace `from ai_spm...` imports with `from siftsec...`.

4. **GitHub Repository URL:**
   The GitHub repository URL will be updated by the repository owner. Update your `git remote` once the repository is renamed on GitHub.
