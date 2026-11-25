# TensorGuard (`ai_spm`) — Workspace Engineering Rules

Always read `docs/ai-rules.md`, `docs/decisions.md`, and the active sub-phase in `docs/PLAYBOOK.md` before editing code.

## Bug-Prevention & Correctness Invariants

1. **Zero Hardcoding:** Never hardcode magic numbers, scoring weights, file extensions, ports, or static placeholders (`<bucket>`) inside rules or collectors. Put all tunables in `AISPMConfig` (`ai_spm/config.py`) and interpolate resource fields safely (`shlex.quote` for shell, `json.dumps` for HCL).
2. **Unknown ≠ Fail / Never False-Pass:** Every rule reading fallible attributes must declare `required_attrs` so missing/unreadable attributes in `resource.gaps` emit `Status.ERROR` instead of silently returning `Status.PASSED` or `Status.FAILED`. Return `None` (never `100`) for `posture_score` when zero checks were evaluated.
3. **Hostile-Input & Parser Safety:**
   - Never execute untrusted artifacts (`pickle.loads` / `torch.load` / spawning untrusted MCP servers). Use `pickletools.genops()` and static JSON parsing.
   - Enforce cumulative uncompressed byte caps, compression-ratio limits, zip-slip (`..`) checks, symlink skips (`is_symlink()`), and per-file timeouts.
   - Scope `--path` scans strictly to the target path unless user-global configs are explicitly requested.
4. **Secret Redaction at Construction:** Mask matched secrets via `redact()` inside `BaseRule._build()` and logger filters so raw credentials never reach stdout, stderr, JSON, or SARIF.
5. **Verify External Facts:** Never cite CVEs, MITRE ATLAS IDs, OWASP LLM numbers, or AWS API parameters from memory—verify against NVD / official specs / `boto3` docs first.
6. **Mandatory Verification Gate:** Before finishing any code change, run and pass:
   - `uv run ruff check .` and `uv run ruff format --check ai_spm tests`
   - `uv run mypy ai_spm`
   - `uv run pytest` (including `hypothesis` fuzz tests for any parser changes)
