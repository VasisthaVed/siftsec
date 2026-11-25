# TensorGuard (`ai-spm`): Engineering Decisions & Coding Standards

This document captures the **staff-level architectural decisions**, trade-offs, research justifications, and strict coding/commenting standards that govern TensorGuard. Every decision is designed to keep the codebase fast, testable, dynamic (zero hardcoding), and free of technical debt.

---

## 1. Architectural Decision Records (ADRs)

### ADR-001: Configuration-Driven Design via `pydantic-settings` (Zero Hardcoding)
* **Context:** Security scanners frequently rot because magic numbers (scoring weights), file extensions (`.pt`, `.pkl`), port lists (`11434`), and thresholds are scattered across rule files.
* **Options Considered:**
  1. *Module-level constants in each rule file:* Fast to write, impossible to override at runtime or per enterprise.
  2. *Raw `os.getenv()` calls everywhere:* Error-prone type casting and no schema validation.
  3. *Centralized `AISPMConfig(BaseSettings)` (`ai_spm/config.py`):* Typed, validated at startup, overridable via `AI_SPM_*` environment variables or config files.
* **Decision:** Option 3 (`AISPMConfig`).
* **Implementation Contract:** No rule, collector, or reporter may hardcode tunable lists or thresholds. All heuristics live in `AISPMConfig` with safe defaults.
* **Failure Mode & Mitigation:** Invalid env var types (e.g., `AI_SPM_DEFAULT_FAIL_ON=INVALID`) fail fast at CLI startup with a clear Pydantic validation error instead of silently misbehaving mid-scan.

---

### ADR-002: Pure, Side-Effect-Free Rules & Isolated Collectors
* **Context:** Coupling Boto3/HTTP calls directly inside security rules makes unit testing slow, forces real credentials in CI, and mixes I/O error handling with policy logic.
* **Options Considered:**
  1. *Rules fetch their own data via Boto3:* Simple for 3 rules, catastrophic at 30 rules (duplicate API calls, throttling, untestable).
  2. *Two-stage pipeline (`Collector -> CloudResource -> BaseRule.evaluate()`):* Collectors handle I/O, retries, pagination, and normalization; rules are pure functions.
* **Decision:** Option 2.
* **Implementation Contract:**
  - `BaseRule.evaluate(resource: CloudResource) -> Finding` **must never** perform network I/O, disk I/O, or import `boto3`.
  - Every failing `Finding` must dynamically interpolate `resource.name`, `resource.region`, `resource.id`, and `resource.arn` into its `message` and `remediation` fields.
* **Verification:** Every rule must pass unit tests with synthetic `CloudResource` fixtures in `< 5ms` with zero network access.

---

### ADR-003: Dynamic Plugin & Rule Discovery (`pkgutil` + `entry_points`)
* **Context:** Requiring developers to manually edit `rules/__init__.py` or `cli.py` whenever a new rule is added creates merge conflicts and forgotten registrations.
* **Decision:** `RuleRegistry` auto-discovers internal modules using `pkgutil.iter_modules` and external community plugins via `importlib.metadata.entry_points(group="ai_spm.rules")`.
* **Security Trade-off:** Arbitrary `.py` loading from untrusted user directories would create a code-execution risk. Therefore, `discover_package` only scans the installed `ai_spm.rules` package namespace, and third-party plugins must be explicitly installed Python packages declaring standard entry points.

---

### ADR-004: Static Pickle Opcode Inspection (`pickletools`) — Never `pickle.loads()`
* **Context:** PyTorch checkpoints (`.pt`, `.pth`, `.bin`) and `.pkl` files use Python's `pickle` format. Deserializing untrusted checkpoints via `torch.load()` triggers arbitrary RCE via `__reduce__` opcodes.
* **Options Considered:**
  1. *Load with `torch.load(weights_only=True)`:* Pulls a 2GB+ PyTorch dependency into a lightweight CLI scanner and still fails on older formats.
  2. *Filename extension check only (`.pt` vs `.safetensors`):* Useful as a cloud metadata heuristic (`AI-SPM-S3-004`), but cannot inspect actual payload safety locally.
  3. *Static bytecode disassembly via stdlib `pickletools.genops()`:* Zero heavy dependencies, zero code execution, inspects exact `GLOBAL`/`STACK_GLOBAL` opcodes.
* **Decision:** Option 2 for remote S3 metadata heuristics (to avoid downloading multi-GB model weights) + Option 3 (`pickletools.genops`) for local model scanning (`AI-SPM-LOCAL-001`).
* **Failure Mode & Mitigation:** PyTorch `.pt` files are often ZIP archives containing `archive/data.pkl`. The local scanner must inspect ZIP entries safely (with zip-bomb size limits) before streaming `data.pkl` into `pickletools.genops()`.

---

### ADR-005: Non-Executing MCP Manifest & Rug-Pull Auditing
* **Context:** Invariant Labs and Check Point (2025) demonstrated two critical Model Context Protocol (MCP) attack vectors:
  1. *Tool Poisoning:* Hidden instructions inside tool descriptions (including Unicode tag smuggling `U+E0000–U+E007F` or Base64) hijack agent reasoning.
  2. *Rug Pulls:* Unpinned `npx -y` / `uvx` servers silently mutate behavior after initial user approval.
* **Decision:** TensorGuard **never spawns or connects to untrusted MCP servers** during static posture audits. Instead, it:
  1. Parses `mcp.json` / `claude_desktop_config.json` statically.
  2. Flags unpinned dynamic runners (`npx`, `uvx` without explicit version pins).
  3. Computes SHA-256 hashes of server definitions to detect manifest drift (rug pulls).
  4. Scans tool metadata for obfuscated prompt-injection markers and plaintext API keys in `env` blocks (redacting secret values before writing findings).

---

### ADR-006: Boto3 Resilience, Adaptive Retries & Exception Barriers
* **Context:** Enterprise AWS accounts frequently trigger `ThrottlingException`, partial `AccessDenied` on restricted services (e.g., Bedrock not enabled in all regions), and paginated responses exceeding 100 items.
* **Decision:**
  - All Boto3 clients use `botocore.config.Config(retries={"max_attempts": 5, "mode": "adaptive"})`.
  - All list/describe calls must use `get_paginator()` or explicit token loops.
  - Collectors wrap per-service/per-resource calls in an exception barrier catching `ClientError`: permission denials emit a structured warning/diagnostic and allow remaining services to finish.
  - `ScanRunner.run()` wraps each `rule.evaluate()` call in a `try...except` barrier emitting `Status.ERROR` so one malformed payload never aborts a scan.

---

### ADR-007: Severity-Weighted CSPM Posture Score & Responsive Terminal UI
* **Context:** Linear score deduction (`100 - 15*critical`) collapses to `0/100` after just 7 critical findings, losing signal on large accounts. Furthermore, fixed-width Rich table columns truncate short labels (`Status` → `…`, `Severity` → `CRI…`) on 80-column terminals.
* **Decision:**
  - **Weighted Pass-Rate Formula:**
    $$\text{Score} = \text{round}\left(\frac{\sum_{s} (W_s \times P_s)}{\sum_{s} (W_s \times T_s)} \times 100\right)$$
    where $W_s$ comes dynamically from `settings.severity_weights`.
  - **Responsive Rich Layout:** Use `Table(expand=True)` with `no_wrap=True` on fixed-vocabulary columns (`Status`, `Severity`, `Rule ID`) and `ratio` + `overflow="ellipsis"` on variable-length columns (`Resource`, `Framework / Threat`).

---

### ADR-008: Multi-Sink Reporting & Secret-Safe CI/CD Contract
* **Context:** Findings must be consumable by humans (terminal), GitHub Code Scanning (SARIF v2.1.0), PR bots (Markdown), and automation pipelines (JSON).
* **Decision:**
  - Support `SARIFReporter` (OASIS SARIF v2.1.0) with `security-severity` scores mapped to GitHub's native severity tiers.
  - Enforce deterministic exit codes: `0` = clean / below threshold, `1` = findings $\ge$ `--fail-on`, `2` = fatal config/runtime error.
  - **Secret Redaction Rule:** Any finding involving leaked keys (`AI-SPM-SECRETS-001`) must mask the secret value (e.g., `sk-proj-****`) before passing to any reporter so credentials are never leaked into CI logs or SARIF artifacts.

---

## 2. Code Quality & Commenting Guidelines

Every contributor and AI coding assistant working on TensorGuard must follow these standards:

1. **Strict Typing Everywhere (`mypy --strict`):**
   - Every function and method must declare full parameter and return type annotations (`-> None`, `-> list[Finding]`).
   - Avoid `Any` outside of raw external API payload boundaries (`metadata: dict[str, Any]`).
2. **Shallow Nesting & Early Returns:**
   - Validate preconditions and handle edge cases (`if not evaluated: return 100`) at the top of functions rather than nesting `if/else` blocks 3+ levels deep.
3. **No Duplicated Logic:**
   - Extract shared pagination, error barriers, and secret masking into reusable helpers in `collectors/base.py` and `utils/`.
4. **Meaningful Docstrings & "Why" Comments:**
   - Every public class, collector, and non-trivial helper must have a concise one-line or multi-line docstring explaining its **contract**.
   - Use inline comments to explain **why** (security invariants, non-obvious AWS API quirks, CVE mitigations)—never **what** the Python syntax is doing.
   - *Good:* `# Use pickletools.genops instead of pickle.loads to prevent __reduce__ RCE.`
   - *Bad:* `# Loop over items in list.`
5. **Testability & Mocking Discipline:**
   - Never require live cloud credentials or internet access in `tests/`.
   - Use `moto` for AWS SDK tests, `monkeypatch` for `AISPMConfig` env var tests, and `CliRunner` for end-to-end CLI exit-code verification.
