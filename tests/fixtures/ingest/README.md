# Ingest Fixtures & Live-Tool Verification Status (Phase 10.1)

**TODO (2026-11-25):** Current test payloads are schema-aligned synthetic fixtures. Before closing Phase 10.1, capture real redacted outputs from each external binary via `scripts/record_fixtures.py`:

| Tool | Adapter Path | Real Output Fixture Status |
| :--- | :--- | :--- |
| `ModelAudit` | `sarif_adapter.py`, `json_adapter.py` | Recorded (`modelaudit.sarif`, v0.2.58, redacted) |
| `mcpvuln` | `json_adapter.py` | TODO (synthetic fixture only) |
| `Trivy` | `sarif_adapter.py` | Recorded (`trivy.sarif`, v0.76.2, redacted) |
| `Prowler` | `json_adapter.py`, `sarif_adapter.py` | TODO (synthetic fixture only) |
| `Semgrep` | `sarif_adapter.py` | TODO (synthetic fixture only) |
| `agent-bom` | `sarif_adapter.py`, `json_adapter.py` | TODO (synthetic fixture only). Scenario 3 (`test_graph.py::test_compromised_skill_to_credential_critical`) exercises graph logic against synthetic agent-bom output. Real fixture pending. |
| `mcp-tool-auditor` | `sarif_adapter.py` | TODO (synthetic fixture only) |
| `MCPiranha` | `sarif_adapter.py` | TODO (synthetic fixture only) |
| `agent-audit-kit` | `sarif_adapter.py`, `json_adapter.py` | TODO (synthetic fixture only) |
| `Cisco MCP Scanner` | `sarif_adapter.py` | TODO (synthetic fixture only) |
