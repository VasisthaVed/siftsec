# Research & Citations

Every empirical number, architectural choice, and limitation in `siftsec` is grounded in published engineering research or primary vendor documentation. Below are the references cited in [README.md](../README.md).

---

## 1. Developer Survey on Alert Fatigue & Scanner Overlap

- **Source:** Safeguard Developer Survey (2026), *540-developer false-positive and security-gate survey*
- **Key findings:** 61% of respondents reported that more than half of security alerts are false positives or non-exploitable in their code path; 68% run three or more overlapping scanners with contradictory findings; 54% disabled a security gate in the prior 12 months due to unjustified release blocks; reachability outranked coverage and speed combined.
- **How `siftsec` uses it:** Motivates `siftsec`'s core architecture: deduplicating overlapping scanner outputs and ranking findings by attacker reachability rather than adding another primary scanner.

## 2. MCP Ecosystem Scale & Static Scanner Noise

- **Source:** MCPZoo (July 2026), *64,611-server Model Context Protocol (MCP) corpus*
- **Key findings:** Large-scale evaluation of runnable MCP servers demonstrated high false-positive rates from naive automated checks across heterogeneous tool ecosystems.
- **How `siftsec` uses it:** Provides the evaluation corpus structure for Phase 10.6 end-to-end alert-reduction and precision benchmarking across MCP and AI-agent findings.

## 3. Quantized Model Verifiability & Supply-Chain Gaps

- **Title:** *What You Sign Is Not What You Run: The Verifiability Gap in Quantized LLM Supply Chains*
- **Year / ID:** October 2026 · [arXiv:2610.19498](https://arxiv.org/abs/2610.19498)
- **Key findings:** Introduces Independent Verifiability Rate (IVR) across the top 200 Hugging Face GGUF repositories, showing an initial 0/198 baseline due to missing build coordinates and quantization recipes.
- **How `siftsec` uses it:** Informs `siftsec`'s provenance and model-artifact integrity checks (`ADR-043` `model` and `model_handoff` graph nodes) and prevents false certainty when artifact metadata is absent.

## 4. Rust vs. Algorithm Speedups in Security Parsing

- **Title:** *Where does a Rust speedup come from?*
- **Year / ID:** October 2026 · [arXiv:2610.07931](https://arxiv.org/abs/2610.07931)
- **Key findings:** Separates language-level execution speedups from algorithmic and memory-layout improvements when porting hot paths to Rust.
- **How `siftsec` uses it:** Guides the boundary between Python orchestration and the Rust `siftsec._core` native extension (`parse_json_bounded`, `index_findings`, and `build_graph_and_score` with `py.detach` GIL release and Criterion gates).

## 5. Structure-Aware Pickle Opcode Fuzzing

- **Tool:** Cisco AI Defense, `pickle-fuzzer`
- **URL:** [github.com/cisco-ai-defense/pickle-fuzzer](https://github.com/cisco-ai-defense/pickle-fuzzer)
- **How `siftsec` uses it:** Inspires `siftsec`'s static `pickletools.genops()` inspection and adversarial pickle-stream fuzzing without ever invoking `pickle.loads()` or `torch.load()`.

## 6. Agent Delegation & Semantic Compliance Hijacking Limits

- **Sources:** IETF `DAWN` / `APKI` / `PEDIGREE` working drafts (agent delegation provenance); 2026 ClawHub `SKILL.md` Semantic Compliance Hijacking evaluations (0.00% static-analysis detection rate).
- **How `siftsec` uses it:** Shapes `ADR-043` (`skill`, `model`, and `model_handoff` edge semantics for credential inheritance) and anchors the explicit static-analysis limitation in `README.md`.
