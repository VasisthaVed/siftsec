# AI-SPM: Foundational Architecture, Security Rules & Master Roadmap

> **AI Security Posture Management (AI-SPM) Scanner**
> *A modular, research-grounded open-source scanner designed to discover, audit, and secure AI/ML infrastructure across cloud providers, Kubernetes GPU clusters, foundation model endpoints, vector databases, model weights, agentic runtimes, and the AI supply chain.*

---

## 1. Executive Vision & Paradigm Shift

### Why Traditional CSPM Fails at AI
Traditional Cloud Security Posture Management (CSPM) tools (such as Prowler, ScoutSuite, or Trivy) inspect generic cloud primitives: open security groups, unencrypted EBS volumes, or public S3 buckets. **They treat AI workloads as dumb infrastructure.**

AI pipelines introduce fundamentally different attack surfaces:

1. **Model Weights as Executable Payloads:** A `.pt`, `.bin`, or `.pkl` checkpoint stored in S3 is not passive data; it is serialized Python bytecode that executes arbitrary system code on deserialization (`torch.load()` RCE via `__reduce__`).
2. **The Vector "Hash" Fallacy:** Storing vector embeddings in an unauthenticated or public vector database assumes embeddings are irreversible one-way hashes. Peer-reviewed research proves **vector embeddings can be inverted into original plaintext with >90% precision** (Vec2Text, Cornell 2023).
3. **Autonomous Agents as Confused Deputies:** AI agents integrated with tools (via Bedrock Agents, LangGraph, or Model Context Protocol) collapse the boundary between data and control plane. An indirect prompt injection in an ingested document can weaponize the agent's IAM credentials to execute destructive cloud API calls.
4. **MCP Tool Poisoning & Rug Pulls:** Model Context Protocol servers can be published with benign metadata, then silently updated with hidden malicious instructions that exfiltrate SSH keys, secrets, or PII while returning correct-looking outputs to the user.
5. **RAG Knowledge Base Poisoning:** Attackers slip optimized malicious documents into enterprise knowledge stores (SharePoint, Confluence, S3 data sources). With as few as 5 injected texts, research shows >90% attack success rate against GPT-4 and similar models (PoisonedRAG, USENIX 2024).
6. **GPU Container Escape & CUDA Hijacking:** NVIDIA Container Toolkit vulnerabilities (CVE-2024-0132, CVE-2025-23266 "NVIDIAScape") enable container-to-host escape with full root access via malicious OCI hooks exploiting `LD_PRELOAD` and TOCTOU race conditions.
7. **Shadow AI Infrastructure:** Engineering teams frequently spin up unmanaged inference instances (Ollama on `11434`, vLLM on `8000`, Triton on `8001`) with open internet egress and hardcoded API tokens (`OPENAI_API_KEY`, `HF_TOKEN`).
8. **Model IP Theft via Distillation:** Unauthorized knowledge distillation extracts proprietary model capabilities into smaller clones. Modern fingerprinting research (ICML/ICLR 2024–2025) shows watermarks can be stolen, spoofed, or scrubbed through quantization and fine-tuning.
9. **Missing AI Supply Chain Provenance:** Without an AI Bill of Materials (AIBOM), organizations cannot trace which base models, datasets, adapters, and MCP tools compose their production systems—making zero-day response and compliance audits impossible.

**AI-SPM bridges this gap by scanning the entire AI lifecycle from the metal up—across AWS, GCP, Azure, and Kubernetes.**

---

## 2. Open-Source Strategy: How to Reach 1,000+ GitHub Stars

To achieve breakout adoption alongside Prowler (10k+ stars), Trivy (24k+ stars), and Checkov (7k+ stars):

```
+--------------------------+     +--------------------------+     +--------------------------+
|  10-Second "Aha!" Moment | --> | Visual Terminal Report   | --> | 1-Click CI/CD (SARIF)    |
|  `uvx ai-spm scan --demo`|     | Rich tables & score/100  |     | Native GitHub Alerts     |
+--------------------------+     +--------------------------+     +--------------------------+
         |                                    |                                    |
         v                                    v                                    v
+--------------------------+     +--------------------------+     +--------------------------+
| Multi-Cloud Scanning     |     | AI SBOM Generation       |     | Research-Backed Authority|
| AWS + GCP + Azure + K8s  |     | CycloneDX / SPDX 3.0    |     | MITRE ATLAS, NIST, OWASP |
+--------------------------+     +--------------------------+     +--------------------------+
```

### 2.1 The 10-Second "Aha!" Moment (`--demo`)
- `uvx ai-spm scan --demo` runs an instant in-memory simulation of a compromised enterprise AI environment—no AWS credentials needed.
- Simulates: exposed Ollama instance, unencrypted PyTorch weights, unauthenticated OpenSearch vector domain, Bedrock agent missing guardrails, poisoned MCP server, and a Pickle-laden S3 bucket.

### 2.2 Novel Differentiators (Checks No Other Open-Source Tool Has)
- **Model Serialization Audit:** Inspect S3 for dangerous pickle files (`.pt`, `.bin`, `.pkl`) and enforce SafeTensors.
- **MCP Tool Manifest Integrity:** Hash and audit MCP server tool descriptions for hidden prompt injection markers and rug-pull mutations.
- **RAG Poisoning Canary Detection:** Inject verifiable canary embeddings into knowledge bases to detect tampering.
- **AI SBOM Generation:** Automatically produce CycloneDX v1.7 or SPDX 3.0 AI Bills of Materials tracking models, datasets, adapters, and MCP tools.
- **Shadow AI Discovery:** Scan VPCs for unmanaged inference endpoints on well-known ports.
- **GPU Runtime Posture:** Audit Kubernetes node NVIDIA Container Toolkit versions and pod GPU security configurations.
- **Model Provenance & Watermark Verification:** Detect unsigned or untraceable model weights lacking cryptographic provenance hashes.

### 2.3 GitHub Code Scanning & SARIF First-Class Citizen
- Emits OASIS SARIF v2.1.0 reports for the GitHub **Security → Code Scanning Alerts** tab.
- Reusable GitHub Action (`uses: ai-spm/action@v1`).

### 2.4 Rigorous Academic & Compliance Mappings
- Every rule is tied to **MITRE ATLAS**, **OWASP Top 10 for LLMs (2025)**, **NIST AI 600-1**, and **EU AI Act** transparency requirements.

---

## 3. Academic Foundations & Threat Research Library

### 3.1 Core Research Papers

| # | Threat Domain | Research Paper / Benchmark | Key Finding |
| :--- | :--- | :--- | :--- |
| **R1** | **Vector Inversion** | **Vec2Text:** *"Text Embeddings Reveal (Almost) As Much As Text"* (Morris et al., Cornell, 2023) | Dense embeddings stored in vector databases can be inverted into original plaintext with >92% precision via iterative multi-step correction. Vector DBs must be treated as sensitive plaintext datastores. |
| **R2** | **Model Supply Chain** | **Insecure Deserialization in PyTorch** (`pickle.__reduce__` RCE, Hugging Face PickleScan, SafeTensors) | Loading unverified `.pt`/`.bin` files via `torch.load()` executes arbitrary Python bytecode via `__reduce__`. Mitigated by SafeTensors format or `weights_only=True`. |
| **R3** | **Confused Deputy** | *"Capability Gates Are Not Authorization: Confused-Deputy Failures in LLM Agent Frameworks"* (arXiv, 2024) | LLM agents with tool access lack deterministic value authorization gates. Indirect prompt injections hijack agent credentials to execute destructive commands. Model-level fixes (RLHF, system prompts) are provably insufficient. |
| **R4** | **RAG Poisoning** | **PoisonedRAG:** *"Knowledge Corruption Attacks to RAG"* (USENIX, 2024) | Attackers achieve >90% Attack Success Rate by injecting as few as 5 optimized malicious texts into million-document knowledge bases. GPT-4, PaLM 2 fail to distinguish poisoned context from authentic. |
| **R5** | **RAG Single-Doc** | **AuthChain:** *"One Shot Dominance: Knowledge Poisoning Attack on RAG"* (arXiv, 2025) | A single Chain-of-Evidence (CoE) document crafted to mimic official policy can override multi-hop RAG pipelines without saturation flooding. |
| **R6** | **MCP Tool Poisoning** | **Invariant Labs / Check Point MCP Security Disclosures** (2025) | MCP servers embed hidden malicious instructions in tool descriptions. Agents treat metadata as trusted developer directives—executing data exfiltration while returning correct user-facing outputs. Rug-pull attacks silently mutate tool behavior post-approval. |
| **R7** | **GPU Container Escape** | **NVIDIAScape** (CVE-2024-0132, CVE-2025-23266) | NVIDIA Container Toolkit OCI hooks run as root on the host. Malicious images exploit `LD_PRELOAD` injection or TOCTOU race conditions to escape containers with full host root access. CVSS 9.0. |
| **R8** | **Model IP Theft** | **Watermark Stealing & Distillation Detection** (ICML/ICLR, 2024–2025) | Standard LLM watermarks can be reverse-engineered via API querying, enabling spoofing and scrubbing attacks. Defense shifted to multi-bit error-corrected watermarks combined with behavioral fingerprinting. |
| **R9** | **Few-Shot Inversion** | **ALGEN:** *"Few-Shot Inversion Attacks on Textual Embeddings"* (ACL, 2024) | Cross-model alignment enables embedding inversion with minimal training data, lowering the barrier for vector store data extraction. |
| **R10** | **Zero-Shot Inversion** | **ZSinvert:** *"Universal Zero-shot Embedding Inversion"* (arXiv, 2025) | Query-efficient zero-shot text reconstruction from embeddings without training an embedding-specific inversion model. |

### 3.2 Compliance & Governance Frameworks

| Framework | Issuing Body | Relevance to AI-SPM |
| :--- | :--- | :--- |
| **MITRE ATLAS** (`AML.T0044`, `AML.T0043`, `AML.T0020`, `AML.T0010`) | MITRE | Maps adversary tactics for AI: Model Exfiltration, Data Exfiltration, Training Data Poisoning, ML Supply Chain Compromise. |
| **OWASP Top 10 for LLM Applications (2025)** | OWASP | Primary application risks: Prompt Injection (`LLM01`), Sensitive Info Disclosure (`LLM02`), Supply Chain (`LLM03`), Excessive Agency (`LLM06`), Unbounded Consumption (`LLM10`). |
| **NIST AI 600-1** (Generative AI Profile, July 2024) | NIST | 200+ actions across Govern/Map/Measure/Manage for 12 generative AI risk domains (data privacy, information security, supply chain, confabulation). |
| **EU AI Act** (2024) | European Parliament | Mandates technical documentation, training-data summaries, and supply chain transparency—making automated AIBOM generation a compliance necessity. |
| **OWASP CycloneDX v1.7 / SPDX 3.0** | OWASP / Linux Foundation | Machine-readable AI Bill of Materials standards for tracking models, datasets, adapters, MCP tools, and inference dependencies. |
| **Google SAIF** (Secure AI Framework) | Google | Maps security controls for Vertex AI covering IAM, VPC Service Controls, and model endpoint protection. |
| **CSA AI Safety Initiative** | Cloud Security Alliance | Autonomous agent trust boundaries, multi-agent confused deputy taxonomy, and MCP security guidelines. |

---

## 4. System Architecture: 7-Tier Defense Model (Bottom-Up)

```
=========================================================================================
                       AI-SPM 7-TIER DEFENSE ARCHITECTURE (EXPANDED)
=========================================================================================

 [TIER 6: AI SUPPLY CHAIN & PROVENANCE]
  - AI Bill of Materials (AIBOM) Generation (CycloneDX v1.7 / SPDX 3.0)
  - Model Provenance Hashing & Watermark Verification
  - MCP Tool Manifest Integrity Auditing (Hash Pinning, Rug-Pull Detection)
  - Dataset Lineage & License Compliance Tracking
                                      |
                                      v
 [TIER 5: MCP, TOOL RUNTIMES & AGENTIC ORCHESTRATION]
  - MCP Server Tool Description Scanning (Hidden Prompt Injection Markers)
  - MCP Rug-Pull Detection (Manifest Hash Drift Monitoring)
  - Agent Tool Authorization Gates & Blast Radius Policies
  - Multi-Agent Confused Deputy Chain Detection
                                      |
                                      v
 [TIER 4: AUTONOMOUS AGENTS & GUARDRAILS]
  - Bedrock Agents / LangGraph / CrewAI Guardrails (Content Filtering, PII Masking)
  - IAM Blast Radius Reduction for Agent Execution Roles
  - Mitigating: Indirect Prompt Injection, Confused Deputy (OWASP LLM06 / NIST MG-3.1)
                                      |
                                      v
 [TIER 3: INFERENCE GATEWAYS & FOUNDATION MODELS]
  - Bedrock Model Invocation Logging / Vertex AI Audit Logging / Azure AI Foundry Monitoring
  - SageMaker Endpoints / Vertex AI Endpoints / Azure ML Endpoints: VPC & Encryption
  - Shadow LLM Discovery (Ollama:11434, vLLM:8000, Triton:8001, TGI:8080)
                                      |
                                      v
 [TIER 2: VECTOR DATABASES & RAG PIPELINES]
  - OpenSearch / Qdrant / Milvus / Chroma / Pinecone VPC Isolation
  - Fine-Grained Access Control (FGAC) & Multi-Tenant Namespace Segmentation
  - RAG Poisoning Canary Detection & Post-Retrieval Sanitization
  - Mitigating: Vector Inversion (Vec2Text/ALGEN/ZSinvert), Knowledge Corruption (PoisonedRAG)
                                      |
                                      v
 [TIER 1: MODEL WEIGHTS & ARTIFACT REPOSITORIES]
  - S3 / GCS / Azure Blob: SafeTensors vs. Legacy Pickle Checkpoints (.pt, .bin, .pkl)
  - Customer KMS CMK Encryption & Block Public Access Enforcement
  - ECR / Artifact Registry / ACR Container Scan-on-Push & Tag Immutability
  - Model Fingerprint Verification (Cryptographic Hash Provenance)
                                      |
                                      v
 [TIER 0: INFRASTRUCTURE, GPU RUNTIME, IAM & SECRETS BASELINE]
  - SageMaker / Vertex AI / Azure ML Notebook DIA & Root Access Controls
  - Kubernetes GPU Node Security: NVIDIA Container Toolkit Version Audit (CVE-2025-23266)
  - GPU Pod Isolation: MIG Partitioning vs. Unsafe Time-Slicing
  - Least-Privilege IAM / Workload Identity for Training & Inference Roles
  - Leaked AI Secrets (OPENAI_API_KEY, HF_TOKEN, ANTHROPIC_API_KEY) in Environment Variables
=========================================================================================
```

### Scanner Execution Pipeline

```
     +------------------------------------------------------------------+
     |                    CLI & Execution Controller                    |
     |  ai-spm scan [--services ...] [--cloud aws|gcp|azure|k8s]       |
     |              [--demo] [--output ...] [--sbom cyclonedx|spdx]    |
     +------------------------------------------------------------------+
                                      |
                   +------------------+------------------+
                   |                                     |
                   v                                     v
     +---------------------------+         +---------------------------+
     |   Cloud Collector Engine  |         |   K8s Collector Engine    |
     | - AWS Boto3 Adapter       |         | - kubectl / K8s API       |
     | - GCP Discovery Client    |         | - GPU Node Inspector      |
     | - Azure SDK Adapter       |         | - Pod Security Auditor    |
     | - Mock Collector (--demo) |         | - Helm Release Scanner    |
     +---------------------------+         +---------------------------+
                   |                                     |
                   +------------------+------------------+
                                      |
                           (CloudResource Pydantic Models)
                                      |
                                      v
     +------------------------------------------------------------------+
     |                     Rule Evaluation Engine                       |
     |   - Rule Registry: Dynamically loads BaseRule subclasses         |
     |   - Evaluator: Pure, isolated evaluation (Resource -> Finding)   |
     |   - Metadata: MITRE ATLAS, OWASP LLM, NIST AI 600-1, EU AI Act |
     +------------------------------------------------------------------+
                                      |
                              (Stream of Findings)
                                      |
                   +------------------+------------------+
                   |                  |                  |
                   v                  v                  v
     +----------------+  +------------------+  +------------------+
     | Rich Terminal   |  | JSON / SARIF     |  | AI SBOM          |
     | (Score, Tables) |  | (GitHub Security)|  | (CycloneDX/SPDX) |
     +----------------+  +------------------+  +------------------+
```

---

## 5. Comprehensive AI-SPM Rules Matrix (Expanded)

### Tier 0: Infrastructure, GPU Runtime, IAM & Secrets

| Rule ID | Target | Severity | Threat & Mapping | Detection Logic |
| :--- | :--- | :--- | :--- | :--- |
| **`AI-SPM-SAGEMAKER-001`** | SageMaker Notebook | `CRITICAL` | Shadow AI Egress (`AML.T0043`, `SageMaker.1`) | Fail if `DirectInternetAccess: Enabled`. |
| **`AI-SPM-SAGEMAKER-002`** | SageMaker Notebook | `HIGH` | Uncontrolled Network (`SageMaker.2`) | Fail if missing VPC subnet attachment. |
| **`AI-SPM-SAGEMAKER-003`** | SageMaker Notebook | `HIGH` | Root Privilege Escalation (`SageMaker.3`) | Fail if `RootAccess: Enabled`. |
| **`AI-SPM-IAM-001`** | IAM AI Roles | `HIGH` | Excessive Agency (`LLM06:2025`) | Fail if wildcard (`*`) actions on AI execution roles. |
| **`AI-SPM-SECRETS-001`** | EC2/ECS/Lambda | `CRITICAL` | API Key Leakage (`LLM02:2025`) | Fail if `OPENAI_API_KEY`, `HF_TOKEN`, `ANTHROPIC_API_KEY` found in plaintext environment variables. |
| **`AI-SPM-K8S-GPU-001`** | K8s GPU Nodes | `CRITICAL` | Container Escape (`CVE-2025-23266`) | Fail if NVIDIA Container Toolkit version < `v1.17.8`. |
| **`AI-SPM-K8S-GPU-002`** | K8s GPU Pods | `HIGH` | GPU Memory Leak / Cross-Tenant | Fail if GPU pods use time-slicing without MIG isolation in multi-tenant clusters. |
| **`AI-SPM-K8S-GPU-003`** | K8s GPU Pods | `HIGH` | Privileged Container Escape | Fail if AI pods run with `privileged: true` or mount `/dev/nvidia*` via HostPath. |

### Tier 1: Model Weights & Artifact Repositories

| Rule ID | Target | Severity | Threat & Mapping | Detection Logic |
| :--- | :--- | :--- | :--- | :--- |
| **`AI-SPM-S3-001`** | S3 (AI Buckets) | `CRITICAL` | Model Weight Theft (`AML.T0044`, `LLM02:2025`) | Fail if weights use SSE-S3 instead of KMS CMK. |
| **`AI-SPM-S3-002`** | S3 (AI Buckets) | `CRITICAL` | Public Model Exposure (`AML.T0044`) | Fail if Public Access Block not fully enabled. |
| **`AI-SPM-S3-003`** | S3 (Training Data) | `MEDIUM` | Training Data Tampering (`AML.T0020`) | Fail if Object Versioning disabled. |
| **`AI-SPM-S3-004`** | S3 (Model Weights) | `MEDIUM` | Pickle RCE Heuristic (`AML.T0010`, `LLM04:2026`) | Heuristic: flag legacy `.pt`/`.bin`/`.pkl` without SafeTensors. |
| **`AI-SPM-S3-005`** | S3 (Model Weights) | `MEDIUM` | Missing Provenance (Supply Chain) | Fail if model files lack cryptographic hash manifest or Sigstore/Cosign signatures. |
| **`AI-SPM-ECR-001`** | ECR | `HIGH` | Container Poisoning (`AML.T0010`) | Fail if `scanOnPush: false`. |
| **`AI-SPM-ECR-002`** | ECR | `MEDIUM` | Tag Tampering (`AML.T0010`) | Fail if `imageTagMutability: MUTABLE`. |

### Tier 2: Vector Databases & RAG Pipelines

| Rule ID | Target | Severity | Threat & Mapping | Detection Logic |
| :--- | :--- | :--- | :--- | :--- |
| **`AI-SPM-VECTOR-001`** | OpenSearch / Vector DB | `CRITICAL` | Vector Inversion (`AML.T0044`, `LLM02:2025`) | Fail if endpoint is public (no VPC). |
| **`AI-SPM-VECTOR-002`** | OpenSearch | `HIGH` | Multi-Tenant RAG Breach (`LLM02:2025`) | Fail if FGAC disabled. |
| **`AI-SPM-VECTOR-003`** | OpenSearch | `HIGH` | In-Transit Interception | Fail if node-to-node encryption disabled. |
| **`AI-SPM-RAG-001`** | Bedrock KB / RAG Sources | `HIGH` | RAG Poisoning (`AML.T0020`, `LLM03:2025`) | Fail if knowledge base data sources lack write access controls or change-detection monitoring. |
| **`AI-SPM-RAG-002`** | RAG Pipeline | `MEDIUM` | Knowledge Corruption (PoisonedRAG) | Warn if no post-retrieval sanitization layer (perplexity filtering, source credibility scoring) is configured. |

### Tier 3: Inference Gateways & Foundation Models

| Rule ID | Target | Severity | Threat & Mapping | Detection Logic |
| :--- | :--- | :--- | :--- | :--- |
| **`AI-SPM-SAGEMAKER-004`** | SageMaker Endpoint | `HIGH` | Inference Volume Exposure (`LLM02:2025`) | Fail if `KmsKeyId` missing on EndpointConfig. |
| **`AI-SPM-SAGEMAKER-005`** | SageMaker Training | `HIGH` | Training Job C2 (`AML.T0010`) | Fail if `EnableNetworkIsolation: False` with custom containers. |
| **`AI-SPM-BEDROCK-001`** | Bedrock | `HIGH` | Zero Auditability (`LLM01:2025`, `MS-2.7`) | Fail if Model Invocation Logging disabled. |
| **`AI-SPM-BEDROCK-002`** | Bedrock KB | `HIGH` | RAG Knowledge Exposure (`LLM02:2025`) | Fail if data source lacks KMS CMK. |
| **`AI-SPM-SHADOW-001`** | VPC / EC2 | `HIGH` | Shadow AI (`AML.T0043`) | Fail if instances listen on AI inference ports (11434, 8000, 8001, 8080) without security group restrictions. |

### Tier 4: Autonomous Agents & Guardrails

| Rule ID | Target | Severity | Threat & Mapping | Detection Logic |
| :--- | :--- | :--- | :--- | :--- |
| **`AI-SPM-BEDROCK-003`** | Bedrock Agent | `CRITICAL` | Confused Deputy (`LLM06:2025`, `MG-3.1`) | Fail if no active Bedrock Guardrail with PII masking, toxic filtration, and prompt injection defense. |
| **`AI-SPM-AGENT-001`** | Agent Execution Role | `HIGH` | Blast Radius Expansion (`LLM06:2025`) | Fail if agent Lambda/IAM role has write access to S3, DynamoDB, or SecretsManager beyond scoped ARNs. |
| **`AI-SPM-AGENT-002`** | Agent Action Groups | `MEDIUM` | Unbounded Tool Access (`LLM10:2025`) | Warn if Bedrock Agent has >10 action groups without rate limiting or human-in-the-loop confirmation gates. |

### Tier 5: MCP, Tool Runtimes & Agentic Orchestration

| Rule ID | Target | Severity | Threat & Mapping | Detection Logic |
| :--- | :--- | :--- | :--- | :--- |
| **`AI-SPM-MCP-001`** | MCP Server Manifests | `CRITICAL` | Tool Poisoning (Hidden Injection) | Fail if MCP tool descriptions contain encoded instructions, Base64 payloads, or steganographic prompt injection markers. |
| **`AI-SPM-MCP-002`** | MCP Server Config | `HIGH` | Rug-Pull Attack (Supply Chain) | Fail if MCP tool definitions are not hash-pinned; warn on any manifest hash drift since last approval. |
| **`AI-SPM-MCP-003`** | MCP Server Auth | `HIGH` | Unauthenticated Tool Access | Fail if remote MCP servers communicate over HTTP without mTLS, OAuth, or API key authentication. |
| **`AI-SPM-MCP-004`** | MCP Server Scope | `MEDIUM` | Excessive Filesystem/API Access | Warn if local MCP servers have read/write access to directories outside their designated scope. |

### Tier 6: AI Supply Chain & Provenance

| Rule ID | Target | Severity | Threat & Mapping | Detection Logic |
| :--- | :--- | :--- | :--- | :--- |
| **`AI-SPM-SBOM-001`** | AI Deployment | `HIGH` | Missing AI Bill of Materials (`LLM03:2025`) | Fail if production AI system has no machine-readable AIBOM (CycloneDX or SPDX) tracking models, datasets, and tools. |
| **`AI-SPM-SBOM-002`** | Model Artifacts | `MEDIUM` | Unsigned Model Weights | Warn if deployed models lack Sigstore/Cosign signatures or SHA-256 provenance manifests. |
| **`AI-SPM-SBOM-003`** | AI Dependencies | `HIGH` | Vulnerable AI Libraries | Fail if PyTorch, TensorFlow, LangChain, or transformers versions contain known CVEs. |
| **`AI-SPM-SBOM-004`** | Dataset Provenance | `MEDIUM` | Untraceable Training Data (`EU AI Act`) | Warn if training/fine-tuning datasets lack data cards or lineage documentation. |

---

## 6. Multi-Cloud & Kubernetes Expansion Strategy

### 6.1 Cloud Provider Coverage Matrix

| Capability | AWS (Phase 1) | GCP (Phase 6) | Azure (Phase 7) | Kubernetes (Phase 8) |
| :--- | :--- | :--- | :--- | :--- |
| **Model Storage** | S3 encryption, public access | GCS bucket encryption, IAM | Azure Blob encryption, SAS tokens | PV encryption, StorageClass |
| **Training Compute** | SageMaker notebooks, training jobs | Vertex AI Workbench, Custom Jobs | Azure ML Compute, Notebooks | GPU pods, MIG isolation |
| **Foundation Models** | Bedrock invocation logging | Vertex AI Model Garden, audit logs | Azure AI Foundry, Defender for AI | Self-hosted (Ollama, vLLM) |
| **Vector Databases** | OpenSearch VPC, FGAC | AlloyDB, Vertex AI Search | Azure AI Search, Cosmos DB vCore | Self-hosted Qdrant, Milvus, Chroma |
| **Container Registry** | ECR scan-on-push | Artifact Registry scanning | ACR vulnerability scanning | Any OCI registry + Cosign |
| **Agent Guardrails** | Bedrock Guardrails | Vertex AI Safety Filters | Azure AI Content Safety | Custom OPA/Kyverno policies |
| **GPU Runtime** | — | GKE GPU node pools | AKS GPU node pools | NVIDIA Container Toolkit audit |
| **Service IAM** | IAM roles & policies | Workload Identity, VPC-SC | Entra ID, Managed Identity | RBAC, PSA, NetworkPolicy |

### 6.2 GCP Vertex AI Specific Threats
- **Overly Permissive Service Agents:** Default Vertex AI service accounts may have lateral movement access to BigQuery, Cloud Storage, and Pub/Sub.
- **VPC Service Controls Gaps:** Vertex AI endpoints deployed outside VPC Service Controls perimeters allow data exfiltration via model responses.
- **Ray on Vertex AI:** Shared Ray clusters may expose inter-worker communication without authentication.

### 6.3 Azure AI Foundry Specific Threats
- **Model Catalog Supply Chain:** Azure AI Foundry hosts hundreds of third-party models (Llama, Mistral, DeepSeek)—each a potential supply chain vector.
- **ASCII Smuggling in Copilot:** Unicode and ASCII control character injection to bypass content safety filters.
- **Defender for AI Runtime Gaps:** Defender detects prompt injection at the API boundary but not within chained multi-agent workflows.

### 6.4 Kubernetes GPU Security Threats
- **NVIDIA Container Toolkit CVEs:** OCI hooks running as root enable container escape (CVE-2024-0132, CVE-2025-23266).
- **GPU Memory Side-Channel:** Time-sliced GPU sharing without MIG allows cross-tenant memory read in shared clusters.
- **Privileged Pod Escalation:** AI pods mounting `/dev/nvidia*` via HostPath gain kernel-level device access.
- **Admission Control Gaps:** Missing OPA Gatekeeper/Kyverno policies allow `privileged: true` or `hostPID` on GPU workloads.

---

## 7. Engineering Roadmap (Revised — Ship First, Correlate Second)

> **Why this order?** The blunt reality: phases 0–10.1 built a rigorous scaffold. The gap between "rigorous scaffold" and "thing people actually use" is not more Rust — it's a working `pip install`, real fixtures, and a GitHub Action users can drop into their CI in 30 seconds. We close that gap first, then finish the correlation engine on top of real user feedback.

---

### Status Summary

| Phase | Description | Status |
| :---: | :--- | :---: |
| 0–4 | Core engine, local scanner, AWS collectors/rules, reporters, CLI | ✅ Done |
| 5 | Kubernetes GPU runtime security | ✅ Done |
| 6 | GCP Vertex AI collector & rules | ✅ Done |
| 7 | AI supply chain & AIBOM (CycloneDX / SPDX) | ✅ Done |
| 8 | Hardening, threat model, observability | ✅ Done |
| 9 | Attack-path correlation graph, scan diff, compliance evidence | ✅ Done |
| 10.1 | Hybrid Rust/Python core: `parse_json_bounded`, 10-tool ingest adapters | ✅ Done |
| **S1** | **Ship: PyPI wheel + GitHub Action** | 🔴 Blocker |
| **S2** | **Real fixtures: replace all synthetic SARIF with recorded tool output** | 🔴 Blocker |
| **S3** | **Local scan UX: `pip install tensorguard` → `tensorguard scan --local .` just works** | 🟡 Next |
| 10.2 | Rust dedup engine (`FindingIndex`, SipHash-1-3, ≤5ms/200 findings) | 📋 Planned |
| 10.3 | Correlation graph (`petgraph DiGraph<u32>`, skill nodes, `model→model` edges) | 📋 Planned |
| 10.4 | Reachability BFS (blast-radius scoring, predecessor path, ≥5× reduction gate) | 📋 Planned |
| 10.5 | Wedge-A prioritization (cross-tool severity fusion) | 📋 Planned |
| 10.6 | Benchmark & falsification gate (negative result published if <5× / <50% precision) | 📋 Planned |
| 11 | Model signing & post-quantum (ML-DSA-65 / FIPS 204, subliminal-channel mitigation) | 📋 Planned |
| 12 | Agent skill supply chain (registry collector, MinHash LSH campaign detection) | 📋 Planned |
| 13 | Compliance evidence export (EU AI Act 2027-12-02, NIST AI 600-1, ISO 42001) | 📋 Planned |

---

### Phases 0–10.1 — Completed Work

**Phase 0–4: Core Engine, Local Scanner, AWS, Reporters (Complete)**
- Pydantic v2 data models (`CloudResource`, `Finding`, `CoverageGap`, `ScanSummary`), `AISPMConfig` (`AI_SPM_*`), `RuleRegistry` entry-point discovery, weighted posture scoring (`None` on 0 evaluated), secret redaction (`redact()`), and expiry-enforced suppressions/baselines.
- Hostile-input local scanners: `pickletools.genops()` static disassembler, zip-bomb/zip-slip guards, SafeTensors header checks, `mcp.json` auditor + SHA-256 lockfile (`tensorguard mcp-lock`).
- Resilient AWS collectors (`s3`, `sagemaker`, `bedrock`, `ecr`, `opensearch`, `iam`, `ec2`) with `AccessDenied` → `CoverageGap` tracking and 37 auto-discovered security rules.
- Atomic `0600` writers, Rich Console, JSON, SARIF v2.1.0 (`partialFingerprints`), GFM Markdown reporters.

**Phase 5–9: K8s, GCP, AIBOM, Hardening, Correlation (Complete)**
- `K8sCollector` with NVIDIA Container Toolkit CVE-2025-23266 audit, GPU time-slicing/MIG rules, privileged pod escape checks.
- `GcpCollector` with Vertex AI Workbench, Endpoints, GCS model bucket rules.
- Deterministic CycloneDX 1.7 ML-BOM and SPDX 3.0 AI-profile AIBOM generation.
- `docs/threat-model.md` STRIDE matrix, `SECURITY.md`, `--log-json`, `--debug-bundle`.
- `ResourceGraph` multi-hop CRITICAL attack-path correlation, fingerprint scan diff, compliance control summaries.

**Phase 10.1: Hybrid Rust/Python Core (Complete)**
- `rust/tensorguard-core` (`pyo3 0.28.3`, `abi3-py312`, `panic = "unwind"`, `thiserror` → `PyErr`, 3-bound `parse_bounded` with byte cap + depth pre-pass + `serde_stacker`).
- Pure-Python `_fallback/` + `_core_loader.py` with parity test suite (71 tests pass, `HAS_RUST = True`).
- SARIF & native JSON ingest adapters for 10 tools: `ModelAudit`, `mcpvuln`, `Trivy`, `Prowler`, `Semgrep`, `agent-bom`, `mcp-tool-auditor`, `MCPiranha`, `agent-audit-kit`, `Cisco MCP Scanner`.
- `deny.toml`, `wheels.yml` (abi3 matrix), `rust-gates.yml` (clippy + cargo-deny), `benches/sarif_parse.rs`, `rust/tensorguard-fuzz/`.

---

### STAGE S1 — Ship: PyPI Wheel + Working GitHub Action
> **Why first:** None of the correlation work matters if users can't `pip install tensorguard`. This is the actual gate to any adoption.

**S1.1 — PyPI release**
- Register `tensorguard` on PyPI (or `ai-spm` if taken). Configure `pyproject.toml` with correct metadata, entry points, and optional extras (`[aws]`, `[k8s]`, `[gcp]`, `[dev]`).
- Add `publish.yml` GitHub Actions workflow: on `push tag v*.*.*` → `maturin publish` (Rust wheel) + `uv publish` (pure-Python sdist fallback). Requires `PYPI_TOKEN` secret.
- Pre-built `abi3-py312` wheels for linux/x86_64, linux/aarch64, macos/arm64, windows/amd64 (already in `wheels.yml` matrix).
- **Exit gate:** `pip install tensorguard` works in a clean venv. `tensorguard scan --demo` runs without cloning the repo.

**S1.2 — `uses: VasisthaVed/tensorguard/.github/actions/scan@v1` GitHub Action**
- Create `.github/actions/scan/action.yml` (composite action): installs `uv`, installs `tensorguard[aws]`, runs `tensorguard scan --local --path ${{ inputs.path }} --format sarif --output tensorguard.sarif`, then calls `github/codeql-action/upload-sarif@v3`.
- Document in README as a 4-line drop-in. This is how tools like Trivy and Semgrep get stars — the GH Action discovery path.
- **Exit gate:** A test repo running `uses: VasisthaVed/tensorguard/.github/actions/scan@v1` produces a populated Security Alerts tab.

**S1.3 — `uvx tensorguard scan --demo` works (zero-install path)**
- Confirm `uvx tensorguard` works from PyPI (the pure-Python sdist, Rust optional). The `_fallback` path exists for exactly this. Test on a clean machine with only `uv` installed.

---

### STAGE S2 — Real Fixtures: Replace Synthetic SARIF
> **Why before 10.2:** The dedup engine will be tested against fixtures. If fixtures are synthetic they will silently drift from reality. Real fixtures first, then dedup on top.

**S2.1 — `scripts/record_fixtures.py`**
- Script that runs each of the 10 tools (where installable via `pip`/`npx`/`cargo`) against a controlled test repo (`tests/fixtures/target_repo/`) and records the raw output to `tests/fixtures/ingest/<tool>/real_output.json` or `.sarif`.
- Redact any secrets or paths before committing.
- **Tools that can be recorded locally:** `Trivy` (Docker), `Prowler` (pip), `Semgrep` (pip), `ModelAudit` (pip). Others (MCPiranha, mcp-tool-auditor) get documented stubs with the recorded schema version and a dated TODO.
- **Exit gate:** At least 4 of 10 adapters validated against real recorded output. `tests/fixtures/ingest/README.md` updated with per-tool status.

**S2.2 — Adapter schema version pinning**
- Each adapter records `tool_version` in the fixture metadata. CI fails if the tool version changes without a matching fixture update. Prevents silent adapter drift.

---

### STAGE S3 — Local Scan UX: Make the Wedge Frictionless
> **Why:** `tensorguard scan --local --path .` is the realistic entry point for 95% of potential users (ML engineers, not cloud admins). It needs to be near-instant, visually clear, and produce zero false positives on a clean repo.

**S3.1 — Demo repo (`tests/demo_targets/`)**
- Add a small deliberately-vulnerable fake repo: a pickle file with a benign `__reduce__`, an `mcp.json` with an unpinned `npx` server, and a `.env` with a fake `OPENAI_API_KEY`. Used as the `--demo` target and for `record_fixtures.py`.
- Ensures `tensorguard scan --local --path tests/demo_targets/` always produces at least 3 CRITICAL findings that match the README's "aha moment" description.

**S3.2 — Output quality pass**
- Review every `Finding.message` and `remediation` field for clarity. A first-time user reading the console output must immediately understand: what's wrong, why it matters, how to fix it. No jargon, no internal rule IDs without explanation.
- **Exit gate:** 3 external reviewers (or a fresh read-through) confirm every finding message is actionable without reading docs.

**S3.3 — `tensorguard doctor` without AWS**
- Currently `tensorguard doctor` checks AWS credentials. Add a `--local` mode that checks: Python version, Rust extension installed (or warns fallback active), `uv` installed, `mcp.json` found/not found, model files found/not found. Gives users a preflight check before scanning.

---

### Phase 10.2 — Rust Dedup Engine
> Start this only after S1 (PyPI) is live. Building dedup without users means building for a problem you haven't validated.

- `rust/tensorguard-core/src/dedup.rs`: `FindingIndex` with `HashMap<String, Vec<NormalizedFinding>>` (SipHash-1-3 for untrusted string keys, ADR-026). `NodeMap` with `FxHashMap<u32, NodeIndex<u32>>` for internal trusted indices only.
- Deterministic `(component_hash | rule_or_cwe | location)` merge key. Sort merged output before returning. `sources: [tool_a, tool_b, tool_c]` on merged findings.
- Python wrapper `ai_spm/ingest/dedup.py`.
- **Exit gate:** 3 tools reporting the same MCP server → 1 entity; ≤5ms on 200 findings; collision benchmark.

### Phase 10.3 — Correlation Graph
- `petgraph DiGraph<u32>` with `skill` node type and `model→model` edges (ADR-043 schema: `schema: 1`).
- Python wrapper `ai_spm/ingest/graph.py`.
- **Exit gate:** golden graph test with known topology; schema frozen before tests.

### Phase 10.4 — Reachability BFS
- Blast-radius scoring via BFS + predecessor path. `R3` data-store reachability first, then `R2` skill/agent/model-handoff.
- **Exit gate:** ≥5× raw→reachable finding reduction on the demo target repo. If not met, publish negative result.

### Phase 10.5 — Wedge-A Prioritization
- Cross-tool severity fusion. Findings that appear in ≥2 tools get severity boosted by one level. Findings only in one tool and not reachable get suppressed to `INFO`.
- **Exit gate:** 50%+ precision on a held-out labeled finding set. If not met, publish negative result.

### Phase 10.6 — Benchmark & Falsification
- End-to-end benchmark: `200 raw findings → N reachable` measured on 3 target environments.
- **Commitment:** if reduction <5× or precision <50%, publish the negative result in `docs/benchmark.md` and do not claim the feature works.

---

### Phase 11 — Model Signing & Post-Quantum (Planned)
- Signing-profile audit: reject randomized-mode ML-DSA `rnd != 0^256` (subliminal channel mitigation, ADR post-Phase 9 research finding).
- GGUF verifiability manifest & per-tensor re-derivation, OMS/Sigstore integration, AISVS mapping.
- **Prerequisite:** Phase S1 (PyPI) + 10.2–10.4 complete.

### Phase 12 — Agent Skill Supply Chain (Planned)
- Skill registry collector (ClawHub/OpenClaw/MCP catalogs), MinHash LSH near-duplicate campaign detection, `OWASP AST02` mapping.

### Phase 13 — Compliance Evidence Export (Planned, deadline 2027-12-02)
- `frameworks.yaml` mapping to EU AI Act Art. 15 / Reg. (EU) 2026/1744, NIST AI 600-1, ISO/IEC 42001.
- Signed tamper-evident evidence packs and GRC JSON export.
- **Hard deadline:** EU AI Act enforcement date — 2 December 2027.

---

## 8. Master Documentation Index (`docs/`)

All public subsystem specifications and security guides are maintained in `docs/`:

1. **[System Architecture & Design](file:///c:/Pro/PROJECT/AI-SPM/docs/architecture.md):** Component diagrams, collector abstractions, and resilience patterns.
2. **[AI-SPM Security Rules Catalog](file:///c:/Pro/PROJECT/AI-SPM/docs/ai-spm-rules-catalog.md):** Detection logic and remediation commands.
3. **[AI Threat Model & Risk Analysis](file:///c:/Pro/PROJECT/AI-SPM/docs/threat-model.md):** STRIDE traceability matrix and mitigations.
4. **[Security Policy](file:///c:/Pro/PROJECT/AI-SPM/SECURITY.md):** Vulnerability disclosure process.
5. **[AWS Least-Privilege IAM Policy](file:///c:/Pro/PROJECT/AI-SPM/docs/aws-iam-permissions.md):** Read-only IAM policy for target environment auditing.
6. **[Product Requirements Document (PRD)](file:///c:/Pro/PROJECT/AI-SPM/docs/prd.md):** Personas, functional requirements, and performance targets.
