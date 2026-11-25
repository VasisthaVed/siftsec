# AI-SPM Security Rules Catalog

This document defines the formal detection rules implemented by the **AI-SPM Scanner**. Each rule addresses real-world threat vectors targeting machine learning infrastructure, proprietary model weights, vector databases, and generative AI pipelines on AWS.

---

## Rule Taxonomy & Identifier Standard

All rule IDs follow the standard: `AI-SPM-<SERVICE>-<NUMBER>`
* **Severity Levels:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`
* **Target Services:** `S3`, `SAGEMAKER`, `BEDROCK`, `ECR`, `OPENSEARCH`, `IAM`

---

## 1. Amazon S3 (AI Model Weights & Training Data)

### `AI-SPM-S3-001`: Unencrypted AI Model Weights Storage
* **Severity:** `CRITICAL`
* **Threat Vector:** Model Weight Theft & Intellectual Property Loss (MITRE ATLAS: `AML.T0044`)
* **OWASP LLM:** `LLM02:2025` (Sensitive Information Disclosure)
* **Target:** S3 buckets containing model weights (`.bin`, `.pt`, `.safetensors`, `.onnx`, `.h5`) or tagged with `workload=ai` / `data=model`.
* **Detection Logic:**
  - Query bucket encryption configuration (`s3:GetBucketEncryption`).
  - Flag as `FAIL` if server-side encryption is disabled or relies only on default `AES256` (SSE-S3) instead of AWS KMS Customer-Managed Keys (`aws:kms` with CMK).
* **Remediation:**
  - Configure default bucket encryption to use an AWS KMS Customer-Managed Key with granular key policies.

### `AI-SPM-S3-002`: Public Access Allowed on AI Datasets/Artifacts Bucket
* **Severity:** `CRITICAL`
* **Threat Vector:** Unauthorized Model Download & Data Poisoning (MITRE ATLAS: `AML.T0020`, `AML.T0044`)
* **OWASP LLM:** `LLM02:2025`, `LLM03:2025`
* **Target:** S3 buckets tagged for AI workloads or holding datasets/model artifacts.
* **Detection Logic:**
  - Check `s3:GetPublicAccessBlock`.
  - Flag as `FAIL` if any of `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, or `RestrictPublicBuckets` is `False`.
* **Remediation:**
  - Enable AWS S3 Block Public Access settings on the bucket and account level.

### `AI-SPM-S3-003`: Missing Object Versioning on Training Datasets
* **Severity:** `MEDIUM`
* **Threat Vector:** Training Data Poisoning & Ransomware / Tampering (MITRE ATLAS: `AML.T0020`)
* **OWASP LLM:** `LLM03:2025` (Supply Chain Vulnerabilities)
* **Target:** S3 buckets holding training/fine-tuning datasets.
* **Detection Logic:**
  - Check `s3:GetBucketVersioning`.
  - Flag as `FAIL` if `Status != 'Enabled'`.
* **Remediation:**
  - Enable S3 Bucket Versioning and consider enabling S3 Object Lock (WORM) for training data provenance.

### `AI-SPM-S3-004`: Insecure Model Checkpoint Serialization (Pickle vs SafeTensors)
* **Severity:** `MEDIUM` (Heuristic)
* **Threat Vector:** Remote Code Execution via Insecure Model Deserialization (MITRE ATLAS: `AML.T0010`)
* **OWASP LLM:** `LLM04:2026` (Model Supply Chain Vulnerabilities)
* **Target:** S3 buckets storing AI model weights.
* **Detection Logic:**
  - Sample object keys in the bucket for legacy PyTorch/pickle checkpoint extensions (`.pt`, `.pth`, `.bin`, `.pkl`).
  - Flag as `FAIL` if legacy pickle formats exist without accompanying SafeTensors (`.safetensors`) or cryptographic integrity hashes.
* **Remediation:**
  - Convert model checkpoints to the safe `.safetensors` format (e.g. using Hugging Face `safetensors`) or enforce PyTorch 2.6+ `torch.load(..., weights_only=True)`.

---

## 2. Amazon SageMaker (Training, Inference & Workstations)

### `AI-SPM-SAGEMAKER-001`: SageMaker Notebook Direct Internet Access Enabled
* **Severity:** `CRITICAL`
* **Threat Vector:** Shadow AI & Data Exfiltration via Outbound Egress (MITRE ATLAS: `AML.T0043`, `AML.T0044`)
* **OWASP LLM:** `LLM02:2025`
* **AWS Security Hub:** `SageMaker.1` (`sagemaker-notebook-no-direct-internet-access`)
* **Target:** `AWS::SageMaker::NotebookInstance`
* **Detection Logic:**
  - Inspect `DirectInternetAccess` property on `DescribeNotebookInstance`.
  - Flag as `FAIL` if `DirectInternetAccess == 'Enabled'`.
* **Remediation:**
  - Re-create or configure notebook instances with `DirectInternetAccess: Disabled` and attach them to a private VPC subnet with managed egress through security inspection firewalls/proxies.

### `AI-SPM-SAGEMAKER-002`: SageMaker Notebook Missing Custom VPC Attachment
* **Severity:** `HIGH`
* **Threat Vector:** Network Lateral Movement & Uncontrolled Egress
* **AWS Security Hub:** `SageMaker.2`
* **Target:** `AWS::SageMaker::NotebookInstance`
* **Detection Logic:**
  - Inspect `SubnetId` and `SecurityGroupIds` on `DescribeNotebookInstance`.
  - Flag as `FAIL` if `SubnetId` is missing or empty (running outside custom VPC).
* **Remediation:**
  - Deploy SageMaker Notebook instances inside private subnets within a dedicated corporate VPC.

### `AI-SPM-SAGEMAKER-003`: Root Privileges Enabled on SageMaker Notebook Instance
* **Severity:** `HIGH`
* **Threat Vector:** Privilege Escalation & Host Compromise
* **AWS Security Hub:** `SageMaker.3`
* **Target:** `AWS::SageMaker::NotebookInstance`
* **Detection Logic:**
  - Inspect `RootAccess` on `DescribeNotebookInstance`.
  - Flag as `FAIL` if `RootAccess == 'Enabled'`.
* **Remediation:**
  - Set `RootAccess: Disabled` to restrict users from installing unapproved packages or tampering with security agents and OS audit logs.

### `AI-SPM-SAGEMAKER-004`: SageMaker Endpoint Unencrypted Storage Volume (EBS KMS)
* **Severity:** `HIGH`
* **Threat Vector:** Data at Rest Compromise on Inference Nodes
* **Target:** `AWS::SageMaker::EndpointConfig`
* **Detection Logic:**
  - Inspect `KmsKeyId` in `ProductionVariants` or endpoint storage configuration.
  - Flag as `FAIL` if `KmsKeyId` is missing or default.
* **Remediation:**
  - Attach a Customer-Managed KMS Key (`KmsKeyId`) to the SageMaker Endpoint Configuration.

### `AI-SPM-SAGEMAKER-005`: SageMaker Training Job Missing Network Isolation
* **Severity:** `HIGH`
* **Threat Vector:** Supply-Chain Code Execution During Model Training (Pickle / Dependency Poisoning)
* **Target:** `AWS::SageMaker::TrainingJob`
* **Detection Logic:**
  - Inspect `EnableNetworkIsolation` in `DescribeTrainingJob`.
  - Flag as `FAIL` if `EnableNetworkIsolation == False` when custom third-party containers are used.
* **Remediation:**
  - Set `EnableNetworkIsolation: True` to prevent containerized training code from making arbitrary outbound internet requests.

---

## 3. Amazon Bedrock (Foundation Models, Agents & RAG)

### `AI-SPM-BEDROCK-001`: Bedrock Model Invocation Logging Disabled
* **Severity:** `HIGH`
* **Threat Vector:** Zero Auditability for Prompt Injections, Jailbreaks & Exfiltration
* **OWASP LLM:** `LLM01:2025` (Prompt Injection), `LLM02:2025` (Sensitive Information Disclosure)
* **Target:** Bedrock Account / Region Configuration
* **Detection Logic:**
  - Call `bedrock:GetModelInvocationLoggingConfiguration`.
  - Flag as `FAIL` if logging configuration is not set, or both `cloudWatchConfig` and `s3Config` are disabled.
* **Remediation:**
  - Enable Model Invocation Logging streaming to an encrypted Amazon CloudWatch Log Group or KMS-encrypted S3 audit bucket.

### `AI-SPM-BEDROCK-002`: Bedrock Knowledge Base Data Source Missing KMS CMK Encryption
* **Severity:** `HIGH`
* **Threat Vector:** Unauthorized Access to RAG Embeddings & Knowledge Source Data
* **OWASP LLM:** `LLM02:2025`
* **AWS Security Hub:** `Bedrock.1` (`bedrock-data-source-encryption-enabled`)
* **Target:** `AWS::Bedrock::DataSource`
* **Detection Logic:**
  - Call `bedrock-agent:GetDataSource`.
  - Inspect `serverSideEncryptionConfiguration.kmsKeyArn`.
  - Flag as `FAIL` if KMS Key ARN is missing, null, or using default AWS-managed key.
* **Remediation:**
  - Configure the Knowledge Base data source with a Customer-Managed Key (CMK).

### `AI-SPM-BEDROCK-003`: Bedrock Agent Missing Guardrails / Filter Controls
* **Severity:** `HIGH`
* **Threat Vector:** Excessive Agency, Prompt Injection & Harmful Content Generation
* **OWASP LLM:** `LLM01:2025`, `LLM06:2025` (Excessive Agency)
* **Target:** `AWS::Bedrock::Agent`
* **Detection Logic:**
  - Call `bedrock-agent:GetAgent`.
  - Inspect `guardrailConfiguration`.
  - Flag as `FAIL` if `guardrailIdentifier` is not configured or guardrail status is not active.
* **Remediation:**
  - Attach an Amazon Bedrock Guardrail enforcing PII masking, toxic content filtration, and denied prompt injection patterns.

---

## 4. Amazon ECR (AI/ML Container Images & Models)

### `AI-SPM-ECR-001`: ECR Repository Vulnerability Scan on Push Disabled
* **Severity:** `HIGH`
* **Threat Vector:** Supply Chain Poisoning via Compromised Base Images (PyTorch, TensorFlow, CUDA)
* **OWASP LLM:** `LLM03:2025` (Supply Chain Vulnerabilities)
* **Target:** `AWS::ECR::Repository` (tagged for AI or named `*model*`, `*inference*`, `*sagemaker*`, `*train*`)
* **Detection Logic:**
  - Inspect `imageScanningConfiguration.scanOnPush` on `DescribeRepositories`.
  - Flag as `FAIL` if `scanOnPush == False`.
* **Remediation:**
  - Enable `imageScanningConfiguration: { scanOnPush: true }` or activate AWS Inspector continuous scanning for ECR.

### `AI-SPM-ECR-002`: ECR Image Tag Immutability Disabled
* **Severity:** `MEDIUM`
* **Threat Vector:** Image Overwrite & Model Trojan Injection
* **Target:** `AWS::ECR::Repository`
* **Detection Logic:**
  - Inspect `imageTagMutability` on `DescribeRepositories`.
  - Flag as `FAIL` if `imageTagMutability == 'MUTABLE'`.
* **Remediation:**
  - Set `imageTagMutability: 'IMMUTABLE'` to prevent overwriting production inference containers (e.g. `latest` tag poisoning).

---

## 5. Amazon OpenSearch Service / OpenSearch Serverless (Vector DBs)

### `AI-SPM-OPENSEARCH-001`: OpenSearch Vector DB Domain Exposed to Public Internet
* **Severity:** `CRITICAL`
* **Threat Vector:** Vector DB Exposure & Semantic Inversion Attack
* **OWASP LLM:** `LLM02:2025`
* **Target:** `AWS::OpenSearch::Domain` (used for RAG or tagged `workload=ai` / `component=vectordb`)
* **Detection Logic:**
  - Inspect `VPCOptions` in `DescribeDomain`.
  - Flag as `FAIL` if `VPCOptions` is missing or `VPCId` is null (public endpoint enabled).
* **Remediation:**
  - Migrate OpenSearch vector domain into private subnets within a VPC and access via Security Groups or PrivateLink.

### `AI-SPM-OPENSEARCH-002`: OpenSearch Fine-Grained Access Control (FGAC) Disabled
* **Severity:** `HIGH`
* **Threat Vector:** Unauthorized Access to Multi-Tenant Vector Embeddings & Raw Metadata
* **Target:** `AWS::OpenSearch::Domain`
* **Detection Logic:**
  - Inspect `AdvancedSecurityOptions.Enabled` in `DescribeDomain`.
  - Flag as `FAIL` if `AdvancedSecurityOptions.Enabled == False`.
* **Remediation:**
  - Enable Fine-Grained Access Control (FGAC) with IAM or SAML master users and configure index/document-level security.

### `AI-SPM-OPENSEARCH-003`: OpenSearch Node-to-Node Encryption Disabled
* **Severity:** `HIGH`
* **Threat Vector:** Interception of Vectors & In-Transit Embeddings Across Shards
* **Target:** `AWS::OpenSearch::Domain`
* **Detection Logic:**
  - Inspect `NodeToNodeEncryptionOptions.Enabled`.
  - Flag as `FAIL` if `Enabled == False`.
* **Remediation:**
  - Enable Node-to-Node Encryption with TLS for the cluster.

---

## 6. AWS IAM (Autonomous Agents & Inference Execution Roles)

### `AI-SPM-IAM-001`: Excessive Agency & Wildcard Permissions in AI Roles
* **Severity:** `HIGH`
* **Threat Vector:** Confused Deputy & Blast Radius Expansion via Agentic Exploitation (MITRE ATLAS: `AML.T0043` | NIST AI 600-1: `MG-3.1`)
* **OWASP LLM:** `LLM06:2025` (Excessive Agency)
* **Target:** `AWS::IAM::Role` (attached to Bedrock Agents, SageMaker Notebooks, or SageMaker Endpoints)
* **Detection Logic:**
  - Inspect attached inline and managed policies for wildcard actions (`Action: "*"`, `Action: "s3:*"`, `Action: "dynamodb:*"`) paired with wildcard resources (`Resource: "*"`).
  - Flag as `FAIL` if broad administrative write or data exfiltration privileges exist on AI execution roles.
* **Remediation:**
  - Scope IAM policies down to minimum required actions and specific target ARNs (see AWS IAM Least-Privilege documentation and `docs/aws-iam-permissions.md`).

---

## 7. Summary Matrix: Severity & Framework Alignment

| Rule ID | Service | Severity | MITRE ATLAS | OWASP LLM | AWS Security Standard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `AI-SPM-S3-001` | S3 | **CRITICAL** | `AML.T0044` | `LLM02:2025` | CIS AWS 2.1.1 |
| `AI-SPM-S3-002` | S3 | **CRITICAL** | `AML.T0020`, `AML.T0044` | `LLM02`, `LLM03` | CIS AWS 2.1.5 |
| `AI-SPM-S3-003` | S3 | **MEDIUM** | `AML.T0020` | `LLM03:2025` | AWS Well-Architected |
| `AI-SPM-S3-004` | S3 | **MEDIUM** | `AML.T0010` | `LLM04:2026` | SafeTensors / PickleScan |
| `AI-SPM-SAGEMAKER-001` | SageMaker | **CRITICAL** | `AML.T0043`, `AML.T0044` | `LLM02:2025` | `SageMaker.1` |
| `AI-SPM-SAGEMAKER-002` | SageMaker | **HIGH** | Lateral Movement | Infrastructure | `SageMaker.2` |
| `AI-SPM-SAGEMAKER-003` | SageMaker | **HIGH** | Host Compromise | Least Privilege | `SageMaker.3` |
| `AI-SPM-SAGEMAKER-004` | SageMaker | **HIGH** | `AML.T0044` | `LLM02:2025` | AWS Well-Architected |
| `AI-SPM-SAGEMAKER-005` | SageMaker | **HIGH** | `AML.T0020` | `LLM03:2025` | AWS Security Hub |
| `AI-SPM-BEDROCK-001` | Bedrock | **HIGH** | Audit Gap | `LLM01`, `LLM02` | AWS Well-Architected ML |
| `AI-SPM-BEDROCK-002` | Bedrock | **HIGH** | `AML.T0044` | `LLM02:2025` | `Bedrock.1` |
| `AI-SPM-BEDROCK-003` | Bedrock | **CRITICAL** | `AML.T0043` | `LLM01`, `LLM06` | Bedrock Guardrails |
| `AI-SPM-ECR-001` | ECR | **HIGH** | `AML.T0020` | `LLM03:2025` | CIS AWS 2.4.1 |
| `AI-SPM-ECR-002` | ECR | **MEDIUM** | Supply Chain | `LLM03:2025` | ECR Best Practices |
| `AI-SPM-OPENSEARCH-001` | OpenSearch | **CRITICAL** | `AML.T0044` | `LLM02:2025` | OpenSearch Security |
| `AI-SPM-OPENSEARCH-002` | OpenSearch | **HIGH** | Model Inversion | `LLM02:2025` | OpenSearch FGAC |
| `AI-SPM-OPENSEARCH-003` | OpenSearch | **HIGH** | Data Interception | In-Transit Encryption | AWS Security Hub |
| `AI-SPM-IAM-001` | IAM | **HIGH** | `AML.T0043` | `LLM06:2025` | Least Privilege / NIST MG-3.1 |
