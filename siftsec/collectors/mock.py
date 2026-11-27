from siftsec.collectors.base import BaseCollector
from siftsec.engine.models import CloudProvider, CloudResource


class MockCollector(BaseCollector):
    """Simulates realistic enterprise AI infrastructure for zero-credential demo runs."""

    def collect(self) -> list[CloudResource]:
        return [
            # 1. Vulnerable S3 Bucket with legacy pickle weights and default SSE-S3
            CloudResource(
                arn="arn:aws:s3:::corp-ai-model-checkpoints-prod",
                id="corp-ai-model-checkpoints-prod",
                name="corp-ai-model-checkpoints-prod",
                service="s3",
                kind="s3_bucket",
                provider=CloudProvider.AWS,
                region="us-east-1",
                account_id="123456789012",
                tags={"workload": "ai", "data": "model-weights", "env": "prod"},
                metadata={
                    "encryption_type": "AES256",
                    "kms_key_id": None,
                    "public_access_block": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    },
                    "model_file_extensions": [".pt", ".bin", ".pkl"],
                },
            ),
            # 2. Compliant S3 Bucket with SafeTensors & KMS CMK
            CloudResource(
                arn="arn:aws:s3:::corp-ai-safetensors-v2",
                id="corp-ai-safetensors-v2",
                name="corp-ai-safetensors-v2",
                service="s3",
                kind="s3_bucket",
                provider=CloudProvider.AWS,
                region="us-east-1",
                account_id="123456789012",
                tags={"workload": "ai", "data": "model-weights"},
                metadata={
                    "encryption_type": "aws:kms",
                    "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/cmk-ai-models",
                    "kms_key_is_cmk": True,
                    "public_access_block": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                    "model_file_extensions": [".safetensors"],
                },
            ),
            # 3. Vulnerable SageMaker Notebook with DIA & RootAccess Enabled
            CloudResource(
                arn="arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/ml-research-dev",
                id="ml-research-dev",
                name="ml-research-dev",
                service="sagemaker",
                kind="sagemaker_notebook",
                provider=CloudProvider.AWS,
                region="us-east-1",
                account_id="123456789012",
                tags={"team": "data-science"},
                metadata={
                    "direct_internet_access": "Enabled",
                    "root_access": "Enabled",
                    "subnet_id": None,
                    "min_imdsv_version": "1",
                },
            ),
            # 4. Vulnerable Bedrock Agent missing guardrails & session KMS
            CloudResource(
                arn="arn:aws:bedrock:us-east-1:123456789012:agent/FIN-REPORT-AUTONOMOUS-AGENT",
                id="FIN-REPORT-AUTONOMOUS-AGENT",
                name="FIN-REPORT-AUTONOMOUS-AGENT",
                service="bedrock",
                kind="bedrock_agent",
                provider=CloudProvider.AWS,
                region="us-east-1",
                account_id="123456789012",
                tags={"purpose": "financial-reasoning"},
                metadata={"guardrail_id": None, "customer_encryption_key_arn": None},
            ),
            # 5. Public OpenSearch Vector DB (Embedding Inversion Risk)
            CloudResource(
                arn="arn:aws:es:us-east-1:123456789012:domain/rag-vector-search-cluster",
                id="rag-vector-search-cluster",
                name="rag-vector-search-cluster",
                service="opensearch",
                kind="opensearch_domain",
                provider=CloudProvider.AWS,
                region="us-east-1",
                account_id="123456789012",
                tags={"component": "vectordb", "pipeline": "rag"},
                metadata={
                    "in_vpc": False,
                    "fgac_enabled": False,
                    "node_to_node_encryption": False,
                    "public_principal": False,
                },
            ),
            # 6. Over-privileged IAM role on AI agent
            CloudResource(
                arn="arn:aws:iam::123456789012:role/BedrockExecutionAdminRole",
                id="BedrockExecutionAdminRole",
                name="BedrockExecutionAdminRole",
                service="iam",
                kind="iam_role",
                provider=CloudProvider.AWS,
                region="global",
                account_id="123456789012",
                tags={"attached-to": "bedrock-agent"},
                metadata={"has_wildcard_policy": True},
            ),
            # 7. Compromised MCP Server manifest
            CloudResource(
                arn="mcp://local/untrusted-github-context-tool",
                id="untrusted-github-context-tool",
                name="untrusted-github-context-tool",
                service="mcp",
                kind="mcp_server_demo",
                provider=CloudProvider.MCP,
                region="local",
                account_id="local",
                tags={"runtime": "mcp-stdio"},
                metadata={"has_suspicious_instructions": True},
            ),
        ]
