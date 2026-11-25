"""Typed resource attribute models for local and cloud AI assets."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PickleHit(BaseModel):
    """Single dangerous or unknown global import discovered via static pickletools."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    module: str
    callable_name: str
    opcode: str
    offset: int | None = None
    severity_hint: Literal["CRITICAL", "MEDIUM"]


class LocalModelFileAttrs(BaseModel):
    """Normalized metadata for a local model checkpoint or weight file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["local_model_file"] = "local_model_file"
    path: str
    size_bytes: int
    sha256: str | None = None
    format: Literal[
        "pickle",
        "torch_zip",
        "safetensors",
        "gguf",
        "onnx",
        "keras_h5",
        "unknown",
    ]
    pickle_hits: list[PickleHit] = Field(default_factory=list)
    scan_error: str | None = None
    zip_ratio_exceeded: bool = False
    safetensors_header_ok: bool | None = None


class McpServerAttrs(BaseModel):
    """Normalized metadata for an audited MCP server configuration entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["mcp_server"] = "mcp_server"
    config_path: str
    server_name: str
    runner: Literal["npx", "uvx", "docker", "node", "python", "binary", "remote"]
    command: str
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    pinned: bool = True
    definition_sha256: str
    lock_state: Literal["match", "drift", "new", "no_lock"] = "no_lock"
    env_secret_keys: list[str] = Field(default_factory=list)
    hidden_unicode: list[str] = Field(default_factory=list)
    suspicious_blobs: list[str] = Field(default_factory=list)
    insecure_transport: bool = False
    pipe_to_shell: bool = False


class PublicAccessBlock(BaseModel):
    """Normalized S3 Public Access Block booleans."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    block_public_acls: bool = False
    ignore_public_acls: bool = False
    block_public_policy: bool = False
    restrict_public_buckets: bool = False

    @property
    def all_enabled(self) -> bool:
        return (
            self.block_public_acls
            and self.ignore_public_acls
            and self.block_public_policy
            and self.restrict_public_buckets
        )


class S3BucketAttrs(BaseModel):
    """Normalized metadata for an AWS S3 bucket."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["s3_bucket"] = "s3_bucket"
    sse_algorithm: Literal["AES256", "aws:kms", "aws:kms:dsse"] | None = None
    kms_key_arn: str | None = None
    kms_key_is_cmk: bool | None = None
    public_access_block: PublicAccessBlock | None = None
    pab_absent: bool | None = None
    account_pab_all_enabled: bool | None = None
    is_public_by_policy: bool | None = None
    versioning: Literal["Enabled", "Suspended", "Disabled"] | None = None
    sampled_keys: list[str] = Field(default_factory=list)
    model_extension_counts: dict[str, int] = Field(default_factory=dict)


class SageMakerNotebookAttrs(BaseModel):
    kind: Literal["sagemaker_notebook"] = "sagemaker_notebook"
    status: str = "Unknown"
    direct_internet_access: str | None = None
    root_access: str | None = None
    subnet_id: str | None = None
    security_groups: list[str] = Field(default_factory=list)
    kms_key_id: str | None = None
    role_arn: str | None = None
    min_imdsv_version: str | None = None


class SageMakerEndpointConfigAttrs(BaseModel):
    kind: Literal["sagemaker_endpoint_config"] = "sagemaker_endpoint_config"
    kms_key_id: str | None = None
    data_capture_enabled: bool = False
    data_capture_kms_key_id: str | None = None
    instance_types: list[str] = Field(default_factory=list)
    in_use: bool = False


class SageMakerTrainingJobAttrs(BaseModel):
    kind: Literal["sagemaker_training_job"] = "sagemaker_training_job"
    enable_network_isolation: bool | None = None
    has_vpc_config: bool = False
    training_image: str | None = None
    image_is_aws_owned: bool | None = None
    role_arn: str | None = None
    output_kms_key_id: str | None = None


class SageMakerDomainAttrs(BaseModel):
    kind: Literal["sagemaker_domain"] = "sagemaker_domain"
    app_network_access_type: str | None = None
    kms_key_id: str | None = None
    subnet_ids: list[str] = Field(default_factory=list)


class BedrockAccountConfigAttrs(BaseModel):
    kind: Literal["bedrock_account_config"] = "bedrock_account_config"
    logging_enabled: bool = False
    cloudwatch_enabled: bool = False
    s3_enabled: bool = False
    bedrock_in_use: bool = False


class BedrockGuardrailAttrs(BaseModel):
    kind: Literal["bedrock_guardrail"] = "bedrock_guardrail"
    guardrail_id: str
    status: str | None = None
    kms_key_arn: str | None = None


class BedrockAgentAttrs(BaseModel):
    kind: Literal["bedrock_agent"] = "bedrock_agent"
    agent_status: str | None = None
    role_arn: str | None = None
    guardrail_id: str | None = None
    guardrail_version: str | None = None
    guardrail_ready: bool | None = None
    customer_encryption_key_arn: str | None = None


class BedrockDataSourceAttrs(BaseModel):
    kind: Literal["bedrock_data_source"] = "bedrock_data_source"
    knowledge_base_id: str
    vector_store_arn: str | None = None
    kms_key_arn: str | None = None


class ECRRepositoryAttrs(BaseModel):
    kind: Literal["ecr_repository"] = "ecr_repository"
    scan_on_push: bool | None = None
    registry_scan_type: Literal["BASIC", "ENHANCED"] | None = None
    image_tag_mutability: str | None = None
    encryption_type: str | None = None
    kms_key: str | None = None
    policy_allows_public: bool | None = None


class OpenSearchDomainAttrs(BaseModel):
    kind: Literal["opensearch_domain"] = "opensearch_domain"
    vpc_id: str | None = None
    subnet_ids: list[str] = Field(default_factory=list)
    fgac_enabled: bool | None = None
    node_to_node_encryption: bool | None = None
    encryption_at_rest: bool | None = None
    kms_key_id: str | None = None
    enforce_https: bool | None = None
    public_principal: bool | None = None


class OpenSearchServerlessAttrs(BaseModel):
    kind: Literal["opensearch_serverless"] = "opensearch_serverless"
    collection_type: str | None = None
    kms_key_arn: str | None = None
    network_public: bool | None = None
    aws_owned_encryption_key: bool | None = None


class PolicyStatement(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    effect: str
    actions: list[str] = Field(default_factory=list)
    not_actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    not_resources: list[str] = Field(default_factory=list)
    has_condition: bool = False


class IamRoleAttrs(BaseModel):
    kind: Literal["iam_role"] = "iam_role"
    statements: list[PolicyStatement] = Field(default_factory=list)
    attached_managed_arns: list[str] = Field(default_factory=list)
    trust_principals: list[str] = Field(default_factory=list)
    trust_has_source_condition: bool = False
    permissions_boundary_arn: str | None = None


class IngressRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    protocol: str
    from_port: int | None = None
    to_port: int | None = None
    cidrs_v4: list[str] = Field(default_factory=list)
    cidrs_v6: list[str] = Field(default_factory=list)
    source_sg_ids: list[str] = Field(default_factory=list)


class EC2SecurityGroupAttrs(BaseModel):
    kind: Literal["ec2_security_group"] = "ec2_security_group"
    vpc_id: str | None = None
    attached: bool | None = None
    ingress: list[IngressRule] = Field(default_factory=list)


class K8sNodeAttrs(BaseModel):
    kind: Literal["k8s_node"] = "k8s_node"
    gpu_capacity: int = 0
    gpu_product: str | None = None
    mig_config: str | None = None
    toolkit_version: str | None = None
    multi_tenant_gpu_namespaces: int = 0


class K8sPodAttrs(BaseModel):
    kind: Literal["k8s_pod"] = "k8s_pod"
    namespace: str = "default"
    node_name: str | None = None
    privileged: bool = False
    host_network: bool = False
    host_pid: bool = False
    host_paths: list[str] = Field(default_factory=list)
    gpu_requested: int = 0
    images: list[str] = Field(default_factory=list)
    all_images_use_digest: bool = True
    run_as_non_root: bool | None = None
    runtime_class_name: str | None = None
