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
