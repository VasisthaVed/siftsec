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
