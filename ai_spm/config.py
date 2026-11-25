from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from ai_spm.engine.models import Severity


class AISPMConfig(BaseSettings):
    """Dynamic configuration for AI-SPM, overridable via AI_SPM_* environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="AI_SPM_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    app_name: str = "AI-SPM"
    app_version: str = "0.1.0"
    default_fail_on: Severity = Severity.HIGH

    # Weighted severity scoring (CSPM weighted pass-rate formula)
    severity_weights: dict[Severity, int] = Field(
        default_factory=lambda: {
            Severity.CRITICAL: 15,
            Severity.HIGH: 8,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.INFORMATIONAL: 0,
        }
    )

    # Model serialization heuristics (Tier 1 & Local)
    insecure_model_extensions: list[str] = Field(
        default_factory=lambda: [".pt", ".pth", ".bin", ".pkl", ".pickle", ".ckpt", ".joblib"]
    )
    safe_model_extensions: list[str] = Field(
        default_factory=lambda: [".safetensors", ".gguf", ".onnx"]
    )
    preferred_kms_encryption: str = "aws:kms"

    # Safe pickle opcode scanner bounds & allow/deny lists (ADR-004)
    dangerous_pickle_modules: list[str] = Field(
        default_factory=lambda: [
            "os",
            "posix",
            "nt",
            "subprocess",
            "socket",
            "builtins",
            "sys",
            "shutil",
            "runpy",
            "importlib",
            "ctypes",
            "webbrowser",
            "http",
        ]
    )
    dangerous_pickle_callables: list[str] = Field(
        default_factory=lambda: ["eval", "exec", "compile", "__import__", "system", "popen"]
    )
    allowed_pickle_globals: frozenset[tuple[str, str]] = Field(
        default_factory=lambda: frozenset(
            {
                ("torch._utils", "_rebuild_tensor_v2"),
                ("torch._utils", "_rebuild_parameter"),
                ("torch", "FloatStorage"),
                ("torch", "HalfStorage"),
                ("torch", "BFloat16Storage"),
                ("torch", "LongStorage"),
                ("collections", "OrderedDict"),
            }
        )
    )
    max_pickle_ops: int = Field(default=5_000_000, ge=1_000)
    max_zip_uncompressed_bytes: int = Field(default=5 * 1024**3, ge=1024)
    max_zip_ratio: float = Field(default=200.0, ge=1.0)
    per_file_timeout_s: float = Field(default=10.0, gt=0.0)
    max_safetensors_header: int = Field(default=100 * 1024 * 1024, ge=1024)
    max_local_files: int = Field(default=10_000, ge=1)
    max_workers: int = Field(default=8, ge=1, le=64)

    # Local MCP & injection heuristics (ADR-005)
    local_mcp_paths: list[str] = Field(
        default_factory=lambda: [
            "~/.cursor/mcp.json",
            "~/.config/Claude/claude_desktop_config.json",
            "~/AppData/Roaming/Claude/claude_desktop_config.json",
            "~/Library/Application Support/Claude/claude_desktop_config.json",
            "./.mcp.json",
            "./.cursor/mcp.json",
            "./.vscode/mcp.json",
        ]
    )
    max_mcp_config_bytes: int = Field(default=5 * 1024 * 1024, ge=1024)
    injection_markers: list[str] = Field(
        default_factory=lambda: [
            "ignore previous",
            "ignore all previous",
            "exfiltrate",
            "~/.ssh",
            "/.aws/credentials",
            "curl ",
            "wget ",
        ]
    )

    # Shadow AI & inference port heuristics (Tier 3)
    shadow_ai_ports: dict[int, str] = Field(
        default_factory=lambda: {
            11434: "Ollama",
            8000: "vLLM / Chroma",
            8001: "NVIDIA Triton",
            8080: "HuggingFace TGI / Weaviate",
            6333: "Qdrant",
            19530: "Milvus",
        }
    )

    # AI workload classification tags
    ai_workload_tags: dict[str, list[str]] = Field(
        default_factory=lambda: {
            "workload": ["ai", "ml", "llm", "rag", "genai"],
            "component": ["vectordb", "model", "agent", "inference"],
        }
    )


settings = AISPMConfig()
