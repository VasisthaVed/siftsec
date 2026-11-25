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

    # Model serialization heuristics (Tier 1)
    insecure_model_extensions: list[str] = Field(
        default_factory=lambda: [".pt", ".pth", ".bin", ".pkl", ".ckpt"]
    )
    safe_model_extensions: list[str] = Field(
        default_factory=lambda: [".safetensors", ".gguf", ".onnx"]
    )
    preferred_kms_encryption: str = "aws:kms"

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
