# SPDX-License-Identifier: Apache-2.0
"""Static MCP configuration auditor (ADR-005). Never launches or connects to servers."""

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Literal

from siftsec.collectors.base import BaseCollector
from siftsec.config import SiftsecConfig, settings
from siftsec.engine.attrs import McpServerAttrs
from siftsec.engine.models import CloudProvider, CloudResource
from siftsec.utils.redact import DEFAULT_SECRET_PATTERNS

_SECRET_ENV_NAME_RE = re.compile(r"(?i)(api[_-]?key|token|secret|password)")
_ENV_VAR_REF_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_SEMVER_AT_RE = re.compile(r"@\d+\.\d+\.\d+")
_UVX_PIN_RE = re.compile(r"(==|@)\S+")
_PIPE_SHELL_RE = re.compile(r"(curl|wget)\b.*\|\s*(sh|bash|zsh)", re.IGNORECASE)


def _classify_runner(
    command: str, url: str | None
) -> Literal["npx", "uvx", "docker", "node", "python", "binary", "remote"]:
    if url:
        return "remote"
    cmd_name = Path(command).name.lower()
    if cmd_name in ("npx", "npx.cmd"):
        return "npx"
    if cmd_name in ("uvx", "uvx.exe"):
        return "uvx"
    if cmd_name in ("docker", "podman"):
        return "docker"
    if cmd_name in ("node", "node.exe"):
        return "node"
    if cmd_name.startswith("python"):
        return "python"
    return "binary"


def _is_pinned(
    runner: Literal["npx", "uvx", "docker", "node", "python", "binary", "remote"],
    args: list[str],
) -> bool:
    if runner == "npx":
        pkg_args = [a for a in args if not a.startswith("-")]
        return any(_SEMVER_AT_RE.search(a) for a in pkg_args)
    if runner == "uvx":
        return any(_UVX_PIN_RE.search(a) for a in args)
    if runner == "docker":
        # Ignore port mappings (-p 8080:8080) or volume mounts (-v /a:/b) when checking image tags.
        non_flag_args = [a for a in args if not a.startswith("-") and not a.startswith("/")]
        image_candidates = [a for a in non_flag_args if not re.fullmatch(r"\d+:\d+", a)]
        if not image_candidates:
            return False
        image = image_candidates[-1]
        return ":latest" not in image and (
            "@sha256:" in image or bool(re.search(r":[A-Za-z0-9_.-]+$", image))
        )
    return True


def _scan_hidden_unicode(value: str, location: str) -> list[str]:
    hits: list[str] = []
    for ch in value:
        cp = ord(ch)
        is_tag = 0xE0000 <= cp <= 0xE007F
        is_zw = cp in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF)
        is_bidi = (0x202A <= cp <= 0x202E) or (0x2066 <= cp <= 0x2069)
        if is_tag or is_zw or is_bidi:
            hits.append(f"U+{cp:04X} at {location}")
            break
    return hits


def _scan_suspicious_blobs(value: str, cfg: SiftsecConfig, location: str) -> list[str]:
    hits: list[str] = []
    lower = value.lower()
    for marker in cfg.injection_markers:
        if marker.lower() in lower:
            hits.append(f"marker '{marker}' at {location}")

    for match in _BASE64_BLOB_RE.finditer(value):
        try:
            decoded = base64.b64decode(match.group(0), validate=True).decode(
                "utf-8", errors="ignore"
            )
        except ValueError:
            continue
        dec_lower = decoded.lower()
        for marker in cfg.injection_markers:
            if marker.lower() in dec_lower:
                hits.append(f"base64('{marker}') at {location}")
    return hits


def _extract_env_secret_keys(env: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    for k, v in env.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        if _ENV_VAR_REF_RE.match(v.strip()):
            continue
        matches_value = any(pat.search(v) for pat in DEFAULT_SECRET_PATTERNS.values())
        matches_name = bool(_SECRET_ENV_NAME_RE.search(k)) and len(v.strip()) > 0
        if matches_value or matches_name:
            # Store ONLY the key name, never the secret value.
            keys.append(k)
    return keys


class LocalMcpCollector(BaseCollector):
    """Audits local and workspace MCP configuration files statically."""

    def __init__(
        self,
        paths: list[Path] | None = None,
        cfg: SiftsecConfig | None = None,
        *,
        lockfile_path: Path | None = None,
        include_user_configs: bool = False,
    ) -> None:
        self.cfg = cfg or settings
        self.workspace_roots = list(paths) if paths else [Path(".")]
        self.lockfile_path = lockfile_path
        self.include_user_configs = include_user_configs

    def _discover_configs(self) -> list[Path]:
        seen: set[Path] = set()
        configs: list[Path] = []

        candidates: list[Path] = (
            [Path(p).expanduser() for p in self.cfg.local_mcp_paths]
            if self.include_user_configs
            else []
        )
        for root in self.workspace_roots:
            if root.is_file() and root.name.endswith(".json"):
                candidates.append(root)
            elif root.is_dir():
                candidates.extend(
                    [
                        root / ".mcp.json",
                        root / ".cursor" / "mcp.json",
                        root / ".vscode" / "mcp.json",
                        root / "mcp.json",
                    ]
                )

        for cand in candidates:
            try:
                resolved = cand.resolve()
            except OSError:
                continue
            if resolved not in seen and resolved.is_file():
                seen.add(resolved)
                configs.append(resolved)
        return configs

    def _load_lockfile(self, config_dir: Path) -> dict[str, dict[str, str]]:
        lock_path = self.lockfile_path or (config_dir / ".siftsec-lock.json")
        if not lock_path.is_file():
            return {}
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _audit_config(self, cfg_path: Path) -> list[CloudResource]:
        resources: list[CloudResource] = []
        try:
            if cfg_path.stat().st_size > self.cfg.max_mcp_config_bytes:
                return [
                    CloudResource(
                        arn=f"local://mcp/{hashlib.sha256(str(cfg_path).encode()).hexdigest()[:16]}",
                        id=cfg_path.name,
                        name=cfg_path.name,
                        service="mcp",
                        kind="mcp_server",
                        provider=CloudProvider.MCP,
                        region="local",
                        account_id="local",
                        gaps={"parse": "MaxConfigSizeExceeded"},
                    )
                ]
            raw_text = cfg_path.read_text(encoding="utf-8-sig")
            data = json.loads(raw_text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return [
                CloudResource(
                    arn=f"local://mcp/{hashlib.sha256(str(cfg_path).encode()).hexdigest()[:16]}",
                    id=cfg_path.name,
                    name=cfg_path.name,
                    service="mcp",
                    kind="mcp_server",
                    provider=CloudProvider.MCP,
                    region="local",
                    account_id="local",
                    gaps={"parse": type(exc).__name__},
                )
            ]

        if not isinstance(data, dict):
            return resources

        servers_obj: Any = data.get("mcpServers") or data.get("servers") or {}
        if not isinstance(servers_obj, dict):
            return resources

        lock_data = self._load_lockfile(cfg_path.parent)
        lock_for_cfg = lock_data.get(str(cfg_path), lock_data.get(cfg_path.name, {}))

        for server_name, server_def in servers_obj.items():
            if not isinstance(server_def, dict):
                continue
            command = str(server_def.get("command", ""))
            raw_args = server_def.get("args", [])
            args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
            url = str(server_def["url"]) if server_def.get("url") else None
            env = server_def.get("env", {}) if isinstance(server_def.get("env"), dict) else {}

            runner = _classify_runner(command, url)
            pinned = _is_pinned(runner, args)
            canonical = json.dumps(server_def, sort_keys=True, separators=(",", ":")).encode()
            def_sha = hashlib.sha256(canonical).hexdigest()

            if not lock_data:
                lock_state: Literal["match", "drift", "new", "no_lock"] = "no_lock"
            elif server_name not in lock_for_cfg:
                lock_state = "new"
            elif lock_for_cfg[server_name] == def_sha:
                lock_state = "match"
            else:
                lock_state = "drift"

            hidden_unicode: list[str] = []
            suspicious_blobs: list[str] = []
            for idx, arg in enumerate(args):
                hidden_unicode.extend(_scan_hidden_unicode(arg, f"args[{idx}]"))
                suspicious_blobs.extend(_scan_suspicious_blobs(arg, self.cfg, f"args[{idx}]"))
            hidden_unicode.extend(_scan_hidden_unicode(command, "command"))
            suspicious_blobs.extend(_scan_suspicious_blobs(command, self.cfg, "command"))
            if url:
                hidden_unicode.extend(_scan_hidden_unicode(url, "url"))
                suspicious_blobs.extend(_scan_suspicious_blobs(url, self.cfg, "url"))
            for env_k, env_v in env.items():
                if isinstance(env_v, str):
                    hidden_unicode.extend(_scan_hidden_unicode(env_v, f"env[{env_k}]"))
                    suspicious_blobs.extend(
                        _scan_suspicious_blobs(env_v, self.cfg, f"env[{env_k}]")
                    )

            full_cmd = f"{command} {' '.join(args)}"
            pipe_to_shell = bool(_PIPE_SHELL_RE.search(full_cmd))
            insecure_transport = bool(url and url.lower().startswith("http://"))

            attrs = McpServerAttrs(
                config_path=str(cfg_path),
                server_name=str(server_name),
                runner=runner,
                command=command,
                args=args,
                url=url,
                pinned=pinned,
                definition_sha256=def_sha,
                lock_state=lock_state,
                env_secret_keys=_extract_env_secret_keys(env),
                hidden_unicode=hidden_unicode,
                suspicious_blobs=suspicious_blobs,
                insecure_transport=insecure_transport,
                pipe_to_shell=pipe_to_shell,
            )

            arn_id = hashlib.sha256(f"{cfg_path}|{server_name}".encode()).hexdigest()[:16]
            resources.append(
                CloudResource(
                    arn=f"local://mcp/{arn_id}",
                    id=str(server_name),
                    name=str(server_name),
                    service="mcp",
                    kind="mcp_server",
                    provider=CloudProvider.MCP,
                    region="local",
                    account_id="local",
                    is_ai_workload=True,
                    ai_reason="mcp server config",
                    metadata=attrs.model_dump(),
                )
            )
        return resources

    def collect(self) -> list[CloudResource]:
        all_resources: list[CloudResource] = []
        for cfg_path in self._discover_configs():
            all_resources.extend(self._audit_config(cfg_path))
        return all_resources
