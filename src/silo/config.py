"""Configuration loading.

Config is TOML, taken from --config PATH, else $SILO_CONFIG, else $XDG_CONFIG_HOME/silo/silo.toml.
The file is trusted input: it chooses the image, the model directory and the base seccomp profile.
That is why it is never looked up in the current directory (silo is routinely run from model
directories, and a downloaded model must not be able to bring its own silo.toml), and why commands
that launch something print which file they used. Unknown keys and wrong types are errors: in a
containment tool a silently ignored typo is a silently missing control.
"""

from __future__ import annotations

import ipaddress
import os
import re
import tomllib
import types
import typing
from dataclasses import dataclass, field, fields
from pathlib import Path

DEFAULT_IMAGE = "ghcr.io/ggml-org/llama.cpp:server"
DEFAULT_PROBE_IMAGE = "docker.io/library/python:3.13-slim"
DEFAULT_SECCOMP_BASE = Path("/usr/share/containers/seccomp.json")

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
_MEMORY_RE = re.compile(r"^\d+[bkmg]?$", re.IGNORECASE)
# An image reference can never look like a podman option or carry whitespace.
_IMAGE_RE = re.compile(r"^[a-z0-9][A-Za-z0-9._/:@-]{0,254}$")
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Never a model directory themselves (a dedicated directory below /srv, /opt, /mnt ... is fine).
_SYSTEM_DIRS = frozenset(Path(p) for p in (
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt", "/proc", "/root",
    "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var", "/var/lib", "/var/home", "/var/tmp"))


class ConfigError(ValueError):
    pass


def _xdg(var: str, fallback: str) -> Path:
    value = os.environ.get(var)
    return Path(value) if value else Path.home() / fallback


def state_root() -> Path:
    return _xdg("XDG_STATE_HOME", ".local/state") / "silo"


def config_root() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config") / "silo"


def runtime_root() -> Path:
    # $XDG_RUNTIME_DIR is a per-user 0700 tmpfs: the right home for the model socket.
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    return Path(xdg) / "silo" if xdg else state_root() / "run"


@dataclass
class ModelConfig:
    dir: Path | None = None
    file: str | None = None
    ctx_size: int = 4096
    threads: int | None = None
    extra_args: list[str] = field(default_factory=list)


@dataclass
class RuntimeConfig:
    image: str = DEFAULT_IMAGE
    probe_image: str = DEFAULT_PROBE_IMAGE
    memory: str = "8g"
    cpus: float | None = None
    pids_limit: int = 256
    gpu: str = "none"  # none | nvidia | amd | dri
    seccomp_action: str = "errno"  # errno | kill
    seccomp_base: Path = DEFAULT_SECCOMP_BASE
    startup_timeout: float = 600.0


@dataclass
class GatewayConfig:
    listen: str = "127.0.0.1"
    port: int = 8088
    max_request_bytes: int = 1 << 20
    max_response_bytes: int = 16 << 20
    timeout: float = 600.0  # total seconds per request, connect to last byte
    max_concurrency: int = 4
    scanner: str = "monitor"  # off | monitor | enforce
    allow_tools: bool = False
    log_content: bool = False
    api_key_env: str | None = None


@dataclass
class Config:
    name: str = "default"
    model: ModelConfig = field(default_factory=ModelConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    source: Path | None = None

    @property
    def container_name(self) -> str:
        return f"silo-{self.name}"

    @property
    def socket_dir(self) -> Path:
        return runtime_root() / self.name

    @property
    def socket_path(self) -> Path:
        return self.socket_dir / "llama.sock"

    @property
    def audit_log(self) -> Path:
        return state_root() / "audit" / f"{self.name}.jsonl"

    @property
    def manifest_path(self) -> Path:
        return state_root() / "manifests" / f"{self.name}.json"

    @property
    def seccomp_path(self) -> Path:
        return state_root() / "seccomp" / f"{self.name}.json"

    def require_model(self) -> tuple[Path, str]:
        if self.model.dir is None or self.model.file is None:
            raise ConfigError("[model] dir and file must be set (see examples/silo.example.toml)")
        return self.model.dir, self.model.file


def _coerce(value, hint, where: str):
    """Check a TOML value against a dataclass type hint; returns the value to store."""
    if typing.get_origin(hint) in (types.UnionType, typing.Union):
        hint = next(a for a in typing.get_args(hint) if a is not type(None))
    if hint is Path:
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{where} must be a path string")
        return Path(os.path.expanduser(value)).resolve()
    if typing.get_origin(hint) is list:
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{where} must be a list of strings")
        return list(value)
    if hint is float:
        ok = type(value) in (int, float)
    else:  # bool, int, str: exact, so `port = true` or `allow_tools = 1` do not slip through
        ok = type(value) is hint
    if not ok:
        raise ConfigError(f"{where} must be {getattr(hint, '__name__', hint)}, got {type(value).__name__}")
    return float(value) if hint is float else value


def _build(cls, table, section: str):
    if not isinstance(table, dict):
        raise ConfigError(f"[{section}] must be a table")
    hints = typing.get_type_hints(cls)
    unknown = set(table) - set(hints)
    if unknown:
        raise ConfigError(f"unknown key(s) in [{section}]: {', '.join(sorted(unknown))}")
    return cls(**{key: _coerce(value, hints[key], f"{section}.{key}") for key, value in table.items()})


def _check_model_dir(path: Path) -> None:
    home = Path.home().resolve()
    if not path.is_absolute() or path in _SYSTEM_DIRS or path == home or path in home.parents:
        # The directory is bind-mounted and SELinux-relabelled (container_file_t); neither should
        # ever happen to a home directory or to anything above it.
        raise ConfigError(f"model.dir = {path} is too broad; use a directory that holds only model files")
    if ":" in str(path) or "," in str(path):
        raise ConfigError("model.dir must not contain ':' or ',' (podman volume syntax)")


def validate(cfg: Config) -> Config:
    if not isinstance(cfg.name, str) or not _NAME_RE.match(cfg.name):
        raise ConfigError(f"invalid silo name {cfg.name!r}: use [a-z0-9_.-], max 63 chars")
    rt, gw, m = cfg.runtime, cfg.gateway, cfg.model
    for label, image in (("runtime.image", rt.image), ("runtime.probe_image", rt.probe_image)):
        if not _IMAGE_RE.match(image):
            raise ConfigError(f"{label} is not a valid image reference: {image!r}")
    if rt.gpu not in ("none", "nvidia", "amd", "dri"):
        raise ConfigError("runtime.gpu must be one of: none, nvidia, amd, dri")
    if rt.seccomp_action not in ("errno", "kill"):
        raise ConfigError("runtime.seccomp_action must be 'errno' or 'kill'")
    if not _MEMORY_RE.match(rt.memory):
        raise ConfigError("runtime.memory must look like 8g, 512m, ...")
    if rt.pids_limit < 16:
        raise ConfigError("runtime.pids_limit must be >= 16")
    if rt.cpus is not None and rt.cpus <= 0:
        raise ConfigError("runtime.cpus must be > 0")
    if rt.startup_timeout <= 0 or gw.timeout <= 0:
        raise ConfigError("timeouts must be > 0")
    if ":" in str(rt.seccomp_base):
        raise ConfigError("runtime.seccomp_base must not contain ':'")
    if gw.scanner not in ("off", "monitor", "enforce"):
        raise ConfigError("gateway.scanner must be off, monitor or enforce")
    if not 1 <= gw.port <= 65535:
        raise ConfigError("gateway.port must be 1-65535")
    if gw.max_request_bytes < 1 or gw.max_response_bytes < 1 or gw.max_concurrency < 1:
        raise ConfigError("gateway size and concurrency limits must be >= 1")
    if gw.api_key_env is not None and not _ENV_RE.match(gw.api_key_env):
        raise ConfigError("gateway.api_key_env must be an environment variable name")
    if m.ctx_size < 1 or (m.threads is not None and m.threads < 1):
        raise ConfigError("model.ctx_size and model.threads must be >= 1")
    if m.dir is not None:
        _check_model_dir(m.dir)
    if m.file is not None and (not m.file or Path(m.file).is_absolute() or ".." in Path(m.file).parts):
        raise ConfigError("model.file must be a path relative to model.dir")
    try:
        loopback = ipaddress.ip_address(gw.listen).is_loopback
    except ValueError as exc:
        raise ConfigError(f"gateway.listen must be an IP address: {exc}") from exc
    if not loopback and not gw.api_key_env:
        raise ConfigError("refusing a non-loopback gateway.listen without gateway.api_key_env")
    return cfg


def default_config_path() -> Path:
    return config_root() / "silo.toml"


def load(path: Path | None = None) -> Config:
    explicit = path or (Path(os.environ["SILO_CONFIG"]) if os.environ.get("SILO_CONFIG") else None)
    candidate = explicit or default_config_path()
    if not candidate.is_file():
        if explicit:
            raise ConfigError(f"config file not found: {explicit}")
        return validate(Config())
    try:
        with candidate.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{candidate}: {exc}") from exc

    unknown = set(data) - {"silo", "model", "runtime", "gateway"}
    if unknown:
        raise ConfigError(f"unknown section(s): {', '.join(sorted(unknown))}")
    silo = data.get("silo", {})
    if not isinstance(silo, dict) or set(silo) - {"name"}:
        raise ConfigError("[silo] only supports 'name'")
    cfg = Config(
        name=silo.get("name", "default"),
        model=_build(ModelConfig, data.get("model", {}), "model"),
        runtime=_build(RuntimeConfig, data.get("runtime", {}), "runtime"),
        gateway=_build(GatewayConfig, data.get("gateway", {}), "gateway"),
        source=candidate.resolve(),
    )
    return validate(cfg)
