# pyre-unsafe
"""Configuration loader — reads .cybersentry/config.toml and env vars."""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

try:
    import tomli_w
except ImportError:
    tomli_w = None  # type: ignore[assignment]

from dotenv import load_dotenv, find_dotenv

# Load .env file — searches up from cwd to find it
load_dotenv(find_dotenv(usecwd=True))

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    "general": {
        "project_name": "my-project",
        "llm_mode": "local",
        "chat_model": "qwen2.5-coder:7b",
        "coding_model": "qwen2.5-coder:7b",
        "max_react_iterations": 10,
        "debate_rounds": 3,
    },
    "scanners": {
        "enabled": ["bandit", "semgrep"],
    },
    "openrouter": {
        "api_key_env": "OPENROUTER_API_KEY",
        "base_url": "https://openrouter.ai/api/v1",
        "temperature": 0.3,
        "max_tokens": 4096,
        "chat_model": "openai/gpt-4o-mini",
        "coding_model": "qwen/qwen3-coder:free",
    },
    "local_llm": {
        "base_url": "http://localhost:11434/v1",
        "chat_model": "qwen2.5-coder:7b",
        "coding_model": "qwen2.5-coder:7b",
    },
    "scoring": {
        "severity_weights": {
            "CRITICAL": 1.00,
            "HIGH": 0.75,
            "MEDIUM": 0.45,
            "LOW": 0.20,
            "INFO": 0.05,
        },
    },
}

CONFIG_DIR_NAME = ".cybersentry"
CONFIG_FILE_NAME = "config.toml"
RUNS_DIR_NAME = "runs"


# ---------------------------------------------------------------------------
# Config class
# ---------------------------------------------------------------------------

class Config:
    """Loads and provides access to CyberSentry configuration."""

    def __init__(self, project_root: Path | None = None) -> None:
        self.project_root = project_root or Path.cwd()
        self.config_dir = self.project_root / CONFIG_DIR_NAME
        self.config_file = self.config_dir / CONFIG_FILE_NAME
        self.runs_dir = self.config_dir / RUNS_DIR_NAME
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load config from TOML file, falling back to defaults."""
        self._data = copy.deepcopy(DEFAULT_CONFIG)
        if self.config_file.exists() and tomllib is not None:
            with open(self.config_file, "rb") as f:
                file_data = tomllib.load(f)
            self._deep_merge(self._data, file_data)

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        for key, val in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(val, dict):
                Config._deep_merge(base[key], val)
            else:
                base[key] = val
        return base

    # -- accessors ----------------------------------------------------------

    def get(self, *keys: str, default: Any = None) -> Any:
        """Dot-path accessor: config.get('openrouter', 'temperature')."""
        node = self._data
        for k in keys:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                return default
        return node

    @property
    def openrouter_api_key(self) -> str:
        env_name = self.get("openrouter", "api_key_env", default="OPENROUTER_API_KEY")
        return os.environ.get(env_name, "")

    @property
    def llm_mode(self) -> str:
        mode = os.environ.get("CYBERSENTRY_LLM_MODE") or self.get("general", "llm_mode", default="local")
        mode = str(mode).strip().lower()
        return mode if mode in {"production", "local"} else "local"

    @property
    def llm_base_url(self) -> str:
        if self.llm_mode == "local":
            return self.get("local_llm", "base_url", default="http://localhost:11434/v1")
        return self.get("openrouter", "base_url", default="https://openrouter.ai/api/v1")

    @property
    def using_local_llm(self) -> bool:
        return self.llm_mode == "local"

    @property
    def chat_model(self) -> str:
        if self.using_local_llm:
            return self.get("local_llm", "chat_model", default="qwen2.5-coder:7b")
        return self.get("openrouter", "chat_model", default="openai/gpt-4o-mini")

    @property
    def coding_model(self) -> str:
        if self.using_local_llm:
            return self.get("local_llm", "coding_model", default="qwen2.5-coder:7b")
        return self.get("openrouter", "coding_model", default="qwen/qwen3-coder:free")

    @property
    def temperature(self) -> float:
        return float(self.get("openrouter", "temperature", default=0.3))

    @property
    def max_tokens(self) -> int:
        return int(self.get("openrouter", "max_tokens", default=4096))

    @property
    def debate_rounds(self) -> int:
        return int(self.get("general", "debate_rounds", default=3))

    @property
    def max_react_iterations(self) -> int:
        return int(self.get("general", "max_react_iterations", default=10))

    @property
    def enabled_scanners(self) -> list[str]:
        return self.get("scanners", "enabled", default=["bandit", "semgrep"])

    # -- initialization -----------------------------------------------------

    def initialize(self) -> Path:
        """Create .cybersentry directory with default config."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        (self.config_dir / "policies").mkdir(exist_ok=True)

        if not self.config_file.exists() and tomli_w is not None:
            with open(self.config_file, "wb") as f:
                tomli_w.dump(DEFAULT_CONFIG, f)

        self._load()
        return self.config_dir

    @property
    def default_model(self) -> str:
        """Alias for chat_model — used by cs doctor."""
        return self.chat_model

    @property
    def llm_backend_label(self) -> str:
        return "Ollama (primary)" if self.using_local_llm else "OpenRouter (backup)"

    @property
    def is_initialized(self) -> bool:
        return self.config_dir.exists()
