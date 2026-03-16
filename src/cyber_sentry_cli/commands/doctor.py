# pyre-unsafe
"""cs doctor — Validate environment, tools, and configuration."""

from __future__ import annotations

import shutil
import subprocess
import sys
from urllib.parse import urlparse

import httpx

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.scanners.base import find_tool
from cyber_sentry_cli.output.terminal import (
    console,
    print_doctor_table,
    print_error,
    print_info,
    print_success,
)


def doctor_command() -> None:
    """Check that all required tools and configuration are in place."""
    config = Config()
    checks: list[tuple[str, bool, str]] = []

    # 1. Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 10)
    checks.append(("Python >= 3.10", py_ok, py_ver))

    # 2. CyberSentry config
    checks.append((".cybersentry/ initialized", config.is_initialized,
                   str(config.config_dir) if config.is_initialized else "Run: cs init"))

    # 3. Semgrep
    semgrep_path = find_tool("semgrep")
    if semgrep_path:
        try:
            result = subprocess.run([semgrep_path, "--version"], capture_output=True, text=True, timeout=10)
            semgrep_ver = result.stdout.strip()
            checks.append(("Semgrep", True, semgrep_ver))
        except Exception:
            checks.append(("Semgrep", True, "found"))
    else:
        checks.append(("Semgrep", False, "pip install semgrep"))

    # 4. Bandit
    bandit_path = find_tool("bandit")
    if bandit_path:
        try:
            result = subprocess.run([bandit_path, "--version"], capture_output=True, text=True, timeout=10)
            bandit_ver = result.stdout.strip().split("\n")[0]
            checks.append(("Bandit", True, bandit_ver))
        except Exception:
            checks.append(("Bandit", True, "found"))
    else:
        checks.append(("Bandit", False, "pip install bandit"))

    # 5. LLM backend
    checks.append(("LLM Mode", True, f"{config.llm_mode} ({config.llm_backend_label})"))
    if config.using_local_llm:
        parsed = urlparse(config.llm_base_url)
        ollama_root = f"{parsed.scheme}://{parsed.netloc}"
        try:
            response = httpx.get(f"{ollama_root}/api/tags", timeout=5.0)
            response.raise_for_status()
            models = response.json().get("models", [])
            model_names = ", ".join(m.get("name", "") for m in models[:3] if m.get("name"))
            detail = model_names or "reachable"
            checks.append(("Ollama Endpoint", True, detail))
        except Exception:
            checks.append(("Ollama Endpoint", False, f"Start Ollama at {ollama_root}"))
    else:
        api_key = config.openrouter_api_key
        if api_key:
            masked = api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
            checks.append(("OpenRouter API Key", True, f"set ({masked})"))
        else:
            checks.append(("OpenRouter API Key", False, "export OPENROUTER_API_KEY=your-key"))

    # 6. Active LLM models
    checks.append(("Chat Model", True, config.chat_model))
    checks.append(("Coding Model", True, config.coding_model))

    # Display
    console.print()
    print_doctor_table(checks)
    console.print()

    all_ok = all(ok for _, ok, _ in checks)
    if all_ok:
        print_success("All checks passed! CyberSentry is ready to hunt. 🎯")
    else:
        print_info("Fix the failing checks above, then run [cyan]cs doctor[/cyan] again.")
