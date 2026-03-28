# pyre-unsafe
"""cs init — Initialize CyberSentry project config."""

from __future__ import annotations

import typer
from rich.console import Console

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.output.terminal import print_success, print_info, print_warning

console = Console()


def init_command(
    path: str = typer.Argument(default=".", help="Project root directory"),
) -> None:
    """Initialize CyberSentry in the target directory."""
    from pathlib import Path

    project_root = Path(path).resolve()
    config = Config(project_root=project_root)

    if config.is_initialized:
        print_warning(f".cybersentry already exists at {config.config_dir}")
        print_info("Use existing config or delete .cybersentry/ to reinitialize.")
        return

    config_dir = config.initialize()
    console.print()
    print_success(f"CyberSentry initialized at [cyan]{config_dir}[/cyan]")
    print_info("Created: config.toml, runs/, policies/")
    print_info("Production uses OpenRouter by default; switch [cyan]general.llm_mode[/cyan] to [yellow]local[/yellow] for Ollama testing.")
    print_info("You can also override mode per shell with [yellow]CYBERSENTRY_LLM_MODE=local[/yellow].")
    print_info("Run [cyan]cs doctor[/cyan] to verify your setup.")
