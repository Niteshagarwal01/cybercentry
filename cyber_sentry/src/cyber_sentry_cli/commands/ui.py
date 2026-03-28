# pyre-unsafe
"""cs ui — launch the CyberSentry web UI/API server."""

from __future__ import annotations

import typer

from cyber_sentry_cli.output.terminal import print_error, print_info


def ui_command(host: str = "127.0.0.1", port: int = 8080, reload: bool = False) -> None:
    """Run FastAPI + static UI server for demo and team workflows."""
    try:
        import uvicorn
    except Exception:
        print_error("UI dependencies are missing.")
        print_info("Install with: [cyan]pip install 'cyber-sentry[ui]'[/cyan]")
        raise typer.Exit(code=1)

    print_info(f"Starting UI at [cyan]http://{host}:{port}[/cyan]")
    uvicorn.run("cyber_sentry_cli.api.app:app", host=host, port=port, reload=reload)
