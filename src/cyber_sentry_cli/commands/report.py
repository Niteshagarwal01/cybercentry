# pyre-unsafe
"""cs report — Export scan and remediation report."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.output.terminal import print_error, print_info, print_success

console = Console()


def report_command(run_id: str, fmt: str = "md", output: str = "") -> None:
    """Generate and export a report for a run."""
    config = Config()
    state = RunStateManager(config)

    # Resolve run
    if run_id == "latest":
        runs = state.list_runs()
        if not runs:
            print_error("No runs found.")
            raise typer.Exit(code=1)
        run_id = runs[0]

    # Load run
    try:
        run = state.load_run(run_id)
    except FileNotFoundError:
        print_error(f"Run not found: {run_id}")
        raise typer.Exit(code=1)

    # Generate report
    from cyber_sentry_cli.output.json_export import export_json, export_markdown
    from cyber_sentry_cli.output.sarif_export import export_sarif

    if fmt == "json":
        report_text = export_json(run)
        ext = ".json"
    elif fmt == "sarif":
        report_text = export_sarif(run)
        ext = ".sarif"
    else:
        report_text = export_markdown(run)
        ext = ".md"

    # Output
    if output:
        Path(output).write_text(report_text, encoding="utf-8")
        print_success(f"Report saved to: [cyan]{output}[/cyan]")
    else:
        # Save to run directory
        report_path = state.get_run_dir(run_id) / f"report{ext}"
        report_path.write_text(report_text, encoding="utf-8")
        console.print(report_text)
        console.print()
        print_success(f"Report saved to: [cyan]{report_path}[/cyan]")
