"""cs report — Export scan and remediation report."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.output.terminal import (
    print_error,
    print_info,
    print_rich_report,
    print_success,
)

console = Console()


def report_command(
    run_id: str,
    fmt: str = "md",
    output: str = "",
    show_terminal: bool = True,
) -> None:
    """Generate and export a formatted report for a run."""
    config = Config()
    state = RunStateManager(config)

    # Resolve run
    if run_id == "latest":
        runs = state.list_runs()
        if not runs:
            print_error("No runs found. Run [cyan]cs scan[/cyan] first.")
            raise typer.Exit(code=1)
        run_id = runs[0]

    # Load run
    try:
        run = state.load_run(run_id)
    except FileNotFoundError:
        print_error(f"Run not found: {run_id}")
        raise typer.Exit(code=1)

    from cyber_sentry_cli.output.json_export import export_json, export_markdown
    from cyber_sentry_cli.output.sarif_export import export_sarif

    # ── Always auto-save REPORT.md (readable by humans / GitHub) ───────────
    md_text = export_markdown(run)
    run_dir = state.get_run_dir(run_id)
    md_path = run_dir / "REPORT.md"
    md_path.write_text(md_text, encoding="utf-8")

    # ── Generate requested format ───────────────────────────────────────────
    if fmt == "json":
        report_text = export_json(run)
        ext = ".json"
    elif fmt == "sarif":
        report_text = export_sarif(run)
        ext = ".sarif"
    else:
        report_text = md_text
        ext = ".md"

    # ── Save to custom output path if specified ─────────────────────────────
    if output:
        Path(output).write_text(report_text, encoding="utf-8")

    # ── Print rich terminal report ──────────────────────────────────────────
    if show_terminal:
        console.print()
        print_rich_report(run)
        console.print()

    print_success(f"REPORT.md saved → [cyan]{md_path}[/cyan]")
    if output:
        print_success(f"{fmt.upper()} report saved → [cyan]{output}[/cyan]")
