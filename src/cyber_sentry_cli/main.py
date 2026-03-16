# pyre-unsafe
"""CyberSentry CLI — main entrypoint with all commands."""

from __future__ import annotations

from typing import Optional

import typer

from cyber_sentry_cli import __version__
from cyber_sentry_cli.output.terminal import print_banner, print_mini_banner

app = typer.Typer(
    name="cs",
    help="🛡️ CyberSentry — Autonomous Red Team AI Agent\n\nRun [bold cyan]cs chat[/] to start interactive mode.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def version_callback(value: bool) -> None:
    if value:
        print_banner()
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None, "--version", "-v",
        help="Show CyberSentry version.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """🛡️ CyberSentry — Hunt. Debate. Defend."""
    pass


# -- Primary: Interactive Chat -----------------------------------------------

@app.command("chat")
def cmd_chat(
    target: Optional[str] = typer.Argument(default=None, help="Optional target to auto-scan on launch"),
) -> None:
    """⚡ Launch interactive agent mode — chat, scan, triage, patch."""
    from cyber_sentry_cli.commands.chat import chat_command
    chat_command(target)


# -- Register other commands -------------------------------------------------

@app.command("init")
def cmd_init(
    path: str = typer.Argument(default=".", help="Project root directory"),
) -> None:
    """Initialize CyberSentry in a project directory."""
    from cyber_sentry_cli.commands.init_cmd import init_command
    print_mini_banner()
    init_command(path)


@app.command("doctor")
def cmd_doctor() -> None:
    """Validate environment, tools, and secrets."""
    from cyber_sentry_cli.commands.doctor import doctor_command
    print_mini_banner()
    doctor_command()


@app.command("scan")
def cmd_scan(
    target: str = typer.Argument(help="File or directory to scan"),
    scanners: str = typer.Option("auto", "--scanners", "-s", help="Comma-separated scanner names or 'auto'"),
) -> None:
    """Run security scanners on a target codebase."""
    from cyber_sentry_cli.commands.scan import scan_command
    print_banner()
    scan_command(target, scanners)


@app.command("triage")
def cmd_triage(
    run_id: str = typer.Argument(help="Run ID to triage (use 'latest' for most recent)"),
) -> None:
    """Deduplicate, cluster, and prioritize findings."""
    from cyber_sentry_cli.commands.triage import triage_command
    print_mini_banner()
    triage_command(run_id)


@app.command("debate")
def cmd_debate(
    finding_id: str = typer.Argument(help="Finding ID to debate remediation for"),
    run_id: str = typer.Option("latest", "--run", "-r", help="Run ID containing the finding"),
) -> None:
    """Run multi-agent remediation debate (Red vs Blue vs Auditor + Judge)."""
    from cyber_sentry_cli.commands.debate import debate_command
    print_banner()
    debate_command(finding_id, run_id)


@app.command("patch")
def cmd_patch(
    finding_id: str = typer.Argument(help="Finding ID to generate patch for"),
    run_id: str = typer.Option("latest", "--run", "-r", help="Run ID containing the finding"),
    dry_run: bool = typer.Option(True, "--dry-run/--apply", help="Show diff without applying"),
) -> None:
    """Generate a patch candidate for a finding."""
    from cyber_sentry_cli.commands.patch import patch_command
    print_mini_banner()
    patch_command(finding_id, run_id, dry_run)


@app.command("report")
def cmd_report(
    run_id: str = typer.Argument(help="Run ID to generate report for (use 'latest')"),
    fmt: str = typer.Option("md", "--format", "-f", help="Output format: json, md, sarif"),
    output: str = typer.Option("", "--output", "-o", help="Output file path (default: stdout)"),
) -> None:
    """Export scan and remediation report."""
    from cyber_sentry_cli.commands.report import report_command
    print_mini_banner()
    report_command(run_id, fmt, output)


@app.command("trace")
def cmd_trace(
    run_id: str = typer.Argument(help="Run ID to replay trace for (use 'latest')"),
) -> None:
    """Replay the full reasoning and tool timeline for a run."""
    from cyber_sentry_cli.commands.trace import trace_command
    print_mini_banner()
    trace_command(run_id)


# ---------------------------------------------------------------------------
def chat_entrypoint() -> None:
    """Direct `chat` entry point — equivalent to running `cs chat`."""
    import sys
    from cyber_sentry_cli.commands.chat import chat_command
    # Ignore flag arguments (--help, -v, etc.); only treat plain paths as target
    positional = [a for a in sys.argv[1:] if not a.startswith("-")]
    target = positional[0] if positional else None
    chat_command(target)


if __name__ == "__main__":
    app()
