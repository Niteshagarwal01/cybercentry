# pyre-unsafe
"""cs debate — Run multi-agent remediation debate."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.models import AgentRole, Finding
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.output.terminal import (
    print_error,
    print_info,
    print_judge_scores,
    print_success,
    print_warning,
)

console = Console()


def _find_finding(findings: list[Finding], finding_id: str) -> Finding:
    """Find a finding by ID or prefix, raising Exit if not found."""
    for f in findings:
        if f.id == finding_id or f.id.startswith(finding_id):
            return f
    print_error(f"Finding not found: {finding_id}")
    print_info("Available findings:")
    for f in findings[:10]:
        console.print(f"  • {f.id}: [{f.severity.color}]{f.severity.value}[/] {f.title[:60]}")
    raise typer.Exit(code=1)


def debate_command(finding_id: str, run_id: str = "latest") -> None:
    """Run Red vs Blue vs Auditor debate for a specific finding."""
    config = Config()
    state = RunStateManager(config)

    # Check API key
    from cyber_sentry_cli.integrations.openrouter import OpenRouterClient

    llm = OpenRouterClient(config)
    if not llm.is_configured():
        print_error("No LLM backend configured!")
        print_info("Configure OpenRouter or a local Ollama endpoint in [cyan].cybersentry/config.toml[/cyan].")
        raise typer.Exit(code=1)

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

    # Find the finding (returns Finding or raises Exit)
    finding: Finding = _find_finding(run.findings, finding_id)

    # Show finding details
    console.print()
    code_display = finding.code_snippet[:300] if finding.code_snippet else "N/A"
    console.print(Panel(
        Text.from_markup(
            f"[bold]{finding.title}[/bold]\n\n"
            f"[dim]Severity:[/dim] [{finding.severity.color}]{finding.severity.value}[/]\n"
            f"[dim]File:[/dim] {finding.file_path}:{finding.line_start}\n"
            f"[dim]CWE:[/dim] {finding.cwe or 'N/A'}\n"
            f"[dim]Scanner:[/dim] {finding.scanner}\n"
            f"[dim]Rule:[/dim] {finding.rule_id}\n\n"
            f"[dim]Code:[/dim]\n{code_display}"
        ),
        title="🎯 Debating Finding",
        border_style="red",
        padding=(1, 2),
    ))
    console.print()

    # Run debate
    from cyber_sentry_cli.reasoning.debate_engine import DebateEngine
    from cyber_sentry_cli.reasoning.judge import JudgeAgent

    engine = DebateEngine(config)
    session = engine.run_debate(finding)

    # Run judge
    console.print()
    judge = JudgeAgent(config)
    session = judge.evaluate(session, finding)

    # Display scores
    if session.scores:
        console.print()
        print_judge_scores(session.scores)

    # Display winner
    if session.winner:
        console.print()
        winner_icon = {"RED_TEAM": "🔴", "BLUE_TEAM": "🔵", "AUDITOR": "📋"}.get(
            session.winner.value, "🏆"
        )
        console.print(Panel(
            Text.from_markup(
                f"{winner_icon} [bold]{session.winner.value}[/bold] wins!\n\n"
                f"{session.winner_rationale}"
            ),
            title="🏆 Debate Winner",
            border_style="green bold",
            padding=(1, 2),
        ))

    # Save debate session
    state.save_artifact(run_id, f"debate_{finding.id}", session.model_dump(mode="json"))

    console.print()
    print_success("Debate complete. Session saved.")
    print_info(f"Generate patch: [cyan]cs patch {finding.id} --run {run_id}[/cyan]")
