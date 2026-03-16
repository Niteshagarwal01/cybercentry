# pyre-unsafe
"""cs trace — Replay the full reasoning and tool timeline for a run."""

from __future__ import annotations

import json
from datetime import datetime

import typer
from rich.console import Console
from rich.panel import Panel

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.output.terminal import print_error, print_info, print_success

console = Console()


def trace_command(run_id: str) -> None:
    """Replay the thought trace timeline for a run."""
    config = Config()
    state = RunStateManager(config)

    # Resolve run
    if run_id == "latest":
        runs = state.list_runs()
        if not runs:
            print_error("No runs found.")
            raise typer.Exit(code=1)
        run_id = runs[0]

    # Load events
    try:
        events = state.load_artifact(run_id, "events")
    except FileNotFoundError:
        print_error(f"No trace data found for run: {run_id}")
        print_info("Events are recorded during [cyan]cs scan[/cyan] and [cyan]cs debate[/cyan].")
        raise typer.Exit(code=1)

    if not events:
        print_info("No events recorded for this run.")
        return

    # Display timeline
    console.print()
    console.print(Panel(
        f"[bold]Thought Trace Timeline[/bold]\n"
        f"Run ID: [cyan]{run_id}[/cyan] | Events: {len(events)}",
        border_style="blue",
    ))
    console.print()

    # Event type styling
    style_map = {
        "THINK": ("💭", "cyan"),
        "ACT": ("⚡", "yellow"),
        "OBSERVE": ("👁️ ", "green"),
        "PIVOT": ("🔄", "magenta"),
        "TOOL_CALL": ("🔧", "yellow"),
        "TOOL_RESULT": ("📋", "green"),
        "DEBATE_START": ("🤝", "blue bold"),
        "DEBATE_ROUND": ("💬", "blue"),
        "JUDGE_SCORE": ("⚖️ ", "cyan bold"),
        "PATCH_GENERATED": ("🩹", "green bold"),
        "APPROVAL_REQUESTED": ("🙋", "yellow bold"),
        "ERROR": ("❌", "red bold"),
        "INFO": ("ℹ️ ", "dim"),
    }

    for i, event in enumerate(events, 1):
        event_type = event.get("event_type", "INFO")
        icon, style = style_map.get(event_type, ("•", "white"))
        content = event.get("content", "")
        timestamp = event.get("timestamp", "")
        agent_role = event.get("agent_role", "")

        # Format timestamp
        ts_str = ""
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                ts_str = dt.strftime("%H:%M:%S")
            except (ValueError, AttributeError):
                ts_str = str(timestamp)[:8]

        role_tag = f" [{agent_role}]" if agent_role else ""
        header = f"[dim]{ts_str}[/dim] [{style}]{icon} {event_type}{role_tag}[/{style}]"
        console.print(f"  {header}")
        if content:
            for line in content.split("\n"):
                console.print(f"    [dim]│[/dim] {line}")
        console.print()

    print_success(f"Trace replay complete. {len(events)} events.")
