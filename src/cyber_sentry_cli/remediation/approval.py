# pyre-unsafe
"""Approval gate — human-in-the-loop safety control."""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Confirm

from cyber_sentry_cli.core.events import emit
from cyber_sentry_cli.core.models import EventType, PatchCandidate

console = Console()


def request_approval(patch: PatchCandidate) -> bool:
    """Show patch details and request human approval."""
    emit(EventType.APPROVAL_REQUESTED, f"Approval requested for patch on {patch.file_path}")

    console.print()
    console.print("  [bold yellow]⚠️  HUMAN APPROVAL REQUIRED[/bold yellow]")
    console.print()

    if patch.rationale:
        console.print(f"  [dim]Rationale:[/dim] {patch.rationale}")
    if patch.risks:
        console.print(f"  [dim]Risks:[/dim] {patch.risks}")
    if patch.rollback_note:
        console.print(f"  [dim]Rollback:[/dim] {patch.rollback_note}")

    console.print()

    approved = Confirm.ask("  [bold]Apply this patch?[/bold]", default=False)

    if approved:
        patch.approved = True
        console.print("  [green bold]✓ Patch approved[/green bold]")
    else:
        patch.approved = False
        console.print("  [red]✗ Patch rejected[/red]")

    return approved
