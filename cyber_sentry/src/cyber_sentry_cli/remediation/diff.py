# pyre-unsafe
"""Diff renderer — displays patches with Rich syntax highlighting."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()


def render_diff(diff_text: str, title: str = "Proposed Patch") -> None:
    """Render a unified diff with syntax highlighting."""
    if not diff_text.strip():
        console.print("  [dim]No diff available.[/dim]")
        return

    console.print(Panel(
        Syntax(diff_text, "diff", theme="monokai", line_numbers=True),
        title=f"🩹 {title}",
        border_style="green",
        padding=(0, 1),
    ))


def render_before_after(original: str, patched: str, language: str = "python") -> None:
    """Show before/after code blocks side by side."""
    console.print(Panel(
        Syntax(original, language, theme="monokai", line_numbers=True),
        title="❌ Before (Vulnerable)",
        border_style="red",
        padding=(0, 1),
    ))
    console.print(Panel(
        Syntax(patched, language, theme="monokai", line_numbers=True),
        title="✅ After (Fixed)",
        border_style="green",
        padding=(0, 1),
    ))
