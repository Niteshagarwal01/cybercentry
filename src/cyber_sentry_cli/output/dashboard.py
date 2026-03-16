"""Live Thought-Trace Dashboard — streams AI reasoning events in real-time using Rich Live."""

from __future__ import annotations

import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from rich.align import Align
from rich.box import ROUNDED, SIMPLE
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

console = Console()

# ---------------------------------------------------------------------------
# Config / style maps
# ---------------------------------------------------------------------------

_ICON_MAP: dict[str, str] = {
    "THINK":              "💭",
    "ACT":                "⚡",
    "OBSERVE":            "👁",
    "PIVOT":              "🔄",
    "TOOL_CALL":          "🔧",
    "TOOL_RESULT":        "📋",
    "DEBATE_START":       "🤝",
    "DEBATE_ROUND":       "💬",
    "JUDGE_SCORE":        "⚖",
    "PATCH_GENERATED":    "🩹",
    "APPROVAL_REQUESTED": "🙋",
    "ERROR":              "❌",
    "INFO":               "ℹ",
}

_COLOUR_MAP: dict[str, str] = {
    "THINK":              "cyan",
    "ACT":                "yellow",
    "OBSERVE":            "green",
    "PIVOT":              "magenta",
    "TOOL_CALL":          "yellow",
    "TOOL_RESULT":        "green",
    "DEBATE_START":       "blue bold",
    "DEBATE_ROUND":       "blue",
    "JUDGE_SCORE":        "cyan bold",
    "PATCH_GENERATED":    "green bold",
    "APPROVAL_REQUESTED": "yellow bold",
    "ERROR":              "red bold",
    "INFO":               "dim",
}


# ---------------------------------------------------------------------------
# ThoughtTraceDashboard
# ---------------------------------------------------------------------------

class ThoughtTraceDashboard:
    """
    A Rich Live dashboard that renders AI reasoning events in real-time.

    Usage::

        with ThoughtTraceDashboard(title="Scanning .") as dash:
            dash.add_event("THINK", "Analysing imported modules…")
            dash.add_event("ACT",   "Running Bandit scanner")
            dash.set_status("Running Semgrep…", findings=3)
    """

    # Maximum number of trace lines kept in the live panel before scrolling
    MAX_LINES: int = 28

    def __init__(
        self,
        title: str = "AI Reasoning Trace",
        target: str = "",
        show_spinner: bool = True,
    ) -> None:
        self.title = title
        self.target = target
        self.show_spinner = show_spinner

        self._events: list[Text] = []
        self._status: str = "Starting…"
        self._findings: int = 0
        self._stage: str = ""
        self._start: float = time.monotonic()
        self._live: Optional[Live] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_event(
        self,
        event_type: str,
        content: str,
        agent_role: str = "",
    ) -> None:
        """Append a thought event to the live trace panel."""
        icon = _ICON_MAP.get(event_type, "•")
        colour = _COLOUR_MAP.get(event_type, "white")

        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        role_tag = f" [{agent_role}]" if agent_role else ""

        line = Text()
        line.append(f" {now} ", style="dim")
        line.append(f"{icon} ", style="bold")
        line.append(f"{event_type}{role_tag}", style=f"bold {colour}")
        if content:
            # Truncate long content for dashboard readability
            short = content.replace("\n", " ").strip()
            if len(short) > 110:
                short = short[:107] + "…"
            line.append(f"  {short}", style="white")

        self._events.append(line)
        # Keep only the last MAX_LINES entries
        if len(self._events) > self.MAX_LINES:
            self._events = self._events[-self.MAX_LINES :]

        self._refresh()

    def set_status(
        self,
        status: str,
        findings: int = -1,
        stage: str = "",
    ) -> None:
        """Update the status bar text."""
        self._status = status
        if findings >= 0:
            self._findings = findings
        if stage:
            self._stage = stage
        self._refresh()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "ThoughtTraceDashboard":
        self._live = Live(
            self._render(),
            console=console,
            refresh_per_second=8,
            vertical_overflow="visible",
        )
        self._live.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        if self._live:
            self._live.__exit__(*args)
            self._live = None

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render(self) -> Panel:
        elapsed = time.monotonic() - self._start

        # ── Trace body ────────────────────────────────────────────────
        body = Table.grid(padding=(0, 0))
        body.add_column(no_wrap=False)

        if self._events:
            for line in self._events:
                body.add_row(line)
        else:
            body.add_row(Text("  Waiting for AI events…", style="dim italic"))

        # ── Status bar ────────────────────────────────────────────────
        bar = Table.grid(expand=True, padding=(0, 1))
        bar.add_column(ratio=2)
        bar.add_column(ratio=1, justify="center")
        bar.add_column(ratio=1, justify="right")

        stage_text = Text()
        if self.show_spinner:
            stage_text.append("⠿ ", style="bright_cyan")
        stage_str = self._stage or self._status
        stage_text.append(stage_str, style="bright_cyan")

        findings_text = Text()
        findings_text.append("🔍 Findings: ", style="dim")
        findings_text.append(str(self._findings), style="bold yellow")

        time_text = Text()
        time_text.append(f"⏱ {elapsed:.0f}s", style="dim")

        bar.add_row(stage_text, findings_text, time_text)

        group = Group(body, Rule(style="grey23"), bar)

        title_text = Text()
        title_text.append("🧠 ", style="bold")
        title_text.append(self.title, style="bold bright_white")
        if self.target:
            title_text.append(f"  —  {self.target}", style="dim")

        return Panel(
            group,
            title=title_text,
            border_style="bright_cyan",
            box=ROUNDED,
            padding=(0, 1),
        )

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())


# ---------------------------------------------------------------------------
# Global active dashboard (singleton so events.py can feed into it)
# ---------------------------------------------------------------------------

_active_dashboard: Optional[ThoughtTraceDashboard] = None


def get_active_dashboard() -> Optional[ThoughtTraceDashboard]:
    """Return the currently active dashboard, if any."""
    return _active_dashboard


def set_active_dashboard(dash: Optional[ThoughtTraceDashboard]) -> None:
    global _active_dashboard  # noqa: PLW0603
    _active_dashboard = dash


@contextmanager
def live_dashboard(title: str = "AI Reasoning Trace", target: str = "") -> Iterator[ThoughtTraceDashboard]:
    """
    Context manager that creates, activates, and tears down a live dashboard.

    Example::

        with live_dashboard("Scanning codebase", target=".") as dash:
            do_scan(...)
    """
    global _active_dashboard  # noqa: PLW0603
    dash = ThoughtTraceDashboard(title=title, target=target)
    _active_dashboard = dash
    try:
        with dash:
            yield dash
    finally:
        _active_dashboard = None
