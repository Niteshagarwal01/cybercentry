# pyre-unsafe
"""Rich terminal output — premium CLI aesthetics."""

from __future__ import annotations

from typing import Optional

from rich.align import Align
from rich.box import DOUBLE, HEAVY, ROUNDED, SIMPLE
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.markdown import Markdown
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich.theme import Theme

from cyber_sentry_cli.core.models import Finding, Severity, Cluster, JudgeScore, AgentRole

# ---------------------------------------------------------------------------
# Custom Theme
# ---------------------------------------------------------------------------
CYBER_THEME = Theme({
    "cs.brand": "bold bright_red",
    "cs.accent": "bright_cyan",
    "cs.success": "bold bright_green",
    "cs.error": "bold bright_red",
    "cs.warning": "bold bright_yellow",
    "cs.info": "dim bright_white",
    "cs.muted": "dim",
    "cs.highlight": "bold bright_magenta",
    "cs.header": "bold bright_white on grey23",
    "cs.severity.critical": "bold bright_red on dark_red",
    "cs.severity.high": "bold bright_red",
    "cs.severity.medium": "bold bright_yellow",
    "cs.severity.low": "bright_cyan",
    "cs.severity.info": "dim",
    "cs.agent.red": "bold red",
    "cs.agent.blue": "bold blue",
    "cs.agent.auditor": "bold yellow",
    "cs.agent.judge": "bold magenta",
})

console = Console(theme=CYBER_THEME)

# ---------------------------------------------------------------------------
# Premium Banner
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Print an animated-style premium banner."""
    banner_width = 109
    if console.width < banner_width + 4:
        if console.width < 72:
            print_mini_banner()
            return

        brand = Text()
        brand.append("  CYBER", style="bold bright_red")
        brand.append("SENTRY", style="bold bright_white")
        version = Text("  Autonomous Security Engineer  •  v0.1.0  •  Hunt. Debate. Defend.", style="bright_cyan")

        console.print()
        console.print(Align.center(brand))
        console.print(Align.center(version))
        console.print(Align.center(Rule(style="bright_red", characters="━")))
        console.print()
        return

    logo_lines = [
        "   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗",
        "  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝",
        "  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ ",
        "  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  ",
        "  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   ",
        "   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ",
    ]

    # Gradient colors for each line
    gradient = ["bright_red", "red", "bright_magenta", "magenta", "bright_cyan", "cyan"]

    banner_text = Text()
    for i, line in enumerate(logo_lines):
        color = gradient[i % len(gradient)]
        banner_text.append(line + "\n", style=color)

    tagline = Text()
    tagline.append("  ⚡ ", style="bright_yellow")
    tagline.append("Autonomous Security Engineer", style="bold bright_white")
    tagline.append("  •  ", style="dim")
    tagline.append("v0.1.0", style="bright_cyan")
    tagline.append("  •  ", style="dim")
    tagline.append("Hunt. Debate. Defend.", style="italic bright_red")

    console.print()
    console.print(Align.center(banner_text))
    console.print(Align.center(tagline))
    console.print(Align.center(Rule(style="bright_red", characters="━")))
    console.print()


def print_mini_banner() -> None:
    """Print a compact banner for subcommands."""
    line = Text()
    line.append("  🛡️  ", style="bright_red")
    line.append("CyberSentry", style="bold bright_white")
    line.append(" v0.1.0", style="dim bright_cyan")
    console.print(line)
    console.print(Rule(style="grey37", characters="─"))
    console.print()


# ---------------------------------------------------------------------------
# Status Messages
# ---------------------------------------------------------------------------

def print_success(message: str) -> None:
    console.print(f"  [cs.success]✓[/cs.success] {message}")

def print_error(message: str) -> None:
    console.print(f"  [cs.error]✗[/cs.error] {message}")

def print_warning(message: str) -> None:
    console.print(f"  [cs.warning]⚠[/cs.warning] {message}")

def print_info(message: str) -> None:
    console.print(f"  [cs.info]ℹ[/cs.info] {message}")

def print_step(step: str, detail: str = "") -> None:
    """Print a workflow step indicator."""
    line = Text()
    line.append("  ▸ ", style="bright_cyan")
    line.append(step, style="bold bright_white")
    if detail:
        line.append(f"  {detail}", style="dim")
    console.print(line)


# ---------------------------------------------------------------------------
# Doctor Table
# ---------------------------------------------------------------------------

def print_doctor_table(checks: list[tuple[str, bool, str]]) -> None:
    """Print the doctor checks as a styled table."""
    table = Table(
        title="",
        box=ROUNDED,
        border_style="grey37",
        title_style="bold bright_white",
        header_style="bold bright_cyan",
        padding=(0, 2),
        show_edge=True,
    )
    table.add_column("Check", style="bright_white", min_width=28)
    table.add_column("Status", justify="center", min_width=8)
    table.add_column("Details", style="dim", min_width=35)

    for name, ok, detail in checks:
        status = Text("✓ OK", style="bright_green bold") if ok else Text("✗ FAIL", style="bright_red bold")
        table.add_row(name, status, detail)

    console.print(Panel(
        table,
        title="[bold bright_white]🩺 System Health Check[/]",
        border_style="bright_cyan",
        box=ROUNDED,
        padding=(1, 1),
    ))


# ---------------------------------------------------------------------------
# Findings Table
# ---------------------------------------------------------------------------

def print_findings_table(findings: list[Finding]) -> None:
    """Print a premium findings table."""
    table = Table(
        box=ROUNDED,
        border_style="grey37",
        header_style="bold bright_cyan",
        padding=(0, 1),
        row_styles=["", "on grey7"],
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("ID", style="bright_cyan", width=12)
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Scanner", style="bright_blue", width=10)
    table.add_column("Rule", style="bright_white", width=25, overflow="ellipsis")
    table.add_column("File", style="bright_green", width=30, overflow="ellipsis")
    table.add_column("Line", style="bright_yellow", width=6, justify="right")

    sev_styles = {
        "CRITICAL": "cs.severity.critical",
        "HIGH": "cs.severity.high",
        "MEDIUM": "cs.severity.medium",
        "LOW": "cs.severity.low",
        "INFO": "cs.severity.info",
    }

    for i, f in enumerate(findings, 1):
        sev_style = sev_styles.get(f.severity.value, "")
        sev_text = Text(f" {f.severity.value} ", style=sev_style)
        table.add_row(
            str(i), f.id[:11], sev_text, f.scanner, f.rule_id,
            f.file_path.split("\\")[-1] if "\\" in f.file_path else f.file_path.split("/")[-1],
            str(f.line_start),
        )

    console.print(Panel(
        table,
        title="[bold bright_white]🔍 Scan Findings[/]",
        border_style="bright_red",
        box=ROUNDED,
        padding=(0, 0),
    ))

    # Summary bar
    from collections import Counter
    sev_counts = Counter(f.severity.value for f in findings)
    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in sev_counts:
            style = sev_styles.get(sev, "")
            summary_parts.append(f"[{style}]{sev}: {sev_counts[sev]}[/{style}]")

    summary_line = Text.from_markup(f"  📊 {' · '.join(summary_parts)}")
    console.print(summary_line)
    console.print()


# ---------------------------------------------------------------------------
# Clusters Table
# ---------------------------------------------------------------------------

def print_clusters_table(clusters: list[Cluster], findings: list[Finding]) -> None:
    """Print a styled clusters table."""
    table = Table(
        box=ROUNDED,
        border_style="grey37",
        header_style="bold bright_cyan",
        padding=(0, 1),
        row_styles=["", "on grey7"],
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Root Cause", style="bold bright_white", min_width=30, overflow="ellipsis")
    table.add_column("Risk", style="bright_red bold", width=8, justify="center")
    table.add_column("Findings", style="bright_yellow", width=8, justify="center")
    table.add_column("Reasoning", style="dim", min_width=35, overflow="ellipsis")

    for i, c in enumerate(clusters, 1):
        risk_color = "bright_red" if c.risk_score >= 0.7 else "bright_yellow" if c.risk_score >= 0.4 else "bright_green"
        risk_text = Text(f"{c.risk_score:.2f}", style=f"bold {risk_color}")
        reasoning = c.reasoning[:80] + "..." if len(c.reasoning) > 80 else c.reasoning
        table.add_row(str(i), c.root_cause, risk_text, str(len(c.finding_ids)), reasoning)

    console.print(Panel(
        table,
        title="[bold bright_white]📊 Root Cause Clusters[/]",
        border_style="bright_magenta",
        box=ROUNDED,
        padding=(0, 0),
    ))


# ---------------------------------------------------------------------------
# Judge Scores
# ---------------------------------------------------------------------------

def print_judge_scores(scores: list[JudgeScore]) -> None:
    """Print judge scores in a premium styled table."""
    table = Table(
        box=ROUNDED,
        border_style="grey37",
        header_style="bold bright_cyan",
        padding=(0, 1),
    )
    table.add_column("Agent", width=12, style="bold")
    table.add_column("Security", width=9, justify="center")
    table.add_column("Safety", width=9, justify="center")
    table.add_column("Maintain.", width=9, justify="center")
    table.add_column("Compliance", width=10, justify="center")
    table.add_column("Effort", width=8, justify="center")
    table.add_column("TOTAL", width=8, justify="center", style="bold bright_white")

    agent_styles = {
        "RED_TEAM": "cs.agent.red",
        "BLUE_TEAM": "cs.agent.blue",
        "AUDITOR": "cs.agent.auditor",
    }

    sorted_scores = sorted(scores, key=lambda x: x.total_score, reverse=True)
    for i, s in enumerate(sorted_scores):
        style = agent_styles.get(s.agent_role.value, "")
        is_winner = i == 0
        row_style = "on grey11" if is_winner else ""
        agent_text = Text(s.agent_role.value, style=style)
        if is_winner:
            agent_text.append(" 🏆", style="bright_yellow")

        table.add_row(
            agent_text,
            f"{s.security_effectiveness:.1f}",
            f"{s.implementation_safety:.1f}",
            f"{s.maintainability:.1f}",
            f"{s.compliance_alignment:.1f}",
            f"{s.effort_estimate:.1f}",
            Text(f"{s.total_score:.2f}", style="bold bright_green" if is_winner else "bold"),
            style=row_style,
        )

    console.print(Panel(
        table,
        title="[bold bright_white]⚖️  Judge Scoring[/]",
        border_style="bright_magenta",
        box=ROUNDED,
        padding=(0, 0),
    ))


# ---------------------------------------------------------------------------
# Diff Display
# ---------------------------------------------------------------------------

def print_diff(diff_text: str, title: str = "Proposed Patch") -> None:
    """Print a unified diff with syntax highlighting."""
    console.print(Panel(
        Syntax(diff_text, "diff", theme="monokai", line_numbers=True),
        title=f"[bold bright_white]🩹 {title}[/]",
        border_style="bright_green",
        box=ROUNDED,
    ))


# ---------------------------------------------------------------------------
# Progress & Spinners
# ---------------------------------------------------------------------------

def create_scan_progress() -> Progress:
    """Create a premium progress bar for scanning."""
    return Progress(
        SpinnerColumn("dots", style="bright_cyan"),
        TextColumn("[bright_white]{task.description}[/]"),
        BarColumn(bar_width=30, style="grey37", complete_style="bright_cyan", finished_style="bright_green"),
        TextColumn("[bright_cyan]{task.percentage:>3.0f}%[/]"),
        TimeElapsedColumn(),
        console=console,
    )
