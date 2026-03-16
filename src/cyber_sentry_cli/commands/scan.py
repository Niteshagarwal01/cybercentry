# pyre-unsafe
"""cs scan — Run security scanners on a target codebase."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.events import emit, scoped_run
from cyber_sentry_cli.core.models import EventType, Finding
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.output.dashboard import live_dashboard
from cyber_sentry_cli.output.terminal import (
    print_error,
    print_findings_table,
    print_info,
    print_success,
    print_warning,
)
from cyber_sentry_cli.scanners.bandit import BanditScanner
from cyber_sentry_cli.scanners.semgrep import SemgrepScanner

console = Console()


def scan_command(target: str, scanners: str = "auto") -> None:
    """Orchestrate security scanning and store results."""
    target_path = Path(target).resolve()
    if not target_path.exists():
        print_error(f"Target not found: {target_path}")
        raise typer.Exit(code=1)

    config = Config()
    if not config.is_initialized:
        print_warning("CyberSentry not initialized. Running [cyan]cs init[/cyan] first...")
        config.initialize()

    state = RunStateManager(config)
    run = state.create_run(target=str(target_path))
    display_target = target if len(target) <= 72 else target_path.name

    with scoped_run(run.id):
        emit(EventType.INFO, f"Starting scan on: {display_target}", run_id=run.id)
        console.print()

    # -- Determine which scanners to use ------------------------------------
    available_scanners = []
    all_scanners = [BanditScanner(), SemgrepScanner()]

    if scanners == "auto":
        for s in all_scanners:
            if s.is_available():
                available_scanners.append(s)
            else:
                print_warning(f"Scanner '{s.name}' not found — skipping")
    else:
        for name in scanners.split(","):
            name = name.strip().lower()
            for s in all_scanners:
                if s.name == name:
                    if s.is_available():
                        available_scanners.append(s)
                    else:
                        print_error(f"Scanner '{name}' not installed")

    if not available_scanners:
        print_error("No scanners available! Install: pip install bandit semgrep")
        state.fail_run(run, "No scanners available")
        raise typer.Exit(code=1)

        # -- Run scanners (inside live thought-trace dashboard) -------------
        all_findings: list[Finding] = []

        with live_dashboard(title="Scanning codebase", target=display_target) as dash:
            dash.set_status("Initialising scanners…", stage="initialising")

            for scanner in available_scanners:
                dash.set_status(f"Running {scanner.name}…", stage=f"scanner:{scanner.name}")
                emit(EventType.ACT, f"Running scanner: {scanner.name}", run_id=run.id)

                try:
                    findings = scanner.scan(target_path)
                    all_findings.extend(findings)
                    run.scanners_used.append(scanner.name)
                    emit(
                        EventType.OBSERVE,
                        f"{scanner.name} → {len(findings)} issue(s) found",
                        run_id=run.id,
                    )
                    dash.set_status(
                        f"{scanner.name} done — {len(findings)} findings",
                        findings=len(all_findings),
                        stage=f"scanner:{scanner.name}:done",
                    )
                except Exception as e:
                    emit(EventType.ERROR, f"{scanner.name} failed: {e}", run_id=run.id)

            dash.set_status("Finalising scan…", stage="saving")

        # -- Store results --------------------------------------------------
        run.findings = all_findings
        run.total_findings = len(all_findings)
        state.complete_run(run)

        # Save findings as a separate artifact too
        state.save_artifact(run.id, "findings", [f.model_dump(mode="json") for f in all_findings])

        # Save events
        from cyber_sentry_cli.core.events import events_to_dicts
        state.save_artifact(run.id, "events", events_to_dicts(run.id))

    # -- Display results ----------------------------------------------------
    console.print()
    if all_findings:
        print_findings_table(all_findings)
        console.print()

        # Summary by severity
        from collections import Counter
        sev_counts = Counter(f.severity.value for f in all_findings)
        from cyber_sentry_cli.core.models import Severity
        summary_parts = [f"[{Severity(sev).color}]{sev}: {count}[/]" for sev, count in sev_counts.most_common()]
        console.print(f"  📊 Summary: {' · '.join(summary_parts)}")
    else:
        print_success("No findings detected! Your code looks clean. 🎉")

    console.print()
    print_success(f"Run ID: [cyan]{run.id}[/cyan]")
    print_info(f"Artifacts saved to: {state.get_run_dir(run.id)}")
    print_info(f"Next: [cyan]cs triage {run.id}[/cyan]")
