# pyre-unsafe
"""cs triage — Deduplicate, cluster, and prioritize findings."""

from __future__ import annotations

import typer
from rich.console import Console

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.models import Finding
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.core.triage import cluster_findings
from cyber_sentry_cli.output.terminal import (
    print_clusters_table,
    print_error,
    print_info,
    print_success,
)

console = Console()


def triage_command(run_id: str) -> None:
    """Load findings from a run, cluster and prioritize them."""
    config = Config()
    state = RunStateManager(config)

    # Resolve 'latest'
    if run_id == "latest":
        runs = state.list_runs()
        if not runs:
            print_error("No runs found. Run [cyan]cs scan[/cyan] first.")
            raise typer.Exit(code=1)
        run_id = runs[0]
        print_info(f"Using latest run: [cyan]{run_id}[/cyan]")

    # Load run
    try:
        run = state.load_run(run_id)
    except FileNotFoundError:
        print_error(f"Run not found: {run_id}")
        raise typer.Exit(code=1)

    if not run.findings:
        print_info("No findings to triage.")
        return

    console.print()
    console.print(f"  📋 Triaging [cyan]{len(run.findings)}[/cyan] findings from run [cyan]{run_id}[/cyan]...")
    console.print()

    # Cluster
    clusters = cluster_findings(run.findings, config)

    # Save clusters back to the run
    run.clusters = clusters
    state.save_run(run)
    state.save_artifact(run_id, "clusters", [c.model_dump(mode="json") for c in clusters])

    # Display
    print_clusters_table(clusters, run.findings)
    console.print()

    # Show top escalation candidates
    critical_clusters = [c for c in clusters if c.risk_score >= 0.7]
    if critical_clusters:
        console.print(f"  🚨 [red bold]{len(critical_clusters)} cluster(s) recommended for debate escalation[/red bold]")
        for c in critical_clusters[:3]:
            console.print(f"     → {c.root_cause} (risk: {c.risk_score:.2f}, {len(c.finding_ids)} findings)")
            if c.finding_ids:
                console.print(f"       Debate: [cyan]cs debate {c.finding_ids[0]} --run {run_id}[/cyan]")
    else:
        print_success("No critical clusters requiring debate escalation.")

    console.print()
    print_success(f"Triage complete. {len(clusters)} clusters identified.")
