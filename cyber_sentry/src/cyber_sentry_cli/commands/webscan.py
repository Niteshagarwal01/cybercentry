# pyre-unsafe
"""cs webscan — Scan an authorized website URL for common security issues."""

from __future__ import annotations

from urllib.parse import urlparse

import typer
from rich.console import Console

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.events import emit, scoped_run
from cyber_sentry_cli.core.models import EventType
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.output.dashboard import live_dashboard
from cyber_sentry_cli.output.terminal import (
    print_error,
    print_findings_table,
    print_info,
    print_success,
)
from cyber_sentry_cli.web.website_scanner import WebScanConfig, scan_website

console = Console()


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise typer.BadParameter("URL must include http/https scheme and hostname")


def webscan_command(
    url: str,
    *,
    i_own_this_target: bool,
    max_pages: int,
    max_depth: int,
    timeout: float,
    rate_limit_ms: int,
) -> None:
    """Run authorized URL scan and store results like other scan runs."""
    _validate_url(url)

    if not i_own_this_target:
        print_error("Web scan requires explicit authorization acknowledgement.")
        print_info("Re-run with [cyan]--i-own-this-target[/cyan] only for assets you own or are allowed to test.")
        raise typer.Exit(code=1)

    config = Config()
    if not config.is_initialized:
        config.initialize()

    state = RunStateManager(config)
    run = state.create_run(target=url)

    with scoped_run(run.id):
        emit(EventType.INFO, f"Starting authorized website scan: {url}", run_id=run.id)

        def _progress(status: str, pages: int) -> None:
            emit(EventType.OBSERVE, f"{status} (pages={pages})", run_id=run.id, silent=True)
            dash.set_status(
                status,
                findings=len(run.findings),
                stage=f"webscan:pages:{pages}",
            )

        with live_dashboard(title="Website Security Scan", target=url) as dash:
            dash.set_status("Preparing crawler…", stage="webscan:init")

            result = scan_website(
                url,
                WebScanConfig(
                    max_pages=max_pages,
                    max_depth=max_depth,
                    timeout_seconds=timeout,
                    rate_limit_ms=rate_limit_ms,
                ),
                progress=_progress,
            )

            run.findings = result.findings
            run.total_findings = len(result.findings)
            run.scanners_used = ["webscan"]

            dash.set_status(
                f"Completed: {result.pages_scanned} page(s), {run.total_findings} finding(s)",
                findings=run.total_findings,
                stage="webscan:done",
            )

        state.complete_run(run)
        state.save_artifact(run.id, "findings", [f.model_dump(mode="json") for f in run.findings])
        state.save_artifact(
            run.id,
            "webscan_summary",
            {
                "target": url,
                "pages_scanned": result.pages_scanned,
                "visited_urls": result.visited_urls,
                "max_pages": max_pages,
                "max_depth": max_depth,
                "timeout": timeout,
                "rate_limit_ms": rate_limit_ms,
            },
        )

        from cyber_sentry_cli.core.events import events_to_dicts

        state.save_artifact(run.id, "events", events_to_dicts(run.id))

        remediation_md = _build_web_remediation_markdown(run.id, run.findings)
        run_dir = state.get_run_dir(run.id)
        remediation_path = run_dir / "WEB_REMEDIATION.md"
        remediation_path.write_text(remediation_md, encoding="utf-8")

        # Auto-generate REPORT.md so users always get report output for webscan runs.
        from cyber_sentry_cli.commands.report import report_command

        report_command(run.id, fmt="md", output="", show_terminal=False)

    console.print()
    if run.findings:
        print_findings_table(run.findings)
    else:
        print_success("No web findings detected in the scanned scope.")

    console.print()
    print_success(f"Web scan run ID: [cyan]{run.id}[/cyan]")
    print_info(f"Pages scanned: [cyan]{result.pages_scanned}[/cyan]")
    print_info(f"Remediation guide: [cyan]{state.get_run_dir(run.id) / 'WEB_REMEDIATION.md'}[/cyan]")
    print_info(f"Report: [cyan]{state.get_run_dir(run.id) / 'REPORT.md'}[/cyan]")
    print_info(f"Next: [cyan]cs report {run.id}[/cyan] or [cyan]cs triage {run.id}[/cyan]")


def _build_web_remediation_markdown(run_id: str, findings: list) -> str:
    """Generate actionable remediation guidance for web scan findings."""
    lines: list[str] = [
        "# CyberSentry Web Remediation Guide",
        "",
        f"Run ID: `{run_id}`",
        "",
    ]

    if not findings:
        lines += [
            "No findings were detected in this web scan scope.",
            "",
            "Keep monitoring with recurring scans and enforce secure headers in your default server config.",
        ]
        return "\n".join(lines)

    lines += [
        "## Findings and Fix Actions",
        "",
    ]

    guidance = {
        "WS001:insecure-transport": "Enforce HTTPS-only traffic and redirect all HTTP requests to HTTPS with HSTS.",
        "WS002:missing-hsts": "Add Strict-Transport-Security with long max-age and includeSubDomains when appropriate.",
        "WS003:missing-csp": "Define a Content-Security-Policy that restricts script, style, and frame sources.",
        "WS004:missing-xfo": "Add X-Frame-Options DENY or SAMEORIGIN to reduce clickjacking exposure.",
        "WS005:missing-xcto": "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.",
        "WS006:missing-referrer-policy": "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
        "WS007:verbose-server-banner": "Hide or minimize server/version disclosure in HTTP response headers.",
        "WS008:cookie-no-httponly": "Set HttpOnly on session/auth cookies to block JavaScript cookie access.",
        "WS009:cookie-no-secure": "Set Secure on sensitive cookies so they are only sent over HTTPS.",
        "WS010:cookie-no-samesite": "Set SameSite=Lax or Strict on sensitive cookies to reduce CSRF risk.",
        "WS011:insecure-form-action": "Ensure POST form actions submit to HTTPS endpoints only.",
        "WS000:request-error": "Review reachability and DNS/network/WAF behavior for scan target; verify allowed scope.",
    }

    for finding in findings:
        lines += [
            f"### [{finding.severity.value}] {finding.rule_id}",
            f"- Target: `{finding.file_path}`",
            f"- Issue: {finding.title}",
            f"- Recommended fix: {guidance.get(finding.rule_id, 'Review server/application configuration and apply secure defaults.')}",
            "",
        ]

    return "\n".join(lines)
