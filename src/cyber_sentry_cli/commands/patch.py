# pyre-unsafe
"""cs patch — Generate a patch candidate for a finding."""

from __future__ import annotations

import typer
from pathlib import Path
from rich.console import Console
from typing import Optional

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.models import DebateSession, Finding, PatchCandidate
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.core.utils import find_finding_by_id, safe_resolve_path
from cyber_sentry_cli.output.terminal import print_error, print_info, print_success
from cyber_sentry_cli.remediation.diff import render_before_after, render_diff

console = Console()


def _resolve_run_id(state: RunStateManager, run_id: str) -> str:
    """Resolve 'latest' to an actual run ID."""
    if run_id == "latest":
        runs = state.list_runs()
        if not runs:
            print_error("No runs found.")
            raise typer.Exit(code=1)
        return runs[0]
    return run_id


def patch_command(finding_id: str, run_id: str = "latest", dry_run: bool = True) -> None:
    """Generate a patch for a finding and optionally apply it."""
    config = Config()
    state = RunStateManager(config)

    # Resolve run
    run_id = _resolve_run_id(state, run_id)

    # Load run
    try:
        run = state.load_run(run_id)
    except FileNotFoundError:
        print_error(f"Run not found: {run_id}")
        raise typer.Exit(code=1)

    # Find the finding
    finding = find_finding_by_id(run.findings, finding_id)
    if not finding:
        print_error(f"Finding not found: {finding_id}")
        raise typer.Exit(code=1)

    # Web findings do not map to local file patches; provide remediation actions instead.
    if finding.scanner == "webscan" or finding.file_path.startswith(("http://", "https://")):
        remediation_text = _web_remediation_for_finding(finding)
        state.save_artifact(
            run_id,
            f"patch_{finding.id}",
            {
                "finding_id": finding.id,
                "scanner": finding.scanner,
                "target": finding.file_path,
                "guidance": remediation_text,
                "mode": "web-remediation",
            },
        )
        console.print()
        print_info("This finding is from website scanning and cannot be auto-patched in local source files.")
        print_info(f"Suggested remediation: {remediation_text}")
        print_success(f"Remediation artifact saved to run {run_id}")
        return

    # Try to load debate session
    session: Optional[DebateSession] = None
    try:
        debate_data = state.load_artifact(run_id, f"debate_{finding.id}")
        if isinstance(debate_data, dict):
            session = DebateSession.model_validate(debate_data)
    except FileNotFoundError:
        print_info("No debate session found. Generating patch directly from finding.")

    # Generate patch
    from cyber_sentry_cli.remediation.generator import generate_patch

    patch = generate_patch(finding, session, config)

    # Display
    console.print()
    if patch.unified_diff:
        render_diff(patch.unified_diff)
    elif patch.original_code and patch.patched_code:
        render_before_after(patch.original_code, patch.patched_code)
    else:
        print_info("No code diff generated.")
        if patch.rationale:
            console.print(f"  [dim]Rationale:[/dim] {patch.rationale}")

    # Save patch artifact
    state.save_artifact(run_id, f"patch_{finding.id}", patch.model_dump(mode="json"))

    if dry_run:
        console.print()
        print_info("[yellow]--dry-run mode:[/yellow] Patch NOT applied.")
        print_info(f"To apply: [cyan]cs patch {finding_id} --run {run_id} --apply[/cyan]")
    else:
        # Apply with approval gate
        from cyber_sentry_cli.remediation.approval import request_approval

        approved = request_approval(patch)
        if approved:
            if _apply_patch(patch):
                print_success("Patch applied successfully!")
            else:
                print_error("Patch approval succeeded, but file update failed.")
        else:
            print_info("Patch rejected. No changes made.")

    console.print()
    print_success(f"Patch artifact saved to run {run_id}")


def _apply_patch(patch: PatchCandidate) -> bool:
    """Apply the patch to the actual file (sandboxed to project root)."""
    target_file = safe_resolve_path(patch.file_path, Path.cwd())
    if not target_file:
        print_error(f"Rejected: path '{patch.file_path}' is outside the project root.")
        return False
    if not target_file.exists():
        print_error(f"Target file not found: {target_file}")
        return False

    content = target_file.read_text(encoding="utf-8")
    if patch.original_code and patch.original_code in content:
        new_content = content.replace(patch.original_code, patch.patched_code, 1)
        target_file.write_text(new_content, encoding="utf-8")
        return True

    if patch.line_start > 0 and patch.patched_code:
        lines = content.splitlines(keepends=True)
        start_index = patch.line_start - 1
        end_index = patch.line_end if patch.line_end >= patch.line_start else patch.line_start

        if start_index < len(lines):
            replacement = patch.patched_code
            if lines and not replacement.endswith(("\n", "\r\n")):
                replacement += "\n"
            replacement_lines = replacement.splitlines(keepends=True)
            lines[start_index:end_index] = replacement_lines
            target_file.write_text("".join(lines), encoding="utf-8")
            return True
    else:
        print_error("Could not find original code in file. Manual patching may be needed.")
    return False


def _web_remediation_for_finding(finding: Finding) -> str:
    guidance = {
        "WS001:insecure-transport": "Enforce HTTPS and redirect all HTTP to HTTPS.",
        "WS002:missing-hsts": "Set Strict-Transport-Security with secure max-age.",
        "WS003:missing-csp": "Define a strict Content-Security-Policy.",
        "WS004:missing-xfo": "Add X-Frame-Options DENY or SAMEORIGIN.",
        "WS005:missing-xcto": "Add X-Content-Type-Options: nosniff.",
        "WS006:missing-referrer-policy": "Add Referrer-Policy strict-origin-when-cross-origin or stricter.",
        "WS007:verbose-server-banner": "Reduce or remove server/version header disclosure.",
        "WS008:cookie-no-httponly": "Set HttpOnly on sensitive cookies.",
        "WS009:cookie-no-secure": "Set Secure on sensitive cookies.",
        "WS010:cookie-no-samesite": "Set SameSite=Lax or Strict on sensitive cookies.",
        "WS011:insecure-form-action": "Use HTTPS-only form action endpoints.",
        "WS000:request-error": "Verify target reachability and scan scope permissions.",
    }
    return guidance.get(
        finding.rule_id,
        "Review web server/application security configuration and apply secure defaults.",
    )
