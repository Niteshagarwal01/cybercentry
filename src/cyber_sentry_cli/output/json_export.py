"""JSON and Markdown report exporter."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from cyber_sentry_cli import __version__
from cyber_sentry_cli.core.models import Run, Severity


def export_json(run: Run) -> str:
    """Export run as formatted JSON."""
    return run.model_dump_json(indent=2)


def export_markdown(run: Run) -> str:
    """Export run as a rich Markdown report (README-quality)."""
    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────
    lines += [
        "# 🛡️ CyberSentry Security Report",
        "",
        "---",
        "",
        "## 📋 Executive Summary",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Run ID** | `{run.id}` |",
        f"| **Target** | `{run.target}` |",
        f"| **Started** | {run.started_at.strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| **Completed** | {run.completed_at.strftime('%Y-%m-%d %H:%M UTC') if run.completed_at else 'In Progress'} |",
        f"| **Status** | {run.status.upper()} |",
        f"| **Scanners** | {', '.join(run.scanners_used) if run.scanners_used else 'N/A'} |",
        f"| **Total Findings** | **{run.total_findings}** |",
        "",
    ]

    # ── Risk Rating ───────────────────────────────────────────────────────
    sev_counts = Counter(f.severity.value for f in run.findings)
    criticals = sev_counts.get("CRITICAL", 0)
    highs = sev_counts.get("HIGH", 0)

    if criticals > 0:
        risk_rating = "🔴 CRITICAL"
        risk_note = f"{criticals} CRITICAL finding(s) require immediate attention."
    elif highs > 0:
        risk_rating = "🟠 HIGH"
        risk_note = f"{highs} HIGH finding(s) should be remediated soon."
    elif sev_counts:
        risk_rating = "🟡 MEDIUM / LOW"
        risk_note = "No critical or high findings. Review medium and low issues."
    else:
        risk_rating = "🟢 CLEAN"
        risk_note = "No findings detected. Code appears clean."

    lines += [
        f"### Overall Risk: {risk_rating}",
        "",
        f"> {risk_note}",
        "",
    ]

    # ── Severity Summary ──────────────────────────────────────────────────
    lines += [
        "## 📊 Severity Breakdown",
        "",
        "| Severity | Count | Risk |",
        "|----------|-------|------|",
    ]
    for sev, emoji in [("CRITICAL", "🔴"), ("HIGH", "🟠"), ("MEDIUM", "🟡"), ("LOW", "🔵"), ("INFO", "⚪")]:
        count = sev_counts.get(sev, 0)
        if count:
            lines.append(f"| {emoji} **{sev}** | {count} | {'Immediate action required' if sev == 'CRITICAL' else 'Review recommended'} |")
    lines.append("")

    # ── Findings ──────────────────────────────────────────────────────────
    if run.findings:
        lines += ["## 🔍 Findings", ""]

        # Group by severity to display critical first
        ordered = sorted(run.findings, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(f.severity.value))

        for i, f in enumerate(ordered, 1):
            sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(f.severity.value, "•")
            lines += [
                f"### {i}. {sev_emoji} [{f.severity.value}] {f.title}",
                "",
                f"| Property | Value |",
                f"|----------|-------|",
                f"| **Finding ID** | `{f.id}` |",
                f"| **Scanner** | {f.scanner} |",
                f"| **Rule** | `{f.rule_id}` |",
                f"| **CWE** | {f.cwe or 'N/A'} |",
                f"| **OWASP** | {f.owasp or 'N/A'} |",
                f"| **File** | `{f.file_path}` (line {f.line_start}) |",
                f"| **Confidence** | {f.confidence:.0%} |",
                "",
            ]

            if f.description:
                lines += [
                    "**Description:**",
                    "",
                    f"> {f.description}",
                    "",
                ]

            if f.code_snippet:
                lang = "python" if f.file_path.endswith(".py") else ""
                lines += [
                    "**Vulnerable Code:**",
                    "",
                    f"```{lang}",
                    f.code_snippet.strip(),
                    "```",
                    "",
                ]

            lines += [
                "**Remediation Guidance:**",
                "",
                f"> Fix the identified `{f.rule_id}` pattern. "
                f"Refer to CWE {f.cwe or 'documentation'} for detailed guidance. "
                f"Run `cs debate {f.id}` to get AI-generated fix proposals "
                f"and `cs patch {f.id}` to auto-generate a patch.",
                "",
                "---",
                "",
            ]
    else:
        lines += [
            "## ✅ No Findings",
            "",
            "No security findings were detected in this scan.",
            "",
        ]

    # ── Root Cause Clusters ───────────────────────────────────────────────
    if run.clusters:
        lines += [
            "## 🔗 Root Cause Clusters",
            "",
            "These findings share common root causes and should be addressed together:",
            "",
        ]
        for i, c in enumerate(run.clusters, 1):
            lines += [
                f"### Cluster {i}: {c.root_cause}",
                "",
                f"- **Risk Score:** {c.risk_score:.2f}",
                f"- **Affected Findings:** {len(c.finding_ids)}",
                f"- **AI Reasoning:** {c.reasoning}",
                "",
            ]

    # ── Recommended Next Steps ────────────────────────────────────────────
    lines += [
        "## 🚀 Recommended Next Steps",
        "",
        "| Step | Command | Description |",
        "|------|---------|-------------|",
        f"| 1 | `cs triage {run.id}` | Cluster and prioritise findings by root cause |",
    ]

    if run.findings:
        top = run.findings[0]
        lines += [
            f"| 2 | `cs debate {top.id}` | Run Red vs Blue vs Auditor debate on top finding |",
            f"| 3 | `cs patch {top.id}` | Generate and review a patch for the top finding |",
        ]

    lines += [
        f"| 4 | `cs report {run.id} --format json` | Export full data as JSON |",
        f"| 5 | `cs trace {run.id}` | Replay the AI reasoning trace |",
        "",
        "---",
        "",
        f"*Generated by CyberSentry v{__version__} on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
    ]

    return "\n".join(lines)
