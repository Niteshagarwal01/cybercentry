# pyre-unsafe
"""SARIF 2.1.0 exporter — produces Static Analysis Results Interchange Format output."""

from __future__ import annotations

import json
from datetime import timezone
from typing import Any

from cyber_sentry_cli.core.models import Finding, Run, Severity

# SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# Map our Severity to SARIF notification level
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

# Map our Severity to SARIF security-severity score (CVSS-like 0.0–10.0)
_SARIF_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def export_sarif(run: Run) -> str:
    """Export a Run as a SARIF 2.1.0 JSON string."""
    sarif_doc: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [_build_sarif_run(run)],
    }
    return json.dumps(sarif_doc, indent=2)


def _build_sarif_run(run: Run) -> dict[str, Any]:
    """Build a single SARIF run object from a CyberSentry Run."""
    # Collect unique rules (one per (scanner, rule_id) pair)
    rules: dict[str, dict[str, Any]] = {}
    for finding in run.findings:
        rule_id = _sarif_rule_id(finding)
        if rule_id not in rules:
            rules[rule_id] = _build_rule(finding)

    # Build results
    results = [_build_result(f) for f in run.findings]

    # Build tool component per scanner used
    tool_components = []
    for scanner_name in run.scanners_used:
        scanner_rules = [r for rid, r in rules.items() if rid.startswith(f"{scanner_name}/")]
        tool_components.append({
            "name": scanner_name,
            "informationUri": _scanner_uri(scanner_name),
            "rules": scanner_rules,
        })

    # If no scanners are listed fall back to a generic tool
    if not tool_components:
        tool_components.append({
            "name": "cybersentry",
            "informationUri": "https://cybersentry.dev",
            "rules": list(rules.values()),
        })

    sarif_run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "CyberSentry",
                "version": "0.1.0",
                "informationUri": "https://cybersentry.dev",
                "rules": list(rules.values()),
                "extensions": tool_components,
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": run.status != "failed",
                "startTimeUtc": run.started_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                "endTimeUtc": (
                    run.completed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                    if run.completed_at else None
                ),
                "workingDirectory": {"uri": _path_to_uri(run.target)},
            }
        ],
        "artifacts": [
            {
                "location": {"uri": _path_to_uri(run.target)},
                "description": {"text": f"Scan target: {run.target}"},
            }
        ],
        "properties": {
            "cybersentry:runId": run.id,
            "cybersentry:totalFindings": run.total_findings,
            "cybersentry:schemaVersion": run.schema_version,
        },
    }
    return sarif_run


def _build_rule(finding: Finding) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor (rule) from a finding."""
    rule_id = _sarif_rule_id(finding)
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": finding.rule_id.replace(":", "_").replace("-", "_"),
        "shortDescription": {"text": finding.title or finding.rule_id},
        "fullDescription": {"text": finding.description or finding.title or finding.rule_id},
        "defaultConfiguration": {
            "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        },
        "properties": {
            "security-severity": _SARIF_SECURITY_SEVERITY.get(finding.severity, "5.0"),
        },
    }
    if finding.cwe:
        rule["properties"]["cwe"] = finding.cwe
    if finding.owasp:
        rule["properties"]["owasp"] = finding.owasp
    return rule


def _build_result(finding: Finding) -> dict[str, Any]:
    """Build a SARIF result object from a Finding."""
    result: dict[str, Any] = {
        "ruleId": _sarif_rule_id(finding),
        "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {
            "text": finding.description or finding.title,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _path_to_uri(finding.file_path),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(finding.line_start, 1),
                        "endLine": max(finding.line_end or finding.line_start, finding.line_start, 1),
                    },
                }
            }
        ],
        "fingerprints": {
            "cybersentry/v1": finding.id,
        },
        "properties": {
            "cybersentry:findingId": finding.id,
            "cybersentry:scanner": finding.scanner,
            "cybersentry:confidence": finding.confidence,
            "cybersentry:severity": finding.severity.value,
        },
    }

    if finding.code_snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": finding.code_snippet[:500],
        }

    if finding.cwe:
        result["taxa"] = [
            {
                "id": finding.cwe,
                "toolComponent": {"name": "CWE"},
            }
        ]

    return result


def _sarif_rule_id(finding: Finding) -> str:
    """Generate a stable SARIF rule ID from a finding."""
    return f"{finding.scanner}/{finding.rule_id}".replace(" ", "_")


def _path_to_uri(path: str) -> str:
    """Convert a filesystem path to a URI-style string for SARIF."""
    # Normalize Windows backslashes and strip drive letter for relative URIs
    normalized = path.replace("\\", "/")
    # If absolute path, return as-is (consumers will resolve against uriBaseId)
    return normalized


def _scanner_uri(scanner_name: str) -> str:
    uris = {
        "bandit": "https://bandit.readthedocs.io",
        "semgrep": "https://semgrep.dev",
    }
    return uris.get(scanner_name.lower(), f"https://cybersentry.dev/scanners/{scanner_name}")
