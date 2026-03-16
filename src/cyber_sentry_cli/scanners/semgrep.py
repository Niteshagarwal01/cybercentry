# pyre-unsafe
"""Semgrep scanner adapter — runs semgrep and normalizes output."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from cyber_sentry_cli.core.models import Finding, Severity
from cyber_sentry_cli.scanners.base import BaseScanner, find_tool

# Map semgrep severity strings to our Severity enum
_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepScanner(BaseScanner):
    """Adapter for Semgrep static analysis."""

    name = "semgrep"

    def is_available(self) -> bool:
        return find_tool("semgrep") is not None

    def scan(self, target: Path) -> list[Finding]:
        """Run semgrep --json on the target and parse results."""
        semgrep_exe = find_tool("semgrep") or "semgrep"
        try:
            result = subprocess.run(
                [semgrep_exe, "--json", "--config", "auto", str(target)],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError:
            return []
        except subprocess.TimeoutExpired:
            return []

        findings: list[Finding] = []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        for item in data.get("results", []):
            severity_str = item.get("extra", {}).get("severity", "INFO").upper()
            severity = _SEVERITY_MAP.get(severity_str, Severity.LOW)

            # Extract CWE if present
            cwe = ""
            metadata = item.get("extra", {}).get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            if isinstance(cwe_list, list) and cwe_list:
                cwe = cwe_list[0] if isinstance(cwe_list[0], str) else str(cwe_list[0])
            elif isinstance(cwe_list, str):
                cwe = cwe_list

            # Extract OWASP
            owasp = ""
            owasp_list = metadata.get("owasp", [])
            if isinstance(owasp_list, list) and owasp_list:
                owasp = owasp_list[0] if isinstance(owasp_list[0], str) else str(owasp_list[0])

            finding = Finding(
                scanner="semgrep",
                rule_id=item.get("check_id", ""),
                title=item.get("extra", {}).get("message", "")[:150],
                description=item.get("extra", {}).get("message", ""),
                severity=severity,
                confidence=0.85,
                file_path=item.get("path", ""),
                line_start=item.get("start", {}).get("line", 0),
                line_end=item.get("end", {}).get("line", 0),
                code_snippet=item.get("extra", {}).get("lines", ""),
                cwe=cwe,
                owasp=owasp,
                metadata={
                    "semgrep_id": item.get("check_id", ""),
                    "fingerprint": item.get("extra", {}).get("fingerprint", ""),
                },
            )
            findings.append(finding)

        return findings
