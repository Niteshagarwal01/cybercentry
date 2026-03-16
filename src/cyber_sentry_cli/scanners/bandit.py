# pyre-unsafe
"""Bandit scanner adapter — runs bandit and normalizes output."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from cyber_sentry_cli.core.models import Finding, Severity
from cyber_sentry_cli.scanners.base import BaseScanner, find_tool

# Map bandit severity/confidence to our Severity enum
_SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# CWE mapping for common bandit test IDs
_BANDIT_CWE: dict[str, str] = {
    "B101": "CWE-703",   # assert used
    "B102": "CWE-78",    # exec used
    "B103": "CWE-732",   # bad file permissions
    "B104": "CWE-1188",  # bind all interfaces
    "B105": "CWE-259",   # hardcoded password (string)
    "B106": "CWE-259",   # hardcoded password (argument)
    "B107": "CWE-259",   # hardcoded password (default)
    "B108": "CWE-377",   # hardcoded tmp directory
    "B110": "CWE-390",   # try-except-pass
    "B112": "CWE-390",   # try-except-continue
    "B201": "CWE-94",    # flask debug
    "B301": "CWE-502",   # pickle
    "B302": "CWE-502",   # marshal
    "B303": "CWE-328",   # insecure hash (md5/sha1)
    "B304": "CWE-327",   # insecure cipher
    "B305": "CWE-327",   # insecure cipher mode
    "B306": "CWE-377",   # mktemp
    "B307": "CWE-78",    # eval
    "B308": "CWE-79",    # mark_safe
    "B310": "CWE-22",    # urllib urlopen
    "B311": "CWE-330",   # random
    "B312": "CWE-295",   # telnet
    "B320": "CWE-79",    # xml (lxml)
    "B321": "CWE-93",    # ftp
    "B323": "CWE-295",   # unverified SSL
    "B324": "CWE-328",   # insecure hash function
    "B501": "CWE-295",   # no cert validation
    "B502": "CWE-295",   # ssl no version
    "B503": "CWE-295",   # ssl insecure version
    "B504": "CWE-295",   # ssl no cert
    "B505": "CWE-327",   # weak crypto key
    "B506": "CWE-295",   # unsafe yaml
    "B507": "CWE-295",   # ssh no key verify
    "B601": "CWE-78",    # paramiko calls
    "B602": "CWE-78",    # subprocess popen shell=True
    "B603": "CWE-78",    # subprocess without shell
    "B604": "CWE-78",    # function call with shell
    "B605": "CWE-78",    # start process
    "B606": "CWE-78",    # os.popen
    "B607": "CWE-78",    # partial path
    "B608": "CWE-89",    # SQL injection
    "B609": "CWE-78",    # wildcard injection
    "B610": "CWE-78",    # django extra
    "B611": "CWE-78",    # django raw SQL
    "B701": "CWE-94",    # jinja2 templates
    "B702": "CWE-79",    # mako templates
    "B703": "CWE-79",    # django XSS
}


class BanditScanner(BaseScanner):
    """Adapter for Bandit Python security linter."""

    name = "bandit"

    def is_available(self) -> bool:
        return find_tool("bandit") is not None

    def scan(self, target: Path) -> list[Finding]:
        """Run bandit -f json on the target and parse results."""
        bandit_exe = find_tool("bandit") or "bandit"
        cmd = [bandit_exe, "-f", "json", "-ll"]  # -ll = medium+ severity

        if target.is_dir():
            cmd.extend(["-r", str(target)])
        else:
            cmd.append(str(target))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError:
            return []
        except subprocess.TimeoutExpired:
            return []

        findings: list[Finding] = []

        # Bandit exits 1 when findings exist, so we check stdout not returncode
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        for item in data.get("results", []):
            severity_str = item.get("issue_severity", "LOW").upper()
            severity = _SEVERITY_MAP.get(severity_str, Severity.LOW)
            confidence_str = item.get("issue_confidence", "LOW").upper()
            confidence_val = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4}.get(confidence_str, 0.5)
            line_start = int(item.get("line_number", 0) or 0)
            line_range = item.get("line_range", [])
            if isinstance(line_range, list) and line_range:
                line_end = int(line_range[-1] or line_start)
            else:
                line_end = line_start

            test_id = item.get("test_id", "")
            cwe = _BANDIT_CWE.get(test_id, "")
            cwe_data = item.get("issue_cwe", {})
            if isinstance(cwe_data, dict) and cwe_data.get("id"):
                cwe = f"CWE-{cwe_data['id']}"

            finding = Finding(
                scanner="bandit",
                rule_id=f"{test_id}:{item.get('test_name', '')}",
                title=item.get("issue_text", "")[:150],
                description=item.get("issue_text", ""),
                severity=severity,
                confidence=confidence_val,
                file_path=item.get("filename", ""),
                line_start=line_start,
                line_end=line_end,
                code_snippet=item.get("code", ""),
                cwe=cwe,
                metadata={
                    "test_id": test_id,
                    "test_name": item.get("test_name", ""),
                    "more_info": item.get("more_info", ""),
                },
            )
            findings.append(finding)

        return findings
