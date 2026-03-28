# pyre-unsafe
"""Authorized website URL scanner (DAST-lite) for common web security risks."""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Callable, Optional
from urllib.parse import urljoin, urldefrag, urlparse

import httpx

from cyber_sentry_cli.core.models import Finding, Severity


@dataclass
class WebScanConfig:
    max_pages: int = 30
    max_depth: int = 2
    timeout_seconds: float = 8.0
    rate_limit_ms: int = 150
    allow_subdomains: bool = False
    user_agent: str = "CyberSentry-WebScan/0.1"


@dataclass
class WebScanResult:
    findings: list[Finding]
    pages_scanned: int
    visited_urls: list[str]


class _LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
        elif tag.lower() == "form":
            self.forms.append(
                {
                    "action": attr_map.get("action", "").strip(),
                    "method": (attr_map.get("method", "get") or "get").strip().lower(),
                }
            )


def _normalize_url(raw_url: str, base: str) -> str:
    joined = urljoin(base, raw_url)
    cleaned, _ = urldefrag(joined)
    return cleaned


def _is_allowed_target(target_url: str, base_host: str, allow_subdomains: bool) -> bool:
    host = (urlparse(target_url).hostname or "").lower()
    if not host:
        return False
    if host == base_host:
        return True
    return allow_subdomains and host.endswith(f".{base_host}")


def _add_finding(
    findings: list[Finding],
    dedupe: set[tuple[str, str]],
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    url: str,
    cwe: str = "",
    metadata: Optional[dict] = None,
) -> None:
    key = (rule_id, url)
    if key in dedupe:
        return
    dedupe.add(key)
    findings.append(
        Finding(
            scanner="webscan",
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            confidence=0.8,
            file_path=url,
            line_start=1,
            line_end=1,
            cwe=cwe,
            metadata=metadata or {},
        )
    )


def scan_website(
    start_url: str,
    config: WebScanConfig,
    *,
    progress: Optional[Callable[[str, int], None]] = None,
) -> WebScanResult:
    """Scan an authorized website URL and return normalized findings."""
    parsed_start = urlparse(start_url)
    if parsed_start.scheme not in {"http", "https"} or not parsed_start.hostname:
        raise ValueError("URL must include http/https scheme and hostname")

    base_host = parsed_start.hostname.lower()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    visited: set[str] = set()
    findings: list[Finding] = []
    dedupe: set[tuple[str, str]] = set()

    headers = {
        "User-Agent": config.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    }

    with httpx.Client(follow_redirects=True, timeout=config.timeout_seconds, headers=headers) as client:
        while queue and len(visited) < config.max_pages:
            current_url, depth = queue.popleft()
            normalized_current = _normalize_url(current_url, current_url)
            if normalized_current in visited:
                continue
            if not _is_allowed_target(normalized_current, base_host, config.allow_subdomains):
                continue

            visited.add(normalized_current)
            if progress:
                progress(f"Fetching {normalized_current}", len(visited))

            try:
                response = client.get(normalized_current)
            except Exception as exc:
                _add_finding(
                    findings,
                    dedupe,
                    rule_id="WS000:request-error",
                    title="Request failed during web scan",
                    description=f"Request to {normalized_current} failed: {exc}",
                    severity=Severity.LOW,
                    url=normalized_current,
                    cwe="CWE-248",
                )
                time.sleep(max(config.rate_limit_ms, 0) / 1000.0)
                continue

            _check_transport(findings, dedupe, normalized_current)
            _check_security_headers(findings, dedupe, normalized_current, response.headers)
            _check_server_banner(findings, dedupe, normalized_current, response.headers)
            _check_cookie_flags(findings, dedupe, normalized_current, response.headers)

            content_type = response.headers.get("content-type", "").lower()
            if "text/html" in content_type:
                parser = _LinkFormParser()
                parser.feed(response.text)
                _check_forms(findings, dedupe, normalized_current, parser.forms)

                if depth < config.max_depth:
                    for raw_link in parser.links:
                        candidate = _normalize_url(raw_link, normalized_current)
                        if candidate in visited:
                            continue
                        if _is_allowed_target(candidate, base_host, config.allow_subdomains):
                            queue.append((candidate, depth + 1))

            time.sleep(max(config.rate_limit_ms, 0) / 1000.0)

    return WebScanResult(
        findings=findings,
        pages_scanned=len(visited),
        visited_urls=sorted(visited),
    )


def _check_transport(findings: list[Finding], dedupe: set[tuple[str, str]], url: str) -> None:
    if urlparse(url).scheme.lower() != "https":
        _add_finding(
            findings,
            dedupe,
            rule_id="WS001:insecure-transport",
            title="Insecure transport (HTTP)",
            description="Target is served over HTTP. Traffic may be intercepted or modified.",
            severity=Severity.HIGH,
            url=url,
            cwe="CWE-319",
        )


def _check_security_headers(
    findings: list[Finding],
    dedupe: set[tuple[str, str]],
    url: str,
    headers: httpx.Headers,
) -> None:
    required_headers: list[tuple[str, str, str]] = [
        ("strict-transport-security", "WS002:missing-hsts", "CWE-319"),
        ("content-security-policy", "WS003:missing-csp", "CWE-693"),
        ("x-frame-options", "WS004:missing-xfo", "CWE-1021"),
        ("x-content-type-options", "WS005:missing-xcto", "CWE-16"),
        ("referrer-policy", "WS006:missing-referrer-policy", "CWE-200"),
    ]

    for header_name, rule_id, cwe in required_headers:
        if header_name not in headers:
            _add_finding(
                findings,
                dedupe,
                rule_id=rule_id,
                title=f"Missing security header: {header_name}",
                description=(
                    f"Response from {url} is missing '{header_name}'. "
                    "Security hardening headers should be set explicitly."
                ),
                severity=Severity.MEDIUM,
                url=url,
                cwe=cwe,
            )


def _check_server_banner(
    findings: list[Finding],
    dedupe: set[tuple[str, str]],
    url: str,
    headers: httpx.Headers,
) -> None:
    server_header = headers.get("server", "")
    if server_header and re.search(r"\d", server_header):
        _add_finding(
            findings,
            dedupe,
            rule_id="WS007:verbose-server-banner",
            title="Verbose server banner disclosed",
            description=(
                f"Server header exposes technology/version details: '{server_header}'. "
                "Version disclosure can help attackers fingerprint vulnerable components."
            ),
            severity=Severity.LOW,
            url=url,
            cwe="CWE-200",
            metadata={"server": server_header},
        )


def _check_cookie_flags(
    findings: list[Finding],
    dedupe: set[tuple[str, str]],
    url: str,
    headers: httpx.Headers,
) -> None:
    cookies = headers.get_list("set-cookie")
    for cookie in cookies:
        lower = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip()
        sensitive_name = any(token in cookie_name.lower() for token in ("sess", "auth", "token", "jwt"))

        if sensitive_name and "httponly" not in lower:
            _add_finding(
                findings,
                dedupe,
                rule_id="WS008:cookie-no-httponly",
                title=f"Sensitive cookie missing HttpOnly: {cookie_name}",
                description="Session/auth cookie is missing HttpOnly and may be exposed to script access.",
                severity=Severity.HIGH,
                url=url,
                cwe="CWE-1004",
                metadata={"cookie": cookie_name},
            )

        if sensitive_name and "secure" not in lower:
            _add_finding(
                findings,
                dedupe,
                rule_id="WS009:cookie-no-secure",
                title=f"Sensitive cookie missing Secure: {cookie_name}",
                description="Session/auth cookie is missing Secure and may be sent over unencrypted channels.",
                severity=Severity.HIGH,
                url=url,
                cwe="CWE-614",
                metadata={"cookie": cookie_name},
            )

        if sensitive_name and "samesite" not in lower:
            _add_finding(
                findings,
                dedupe,
                rule_id="WS010:cookie-no-samesite",
                title=f"Sensitive cookie missing SameSite: {cookie_name}",
                description="Session/auth cookie is missing SameSite and may increase CSRF exposure.",
                severity=Severity.MEDIUM,
                url=url,
                cwe="CWE-352",
                metadata={"cookie": cookie_name},
            )


def _check_forms(
    findings: list[Finding],
    dedupe: set[tuple[str, str]],
    page_url: str,
    forms: list[dict[str, str]],
) -> None:
    for form in forms:
        method = form.get("method", "get").lower()
        action = form.get("action", "")
        action_url = _normalize_url(action or page_url, page_url)

        if method == "post" and urlparse(action_url).scheme.lower() == "http":
            _add_finding(
                findings,
                dedupe,
                rule_id="WS011:insecure-form-action",
                title="POST form submits over HTTP",
                description=(
                    f"A POST form from {page_url} submits to insecure action URL {action_url}. "
                    "Sensitive form data may be exposed in transit."
                ),
                severity=Severity.HIGH,
                url=page_url,
                cwe="CWE-319",
                metadata={"action": action_url},
            )
