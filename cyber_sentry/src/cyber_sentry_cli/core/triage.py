# pyre-unsafe
"""Triage engine — LLM-assisted clustering, dedup, and prioritization."""

from __future__ import annotations

from collections import defaultdict

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.events import emit
from cyber_sentry_cli.core.models import Cluster, EventType, Finding, Severity
from cyber_sentry_cli.integrations.openrouter import OpenRouterClient


def cluster_findings(
    findings: list[Finding],
    config: Config,
) -> list[Cluster]:
    """Cluster findings by root cause using LLM reasoning."""

    if not findings:
        return []

    # Step 1: Pre-group by rule_id and CWE for initial clustering
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        key = f"{f.rule_id}|{f.cwe}" if f.cwe else f.rule_id
        groups[key].append(f)

    clusters: list[Cluster] = []

    # Step 2: Use LLM to analyze each group and provide reasoning
    llm = OpenRouterClient(config)

    if llm.is_configured():
        emit(EventType.THINK, "Using LLM to analyze root causes and cluster findings...")

        findings_summary = _format_findings_for_llm(findings)

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a senior security analyst. Your task is to analyze vulnerability findings "
                    "and group them into root-cause clusters. For each cluster, provide:\n"
                    "1. A concise root_cause label\n"
                    "2. A risk_score from 0.0 to 1.0\n"
                    "3. A brief reasoning explaining why these findings are grouped and how critical they are\n\n"
                    "Respond in JSON format:\n"
                    '{"clusters": [{"root_cause": "...", "finding_ids": [...], "risk_score": 0.0, "reasoning": "..."}]}'
                ),
            },
            {
                "role": "user",
                "content": f"Analyze and cluster these {len(findings)} security findings:\n\n{findings_summary}",
            },
        ]

        try:
            result = llm.chat_json(messages)
            llm_clusters = result.get("clusters", [])

            for lc in llm_clusters:
                cluster = Cluster(
                    root_cause=lc.get("root_cause", "Unknown"),
                    finding_ids=lc.get("finding_ids", []),
                    risk_score=float(lc.get("risk_score", 0.5)),
                    reasoning=lc.get("reasoning", ""),
                )
                clusters.append(cluster)

            emit(
                EventType.OBSERVE,
                f"LLM grouped {len(findings)} findings into {len(clusters)} root-cause clusters",
            )
            return sorted(clusters, key=lambda c: c.risk_score, reverse=True)

        except Exception as e:
            emit(EventType.ERROR, f"LLM clustering failed, falling back to rule-based: {e}")

    # Fallback: rule-based clustering
    emit(EventType.THINK, "Using rule-based clustering (LLM not available)")

    for key, group in groups.items():
        max_severity = max(group, key=lambda f: f.severity.weight)
        avg_confidence = sum(f.confidence for f in group) / len(group)

        risk_score = max_severity.severity.weight * avg_confidence
        root_cause = group[0].cwe if group[0].cwe else group[0].rule_id

        cluster = Cluster(
            root_cause=root_cause,
            finding_ids=[f.id for f in group],
            risk_score=round(risk_score, 3),
            reasoning=(
                f"Grouped {len(group)} finding(s) sharing rule '{group[0].rule_id}'. "
                f"Max severity: {max_severity.severity.value}. "
                f"Avg confidence: {avg_confidence:.0%}."
            ),
        )
        clusters.append(cluster)

    return sorted(clusters, key=lambda c: c.risk_score, reverse=True)


def _format_findings_for_llm(findings: list[Finding]) -> str:
    """Format findings into a readable summary for the LLM."""
    lines = []
    for f in findings:
        lines.append(
            f"- ID: {f.id} | Severity: {f.severity.value} | Scanner: {f.scanner} | "
            f"Rule: {f.rule_id} | CWE: {f.cwe or 'N/A'} | File: {f.file_path}:{f.line_start} | "
            f"Title: {f.title[:100]}"
        )
    return "\n".join(lines)
