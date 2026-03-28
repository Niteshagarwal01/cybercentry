"""Unit tests for core/models.py — Finding, Run, Cluster, Proposal, JudgeScore."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from cyber_sentry_cli.core.models import (
    AgentRole,
    Cluster,
    DebateSession,
    EventType,
    Finding,
    JudgeScore,
    Proposal,
    PatchCandidate,
    Run,
    Severity,
)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class TestSeverity:
    def test_weights_are_ordered(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFO.weight

    def test_critical_weight_is_one(self):
        assert Severity.CRITICAL.weight == 1.0

    def test_info_weight_is_low(self):
        assert Severity.INFO.weight < 0.1

    def test_color_returns_string(self):
        for sev in Severity:
            assert isinstance(sev.color, str)
            assert len(sev.color) > 0


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class TestFinding:
    def test_default_id_is_12_chars(self):
        f = Finding(title="Test")
        assert len(f.id) == 12

    def test_ids_are_unique(self):
        ids = {Finding(title="x").id for _ in range(20)}
        assert len(ids) == 20

    def test_default_severity_is_medium(self):
        f = Finding()
        assert f.severity == Severity.MEDIUM

    def test_schema_version_set(self):
        f = Finding()
        assert f.schema_version == "1.0.0"

    def test_created_at_is_utc(self):
        f = Finding()
        assert f.created_at.tzinfo is not None

    def test_fields_stored_correctly(self):
        f = Finding(
            title="SQL injection",
            severity=Severity.HIGH,
            file_path="app/db.py",
            line_start=42,
            scanner="bandit",
            rule_id="B608",
            cwe="CWE-89",
        )
        assert f.title == "SQL injection"
        assert f.severity == Severity.HIGH
        assert f.file_path == "app/db.py"
        assert f.line_start == 42
        assert f.scanner == "bandit"
        assert f.cwe == "CWE-89"


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

class TestRun:
    def test_default_status_is_running(self):
        r = Run()
        assert r.status == "running"

    def test_total_findings_defaults_to_zero(self):
        r = Run()
        assert r.total_findings == 0

    def test_findings_list_is_empty_by_default(self):
        r = Run()
        assert r.findings == []

    def test_serialization_round_trip(self):
        f = Finding(title="test", severity=Severity.HIGH, scanner="bandit")
        r = Run(target="/tmp/app", findings=[f], total_findings=1, status="completed")
        json_str = r.model_dump_json()
        r2 = Run.model_validate_json(json_str)
        assert r2.id == r.id
        assert r2.status == "completed"
        assert len(r2.findings) == 1
        assert r2.findings[0].title == "test"


# ---------------------------------------------------------------------------
# Cluster
# ---------------------------------------------------------------------------

class TestCluster:
    def test_default_risk_score_is_zero(self):
        c = Cluster(root_cause="SQL Injection")
        assert c.risk_score == 0.0

    def test_finding_ids_list(self):
        c = Cluster(root_cause="XSS", finding_ids=["abc", "def"])
        assert len(c.finding_ids) == 2


# ---------------------------------------------------------------------------
# JudgeScore
# ---------------------------------------------------------------------------

class TestJudgeScore:
    def test_compute_total_uses_weighted_sum(self):
        s = JudgeScore(
            proposal_id="p1",
            agent_role=AgentRole.RED_TEAM,
            security_effectiveness=10.0,
            implementation_safety=10.0,
            maintainability=10.0,
            compliance_alignment=10.0,
            effort_estimate=10.0,
        )
        total = s.compute_total()
        # Weights: 0.30 + 0.25 + 0.20 + 0.15 + 0.10 = 1.0 → total = 10.0
        assert total == 10.0

    def test_compute_total_partial(self):
        s = JudgeScore(
            proposal_id="p2",
            agent_role=AgentRole.BLUE_TEAM,
            security_effectiveness=8.0,
            implementation_safety=6.0,
            maintainability=7.0,
            compliance_alignment=5.0,
            effort_estimate=9.0,
        )
        total = s.compute_total()
        expected = round(8.0 * 0.30 + 6.0 * 0.25 + 7.0 * 0.20 + 5.0 * 0.15 + 9.0 * 0.10, 2)
        assert total == expected

    def test_total_score_stored_on_model(self):
        s = JudgeScore(
            proposal_id="p3",
            agent_role=AgentRole.AUDITOR,
            security_effectiveness=5.0,
            implementation_safety=5.0,
            maintainability=5.0,
            compliance_alignment=5.0,
            effort_estimate=5.0,
        )
        s.compute_total()
        assert s.total_score == 5.0


# ---------------------------------------------------------------------------
# PatchCandidate
# ---------------------------------------------------------------------------

class TestPatchCandidate:
    def test_approved_defaults_to_none(self):
        p = PatchCandidate(finding_id="abc123", file_path="app.py")
        assert p.approved is None

    def test_fields_stored(self):
        p = PatchCandidate(
            finding_id="abc123",
            file_path="app/db.py",
            original_code="eval(x)",
            patched_code="int(x)",
            rationale="eval is dangerous",
        )
        assert p.original_code == "eval(x)"
        assert p.rationale == "eval is dangerous"
