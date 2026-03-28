# pyre-unsafe
"""Pydantic data models for all CyberSentry entities."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> float:
        return {
            Severity.CRITICAL: 1.00,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.45,
            Severity.LOW: 0.20,
            Severity.INFO: 0.05,
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "red bold",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]


class EventType(str, Enum):
    """Types of events in the thought trace timeline."""
    THINK = "THINK"
    ACT = "ACT"
    OBSERVE = "OBSERVE"
    PIVOT = "PIVOT"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    DEBATE_START = "DEBATE_START"
    DEBATE_ROUND = "DEBATE_ROUND"
    JUDGE_SCORE = "JUDGE_SCORE"
    PATCH_GENERATED = "PATCH_GENERATED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    ERROR = "ERROR"
    INFO = "INFO"


class AgentRole(str, Enum):
    """Roles in the multi-agent debate."""
    RED_TEAM = "RED_TEAM"
    BLUE_TEAM = "BLUE_TEAM"
    AUDITOR = "AUDITOR"
    JUDGE = "JUDGE"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Core Models
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1.0.0"


class Finding(BaseModel):
    """A single vulnerability finding from a scanner."""
    id: str = Field(default_factory=_new_id)
    schema_version: str = SCHEMA_VERSION
    scanner: str = ""                       # semgrep, bandit, etc.
    rule_id: str = ""                       # scanner-specific rule identifier
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.8                 # 0.0 – 1.0
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    code_snippet: str = ""
    cwe: str = ""                           # e.g. "CWE-89"
    owasp: str = ""                         # e.g. "A03:2021"
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_now)


class Cluster(BaseModel):
    """A group of related findings sharing a root cause."""
    id: str = Field(default_factory=_new_id)
    root_cause: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    reasoning: str = ""


class Run(BaseModel):
    """A single scan run with all of its artifacts."""
    id: str = Field(default_factory=_new_id)
    schema_version: str = SCHEMA_VERSION
    target: str = ""
    started_at: datetime = Field(default_factory=_now)
    completed_at: Optional[datetime] = None
    scanners_used: list[str] = Field(default_factory=list)
    total_findings: int = 0
    findings: list[Finding] = Field(default_factory=list)
    clusters: list[Cluster] = Field(default_factory=list)
    status: str = "running"                 # running | completed | failed


class Proposal(BaseModel):
    """A remediation proposal from a debate agent."""
    id: str = Field(default_factory=_new_id)
    agent_role: AgentRole
    round_number: int = 1
    summary: str = ""
    detailed_fix: str = ""
    code_patch: str = ""
    rationale: str = ""
    risks: str = ""
    effort_estimate: str = ""


class JudgeScore(BaseModel):
    """Judge's scoring of a proposal."""
    proposal_id: str
    agent_role: AgentRole
    security_effectiveness: float = 0.0     # 0–10
    implementation_safety: float = 0.0      # 0–10
    maintainability: float = 0.0            # 0–10
    compliance_alignment: float = 0.0       # 0–10
    effort_estimate: float = 0.0            # 0–10 (lower effort = higher score)
    total_score: float = 0.0
    rationale: str = ""

    def compute_total(self) -> float:
        self.total_score = round(
            self.security_effectiveness * 0.30
            + self.implementation_safety * 0.25
            + self.maintainability * 0.20
            + self.compliance_alignment * 0.15
            + self.effort_estimate * 0.10,
            2,
        )
        return self.total_score


class DebateSession(BaseModel):
    """A complete debate session for a finding."""
    id: str = Field(default_factory=_new_id)
    finding_id: str
    rounds: int = 3
    proposals: list[Proposal] = Field(default_factory=list)
    scores: list[JudgeScore] = Field(default_factory=list)
    winner: Optional[AgentRole] = None
    winner_rationale: str = ""
    started_at: datetime = Field(default_factory=_now)
    completed_at: Optional[datetime] = None


class PatchCandidate(BaseModel):
    """A generated patch ready for human review."""
    id: str = Field(default_factory=_new_id)
    finding_id: str
    debate_session_id: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    original_code: str = ""
    patched_code: str = ""
    unified_diff: str = ""
    rationale: str = ""
    risks: str = ""
    rollback_note: str = ""
    approved: Optional[bool] = None


class Event(BaseModel):
    """A single event in the thought trace timeline."""
    id: str = Field(default_factory=_new_id)
    run_id: str = ""
    event_type: EventType
    timestamp: datetime = Field(default_factory=_now)
    agent_role: Optional[AgentRole] = None
    content: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
