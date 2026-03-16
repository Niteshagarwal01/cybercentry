# pyre-unsafe
"""Judge agent — LLM-powered scoring and ranking of debate proposals."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from rich.console import Console

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.events import emit
from cyber_sentry_cli.core.models import (
    AgentRole,
    DebateSession,
    EventType,
    Finding,
    JudgeScore,
)
from cyber_sentry_cli.integrations.openrouter import OpenRouterClient
from cyber_sentry_cli.reasoning.prompts import JUDGE_EVALUATION_USER, JUDGE_SYSTEM

console = Console()


class JudgeAgent:
    """Scores proposals from the debate and selects a winner."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.llm = OpenRouterClient(config)

    def evaluate(self, session: DebateSession, finding: Finding) -> DebateSession:
        """Run judge evaluation on the debate session's final proposals."""
        emit(EventType.JUDGE_SCORE, "⚖️  Judge is evaluating proposals...")

        # Get final round proposals
        final_round = session.rounds
        final_proposals = {
            p.agent_role: p for p in session.proposals if p.round_number == final_round
        }

        # Format proposals for the judge
        def _format_proposal(p) -> str:
            if p is None:
                return "No proposal submitted."
            parts = [f"**Summary:** {p.summary}"]
            if p.detailed_fix:
                parts.append(f"**Fix:** {p.detailed_fix}")
            if p.code_patch:
                parts.append(f"**Code:**\n```\n{p.code_patch}\n```")
            if p.rationale:
                parts.append(f"**Rationale:** {p.rationale}")
            if p.risks:
                parts.append(f"**Risks:** {p.risks}")
            if p.effort_estimate:
                parts.append(f"**Effort:** {p.effort_estimate}")
            return "\n".join(parts)

        user_prompt = JUDGE_EVALUATION_USER.format(
            finding_title=finding.title,
            severity=finding.severity.value,
            cwe=finding.cwe or "N/A",
            file_path=finding.file_path,
            line_start=finding.line_start,
            red_team_proposal=_format_proposal(final_proposals.get(AgentRole.RED_TEAM)),
            blue_team_proposal=_format_proposal(final_proposals.get(AgentRole.BLUE_TEAM)),
            auditor_proposal=_format_proposal(final_proposals.get(AgentRole.AUDITOR)),
        )

        messages = [
            {"role": "system", "content": JUDGE_SYSTEM},
            {"role": "user", "content": user_prompt},
        ]

        try:
            response = self.llm.chat(messages)
            scores, winner, winner_rationale = self._parse_judge_response(response)

            session.scores = scores
            session.winner = winner
            session.winner_rationale = winner_rationale
            session.completed_at = datetime.now(timezone.utc)

            emit(
                EventType.JUDGE_SCORE,
                f"🏆 Winner: {winner.value if winner else 'None'}\n{winner_rationale}",
                agent_role=AgentRole.JUDGE,
            )

        except Exception as e:
            emit(EventType.ERROR, f"Judge evaluation failed: {e}", agent_role=AgentRole.JUDGE)
            session.completed_at = datetime.now(timezone.utc)

        return session

    def _parse_judge_response(
        self, response: str
    ) -> tuple[list[JudgeScore], AgentRole | None, str]:
        """Parse the judge's JSON response into scores."""
        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            try:
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0].strip()
                    data = json.loads(json_str)
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0].strip()
                    data = json.loads(json_str)
                else:
                    return [], None, "Failed to parse judge response"
            except (json.JSONDecodeError, IndexError):
                return [], None, "Failed to parse judge response"

        scores: list[JudgeScore] = []
        role_map = {
            "RED_TEAM": AgentRole.RED_TEAM,
            "BLUE_TEAM": AgentRole.BLUE_TEAM,
            "AUDITOR": AgentRole.AUDITOR,
        }

        for score_data in data.get("scores", []):
            role_str = score_data.get("agent_role", "")
            role = role_map.get(role_str)
            if not role:
                continue

            score = JudgeScore(
                proposal_id="",
                agent_role=role,
                security_effectiveness=float(score_data.get("security_effectiveness", 0)),
                implementation_safety=float(score_data.get("implementation_safety", 0)),
                maintainability=float(score_data.get("maintainability", 0)),
                compliance_alignment=float(score_data.get("compliance_alignment", 0)),
                effort_estimate=float(score_data.get("effort_estimate", 0)),
                rationale=score_data.get("rationale", ""),
            )
            score.compute_total()
            scores.append(score)

        winner_str = data.get("winner", "")
        winner = role_map.get(winner_str)
        winner_rationale = data.get("winner_rationale", "")

        return scores, winner, winner_rationale
