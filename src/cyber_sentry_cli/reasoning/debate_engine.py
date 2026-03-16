# pyre-unsafe
"""Multi-agent debate engine — Red Team vs Blue Team vs Auditor, with LLM-powered reasoning."""

from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.events import emit
from cyber_sentry_cli.core.models import (
    AgentRole,
    DebateSession,
    EventType,
    Finding,
    Proposal,
)
from cyber_sentry_cli.integrations.openrouter import OpenRouterClient
from cyber_sentry_cli.reasoning.prompts import (
    AUDITOR_SYSTEM,
    BLUE_TEAM_SYSTEM,
    DEBATE_ROUND_1_USER,
    DEBATE_ROUND_2_USER,
    DEBATE_ROUND_3_USER,
    RED_TEAM_SYSTEM,
)

console = Console()

# Agent role → system prompt mapping
_ROLE_PROMPTS = {
    AgentRole.RED_TEAM: RED_TEAM_SYSTEM,
    AgentRole.BLUE_TEAM: BLUE_TEAM_SYSTEM,
    AgentRole.AUDITOR: AUDITOR_SYSTEM,
}

_ROLE_ICONS = {
    AgentRole.RED_TEAM: "🔴",
    AgentRole.BLUE_TEAM: "🔵",
    AgentRole.AUDITOR: "📋",
}


class DebateEngine:
    """Runs a multi-round debate between Red Team, Blue Team, and Auditor agents."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.llm = OpenRouterClient(config)
        self.rounds = config.debate_rounds

    def run_debate(self, finding: Finding) -> DebateSession:
        """Execute a full debate session for a finding."""
        session = DebateSession(finding_id=finding.id, rounds=self.rounds)

        emit(
            EventType.DEBATE_START,
            f"Starting {self.rounds}-round debate for finding: {finding.title[:80]}",
            agent_role=None,
        )

        # Store proposals per round for cross-referencing
        round_proposals: dict[int, dict[AgentRole, str]] = {}

        for round_num in range(1, self.rounds + 1):
            emit(
                EventType.DEBATE_ROUND,
                f"━━━ Round {round_num}/{self.rounds} ━━━",
            )

            round_proposals[round_num] = {}

            for role in [AgentRole.RED_TEAM, AgentRole.BLUE_TEAM, AgentRole.AUDITOR]:
                icon = _ROLE_ICONS[role]
                emit(
                    EventType.DEBATE_ROUND,
                    f"{icon} {role.value} is formulating proposal...",
                    agent_role=role,
                )

                # Build the user prompt based on round
                user_prompt = self._build_round_prompt(
                    round_num, finding, role, round_proposals
                )

                # Call LLM
                messages = [
                    {"role": "system", "content": _ROLE_PROMPTS[role]},
                    {"role": "user", "content": user_prompt},
                ]

                try:
                    response = self.llm.chat(messages)
                    round_proposals[round_num][role] = response

                    # Parse into Proposal
                    proposal = self._parse_proposal(response, role, round_num)
                    session.proposals.append(proposal)

                    # Show proposal summary
                    emit(
                        EventType.DEBATE_ROUND,
                        f"{icon} {role.value}: {proposal.summary}",
                        agent_role=role,
                    )

                except Exception as e:
                    emit(EventType.ERROR, f"{role.value} failed: {e}", agent_role=role)
                    # Create a fallback proposal
                    fallback = Proposal(
                        agent_role=role,
                        round_number=round_num,
                        summary=f"[Error: {role.value} could not generate proposal]",
                        rationale=str(e),
                    )
                    session.proposals.append(fallback)
                    round_proposals[round_num][role] = f"Error: {e}"

        return session

    def _build_round_prompt(
        self,
        round_num: int,
        finding: Finding,
        role: AgentRole,
        round_proposals: dict[int, dict[AgentRole, str]],
    ) -> str:
        """Build the appropriate prompt for the current round."""
        if round_num == 1:
            return DEBATE_ROUND_1_USER.format(
                finding_id=finding.id,
                severity=finding.severity.value,
                scanner=finding.scanner,
                rule_id=finding.rule_id,
                cwe=finding.cwe or "N/A",
                file_path=finding.file_path,
                line_start=finding.line_start,
                title=finding.title,
                description=finding.description,
                code_snippet=finding.code_snippet or "N/A",
            )
        elif round_num == 2:
            prev = round_proposals.get(1, {})
            return DEBATE_ROUND_2_USER.format(
                red_team_proposal=prev.get(AgentRole.RED_TEAM, "N/A"),
                blue_team_proposal=prev.get(AgentRole.BLUE_TEAM, "N/A"),
                auditor_proposal=prev.get(AgentRole.AUDITOR, "N/A"),
            )
        else:
            prev = round_proposals.get(round_num - 1, {})
            return DEBATE_ROUND_3_USER.format(
                red_team_proposal=prev.get(AgentRole.RED_TEAM, "N/A"),
                blue_team_proposal=prev.get(AgentRole.BLUE_TEAM, "N/A"),
                auditor_proposal=prev.get(AgentRole.AUDITOR, "N/A"),
            )

    def _parse_proposal(self, response: str, role: AgentRole, round_num: int) -> Proposal:
        """Parse LLM response into a Proposal object."""
        import json

        try:
            # Try to parse as JSON
            data = json.loads(response)
        except json.JSONDecodeError:
            # Try extracting JSON from markdown code blocks
            try:
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0].strip()
                    data = json.loads(json_str)
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0].strip()
                    data = json.loads(json_str)
                else:
                    data = {}
            except (json.JSONDecodeError, IndexError):
                data = {}

        return Proposal(
            agent_role=role,
            round_number=round_num,
            summary=str(data.get("summary") or response[:150]),
            detailed_fix=str(data.get("detailed_fix") or ""),
            code_patch=str(data.get("code_patch") or ""),
            rationale=str(data.get("rationale") or ""),
            risks=str(data.get("risks") or ""),
            effort_estimate=str(data.get("effort_estimate") or ""),
        )
