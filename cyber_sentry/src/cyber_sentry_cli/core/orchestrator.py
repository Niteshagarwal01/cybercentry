# pyre-unsafe
"""ReAct loop orchestrator — LLM-powered autonomous investigation agent."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.events import emit
from cyber_sentry_cli.core.models import EventType
from cyber_sentry_cli.core.utils import parse_llm_json, safe_resolve_path
from cyber_sentry_cli.integrations.openrouter import OpenRouterClient
from cyber_sentry_cli.reasoning.prompts import REACT_SYSTEM

console = Console()


# ---------------------------------------------------------------------------
# Tools available to the ReAct agent
# ---------------------------------------------------------------------------

def _tool_read_file(params: dict) -> str:
    """Read contents of a file (sandboxed to project root)."""
    raw = params.get("path", "")
    project_root = Path.cwd()
    path = safe_resolve_path(raw, project_root)
    if path is None:
        return f"Error: Path rejected (must be inside project root {project_root})"
    if not path.exists():
        return f"Error: File not found: {path}"
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        if len(content) > 5000:
            content = content[:5000] + "\n... [truncated]"
        return content
    except Exception as e:
        return f"Error reading file: {e}"


def _tool_search_pattern(params: dict) -> str:
    """Search for a string pattern across Python files (cross-platform, pure Python)."""
    import re

    pattern = params.get("pattern", "")
    directory = params.get("directory", ".")
    if not pattern:
        return "Error: no pattern provided."

    matches: list[str] = []
    try:
        for py_file in Path(directory).rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
                for i, line in enumerate(content.splitlines(), 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        matches.append(f"{py_file}:{i}: {line.strip()}")
                        if len(matches) >= 50:
                            break
            except Exception:
                continue
            if len(matches) >= 50:
                break
    except Exception as e:
        return f"Error: {e}"

    output = "\n".join(matches)
    if len(output) > 3000:
        output = output[:3000] + "\n... [truncated]"
    return output or "No matches found."


def _tool_list_files(params: dict) -> str:
    """List files in a directory (sandboxed to project root)."""
    raw = params.get("directory", ".")
    project_root = Path.cwd()
    directory = safe_resolve_path(raw, project_root)
    if directory is None:
        return f"Error: Path rejected (must be inside project root {project_root})"
    file_pattern = params.get("pattern", "*.py")

    try:
        files = list(directory.rglob(file_pattern))
        result = [str(f) for f in files[:50]]
        return "\n".join(result) if result else "No files found."
    except Exception as e:
        return f"Error: {e}"


TOOLS = {
    "read_file": {
        "fn": _tool_read_file,
        "description": "Read the contents of a file. Parameters: {\"path\": \"file/path.py\"}",
    },
    "search_pattern": {
        "fn": _tool_search_pattern,
        "description": "Search for a pattern across Python files. Parameters: {\"pattern\": \"search_term\", \"directory\": \".\"}",
    },
    "list_files": {
        "fn": _tool_list_files,
        "description": "List files matching a pattern. Parameters: {\"directory\": \".\", \"pattern\": \"*.py\"}",
    },
}


# ---------------------------------------------------------------------------
# ReAct Orchestrator
# ---------------------------------------------------------------------------

class ReActOrchestrator:
    """Runs an LLM-powered ReAct loop for autonomous investigation."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.llm = OpenRouterClient(config)
        self.max_iterations = config.max_react_iterations

    def investigate(self, target: str, context: str = "") -> list[dict[str, Any]]:
        """Run a ReAct investigation on the target."""
        tools_desc = "\n".join(
            f"- {name}: {info['description']}" for name, info in TOOLS.items()
        )
        tools_desc += '\n- finish: End investigation and report findings. Parameters: {"summary": "..."}'

        system_prompt = REACT_SYSTEM.format(
            tools_description=tools_desc,
            max_iterations=self.max_iterations,
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"Investigate security issues in: {target}\n\n{context}",
            },
        ]

        trace: list[dict[str, Any]] = []

        for i in range(self.max_iterations):
            emit(EventType.THINK, f"ReAct iteration {i + 1}/{self.max_iterations}")

            try:
                response = self.llm.chat(messages)
                step = self._parse_step(response)
            except Exception as e:
                emit(EventType.ERROR, f"ReAct step failed: {e}")
                break

            thought = step.get("thought", "")
            action = step.get("action", "finish")
            action_input = step.get("action_input", {})

            emit(EventType.THINK, f"Thought: {thought}")
            trace.append({"iteration": i + 1, "thought": thought, "action": action})

            if action == "finish":
                emit(EventType.OBSERVE, f"Investigation complete: {action_input.get('summary', '')}")
                trace.append({"summary": action_input.get("summary", "")})
                break

            # Execute tool
            if action in TOOLS:
                emit(EventType.TOOL_CALL, f"Tool: {action}({json.dumps(action_input)})")
                result = TOOLS[action]["fn"](action_input)
                emit(EventType.TOOL_RESULT, f"Result: {result[:200]}")
                trace.append({"tool_result": result[:2000]})

                # Add observation to conversation
                messages.append({"role": "assistant", "content": response})
                messages.append({
                    "role": "user",
                    "content": f"Observation from {action}:\n{result}",
                })
            else:
                emit(EventType.ERROR, f"Unknown tool: {action}")
                messages.append({"role": "assistant", "content": response})
                messages.append({
                    "role": "user",
                    "content": f"Error: Tool '{action}' not found. Available: {list(TOOLS.keys())}",
                })

        return trace

    def _parse_step(self, response: str) -> dict:
        """Parse a ReAct step response."""
        result = parse_llm_json(response)
        if result:
            return result
        # Fallback: treat the raw text as a finish action
        return {"thought": response[:200], "action": "finish", "action_input": {"summary": response}}
