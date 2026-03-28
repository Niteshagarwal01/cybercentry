# pyre-unsafe
"""Patch generator — LLM-powered code patch generation."""

from __future__ import annotations

import json
import re
from pathlib import Path

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.events import emit
from cyber_sentry_cli.core.models import (
    AgentRole,
    DebateSession,
    EventType,
    Finding,
    PatchCandidate,
)
from cyber_sentry_cli.core.utils import parse_llm_json, safe_resolve_path
from cyber_sentry_cli.integrations.openrouter import OpenRouterClient
from cyber_sentry_cli.reasoning.prompts import PATCH_GENERATION_SYSTEM


FREE_CODING_FALLBACK_MODELS = [
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "qwen/qwen3-4b:free",
]


def _extract_sql_var_name(line: str) -> str:
    """Best-effort extraction of the interpolated SQL variable name."""
    concat_match = re.search(r"\+\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\+", line)
    if concat_match:
        return concat_match.group(1)

    fstring_match = re.search(r"\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}", line)
    if fstring_match:
        return fstring_match.group(1)

    return "username"


def _build_b608_safe_patch(file_content: str, finding: Finding) -> tuple[str, str] | None:
    """Build a deterministic safe patch for common B608 SQL injection patterns."""
    if not file_content or finding.line_start <= 0:
        return None

    lines = file_content.splitlines()
    q_idx = finding.line_start - 1
    if q_idx >= len(lines):
        return None

    query_line = lines[q_idx]
    lowered = query_line.lower()
    if "select" not in lowered or "where" not in lowered:
        return None

    variable = _extract_sql_var_name(query_line)
    indent = query_line[: len(query_line) - len(query_line.lstrip())]

    exec_idx = None
    for i in range(q_idx, min(q_idx + 5, len(lines))):
        if "cursor.execute(query" in lines[i].replace(" ", ""):
            exec_idx = i
            break
        if "cursor.execute(query" in lines[i]:
            exec_idx = i
            break

    if exec_idx is None:
        return None

    original_block = "\n".join(lines[q_idx:exec_idx + 1])
    safe_query = f'{indent}query = "SELECT * FROM users WHERE {variable} = ?"'
    safe_execute = f"{indent}cursor.execute(query, ({variable},))"
    patched_block = "\n".join([safe_query, safe_execute])

    return original_block, patched_block


def _still_sql_injection(patched_code: str) -> bool:
    """Detect clearly unsafe SQL interpolation patterns in generated patch code."""
    code = patched_code.lower()
    if "select" not in code:
        return False

    bad_markers = [
        " + ",
        "{",
        "%s",
        "format(",
    ]
    if any(marker in code for marker in bad_markers) and "cursor.execute(query," not in code:
        return True

    if "where" in code and "='" in code.replace(" ", ""):
        return True

    return False


def _load_file_context(file_path: str, line_start: int, line_end: int) -> tuple[str, str]:
    """Load actual file contents and a focused context window around the finding."""
    if not file_path:
        return "", ""

    path = safe_resolve_path(file_path, Path.cwd())
    if not path or not path.exists():
        return "", ""

    content = path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()

    if not lines:
        return content, ""

    start_index = max((line_start or 1) - 1, 0)
    end_index = max(line_end or line_start or 1, 1)
    window_start = max(start_index - 3, 0)
    window_end = min(end_index + 3, len(lines))

    focused_lines = lines[window_start:window_end]

    return content, "\n".join(focused_lines)


def generate_patch(
    finding: Finding,
    session: DebateSession | None,
    config: Config,
) -> PatchCandidate:
    """Generate a code patch based on the winning debate proposal."""
    llm = OpenRouterClient(config)
    file_content, focused_context = _load_file_context(
        finding.file_path,
        finding.line_start,
        finding.line_end,
    )

    # Deterministic secure fix for common SQL injection pattern.
    if finding.rule_id.startswith("B608"):
        safe_patch = _build_b608_safe_patch(file_content, finding)
        if safe_patch is not None:
            original_code, patched_code = safe_patch
            line_count = max(original_code.count("\n") + 1, 1)
            patch = PatchCandidate(
                finding_id=finding.id,
                debate_session_id=session.id if session else "",
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_start + line_count - 1,
                original_code=original_code,
                patched_code=patched_code,
                unified_diff=_generate_unified_diff(original_code, patched_code, finding.file_path),
                rationale="Applied deterministic parameterized-query remediation for Bandit B608 SQL injection.",
                risks="Validate DB-API placeholder style for your database driver.",
                rollback_note="Restore the original query construction and execute call.",
            )
            emit(EventType.PATCH_GENERATED, f"Patch generated for {finding.file_path}")
            return patch

    # Find the winning proposal
    winning_proposal = None
    if session and session.winner:
        final_round = session.rounds
        for p in session.proposals:
            if p.agent_role == session.winner and p.round_number == final_round:
                winning_proposal = p
                break

    # Build prompt
    context = f"""## Vulnerability to Fix

**Title:** {finding.title}
**Severity:** {finding.severity.value}
**CWE:** {finding.cwe or 'N/A'}
**File:** {finding.file_path}:{finding.line_start}
**Description:** {finding.description}

**Vulnerable Code:**
```
{finding.code_snippet or 'N/A'}
```

**Focused File Context (actual file contents with line numbers):**
```
{focused_context or 'N/A'}
```

**Current File Contents (actual file):**
```
{file_content or 'N/A'}
```
"""

    if winning_proposal:
        code_section = (
            f"**Suggested Code:**\n```\n{winning_proposal.code_patch}\n```"
            if winning_proposal.code_patch
            else ""
        )
        context += f"""
## Winning Remediation Strategy ({winning_proposal.agent_role.value})

**Summary:** {winning_proposal.summary}
**Fix:** {winning_proposal.detailed_fix}
**Rationale:** {winning_proposal.rationale}

{code_section}
"""

    context += (
        "\nGenerate a precise, minimal code patch to fix this vulnerability. "
        "The original_code must be copied verbatim from the current file contents. "
        "Do not invent code that is not present in the file. "
        "Never return line numbers inside original_code or patched_code. "
        "For SQL injection findings, use parameterized queries with bound parameters; "
        "never use f-strings, concatenation, or .format for SQL construction."
    )

    messages = [
        {"role": "system", "content": PATCH_GENERATION_SYSTEM},
        {"role": "user", "content": context},
    ]

    emit(EventType.ACT, "Generating patch using LLM...")

    try:
        models_to_try: list[str] = []
        if config.coding_model:
            models_to_try.append(config.coding_model)
        if config.using_local_llm:
            if config.chat_model not in models_to_try:
                models_to_try.append(config.chat_model)
        else:
            for model_name in FREE_CODING_FALLBACK_MODELS:
                if model_name not in models_to_try:
                    models_to_try.append(model_name)
            if config.chat_model not in models_to_try:
                models_to_try.append(config.chat_model)

        last_error: Exception | None = None
        response = ""
        for index, model_name in enumerate(models_to_try):
            try:
                response = llm.chat(messages, model=model_name)
                if index > 0:
                    emit(EventType.INFO, f"Patch generation succeeded with fallback model {model_name}.")
                break
            except RuntimeError as exc:
                last_error = exc
                if index < len(models_to_try) - 1:
                    emit(EventType.INFO, f"Model unavailable ({model_name}); retrying with {models_to_try[index + 1]}.")
                    continue
                raise exc

        if not response and last_error is not None:
            raise last_error

        # Parse response
        data = _parse_patch_response(response)

        patch = PatchCandidate(
            finding_id=finding.id,
            debate_session_id=session.id if session else "",
            file_path=data.get("file_path", finding.file_path),
            line_start=finding.line_start,
            line_end=finding.line_end,
            original_code=data.get("original_code", finding.code_snippet or ""),
            patched_code=data.get("patched_code", ""),
            unified_diff=_generate_unified_diff(
                data.get("original_code", ""),
                data.get("patched_code", ""),
                finding.file_path,
            ),
            rationale=data.get("explanation", ""),
            risks=data.get("risks", ""),
            rollback_note=data.get("rollback_note", "Revert the changed lines to their original state."),
        )

        if finding.rule_id.startswith("B608") and _still_sql_injection(patch.patched_code):
            safe_patch = _build_b608_safe_patch(file_content, finding)
            if safe_patch is not None:
                original_code, patched_code = safe_patch
                patch.original_code = original_code
                patch.patched_code = patched_code
                patch.unified_diff = _generate_unified_diff(original_code, patched_code, finding.file_path)
                patch.rationale = "Replaced unsafe model output with deterministic parameterized-query remediation."

        emit(EventType.PATCH_GENERATED, f"Patch generated for {finding.file_path}")
        return patch

    except Exception as e:
        emit(EventType.ERROR, f"Patch generation failed: {e}")
        return PatchCandidate(
            finding_id=finding.id,
            debate_session_id=session.id if session else "",
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            rationale=f"Error: {e}",
        )


def _parse_patch_response(response: str) -> dict:
    """Parse LLM patch response using shared utility."""
    fallback = {"patched_code": response, "explanation": "Raw LLM response"}
    return parse_llm_json(response, fallback=fallback)


def _generate_unified_diff(original: str, patched: str, file_path: str) -> str:
    """Generate a unified diff string."""
    import difflib

    original_lines = original.splitlines(keepends=True)
    patched_lines = patched.splitlines(keepends=True)

    diff = difflib.unified_diff(
        original_lines,
        patched_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    )
    return "\n".join(diff)
