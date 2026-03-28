# pyre-unsafe
"""Shared utilities — JSON parsing, finding lookup, path sandboxing."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from cyber_sentry_cli.core.models import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON Parsing (shared by orchestrator, debate_engine, judge, generator)
# ---------------------------------------------------------------------------

def parse_llm_json(response: str, *, fallback: dict | None = None) -> dict:
    """Parse a JSON response from an LLM, handling markdown code fences.

    Tries:
      1. Direct ``json.loads``
      2. Extract from ```json ... ``` block
      3. Extract from ``` ... ``` block
      4. Return *fallback* (defaults to empty dict)
    """
    # 1. Direct parse
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    # 2/3. Extract from fenced code blocks
    for fence in ("```json", "```"):
        if fence in response:
            try:
                json_str = response.split(fence, 1)[1].split("```", 1)[0].strip()
                return json.loads(json_str)
            except (json.JSONDecodeError, IndexError):
                continue

    logger.debug("Failed to parse LLM response as JSON (len=%d)", len(response))
    return fallback if fallback is not None else {}


# ---------------------------------------------------------------------------
# Finding Lookup (shared by debate, patch, explain)
# ---------------------------------------------------------------------------

def find_finding_by_id(findings: list[Finding], finding_id: str) -> Finding | None:
    """Find a finding by exact ID or prefix match. Returns None if not found."""
    for f in findings:
        if f.id == finding_id or f.id.startswith(finding_id):
            return f
    return None


# ---------------------------------------------------------------------------
# Path Sandboxing
# ---------------------------------------------------------------------------

def safe_resolve_path(raw_path: str, project_root: Path) -> Path | None:
    """Resolve *raw_path* and return it only if it's inside *project_root*.

    Returns ``None`` when the path escapes the sandbox.
    """
    try:
        target = Path(raw_path).resolve()
        root = project_root.resolve()
        if target == root or target.is_relative_to(root):
            return target
        return None
    except (OSError, ValueError):
        return None
