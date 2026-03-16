# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

CyberSentry (`cs`) is an autonomous security CLI tool that scans Python codebases for vulnerabilities, clusters findings by root cause, runs a multi-agent debate to select the best remediation, and generates human-approved patches. All LLM calls route through OpenRouter.

## Setup

```bash
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows PowerShell
source .venv/bin/activate     # Linux/macOS

# Install package with dev dependencies
pip install -e ".[dev,scanners]"

# Copy and fill in the API key
cp .env.example .env
# Set OPENROUTER_API_KEY in .env

# Initialize project config (creates .cybersentry/config.toml)
cs init
```

External scanners (optional but recommended):
- `pip install bandit` or `pip install ".[scanners]"`
- Install [semgrep](https://semgrep.dev/docs/getting-started/) separately

Verify everything works:
```bash
cs doctor
```

## Common Commands

```bash
# Lint
ruff check src/

# Type check
pyright

# Run tests
pytest

# Run a specific test file
pytest tests/vulnerable_sample.py

# Full scan → triage → report workflow
cs scan tests/vulnerable_sample.py
cs triage latest
cs debate <finding-id>
cs patch <finding-id> --dry-run
cs patch <finding-id> --apply
cs report latest --format md
cs trace latest

# Interactive agentic chat (primary UX)
cs chat
cs chat tests/vulnerable_sample.py   # auto-scans target on launch
```

Run IDs are 12-character hex strings. Use `latest` as a shorthand wherever a run ID is accepted.

## Architecture

### CLI Entry Point
`main.py` registers all Typer commands. Each command is a thin wrapper that calls `<name>_command()` from `commands/`. Commands are lazy-imported to keep startup fast.

### Data Flow
```
cs scan → scanners/ (Bandit + Semgrep adapters) → Finding[] 
       → RunStateManager saves run.json + findings.json
cs triage → core/triage.py clusters findings via LLM → clusters.json
cs debate → reasoning/debate_engine.py (Red/Blue/Auditor × 3 rounds)
          → reasoning/judge.py scores proposals → winner
cs patch  → remediation/generator.py calls LLM with coding_model
          → remediation/diff.py + approval.py (human gate)
```

### Core Modules (`src/cyber_sentry_cli/`)

- **`core/models.py`** — All Pydantic models: `Finding`, `Run`, `Cluster`, `Proposal`, `JudgeScore`, `DebateSession`, `PatchCandidate`, `Event`. `Severity` and `EventType` enums live here.
- **`core/config.py`** — `Config` class. Merges `.cybersentry/config.toml` over `DEFAULT_CONFIG`. Two LLM model slots: `chat_model` (default `gpt-4o-mini`) and `coding_model` (default `qwen/qwen3-coder-480b-a35b-instruct:free`).
- **`core/orchestrator.py`** — `ReActOrchestrator` runs the Think→Act→Observe loop (max 10 iterations). Available tools: `read_file`, `search_pattern`, `list_files`.
- **`core/run_state.py`** — `RunStateManager` persists JSON artifacts under `.cybersentry/runs/<run-id>/`.
- **`core/triage.py`** — LLM-powered root-cause clustering with rule-based fallback.
- **`core/events.py`** — `emit()` broadcasts `Event` objects; subscribers render to terminal and append to `events.json`.

### Scanners (`scanners/`)
All scanners extend `BaseScanner` (abstract: `scan()` + `is_available()`). `BanditScanner` and `SemgrepScanner` invoke the external CLI via `subprocess`, parse JSON output, and normalize results to `Finding` objects. Bandit exits with code 1 when findings exist — check `stdout`, not return code.

### Reasoning (`reasoning/`)
- **`debate_engine.py`** — `DebateEngine` runs `N` rounds (default 3). In each round, Red Team, Blue Team, and Auditor agents each call the LLM independently. Round 2+ prompts include the previous round's proposals for cross-pollination.
- **`judge.py`** — Scores all final proposals on 5 weighted dimensions and selects a winner.
- **`prompts.py`** — All system and user prompt templates. JSON-structured responses are expected from every agent.

### Integrations (`integrations/`)
`OpenRouterClient` wraps `httpx`. Use `chat()` for single-shot responses, `chat_stream()` for token streaming (used in `cs chat`), and `chat_json()` for JSON-mode calls. The `coding_model` is used for patch generation; all other calls use `chat_model`.

### Run Artifacts
Each run directory (`.cybersentry/runs/<run-id>/`) contains:
- `run.json` — serialized `Run` model (findings embedded)
- `findings.json` — flat findings list
- `clusters.json` — triage output
- `events.json` — full thought-trace timeline

### Configuration
`.cybersentry/config.toml` overrides `DEFAULT_CONFIG` in `core/config.py`. The `[general]` section controls model names, debate rounds, and ReAct iterations. `OPENROUTER_API_KEY` is always read from environment (via `.env`).
