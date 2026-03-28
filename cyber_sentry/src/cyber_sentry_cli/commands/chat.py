# pyre-unsafe
"""cs chat — Interactive agentic chat mode with tool picker and approval flow."""

from __future__ import annotations

import json
import re
import shlex
import time
from pathlib import Path
from typing import Any, Optional

from rich.align import Align
from rich.box import ROUNDED
from rich.console import Console, Group
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.spinner import Spinner
from rich.text import Text
from rich.theme import Theme

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.models import Finding
from cyber_sentry_cli.core.utils import safe_resolve_path
from cyber_sentry_cli.output.terminal import (
    CYBER_THEME,
    console,
    print_error,
    print_info,
    print_mini_banner,
    print_step,
    print_success,
    print_warning,
)

# ---------------------------------------------------------------------------
# Tool definitions (what the LLM can call)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "scan_codebase",
        "description": "Run security scanners (Bandit + Semgrep) on the target codebase",
        "icon": "🔍",
        "color": "bright_cyan",
    },
    {
        "name": "triage_findings",
        "description": "Cluster and prioritize findings by root cause",
        "icon": "📊",
        "color": "bright_magenta",
    },
    {
        "name": "debate_finding",
        "description": "Run multi-agent debate (Red vs Blue vs Auditor) on a specific finding",
        "icon": "⚔️",
        "color": "bright_red",
    },
    {
        "name": "generate_patch",
        "description": "Generate a code patch for a vulnerability",
        "icon": "🩹",
        "color": "bright_green",
    },
    {
        "name": "read_file",
        "description": "Read and analyze a source code file",
        "icon": "📄",
        "color": "bright_yellow",
    },
    {
        "name": "search_code",
        "description": "Search for patterns across the codebase",
        "icon": "🔎",
        "color": "bright_blue",
    },
    {
        "name": "explain_finding",
        "description": "Explain a vulnerability in detail with examples",
        "icon": "💡",
        "color": "bright_white",
    },
]

TOOLS_PROMPT = """You are CyberSentry — an expert offensive and defensive security engineer AI.
You are precise, technical, and direct. No pleasantries. Respond like a senior AppSec engineer.

RESPONSE RULES:
- Use correct security terminology: CWE IDs, OWASP categories, CVSS scores, CVE references where relevant
- Lead with the vulnerability class and attack vector, then explain impact, then remediation
- Format with headers, bullet points, and fenced code blocks (language-tagged)
- Never say "Great question!" or similar fluff — go straight to the answer
- When showing code, always show the vulnerable pattern AND the secure replacement
- Prefer concrete examples over abstract descriptions
- Reference OWASP Top 10, SANS Top 25, or NIST guidelines when applicable

AVAILABLE TOOLS:
1. scan_codebase(target) — Static analysis via Bandit + Semgrep; returns Finding objects with CWE/severity
2. triage_findings(run_id) — LLM-powered root-cause clustering; groups findings by vulnerability class
3. debate_finding(finding_id, run_id) — Red Team / Blue Team / Auditor multi-agent debate on best remediation
4. generate_patch(finding_id, run_id) — LLM generates a minimal, safe code patch with unified diff
5. read_file(path) — Read source file for manual analysis
6. search_code(pattern, path) — Grep-style search for vulnerable patterns across codebase
7. explain_finding(finding_id, run_id) — Deep-dive on a specific finding: root cause, exploit scenario, fix

To call a tool emit exactly this block (nothing else on that line):
```tool
{{"tool": "tool_name", "args": {{"arg1": "value1"}}}}
```

CRITICAL INSTRUCTION: Once you emit a ```tool block, you MUST STOP GENERATING TEXT IMMEDIATELY. Do NOT hallucinate the tool result! Wait for the user to provide the tool result back to you before continuing.

After a tool result (provided by the user): interpret it with technical depth, state risk severity, and recommend the next action.
Before applying any patch: show the exact unified diff and wait for explicit user confirmation.

Project: {project_path}
CWD: {cwd}
"""


# ---------------------------------------------------------------------------
# Chat Session
# ---------------------------------------------------------------------------

class ChatSession:
    """Interactive agentic chat session."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.history: list[dict[str, str]] = []
        self.current_run_id: Optional[str] = None
        self.findings: list[Finding] = []

        from cyber_sentry_cli.integrations.openrouter import OpenRouterClient
        self.llm = OpenRouterClient(config)

    def _build_system_prompt(self) -> str:
        """Build the system prompt with current context."""
        cwd = Path.cwd()
        ctx = TOOLS_PROMPT.format(project_path=cwd, cwd=cwd)

        if self.current_run_id:
            ctx += f"\nLast scan run ID: {self.current_run_id}"
        if self.findings:
            ctx += f"\nLoaded findings: {len(self.findings)}"
            for i, f in enumerate(self.findings[:5]):
                ctx += f"\n  {i+1}. [{f.severity.value}] {f.title} — {f.file_path}:{f.line_start}"

        return ctx

    def chat(self, user_message: str) -> str:
        """Send a message and get the agent's response."""
        self.history.append({"role": "user", "content": user_message})

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            *self.history[-20:],  # Keep last 20 messages for context
        ]

        response = self.llm.chat(messages, temperature=0.3)
        self.history.append({"role": "assistant", "content": response})
        return response

    def stream_chat(self, user_message: str):
        """Stream a response token by token."""
        self.history.append({"role": "user", "content": user_message})

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            *self.history[-20:],
        ]

        full_response = ""
        for token in self.llm.chat_stream(messages, temperature=0.3):
            full_response += token
            yield token

        self.history.append({"role": "assistant", "content": full_response})


# ---------------------------------------------------------------------------
# Tool Executor
# ---------------------------------------------------------------------------

def _show_tool_call(tool_name: str, args: dict) -> bool:
    """Display a tool call and ask for approval."""
    tool_info = next((t for t in TOOLS if t["name"] == tool_name), None)
    icon = tool_info["icon"] if tool_info else "🔧"
    color = tool_info["color"] if tool_info else "bright_white"
    desc = tool_info["description"] if tool_info else tool_name

    console.print()
    tool_panel = Text()
    tool_panel.append(f"{icon} ", style=color)
    tool_panel.append(f"{tool_name}", style=f"bold {color}")
    tool_panel.append(f"\n{desc}", style="dim")

    if args:
        tool_panel.append("\n\n", style="")
        for k, v in args.items():
            tool_panel.append(f"  {k}", style="bright_white bold")
            tool_panel.append(f" = ", style="dim")
            tool_panel.append(f"{v}", style="bright_cyan")
            tool_panel.append("\n", style="")

    console.print(Panel(
        tool_panel,
        title="[bold bright_white]🔧 Tool Call[/]",
        subtitle="[dim]approve to execute[/]",
        border_style=color,
        box=ROUNDED,
        padding=(1, 2),
    ))

    return Confirm.ask("  [bright_yellow]Execute this tool?[/]", default=True)


def execute_tool(tool_name: str, args: dict, config: Config) -> str:
    """Execute a tool and return the result."""
    from cyber_sentry_cli.core.run_state import RunStateManager

    state = RunStateManager(config)

    if tool_name == "scan_codebase":
        return _tool_scan(args.get("target", "."), config)
    elif tool_name == "triage_findings":
        return _tool_triage(args.get("run_id", "latest"), config)
    elif tool_name == "read_file":
        return _tool_read_file(args.get("path", ""))
    elif tool_name == "search_code":
        return _tool_search(args.get("pattern", ""), args.get("path", "."))
    elif tool_name == "explain_finding":
        return _tool_explain(args.get("finding_id", ""), args.get("run_id", "latest"), config)
    elif tool_name == "debate_finding":
        return f"Debate tool called for finding {args.get('finding_id', '')} — use `cs debate` for full debate."
    elif tool_name == "generate_patch":
        return f"Patch tool called for finding {args.get('finding_id', '')} — use `cs patch` for full patch generation."
    else:
        return f"Unknown tool: {tool_name}"


def _tool_scan(target: str, config: Config) -> str:
    """Run a scan and return results summary."""
    from cyber_sentry_cli.commands.scan import scan_command
    from cyber_sentry_cli.core.run_state import RunStateManager

    print_step("Scanning", target)
    scan_command(target, "auto")

    state = RunStateManager(config)
    runs = state.list_runs()
    if not runs:
        return "Scan finished but no run was found on disk."

    run = state.load_run(runs[0])
    return (
        f"Scan complete. run_id={run.id}; findings={run.total_findings}. "
        "Use triage_findings with this run_id next."
    )


def _tool_triage(run_id: str, config: Config) -> str:
    """Run triage and return results."""
    from cyber_sentry_cli.commands.triage import triage_command
    from cyber_sentry_cli.core.run_state import RunStateManager

    print_step("Triaging findings", f"run: {run_id}")
    triage_command(run_id)

    state = RunStateManager(config)
    effective_run_id = run_id
    if run_id == "latest":
        runs = state.list_runs()
        if runs:
            effective_run_id = runs[0]

    try:
        run = state.load_run(effective_run_id)
        return f"Triage complete. run_id={run.id}; clusters={len(run.clusters)}."
    except Exception:
        return "Triage complete."


def _tool_read_file(path: str) -> str:
    """Read a file and return its contents."""
    try:
        p = safe_resolve_path(path, Path.cwd())
        if p is None:
            return "Path rejected: must stay inside the project directory."
        if not p.exists():
            return f"File not found: {path}"
        if p.is_dir():
            return f"Path is a directory: {p}"
        content = p.read_text(encoding="utf-8", errors="replace")
        if len(content) > 3000:
            content = content[:3000] + f"\n... (truncated, {len(content)} chars total)"
        return content
    except Exception as e:
        return f"Error reading file: {e}"


def _tool_search(pattern: str, path: str) -> str:
    """Search for a pattern in files."""
    if not pattern:
        return "Search error: empty pattern"
    try:
        base = safe_resolve_path(path, Path.cwd())
        if base is None:
            return "Search error: path rejected (outside project directory)"
        if not base.exists():
            return f"Search error: path does not exist: {path}"

        matches: list[str] = []
        regex = re.compile(pattern, re.IGNORECASE)
        for file_path in base.rglob("*.py"):
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for line_no, line in enumerate(text.splitlines(), 1):
                if regex.search(line):
                    rel = file_path.relative_to(Path.cwd())
                    matches.append(f"{rel}:{line_no}: {line.strip()}")
                    if len(matches) >= 80:
                        break
            if len(matches) >= 80:
                break

        output = "\n".join(matches)
        if len(output) > 2000:
            output = output[:2000] + "\n... (truncated)"
        return output or "No matches found."
    except Exception as e:
        return f"Search error: {e}"


def _tool_explain(finding_id: str, run_id: str, config: Config) -> str:
    """Explain a finding in detail."""
    from cyber_sentry_cli.core.run_state import RunStateManager

    state = RunStateManager(config)
    try:
        if run_id == "latest":
            runs = state.list_runs()
            if runs:
                run_id = runs[0]
        run = state.load_run(run_id)
        for f in run.findings:
            if f.id.startswith(finding_id):
                return (
                    f"Finding: {f.title}\n"
                    f"Severity: {f.severity.value}\n"
                    f"File: {f.file_path}:{f.line_start}\n"
                    f"Rule: {f.rule_id}\n"
                    f"CWE: {f.cwe or 'N/A'}\n"
                    f"Code:\n{f.code_snippet or 'N/A'}\n"
                    f"Description: {f.description}"
                )
        return f"Finding {finding_id} not found."
    except Exception as e:
        return f"Error loading finding: {e}"


# ---------------------------------------------------------------------------
# Parse tool calls from LLM response
# ---------------------------------------------------------------------------

def parse_tool_calls(response: str) -> list[tuple[str, dict]]:
    """Extract tool calls from the LLM response."""
    tool_calls = []
    if "```tool" in response:
        parts = response.split("```tool")
        for part in parts[1:]:
            json_str = part.split("```")[0].strip()
            try:
                data = json.loads(json_str)
                tool_calls.append((data["tool"], data.get("args", {})))
            except (json.JSONDecodeError, KeyError):
                continue
    return tool_calls


# ---------------------------------------------------------------------------
# Interactive Chat Command
# ---------------------------------------------------------------------------

def chat_command(target: Optional[str] = None) -> None:
    """Run the interactive chat mode."""
    config = Config()
    from cyber_sentry_cli.integrations.openrouter import OpenRouterClient

    # Check LLM backend
    llm = OpenRouterClient(config)
    if not llm.is_configured():
        print_error("No LLM backend configured!")
        print_info("Set [cyan]openrouter.base_url[/cyan] to an Ollama/OpenRouter endpoint and configure a model.")
        return

    session = ChatSession(config)

    # Welcome screen
    console.print()
    _print_welcome()

    # Auto-scan if target provided
    if target:
        console.print()
        print_step("Auto-scanning target", target)
        response = session.chat(f"Please scan this target for vulnerabilities: {target}")
        _display_response(response, config)

    # Main loop
    while True:
        console.print()
        try:
            user_input = Prompt.ask(
                "[bright_red bold]🛡️  you[/]",
                console=console,
            )
        except (KeyboardInterrupt, EOFError):
            console.print()
            _print_goodbye()
            break

        user_input = user_input.strip()
        if not user_input:
            continue

        # Exit commands
        if user_input.lower() in ("exit", "quit", "bye", "/quit", "/exit"):
            _print_goodbye()
            break

        # Slash commands
        if user_input.startswith("/"):
            _handle_slash_command(user_input, session, config)
            continue

        # Stream response — buffer tokens, re-render markdown live so no raw asterisks
        console.print()
        console.print(Text("  🤖 CyberSentry", style="bold bright_cyan"))
        console.print(Rule(style="grey30", characters="·"))
        console.print()

        full_response = ""
        try:
            with Live(
                Markdown(""),
                console=console,
                refresh_per_second=12,
                vertical_overflow="visible",
            ) as live:
                for token in session.stream_chat(user_input):
                    full_response += token
                    live.update(Markdown(full_response))
        except Exception as e:
            print_error(f"LLM error: {e}")
            # stream_chat already pushed the user msg to history before failing;
            # pop it so the non-stream fallback doesn't duplicate it.
            if session.history and session.history[-1]["role"] == "user":
                session.history.pop()
            try:
                full_response = session.chat(user_input)
                console.print(Markdown(full_response))
            except Exception as e2:
                print_error(f"Fallback failed: {e2}")
                continue

        console.print()

        # Check for tool calls in the response
        tool_calls = parse_tool_calls(full_response)
        for tool_name, tool_args in tool_calls:
            approved = _show_tool_call(tool_name, tool_args)
            if approved:
                console.print()
                print_step("Executing", f"{tool_name}...")

                with console.status(f"[bright_cyan]Running {tool_name}...[/]", spinner="dots"):
                    result = execute_tool(tool_name, tool_args, config)

                # Show tool result
                console.print(Panel(
                    Text(result[:1000] if len(result) > 1000 else result, style="dim"),
                    title=f"[bold bright_white]📋 Result[/]",
                    border_style="grey37",
                    box=ROUNDED,
                    padding=(0, 1),
                ))

                # Feed result back to conversation
                session.history.append({
                    "role": "user",
                    "content": f"[Tool result from {tool_name}]:\n{result[:2000]}"
                })
            else:
                console.print()
                print_warning(f"Tool '{tool_name}' skipped by user.")


def _print_welcome() -> None:
    """Print the interactive mode welcome screen."""
    from cyber_sentry_cli.output.terminal import print_banner
    print_banner()

    welcome = Text()
    welcome.append("  Interactive Mode", style="bold bright_white")
    welcome.append(" — Chat with your security agent\n\n", style="dim")
    welcome.append("  Commands:\n", style="bright_cyan")
    welcome.append("    /scan <target>   ", style="bright_white")
    welcome.append("  Scan a file or directory\n", style="dim")
    welcome.append("    /findings        ", style="bright_white")
    welcome.append("  Show current findings\n", style="dim")
    welcome.append("    /triage          ", style="bright_white")
    welcome.append("  Cluster and prioritize\n", style="dim")
    welcome.append("    /debate <id>     ", style="bright_white")
    welcome.append("  Run remediation debate for a finding\n", style="dim")
    welcome.append("    /patch <id>      ", style="bright_white")
    welcome.append("  Generate patch (add --apply for approval flow)\n", style="dim")
    welcome.append("    /tools           ", style="bright_white")
    welcome.append("  Show available tools\n", style="dim")
    welcome.append("    /help            ", style="bright_white")
    welcome.append("  Show this help\n", style="dim")
    welcome.append("    /exit            ", style="bright_white")
    welcome.append("  Exit chat mode\n", style="dim")
    welcome.append("\n  Or just ask me anything about security! 💬", style="italic bright_cyan")

    console.print(Panel(
        welcome,
        border_style="bright_red",
        box=ROUNDED,
        padding=(1, 1),
    ))


def _print_goodbye() -> None:
    """Print exit message."""
    console.print()
    console.print(Align.center(
        Text("👋 Stay secure. CyberSentry signing off.", style="bold bright_cyan")
    ))
    console.print(Align.center(Rule(style="bright_red", characters="━")))
    console.print()


def _handle_slash_command(cmd: str, session: ChatSession, config: Config) -> None:
    """Handle slash commands."""
    parts = cmd.split(maxsplit=1)
    command = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    if command == "/help":
        _print_welcome()

    elif command == "/tools":
        console.print()
        for t in TOOLS:
            line = Text()
            line.append(f"  {t['icon']} ", style=t["color"])
            line.append(f"{t['name']}", style=f"bold {t['color']}")
            line.append(f"  — {t['description']}", style="dim")
            console.print(line)

    elif command == "/scan":
        target = arg or "."
        print_step("Scanning", target)
        from cyber_sentry_cli.commands.scan import scan_command
        from cyber_sentry_cli.core.run_state import RunStateManager

        scan_command(target, "auto")

        # Refresh session context to keep /findings and /triage pinned to this scan.
        try:
            state = RunStateManager(config)
            runs = state.list_runs()
            if runs:
                run = state.load_run(runs[0])
                session.current_run_id = run.id
                session.findings = run.findings
                print_info(f"Using run: [cyan]{run.id}[/cyan]")
        except Exception:
            # Non-fatal; scan output already printed.
            pass

    elif command == "/findings":
        from cyber_sentry_cli.core.run_state import RunStateManager
        state = RunStateManager(config)
        run_id = session.current_run_id
        if not run_id:
            runs = state.list_runs()
            run_id = runs[0] if runs else None

        if run_id:
            run = state.load_run(run_id)
            session.current_run_id = run.id
            session.findings = run.findings
            from cyber_sentry_cli.output.terminal import print_findings_table
            print_findings_table(run.findings)
        else:
            print_info("No scan runs found. Run [cyan]/scan <target>[/cyan] first.")

    elif command == "/triage":
        from cyber_sentry_cli.commands.triage import triage_command
        run_id = session.current_run_id or "latest"
        triage_command(run_id)

    elif command == "/debate":
        if not arg:
            print_info("Usage: [cyan]/debate <finding-id> [--run <run-id>][/cyan]")
            return

        parts = shlex.split(arg)
        finding_id = ""
        run_id = session.current_run_id or "latest"

        idx = 0
        while idx < len(parts):
            part = parts[idx]
            if part == "--run" and idx + 1 < len(parts):
                run_id = parts[idx + 1]
                idx += 1
            elif not part.startswith("--") and not finding_id:
                finding_id = part
            idx += 1

        if not finding_id:
            print_error("Finding ID is required.")
            print_info("Usage: [cyan]/debate <finding-id> [--run <run-id>][/cyan]")
            return

        from cyber_sentry_cli.commands.debate import debate_command
        debate_command(finding_id=finding_id, run_id=run_id)

    elif command == "/patch":
        if not arg:
            print_info("Usage: [cyan]/patch <finding-id> [--dry-run|--apply] [--run <run-id>][/cyan]")
            return

        parts = shlex.split(arg)
        normalized_parts: list[str] = []
        for part in parts:
            if "--" in part and not part.startswith("--"):
                token, suffix = part.split("--", 1)
                if token:
                    normalized_parts.append(token)
                if suffix:
                    normalized_parts.append(f"--{suffix}")
            else:
                normalized_parts.append(part)

        parts = normalized_parts

        finding_id = ""
        use_apply = False
        run_id = session.current_run_id or "latest"

        idx = 0
        while idx < len(parts):
            part = parts[idx]
            if part == "--apply":
                use_apply = True
            elif part == "--dry-run":
                use_apply = False
            elif part == "--run" and idx + 1 < len(parts):
                run_id = parts[idx + 1]
                idx += 1
            elif not part.startswith("--") and not finding_id:
                finding_id = part
            idx += 1

        if not finding_id:
            print_error("Finding ID is required.")
            print_info("Usage: [cyan]/patch <finding-id> [--dry-run|--apply] [--run <run-id>][/cyan]")
            return

        from cyber_sentry_cli.commands.patch import patch_command
        patch_command(finding_id=finding_id, run_id=run_id, dry_run=not use_apply)

    elif command in ("/exit", "/quit"):
        _print_goodbye()
        raise SystemExit(0)

    else:
        print_warning(f"Unknown command: {command}")
        print_info("Type [cyan]/help[/cyan] for available commands.")


def _display_response(response: str, config: Config) -> None:
    """Display an LLM response with markdown rendering."""
    console.print()
    console.print(Markdown(response))

    tool_calls = parse_tool_calls(response)
    for tool_name, tool_args in tool_calls:
        approved = _show_tool_call(tool_name, tool_args)
        if approved:
            result = execute_tool(tool_name, tool_args, config)
            console.print(Panel(
                Text(result[:1000], style="dim"),
                title="[bold]📋 Result[/]",
                border_style="grey37",
            ))
