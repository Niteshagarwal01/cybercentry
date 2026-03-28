# pyre-unsafe
"""Event emitter for the thought trace timeline."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cyber_sentry_cli.core.models import AgentRole, Event, EventType

console = Console()

# In-memory event store for the current run
_events: list[Event] = []
_current_run_id: str = ""


def emit(
    event_type: EventType,
    content: str,
    run_id: str = "",
    agent_role: Optional[AgentRole] = None,
    metadata: Optional[dict[str, Any]] = None,
    silent: bool = False,
) -> Event:
    """Create and store an event, optionally printing it to the terminal."""
    effective_run_id = run_id or _current_run_id
    event = Event(
        run_id=effective_run_id,
        event_type=event_type,
        agent_role=agent_role,
        content=content,
        metadata=metadata or {},
    )
    _events.append(event)

    if not silent:
        _print_event(event)

    return event


def get_events(run_id: str = "") -> list[Event]:
    """Get all events, optionally filtered by run ID."""
    if run_id:
        return [e for e in _events if e.run_id == run_id]
    return list(_events)


def clear_events() -> None:
    """Clear the in-memory event store."""
    _events.clear()


@contextmanager
def scoped_run(run_id: str) -> Iterator[None]:
    """Context manager that sets the current run ID and clears stale events on entry."""
    global _current_run_id  # noqa: PLW0603
    previous = _current_run_id
    clear_events()
    _current_run_id = run_id
    try:
        yield
    finally:
        _current_run_id = previous


def events_to_dicts(run_id: str = "") -> list[dict[str, Any]]:
    """Serialize events to dicts for JSON export."""
    return [e.model_dump(mode="json") for e in get_events(run_id)]


# ---------------------------------------------------------------------------
# Terminal display
# ---------------------------------------------------------------------------

_STYLE_MAP: dict[EventType, tuple[str, str]] = {
    EventType.THINK:              ("💭", "cyan"),
    EventType.ACT:                ("⚡", "yellow"),
    EventType.OBSERVE:            ("👁️ ", "green"),
    EventType.PIVOT:              ("🔄", "magenta"),
    EventType.TOOL_CALL:          ("🔧", "yellow"),
    EventType.TOOL_RESULT:        ("📋", "green"),
    EventType.DEBATE_START:       ("🤝", "blue bold"),
    EventType.DEBATE_ROUND:       ("💬", "blue"),
    EventType.JUDGE_SCORE:        ("⚖️ ", "cyan bold"),
    EventType.PATCH_GENERATED:    ("🩹", "green bold"),
    EventType.APPROVAL_REQUESTED: ("🙋", "yellow bold"),
    EventType.ERROR:              ("❌", "red bold"),
    EventType.INFO:               ("ℹ️ ", "dim"),
}


def _print_event(event: Event) -> None:
    # Feed into live dashboard if one is active
    try:
        from cyber_sentry_cli.output.dashboard import get_active_dashboard
        dash = get_active_dashboard()
        if dash is not None:
            role = event.agent_role.value if event.agent_role else ""
            dash.add_event(event.event_type.value, event.content, agent_role=role)
            return  # dashboard handles rendering; skip duplicate console print
    except ImportError:
        pass

    # Fallback: plain terminal output when no dashboard is running
    icon, style = _STYLE_MAP.get(event.event_type, ("•", "white"))
    role_tag = f" [{event.agent_role.value}]" if event.agent_role else ""
    header = f"{icon} {event.event_type.value}{role_tag}"

    if event.event_type in (EventType.THINK, EventType.DEBATE_ROUND, EventType.JUDGE_SCORE):
        console.print(Panel(
            Text(event.content),
            title=header,
            border_style=style,
            padding=(0, 1),
        ))
    else:
        console.print(f"  [{style}]{header}[/{style}]  {event.content}")
