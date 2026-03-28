# pyre-unsafe
"""FastAPI app for CyberSentry web UI and API."""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from cyber_sentry_cli.commands.webscan import _build_web_remediation_markdown
from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.events import emit, scoped_run
from cyber_sentry_cli.core.models import EventType
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.output.json_export import export_markdown
from cyber_sentry_cli.web.website_scanner import WebScanConfig, scan_website

app = FastAPI(title="CyberSentry API", version="0.1.0")

# Local-only UX: allow the Chrome extension (chrome-extension://...) and the local UI to call this API.
# We keep it permissive because this server is intended to be bound to localhost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class WebScanRequest(BaseModel):
    url: str = Field(..., description="http/https URL to scan")
    i_own_this_target: bool = Field(False, description="Must be true to run scan")
    max_pages: int = Field(30, ge=1, le=500)
    max_depth: int = Field(2, ge=0, le=10)
    timeout: float = Field(8.0, ge=1.0, le=60.0)
    rate_limit_ms: int = Field(150, ge=0, le=5000)

class WebScanLiteRequest(BaseModel):
    url: str = Field(..., description="http/https URL to scan")
    i_own_this_target: bool = Field(False, description="Must be true to run scan")


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="URL must include http/https scheme and hostname")


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/api/webscan")
def api_webscan(payload: WebScanRequest) -> dict:
    return _run_webscan(
        url=payload.url,
        i_own_this_target=payload.i_own_this_target,
        max_pages=payload.max_pages,
        max_depth=payload.max_depth,
        timeout=payload.timeout,
        rate_limit_ms=payload.rate_limit_ms,
    )


@app.post("/api/webscan-lite")
def api_webscan_lite(payload: WebScanLiteRequest) -> dict:
    """
    Fast, extension-friendly scan with conservative defaults.
    Intended for quick "is this risky?" signals, not full coverage.
    """
    return _run_webscan(
        url=payload.url,
        i_own_this_target=payload.i_own_this_target,
        max_pages=8,
        max_depth=1,
        timeout=6.0,
        rate_limit_ms=120,
    )


def _run_webscan(
    *,
    url: str,
    i_own_this_target: bool,
    max_pages: int,
    max_depth: int,
    timeout: float,
    rate_limit_ms: int,
) -> dict:
    _validate_url(url)
    if not i_own_this_target:
        raise HTTPException(status_code=400, detail="Authorization acknowledgement is required")

    cfg = Config()
    if not cfg.is_initialized:
        cfg.initialize()

    state = RunStateManager(cfg)
    run = state.create_run(target=url)

    with scoped_run(run.id):
        # Web API: avoid printing Rich output to the Windows console (can crash on cp1252 encoding).
        emit(EventType.INFO, f"Starting authorized website scan: {url}", run_id=run.id, silent=True)

        def _progress(status: str, pages: int) -> None:
            emit(EventType.OBSERVE, f"{status} (pages={pages})", run_id=run.id, silent=True)

        result = scan_website(
            url,
            WebScanConfig(
                max_pages=max_pages,
                max_depth=max_depth,
                timeout_seconds=timeout,
                rate_limit_ms=rate_limit_ms,
            ),
            progress=_progress,
        )

        run.findings = result.findings
        run.total_findings = len(result.findings)
        run.scanners_used = ["webscan"]

        for finding in run.findings[:25]:
            emit(
                EventType.OBSERVE,
                f"Finding: [{finding.severity.value}] {finding.rule_id} @ {finding.file_path}",
                run_id=run.id,
                silent=True,
            )

        state.complete_run(run)
        state.save_artifact(run.id, "findings", [f.model_dump(mode="json") for f in run.findings])
        state.save_artifact(
            run.id,
            "webscan_summary",
            {
                "target": url,
                "pages_scanned": result.pages_scanned,
                "visited_urls": result.visited_urls,
                "max_pages": max_pages,
                "max_depth": max_depth,
                "timeout": timeout,
                "rate_limit_ms": rate_limit_ms,
            },
        )

        from cyber_sentry_cli.core.events import events_to_dicts

        state.save_artifact(run.id, "events", events_to_dicts(run.id))

    run_dir = state.get_run_dir(run.id)
    remediation_path = run_dir / "WEB_REMEDIATION.md"
    remediation_path.write_text(_build_web_remediation_markdown(run.id, run.findings), encoding="utf-8")
    # Web API: generate REPORT.md without printing Rich output to the terminal.
    report_path = run_dir / "REPORT.md"
    report_path.write_text(export_markdown(run), encoding="utf-8")

    return {
        "run_id": run.id,
        "total_findings": run.total_findings,
        "pages_scanned": result.pages_scanned,
        "report_path": str(report_path),
        "remediation_path": str(remediation_path),
    }


@app.get("/api/runs/{run_id}")
def api_get_run(run_id: str) -> dict:
    cfg = Config()
    state = RunStateManager(cfg)
    try:
        run = state.load_run(run_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Run not found")
    return run.model_dump(mode="json")


@app.get("/api/runs/{run_id}/findings")
def api_get_findings(run_id: str) -> list[dict]:
    cfg = Config()
    state = RunStateManager(cfg)
    try:
        run = state.load_run(run_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Run not found")
    return [f.model_dump(mode="json") for f in run.findings]


@app.get("/api/runs/{run_id}/webscan-summary")
def api_get_webscan_summary(run_id: str) -> dict:
    cfg = Config()
    state = RunStateManager(cfg)
    try:
        summary = state.load_artifact(run_id, "webscan_summary")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Web scan summary not found")

    if not isinstance(summary, dict):
        raise HTTPException(status_code=500, detail="Web scan summary has invalid format")
    return summary


@app.get("/api/runs/{run_id}/report")
def api_get_report(run_id: str) -> dict:
    cfg = Config()
    state = RunStateManager(cfg)
    path = state.get_run_dir(run_id) / "REPORT.md"
    if not path.exists():
        raise HTTPException(status_code=404, detail="REPORT.md not found")
    return {"content": path.read_text(encoding="utf-8"), "path": str(path)}


@app.get("/api/runs/{run_id}/remediation")
def api_get_remediation(run_id: str) -> dict:
    cfg = Config()
    state = RunStateManager(cfg)
    path = state.get_run_dir(run_id) / "WEB_REMEDIATION.md"
    if not path.exists():
        raise HTTPException(status_code=404, detail="WEB_REMEDIATION.md not found")
    return {"content": path.read_text(encoding="utf-8"), "path": str(path)}


import json
from pathlib import Path
from fastapi.staticfiles import StaticFiles

# Mount static files
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")

class ChatRequest(BaseModel):
    message: str
    mode: str = "general"

@app.post("/api/chat")
def api_chat(payload: ChatRequest) -> dict:
    """
    Chat endpoint for both:
    - mode=general: security-only assistant
    - mode=autonomous: local agent-style assistant

    Uses ONLY local Ollama (no OpenRouter / no external APIs):
    - http://localhost:11434/api/tags (preflight)
    - http://localhost:11434/api/chat (chat)
    """
    import requests

    if payload.mode == "autonomous":
        system_prompt = (
            "You are CyberSentry, an autonomous Red Team AI Agent running locally on the user's filesystem. "
            "You help scan the current codebase, triage findings, debate remediations, and execute terminal commands. "
            "Be concise, direct, and assume full context of the repository."
        )
    else:
        system_prompt = (
            "You are a CyberSentry Security Assistant. You MUST ONLY answer questions strictly related to "
            "cybersecurity, application security, cryptography, hacking, IT infrastructure, and secure coding. "
            "If the user asks about ANYTHING else (e.g., cooking, general programming without security context, "
            "politics, general chat), you MUST politely decline and state that you are specialized only in cybersecurity. "
            "Use markdown formatting."
        )

    cfg = Config()
    if not cfg.is_initialized:
        cfg.initialize()

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": payload.message},
    ]

    try:
        # Preflight: Ollama up?
        try:
            tags_resp = requests.get("http://localhost:11434/api/tags", timeout=3)
            tags_resp.raise_for_status()
        except Exception as e:
            raise HTTPException(
                status_code=503,
                detail=f"Ollama is not reachable on localhost:11434. Start Ollama and retry. ({e})",
            )

        resp = requests.post(
            "http://localhost:11434/api/chat",
            json={"model": cfg.chat_model, "messages": messages, "stream": False},
            timeout=120,
        )

        if not resp.ok:
            # Ollama typically returns {"error":"..."} — surface it.
            try:
                err = resp.json()
                detail = err.get("error") if isinstance(err, dict) else err
            except Exception:
                detail = resp.text
            raise HTTPException(status_code=502, detail=f"Ollama error: {detail}")

        data = resp.json()
        reply = (data.get("message") or {}).get("content") or ""
        if not reply:
            raise HTTPException(status_code=502, detail="Ollama returned an empty reply.")
        return {"reply": reply}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/setup-status")
def setup_status() -> dict:
    from cyber_sentry_cli.core.config import Config
    cfg = Config()
    if not cfg.is_initialized:
        try:
            cfg.initialize()
        except:
            pass
    return {"is_setup": cfg.is_initialized}

@app.get("/", response_class=HTMLResponse)
def index() -> str:
    index_file = static_dir / "index.html"
    if not index_file.exists():
        return "<html><body><h1>UI build in progress...</h1></body></html>"
    return index_file.read_text(encoding="utf-8")
