# pyre-unsafe
"""FastAPI app for CyberSentry web UI and API."""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from cyber_sentry_cli.commands.report import report_command
from cyber_sentry_cli.commands.webscan import _build_web_remediation_markdown
from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.events import emit, scoped_run
from cyber_sentry_cli.core.models import EventType
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.web.website_scanner import WebScanConfig, scan_website

app = FastAPI(title="CyberSentry API", version="0.1.0")


class WebScanRequest(BaseModel):
    url: str = Field(..., description="http/https URL to scan")
    i_own_this_target: bool = Field(False, description="Must be true to run scan")
    max_pages: int = Field(30, ge=1, le=500)
    max_depth: int = Field(2, ge=0, le=10)
    timeout: float = Field(8.0, ge=1.0, le=60.0)
    rate_limit_ms: int = Field(150, ge=0, le=5000)


  class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    run_id: str | None = Field(default=None, description="Optional run_id for contextual chat answers")


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="URL must include http/https scheme and hostname")


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/api/webscan")
def api_webscan(payload: WebScanRequest) -> dict:
    _validate_url(payload.url)
    if not payload.i_own_this_target:
        raise HTTPException(status_code=400, detail="Authorization acknowledgement is required")

    cfg = Config()
    if not cfg.is_initialized:
        cfg.initialize()

    state = RunStateManager(cfg)
    run = state.create_run(target=payload.url)

    with scoped_run(run.id):
        emit(EventType.INFO, f"Starting authorized website scan: {payload.url}", run_id=run.id)

        def _progress(status: str, pages: int) -> None:
            emit(EventType.OBSERVE, f"{status} (pages={pages})", run_id=run.id, silent=True)

        result = scan_website(
            payload.url,
            WebScanConfig(
                max_pages=payload.max_pages,
                max_depth=payload.max_depth,
                timeout_seconds=payload.timeout,
                rate_limit_ms=payload.rate_limit_ms,
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
                "target": payload.url,
                "pages_scanned": result.pages_scanned,
                "visited_urls": result.visited_urls,
                "max_pages": payload.max_pages,
                "max_depth": payload.max_depth,
                "timeout": payload.timeout,
                "rate_limit_ms": payload.rate_limit_ms,
            },
        )

        from cyber_sentry_cli.core.events import events_to_dicts

        state.save_artifact(run.id, "events", events_to_dicts(run.id))

    run_dir = state.get_run_dir(run.id)
    remediation_path = run_dir / "WEB_REMEDIATION.md"
    remediation_path.write_text(_build_web_remediation_markdown(run.id, run.findings), encoding="utf-8")

    report_command(run.id, fmt="md", output="", show_terminal=False)

    return {
        "run_id": run.id,
        "total_findings": run.total_findings,
        "pages_scanned": result.pages_scanned,
        "report_path": str(run_dir / "REPORT.md"),
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


  @app.post("/api/chat")
  def api_chat(payload: ChatRequest) -> dict:
    cfg = Config()
    if not cfg.is_initialized:
      cfg.initialize()

    from cyber_sentry_cli.integrations.openrouter import OpenRouterClient

    llm = OpenRouterClient(cfg)
    if not llm.is_configured():
      raise HTTPException(
        status_code=400,
        detail="Chat backend is not configured. Set local LLM/OpenRouter settings first.",
      )

    run_context = ""
    if payload.run_id:
      state = RunStateManager(cfg)
      try:
        run = state.load_run(payload.run_id)
        run_context = (
          f"\nContext run_id={run.id}; target={run.target}; "
          f"total_findings={run.total_findings}; scanners={','.join(run.scanners_used)}"
        )
      except FileNotFoundError:
        run_context = f"\nContext run_id={payload.run_id} (not found on disk)."

    messages = [
      {
        "role": "system",
        "content": (
          "You are CyberSentry web assistant. Be concise, technical, and security-focused. "
          "If asked for remediation, provide specific actionable steps."
          + run_context
        ),
      },
      {"role": "user", "content": payload.message},
    ]

    try:
      response = llm.chat(messages, temperature=0.25)
    except Exception as exc:
      raise HTTPException(status_code=502, detail=f"Chat request failed: {exc}")

    return {"reply": response, "model": cfg.chat_model}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """
<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
  <title>CyberSentry Mission Console</title>
  <style>
    :root {
      --line:#203252;
      --text:#d8e8ff;
      --muted:#88a1c7;
      --lime:#b8ff2c;
      --blue:#2aa8ff;
      --cyan:#53ffd2;
      --good:#43d670;
      --bad:#ff5470;
      --bg:#04080f;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--text);
      background:
        radial-gradient(circle at 10% 12%, rgba(42,168,255,0.20), transparent 35%),
        radial-gradient(circle at 82% 18%, rgba(184,255,44,0.14), transparent 38%),
        radial-gradient(circle at 50% 80%, rgba(255,0,120,0.10), transparent 45%),
        linear-gradient(165deg, #03070f 0%, #061021 44%, #03070f 100%);
      font-family: \"Segoe UI\", \"Helvetica Neue\", Arial, sans-serif;
      min-height: 100vh;
    }
    body::before {
      content: \"\";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(83,255,210,0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(83,255,210,0.05) 1px, transparent 1px);
      background-size: 36px 36px;
      opacity: 0.22;
    }
    .wrap { max-width: 1280px; margin: 22px auto 48px; padding: 0 16px; position: relative; z-index: 1; }
    .topbar {
      display: flex; align-items: center; justify-content: space-between;
      border: 1px solid var(--line); border-radius: 12px; padding: 10px 14px;
      background: linear-gradient(90deg, rgba(10,20,38,.95), rgba(8,14,26,.95)); margin-bottom: 10px;
    }
    .brand { font-size: 20px; font-weight: 900; letter-spacing: .05em; text-transform: uppercase; }
    .brand .x { color: var(--lime); text-shadow: 0 0 16px rgba(184,255,44,.55); }
    .nav { display: flex; gap: 14px; color: var(--muted); font-size: 11px; letter-spacing: .12em; text-transform: uppercase; }

    .hero {
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 20px;
      background: linear-gradient(145deg, rgba(11,19,34,0.95), rgba(8,18,36,0.88));
      box-shadow: 0 0 0 1px rgba(42,168,255,0.20), 0 22px 60px rgba(0,0,0,0.35);
      overflow: hidden;
      position: relative;
    }
    .hero::after {
      content: \"\";
      position: absolute;
      width: 360px;
      height: 360px;
      right: -90px;
      top: -90px;
      background: radial-gradient(circle, rgba(184,255,44,0.20), transparent 72%);
      filter: blur(8px);
    }
    .kicker { color: var(--cyan); letter-spacing: .16em; font-size: 12px; font-weight: 700; text-transform: uppercase; }
    h1 { margin: 8px 0 0; font-size: clamp(24px, 3vw, 36px); text-transform: uppercase; letter-spacing: .06em; }
    .mega {
      margin-top: 12px;
      font-size: clamp(40px, 9vw, 116px);
      line-height: .9;
      font-weight: 900;
      letter-spacing: .02em;
      text-transform: uppercase;
      color: #eef5ff;
      text-shadow: 0 0 28px rgba(42,168,255,0.28);
    }
    .mega .neon { color: var(--lime); text-shadow: 0 0 28px rgba(184,255,44,.42); }
    .subtitle { margin: 10px 0 0; color: var(--muted); max-width: 920px; line-height: 1.5; }
    .metrics { margin-top: 16px; display: grid; grid-template-columns: repeat(4, minmax(130px, 1fr)); gap: 10px; }
    .metric {
      border: 1px solid var(--line); border-radius: 12px; padding: 10px;
      background: linear-gradient(180deg, rgba(16,29,51,0.85), rgba(11,19,34,0.9));
    }
    .metric .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
    .metric .value { margin-top: 6px; font-size: 20px; font-weight: 700; }

    .grid { margin-top: 16px; display: grid; grid-template-columns: 2.1fr 1fr; gap: 14px; }
    .card {
      border: 1px solid var(--line); border-radius: 14px; padding: 16px;
      background: linear-gradient(145deg, rgba(11,19,34,0.94), rgba(10,16,30,0.9));
      box-shadow: inset 0 0 30px rgba(42,168,255,0.06);
    }
    .card h2 { margin: 0 0 8px; font-size: 16px; text-transform: uppercase; letter-spacing: .06em; color: var(--blue); }
    .muted { color: var(--muted); }
    .input { width: 100%; margin-top: 6px; padding: 11px; background: #071120; border: 1px solid #27406a; border-radius: 10px; color: var(--text); }
    .row { display:grid; grid-template-columns: repeat(4,1fr); gap:10px; margin-top:12px; }
    .btn {
      margin-top: 12px; padding: 11px 14px; border: 1px solid rgba(42,168,255,0.55); border-radius: 10px;
      background: linear-gradient(90deg, rgba(42,168,255,0.2), rgba(184,255,44,0.24)); color: #eaf6ff;
      cursor: pointer; font-weight: 700; text-transform: uppercase; letter-spacing: .06em;
    }
    .status { margin-top: 12px; color: var(--muted); min-height: 20px; }
    .good { color: var(--good); }
    .bad { color: var(--bad); }

    .artifact-actions { display:flex; gap:8px; flex-wrap: wrap; margin-top: 10px; }
    .btn-small {
      padding: 8px 10px; border: 1px solid #2c4f7c; border-radius: 8px;
      background: #09182c; color: #cfe3ff; cursor: pointer; font-weight: 600;
    }
    .btn-small:hover { background: #0d2442; }
    .artifact-panel {
      margin-top: 10px; border: 1px solid #2a3f64; border-radius: 10px; background: #07121f; padding: 10px;
    }
    .artifact-panel pre {
      margin: 8px 0 0; max-height: 260px; overflow: auto; white-space: pre-wrap;
      font-family: Consolas, \"Courier New\", monospace; font-size: 12px; line-height: 1.35; color: #dbe9ff;
    }

    .chatbox {
      margin-top: 14px;
      border: 1px solid #294770;
      border-radius: 10px;
      background: #061223;
      padding: 10px;
    }
    .chatlog {
      max-height: 280px;
      overflow: auto;
      border: 1px solid #244061;
      border-radius: 8px;
      padding: 8px;
      background: #040d19;
      font-size: 13px;
      line-height: 1.45;
    }
    .msg { margin-bottom: 8px; }
    .msg-user { color: #b8ff2c; }
    .msg-bot { color: #9fd1ff; }
    .chatrow { display: grid; grid-template-columns: 1fr auto; gap: 8px; margin-top: 8px; }
    .chatbtn {
      padding: 10px 12px;
      border: 1px solid #2f5d8c;
      border-radius: 8px;
      background: #0a1f38;
      color: #e6f1ff;
      font-weight: 700;
      cursor: pointer;
      text-transform: uppercase;
      letter-spacing: .05em;
    }

    .project-list { margin: 8px 0 0; padding-left: 18px; color: var(--muted); line-height: 1.5; }
    .project-list li { margin-bottom: 6px; }
    .download {
      border: 1px solid rgba(184,255,44,0.3); background: linear-gradient(180deg, rgba(20,35,16,0.4), rgba(8,18,12,0.28));
      border-radius: 12px; padding: 10px; margin-top: 10px;
    }
    .download a { color: var(--lime); text-decoration: none; font-weight: 600; }
    .download a:hover { text-decoration: underline; }
    .code {
      margin-top: 8px; border: 1px solid #2f4d2f; background: #07150a; color: #ccfdb0;
      border-radius: 10px; padding: 8px; font-family: Consolas, \"Courier New\", monospace;
      font-size: 12px; white-space: pre-wrap; line-height: 1.4;
    }

    table { width:100%; border-collapse: collapse; margin-top:12px; font-size:13px; }
    th, td { border-bottom: 1px solid var(--line); padding:8px; text-align:left; vertical-align: top; }
    th { color: var(--blue); font-weight: 700; text-transform: uppercase; font-size: 11px; letter-spacing: .06em; }

    @media (max-width: 980px) {
      .grid { grid-template-columns: 1fr; }
      .metrics { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
      .nav { display: none; }
    }
    @media (max-width: 640px) {
      .row { grid-template-columns: repeat(2, 1fr); }
      .metrics { grid-template-columns: 1fr 1fr; }
    }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <div class=\"topbar\">
      <div class=\"brand\">Cyber<span class=\"x\">Sentry</span> // Mission Console</div>
      <div class=\"nav\"><span>problem</span><span>analysis</span><span>reasoning</span><span>remediation</span><span>reporting</span></div>
    </div>

    <section class=\"hero\">
      <div class=\"kicker\">Autonomous Security Engineering Platform</div>
      <h1>CyberSentry Mission Console</h1>
      <div class=\"mega\">Threat <span class=\"neon\">Hunt</span><br/>Control Grid</div>
      <p class=\"subtitle\">CyberSentry scans codebases and authorized website URLs, clusters risk, runs multi-agent remediation reasoning, and produces auditable reports and remediation plans.</p>
      <div class=\"metrics\">
        <div class=\"metric\"><div class=\"label\">Pipeline</div><div class=\"value\">Scan to Patch</div></div>
        <div class=\"metric\"><div class=\"label\">Modes</div><div class=\"value\">CLI + Web UI</div></div>
        <div class=\"metric\"><div class=\"label\">Output</div><div class=\"value\">JSON / MD / SARIF</div></div>
        <div class=\"metric\"><div class=\"label\">Guardrail</div><div class=\"value\">Human Approval</div></div>
      </div>
    </section>

    <section class=\"grid\">
      <div class=\"card\">
        <h2>Authorized URL Security Scan</h2>
        <p class=\"muted\">Run DAST-lite checks on websites you own or are explicitly authorized to test.</p>
        <input class=\"input\" id=\"url\" type=\"text\" placeholder=\"https://example.com\" />
        <div class=\"row\">
          <input class=\"input\" id=\"pages\" type=\"number\" value=\"30\" min=\"1\" max=\"500\" title=\"max pages\" />
          <input class=\"input\" id=\"depth\" type=\"number\" value=\"2\" min=\"0\" max=\"10\" title=\"crawl depth\" />
          <input class=\"input\" id=\"timeout\" type=\"number\" value=\"8\" min=\"1\" max=\"60\" title=\"timeout seconds\" />
          <input class=\"input\" id=\"rate\" type=\"number\" value=\"150\" min=\"0\" max=\"5000\" title=\"rate limit ms\" />
        </div>
        <label class=\"muted\"><input id=\"ack\" type=\"checkbox\" /> I own this target or have explicit permission to test it.</label><br/>
        <button class=\"btn\" onclick=\"runScan()\">Run Security Scan</button>

        <div id=\"status\" class=\"status\"></div>
        <div id=\"scanSummary\" class=\"muted\" style=\"margin-top:6px;\"></div>
        <div class=\"artifact-actions\" id=\"artifactActions\" style=\"display:none;\">
          <button class=\"btn-small\" onclick=\"loadReport()\">Open REPORT.md</button>
          <button class=\"btn-small\" onclick=\"loadRemediation()\">Open WEB_REMEDIATION.md</button>
        </div>
        <div id=\"artifactPanel\" class=\"artifact-panel\" style=\"display:none;\">
          <div id=\"artifactTitle\" class=\"kicker\" style=\"margin:0;\">artifact</div>
          <pre id=\"artifactContent\"></pre>
        </div>
        <div id=\"results\"></div>

        <div class=\"chatbox\">
          <h2 style=\"margin-bottom:4px;\">Cyber Chat (Web)</h2>
          <p class=\"muted\">Ask security questions, request remediation guidance, or reference a run ID for context.</p>
          <div id=\"chatLog\" class=\"chatlog\"></div>
          <div class=\"chatrow\">
            <input class=\"input\" id=\"chatInput\" type=\"text\" placeholder=\"Explain this finding and suggest patch strategy...\" />
            <button class=\"chatbtn\" onclick=\"sendChat()\">Send</button>
          </div>
        </div>
      </div>

      <aside class=\"card\">
        <h2>About This Project</h2>
        <ul class=\"project-list\">
          <li>Autonomous security investigation and remediation workflow.</li>
          <li>Root-cause triage and severity-driven prioritization.</li>
          <li>Multi-agent debate: Red Team, Blue Team, Auditor, Judge.</li>
          <li>Patch candidate generation with human-in-the-loop approval.</li>
          <li>Audit-ready artifacts and thought-trace reporting.</li>
        </ul>

        <div class=\"download\" style=\"margin-top:12px;\">
          <div class=\"kicker\" style=\"color:var(--cyan); margin-bottom:4px;\">Website Access</div>
          <div class=\"muted\">Start local web dashboard:</div>
          <div class=\"code\">cs ui --host 127.0.0.1 --port 8080\n# if 8080 is busy use 8081\ncs ui --host 127.0.0.1 --port 8081\n# then open in browser\nhttp://127.0.0.1:8081</div>
        </div>

        <div class=\"download\">
          <div class=\"kicker\" style=\"color:var(--lime); margin-bottom:4px;\">CLI Interface Download</div>
          <div class=\"muted\">Source repository:</div>
          <a href=\"https://github.com/Niteshagarwal01/cybercentry\" target=\"_blank\" rel=\"noopener noreferrer\">github.com/Niteshagarwal01/cybercentry</a>
          <div class=\"code\">git clone https://github.com/Niteshagarwal01/cybercentry.git\ncd cyber_sentry\npip install -e .\ncs --help\ncs webscan https://example.com --i-own-this-target</div>
        </div>

        <div class=\"download\" style=\"margin-top:12px;\">
          <div class=\"kicker\" style=\"color:var(--blue); margin-bottom:4px;\">CLI + Chat Interface</div>
          <div class=\"muted\">CyberSentry chat and remediation pipeline:</div>
          <div class=\"code\">cs chat\ncs scan .\ncs triage latest\ncs debate <finding_id> --run latest\ncs patch <finding_id> --run latest --dry-run\ncs trace latest\ncs report latest</div>
        </div>
      </aside>
    </section>
  </div>

  <script>
    let lastRunId = '';

    function appendChat(role, text) {
      const log = document.getElementById('chatLog');
      const line = document.createElement('div');
      line.className = 'msg ' + (role === 'user' ? 'msg-user' : 'msg-bot');
      line.textContent = (role === 'user' ? 'You: ' : 'CyberSentry: ') + text;
      log.appendChild(line);
      log.scrollTop = log.scrollHeight;
    }

    async function runScan() {
      const status = document.getElementById('status');
      const scanSummary = document.getElementById('scanSummary');
      const results = document.getElementById('results');
      const artifactActions = document.getElementById('artifactActions');
      const artifactPanel = document.getElementById('artifactPanel');

      status.textContent = 'Running scan...';
      scanSummary.textContent = '';
      results.innerHTML = '';
      artifactActions.style.display = 'none';
      artifactPanel.style.display = 'none';

      const payload = {
        url: document.getElementById('url').value,
        i_own_this_target: document.getElementById('ack').checked,
        max_pages: Number(document.getElementById('pages').value),
        max_depth: Number(document.getElementById('depth').value),
        timeout: Number(document.getElementById('timeout').value),
        rate_limit_ms: Number(document.getElementById('rate').value),
      };

      try {
        const resp = await fetch('/api/webscan', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!resp.ok) {
          status.innerHTML = '<span class="bad">Error: ' + (data.detail || 'Unknown error') + '</span>';
          return;
        }

        lastRunId = data.run_id;
        status.innerHTML = '<span class="good">Mission complete.</span> Run ' + data.run_id + ' | pages=' + data.pages_scanned + ' | findings=' + data.total_findings;
        artifactActions.style.display = 'flex';

        const sResp = await fetch('/api/runs/' + data.run_id + '/webscan-summary');
        if (sResp.ok) {
          const summary = await sResp.json();
          const visited = Array.isArray(summary.visited_urls) ? summary.visited_urls.slice(0, 5) : [];
          scanSummary.innerHTML =
            'Target: ' + (summary.target || '-') +
            ' | Pages scanned: ' + (summary.pages_scanned || 0) +
            (visited.length ? '<br/>Visited: ' + visited.join(' | ') : '');
        }

        const fResp = await fetch('/api/runs/' + data.run_id + '/findings');
        const findings = await fResp.json();
        if (!findings.length) {
          results.innerHTML = '<p class="good">Scan completed successfully. No findings were detected for this target within the scanned scope.</p>';
          return;
        }

        const rows = findings.map(f => '<tr><td>'+f.severity+'</td><td>'+f.rule_id+'</td><td>'+f.file_path+'</td><td>'+f.title+'</td></tr>').join('');
        results.innerHTML = '<table><thead><tr><th>Severity</th><th>Rule</th><th>Target</th><th>Issue</th></tr></thead><tbody>' + rows + '</tbody></table>';
      } catch (e) {
        status.innerHTML = '<span class="bad">Error: ' + e + '</span>';
      }
    }

    async function loadReport() {
      if (!lastRunId) return;
      const resp = await fetch('/api/runs/' + lastRunId + '/report');
      const data = await resp.json();
      if (!resp.ok) return;
      document.getElementById('artifactPanel').style.display = 'block';
      document.getElementById('artifactTitle').textContent = 'REPORT.md';
      document.getElementById('artifactContent').textContent = data.content;
    }

    async function loadRemediation() {
      if (!lastRunId) return;
      const resp = await fetch('/api/runs/' + lastRunId + '/remediation');
      const data = await resp.json();
      if (!resp.ok) return;
      document.getElementById('artifactPanel').style.display = 'block';
      document.getElementById('artifactTitle').textContent = 'WEB_REMEDIATION.md';
      document.getElementById('artifactContent').textContent = data.content;
    }

    async function sendChat() {
      const input = document.getElementById('chatInput');
      const raw = input.value || '';
      const message = raw.trim();
      if (!message) return;

      input.value = '';
      appendChat('user', message);
      appendChat('bot', 'Thinking...');

      const log = document.getElementById('chatLog');
      const thinkingNode = log.lastChild;

      try {
        const resp = await fetch('/api/chat', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ message, run_id: lastRunId || null }),
        });
        const data = await resp.json();
        if (!resp.ok) {
          thinkingNode.textContent = 'CyberSentry: Error - ' + (data.detail || 'chat failed');
          return;
        }
        thinkingNode.textContent = 'CyberSentry: ' + (data.reply || 'No response');
      } catch (e) {
        thinkingNode.textContent = 'CyberSentry: Error - ' + e;
      }
    }

    document.addEventListener('DOMContentLoaded', () => {
      appendChat('bot', 'Web chat ready. Ask about findings, remediation, or scanner setup.');
      const input = document.getElementById('chatInput');
      input.addEventListener('keydown', (evt) => {
        if (evt.key === 'Enter') {
          evt.preventDefault();
          sendChat();
        }
      });
    });
  </script>
</body>
</html>
"""
