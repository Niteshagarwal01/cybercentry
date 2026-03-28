// Side Panel uses the same logic as the old popup.
// This file is intentionally kept separate so Chrome loads it as the panel UI.

// DOM
const badgeEl = document.getElementById("badge");
const siteEl = document.getElementById("site");
const statusEl = document.getElementById("status");
const findingsEl = document.getElementById("findings");
const authToggleEl = document.getElementById("authToggle");
const scanBtn = document.getElementById("scanBtn");
const detailsBtn = document.getElementById("detailsBtn");
const remBtn = document.getElementById("remBtn");
const reportBtn = document.getElementById("reportBtn");
const remediationBtn = document.getElementById("remediationBtn");
const artifactEl = document.getElementById("artifact");
const fixPlanEl = document.getElementById("fixPlan");
const pagesScannedEl = document.getElementById("pagesScanned");
const findingCountEl = document.getElementById("findingCount");

let lastRunId = null;
let lastUrl = "";
let lastFindings = [];

function setBadge(kind, text) {
  badgeEl.className = `badge badge--${kind}`;
  badgeEl.textContent = text;
}

function setStatus(kind, text) {
  statusEl.className = `status${kind ? " " + kind : ""}`;
  statusEl.textContent = text || "";
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}

function riskFrom(totalFindings) {
  if (totalFindings <= 0) return { kind: "ok", label: "OK" };
  if (totalFindings <= 3) return { kind: "warn", label: "Caution" };
  return { kind: "risk", label: "Risk" };
}

function setTab(name) {
  document.querySelectorAll(".tab").forEach((t) => {
    const active = t.dataset.tab === name;
    t.classList.toggle("active", active);
    t.setAttribute("aria-selected", active ? "true" : "false");
  });
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
  const panel = document.getElementById(`tab-${name}`);
  if (panel) panel.classList.add("active");
}

async function send(msg) {
  return await chrome.runtime.sendMessage(msg);
}

async function loadContext() {
  const ctx = await send({ type: "CS_GET_CONTEXT" });
  if (!ctx?.ok) {
    setBadge("risk", "Error");
    siteEl.textContent = "—";
    setStatus("bad", "Could not read active tab.");
    scanBtn.disabled = true;
    return;
  }

  lastUrl = ctx.url || "";
  siteEl.textContent = lastUrl || "—";
  if (!ctx.canScan) {
    setBadge("idle", "Unsupported");
    setStatus("", "Open an http/https website to scan.");
    scanBtn.disabled = true;
    return;
  }

  setBadge("idle", "Ready");
  setStatus("", "");
  scanBtn.disabled = false;
}

async function loadAuthState() {
  const { csAuthorized } = await chrome.storage.local.get(["csAuthorized"]);
  authToggleEl.checked = Boolean(csAuthorized);
}

function renderFindings(findings) {
  if (!Array.isArray(findings) || findings.length === 0) {
    findingsEl.className = "findings empty";
    findingsEl.textContent = "No vulnerabilities found in this quick scan scope.";
    return;
  }

  const top = findings.slice(0, 12);
  findingsEl.className = "findings";
  findingsEl.innerHTML = top
    .map((f) => {
      const sev = escapeHtml(f.severity || "INFO");
      const rid = escapeHtml(f.rule_id || "—");
      const title = escapeHtml(f.title || "Finding");
      const desc = escapeHtml(f.description || "");
      const target = escapeHtml(f.file_path || "");
      const meta = target ? `Target: ${target}` : "";
      return `
        <div class="finding">
          <details>
            <summary>
              <div class="finding-top">
                <div class="sev sev--${sev}">${sev}</div>
                <div class="fid">${rid}</div>
              </div>
              <div class="ftitle">${title}</div>
              ${meta ? `<div class="fmeta">${meta}</div>` : ""}
            </summary>
            ${desc ? `<div class="fdesc">${desc}</div>` : `<div class="fdesc">No description provided.</div>`}
          </details>
        </div>
      `;
    })
    .join("");
}

function guidanceFor(ruleId) {
  const map = {
    "WS001:insecure-transport": "Enforce HTTPS-only traffic and redirect all HTTP requests to HTTPS. Enable HSTS after validating subdomains.",
    "WS002:missing-hsts": "Add Strict-Transport-Security with a long max-age and includeSubDomains when safe.",
    "WS003:missing-csp": "Add Content-Security-Policy to restrict scripts/styles/frames. Start with report-only to reduce breakage.",
    "WS004:missing-xfo": "Set X-Frame-Options DENY or SAMEORIGIN (or use CSP frame-ancestors).",
    "WS005:missing-xcto": "Set X-Content-Type-Options: nosniff.",
    "WS006:missing-referrer-policy": "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    "WS007:verbose-server-banner": "Remove or minimize Server header/version disclosure.",
    "WS008:cookie-no-httponly": "Mark auth/session cookies as HttpOnly to prevent script access.",
    "WS009:cookie-no-secure": "Mark auth/session cookies as Secure so they’re only sent over HTTPS.",
    "WS010:cookie-no-samesite": "Set SameSite=Lax/Strict on auth cookies to reduce CSRF exposure.",
    "WS011:insecure-form-action": "Ensure POST forms submit to HTTPS endpoints only; avoid HTTP action URLs."
  };
  return map[ruleId] || "Review server/app configuration and apply secure defaults for this finding.";
}

function renderFixPlan(findings) {
  if (!Array.isArray(findings) || findings.length === 0) {
    fixPlanEl.className = "fix empty";
    fixPlanEl.textContent = "No fixes needed for this quick scan scope.";
    return;
  }

  const unique = new Map();
  for (const f of findings) {
    const rid = f.rule_id || "UNKNOWN";
    if (!unique.has(rid)) unique.set(rid, f);
  }

  fixPlanEl.className = "fix";
  fixPlanEl.innerHTML =
    `<div class="fix-list">` +
    Array.from(unique.entries())
      .map(([rid, f]) => {
        const title = escapeHtml(f.title || "Finding");
        const why = escapeHtml(f.description || "Security hardening issue detected.");
        const fix = escapeHtml(guidanceFor(rid));
        return `
          <div class="fix-item">
            <div class="fix-head">
              <div class="fix-title">${title}</div>
              <div class="fix-rule">${escapeHtml(rid)}</div>
            </div>
            <div class="fix-body">
              <div><span style="color: rgba(255,255,255,0.62)">Why:</span> ${why}</div>
              <div style="margin-top:6px"><span style="color: rgba(255,255,255,0.62)">Fix:</span> ${fix}</div>
            </div>
          </div>
        `;
      })
      .join("") +
    `</div>`;
}

async function loadArtifactDirect(kind) {
  if (!lastRunId) return;
  artifactEl.className = "artifact";
  artifactEl.textContent = `Loading ${kind.toUpperCase()}…`;
  try {
    const endpoint = `http://127.0.0.1:8081/api/runs/${encodeURIComponent(lastRunId)}/${kind}`;
    const resp = await fetch(endpoint);
    const data = await resp.json().catch(async () => ({ detail: await resp.text() }));
    if (!resp.ok) throw new Error(data.detail || `Server returned ${resp.status}`);
    artifactEl.textContent = data.content || "(Empty artifact)";
  } catch (e) {
    artifactEl.className = "artifact empty";
    artifactEl.textContent = String(e?.message || e);
  }
}

async function runQuickScan() {
  setBadge("idle", "Scanning");
  setStatus("", "Running quick scan on local backend…");
  scanBtn.disabled = true;
  detailsBtn.disabled = true;
  remBtn.disabled = true;
  reportBtn.disabled = true;
  remediationBtn.disabled = true;

  lastRunId = null;
  lastFindings = [];
  pagesScannedEl.textContent = "—";
  findingCountEl.textContent = "—";
  artifactEl.className = "artifact empty";
  artifactEl.textContent = "Running scan…";
  fixPlanEl.className = "fix empty";
  fixPlanEl.textContent = "Running scan…";

  const resp = await send({ type: "CS_WEBSCAN_LITE", url: lastUrl });
  if (!resp?.ok) {
    setBadge("risk", "Error");
    setStatus("bad", resp?.error || "Scan failed.");
    scanBtn.disabled = false;
    return;
  }

  const data = resp.data;
  lastRunId = data.run_id;
  pagesScannedEl.textContent = String(data.pages_scanned ?? "0");
  findingCountEl.textContent = String(data.total_findings ?? "0");

  const { kind, label } = riskFrom(Number(data.total_findings || 0));
  setBadge(kind, label);
  setStatus("good", `Done. Pages: ${data.pages_scanned ?? 0}. Findings: ${data.total_findings ?? 0}.`);

  const fResp = await send({ type: "CS_GET_FINDINGS", runId: lastRunId });
  if (!fResp?.ok) {
    renderFindings([]);
    fixPlanEl.className = "fix empty";
    fixPlanEl.textContent = "Could not load findings.";
    setStatus("bad", `Scan ok, but could not load findings: ${fResp?.error || "unknown error"}`);
  } else {
    lastFindings = Array.isArray(fResp.data) ? fResp.data : [];
    renderFindings(lastFindings);
    renderFixPlan(lastFindings);
  }

  detailsBtn.disabled = false;
  remBtn.disabled = false;
  reportBtn.disabled = false;
  remediationBtn.disabled = false;

  await loadArtifactDirect("report");
  setTab("summary");
  scanBtn.disabled = false;
}

authToggleEl.addEventListener("change", async () => {
  await chrome.storage.local.set({ csAuthorized: authToggleEl.checked });
});

scanBtn.addEventListener("click", runQuickScan);

detailsBtn.addEventListener("click", async () => {
  if (!lastRunId) return;
  const url = `http://127.0.0.1:8081/api/runs/${encodeURIComponent(lastRunId)}`;
  await chrome.tabs.create({ url });
});

remBtn.addEventListener("click", async () => setTab("fix"));
reportBtn.addEventListener("click", async () => loadArtifactDirect("report"));
remediationBtn.addEventListener("click", async () => loadArtifactDirect("remediation"));

(document.querySelectorAll(".tab") || []).forEach((t) => {
  t.addEventListener("click", () => setTab(t.dataset.tab));
});

(async () => {
  await loadAuthState();
  await loadContext();
})();

