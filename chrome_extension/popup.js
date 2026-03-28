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
let lastSummary = null;
let activeArtifactKind = "report"; // report | remediation

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

  const top = findings.slice(0, 8);
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
    "WS002:missing-hsts": "Add Strict-Transport-Security with a long max-age (e.g., 15552000+) and includeSubDomains when safe.",
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
  const lines = [];
  lines.push("Fix plan (quick scan):");
  lines.push("");
  const unique = new Map();
  for (const f of findings) {
    const rid = f.rule_id || "UNKNOWN";
    if (!unique.has(rid)) unique.set(rid, f);
  }
  let idx = 1;
  for (const [rid, f] of unique.entries()) {
    lines.push(`${idx}. ${rid} — ${f.title || "Finding"}`);
    lines.push(`   - Why: ${f.description || "Security hardening issue detected."}`);
    lines.push(`   - Fix: ${guidanceFor(rid)}`);
    lines.push("");
    idx += 1;
  }
  fixPlanEl.className = "fix";
  fixPlanEl.textContent = lines.join("\n");
}

async function loadArtifact(kind) {
  if (!lastRunId) return;
  activeArtifactKind = kind;
  artifactEl.className = "artifact";
  artifactEl.textContent = `Loading ${kind.toUpperCase()}…`;
  const resp = await send({ type: "CS_GET_ARTIFACT", runId: lastRunId, kind });
  if (!resp?.ok) {
    artifactEl.className = "artifact empty";
    artifactEl.textContent = resp?.error || "Failed to load artifact.";
    return;
  }
  const content = resp.data?.content || "";
  artifactEl.className = "artifact";
  artifactEl.textContent = content || "(Empty artifact)";
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
  lastSummary = null;
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
  lastSummary = data;
  pagesScannedEl.textContent = String(data.pages_scanned ?? "0");
  findingCountEl.textContent = String(data.total_findings ?? "0");

  const { kind, label } = riskFrom(Number(data.total_findings || 0));
  setBadge(kind, label);
  setStatus("good", `Done. Pages scanned: ${data.pages_scanned ?? 0}. Findings: ${data.total_findings ?? 0}.`);

  const fResp = await send({ type: "CS_GET_FINDINGS", runId: lastRunId });
  if (!fResp?.ok) {
    renderFindings([]);
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
  await loadArtifact("report");
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

(document.querySelectorAll(".tab") || []).forEach((t) => {
  t.addEventListener("click", () => setTab(t.dataset.tab));
});

remBtn.addEventListener("click", async () => {
  setTab("fix");
});

reportBtn.addEventListener("click", async () => loadArtifact("report"));
remediationBtn.addEventListener("click", async () => loadArtifact("remediation"));

(async () => {
  await loadAuthState();
  await loadContext();
})();

