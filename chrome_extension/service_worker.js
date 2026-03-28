const API_BASE = "http://127.0.0.1:8081";

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ csAuthorized: false });
  // Open Side Panel when user clicks the extension icon (Chrome Side Panel API).
  if (chrome.sidePanel?.setPanelBehavior) {
    chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
  }
});

// Fallback for environments where openPanelOnActionClick isn't honored:
// open the panel explicitly when the action icon is clicked.
chrome.action.onClicked.addListener(async (tab) => {
  try {
    if (chrome.sidePanel?.open && tab?.id != null) {
      await chrome.sidePanel.open({ tabId: tab.id });
    }
  } catch {}
});

async function activeTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

function isHttpUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg?.type === "CS_GET_CONTEXT") {
      const url = await activeTabUrl();
      sendResponse({ ok: true, url, canScan: isHttpUrl(url) });
      return;
    }

    if (msg?.type === "CS_WEBSCAN_LITE") {
      const url = msg.url || (await activeTabUrl());
      if (!isHttpUrl(url)) {
        sendResponse({ ok: false, error: "Open a normal http/https page to scan." });
        return;
      }
      const { csAuthorized } = await chrome.storage.local.get(["csAuthorized"]);
      if (!csAuthorized) {
        sendResponse({ ok: false, error: "Enable authorization toggle first." });
        return;
      }

      try {
        const resp = await fetch(`${API_BASE}/api/webscan-lite`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url, i_own_this_target: true })
        });
        const data = await resp.json().catch(async () => ({ detail: await resp.text() }));
        if (!resp.ok) {
          sendResponse({ ok: false, error: data.detail || `Server returned ${resp.status}` });
          return;
        }
        sendResponse({ ok: true, data });
      } catch (e) {
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
      return;
    }

    if (msg?.type === "CS_GET_FINDINGS") {
      const runId = msg.runId;
      if (!runId) {
        sendResponse({ ok: false, error: "Missing run id." });
        return;
      }
      try {
        const resp = await fetch(`${API_BASE}/api/runs/${encodeURIComponent(runId)}/findings`);
        const data = await resp.json().catch(async () => ({ detail: await resp.text() }));
        if (!resp.ok) {
          sendResponse({ ok: false, error: data.detail || `Server returned ${resp.status}` });
          return;
        }
        sendResponse({ ok: true, data });
      } catch (e) {
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
      return;
    }

    if (msg?.type === "CS_GET_ARTIFACT") {
      const runId = msg.runId;
      const kind = msg.kind; // "report" | "remediation"
      if (!runId) {
        sendResponse({ ok: false, error: "Missing run id." });
        return;
      }
      if (kind !== "report" && kind !== "remediation") {
        sendResponse({ ok: false, error: "Invalid artifact kind." });
        return;
      }
      try {
        const resp = await fetch(`${API_BASE}/api/runs/${encodeURIComponent(runId)}/${kind}`);
        const data = await resp.json().catch(async () => ({ detail: await resp.text() }));
        if (!resp.ok) {
          sendResponse({ ok: false, error: data.detail || `Server returned ${resp.status}` });
          return;
        }
        sendResponse({ ok: true, data });
      } catch (e) {
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
      return;
    }

    sendResponse({ ok: false, error: "Unknown message." });
  })();

  return true;
});

