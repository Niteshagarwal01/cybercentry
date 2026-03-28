// Clerk Auth Initialization
let appBooted = false;

function bootApp() {
  if (appBooted) return;
  appBooted = true;
  document.getElementById('auth-container').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  initAppJS();
}

window.initComponents = async () => {
  const clerkMount = document.getElementById('clerk-mount');
  const userButtonMount = document.getElementById('user-button');

  if (!window.Clerk) {
    console.warn("Clerk object not found. Booting app directly.");
    bootApp();
    return;
  }

  try {
    await window.Clerk.load();
    if (window.Clerk.user) {
      try {
        window.Clerk.mountUserButton(userButtonMount, {
          appearance: {
            variables: {
              colorPrimary: "#00ff88",
              colorText: "#ffffff",
              colorTextSecondary: "#a1a3b1",
              colorBackground: "#050508",
              colorInputBackground: "rgba(0,0,0,0.35)",
              borderRadius: "16px",
              fontFamily: "'Outfit', -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif",
            },
            elements: {
              userButtonPopoverCard: {
                backgroundColor: "rgba(12,12,18,0.94)",
                border: "1px solid rgba(255,255,255,0.12)",
                borderRadius: "24px",
                backdropFilter: "blur(22px)",
              },
              userButtonPopoverActionButton: {
                borderRadius: "14px",
              },
            },
          },
        });
      } catch (e) {
        console.error("Clerk mountUserButton failed:", e);
      }
      bootApp();
      checkSetupStatussilently();
    } else {
      document.getElementById('auth-container').style.display = 'flex';
      window.Clerk.mountSignIn(clerkMount, {
        appearance: {
          variables: {
            colorPrimary: "#00ff88",
            colorText: "#ffffff",
            colorTextSecondary: "rgba(255,255,255,0.65)",
            colorBackground: "rgba(16, 18, 27, 0.4)",
            colorInputBackground: "rgba(255,255,255,0.05)",
            colorInputText: "#ffffff",
            borderRadius: "20px",
            fontFamily: "'Outfit', sans-serif",
          },
          elements: {
            card: {
              backgroundColor: "rgba(16, 18, 27, 0.45)",
              backdropFilter: "blur(24px)",
              border: "1px solid rgba(255,255,255,0.15)",
              boxShadow: "0 20px 50px rgba(0,0,0,0.3)",
            },
            headerTitle: { color: "#ffffff" },
            headerSubtitle: { color: "rgba(255,255,255,0.6)" },
            socialButtonsBlockButton: {
              backgroundColor: "rgba(255,255,255,0.05)",
              borderColor: "rgba(255,255,255,0.1)",
              color: "#ffffff",
              "&:hover": {
                backgroundColor: "rgba(255,255,255,0.1)",
              }
            },
            socialButtonsBlockButtonText: { color: "#ffffff" },
            dividerText: { color: "rgba(255,255,255,0.4)" },
            formFieldLabel: { color: "rgba(255,255,255,0.8)" },
            formFieldInput: {
              backgroundColor: "rgba(255,255,255,0.03)",
              borderColor: "rgba(255,255,255,0.1)",
              color: "#ffffff",
            },
            footerActionText: { color: "rgba(255,255,255,0.6)" },
            footerActionLink: { color: "#00ff88" }
          }
        }
      });
    }
  } catch (err) {
    console.error("Clerk load error:", err);
    bootApp(); // Fail open so the user isn't stuck
  }
};

window.addEventListener('load', () => {
  setTimeout(() => {
    if (!appBooted && !document.getElementById('clerk-components')) {
      console.warn("Clerk timed out. Booting UI directly.");
      bootApp();
    }
  }, 2500);
});

// Main Application Logic
function initAppJS() {

  // ----------------------------------------------------
  // TAB SWITCHING
  // ----------------------------------------------------
  const navBtns = document.querySelectorAll('.nav-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  const toggleHistoryBtn = document.getElementById('toggle-history-btn');

  window.switchTab = function (targetId) {
    const btn = document.querySelector(`.nav-btn[data-tab="${targetId}"]`);
    if (!btn || btn.classList.contains('locked')) return;

    navBtns.forEach(b => b.classList.remove('active'));
    tabContents.forEach(c => c.classList.remove('active'));

    btn.classList.add('active');
    const targetTab = document.getElementById(`${targetId}-tab`);
    if (targetTab) targetTab.classList.add('active');
  };

  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.classList.contains('locked')) return;
      if (btn.dataset.tab) {
        switchTab(btn.dataset.tab);
      }
    });
  });

  function setHistoryHiddenForActiveTab(hidden) {
    const activeTab = document.querySelector('.tab-content.active');
    if (!activeTab) return;
    const layout = activeTab.querySelector('.chat-layout');
    if (!layout) return;
    layout.classList.toggle('history-hidden', hidden);
  }

  function persistHistoryHidden(tabId, hidden) {
    try { localStorage.setItem(`cs_history_hidden_${tabId}`, hidden ? '1' : '0'); } catch (e) { }
  }

  function restoreHistoryHidden() {
    const activeTab = document.querySelector('.tab-content.active');
    if (!activeTab) return;
    const tabId = activeTab.id || '';
    let hidden = false;
    try { hidden = localStorage.getItem(`cs_history_hidden_${tabId}`) === '1'; } catch (e) { }
    setHistoryHiddenForActiveTab(hidden);
  }

  // Restore on boot and on tab changes
  setTimeout(restoreHistoryHidden, 0);
  const originalSwitchTab = window.switchTab;
  window.switchTab = function (targetId) {
    originalSwitchTab(targetId);
    setTimeout(restoreHistoryHidden, 0);
  };

  if (toggleHistoryBtn) {
    toggleHistoryBtn.addEventListener('click', () => {
      const activeTab = document.querySelector('.tab-content.active');
      if (!activeTab) return;
      const layout = activeTab.querySelector('.chat-layout');
      if (!layout) return;
      const willHide = !layout.classList.contains('history-hidden');
      layout.classList.toggle('history-hidden', willHide);
      persistHistoryHidden(activeTab.id || '', willHide);
    });
  }

  // ----------------------------------------------------
  // REAL SETUP VERIFICATION LOGIC
  // ----------------------------------------------------
  const verifyBtn = document.getElementById('verify-setup-btn');
  const verifyError = document.getElementById('verify-error');
  const agentChatNav = document.getElementById('nav-agent-chat');
  const unlockOverlay = document.getElementById('unlock-overlay');

  window.checkSetupStatussilently = async function () {
    try {
      const resp = await fetch('/api/setup-status');
      const data = await resp.json();
      if (data.is_setup) unlockAgentChat(false);
    } catch (e) {
      console.error(e);
    }
  }

  verifyBtn.addEventListener('click', async () => {
    verifyBtn.textContent = 'Pinging local backend...';
    verifyBtn.classList.remove('pulse');
    verifyBtn.disabled = true;
    verifyError.style.display = 'none';

    try {
      const resp = await fetch('/api/setup-status');
      const data = await resp.json();

      if (!resp.ok) throw new Error("Backend offline");

      if (data.is_setup) {
        unlockAgentChat(true);
      } else {
        throw new Error("Local config not found. Please run 'cs init .' in your terminal first.");
      }
    } catch (err) {
      verifyBtn.textContent = 'Link Local Agent';
      verifyBtn.disabled = false;
      verifyBtn.classList.add('pulse');
      verifyError.textContent = err.message;
      verifyError.style.display = 'block';
    }
  });

  function unlockAgentChat(showModal = false) {
    agentChatNav.classList.remove('locked');
    agentChatNav.querySelector('.icon-lock').innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"></path>';

    verifyBtn.textContent = 'Agent Linked via Local Config';
    verifyBtn.style.backgroundColor = 'var(--accent)';
    verifyBtn.style.color = '#000';
    verifyBtn.style.boxShadow = 'none';
    verifyBtn.classList.remove('pulse');
    verifyBtn.disabled = true;

    if (showModal) {
      unlockOverlay.style.display = 'flex';
    }
  }

  window.closeUnlockModal = function () {
    unlockOverlay.style.display = 'none';
    switchTab('agent-chat');
  };

  // ----------------------------------------------------
  // CHAT CORE LOGIC
  // ----------------------------------------------------
  function setupChatSystem(prefix, defaultMode) {
    const input = document.getElementById(`${prefix}-input`);
    const sendBtn = document.getElementById(`${prefix}-send-btn`);
    const welcome = document.getElementById(`${prefix}-welcome`);
    const messages = document.getElementById(`${prefix}-messages`);
    const historyList = document.getElementById(`${prefix}-history-list`);
    const newChatBtn = document.getElementById(`${prefix}-new-chat`);
    const closeHistoryBtn = document.getElementById(`${prefix}-history-close`);
    // Tab sections are named like "security-chat-tab" / "agent-chat-tab" (not "${prefix}-tab").
    // If the scroll container can't be found, fall back to the messages panel to avoid null errors.
    const container =
      document.getElementById(`${prefix}-container`) ||
      document.querySelector(`#${prefix}-chat-tab .chat-container`) ||
      document.querySelector(`#${prefix}-tab .chat-container`) ||
      messages;

    const storageKey = `cs_chat_sessions_${prefix}`;
    let activeSessionId = "";

    function loadSessions() {
      try {
        const raw = localStorage.getItem(storageKey);
        const parsed = raw ? JSON.parse(raw) : [];
        return Array.isArray(parsed) ? parsed : [];
      } catch (e) {
        return [];
      }
    }

    function saveSessions(sessions) {
      try {
        localStorage.setItem(storageKey, JSON.stringify(sessions.slice(0, 40)));
      } catch (e) { }
    }

    function upsertSession(update) {
      const sessions = loadSessions();
      const idx = sessions.findIndex(s => s.id === update.id);
      if (idx >= 0) sessions[idx] = update;
      else sessions.unshift(update);
      // newest first
      sessions.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
      saveSessions(sessions);
      renderHistory();
    }

    function createSessionIfNeeded(firstUserText = "") {
      if (activeSessionId) return activeSessionId;
      const id = `${Date.now()}_${Math.random().toString(16).slice(2)}`;
      activeSessionId = id;
      const title = (firstUserText || "New chat").slice(0, 60);
      upsertSession({ id, title, updated_at: Date.now(), messages: [] });
      setActiveHistoryItem();
      return id;
    }

    function setActiveHistoryItem() {
      if (!historyList) return;
      historyList.querySelectorAll(".chat-history-item").forEach(el => {
        el.classList.toggle("active", el.dataset.sessionId === activeSessionId);
      });
    }

    function formatTime(ts) {
      try {
        const d = new Date(ts);
        return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
      } catch {
        return "";
      }
    }

    function renderHistory() {
      if (!historyList) return;
      const sessions = loadSessions();
      if (!sessions.length) {
        historyList.innerHTML = `<div class="chat-history-item"><div class="chat-history-item-title">No chats yet</div><div class="chat-history-item-meta">Start a new conversation</div></div>`;
        return;
      }

      historyList.innerHTML = sessions.map(s => {
        const title = (s.title || "Chat").replace(/</g, "&lt;");
        const meta = `${formatTime(s.updated_at || 0)} • ${(s.messages || []).length} msg`;
        return `
            <div class="chat-history-item ${s.id === activeSessionId ? "active" : ""}" data-session-id="${s.id}">
              <div class="chat-history-item-title">${title}</div>
              <div class="chat-history-item-meta">${meta}</div>
            </div>
          `;
      }).join("");

      historyList.querySelectorAll(".chat-history-item").forEach(el => {
        el.addEventListener("click", () => {
          const sid = el.dataset.sessionId;
          if (!sid) return;
          activeSessionId = sid;
          setActiveHistoryItem();
          loadSessionIntoUI(sid);
        });
      });
    }

    function clearMessagesUI() {
      messages.innerHTML = "";
      messages.style.display = "none";
      welcome.style.display = "block";
    }

    function loadSessionIntoUI(sessionId) {
      const sessions = loadSessions();
      const session = sessions.find(s => s.id === sessionId);
      if (!session) {
        clearMessagesUI();
        return;
      }

      // Clear UI and re-render
      messages.innerHTML = "";
      welcome.style.display = "none";
      messages.style.display = "flex";
      (session.messages || []).forEach(m => {
        appendMessage(m.content || "", m.role === "user", false);
      });
      if (container) container.scrollTop = container.scrollHeight;
    }

    window[`set${prefix.charAt(0).toUpperCase() + prefix.slice(1)}Chat`] = function (text) {
      input.value = text;
      input.focus();
      handleSubmit();
    };

    input.addEventListener('input', function () {
      this.style.height = 'auto';
      this.style.height = (this.scrollHeight) + 'px';
      sendBtn.disabled = this.value.trim() === '';
    });

    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSubmit();
      }
    });

    sendBtn.addEventListener('click', handleSubmit);

    function appendMessage(text, isUser = false, saveToHistory = true) {
      if (welcome.style.display !== 'none') {
        welcome.style.display = 'none';
        messages.style.display = 'flex';
      }

      const msgDiv = document.createElement('div');
      msgDiv.className = `message ${isUser ? 'user' : 'bot'}`;

      const avatarDiv = document.createElement('div');
      avatarDiv.className = `avatar ${isUser ? 'user' : 'bot'} ${prefix === 'agent' ? 'agent' : ''}`;
      avatarDiv.innerHTML = isUser ? 'U' : (prefix === 'agent' ? 'Σ' : 'AI');

      const bubbleDiv = document.createElement('div');
      bubbleDiv.className = 'bubble glass-card';
      if (isUser) bubbleDiv.classList.remove('glass-card'); // Users don't get the heavy glass effect

      if (!isUser) {
        let formatted = text
          .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
          .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
          .replace(/\n\n/g, '</p><p>')
          .replace(/\n/g, '<br/>');
        bubbleDiv.innerHTML = `<p>${formatted}</p>`;
      } else {
        bubbleDiv.textContent = text;
      }

      msgDiv.appendChild(avatarDiv);
      msgDiv.appendChild(bubbleDiv);
      messages.appendChild(msgDiv);
      if (container) {
        container.scrollTop = container.scrollHeight;
      }

      if (saveToHistory) {
        const sid = createSessionIfNeeded(isUser ? text : "");
        const sessions = loadSessions();
        const session = sessions.find(s => s.id === sid);
        if (session) {
          session.updated_at = Date.now();
          session.title = session.title || (text || "Chat").slice(0, 60);
          session.messages = Array.isArray(session.messages) ? session.messages : [];
          session.messages.push({ role: isUser ? "user" : "assistant", content: text, ts: Date.now() });
          upsertSession(session);
        }
      }

      return bubbleDiv;
    }

    let isProcessing = false;

    async function handleSubmit() {
      if (isProcessing) return;
      const text = input.value.trim();
      if (!text) return;

      isProcessing = true;
      input.value = '';
      input.style.height = 'auto';
      input.disabled = true;
      sendBtn.disabled = true;

      appendMessage(text, true, true);
      const botBubble = appendMessage('<span class="neon-text blink">Connecting to CyberSentry Neural Net...</span>', false, false);

      try {
        const resp = await fetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: text, mode: defaultMode })
        });

        if (!resp.ok) {
          let detail = '';
          try {
            const err = await resp.json();
            detail = (err && (err.detail || err.message)) ? String(err.detail || err.message) : '';
          } catch (e) { }
          throw new Error(detail ? `${resp.status}: ${detail}` : `Server returned ${resp.status}`);
        }

        const data = await resp.json();
        let formatted = data.reply
          .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
          .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
          .replace(/\n\n/g, '</p><p>')
          .replace(/\n/g, '<br/>');
        botBubble.innerHTML = `<p>${formatted}</p>`;

        // Manually save assistant reply to history without creating a new UI element
        const sid = createSessionIfNeeded("");
        const sessions = loadSessions();
        const session = sessions.find(s => s.id === sid);
        if (session) {
          session.updated_at = Date.now();
          session.messages.push({ role: "assistant", content: data.reply, ts: Date.now() });
          upsertSession(session);
        }

        if (container) {
          container.scrollTop = container.scrollHeight;
        }
      } catch (err) {
        botBubble.innerHTML = `<span class="bad">Error: ${err.message}.</span>`;
        // Save the error to history so the flow is preserved
        const sid = createSessionIfNeeded("");
        const sessions = loadSessions();
        const session = sessions.find(s => s.id === sid);
        if (session) {
          session.updated_at = Date.now();
          session.messages.push({ role: "assistant", content: `Error: ${err.message}.`, ts: Date.now() });
          upsertSession(session);
        }
      } finally {
        isProcessing = false;
        input.disabled = false;
        sendBtn.disabled = false;
        input.focus();
      }
    }

    if (newChatBtn) {
      newChatBtn.addEventListener("click", () => {
        activeSessionId = "";
        clearMessagesUI();
        renderHistory();
      });
    }

    if (closeHistoryBtn) {
      closeHistoryBtn.addEventListener("click", () => {
        const tabSection = document.getElementById(`${prefix}-chat-tab`);
        const layout = tabSection ? tabSection.querySelector('.chat-layout') : null;
        if (!layout) return;
        layout.classList.add('history-hidden');
        try { localStorage.setItem(`cs_history_hidden_${tabSection.id}`, '1'); } catch (e) { }
      });
    }

    // Initial render
    renderHistory();
  }

  setupChatSystem('security', 'general');
  setupChatSystem('agent', 'autonomous');

  // ----------------------------------------------------
  // WEBSCAN LOGIC
  // ----------------------------------------------------
  window.runScan = async function () {
    const status = document.getElementById('webscan-status');
    const scanSummary = document.getElementById('scanSummary');
    const results = document.getElementById('results');
    const artifactActions = document.getElementById('artifactActions');
    const artifactPanel = document.getElementById('artifactPanel');

    status.innerHTML = 'Running authorized scan <span class="blink">_</span>';
    scanSummary.innerHTML = '';
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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      let data = null;
      try {
        data = await resp.json();
      } catch (e) {
        const raw = await resp.text();
        throw new Error(raw || `Server returned ${resp.status}`);
      }
      if (!resp.ok) {
        status.innerHTML = '<span class="bad">Error: ' + (data.detail || 'Unknown error') + '</span>';
        return;
      }

      window.lastRunId = data.run_id;
      status.innerHTML = '<span class="good">Mission complete.</span> Run ' + data.run_id;
      artifactActions.style.display = 'flex';

      const sResp = await fetch('/api/runs/' + data.run_id + '/webscan-summary');
      if (sResp.ok) {
        const summary = await sResp.json();
        const visited = Array.isArray(summary.visited_urls) ? summary.visited_urls.slice(0, 5) : [];
        scanSummary.innerHTML =
          'Target: ' + (summary.target || '-') +
          ' | Pages: ' + (summary.pages_scanned || 0) +
          (visited.length ? '<br/><br/>Visited:<br/>' + visited.join('<br/>') : '');
      }

      const fResp = await fetch('/api/runs/' + data.run_id + '/findings');
      const findings = await fResp.json();
      if (!findings.length) {
        results.innerHTML = '<div class="glass-card" style="margin-top:20px; padding: 20px; text-align: center;"><p class="good neon-text">Scan completed successfully. No vulnerabilities found in scope.</p></div>';
        return;
      }

      const rows = findings.map(f => `<tr><td>${f.severity}</td><td>${f.rule_id}</td><td style="word-break:break-all">${f.file_path}</td><td>${f.title}</td></tr>`).join('');
      results.innerHTML = '<table><thead><tr><th>Severity</th><th>Rule</th><th>Target</th><th>Issue</th></tr></thead><tbody>' + rows + '</tbody></table>';
    } catch (e) {
      status.innerHTML = '<span class="bad">Error: ' + e.message + '</span>';
    }
  };

  window.loadArtifact = async function (artifactName) {
    if (!window.lastRunId) return;
    const endpointMap = { 'REPORT.md': '/report', 'WEB_REMEDIATION.md': '/remediation' };
    const endpoint = endpointMap[artifactName];
    if (!endpoint) return;

    const resp = await fetch('/api/runs/' + window.lastRunId + endpoint);
    const data = await resp.json();
    if (!resp.ok) return;

    document.getElementById('artifactPanel').style.display = 'block';
    document.getElementById('artifactTitle').textContent = artifactName;
    document.getElementById('artifactContent').textContent = data.content;
  };
}
