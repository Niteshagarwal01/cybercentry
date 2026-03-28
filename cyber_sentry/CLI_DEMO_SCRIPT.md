# CyberSentry CLI — Full Demo Script
### A Step-by-Step Voiceover Script for Your Video

**Duration**: ~5-7 Minutes (CLI section only)
**Tone**: Confident, technical, authoritative. You are not pitching — you are *demonstrating power*.

---

## 🎬 SCENE 0: The Setup (Before you hit record)

Make sure you have this ready in your terminal:
- A vulnerable sample project directory (e.g., `tests/vulnerable_app/`)
- CyberSentry installed and `.venv` activated
- Ollama running (`ollama serve`)
- Font size bumped up in terminal for visibility

---

## 🎬 SCENE 1: Starting the Demo

**[ You type: nothing yet. Just show the terminal. ]**

> **"This is CyberSentry running entirely on my local machine. No cloud. No API keys. No data leaving this device. Everything you're about to see is powered by a local AI model called Qwen 2.5 Coder, running through Ollama."**

> **"Let me walk you through the full autonomous security engineering pipeline — from raw code, all the way to a patched, auditable, production-ready fix."**

---

## 🎬 SCENE 2: The `/help` Command

**[ Type: `cs chat` then inside chat type `/help` ]**

```
/help
```

> **"First — let me show you the chat interface. This is the interactive mode of CyberSentry. You talk to it like a terminal agent. Here are the seven core commands it understands."**

*(Read them out naturally as they appear on screen)*

> **"Scan. Findings. Triage. Debate. Patch. Tools. And Help. This is your full security engineering workflow in seven commands."**

---

## 🎬 SCENE 3: The `/scan` Command

**[ Type: `/scan tests/vulnerable_app/` ]**

```
/scan tests/vulnerable_app/
```

> **"Let's kick it off. I'm pointing the scanner at a sample vulnerable project. Watch what happens."**

*(Wait for output — narrate as it runs)*

> **"CyberSentry is now firing three scanner adapters simultaneously — Semgrep for pattern-based rules, Bandit for Python-specific security issues, and our custom AST rules engine for deeper logic flaws."**

> **"Each finding gets normalized into a unified schema — severity, rule ID, file path, line number, and a confidence score. This isn't just grep. This is structured, reasoning-ready output."**

---

## 🎬 SCENE 4: The `/findings` Command

**[ Type: `/findings` ]**

```
/findings
```

> **"Now let's see what was found."**

*(Point to the output on screen)*

> **"Here is our findings table. You can see Critical and High severity vulnerabilities grouped by rule type. SQL injection, hardcoded secrets, insecure deserialization — all surfaced in under sixty seconds."**

> **"Notice every finding has a unique ID. That ID is how we drive everything forward."**

---

## 🎬 SCENE 5: The `/triage` Command

**[ Type: `/triage` ]**

```
/triage
```

> **"Raw findings are noisy. Triage is where CyberSentry gets intelligent."**

> **"It clusters related issues together, deduplicates false positives, and applies our risk scoring formula — severity weight, confidence score, and reachability factor — to produce a ranked priority list."**

> **"Your team now has a clear action order. No more debating what to fix first."**

---

## 🎬 SCENE 6: The `/debate` Command

**[ Type: `/debate F-001` — replace with actual finding ID shown on screen ]**

```
/debate F-001
```

> **"Now here's where CyberSentry goes beyond any traditional scanner. I'm running a multi-agent remediation debate on this SQL injection finding."**

*(Wait for the agents to respond)*

> **"Three agents are reasoning about this vulnerability right now. The Red Team agent argues for the most aggressive remediation. The Blue Team agent advocates for the safest, least-breaking change. And the Auditor agent evaluates both positions for correctness and compliance alignment."**

> **"Then our Judge model scores each proposal across five dimensions — security effectiveness, implementation safety, maintainability, compliance, and effort — and picks a winner."**

> **"This is not a simple fix suggestion. This is a structured, reasoned, multi-perspective engineering decision."**

---

## 🎬 SCENE 7: The `/patch` Command

**[ Type: `/patch F-001` ]**

```
/patch F-001
```

> **"Based on the debate outcome, CyberSentry generates a concrete code patch."**

*(Show the diff output)*

> **"Here is the actual diff. Old code, new code, side by side. The patch includes the rationale, a risk summary, and a rollback note."**

> **"And critically — nothing is applied yet. CyberSentry requires your explicit approval."**

**[ Now type: `/patch F-001 --apply` ]**

```
/patch F-001 --apply
```

> **"When you're ready, you add the `--apply` flag to trigger the approval workflow. CyberSentry confirms with you one final time before touching a single line of your codebase."**

> **"Human in the loop. Always."**

---

## 🎬 SCENE 8: The `/tools` Command

**[ Type: `/tools` ]**

```
/tools
```

> **"Quick side note — `/tools` shows you every tool the agent has access to during a session. File readers, code executors, scanner adapters — total transparency about what the agent can and cannot do."**

---

## 🎬 SCENE 9: The `cs trace` Command

**[ Exit chat with `/exit`, then type: `cs trace <run-id>` ]**

```
/exit
cs trace <run-id>
```

> **"Back in the main CLI. I'm now running `cs trace` on this completed run."**

> **"This gives me a full chronological thought trace — a timeline of every decision the agent made, every tool it called, and every reasoning step it took. This is your audit trail. Perfect for compliance teams, post-incident reviews, or just understanding exactly how CyberSentry reached its conclusions."**

---

## 🎬 SCENE 10: The `cs report` Command

**[ Type: `cs report <run-id> --format md` ]**

```
cs report <run-id> --format md
```

> **"Finally — the report. One command, and CyberSentry packages everything into a professional document."**

> **"Executive summary, findings table, debate transcripts, patch decisions, and risk metrics. Available in Markdown for your engineering team, JSON for your CI pipeline, or SARIF for compliance tooling."**

> **"Your security posture is now fully documented, auditable, and shareable."**

---

## 🎬 SCENE 11: The Closer

**[ Hold on the final terminal output ]**

> **"That is the full CyberSentry CLI workflow. Scan. Triage. Debate. Patch. Trace. Report."**

> **"From zero to a fully audited, AI-reasoned, human-approved security fix — without leaving your terminal, without touching the cloud, and without compromising your privacy."**

> **"This is autonomous security engineering. This is CyberSentry."**

---

### 📝 Speaker Quick Reference

| Command | One-Line Pitch to Speak |
|---|---|
| `/scan` | *"Fires three scanners simultaneously, normalizes findings into a unified schema"* |
| `/findings` | *"Shows structured, ranked, severity-tagged vulnerabilities — not just raw grep output"* |
| `/triage` | *"Clusters, deduplicates, and risk-scores so your team knows exactly what to fix first"* |
| `/debate` | *"Three AI agents argue about the fix, a judge scores them — you get the best answer"* |
| `/patch` | *"Generates a real code diff with rationale, requires your approval before touching anything"* |
| `/tools` | *"Shows total transparency about what the agent can access"* |
| `/help` | *"Your command reference, always one keystroke away"* |
| `cs trace` | *"Full chronological audit trail of every AI decision in the run"* |
| `cs report` | *"One command generates a professional report in Markdown, JSON, or SARIF"* |
