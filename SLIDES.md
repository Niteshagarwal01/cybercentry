# CyberSentry — PPT Slides
### Agentic AI Hackathon | National Level | Problem Statement #1

---

---

# SLIDE 0 — COVER

## CyberSentry
### Autonomous Red Team AI Agent

> *"Hunts vulnerabilities. Debates the best fix. Thinks out loud — live."*

- **Problem:** #1 — The Red Team Cyber-Sentry
- **Stack:** ReAct · Multi-Agent Debate · OpenRouter · FastAPI · WebSocket

---
---

# SLIDE 1 — THE PROBLEM

## "Security Scanners Are Blind"

Today's tools — Bandit, Semgrep, Snyk — scan code and spit out a list. They tell you *what* broke, but never *why it matters*, *how bad it is*, or *what to actually do*. A SQL injection in one file might have the same root cause in 12 others — scanners won't connect those dots. A human expert still has to triage, prioritize, and reason through every single finding.

> **"Average breach detection time in 2025: 194 days."**
> The bottleneck isn't detection — it's **reasoning**.

---

### 🖼️ Image Suggestion for This Slide

**Use:** A split-screen image —
- **Left side:** A overwhelmed developer staring at a massive terminal dump of errors (dark screen, scrolling red text)
- **Right side:** The same screen but with 90% greyed out and only 2–3 critical items highlighted in red

**Where to find it:**
- Search **Unsplash** → `"code security terminal"` or `"hacker dark screen"`
- Search **Freepik** → `"vulnerability scan report"`
- Or use a **real Semgrep screenshot** with 100+ findings — paste it into the slide with a red `✗ NOT ENOUGH` watermark over it — looks authentic and judges will recognize it instantly

---
---

# SLIDE 2 — MEET CYBERSENTRY

## "An Autonomous Security Engineer"

> *"Doesn't just find vulnerabilities — hunts them, debates the best fix, explains every decision. Live."*

**Our Solution — 3 Core Capabilities:**

- 🔍 **Autonomous Scanning & Replanning** — Runs a full ReAct loop (Thought → Action → Observe). When a fix is insufficient, the agent *pivots automatically* and explains why — no human needed to guide it.

- 🤝 **Multi-Agent Debate** — 3 specialist agents (Red Team, Blue Team, Auditor) argue the best fix across 3 rounds. A Judge Agent scores and ranks the top approaches — the *best answer wins*, not the first one.

- 👁️ **Live Thought Trace UI** — Every reasoning step streams to a real-time web dashboard via WebSocket. Full observability. Zero black box.

---

**⭐ USP — What No Other Team Has:**
> CyberSentry doesn't just detect. It *reasons like a senior security engineer* — connecting patterns across the entire codebase, running agents that argue against each other, and showing every decision live on screen.

---
---

# SLIDE 3 — SYSTEM ARCHITECTURE

## "The Full Picture"

```
   [Codebase Upload / GitHub URL]
               │
               ▼
   ┌───────────────────────────┐
   │  MASTER ORCHESTRATOR      │
   │  ReAct: Thought→Act→Obs   │
   └───────────┬───────────────┘
               │ spawns on CRITICAL/HIGH
      ┌────────┼────────┐
      ▼        ▼        ▼
  [Agent A] [Agent B] [Agent C]
  Red Team  Blue Team  Auditor
      │        │        │
      └────────┴────────┘
               │ debate
               ▼
         [JUDGE AGENT]
         Scores → Top 3
               │
               ▼
      [THOUGHT TRACE UI]
      Real-time WebSocket
               │
               ▼
      Human Approves → Patch Applied
```

> LLM via **OpenRouter** — model-agnostic (GPT-4o / Claude 3.5 / Mistral)
> Backend via **FastAPI + WebSocket** — async, real-time, production-ready
> **No LangChain** — custom ReAct loop, full reasoning control
> Guardrails between **every tool output and the LLM** — agent never sees raw data
> Debate spawns only on **CRITICAL / HIGH** — compute focused where risk is highest

**Tools integrated:**
Semgrep · Bandit · Custom AST Walker · Dependency Auditor · Patch Generator · Human Approval Gate

---
---

# SLIDE 4 — REACT LOOP + AGENT DEBATE

## "How It Thinks & How Agents Argue"

CyberSentry does not stop at detection. It investigates the issue, checks whether the pattern repeats across the codebase, and escalates critical findings into agent debate before preparing a patch.

**ReAct Loop:**

- **Think** — Identify the real security risk
- **Act** — Run the right analysis tools
- **Observe** — Check if the pattern is repeated elsewhere
- **Pivot** — Replan if the first fix is too narrow
- **Judge** — Pick the strongest solution
- **Patch** — Prepare a fix for approval

**Agent Debate:**

- **Red Team** — Maximum security
- **Blue Team** — Safe implementation
- **Auditor** — OWASP and compliance alignment
- **Judge** — Scores and selects the best fix

**Why this matters:**

- Prevents one-file fixes for codebase-wide problems
- Recommends the best fix, not the fastest one
- Keeps final approval with humans

**Security guardrails built in:**
🔒 Prompt injection filtered · 📁 Path traversal blocked · 🔑 Secrets never exposed · 🙋 Human approval required for every patch

---
---

# SLIDE 5 — LIVE THOUGHT TRACE

## "Watch It Think — In Real Time"

The Thought Trace UI makes CyberSentry fully transparent. Every step is streamed live, from first detection to final patch, so users can see exactly how the agent is reasoning.

**Left Panel:**

- Live thought process and priorities
- Tool execution and scan results
- Findings, severity, and affected files
- Debate, judge score, and patch status

**Right Panel:**

- Vulnerability type and severity
- Affected files and confidence score
- Recommended fix
- Approve, diff, or reject actions

**Why it stands out:**

- Transparent, not black-box
- Easy to trust and audit
- Strong live demo value

> **Design:** Background `#0d1117` · Critical `#ff4d4d` · Approved `#3fb950` · Font: JetBrains Mono
