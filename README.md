# CyberSentry 🛡️

**Autonomous Red Team AI Agent & Security Engineering Pipeline**

CyberSentry is a fully local, AI-powered security engineering tool designed to scan codebases, triage vulnerabilities, debate remediation strategies, and generate patches without any source code ever leaving your machine.

It features a CLI tool, a sleek Web Dashboard (Mission Console), and a Browser Extension for on-the-fly web application scanning.

---

## 🔥 Features

- **Multi-Scanner Architecture**: Concurrently runs Bandit (for Python context) and Semgrep (for OWASP Top 10 rule-based scans).
- **Intelligent Triage Engine**: Automatically groups raw findings into root-cause clusters and calculates a 0.0 - 1.0 Risk Score per cluster to highlight critical escalation targets.
- **Multi-Agent Remediation Debate**:
  - 🔴 **Red Team Agent**: Advocates for comprehensive, defense-in-depth architectural overhauls.
  - 🔵 **Blue Team Agent**: Advocates for minimal, safe, localized fixes that won't break production.
  - 📋 **Auditor Agent**: Evaluates proposals against compliance frameworks (OWASP ASVS).
  - ⚖️ **Judge Agent**: Scores all proposals across five dimensions (Security, Safety, Maintainability, Compliance, Effort) and declares a winner.
- **Auto-Patching Engine**: Generates unified diffs from the winning debate strategy. Uses a strict "dry-run by default" human-in-the-loop approval gate.
- **Mission Console Web UI**: A beautiful, glassmorphism dashboard built with FastAPI to manage URL scans, interact with the Security-Only Chat Assistant, and monitor local agent activity.
- **Browser Extension**: A Chrome extension that triggers local passive scans (`webscan-lite`) with a single click.

---

## 🚀 Getting Started

### 1. Requirements
- Python 3.10+
- [Ollama](https://ollama.com/) (Must be running locally for the LLM features)
- Chrome / Edge (for the browser extension)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/Niteshagarwal01/cybercentry.git
cd cybercentry/cyber_sentry

# Set up the virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate

# Install dependencies
pip install -e .
```

### 3. Basic Setup
```bash
# Initialize the CyberSentry configuration folder
cs init .

# Verify your environment (Checks for Ollama, models, and scanner binaries)
cs doctor
```

---

## 💻 CLI Usage

The entire CyberSentry pipeline is available through the interactive chat interface:

```bash
# Launch interactive agent loop
cs chat
```

### Interactive Commands
- `/scan <target>`: Run static analysis on a directory or file.
- `/findings`: View color-coded findings table.
- `/triage`: Cluster and prioritize raw findings.
- `/debate <finding_id>`: Spin up the 3-agent deliberation engine for a specific vulnerability.
- `/patch <finding_id> [--apply]`: Generate a codebase patch based on the debate winner (requires the `--apply` flag to commit changes to disk).
- `/tools`: View the LLM's available toolset.

---

## 🌐 Mission Console (Web UI)

To launch the Web Dashboard:
```bash
cs ui --port 8081
```
Open `http://localhost:8081` in your browser.

- **URL Scanner**: Check live web targets for insecure transport, cookie flags, CSP, and missing headers.
- **Security Chat**: Ask the specialized neural assistant about vulnerability root causes and modern exploit techniques.
- **Agent Console**: Bridge your CLI filesystem agent to the web UI.

---

## 🧩 Browser Extension

1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** (top right corner).
3. Click **Load unpacked** and select the `chrome_extension` folder.
4. With `cs ui` running in the background, click the extension icon on any page you're authorized to test and click **Scan This Page**.

---

## 🛡️ Privacy First

CyberSentry executes **100% locally**. 
- No API keys required for external LLMs.
- No source code or findings are sent to the cloud.
- Powered by `Qwen 2.5 Coder` via Ollama.

---

*Stay secure.*
