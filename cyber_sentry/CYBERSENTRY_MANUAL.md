# CyberSentry: The Complete Manual

Welcome to the official manual for CyberSentry—your autonomous local security engineering platform. This guide covers every command and every page in detail.

---

## 🛠 Part 1: CLI Commands Reference

CyberSentry is controlled via the `cs` command in your terminal. Follow these steps for each phase of your security audit.

### 1. `cs init [PATH]`
- **Purpose**: Initializes a new CyberSentry project in the specified directory.
- **When to use**: Your first step when starting with a new codebase.
- **What it does**: Creates the `.cybersentry/` configuration folder and local database.

### 2. `cs doctor`
- **Purpose**: A "health check" for your environment.
- **When to use**: If things aren't working or before a major scan.
- **What it does**: Verifies Ollama connectivity, model availability, and environment variables.

### 3. `cs scan [FILE/DIR]`
- **Purpose**: Performs a deep security scan of your local files.
- **When to use**: To find vulnerabilities in your source code.
- **What it does**: Uses the local LLM to identify XSS, SQLi, and other OWASP Top 10 issues.

### 4. `cs triage [RUN_ID]`
- **Purpose**: Reviews and classifies findings from a previous scan.
- **When to use**: After running `cs scan`.
- **What it does**: Categorizes vulnerabilities by severity and filters out false positives.

### 5. `cs ui [--port PORT]`
- **Purpose**: Launches the Premium Web Dashboard.
- **When to use**: When you want to use the graphical interface and AI Chat.
- **What it does**: Starts a local FastAPI server (default port 8081) and opens your browser.

---

## 🌐 Part 2: Web Dashboard Walkthrough

The Web UI provides a premium glassmorphism experience for managing your security posture visually.

### 1. The Entryway (Login Page)
- **Visuals**: Animated mesh gradients with glowing neon orbs.
- **Actions**: Sign in via Clerk (GitHub/Google or Email).
- **Tip**: This screen is 100% local; your session is handled securely via the Clerk integration.

### 3. Security Chat (The 'Neural Net')
- **How to use**: Type any security-related question into the bottom bar.
- **Capabilities**: Ask for exploit explanations, code reviews, or remediation steps.
- **Constraint**: This AI is specialized; it will only answer cybersecurity-related prompts.

### 4. URL Scanner Page
- **Step 1**: Enter the target URL (e.g., `https://example.com`).
- **Step 2**: Check the box confirming you have authorization to scan.
- **Step 3**: Click "Run Scan" and watch the real-time findings populate.

### 5. Agent Console
- **Purpose**: This is where you link your local machine to the web UI.
- **Procedure**: Run `cs ui` first, then click "Link Local Agent" to verify the connection. Once linked, the Agent can perform filesystem operations on your behalf.

---

## 🚀 Getting Started Step-by-Step

1. **Terminal**: Run `ollama serve` to start your AI engine.
2. **Terminal**: Run `cs init .` in your project folder.
3. **Terminal**: Run `cs ui` to open the visual dashboard.
4. **Browser**: Log in and head to the **Local Setup Guide** to link your agent.
5. **Browser**: Start chatting or scanning!

---

*Manual Version 1.0 // CyberSentry Autonomous Systems*
