## CyberSentry Chrome Extension (local-only)

This is a **separate** Chrome extension that talks to your **local** CyberSentry server.
It does **not** replace the website UI.

### Prerequisites

- CyberSentry server running on `http://127.0.0.1:8081`
- Chrome / Edge (Chromium)

### Start the backend (example)

From `cyber_sentry/`:

```bash
.\.venv\Scripts\python.exe -m uvicorn cyber_sentry_cli.api.app:app --host 127.0.0.1 --port 8081
```

### Install the extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the folder: `agenticai/chrome_extension/`

### Use it

1. Open any `http://` or `https://` website tab
2. Click the CyberSentry extension icon (opens the **Side Panel**)
3. Enable: **I confirm I’m authorized…**
4. Click **Quick scan**

The extension calls:
- `POST /api/webscan-lite` for a fast scan
- `GET /api/runs/{run_id}/findings` to show top findings
- `GET /api/runs/{run_id}/report` and `/remediation` for detailed artifacts

### After updates

If you change extension files, go to `chrome://extensions` and click **Reload** on the extension.

