"""
web_dashboard.py — Ultra Web Dashboard
Features: Real-time scan dashboard, live results, progress tracking,
          browser-based UI, WebSocket updates, chart visualization
"""

import json
import os
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from ui.rich_ui import (
    console, info, warning, error, success, section_header
)

DASHBOARD_PORT = 8765
DASHBOARD_HOST = "127.0.0.1"

# Global state
_scan_state: Dict = {
    "target":     "",
    "status":     "idle",
    "progress":   0,
    "current_module": "",
    "findings":   [],
    "stats":      {},
    "log":        [],
    "started":    "",
    "elapsed":    0,
}
_state_lock = threading.Lock()


def _update_state(**kwargs):
    with _state_lock:
        _scan_state.update(kwargs)


def _add_log(msg: str, level: str = "info"):
    with _state_lock:
        _scan_state["log"].append({
            "time":  time.strftime("%H:%M:%S"),
            "level": level,
            "msg":   msg,
        })
        if len(_scan_state["log"]) > 200:
            _scan_state["log"] = _scan_state["log"][-200:]


def _add_finding(finding: Dict):
    with _state_lock:
        _scan_state["findings"].append(finding)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon Toolkit Pro — Live Dashboard</title>
<style>
:root {
  --bg:#0d1117; --bg2:#161b22; --bg3:#1f2937; --border:#30363d;
  --text:#e6edf3; --dim:#8b949e; --red:#f85149; --orange:#d29922;
  --yellow:#e3b341; --green:#3fb950; --blue:#58a6ff; --cyan:#39d0d8;
}
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text); font-family:'Segoe UI',monospace; font-size:13px; }
.header { background:var(--bg2); border-bottom:2px solid var(--blue); padding:16px 24px; display:flex; align-items:center; justify-content:space-between; }
.logo { font-size:18px; font-weight:700; color:var(--blue); }
.logo span { color:var(--red); }
.status-badge { padding:4px 12px; border-radius:12px; font-size:12px; font-weight:600; }
.status-idle     { background:rgba(88,166,255,.2); color:var(--blue); }
.status-running  { background:rgba(63,185,80,.2);  color:var(--green); animation:pulse 1s infinite; }
.status-complete { background:rgba(63,185,80,.2);  color:var(--green); }
.status-error    { background:rgba(248,81,73,.2);  color:var(--red); }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }

.main { display:grid; grid-template-columns:1fr 320px; height:calc(100vh - 60px); }
.left { overflow-y:auto; padding:16px; }
.right { border-left:1px solid var(--border); overflow-y:auto; }

/* Stats */
.stats-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:16px; }
.stat-card { background:var(--bg2); border:1px solid var(--border); border-radius:8px; padding:14px; text-align:center; }
.stat-num { font-size:28px; font-weight:700; line-height:1; }
.stat-lbl { font-size:11px; color:var(--dim); margin-top:4px; }

/* Progress */
.progress-section { background:var(--bg2); border:1px solid var(--border); border-radius:8px; padding:16px; margin-bottom:16px; }
.progress-bar { background:var(--bg3); border-radius:4px; height:8px; overflow:hidden; margin:8px 0; }
.progress-fill { height:100%; background:var(--blue); border-radius:4px; transition:width .3s; }
.module-name { color:var(--cyan); font-size:12px; }

/* Findings table */
.findings-section { background:var(--bg2); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
.section-title { background:var(--bg3); padding:10px 16px; font-weight:600; font-size:13px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; }
table { width:100%; border-collapse:collapse; }
th { text-align:left; padding:8px 12px; color:var(--dim); font-size:11px; text-transform:uppercase; border-bottom:1px solid var(--border); }
td { padding:6px 12px; border-bottom:1px solid rgba(48,54,61,.4); }
tr:hover td { background:rgba(255,255,255,.02); }
.badge { display:inline-block; padding:2px 7px; border-radius:4px; font-size:10px; font-weight:700; }
.critical { background:rgba(248,81,73,.2); color:var(--red); }
.high     { background:rgba(210,153,34,.2); color:var(--orange); }
.medium   { background:rgba(227,179,65,.2); color:var(--yellow); }
.low      { background:rgba(63,185,80,.2);  color:var(--green); }
.info     { background:rgba(88,166,255,.2); color:var(--blue); }
.mono { font-family:monospace; font-size:12px; }
.dim  { color:var(--dim); }

/* Log panel */
.log-panel { height:100%; display:flex; flex-direction:column; }
.log-header { padding:10px 16px; background:var(--bg3); border-bottom:1px solid var(--border); font-weight:600; font-size:13px; }
.log-body { flex:1; overflow-y:auto; padding:8px; font-family:monospace; font-size:11px; }
.log-entry { padding:2px 6px; border-radius:3px; margin:1px 0; }
.log-entry.info    { color:var(--blue); }
.log-entry.success { color:var(--green); }
.log-entry.warning { color:var(--yellow); }
.log-entry.error   { color:var(--red); }
.log-entry.found   { color:var(--red); font-weight:600; }
.log-time { color:var(--dim); margin-right:6px; }

/* Target input */
.target-form { background:var(--bg2); border:1px solid var(--border); border-radius:8px; padding:16px; margin-bottom:16px; }
.target-form h3 { margin-bottom:12px; color:var(--cyan); }
.form-row { display:flex; gap:8px; flex-wrap:wrap; }
input, select { background:var(--bg3); border:1px solid var(--border); color:var(--text); padding:8px 12px; border-radius:6px; font-size:13px; }
input:focus, select:focus { outline:none; border-color:var(--blue); }
input[type=text] { flex:1; min-width:200px; }
button { padding:8px 16px; border-radius:6px; border:none; cursor:pointer; font-weight:600; font-size:13px; }
.btn-start  { background:var(--green); color:#000; }
.btn-stop   { background:var(--red); color:#fff; }
.btn-report { background:var(--blue); color:#000; }
button:hover { opacity:.85; }
</style>
</head>
<body>
<div class="header">
  <div class="logo">RECON<span>TOOLKIT</span> PRO <span style="font-size:12px;color:var(--dim)">v3.2 Ultra</span></div>
  <div id="status-badge" class="status-badge status-idle">⬤ IDLE</div>
</div>

<div class="main">
  <div class="left">
    <!-- Target Form -->
    <div class="target-form">
      <h3>🎯 Scan Target</h3>
      <div class="form-row">
        <input type="text" id="target-input" placeholder="domain.com or IP" value="">
        <select id="scan-mode">
          <option value="88">Full Recon (1-10)</option>
          <option value="00">Full Attack (All 27)</option>
          <option value="99">Custom</option>
        </select>
        <button class="btn-start" onclick="startScan()">▶ Start Scan</button>
        <button class="btn-stop" onclick="stopScan()">■ Stop</button>
        <button class="btn-report" onclick="downloadReport()">⬇ Report</button>
      </div>
      <div id="custom-modules" style="display:none;margin-top:10px">
        <input type="text" placeholder="Module numbers e.g. 1 3 5 16 17" id="custom-input" style="width:100%">
      </div>
    </div>

    <!-- Stats -->
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-num" id="stat-subdomains" style="color:var(--cyan)">0</div><div class="stat-lbl">Subdomains</div></div>
      <div class="stat-card"><div class="stat-num" id="stat-ports"      style="color:var(--orange)">0</div><div class="stat-lbl">Open Ports</div></div>
      <div class="stat-card"><div class="stat-num" id="stat-cves"       style="color:var(--red)">0</div><div class="stat-lbl">CVEs</div></div>
      <div class="stat-card"><div class="stat-num" id="stat-vulns"      style="color:var(--red)">0</div><div class="stat-lbl">Web Vulns</div></div>
      <div class="stat-card"><div class="stat-num" id="stat-emails"     style="color:var(--blue)">0</div><div class="stat-lbl">Emails</div></div>
      <div class="stat-card"><div class="stat-num" id="stat-secrets"    style="color:var(--red)">0</div><div class="stat-lbl">Secrets</div></div>
      <div class="stat-card"><div class="stat-num" id="stat-exploits"   style="color:var(--orange)">0</div><div class="stat-lbl">Exploits</div></div>
      <div class="stat-card"><div class="stat-num" id="stat-risk"       style="color:var(--red)">—</div><div class="stat-lbl">Risk Score</div></div>
    </div>

    <!-- Progress -->
    <div class="progress-section">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span id="module-name" class="module-name">Ready to scan...</span>
        <span id="progress-pct" style="color:var(--dim);font-size:12px">0%</span>
      </div>
      <div class="progress-bar"><div class="progress-fill" id="progress-fill" style="width:0%"></div></div>
      <div style="color:var(--dim);font-size:11px" id="elapsed-time">Elapsed: 0s</div>
    </div>

    <!-- Findings -->
    <div class="findings-section">
      <div class="section-title">
        <span>🔴 Live Findings</span>
        <span id="findings-count" style="color:var(--dim);font-size:12px">0 found</span>
      </div>
      <table>
        <thead><tr><th>Severity</th><th>Type</th><th>Detail</th><th>Time</th></tr></thead>
        <tbody id="findings-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Log Panel -->
  <div class="right">
    <div class="log-panel">
      <div class="log-header">📋 Live Log</div>
      <div class="log-body" id="log-body"></div>
    </div>
  </div>
</div>

<script>
let pollInterval = null;
let elapsedInterval = null;
let startTime = null;

document.getElementById('scan-mode').addEventListener('change', function() {
  document.getElementById('custom-modules').style.display =
    this.value === '99' ? 'block' : 'none';
});

async function startScan() {
  const target = document.getElementById('target-input').value.trim();
  const mode   = document.getElementById('scan-mode').value;
  const custom = document.getElementById('custom-input').value.trim();
  if (!target) { alert('Enter target!'); return; }
  await fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({target, mode, custom})
  });
  startTime = Date.now();
  startPolling();
}

async function stopScan() {
  await fetch('/api/stop', {method:'POST'});
}

async function downloadReport() {
  window.open('/api/report', '_blank');
}

function startPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(updateDashboard, 1000);
  elapsedInterval = setInterval(() => {
    if (startTime) {
      const sec = Math.floor((Date.now() - startTime) / 1000);
      document.getElementById('elapsed-time').textContent = `Elapsed: ${sec}s`;
    }
  }, 1000);
}

async function updateDashboard() {
  try {
    const r    = await fetch('/api/state');
    const data = await r.json();

    // Status
    const badge = document.getElementById('status-badge');
    badge.className = `status-badge status-${data.status}`;
    badge.textContent = `⬤ ${data.status.toUpperCase()}`;

    // Progress
    const pct = data.progress || 0;
    document.getElementById('progress-fill').style.width = pct + '%';
    document.getElementById('progress-pct').textContent  = pct + '%';
    document.getElementById('module-name').textContent   = data.current_module || 'Idle';

    // Stats
    const s = data.stats || {};
    document.getElementById('stat-subdomains').textContent = s.subdomains || 0;
    document.getElementById('stat-ports').textContent      = s.open_ports || 0;
    document.getElementById('stat-cves').textContent       = s.cves || 0;
    document.getElementById('stat-vulns').textContent      = s.web_vulns || 0;
    document.getElementById('stat-emails').textContent     = s.emails || 0;
    document.getElementById('stat-secrets').textContent    = s.secrets || 0;
    document.getElementById('stat-exploits').textContent   = s.exploits || 0;
    document.getElementById('stat-risk').textContent       = s.risk_score || '—';

    // Findings
    const tbody = document.getElementById('findings-body');
    tbody.innerHTML = '';
    document.getElementById('findings-count').textContent = `${(data.findings||[]).length} found`;
    for (const f of (data.findings || []).slice(-50).reverse()) {
      const sev = (f.severity || 'info').toLowerCase();
      tbody.innerHTML += `
        <tr>
          <td><span class="badge ${sev}">${sev.toUpperCase()}</span></td>
          <td class="dim">${f.type||''}</td>
          <td class="mono" style="max-width:300px;overflow:hidden;text-overflow:ellipsis">${f.detail||''}</td>
          <td class="dim" style="white-space:nowrap">${f.time||''}</td>
        </tr>`;
    }

    // Log
    const logBody = document.getElementById('log-body');
    logBody.innerHTML = '';
    for (const entry of (data.log || []).slice(-100).reverse()) {
      logBody.innerHTML += `
        <div class="log-entry ${entry.level}">
          <span class="log-time">${entry.time}</span>${entry.msg}
        </div>`;
    }

    if (data.status === 'complete' || data.status === 'idle') {
      if (pollInterval && data.status === 'complete') {
        clearInterval(pollInterval);
        clearInterval(elapsedInterval);
      }
    }
  } catch(e) {
    console.error('Poll error:', e);
  }
}

// Start polling immediately
updateDashboard();
setInterval(updateDashboard, 2000);
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logging

    def _send_json(self, data: Dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/state":
            with _state_lock:
                self._send_json(dict(_scan_state))
        elif parsed.path == "/api/report":
            # Return latest HTML report
            report_dir = "reports"
            reports = [f for f in os.listdir(report_dir)
                      if f.endswith(".html")] if os.path.exists(report_dir) else []
            if reports:
                latest = sorted(reports)[-1]
                with open(os.path.join(report_dir, latest), "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Disposition",
                               f'attachment; filename="{latest}"')
                self.end_headers()
                self.wfile.write(content)
            else:
                self._send_json({"error": "No report available"}, 404)
        else:
            self._send_html(DASHBOARD_HTML)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length)) if length else {}

        if parsed.path == "/api/start":
            _update_state(
                target=body.get("target", ""),
                status="running",
                progress=0,
                findings=[],
                log=[],
                stats={},
                started=time.strftime("%Y-%m-%d %H:%M:%S"),
            )
            _add_log(f"Scan started: {body.get('target','')} mode={body.get('mode','')}", "info")
            self._send_json({"status": "started"})

        elif parsed.path == "/api/stop":
            _update_state(status="idle", progress=0, current_module="Stopped")
            _add_log("Scan stopped by user", "warning")
            self._send_json({"status": "stopped"})

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()


def start_dashboard(port: int = DASHBOARD_PORT, open_browser: bool = True) -> HTTPServer:
    """Start the web dashboard server."""
    server = HTTPServer((DASHBOARD_HOST, port), DashboardHandler)
    url    = f"http://{DASHBOARD_HOST}:{port}"
    success(f"Dashboard running: {url}")

    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    return server


def update_dashboard_progress(module: str, progress: int, stats: Dict = None):
    """Update dashboard from main scan loop."""
    _update_state(
        current_module=module,
        progress=progress,
    )
    if stats:
        with _state_lock:
            _scan_state["stats"].update(stats)
    _add_log(f"Running: {module}", "info")


def add_dashboard_finding(finding_type: str, severity: str, detail: str):
    """Add a finding to the dashboard."""
    _add_finding({
        "type":     finding_type,
        "severity": severity,
        "detail":   detail[:100],
        "time":     time.strftime("%H:%M:%S"),
    })
    _add_log(f"[{severity.upper()}] {finding_type}: {detail[:60]}", "found")


def run_web_dashboard() -> Dict:
    """Start dashboard and keep alive."""
    section_header("Web Dashboard", "Ultra Live Scan Monitor")
    port = DASHBOARD_PORT

    # Find free port
    import socket
    for p in range(8765, 8800):
        try:
            s = socket.socket()
            s.bind(("127.0.0.1", p))
            s.close()
            port = p
            break
        except Exception:
            pass

    server = start_dashboard(port)
    info(f"Dashboard: http://{DASHBOARD_HOST}:{port}")
    info("Press Ctrl+C to stop dashboard")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        info("Dashboard stopped")

    return {"port": port, "url": f"http://{DASHBOARD_HOST}:{port}"}
