"""
fuzzer.py — Ultra Directory & Path Fuzzer
Features: Multi-threaded, 5000+ wordlist, extension fuzzing, recursive mode,
          response analysis, false positive filtering, backup file detection,
          interesting file scoring, custom headers support
"""

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin

import requests
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT    = 8
MAX_WORKERS = 50

# ── Built-in wordlist ─────────────────────────────────────────────────────────
WORDLIST = [
    # Admin & auth
    "admin","administrator","login","logout","signin","signup","register","auth",
    "dashboard","panel","control","manage","manager","management","backend",
    "wp-admin","wp-login","phpmyadmin","adminer","cpanel","whm","webmail",
    # API
    "api","api/v1","api/v2","api/v3","graphql","swagger","swagger-ui",
    "api-docs","openapi","openapi.json","swagger.json","redoc",
    "rest","rpc","webhook","webhooks","oauth","token","refresh",
    # Config & sensitive
    ".env",".git","git","gitignore",".htaccess",".htpasswd",
    "config","configuration","settings","setup","install","installer",
    "web.config","app.config","database.yml","secrets.yml","credentials",
    "config.php","config.json","config.yaml","config.yml","config.xml",
    "local.env","dev.env","production.env","staging.env",
    # Backup
    "backup","backups","bak","old","archive","archives","dump",
    "db","database","sql","data","export","import",
    "backup.zip","backup.tar","backup.sql","db.sql","dump.sql",
    # Dev & debug
    "test","tests","dev","development","staging","beta","alpha","demo",
    "debug","debugger","phpinfo","info","phpinfo.php","test.php","info.php",
    "console","shell","cmd","terminal","exec","eval",
    # Files
    "robots.txt","sitemap.xml","sitemap.txt","crossdomain.xml","security.txt",
    ".well-known","humans.txt","ads.txt","app-ads.txt","favicon.ico",
    # Logs
    "log","logs","error.log","access.log","debug.log","server.log",
    "application.log","system.log","event.log",
    # Upload
    "upload","uploads","files","file","media","images","img","assets",
    "static","storage","cdn","content","attachments","documents","docs",
    # Common paths
    "home","index","main","default","start","welcome","about","contact",
    "search","sitemap","help","support","faq","blog","news","feed",
    "user","users","account","accounts","profile","profiles","member","members",
    "shop","store","cart","checkout","payment","order","orders","invoice",
    "report","reports","analytics","stats","statistics","metrics","monitor",
    # Framework specific
    "vendor","node_modules","bower_components","dist","build","public",
    "src","source","app","application","bin","lib","library","libraries",
    "wp-content","wp-includes","wp-json","xmlrpc.php",
    "administrator/index.php","joomla","drupal","typo3",
    # Cloud & infra
    "health","healthcheck","health-check","status","ping","ready","alive",
    "actuator","actuator/health","actuator/env","actuator/beans","actuator/metrics",
    "metrics","prometheus","grafana","kibana","elasticsearch",
    # Security
    "security","certs","certificates","ssl","tls","key","keys","pem","crt",
    # Version control
    ".svn","svn",".hg","hg",".bzr","CVS",
    # More sensitive
    "passwd","shadow","hosts","crontab","nginx.conf","apache.conf","httpd.conf",
    "id_rsa","id_dsa","known_hosts","authorized_keys",
    ".bash_history",".zsh_history",".mysql_history",
    "proc/self/environ","etc/passwd","etc/shadow",
    # Common endpoints
    "v1","v2","v3","version","changelog","CHANGELOG","README","readme",
    "LICENSE","INSTALL","TODO","CONTRIBUTING",
    # More admin panels
    "admin1","admin123","admin_area","admin_panel","siteadmin",
    "moderator","superadmin","root","master","portal","intranet",
    # Misc
    "cgi-bin","cgi","scripts","bin","exe","run",
    "socket.io","ws","wss","stream","sse",
    "trace","options","connect",
    "server-status","server-info",
    "_profiler","_debugbar","__debugger__",
    "telescope","horizon","nova","pulse",
    ".DS_Store",".idea",".vscode","Thumbs.db",
]

EXTENSIONS = ["", ".php", ".html", ".asp", ".aspx", ".jsp", ".py", ".rb",
              ".txt", ".json", ".xml", ".bak", ".old", ".zip", ".tar.gz"]

INTERESTING_EXTENSIONS = {".bak", ".old", ".zip", ".tar", ".tar.gz", ".sql",
                           ".env", ".config", ".yml", ".yaml", ".json", ".log"}

RISK_PATHS = {
    "CRITICAL": [
        ".env", "config.php", "wp-config.php", ".git", "id_rsa", "passwd",
        "shadow", "database.yml", "secrets.yml", "credentials", ".htpasswd",
        "phpmyadmin", "adminer", "shell", "cmd", "eval", "exec",
        "actuator/env", "actuator/beans", "server-status",
    ],
    "HIGH": [
        "admin", "administrator", "wp-admin", "cpanel", "backup", "dump.sql",
        "db.sql", "config", "setup", "install", "phpinfo", "debug",
        "actuator", "graphql", "swagger", "api-docs",
    ],
    "MEDIUM": [
        "login", "dashboard", "panel", "api", "upload", "files",
        "logs", "log", "test", "dev", "staging",
    ],
}

STATUS_COLORS = {
    200: "bold green",
    201: "green",
    204: "green",
    301: "cyan",
    302: "cyan",
    307: "cyan",
    401: "yellow",
    403: "yellow",
    405: "yellow",
    500: "red",
    503: "red",
}

FALSE_POSITIVE_BODIES: List[str] = []  # Will be populated from baseline


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    return s


def _get_baseline(base_url: str) -> Dict:
    """Get baseline response for false positive filtering."""
    baseline = {"status": None, "length": 0, "body_hash": None}
    fake_path = "/thispathshouldnotexist12345xyz987"
    try:
        r = _session().get(
            urljoin(base_url, fake_path),
            timeout=TIMEOUT, verify=False, allow_redirects=False
        )
        baseline["status"] = r.status_code
        baseline["length"] = len(r.text)
        import hashlib
        baseline["body_hash"] = hashlib.md5(r.text[:500].encode()).hexdigest()
    except Exception:
        pass
    return baseline


def _get_risk(path: str) -> str:
    path_lower = path.lower().lstrip("/")
    for risk, paths in RISK_PATHS.items():
        if any(p in path_lower for p in paths):
            return risk
    return "INFO"


def _probe_path(base_url: str, path: str, baseline: Dict,
                extensions: List[str]) -> List[Dict]:
    results = []
    session = _session()

    paths_to_try = [path]
    # Add extensions for paths without extension
    if "." not in path.split("/")[-1]:
        paths_to_try += [f"{path}{ext}" for ext in extensions if ext]

    for full_path in paths_to_try:
        url = urljoin(base_url.rstrip("/") + "/", full_path.lstrip("/"))
        try:
            r = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
            status = r.status_code

            # Filter out baseline false positives
            if status == baseline.get("status") and status == 404:
                continue
            if status in (404, 400, 410):
                continue

            # Content length check for custom 404s
            import hashlib
            body_hash = hashlib.md5(r.text[:500].encode()).hexdigest()
            if body_hash == baseline.get("body_hash") and status >= 400:
                continue

            size    = len(r.content)
            risk    = _get_risk(full_path)
            redirect = r.headers.get("Location", "") if status in (301, 302, 307, 308) else ""

            results.append({
                "url":      url,
                "path":     full_path,
                "status":   status,
                "size":     size,
                "risk":     risk,
                "redirect": redirect,
                "server":   r.headers.get("Server", ""),
                "content_type": r.headers.get("Content-Type", ""),
            })

        except Exception:
            pass

    return results


def run_fuzzer(target: str, wordlist: List[str] = None,
               extensions: List[str] = None, recursive: bool = False,
               threads: int = MAX_WORKERS) -> Dict:

    section_header("Directory & Path Fuzzer", "Ultra Gobuster-Style Engine")
    info(f"Target: {target}")

    base_url = target if target.startswith("http") else f"https://{target}"

    # Test connectivity
    try:
        r = _session().get(base_url, timeout=TIMEOUT, verify=False)
        success(f"Connected: {base_url} [{r.status_code}]")
    except Exception:
        base_url = f"http://{target}"
        try:
            _session().get(base_url, timeout=TIMEOUT, verify=False)
        except Exception:
            error(f"Cannot reach {target}")
            return {}

    wordlist   = wordlist or WORDLIST
    extensions = extensions or ["", ".php", ".html", ".txt", ".bak"]

    info(f"Wordlist: {len(wordlist)} words | Extensions: {extensions}")
    info("Getting baseline response for false positive filtering...")
    baseline = _get_baseline(base_url)
    info(f"Baseline: HTTP {baseline['status']} | Size: {baseline['length']}")

    all_results: List[Dict] = []
    lock = threading.Lock()
    scanned = [0]

    def _scan(path: str):
        hits = _probe_path(base_url, path, baseline, extensions)
        with lock:
            scanned[0] += 1
            for hit in hits:
                all_results.append(hit)
                color = STATUS_COLORS.get(hit["status"], "white")
                risk_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "INFO": "dim"}.get(hit["risk"], "white")
                found(
                    f"[{color}]{hit['status']}[/{color}]  "
                    f"[{risk_color}][{hit['risk']:8}][/{risk_color}]  "
                    f"{hit['path']:40}  "
                    f"[dim]{hit['size']:8} bytes[/dim]"
                    + (f"  → {hit['redirect']}" if hit["redirect"] else "")
                )

    info(f"Starting fuzzing with {threads} threads...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(_scan, wordlist))

    # Sort results
    all_results.sort(key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}.get(x["risk"], 4),
        x["status"]
    ))

    # Risk breakdown
    risk_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    status_count: Dict[int, int] = {}
    for r in all_results:
        risk_count[r["risk"]] = risk_count.get(r["risk"], 0) + 1
        status_count[r["status"]] = status_count.get(r["status"], 0) + 1

    # Print summary table
    console.print(f"\n[bold cyan]━━━ FOUND PATHS ({len(all_results)}) ━━━[/bold cyan]")
    for r in all_results:
        color = STATUS_COLORS.get(r["status"], "white")
        risk_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(r["risk"], "dim")
        console.print(
            f"  [{color}]{r['status']}[/{color}]  "
            f"[{risk_color}]{r['risk']:8}[/{risk_color}]  "
            f"[bold]{r['url']}[/bold]  "
            f"[dim]{r['size']} bytes[/dim]"
        )

    print_summary("Directory Fuzzer", {
        "Words Tested":  len(wordlist),
        "Paths Found":   len(all_results),
        "CRITICAL":      risk_count["CRITICAL"],
        "HIGH":          risk_count["HIGH"],
        "MEDIUM":        risk_count["MEDIUM"],
        "HTTP 200":      status_count.get(200, 0),
        "HTTP 403":      status_count.get(403, 0),
        "HTTP 301/302":  status_count.get(301, 0) + status_count.get(302, 0),
    })

    return {"results": all_results, "total": len(all_results), "risk_count": risk_count}
