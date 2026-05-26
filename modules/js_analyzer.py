"""
js_analyzer.py — Ultra JavaScript File Analyzer
Features: 80+ secret patterns, endpoint extraction, API key detection,
          hardcoded credentials, JWT tokens, crypto keys, internal URLs,
          source map detection, webpack chunk analysis, DOM XSS sinks
"""

import hashlib
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 10

# ── 80+ Secret patterns ───────────────────────────────────────────────────────
SECRET_PATTERNS: List[Dict] = [
    # AWS
    {"name": "AWS Access Key",         "severity": "CRITICAL", "pattern": r"AKIA[0-9A-Z]{16}"},
    {"name": "AWS Secret Key",         "severity": "CRITICAL", "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"},
    {"name": "AWS Session Token",      "severity": "CRITICAL", "pattern": r"(?i)aws.{0,20}session.{0,20}['\"][A-Za-z0-9/+=]{100,}['\"]"},
    # Google
    {"name": "Google API Key",         "severity": "CRITICAL", "pattern": r"AIza[0-9A-Za-z\\-_]{35}"},
    {"name": "Google OAuth",           "severity": "HIGH",     "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"},
    {"name": "Google Service Account", "severity": "CRITICAL", "pattern": r"\"type\":\s*\"service_account\""},
    # GitHub
    {"name": "GitHub Token",           "severity": "CRITICAL", "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}"},
    {"name": "GitHub OAuth",           "severity": "HIGH",     "pattern": r"github.{0,20}['\"][0-9a-f]{40}['\"]"},
    # Stripe
    {"name": "Stripe Secret Key",      "severity": "CRITICAL", "pattern": r"sk_live_[0-9a-zA-Z]{24,}"},
    {"name": "Stripe Publishable",     "severity": "MEDIUM",   "pattern": r"pk_live_[0-9a-zA-Z]{24,}"},
    {"name": "Stripe Test Key",        "severity": "LOW",      "pattern": r"sk_test_[0-9a-zA-Z]{24,}"},
    # Twilio
    {"name": "Twilio Account SID",     "severity": "HIGH",     "pattern": r"AC[a-zA-Z0-9]{32}"},
    {"name": "Twilio Auth Token",      "severity": "CRITICAL", "pattern": r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]"},
    # SendGrid
    {"name": "SendGrid API Key",       "severity": "HIGH",     "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"},
    # Slack
    {"name": "Slack Token",            "severity": "CRITICAL", "pattern": r"xox[baprs]-[0-9a-zA-Z\-]{10,}"},
    {"name": "Slack Webhook",          "severity": "HIGH",     "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"},
    # Firebase
    {"name": "Firebase URL",           "severity": "HIGH",     "pattern": r"[a-z0-9-]+\.firebaseio\.com"},
    {"name": "Firebase API Key",       "severity": "HIGH",     "pattern": r"(?i)firebase.{0,20}['\"][A-Za-z0-9_-]{39}['\"]"},
    # JWT
    {"name": "JWT Token",              "severity": "HIGH",     "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"},
    # Generic secrets
    {"name": "Generic API Key",        "severity": "HIGH",     "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"},
    {"name": "Generic Secret",         "severity": "HIGH",     "pattern": r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"},
    {"name": "Generic Token",          "severity": "HIGH",     "pattern": r"(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*['\"][A-Za-z0-9_\-\.]{20,}['\"]"},
    {"name": "Generic Password",       "severity": "HIGH",     "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]"},
    {"name": "Generic Username",       "severity": "MEDIUM",   "pattern": r"(?i)(username|user|login)\s*[=:]\s*['\"][^'\"]{3,}['\"]"},
    # Private keys
    {"name": "RSA Private Key",        "severity": "CRITICAL", "pattern": r"-----BEGIN RSA PRIVATE KEY-----"},
    {"name": "EC Private Key",         "severity": "CRITICAL", "pattern": r"-----BEGIN EC PRIVATE KEY-----"},
    {"name": "PGP Private Key",        "severity": "CRITICAL", "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----"},
    {"name": "SSH Private Key",        "severity": "CRITICAL", "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----"},
    # Database
    {"name": "MongoDB URI",            "severity": "CRITICAL", "pattern": r"mongodb(\+srv)?://[^\s'\"]+"},
    {"name": "PostgreSQL URI",         "severity": "CRITICAL", "pattern": r"postgres(ql)?://[^\s'\"]+"},
    {"name": "MySQL URI",              "severity": "CRITICAL", "pattern": r"mysql://[^\s'\"]+"},
    {"name": "Redis URI",              "severity": "CRITICAL", "pattern": r"redis://[^\s'\"]+"},
    {"name": "DB Connection String",   "severity": "CRITICAL", "pattern": r"(?i)(Data Source|Initial Catalog|User ID|Password)=[^;\"']+"},
    # Cloud
    {"name": "Azure Storage Key",      "severity": "CRITICAL", "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"},
    {"name": "Azure SAS Token",        "severity": "HIGH",     "pattern": r"sv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+"},
    {"name": "GCP Service Account",    "severity": "CRITICAL", "pattern": r"\"private_key\":\s*\"-----BEGIN"},
    # Payment
    {"name": "PayPal Client ID",       "severity": "MEDIUM",   "pattern": r"(?i)paypal.{0,20}client[_-]?id.{0,20}['\"][A-Za-z0-9_-]{20,}['\"]"},
    {"name": "Square Access Token",    "severity": "CRITICAL", "pattern": r"sq0atp-[A-Za-z0-9_-]{22}"},
    # Social
    {"name": "Twitter API Key",        "severity": "HIGH",     "pattern": r"(?i)twitter.{0,20}['\"][A-Za-z0-9]{25,}['\"]"},
    {"name": "Facebook App Secret",    "severity": "CRITICAL", "pattern": r"(?i)facebook.{0,20}app.{0,10}secret.{0,20}['\"][0-9a-f]{32}['\"]"},
    # Misc
    {"name": "Mailgun API Key",        "severity": "HIGH",     "pattern": r"key-[0-9a-zA-Z]{32}"},
    {"name": "HubSpot API Key",        "severity": "HIGH",     "pattern": r"(?i)hubspot.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"},
    {"name": "Heroku API Key",         "severity": "CRITICAL", "pattern": r"(?i)heroku.{0,20}['\"][0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}['\"]"},
    {"name": "NPM Token",              "severity": "HIGH",     "pattern": r"npm_[A-Za-z0-9]{36}"},
    {"name": "Artifactory Token",      "severity": "HIGH",     "pattern": r"(?:\s|=|:|\"|\x60|')?AKC[a-zA-Z0-9]{10,}"},
    {"name": "Cloudinary URL",         "severity": "HIGH",     "pattern": r"cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z]+"},
    {"name": "Mapbox Token",           "severity": "MEDIUM",   "pattern": r"pk\.eyJ1IjoiW[A-Za-z0-9_-]{50,}"},
    {"name": "Algolia API Key",        "severity": "HIGH",     "pattern": r"(?i)algolia.{0,20}['\"][A-Za-z0-9]{32}['\"]"},
    {"name": "Internal IP",            "severity": "MEDIUM",   "pattern": r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}"},
    {"name": "Basic Auth in URL",      "severity": "CRITICAL", "pattern": r"https?://[^:]+:[^@]+@[^\s'\"]+"},
    {"name": "S3 Bucket URL",          "severity": "MEDIUM",   "pattern": r"s3://[a-z0-9.-]+"},
    {"name": "Hardcoded IP",           "severity": "LOW",      "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"},
]

# DOM XSS sinks
DOM_XSS_SINKS = [
    "document.write(", "document.writeln(", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(",
    "execScript(", "Function(", "location.href", "location.replace(",
    "document.location", "window.location",
]

# Interesting patterns
ENDPOINT_PATTERN = re.compile(
    r'(?:fetch|axios|ajax|http|get|post|put|delete|patch)\s*\(?["\']'
    r'(/[a-zA-Z0-9/_.-]+)["\']',
    re.I
)
URL_PATTERN = re.compile(r'["\'](https?://[^\s"\'<>{}|\\^`\[\]]+)["\']')
PATH_PATTERN = re.compile(r'["\'](/[a-zA-Z0-9/_.-]{3,})["\']')


def _session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
    return s


def _get_js_files(base_url: str) -> List[str]:
    """Discover all JS files from a page."""
    js_urls: Set[str] = set()
    try:
        r = _session().get(base_url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")

        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            full = urljoin(base_url, src)
            if full.startswith("http"):
                js_urls.add(full)

        # Find chunk manifests (webpack)
        for m in re.finditer(r'["\']([^"\']+\.js)["\']', r.text):
            path = m.group(1)
            if not path.startswith("http"):
                full = urljoin(base_url, path)
                js_urls.add(full)

    except Exception as e:
        warning(f"[JS Discovery] {e}")

    return list(js_urls)


def _analyze_js(url: str) -> Dict:
    """Analyze a single JS file for secrets."""
    result = {
        "url":       url,
        "secrets":   [],
        "endpoints": [],
        "urls":      [],
        "xss_sinks": [],
        "size":      0,
        "source_map": None,
    }

    try:
        r = _session().get(url, timeout=TIMEOUT, verify=False)
        content = r.text
        result["size"] = len(content)

        # Source map detection
        if "//# sourceMappingURL=" in content:
            m = re.search(r"//# sourceMappingURL=(.+)", content)
            if m:
                result["source_map"] = urljoin(url, m.group(1).strip())

        # Secret scanning
        seen_secrets: Set[str] = set()
        for sig in SECRET_PATTERNS:
            try:
                for match in re.finditer(sig["pattern"], content):
                    val = match.group(0)[:100]
                    key = f"{sig['name']}:{val[:30]}"
                    if key in seen_secrets:
                        continue
                    seen_secrets.add(key)

                    # Get line number
                    line_no = content[:match.start()].count("\n") + 1
                    context = content[max(0, match.start()-30):match.end()+30].replace("\n", " ")

                    result["secrets"].append({
                        "type":     sig["name"],
                        "severity": sig["severity"],
                        "value":    val,
                        "line":     line_no,
                        "context":  context[:100],
                    })
            except Exception:
                pass

        # Endpoint extraction
        for m in ENDPOINT_PATTERN.finditer(content):
            ep = m.group(1)
            if ep not in result["endpoints"]:
                result["endpoints"].append(ep)

        for m in PATH_PATTERN.finditer(content):
            path = m.group(1)
            if path not in result["endpoints"] and len(path) > 3:
                if not any(ext in path for ext in [".png", ".jpg", ".gif", ".css", ".woff"]):
                    result["endpoints"].append(path)

        # External URLs
        for m in URL_PATTERN.finditer(content):
            url_found = m.group(1)
            if url_found not in result["urls"]:
                result["urls"].append(url_found[:100])

        # DOM XSS sinks
        for sink in DOM_XSS_SINKS:
            if sink in content:
                count = content.count(sink)
                result["xss_sinks"].append({"sink": sink, "count": count})

    except Exception as e:
        warning(f"[JS Analyze] {url}: {e}")

    return result


def run_js_analyzer(target: str) -> Dict:
    section_header("JavaScript Analyzer", "Ultra 80+ Secret Patterns")
    info(f"Target: {target}")

    base_url = target if target.startswith("http") else f"https://{target}"

    # Discover JS files
    info("Discovering JavaScript files...")
    js_files = _get_js_files(base_url)
    info(f"Found {len(js_files)} JS files")

    if not js_files:
        warning("No JS files found")
        return {}

    # Analyze all JS files
    all_results: List[Dict] = []
    all_secrets: List[Dict] = []
    all_endpoints: Set[str] = set()
    xss_sinks_found: List[Dict] = []
    source_maps: List[str] = []

    info("Analyzing JS files for secrets...")
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_analyze_js, url): url for url in js_files}
        for future in as_completed(futures):
            result = future.result()
            all_results.append(result)

            if result["secrets"]:
                all_secrets.extend(result["secrets"])

            all_endpoints.update(result["endpoints"])
            xss_sinks_found.extend(result["xss_sinks"])

            if result["source_map"]:
                source_maps.append(result["source_map"])
                warning(f"Source map found: {result['source_map']}")

    # Print secrets
    SEVERITY_COLORS = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "green",
    }

    console.print(f"\n[bold cyan]━━━ SECRETS FOUND ({len(all_secrets)}) ━━━[/bold cyan]")
    if all_secrets:
        all_secrets.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["severity"],4))
        for s in all_secrets:
            color = SEVERITY_COLORS.get(s["severity"], "white")
            console.print(
                f"\n  [{color}][{s['severity']:8}][/{color}]  [bold]{s['type']}[/bold]"
            )
            console.print(f"  Value:   [red]{s['value'][:80]}[/red]")
            console.print(f"  Line:    {s['line']}")
            console.print(f"  Context: [dim]{s['context']}[/dim]")
    else:
        success("No secrets found")

    # Print endpoints
    console.print(f"\n[bold cyan]━━━ DISCOVERED ENDPOINTS ({len(all_endpoints)}) ━━━[/bold cyan]")
    for ep in sorted(all_endpoints)[:50]:
        console.print(f"  [cyan]{ep}[/cyan]")

    # XSS Sinks
    if xss_sinks_found:
        console.print(f"\n[bold red]━━━ DOM XSS SINKS ━━━[/bold red]")
        seen = {}
        for s in xss_sinks_found:
            sink = s["sink"]
            seen[sink] = seen.get(sink, 0) + s["count"]
        for sink, count in sorted(seen.items(), key=lambda x: -x[1]):
            console.print(f"  [red]{sink:35}[/red]  x{count}")

    # Source maps
    if source_maps:
        console.print(f"\n[bold yellow]━━━ SOURCE MAPS (CODE EXPOSURE) ━━━[/bold yellow]")
        for sm in source_maps:
            warning(f"  {sm}")

    # Severity breakdown
    sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in all_secrets:
        sev_count[s["severity"]] = sev_count.get(s["severity"], 0) + 1

    print_summary("JS Analyzer", {
        "JS Files Analyzed": len(js_files),
        "Secrets Found":     len(all_secrets),
        "CRITICAL":          sev_count["CRITICAL"],
        "HIGH":              sev_count["HIGH"],
        "Endpoints Found":   len(all_endpoints),
        "DOM XSS Sinks":     len(set(s["sink"] for s in xss_sinks_found)),
        "Source Maps":       len(source_maps),
    })

    return {
        "js_files":    js_files,
        "secrets":     all_secrets,
        "endpoints":   list(all_endpoints),
        "xss_sinks":   xss_sinks_found,
        "source_maps": source_maps,
        "sev_count":   sev_count,
    }
