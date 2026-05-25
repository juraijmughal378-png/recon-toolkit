"""
dorking.py — Ultra Google Dorking Engine
Features: 80+ dorks across 12 categories, Bing/DuckDuckGo fallback,
          smart URL building, result deduplication, severity rating,
          custom dork support, export-ready output
"""

import re
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT    = 12
DELAY      = 2.0   # Be respectful — avoid rate limiting
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/120.0.0.0 Safari/537.36")

# ── Dork definitions ─────────────────────────────────────────────────────────
DORK_CATEGORIES: Dict[str, List[Tuple[str, str]]] = {

    "Exposed Files & Directories": [
        ('site:{domain} intitle:"index of"',                            "HIGH"),
        ('site:{domain} intitle:"index of" password',                   "CRITICAL"),
        ('site:{domain} intitle:"index of" backup',                     "HIGH"),
        ('site:{domain} intitle:"index of" .git',                       "CRITICAL"),
        ('site:{domain} intitle:"index of" .env',                       "CRITICAL"),
        ('site:{domain} intitle:"index of" config',                     "HIGH"),
        ('site:{domain} filetype:log',                                   "HIGH"),
        ('site:{domain} filetype:bak',                                   "HIGH"),
        ('site:{domain} filetype:sql',                                   "CRITICAL"),
        ('site:{domain} filetype:txt password',                          "CRITICAL"),
        ('site:{domain} filetype:xml password',                          "HIGH"),
        ('site:{domain} filetype:conf',                                  "HIGH"),
        ('site:{domain} filetype:ini',                                   "MEDIUM"),
        ('site:{domain} filetype:cfg',                                   "MEDIUM"),
        ('site:{domain} filetype:env',                                   "CRITICAL"),
    ],

    "Sensitive Data Exposure": [
        ('site:{domain} "password" filetype:txt',                       "CRITICAL"),
        ('site:{domain} "password" filetype:log',                       "CRITICAL"),
        ('site:{domain} "api_key" OR "apikey" OR "api key"',            "CRITICAL"),
        ('site:{domain} "secret_key" OR "secret key"',                  "CRITICAL"),
        ('site:{domain} "access_token" OR "auth_token"',                "CRITICAL"),
        ('site:{domain} "AWS_ACCESS_KEY" OR "AKIA"',                    "CRITICAL"),
        ('site:{domain} "private_key" OR "BEGIN RSA"',                  "CRITICAL"),
        ('site:{domain} "db_password" OR "database_password"',          "CRITICAL"),
        ('site:{domain} "smtp_password" OR "mail_password"',            "HIGH"),
        ('site:{domain} "connection string" OR "connectionstring"',     "HIGH"),
    ],

    "Admin & Login Pages": [
        ('site:{domain} inurl:admin',                                    "MEDIUM"),
        ('site:{domain} inurl:login',                                    "MEDIUM"),
        ('site:{domain} inurl:dashboard',                                "MEDIUM"),
        ('site:{domain} inurl:wp-admin',                                 "HIGH"),
        ('site:{domain} inurl:administrator',                            "MEDIUM"),
        ('site:{domain} inurl:portal',                                   "MEDIUM"),
        ('site:{domain} inurl:cpanel',                                   "HIGH"),
        ('site:{domain} inurl:phpmyadmin',                               "CRITICAL"),
        ('site:{domain} inurl:adminer',                                  "HIGH"),
        ('site:{domain} intitle:"admin panel"',                         "MEDIUM"),
        ('site:{domain} intitle:"control panel"',                       "MEDIUM"),
        ('site:{domain} inurl:/admin/login',                             "MEDIUM"),
    ],

    "Error & Debug Pages": [
        ('site:{domain} "PHP Parse error"',                             "HIGH"),
        ('site:{domain} "PHP Warning"',                                  "MEDIUM"),
        ('site:{domain} "SQL syntax"',                                   "CRITICAL"),
        ('site:{domain} "MySQL server version"',                         "HIGH"),
        ('site:{domain} "Warning: mysql_connect"',                       "HIGH"),
        ('site:{domain} "Fatal error" filetype:php',                    "HIGH"),
        ('site:{domain} "stack trace"',                                  "MEDIUM"),
        ('site:{domain} "Traceback (most recent"',                      "HIGH"),
        ('site:{domain} "ORA-" OR "Oracle error"',                      "HIGH"),
        ('site:{domain} "ODBC Driver" error',                           "HIGH"),
        ('site:{domain} inurl:debug',                                    "HIGH"),
        ('site:{domain} inurl:test',                                     "MEDIUM"),
    ],

    "Cloud & Infrastructure": [
        ('site:{domain} "s3.amazonaws.com"',                            "HIGH"),
        ('site:{domain} "blob.core.windows.net"',                       "HIGH"),
        ('site:{domain} "storage.googleapis.com"',                      "HIGH"),
        ('site:{domain} "firebase.io"',                                  "HIGH"),
        ('site:{domain} inurl:s3 bucket',                               "HIGH"),
        ('site:s3.amazonaws.com "{domain}"',                            "HIGH"),
        ('site:{domain} "heroku" OR "herokuapp"',                       "LOW"),
        ('site:{domain} "pastebin.com"',                                 "MEDIUM"),
    ],

    "Source Code & Version Control": [
        ('site:{domain} inurl:.git',                                     "CRITICAL"),
        ('site:{domain} inurl:.svn',                                     "HIGH"),
        ('site:{domain} inurl:.hg',                                      "HIGH"),
        ('site:{domain} filetype:py "def " OR "import "',               "MEDIUM"),
        ('site:{domain} filetype:php "<?php"',                          "MEDIUM"),
        ('site:{domain} filetype:js "require(" OR "import "',           "MEDIUM"),
        ('"github.com" "{domain}"',                                      "MEDIUM"),
        ('"gitlab.com" "{domain}"',                                      "MEDIUM"),
    ],

    "Network & Technology": [
        ('site:{domain} inurl:wp-content',                               "LOW"),
        ('site:{domain} inurl:wp-includes',                              "LOW"),
        ('site:{domain} intitle:"phpinfo()"',                           "HIGH"),
        ('site:{domain} intitle:"Grafana"',                             "MEDIUM"),
        ('site:{domain} intitle:"Kibana"',                              "HIGH"),
        ('site:{domain} intitle:"Jenkins"',                             "HIGH"),
        ('site:{domain} intitle:"GitLab"',                              "MEDIUM"),
        ('site:{domain} intitle:"Jira"',                                "LOW"),
        ('site:{domain} intitle:"Confluence"',                          "LOW"),
        ('site:{domain} "robots.txt" disallow',                         "LOW"),
    ],

    "Email & User Data": [
        ('site:{domain} "@{domain}" filetype:xls OR filetype:csv',      "HIGH"),
        ('site:{domain} "email" filetype:xls',                          "HIGH"),
        ('site:{domain} "phone" filetype:xls OR filetype:csv',          "HIGH"),
        ('site:{domain} "employee" OR "staff" filetype:xls',            "MEDIUM"),
        ('"@{domain}" site:linkedin.com',                               "LOW"),
        ('"@{domain}" site:pastebin.com',                               "HIGH"),
    ],

    "Documents & Sensitive Files": [
        ('site:{domain} filetype:pdf',                                   "LOW"),
        ('site:{domain} filetype:docx confidential',                    "HIGH"),
        ('site:{domain} filetype:xlsx password',                        "CRITICAL"),
        ('site:{domain} filetype:pptx internal',                        "MEDIUM"),
        ('site:{domain} filetype:pdf "internal use only"',              "HIGH"),
        ('site:{domain} filetype:pdf "confidential"',                   "HIGH"),
    ],

    "Cameras & IoT": [
        ('site:{domain} intitle:"webcam"',                              "HIGH"),
        ('site:{domain} inurl:view/index.shtml',                        "HIGH"),
        ('site:{domain} intitle:"Network Camera"',                      "HIGH"),
        ('site:{domain} inurl:axis-cgi',                                "HIGH"),
    ],

    "API & Endpoints": [
        ('site:{domain} inurl:/api/',                                    "MEDIUM"),
        ('site:{domain} inurl:/v1/ OR inurl:/v2/',                      "MEDIUM"),
        ('site:{domain} inurl:swagger',                                  "MEDIUM"),
        ('site:{domain} inurl:api-docs',                                 "MEDIUM"),
        ('site:{domain} inurl:graphql',                                  "MEDIUM"),
        ('site:{domain} filetype:json "apikey"',                        "CRITICAL"),
        ('site:{domain} filetype:yaml "password"',                      "CRITICAL"),
    ],

    "Custom / Miscellaneous": [
        ('site:{domain} ext:action OR ext:struts',                      "HIGH"),
        ('site:{domain} "Directory listing"',                            "HIGH"),
        ('site:{domain} inurl:backup OR inurl:bkp OR inurl:bak',       "HIGH"),
        ('site:{domain} intitle:"400 Bad Request"',                     "LOW"),
        ('site:{domain} intitle:"500 Internal Server Error"',           "MEDIUM"),
        ('site:{domain} "Powered by" inurl:readme',                     "LOW"),
    ],
}

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}

# ── Search engines ────────────────────────────────────────────────────────────

def _build_google_url(query: str) -> str:
    q = urllib.parse.quote_plus(query)
    return f"https://www.google.com/search?q={q}&num=20&hl=en"


def _build_bing_url(query: str) -> str:
    q = urllib.parse.quote_plus(query)
    return f"https://www.bing.com/search?q={q}&count=20"


def _build_duckduckgo_url(query: str) -> str:
    q = urllib.parse.quote_plus(query)
    return f"https://duckduckgo.com/html/?q={q}"


def _parse_google_results(html: str) -> List[Dict]:
    results = []
    soup = BeautifulSoup(html, "html.parser")
    for g in soup.select("div.g"):
        a = g.find("a")
        title_el = g.find("h3")
        snippet_el = g.find("div", class_=re.compile(r"VwiC3b|s3v9rd|st"))
        if a and a.get("href", "").startswith("http"):
            results.append({
                "url":     a["href"],
                "title":   title_el.get_text() if title_el else "",
                "snippet": snippet_el.get_text() if snippet_el else "",
            })
    return results


def _parse_bing_results(html: str) -> List[Dict]:
    results = []
    soup = BeautifulSoup(html, "html.parser")
    for li in soup.select("li.b_algo"):
        a = li.find("a")
        snippet_el = li.find("p")
        if a and a.get("href", "").startswith("http"):
            results.append({
                "url":     a["href"],
                "title":   a.get_text(),
                "snippet": snippet_el.get_text() if snippet_el else "",
            })
    return results


def _search(query: str, engine: str = "google") -> List[Dict]:
    headers = {
        "User-Agent":      USER_AGENT,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept":          "text/html,application/xhtml+xml",
        "Referer":         "https://www.google.com/",
    }
    try:
        if engine == "bing":
            url = _build_bing_url(query)
        elif engine == "duckduckgo":
            url = _build_duckduckgo_url(query)
        else:
            url = _build_google_url(query)

        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        time.sleep(DELAY)

        if engine == "bing":
            return _parse_bing_results(r.text)
        else:
            return _parse_google_results(r.text)

    except Exception as e:
        warning(f"[Dork] Search failed ({engine}): {e}")
        return []


# ── Main entry point ─────────────────────────────────────────────────────────

def run_dorking(domain: str, categories: Optional[List[str]] = None,
                custom_dorks: Optional[List[str]] = None,
                engine: str = "google") -> Dict:

    section_header("Google Dorking Engine", f"Ultra 80+ Dorks | Engine: {engine.title()}")
    info(f"Target: {domain}  |  Engine: {engine}")

    all_results: List[Dict] = []
    dork_count = 0
    seen_urls: set = set()

    cats_to_run = {k: v for k, v in DORK_CATEGORIES.items()
                   if categories is None or k in categories}

    for category, dorks in cats_to_run.items():
        console.print(f"\n[bold magenta]▶ {category}[/bold magenta]")

        for dork_template, severity in dorks:
            query = dork_template.replace("{domain}", domain)
            dork_count += 1
            info(f"[{dork_count:3d}] {query[:70]}...")

            results = _search(query, engine)
            new_results = []
            for r in results:
                url = r["url"]
                if url not in seen_urls:
                    seen_urls.add(url)
                    r["dork"]     = query
                    r["category"] = category
                    r["severity"] = severity
                    new_results.append(r)
                    all_results.append(r)

            if new_results:
                color = RISK_COLORS.get(severity, "white")
                for r in new_results:
                    found(
                        f"  [{color}][{severity}][/{color}]  "
                        f"{r['url'][:80]}\n"
                        f"         [dim]{r['title'][:60]}[/dim]"
                    )
            else:
                console.print("  [dim]No results[/dim]")

    # Custom dorks
    if custom_dorks:
        console.print("\n[bold magenta]▶ Custom Dorks[/bold magenta]")
        for dork in custom_dorks:
            query = dork.replace("{domain}", domain)
            results = _search(query, engine)
            for r in results:
                if r["url"] not in seen_urls:
                    seen_urls.add(r["url"])
                    r["dork"]     = query
                    r["category"] = "Custom"
                    r["severity"] = "MEDIUM"
                    all_results.append(r)
                    found(f"  [CUSTOM]  {r['url'][:80]}")

    # Severity breakdown
    sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in all_results:
        sev_count[r["severity"]] = sev_count.get(r["severity"], 0) + 1

    # Print top findings
    console.print("\n[bold cyan]━━━ TOP FINDINGS ━━━[/bold cyan]")
    critical_high = [r for r in all_results if r["severity"] in ("CRITICAL", "HIGH")]
    for r in critical_high[:20]:
        color = RISK_COLORS.get(r["severity"], "white")
        console.print(
            f"  [{color}][{r['severity']}][/{color}]  "
            f"[bold]{r['url'][:80]}[/bold]\n"
            f"     [dim]{r['snippet'][:100]}[/dim]\n"
            f"     [cyan]Dork:[/cyan] {r['dork'][:60]}\n"
        )

    print_summary("Google Dorking", {
        "Dorks Run":      dork_count,
        "Total Results":  len(all_results),
        "CRITICAL":       sev_count["CRITICAL"],
        "HIGH":           sev_count["HIGH"],
        "MEDIUM":         sev_count["MEDIUM"],
        "LOW":            sev_count["LOW"],
        "Unique URLs":    len(seen_urls),
    })

    return {
        "results":       all_results,
        "dork_count":    dork_count,
        "unique_urls":   len(seen_urls),
        "severity_breakdown": sev_count,
    }
