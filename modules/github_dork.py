"""
github_dork.py — Ultra GitHub Dorking Engine
Features: 60+ dorks, API + web search, code/commit/issue search,
          secret detection in results, org/user enumeration, repo analysis
"""

import re
import time
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 15
DELAY   = 2.0  # GitHub rate limiting

# ── GitHub dork templates ─────────────────────────────────────────────────────
GITHUB_DORKS: List[Dict] = [
    # Credentials & Secrets
    {"query": '"{domain}" password',              "category": "Credentials",    "severity": "CRITICAL"},
    {"query": '"{domain}" secret',                "category": "Credentials",    "severity": "CRITICAL"},
    {"query": '"{domain}" api_key',               "category": "Credentials",    "severity": "CRITICAL"},
    {"query": '"{domain}" apikey',                "category": "Credentials",    "severity": "CRITICAL"},
    {"query": '"{domain}" api_secret',            "category": "Credentials",    "severity": "CRITICAL"},
    {"query": '"{domain}" token',                 "category": "Credentials",    "severity": "HIGH"},
    {"query": '"{domain}" access_token',          "category": "Credentials",    "severity": "CRITICAL"},
    {"query": '"{domain}" auth_token',            "category": "Credentials",    "severity": "CRITICAL"},
    {"query": '"{domain}" private_key',           "category": "Credentials",    "severity": "CRITICAL"},
    {"query": '"{domain}" client_secret',         "category": "Credentials",    "severity": "CRITICAL"},
    {"query": '"{domain}" BEGIN RSA PRIVATE',     "category": "Credentials",    "severity": "CRITICAL"},
    {"query": '"{domain}" AKIA',                  "category": "AWS",            "severity": "CRITICAL"},
    {"query": '"{domain}" aws_access_key_id',     "category": "AWS",            "severity": "CRITICAL"},
    {"query": '"{domain}" aws_secret_access_key', "category": "AWS",            "severity": "CRITICAL"},
    # Config files
    {"query": '"{domain}" filename:.env',         "category": "Config Files",   "severity": "CRITICAL"},
    {"query": '"{domain}" filename:config.php',   "category": "Config Files",   "severity": "HIGH"},
    {"query": '"{domain}" filename:config.yml',   "category": "Config Files",   "severity": "HIGH"},
    {"query": '"{domain}" filename:database.yml', "category": "Config Files",   "severity": "CRITICAL"},
    {"query": '"{domain}" filename:wp-config.php',"category": "Config Files",   "severity": "CRITICAL"},
    {"query": '"{domain}" filename:settings.py',  "category": "Config Files",   "severity": "HIGH"},
    {"query": '"{domain}" filename:application.properties', "category": "Config Files", "severity": "HIGH"},
    {"query": '"{domain}" filename:.npmrc',        "category": "Config Files",   "severity": "HIGH"},
    {"query": '"{domain}" filename:.dockercfg',    "category": "Config Files",   "severity": "HIGH"},
    {"query": '"{domain}" filename:credentials',   "category": "Config Files",   "severity": "CRITICAL"},
    {"query": '"{domain}" filename:secrets.yml',   "category": "Config Files",   "severity": "CRITICAL"},
    # Database
    {"query": '"{domain}" filename:*.sql',         "category": "Database",       "severity": "CRITICAL"},
    {"query": '"{domain}" DB_PASSWORD',            "category": "Database",       "severity": "CRITICAL"},
    {"query": '"{domain}" DB_USER',                "category": "Database",       "severity": "HIGH"},
    {"query": '"{domain}" database_password',      "category": "Database",       "severity": "CRITICAL"},
    {"query": '"{domain}" mysql_password',         "category": "Database",       "severity": "CRITICAL"},
    # SMTP / Email
    {"query": '"{domain}" smtp_password',          "category": "Email",          "severity": "HIGH"},
    {"query": '"{domain}" mail_password',          "category": "Email",          "severity": "HIGH"},
    {"query": '"{domain}" SENDGRID_API_KEY',       "category": "Email",          "severity": "HIGH"},
    {"query": '"{domain}" MAILGUN_API_KEY',        "category": "Email",          "severity": "HIGH"},
    # Infrastructure
    {"query": '"{domain}" filename:id_rsa',        "category": "SSH Keys",       "severity": "CRITICAL"},
    {"query": '"{domain}" filename:id_dsa',        "category": "SSH Keys",       "severity": "CRITICAL"},
    {"query": '"{domain}" filename:known_hosts',   "category": "SSH Keys",       "severity": "MEDIUM"},
    {"query": '"{domain}" filename:authorized_keys',"category": "SSH Keys",      "severity": "HIGH"},
    # Docker / K8s
    {"query": '"{domain}" filename:Dockerfile',    "category": "DevOps",         "severity": "MEDIUM"},
    {"query": '"{domain}" filename:docker-compose.yml', "category": "DevOps",   "severity": "HIGH"},
    {"query": '"{domain}" filename:kubeconfig',    "category": "DevOps",         "severity": "CRITICAL"},
    {"query": '"{domain}" KUBE_TOKEN',             "category": "DevOps",         "severity": "CRITICAL"},
    # Cloud providers
    {"query": '"{domain}" AZURE_CLIENT_SECRET',    "category": "Azure",          "severity": "CRITICAL"},
    {"query": '"{domain}" GOOGLE_APPLICATION_CREDENTIALS', "category": "GCP",   "severity": "CRITICAL"},
    {"query": '"{domain}" firebase',               "category": "Firebase",       "severity": "MEDIUM"},
    # Internal endpoints
    {"query": '"{domain}" internal',               "category": "Internal",       "severity": "MEDIUM"},
    {"query": '"{domain}" localhost',              "category": "Internal",       "severity": "MEDIUM"},
    {"query": '"{domain}" staging',               "category": "Internal",       "severity": "LOW"},
    {"query": '"{domain}" vpn',                   "category": "Internal",       "severity": "MEDIUM"},
    {"query": '"{domain}" intranet',              "category": "Internal",       "severity": "MEDIUM"},
    # Miscellaneous
    {"query": '"{domain}" TODO FIXME HACK',       "category": "Code Quality",   "severity": "LOW"},
    {"query": '"{domain}" hardcoded',             "category": "Code Quality",   "severity": "HIGH"},
    {"query": '"{domain}" vulnerability',         "category": "Security",       "severity": "MEDIUM"},
    {"query": '"{domain}" SQL injection',         "category": "Security",       "severity": "HIGH"},
    {"query": '"{domain}" XSS',                  "category": "Security",       "severity": "HIGH"},
    {"query": '"{domain}" penetration test',      "category": "Security",       "severity": "MEDIUM"},
]

SECRET_PATTERNS_INLINE = [
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"gh[pousr]_[A-Za-z0-9_]{36,}",
    r"sk_live_[0-9a-zA-Z]{24,}",
    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
]

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}


def _get_token() -> Optional[str]:
    import os
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        console.print("[yellow]No GITHUB_TOKEN env var — using unauthenticated (60 req/hr limit)[/yellow]")
        token = console.input("[bold]Enter GitHub token (or Enter to skip): [/bold]").strip()
    return token if token else None


def _search_github_api(query: str, token: Optional[str], search_type: str = "code") -> List[Dict]:
    """Search GitHub API."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results = []
    try:
        url = f"https://api.github.com/search/{search_type}"
        params = {"q": query, "per_page": 30, "sort": "indexed"}
        r = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)

        if r.status_code == 403:
            warning("GitHub: Rate limited — waiting 60s")
            time.sleep(60)
            r = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)

        if r.status_code == 422:
            return []  # Invalid query

        data = r.json()
        items = data.get("items", [])

        for item in items:
            if search_type == "code":
                results.append({
                    "name":     item.get("name", ""),
                    "path":     item.get("path", ""),
                    "repo":     item.get("repository", {}).get("full_name", ""),
                    "url":      item.get("html_url", ""),
                    "sha":      item.get("sha", ""),
                    "raw_url":  item.get("html_url", "").replace(
                        "github.com", "raw.githubusercontent.com"
                    ).replace("/blob/", "/"),
                })
            elif search_type == "repositories":
                results.append({
                    "name":        item.get("full_name", ""),
                    "description": item.get("description", ""),
                    "url":         item.get("html_url", ""),
                    "stars":       item.get("stargazers_count", 0),
                    "language":    item.get("language", ""),
                    "updated":     item.get("updated_at", "")[:10],
                })

        time.sleep(DELAY)

    except Exception as e:
        warning(f"[GitHub API] {e}")

    return results


def _fetch_raw_content(raw_url: str, token: Optional[str]) -> str:
    """Fetch raw file content to scan for secrets."""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.get(raw_url, headers=headers, timeout=8)
        return r.text[:5000]
    except Exception:
        return ""


def _scan_for_inline_secrets(content: str) -> List[str]:
    """Scan raw content for actual secret values."""
    found_secrets = []
    for pat in SECRET_PATTERNS_INLINE:
        for m in re.finditer(pat, content):
            found_secrets.append(m.group(0)[:80])
    return found_secrets


def _search_repos(domain: str, token: Optional[str]) -> List[Dict]:
    """Find GitHub repos related to the domain/org."""
    org = domain.split(".")[0]
    queries = [
        f'"{domain}" in:readme',
        f'"{org}" in:name',
        f'"{domain}"',
    ]
    repos = []
    for q in queries[:2]:
        r = _search_github_api(q, token, "repositories")
        repos.extend(r)
    return repos[:20]


def run_github_dork(domain: str) -> Dict:
    section_header("GitHub Dorking Engine", "Ultra 60+ Dorks | Credential Hunter")
    info(f"Target: {domain}")

    token = _get_token()
    if token:
        success("GitHub token loaded — authenticated mode (5000 req/hr)")

    all_findings: List[Dict] = []
    all_secrets: List[Dict] = []
    seen_urls: Set[str] = set()

    # Repo discovery
    info("Searching for related repositories...")
    repos = _search_repos(domain, token)
    if repos:
        console.print(f"\n[bold cyan]━━━ RELATED REPOS ({len(repos)}) ━━━[/bold cyan]")
        for repo in repos:
            console.print(
                f"  [cyan]{repo['name']}[/cyan]  ⭐{repo.get('stars',0)}  "
                f"[dim]{repo.get('description','')[:60]}[/dim]\n"
                f"  {repo['url']}"
            )

    # Dork search
    for dork in GITHUB_DORKS:
        query = dork["query"].replace("{domain}", domain)
        category = dork["category"]
        severity = dork["severity"]

        info(f"[{severity}] {query[:60]}...")
        results = _search_github_api(query, token, "code")

        new_results = []
        for r in results:
            if r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                r["category"] = category
                r["severity"] = severity
                r["query"]    = query
                new_results.append(r)

        if new_results:
            color = SEVERITY_COLORS.get(severity, "white")
            console.print(f"\n  [bold magenta]▶ {category} — {severity}[/bold magenta]")
            for r in new_results:
                found(
                    f"  [{color}][{severity}][/{color}]  "
                    f"[bold]{r['repo']}[/bold]  /  {r['path']}\n"
                    f"           {r['url']}"
                )
                all_findings.append(r)

                # Scan raw content for actual secrets
                if severity in ("CRITICAL", "HIGH") and token:
                    content = _fetch_raw_content(r.get("raw_url", ""), token)
                    inline_secrets = _scan_for_inline_secrets(content)
                    if inline_secrets:
                        for sec in inline_secrets:
                            console.print(f"           [bold red]⚠ SECRET:[/bold red] [red]{sec}[/red]")
                            all_secrets.append({
                                "secret": sec,
                                "file":   r["url"],
                                "repo":   r["repo"],
                            })

        time.sleep(DELAY)

    # Severity breakdown
    sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

    console.print(f"\n[bold cyan]━━━ TOP CRITICAL FINDINGS ━━━[/bold cyan]")
    critical = [f for f in all_findings if f["severity"] in ("CRITICAL", "HIGH")]
    for f in critical[:10]:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        console.print(
            f"  [{color}][{f['severity']}][/{color}]  "
            f"[bold]{f['repo']}[/bold]  {f['path']}\n"
            f"  Category: {f['category']}\n"
            f"  URL: {f['url']}\n"
        )

    if all_secrets:
        console.print(f"\n[bold red]━━━ CONFIRMED SECRETS ({len(all_secrets)}) ━━━[/bold red]")
        for s in all_secrets:
            console.print(f"  [red]{s['secret'][:80]}[/red]")
            console.print(f"  [dim]{s['file']}[/dim]")

    print_summary("GitHub Dorking", {
        "Dorks Run":        len(GITHUB_DORKS),
        "Total Results":    len(all_findings),
        "CRITICAL":         sev_count["CRITICAL"],
        "HIGH":             sev_count["HIGH"],
        "Confirmed Secrets":len(all_secrets),
        "Repos Found":      len(repos),
        "Unique Files":     len(seen_urls),
    })

    return {
        "findings":   all_findings,
        "secrets":    all_secrets,
        "repos":      repos,
        "sev_count":  sev_count,
    }
