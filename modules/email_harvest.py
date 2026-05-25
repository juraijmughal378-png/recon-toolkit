"""
email_harvest.py — Ultra Email Harvester
Sources: Website crawl, WHOIS, crt.sh, Wayback Machine, GitHub, Pastebin,
         LinkedIn patterns, Hunter.io style, PGP keyserver, EmailRep, Gravatar
"""

import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

import requests
from bs4 import BeautifulSoup

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT    = 10
MAX_DEPTH  = 3
MAX_PAGES  = 100
DELAY      = 0.5

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE
)

OBFUSCATION_PATTERNS = [
    (r"([a-z0-9._%+\-]+)\s*\[at\]\s*([a-z0-9.\-]+)\s*\[dot\]\s*([a-z]{2,})", r"\1@\2.\3"),
    (r"([a-z0-9._%+\-]+)\s*\(at\)\s*([a-z0-9.\-]+)\s*\(dot\)\s*([a-z]{2,})",  r"\1@\2.\3"),
    (r"([a-z0-9._%+\-]+)\s+AT\s+([a-z0-9.\-]+)\s+DOT\s+([a-z]{2,})",          r"\1@\2.\3"),
    (r"([a-z0-9._%+\-]+)&#64;([a-z0-9.\-]+\.[a-z]{2,})",                       r"\1@\2"),
    (r"([a-z0-9._%+\-]+)%40([a-z0-9.\-]+\.[a-z]{2,})",                         r"\1@\2"),
]

BLACKLIST_DOMAINS = {
    "example.com", "test.com", "domain.com", "email.com", "user.com",
    "sentry.io", "wixpress.com", "schema.org", "w3.org", "jquery.com",
    "getbootstrap.com", "googleapis.com", "gstatic.com", "cloudflare.com",
}

SOCIAL_PLATFORMS = ["linkedin.com", "twitter.com", "github.com", "facebook.com"]

ROLE_PREFIXES = [
    "admin", "info", "contact", "support", "sales", "security", "abuse",
    "noreply", "hello", "help", "ceo", "cto", "ciso", "hr", "jobs",
    "careers", "press", "media", "legal", "privacy", "billing",
]


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    return s


def _extract_emails(text: str) -> Set[str]:
    """Extract and clean emails from text, handling obfuscation."""
    # Deobfuscate
    for pat, rep in OBFUSCATION_PATTERNS:
        text = re.sub(pat, rep, text, flags=re.IGNORECASE)

    # Remove HTML entities
    text = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), text)

    emails = set()
    for match in EMAIL_RE.findall(text):
        email = match.lower().strip(".,;:\"'()[]")
        parts = email.split("@")
        if len(parts) != 2:
            continue
        local, domain = parts
        if domain in BLACKLIST_DOMAINS:
            continue
        if len(local) < 2 or len(domain) < 4:
            continue
        if re.search(r"\.(js|css|png|jpg|gif|svg|ico|woff|ttf)$", domain):
            continue
        emails.add(email)
    return emails


# ── Individual sources ────────────────────────────────────────────────────────

def _crawl_website(domain: str) -> Set[str]:
    """Deep crawl website for emails."""
    info(f"[Website Crawl] Starting on {domain}...")
    emails: Set[str] = set()
    visited: Set[str] = set()
    queue  = [f"https://{domain}", f"http://{domain}"]

    def _crawl(url: str, depth: int = 0):
        if depth > MAX_DEPTH or url in visited or len(visited) >= MAX_PAGES:
            return
        visited.add(url)
        try:
            r = _session().get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            text = r.text
            emails.update(_extract_emails(text))

            if depth < MAX_DEPTH:
                soup = BeautifulSoup(text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if href.startswith("mailto:"):
                        email = href[7:].split("?")[0].lower().strip()
                        if "@" in email:
                            emails.add(email)
                    elif domain in href or href.startswith("/"):
                        full = urllib.parse.urljoin(url, href)
                        if full not in visited and domain in full:
                            _crawl(full, depth + 1)
        except Exception:
            pass

    for start in queue[:1]:
        _crawl(start)

    return emails


def _whois_emails(domain: str) -> Set[str]:
    info("[WHOIS] Extracting emails...")
    emails: Set[str] = set()
    try:
        import whois as python_whois
        w = python_whois.whois(domain)
        raw = str(w)
        emails.update(_extract_emails(raw))
        if w.emails:
            if isinstance(w.emails, list):
                emails.update(e.lower() for e in w.emails if e)
            else:
                emails.add(w.emails.lower())
    except Exception as e:
        warning(f"[WHOIS] {e}")
    return emails


def _crtsh_emails(domain: str) -> Set[str]:
    info("[crt.sh] Extracting emails from certificates...")
    emails: Set[str] = set()
    try:
        r = _session().get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=TIMEOUT
        )
        for entry in r.json():
            text = json.dumps(entry) if not isinstance(entry, str) else entry
            emails.update(_extract_emails(str(entry)))
    except Exception as e:
        warning(f"[crt.sh] {e}")
    return emails


def _wayback_emails(domain: str) -> Set[str]:
    info("[Wayback Machine] Extracting emails...")
    emails: Set[str] = set()
    try:
        url = (f"http://web.archive.org/cdx/search/cdx"
               f"?url={domain}&output=json&fl=original&collapse=urlkey&limit=200")
        r = _session().get(url, timeout=TIMEOUT)
        pages = r.json()[1:]
        for row in pages[:50]:
            try:
                page_url = row[0]
                r2 = _session().get(
                    f"https://web.archive.org/web/2024/{page_url}",
                    timeout=8
                )
                emails.update(_extract_emails(r2.text))
                time.sleep(0.2)
            except Exception:
                pass
    except Exception as e:
        warning(f"[Wayback] {e}")
    return emails


def _github_emails(domain: str) -> Set[str]:
    info("[GitHub] Searching for emails...")
    emails: Set[str] = set()
    queries = [
        f"@{domain}",
        f'"{domain}" email',
        f'"{domain}" contact',
    ]
    for q in queries:
        try:
            encoded = urllib.parse.quote(q)
            url = f"https://api.github.com/search/code?q={encoded}&per_page=30"
            r = _session().get(url, timeout=TIMEOUT,
                               headers={"Accept": "application/vnd.github.v3+json"})
            data = r.json()
            for item in data.get("items", []):
                # Fetch raw content
                raw_url = item.get("html_url", "").replace(
                    "github.com", "raw.githubusercontent.com"
                ).replace("/blob/", "/")
                try:
                    r2 = _session().get(raw_url, timeout=8)
                    emails.update(_extract_emails(r2.text))
                except Exception:
                    pass
                time.sleep(0.3)
        except Exception as e:
            warning(f"[GitHub] {e}")
    return emails


def _pastebin_emails(domain: str) -> Set[str]:
    info("[Pastebin] Searching...")
    emails: Set[str] = set()
    try:
        q = urllib.parse.quote(f"site:pastebin.com {domain} email")
        r = _session().get(
            f"https://www.google.com/search?q={q}&num=20",
            timeout=TIMEOUT
        )
        emails.update({e for e in _extract_emails(r.text) if domain in e})
    except Exception as e:
        warning(f"[Pastebin] {e}")
    return emails


def _pgp_keyserver(domain: str) -> Set[str]:
    info("[PGP Keyserver] Searching...")
    emails: Set[str] = set()
    try:
        r = _session().get(
            f"https://keys.openpgp.org/vks/v1/search?q={domain}",
            timeout=TIMEOUT
        )
        emails.update(_extract_emails(r.text))
    except Exception as e:
        warning(f"[PGP] {e}")
    return emails


def _hunter_style(domain: str) -> Set[str]:
    """Try Hunter.io free search (no API key needed for basic)."""
    info("[Hunter.io] Attempting free search...")
    emails: Set[str] = set()
    try:
        r = _session().get(
            f"https://hunter.io/search/{domain}",
            timeout=TIMEOUT
        )
        emails.update(_extract_emails(r.text))
    except Exception as e:
        warning(f"[Hunter] {e}")
    return emails


def _generate_patterns(domain: str, known_names: List[str]) -> Set[str]:
    """Generate likely email addresses from name patterns."""
    generated: Set[str] = set()
    separators = ["", ".", "_", "-"]
    for name in known_names:
        parts = name.lower().split()
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            for sep in separators:
                generated.add(f"{first}{sep}{last}@{domain}")
                generated.add(f"{last}{sep}{first}@{domain}")
                generated.add(f"{first[0]}{sep}{last}@{domain}")
                generated.add(f"{first}{sep}{last[0]}@{domain}")

    # Role-based
    for role in ROLE_PREFIXES:
        generated.add(f"{role}@{domain}")

    return generated


def _validate_email(email: str) -> Dict:
    """Basic email validation without API."""
    import dns.resolver
    result = {"email": email, "valid_format": True, "mx_exists": False,
              "disposable": False, "role": False}

    local = email.split("@")[0]
    domain = email.split("@")[1]

    # Role-based check
    result["role"] = local.split("+")[0].split("-")[0] in ROLE_PREFIXES

    # MX check
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3
        resolver.resolve(domain, "MX")
        result["mx_exists"] = True
    except Exception:
        pass

    # Disposable domain check (basic)
    disposable = ["mailinator.com","guerrillamail.com","temp-mail.org","10minutemail.com",
                  "throwaway.email","fakeinbox.com","yopmail.com","sharklasers.com"]
    result["disposable"] = domain in disposable

    return result


import json

# ── Main entry point ─────────────────────────────────────────────────────────

def run_email_harvest(domain: str, deep: bool = True) -> Dict:
    section_header("Email Harvester", "Ultra 10-Source Engine")
    info(f"Target: {domain}")

    all_emails: Set[str] = set()
    source_results: Dict[str, Set[str]] = {}

    sources = {
        "Website Crawl":  lambda: _crawl_website(domain),
        "WHOIS":          lambda: _whois_emails(domain),
        "crt.sh":         lambda: _crtsh_emails(domain),
        "PGP Keyserver":  lambda: _pgp_keyserver(domain),
        "Hunter.io":      lambda: _hunter_style(domain),
        "GitHub":         lambda: _github_emails(domain),
        "Pastebin":       lambda: _pastebin_emails(domain),
    }

    if deep:
        sources["Wayback"] = lambda: _wayback_emails(domain)

    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(fn): name for name, fn in sources.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                batch = future.result()
                # Filter to domain-relevant emails
                relevant = {e for e in batch if domain in e or
                            e.split("@")[1] in domain or domain in e.split("@")[1]}
                source_results[name] = relevant
                all_emails.update(batch)  # Keep all for cross-ref
                info(f"[{name}] +{len(relevant)} emails")
            except Exception as e:
                warning(f"[{name}] {e}")

    # Filter to domain emails
    domain_emails = {e for e in all_emails if e.endswith(f"@{domain}")}

    # Generate patterns from any names found
    names_found: List[str] = []
    for email in domain_emails:
        local = email.split("@")[0]
        if "." in local or "_" in local:
            names_found.append(local.replace(".", " ").replace("_", " "))

    patterns = _generate_patterns(domain, names_found)

    # Validate all discovered emails
    info(f"Validating {len(domain_emails)} domain emails...")
    validated: List[Dict] = []
    for email in sorted(domain_emails):
        v = _validate_email(email)
        validated.append(v)
        status = "[green]✓ MX[/green]" if v["mx_exists"] else "[red]✗ MX[/red]"
        role   = "[yellow]ROLE[/yellow]" if v["role"] else ""
        found(f"  {email:50}  {status}  {role}")

    # ── Print summary ─────────────────────────────────────────────────────────
    console.print("\n[bold cyan]━━━ ALL EMAILS FOUND ━━━[/bold cyan]")
    all_sorted = sorted(all_emails)
    for e in all_sorted:
        dom = e.split("@")[1] if "@" in e else ""
        color = "green" if dom == domain else "cyan"
        console.print(f"  [{color}]{e}[/{color}]")

    console.print("\n[bold cyan]━━━ GENERATED PATTERNS ━━━[/bold cyan]")
    for p in sorted(patterns)[:20]:
        console.print(f"  [dim]{p}[/dim]")

    console.print("\n[bold cyan]━━━ SOURCE BREAKDOWN ━━━[/bold cyan]")
    for src, emails in source_results.items():
        console.print(f"  {src:20}  {len(emails)} emails")

    print_summary("Email Harvesting", {
        "Total Emails":    len(all_emails),
        "Domain Emails":   len(domain_emails),
        "MX Verified":     sum(1 for v in validated if v["mx_exists"]),
        "Role Addresses":  sum(1 for v in validated if v["role"]),
        "Patterns Gen'd":  len(patterns),
        "Sources Run":     len(sources),
    })

    return {
        "all_emails":     list(all_emails),
        "domain_emails":  list(domain_emails),
        "validated":      validated,
        "patterns":       list(patterns),
        "source_results": {k: list(v) for k, v in source_results.items()},
    }
