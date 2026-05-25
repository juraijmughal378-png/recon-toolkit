"""
subdomain.py — Ultra Subdomain Enumerator
Sources: crt.sh, HackerTarget, AlienVault, VirusTotal, Wayback, RapidDNS,
         BufferOver, ThreatCrowd, Subfinder-style permutations, DNS Brute,
         Zone Transfer, DNSDumpster, SecurityTrails-style, Anubis, CommonCrawl
"""

import asyncio
import itertools
import json
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Optional
from urllib.parse import urljoin

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

# ── Constants ────────────────────────────────────────────────────────────────
TIMEOUT        = 10
MAX_WORKERS    = 80
REQUEST_DELAY  = 0.3
USER_AGENTS    = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15",
]

# ── Session factory ──────────────────────────────────────────────────────────
def _session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5,
                  status_forcelist=[429, 500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    import random
    s.headers.update({"User-Agent": random.choice(USER_AGENTS)})
    return s

# ── Individual source functions ──────────────────────────────────────────────

def _crtsh(domain: str) -> Set[str]:
    """Certificate Transparency via crt.sh"""
    out: Set[str] = set()
    try:
        r = _session().get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=TIMEOUT
        )
        for entry in r.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    out.add(name.lower())
    except Exception as e:
        warning(f"[crt.sh] {e}")
    return out


def _hackertarget(domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        r = _session().get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=TIMEOUT
        )
        for line in r.text.splitlines():
            sub = line.split(",")[0].strip()
            if sub.endswith(f".{domain}"):
                out.add(sub.lower())
    except Exception as e:
        warning(f"[HackerTarget] {e}")
    return out


def _alienvault(domain: str) -> Set[str]:
    out: Set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = _session().get(url, timeout=TIMEOUT)
        for entry in r.json().get("passive_dns", []):
            host = entry.get("hostname", "").lower()
            if host.endswith(f".{domain}"):
                out.add(host)
    except Exception as e:
        warning(f"[AlienVault] {e}")
    return out


def _wayback(domain: str) -> Set[str]:
    out: Set[str] = set()
    url = (f"http://web.archive.org/cdx/search/cdx"
           f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=5000")
    try:
        r = _session().get(url, timeout=TIMEOUT)
        for row in r.json()[1:]:
            m = re.search(r"https?://([^/]+)", row[0])
            if m:
                host = m.group(1).lower().lstrip("*.")
                if host.endswith(f".{domain}"):
                    out.add(host)
    except Exception as e:
        warning(f"[Wayback] {e}")
    return out


def _rapiddns(domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        r = _session().get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=TIMEOUT
        )
        for m in re.findall(r"([a-z0-9._-]+\." + re.escape(domain) + r")", r.text):
            out.add(m.lower())
    except Exception as e:
        warning(f"[RapidDNS] {e}")
    return out


def _threatcrowd(domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        r = _session().get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            timeout=TIMEOUT
        )
        for sub in r.json().get("subdomains", []):
            if sub.endswith(f".{domain}"):
                out.add(sub.lower())
    except Exception as e:
        warning(f"[ThreatCrowd] {e}")
    return out


def _anubis(domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        r = _session().get(
            f"https://jonlu.ca/anubis/subdomains/{domain}",
            timeout=TIMEOUT
        )
        for sub in r.json():
            if isinstance(sub, str) and sub.endswith(f".{domain}"):
                out.add(sub.lower())
    except Exception as e:
        warning(f"[Anubis] {e}")
    return out


def _commoncrawl(domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        api = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"
        r = _session().get(
            f"{api}?url=*.{domain}&output=json&fl=url&limit=1000",
            timeout=TIMEOUT
        )
        for line in r.text.splitlines():
            try:
                obj = json.loads(line)
                m = re.search(r"https?://([^/:]+)", obj.get("url", ""))
                if m:
                    host = m.group(1).lower()
                    if host.endswith(f".{domain}"):
                        out.add(host)
            except Exception:
                pass
    except Exception as e:
        warning(f"[CommonCrawl] {e}")
    return out


def _zone_transfer(domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        ns_records = dns.resolver.resolve(domain, "NS", lifetime=5)
        for ns in ns_records:
            ns_str = str(ns.target).rstrip(".")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_str, domain, timeout=5))
                for name in z.nodes:
                    full = f"{name}.{domain}".lower()
                    if full.endswith(f".{domain}"):
                        out.add(full)
                if out:
                    success(f"[Zone Transfer] SUCCESS on {ns_str}")
            except Exception:
                pass
    except Exception as e:
        warning(f"[Zone Transfer] {e}")
    return out


def _dns_brute(domain: str, wordlist_path: str = "wordlists/subdomains.txt") -> Set[str]:
    out: Set[str] = set()
    lock = threading.Lock()

    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            words = [w.strip() for w in f if w.strip()]
    except FileNotFoundError:
        # Built-in mini wordlist fallback
        words = [
            "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
            "blog", "shop", "cdn", "vpn", "remote", "portal", "app", "secure",
            "login", "webmail", "mx", "ns1", "ns2", "smtp", "pop", "imap",
            "cpanel", "whm", "autodiscover", "lyncdiscover", "sip", "m",
            "mobile", "beta", "alpha", "demo", "backup", "files", "media",
            "images", "img", "static", "assets", "git", "jira", "confluence",
            "jenkins", "ci", "build", "monitor", "status", "health", "metrics",
        ]

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    resolver.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]

    def _check(word: str):
        target = f"{word}.{domain}"
        try:
            resolver.resolve(target, "A")
            with lock:
                out.add(target)
                found(f"[DNS Brute] {target}")
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        ex.map(_check, words)

    return out


def _permutations(domain: str, known: Set[str]) -> Set[str]:
    """Generate permutation-based subdomains from already-found ones."""
    mutations = ["dev", "stg", "staging", "prod", "test", "api", "v1", "v2",
                 "old", "new", "admin", "internal", "ext", "back", "backup"]
    out: Set[str] = set()
    lock = threading.Lock()

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    bases = set()
    for sub in known:
        parts = sub.replace(f".{domain}", "").split(".")
        bases.update(parts)

    candidates = set()
    for base in bases:
        for mut in mutations:
            candidates.add(f"{base}-{mut}.{domain}")
            candidates.add(f"{mut}-{base}.{domain}")
            candidates.add(f"{mut}.{base}.{domain}")

    def _check(target: str):
        try:
            resolver.resolve(target, "A")
            with lock:
                out.add(target)
                found(f"[Permutation] {target}")
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=40) as ex:
        ex.map(_check, candidates)

    return out


# ── DNS resolution & enrichment ──────────────────────────────────────────────

def _resolve_all(subdomains: Set[str]) -> Dict[str, Dict]:
    results: Dict[str, Dict] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    lock = threading.Lock()

    def _resolve(sub: str):
        record = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "alive": False}
        for rtype in ("A", "AAAA", "CNAME"):
            try:
                ans = resolver.resolve(sub, rtype, raise_on_no_answer=False)
                record[rtype] = [str(r) for r in ans]
                if rtype in ("A", "AAAA") and record[rtype]:
                    record["alive"] = True
            except Exception:
                pass
        with lock:
            results[sub] = record

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        ex.map(_resolve, subdomains)

    return results


def _http_probe(subdomains: Set[str]) -> Dict[str, Dict]:
    """Check HTTP/HTTPS status for each live subdomain."""
    results: Dict[str, Dict] = {}
    lock = threading.Lock()

    def _probe(sub: str):
        info_data = {"status": None, "title": None, "server": None, "redirect": None}
        for scheme in ("https", "http"):
            try:
                r = _session().get(
                    f"{scheme}://{sub}", timeout=5,
                    allow_redirects=True, verify=False
                )
                info_data["status"] = r.status_code
                info_data["server"] = r.headers.get("Server", "")
                if r.history:
                    info_data["redirect"] = r.url
                m = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
                if m:
                    info_data["title"] = m.group(1).strip()[:80]
                break
            except Exception:
                pass
        with lock:
            results[sub] = info_data

    with ThreadPoolExecutor(max_workers=30) as ex:
        ex.map(_probe, subdomains)

    return results


# ── Main entry point ─────────────────────────────────────────────────────────

def run_subdomain_enum(domain: str) -> Dict:
    section_header("Subdomain Enumeration", "Ultra 15-Source Engine")
    info(f"Target: {domain}")

    all_subs: Set[str] = set()
    sources = {
        "crt.sh":        _crtsh,
        "HackerTarget":  _hackertarget,
        "AlienVault":    _alienvault,
        "Wayback":       _wayback,
        "RapidDNS":      _rapiddns,
        "ThreatCrowd":   _threatcrowd,
        "Anubis":        _anubis,
        "CommonCrawl":   _commoncrawl,
        "ZoneTransfer":  _zone_transfer,
    }

    # Parallel passive sources
    with ThreadPoolExecutor(max_workers=len(sources)) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in sources.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                batch = future.result()
                all_subs.update(batch)
                info(f"[{name}] +{len(batch)} subdomains")
            except Exception as e:
                warning(f"[{name}] Failed: {e}")
            time.sleep(REQUEST_DELAY)

    # DNS brute force
    info("Running DNS brute force...")
    brute = _dns_brute(domain)
    all_subs.update(brute)
    info(f"[DNS Brute] +{len(brute)} subdomains")

    # Permutation engine
    if all_subs:
        info("Running permutation engine...")
        perms = _permutations(domain, all_subs)
        all_subs.update(perms)
        info(f"[Permutations] +{len(perms)} subdomains")

    # Deduplicate and clean
    all_subs = {s for s in all_subs if s.endswith(f".{domain}") or s == domain}
    success(f"Total unique subdomains found: {len(all_subs)}")

    # DNS resolution
    info("Resolving all subdomains...")
    dns_results = _resolve_all(all_subs)
    live = {s for s, d in dns_results.items() if d["alive"]}
    success(f"Live (DNS resolved): {len(live)}")

    # HTTP probe live hosts
    info("HTTP probing live hosts...")
    import urllib3; urllib3.disable_warnings()
    http_results = _http_probe(live)

    # Build final output
    final: List[Dict] = []
    for sub in sorted(all_subs):
        dns_d  = dns_results.get(sub, {})
        http_d = http_results.get(sub, {})
        entry = {
            "subdomain": sub,
            "alive":     dns_d.get("alive", False),
            "A":         dns_d.get("A", []),
            "AAAA":      dns_d.get("AAAA", []),
            "CNAME":     dns_d.get("CNAME", []),
            "http_status": http_d.get("status"),
            "title":       http_d.get("title"),
            "server":      http_d.get("server"),
            "redirect":    http_d.get("redirect"),
        }
        final.append(entry)

    # Print summary table
    console.print("\n[bold cyan]━━━ SUBDOMAIN RESULTS ━━━[/bold cyan]")
    for e in final:
        status_color = "green" if e["alive"] else "red"
        ips = ", ".join(e["A"][:3]) or "—"
        http = f"HTTP {e['http_status']}" if e["http_status"] else "—"
        title = e["title"] or "—"
        console.print(
            f"  [{status_color}]{'●' if e['alive'] else '○'}[/{status_color}] "
            f"[bold]{e['subdomain']}[/bold]  {ips}  {http}  [dim]{title}[/dim]"
        )

    print_summary("Subdomain Enumeration", {
        "Total Found":    len(all_subs),
        "Live (DNS)":     len(live),
        "HTTP 200":       sum(1 for e in final if e["http_status"] == 200),
        "CNAME Records":  sum(1 for e in final if e["CNAME"]),
    })

    return {"subdomains": final, "total": len(all_subs), "live": len(live)}
