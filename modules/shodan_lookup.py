"""
shodan_lookup.py — Ultra Shodan Intelligence Module
Features: Full Shodan API, host info, search, org search, CVE lookup,
          facet analysis, honeypot detection, exposure scoring, trending CVEs
"""

import json
import os
import re
import socket
import time
from typing import Dict, List, Optional

import requests

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 15
SHODAN_API = "https://api.shodan.io"

RISK_PORTS = {
    23: "CRITICAL",   21: "HIGH",    3389: "HIGH",
    5900: "HIGH",     2375: "CRITICAL", 6379: "CRITICAL",
    27017: "CRITICAL",9200: "CRITICAL", 11211: "HIGH",
    1521: "HIGH",     3306: "HIGH",   5432: "HIGH",
    10250: "CRITICAL",50070: "HIGH",  445: "CRITICAL",
    512: "CRITICAL",  513: "CRITICAL",514: "CRITICAL",
    4444: "CRITICAL", 7001: "CRITICAL",
}

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}

HONEYPOT_INDICATORS = [
    "kippo", "cowrie", "dionaea", "honeyd", "glastopf",
    "opencanary", "conpot", "elastichoney", "wordpot",
]


def _get_api_key() -> Optional[str]:
    """Get Shodan API key from env or prompt."""
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        console.print("[yellow]No SHODAN_API_KEY env var found.[/yellow]")
        key = console.input("[bold]Enter Shodan API key (or press Enter to skip): [/bold]").strip()
    return key if key else None


def _api_get(endpoint: str, params: Dict, api_key: str) -> Optional[Dict]:
    try:
        params["key"] = api_key
        r = requests.get(f"{SHODAN_API}{endpoint}", params=params, timeout=TIMEOUT)
        if r.status_code == 401:
            error("Shodan: Invalid API key")
            return None
        if r.status_code == 429:
            warning("Shodan: Rate limited — waiting 60s")
            time.sleep(60)
            return _api_get(endpoint, params, api_key)
        return r.json()
    except Exception as e:
        warning(f"[Shodan API] {e}")
        return None


# ── Host intelligence ─────────────────────────────────────────────────────────

def _host_info(ip: str, api_key: str) -> Optional[Dict]:
    info(f"[Shodan] Host lookup: {ip}")
    return _api_get(f"/shodan/host/{ip}", {"history": True, "minify": False}, api_key)


def _host_count(query: str, api_key: str) -> int:
    data = _api_get("/shodan/host/count", {"query": query}, api_key)
    return data.get("total", 0) if data else 0


def _search(query: str, api_key: str, limit: int = 100) -> Optional[Dict]:
    info(f"[Shodan] Search: {query}")
    return _api_get("/shodan/host/search", {"query": query, "limit": limit}, api_key)


def _org_search(org: str, api_key: str) -> Optional[Dict]:
    return _search(f'org:"{org}"', api_key)


def _domain_search(domain: str, api_key: str) -> Optional[Dict]:
    data = _api_get(f"/dns/domain/{domain}", {}, api_key)
    return data


def _honeypot_score(ip: str, api_key: str) -> Optional[float]:
    data = _api_get(f"/labs/honeyscore/{ip}", {}, api_key)
    if data:
        return data.get("score")
    return None


def _exploit_search(query: str, api_key: str) -> Optional[Dict]:
    """Shodan Exploit DB search."""
    try:
        params = {"query": query, "key": api_key}
        r = requests.get("https://exploits.shodan.io/api/search", params=params, timeout=TIMEOUT)
        return r.json()
    except Exception:
        return None


def _calculate_exposure_score(host_data: Dict) -> Dict:
    """Calculate a risk exposure score for the host."""
    score = 0
    reasons = []

    ports = host_data.get("ports", [])
    vulns = host_data.get("vulns", {})
    data  = host_data.get("data", [])

    # Critical ports
    for port in ports:
        risk = RISK_PORTS.get(port)
        if risk == "CRITICAL":
            score += 30
            reasons.append(f"CRITICAL port {port} open")
        elif risk == "HIGH":
            score += 15
            reasons.append(f"HIGH risk port {port} open")

    # Vulnerabilities
    for cve, vuln in vulns.items():
        cvss = float(vuln.get("cvss", 0))
        if cvss >= 9.0:
            score += 25
            reasons.append(f"{cve} (CVSS {cvss} — CRITICAL)")
        elif cvss >= 7.0:
            score += 15
            reasons.append(f"{cve} (CVSS {cvss} — HIGH)")
        elif cvss >= 4.0:
            score += 5
            reasons.append(f"{cve} (CVSS {cvss} — MEDIUM)")

    # Service banners with version info
    for service in data:
        product = service.get("product", "")
        version = service.get("version", "")
        if product and version:
            score += 2  # Version disclosure is a minor risk

    # Default credentials indicators in banners
    for service in data:
        banner = str(service.get("data", "")).lower()
        if any(kw in banner for kw in ["default password", "admin:admin", "root:root", "anonymous"]):
            score += 20
            reasons.append("Default credentials detected in banner")

    score = min(score, 100)

    if score >= 75: level = "CRITICAL"
    elif score >= 50: level = "HIGH"
    elif score >= 25: level = "MEDIUM"
    else: level = "LOW"

    return {"score": score, "level": level, "reasons": reasons[:10]}


def _is_honeypot(host_data: Dict) -> bool:
    """Heuristic honeypot detection."""
    all_text = json.dumps(host_data).lower()
    return any(ind in all_text for ind in HONEYPOT_INDICATORS)


# ── Fallback (no API key) ─────────────────────────────────────────────────────

def _shodan_web_fallback(target: str) -> Dict:
    """Scrape public Shodan search page (very limited)."""
    info("[Shodan] Using web fallback (no API key)...")
    try:
        r = requests.get(
            f"https://www.shodan.io/search?query={target}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT
        )
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "html.parser")

        results = []
        for result in soup.select(".search-result")[:10]:
            ip_el = result.select_one(".ip-title")
            port_el = result.select_one("dt")
            if ip_el:
                results.append({
                    "ip":   ip_el.get_text().strip(),
                    "port": port_el.get_text().strip() if port_el else "?",
                })
        return {"web_results": results, "note": "API key recommended for full data"}
    except Exception as e:
        return {"error": str(e)}


# ── Main entry point ─────────────────────────────────────────────────────────

def run_shodan_lookup(target: str) -> Dict:
    section_header("Shodan Intelligence", "Ultra API Edition")
    info(f"Target: {target}")

    api_key = _get_api_key()

    # Resolve to IP if hostname
    try:
        ip = socket.gethostbyname(target)
        info(f"Resolved: {target} → {ip}")
    except Exception:
        ip = target if re.match(r"^\d+\.\d+\.\d+\.\d+$", target) else None

    if not api_key:
        warning("No API key — using web fallback (limited data)")
        result = _shodan_web_fallback(target)
        console.print(f"\n[yellow]Tip:[/yellow] Set SHODAN_API_KEY env variable for full access")
        console.print(f"  Manual URL: [link]https://www.shodan.io/host/{ip or target}[/link]")
        return result

    # ── Full API workflow ─────────────────────────────────────────────────────
    result = {"target": target, "ip": ip}

    # Host info
    if ip:
        host = _host_info(ip, api_key)
        if host:
            result["host"] = host

            # Exposure score
            exposure = _calculate_exposure_score(host)
            result["exposure"] = exposure

            # Honeypot check
            honeypot = _is_honeypot(host)
            result["honeypot_suspected"] = honeypot

            # Honeyscore
            hs = _honeypot_score(ip, api_key)
            result["honeyscore"] = hs

            # ── Print host info ───────────────────────────────────────────────
            console.print("\n[bold cyan]━━━ SHODAN HOST INFO ━━━[/bold cyan]")
            console.print(f"  IP:           {host.get('ip_str', ip)}")
            console.print(f"  Org:          {host.get('org', '—')}")
            console.print(f"  ISP:          {host.get('isp', '—')}")
            console.print(f"  Country:      {host.get('country_name', '—')} ({host.get('country_code', '')})")
            console.print(f"  City:         {host.get('city', '—')}")
            console.print(f"  ASN:          {host.get('asn', '—')}")
            console.print(f"  Hostnames:    {', '.join(host.get('hostnames', [])) or '—'}")
            console.print(f"  Domains:      {', '.join(host.get('domains', [])) or '—'}")
            console.print(f"  Last Updated: {host.get('last_update', '—')}")
            console.print(f"  Tags:         {', '.join(host.get('tags', [])) or '—'}")

            if honeypot:
                warning("⚠  Honeypot indicators detected!")
            if hs is not None:
                color = "red" if hs > 0.5 else "green"
                console.print(f"  Honeyscore:   [{color}]{hs:.2f}[/{color}] (0=real, 1=honeypot)")

            # Ports
            ports = host.get("ports", [])
            console.print(f"\n[bold cyan]━━━ OPEN PORTS ({len(ports)}) ━━━[/bold cyan]")
            for port in sorted(ports):
                risk = RISK_PORTS.get(port, "INFO")
                color = RISK_COLORS.get(risk, "white")
                console.print(f"  [{color}]{port:6}[/{color}]  [{color}]{risk}[/{color}]")

            # Services detail
            console.print("\n[bold cyan]━━━ SERVICES ━━━[/bold cyan]")
            for svc in host.get("data", []):
                port    = svc.get("port")
                product = svc.get("product", "Unknown")
                version = svc.get("version", "")
                transport = svc.get("transport", "tcp")
                banner  = svc.get("data", "")[:100].replace("\n", " ")
                console.print(
                    f"  [bold]{port}/{transport}[/bold]  "
                    f"[cyan]{product} {version}[/cyan]  "
                    f"[dim]{banner}[/dim]"
                )

            # Vulnerabilities
            vulns = host.get("vulns", {})
            if vulns:
                console.print(f"\n[bold red]━━━ VULNERABILITIES ({len(vulns)}) ━━━[/bold red]")
                sorted_vulns = sorted(
                    vulns.items(),
                    key=lambda x: float(x[1].get("cvss", 0)),
                    reverse=True
                )
                for cve, data in sorted_vulns:
                    cvss  = data.get("cvss", "?")
                    summ  = data.get("summary", "")[:80]
                    refs  = data.get("references", [])
                    cvss_f = float(cvss) if cvss != "?" else 0
                    color = "bold red" if cvss_f >= 9 else ("red" if cvss_f >= 7 else "yellow")
                    console.print(
                        f"  [{color}]{cve}[/{color}]  CVSS: {cvss}  "
                        f"[dim]{summ}[/dim]"
                    )
                    if refs:
                        console.print(f"       [dim]{refs[0]}[/dim]")

            # Exposure score
            color = RISK_COLORS.get(exposure["level"], "white")
            console.print(f"\n[bold cyan]━━━ EXPOSURE SCORE ━━━[/bold cyan]")
            console.print(f"  Score: [{color}]{exposure['score']}/100 ({exposure['level']})[/{color}]")
            for reason in exposure["reasons"]:
                console.print(f"  • {reason}")

    # Domain search
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        info(f"[Shodan] DNS domain lookup: {target}")
        domain_data = _domain_search(target, api_key)
        if domain_data:
            result["domain_data"] = domain_data
            subdomains = domain_data.get("subdomains", [])
            if subdomains:
                console.print(f"\n[bold cyan]━━━ SHODAN SUBDOMAINS ({len(subdomains)}) ━━━[/bold cyan]")
                for sub in subdomains[:20]:
                    found(f"  {sub}.{target}")

    # Org search
    if ip:
        host_data = result.get("host", {})
        org = host_data.get("org")
        if org:
            info(f"[Shodan] Organization search: {org}")
            org_data = _org_search(org, api_key)
            if org_data:
                total = org_data.get("total", 0)
                result["org_total_hosts"] = total
                console.print(f"\n[yellow]Organization '{org}' has {total} hosts on Shodan[/yellow]")

    host_data_for_summary = result.get("host", {})
    print_summary("Shodan Intelligence", {
        "IP":          ip or target,
        "Org":         host_data_for_summary.get("org", "—"),
        "Country":     host_data_for_summary.get("country_name", "—"),
        "Open Ports":  len(host_data_for_summary.get("ports", [])),
        "CVEs Found":  len(host_data_for_summary.get("vulns", {})),
        "Exposure":    f"{result.get('exposure', {}).get('score', '?')}/100",
        "Honeypot":    result.get("honeypot_suspected", False),
    })

    return result
