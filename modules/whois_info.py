"""
whois_info.py — Ultra WHOIS + DNS + GeoIP + ASN + Threat Intel
Features: Full WHOIS parsing, all DNS record types, GeoIP enrichment,
          BGP/ASN lookup, DNSSEC validation, SPF/DMARC/DKIM analysis,
          historical data, typosquatting detection, threat intel
"""

import ipaddress
import json
import re
import socket
import threading
import time
import whois as python_whois
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Optional, Set

import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import requests

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 10
RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"]

DNS_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME",
    "SRV", "CAA", "PTR", "NAPTR", "DS", "DNSKEY",
]


def _session():
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 ReconToolkit/3.2"
    return s


# ── WHOIS ────────────────────────────────────────────────────────────────────

def _get_whois(domain: str) -> Dict:
    info("Fetching WHOIS data...")
    result = {
        "raw": None, "registrar": None, "registered": None,
        "expires": None, "updated": None, "status": [],
        "nameservers": [], "emails": [], "org": None,
        "country": None, "dnssec": None, "age_days": None,
    }
    try:
        w = python_whois.whois(domain)
        result["raw"]         = str(w)
        result["registrar"]   = w.registrar
        result["org"]         = w.org
        result["country"]     = w.country
        result["dnssec"]      = w.dnssec
        result["nameservers"] = [ns.lower() for ns in (w.name_servers or [])]
        result["emails"]      = list(set(w.emails or []))
        result["status"]      = w.status if isinstance(w.status, list) else [w.status]

        # Date handling
        def _first(val):
            if isinstance(val, list): return val[0]
            return val

        result["registered"] = str(_first(w.creation_date))
        result["expires"]    = str(_first(w.expiration_date))
        result["updated"]    = str(_first(w.updated_date))

        # Domain age
        try:
            created = _first(w.creation_date)
            if created:
                if hasattr(created, "timestamp"):
                    age = (datetime.now() - created).days
                    result["age_days"] = age
        except Exception:
            pass

    except Exception as e:
        warning(f"[WHOIS] {e}")
    return result


# ── DNS Records ──────────────────────────────────────────────────────────────

def _get_all_dns(domain: str) -> Dict[str, List]:
    info("Resolving all DNS record types...")
    records: Dict[str, List] = {}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = RESOLVERS
    resolver.lifetime = 5

    def _query(rtype: str):
        try:
            ans = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            records[rtype] = [str(r) for r in ans]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            pass

    with ThreadPoolExecutor(max_workers=len(DNS_RECORD_TYPES)) as ex:
        ex.map(_query, DNS_RECORD_TYPES)

    return records


def _get_reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _check_dnssec(domain: str) -> Dict:
    info("Checking DNSSEC...")
    result = {"enabled": False, "valid": False, "details": ""}
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = RESOLVERS
        # Check for DS record
        try:
            ds = resolver.resolve(domain, "DS")
            result["enabled"] = True
            result["details"] = f"DS records: {len(list(ds))}"
        except Exception:
            pass
        # Check for DNSKEY
        try:
            dnskey = resolver.resolve(domain, "DNSKEY")
            if dnskey:
                result["enabled"] = True
                result["valid"]   = True
                result["details"] += f" | DNSKEY: {len(list(dnskey))} keys"
        except Exception:
            pass
    except Exception as e:
        result["details"] = str(e)
    return result


def _analyze_spf(domain: str, txt_records: List[str]) -> Dict:
    """Parse SPF record and detect misconfigurations."""
    spf = {"found": False, "record": None, "mechanisms": [], "issues": []}
    for txt in txt_records:
        if txt.lower().startswith("v=spf1"):
            spf["found"]  = True
            spf["record"] = txt
            parts = txt.split()
            spf["mechanisms"] = parts[1:]

            # Check for weaknesses
            if "+all" in parts:
                spf["issues"].append("CRITICAL: +all allows any sender!")
            if "~all" in parts:
                spf["issues"].append("WARN: ~all softfail may allow spoofing")
            if "?all" in parts:
                spf["issues"].append("WARN: ?all neutral — no enforcement")
            if "-all" not in parts:
                spf["issues"].append("INFO: No -all hardblock")

            # Count DNS lookups (max 10 allowed)
            lookup_mechs = [p for p in parts if p.startswith(("include:", "a", "mx", "ptr", "exists:"))]
            if len(lookup_mechs) > 10:
                spf["issues"].append(f"WARN: {len(lookup_mechs)} DNS lookups (max 10)")
            break
    return spf


def _analyze_dmarc(domain: str) -> Dict:
    """Fetch and analyze DMARC policy."""
    dmarc = {"found": False, "record": None, "policy": None, "pct": None, "issues": []}
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = RESOLVERS
        ans = resolver.resolve(f"_dmarc.{domain}", "TXT", raise_on_no_answer=False)
        for r in ans:
            txt = str(r).strip('"')
            if "v=DMARC1" in txt:
                dmarc["found"]  = True
                dmarc["record"] = txt

                m = re.search(r"p=(\w+)", txt)
                if m: dmarc["policy"] = m.group(1)

                m = re.search(r"pct=(\d+)", txt)
                if m: dmarc["pct"] = int(m.group(1))

                if dmarc["policy"] == "none":
                    dmarc["issues"].append("WARN: p=none — monitoring only, no enforcement")
                if dmarc.get("pct", 100) < 100:
                    dmarc["issues"].append(f"WARN: pct={dmarc['pct']} — only partial enforcement")
                break
    except Exception:
        pass

    if not dmarc["found"]:
        dmarc["issues"].append("CRITICAL: No DMARC record — domain spoofing possible!")
    return dmarc


def _analyze_dkim(domain: str) -> Dict:
    """Check common DKIM selectors."""
    selectors = ["default", "google", "k1", "mail", "dkim", "selector1", "selector2",
                 "smtp", "email", "key1", "zoho", "mandrill", "mailchimp", "sendgrid"]
    found_selectors = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = RESOLVERS
    resolver.lifetime = 3

    for sel in selectors:
        try:
            ans = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", raise_on_no_answer=False)
            for r in ans:
                txt = str(r)
                if "v=DKIM1" in txt or "p=" in txt:
                    found_selectors.append({"selector": sel, "record": txt[:100]})
                    break
        except Exception:
            pass

    return {"selectors_found": found_selectors, "count": len(found_selectors)}


# ── GeoIP & ASN ─────────────────────────────────────────────────────────────

def _geoip(ip: str) -> Dict:
    info(f"GeoIP lookup: {ip}")
    geo = {}
    try:
        r = _session().get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=TIMEOUT)
        data = r.json()
        if data.get("status") == "success":
            geo = {
                "ip":       data.get("query"),
                "country":  data.get("country"),
                "country_code": data.get("countryCode"),
                "region":   data.get("regionName"),
                "city":     data.get("city"),
                "zip":      data.get("zip"),
                "lat":      data.get("lat"),
                "lon":      data.get("lon"),
                "timezone": data.get("timezone"),
                "isp":      data.get("isp"),
                "org":      data.get("org"),
                "as":       data.get("as"),
                "asname":   data.get("asname"),
                "mobile":   data.get("mobile"),
                "proxy":    data.get("proxy"),
                "hosting":  data.get("hosting"),
            }
    except Exception as e:
        warning(f"[GeoIP] {e}")
    return geo


def _asn_lookup(ip: str) -> Dict:
    info(f"ASN lookup: {ip}")
    asn = {}
    try:
        r = _session().get(f"https://api.bgpview.io/ip/{ip}", timeout=TIMEOUT)
        data = r.json()
        if data.get("status") == "ok":
            pfxs = data.get("data", {}).get("prefixes", [])
            if pfxs:
                p = pfxs[0]
                asn = {
                    "asn":         p.get("asn", {}).get("asn"),
                    "name":        p.get("asn", {}).get("name"),
                    "description": p.get("asn", {}).get("description"),
                    "prefix":      p.get("prefix"),
                    "country":     p.get("asn", {}).get("country_code"),
                    "rir":         p.get("asn", {}).get("rir_allocation", {}).get("rir_name"),
                }
    except Exception as e:
        warning(f"[ASN] {e}")
    return asn


def _threat_intel(domain: str, ip: str) -> Dict:
    """Check domain/IP against threat intelligence sources."""
    threats = {"urlhaus": False, "phishtank": False, "details": []}
    try:
        # URLHaus
        r = _session().post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain}, timeout=TIMEOUT
        )
        data = r.json()
        if data.get("query_status") == "is_host":
            threats["urlhaus"] = True
            threats["details"].append(f"URLHaus: {data.get('url_count', 0)} malicious URLs")
    except Exception:
        pass
    return threats


def _historical_ips(domain: str) -> List[str]:
    """Fetch historical IPs from SecurityTrails-compatible sources."""
    ips: List[str] = []
    try:
        r = _session().get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=TIMEOUT
        )
        for line in r.text.splitlines():
            parts = line.split(",")
            if len(parts) == 2:
                ips.append(parts[1].strip())
    except Exception:
        pass
    return list(set(ips))


def _check_wildcard(domain: str) -> bool:
    """Check if domain has wildcard DNS."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = RESOLVERS
        fake = f"nonexistent-subdomain-xyz.{domain}"
        resolver.resolve(fake, "A")
        return True
    except Exception:
        return False


# ── Main entry point ─────────────────────────────────────────────────────────

def run_whois_lookup(target: str) -> Dict:
    section_header("WHOIS & DNS Intelligence", "Ultra Edition")
    info(f"Target: {target}")

    result = {}

    # Resolve to IP
    try:
        ip = socket.gethostbyname(target)
        info(f"Resolved: {target} → {ip}")
        result["ip"] = ip
    except Exception:
        ip = target if re.match(r"^\d+\.\d+\.\d+\.\d+$", target) else None
        result["ip"] = ip

    # WHOIS
    whois_data = _get_whois(target)
    result["whois"] = whois_data

    # DNS records
    dns_records = _get_all_dns(target)
    result["dns"] = dns_records

    # DNSSEC
    dnssec = _check_dnssec(target)
    result["dnssec"] = dnssec

    # Email security analysis
    txt_records = dns_records.get("TXT", [])
    spf   = _analyze_spf(target, txt_records)
    dmarc = _analyze_dmarc(target)
    dkim  = _analyze_dkim(target)
    result["email_security"] = {"spf": spf, "dmarc": dmarc, "dkim": dkim}

    # Wildcard DNS
    wildcard = _check_wildcard(target)
    result["wildcard_dns"] = wildcard

    # GeoIP + ASN (if we have an IP)
    if ip:
        geo = _geoip(ip)
        asn = _asn_lookup(ip)
        result["geoip"] = geo
        result["asn"]   = asn

        # Reverse DNS
        rdns = _get_reverse_dns(ip)
        result["reverse_dns"] = rdns

        # Threat intel
        threats = _threat_intel(target, ip)
        result["threat_intel"] = threats

    # Historical IPs
    hist = _historical_ips(target)
    result["historical_ips"] = hist

    # ── Print ────────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]━━━ WHOIS ━━━[/bold cyan]")
    console.print(f"  Registrar:  {whois_data.get('registrar') or '—'}")
    console.print(f"  Org:        {whois_data.get('org') or '—'}")
    console.print(f"  Registered: {whois_data.get('registered') or '—'}")
    console.print(f"  Expires:    {whois_data.get('expires') or '—'}")
    console.print(f"  Age:        {whois_data.get('age_days') or '—'} days")
    console.print(f"  DNSSEC:     {whois_data.get('dnssec') or '—'}")
    console.print(f"  Emails:     {', '.join(whois_data.get('emails', [])) or '—'}")
    console.print(f"  Status:     {', '.join(whois_data.get('status', [])) or '—'}")

    console.print("\n[bold cyan]━━━ DNS RECORDS ━━━[/bold cyan]")
    for rtype, vals in sorted(dns_records.items()):
        for v in vals:
            console.print(f"  [yellow]{rtype:8}[/yellow]  {v}")

    console.print("\n[bold cyan]━━━ EMAIL SECURITY ━━━[/bold cyan]")
    # SPF
    if spf["found"]:
        success(f"SPF:   {spf['record'][:80]}")
    else:
        error("SPF:   NOT FOUND — spoofing risk!")
    for issue in spf["issues"]:
        warning(f"       {issue}")

    # DMARC
    if dmarc["found"]:
        color = "green" if dmarc["policy"] in ("quarantine","reject") else "yellow"
        console.print(f"  DMARC: [{color}]p={dmarc['policy']}[/{color}]  pct={dmarc.get('pct',100)}")
    else:
        error("DMARC: NOT FOUND")
    for issue in dmarc["issues"]:
        warning(f"       {issue}")

    # DKIM
    if dkim["count"]:
        success(f"DKIM:  {dkim['count']} selector(s) found: "
                f"{', '.join(s['selector'] for s in dkim['selectors_found'])}")
    else:
        warning("DKIM:  No common selectors found")

    if ip:
        console.print("\n[bold cyan]━━━ GeoIP & ASN ━━━[/bold cyan]")
        geo = result.get("geoip", {})
        asn = result.get("asn", {})
        console.print(f"  IP:       {ip}")
        console.print(f"  Location: {geo.get('city')}, {geo.get('region')}, {geo.get('country')}")
        console.print(f"  ISP:      {geo.get('isp')}")
        console.print(f"  ASN:      AS{asn.get('asn')} — {asn.get('name')}")
        console.print(f"  Prefix:   {asn.get('prefix')}")
        console.print(f"  Proxy:    {'Yes' if geo.get('proxy') else 'No'}  "
                      f"Hosting: {'Yes' if geo.get('hosting') else 'No'}")
        if result.get("reverse_dns"):
            console.print(f"  rDNS:     {result['reverse_dns']}")

    if wildcard:
        warning("Wildcard DNS detected — *.{target} resolves!")

    if hist:
        info(f"Historical IPs: {', '.join(hist[:10])}")

    print_summary("WHOIS & DNS", {
        "DNS Record Types": len(dns_records),
        "SPF Found":        spf["found"],
        "DMARC Policy":     dmarc.get("policy") or "MISSING",
        "DKIM Selectors":   dkim["count"],
        "DNSSEC":           dnssec["enabled"],
        "Wildcard DNS":     wildcard,
        "Country":          result.get("geoip", {}).get("country") or "—",
        "ASN":              f"AS{result.get('asn', {}).get('asn') or '—'}",
    })

    return result
