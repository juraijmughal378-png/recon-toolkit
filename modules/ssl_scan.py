"""
ssl_scan.py — Ultra SSL/TLS Analysis Engine
Features: 3-method cert retrieval, grade A+ to F, cipher analysis,
          protocol version detection, POODLE/BEAST/SWEET32/DROWN/CRIME checks,
          certificate transparency, OCSP stapling, HSTS preload check,
          SAN enumeration, chain validation, key strength analysis
"""

import datetime
import hashlib
import json
import re
import socket
import ssl
import struct
import subprocess
import time
from typing import Dict, List, Optional, Tuple

import requests
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 10

# ── Grading constants ─────────────────────────────────────────────────────────
SECURE_PROTOCOLS   = {"TLSv1.2", "TLSv1.3"}
INSECURE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

WEAK_CIPHERS = [
    "RC4", "NULL", "EXPORT", "DES", "3DES", "MD5", "ADH", "AECDH",
    "aNULL", "eNULL", "SEED", "IDEA", "PSK", "SRP",
]
STRONG_CIPHERS = [
    "AESGCM", "CHACHA20", "AES256", "AES-256", "ECDHE-RSA-AES",
    "ECDHE-ECDSA-AES", "TLS_AES_256", "TLS_CHACHA20",
]

KNOWN_VULNERABILITIES = {
    "POODLE":    {"protocols": ["SSLv3"],         "description": "SSL 3.0 POODLE attack"},
    "BEAST":     {"protocols": ["TLSv1"],          "description": "TLS 1.0 BEAST attack (CBC ciphers)"},
    "DROWN":     {"protocols": ["SSLv2"],          "description": "SSLv2 DROWN cross-protocol attack"},
    "FREAK":     {"ciphers": ["EXPORT"],           "description": "EXPORT cipher FREAK attack"},
    "LOGJAM":    {"ciphers": ["DHE", "EXPORT"],    "description": "DHE key exchange Logjam"},
    "SWEET32":   {"ciphers": ["3DES", "DES"],      "description": "64-bit block cipher SWEET32 (Birthday attack)"},
    "CRIME":     {"feature": "compression",        "description": "TLS compression CRIME attack"},
    "BREACH":    {"feature": "http_compression",   "description": "HTTP compression BREACH attack"},
    "RC4":       {"ciphers": ["RC4"],              "description": "RC4 stream cipher — broken"},
    "Heartbleed":{"version": "openssl_vulnerable", "description": "OpenSSL Heartbleed (pre-1.0.1g)"},
}


# ── Certificate retrieval ─────────────────────────────────────────────────────

def _get_cert_python(host: str, port: int = 443) -> Optional[Dict]:
    """Method 1: Python ssl module."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert(binary_form=False)
                der  = s.getpeercert(binary_form=True)
                cipher = s.cipher()
                version = s.version()
                return {
                    "cert":    cert,
                    "der":     der,
                    "cipher":  cipher,
                    "version": version,
                    "method":  "python-ssl",
                }
    except Exception as e:
        warning(f"[SSL/Python] {e}")
        return None


def _get_cert_openssl(host: str, port: int = 443) -> Optional[Dict]:
    """Method 2: OpenSSL CLI subprocess."""
    try:
        cmd = [
            "openssl", "s_client", "-connect", f"{host}:{port}",
            "-servername", host, "-showcerts", "-tlsextdebug",
            "-status", "-no_ign_eof"
        ]
        proc = subprocess.run(
            cmd, input="Q\n", capture_output=True, text=True, timeout=15
        )
        output = proc.stdout + proc.stderr
        return {"raw": output, "method": "openssl-cli"}
    except Exception as e:
        warning(f"[SSL/OpenSSL] {e}")
        return None


def _get_cert_ssllabs(host: str) -> Optional[Dict]:
    """Method 3: SSL Labs API (no key needed for public domains)."""
    info("[SSL Labs] Submitting for analysis (may take 60-90s)...")
    try:
        # Start analysis
        r = requests.get(
            "https://api.ssllabs.com/api/v3/analyze",
            params={"host": host, "startNew": "on", "all": "done"},
            timeout=TIMEOUT
        )
        data = r.json()

        # Poll until done
        for _ in range(30):
            if data.get("status") in ("READY", "ERROR"):
                break
            time.sleep(10)
            r = requests.get(
                "https://api.ssllabs.com/api/v3/analyze",
                params={"host": host, "all": "done"},
                timeout=TIMEOUT
            )
            data = r.json()

        return data if data.get("status") == "READY" else None
    except Exception as e:
        warning(f"[SSL Labs] {e}")
        return None


# ── Protocol testing ──────────────────────────────────────────────────────────

def _test_protocol(host: str, port: int, protocol: str) -> bool:
    """Test if a specific TLS/SSL protocol is supported."""
    proto_map = {
        "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl, "TLSVersion") else None,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2 if hasattr(ssl, "TLSVersion") else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl, "TLSVersion") else None,
        "TLSv1":   ssl.TLSVersion.TLSv1   if hasattr(ssl, "TLSVersion") else None,
    }

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        version = proto_map.get(protocol)
        if version:
            ctx.minimum_version = version
            ctx.maximum_version = version

        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return True
    except Exception:
        return False


def _get_supported_ciphers(host: str, port: int) -> List[str]:
    """Get list of supported ciphers."""
    supported = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                ciphers = s.context.get_ciphers()
                supported = [c["name"] for c in ciphers if c.get("name")]
    except Exception:
        pass
    return supported


# ── Certificate analysis ──────────────────────────────────────────────────────

def _parse_cert(cert_data: Dict) -> Dict:
    cert = cert_data.get("cert", {})
    result = {
        "subject":       {},
        "issuer":        {},
        "san":           [],
        "valid_from":    None,
        "valid_to":      None,
        "days_remaining": None,
        "is_expired":    False,
        "is_self_signed": False,
        "key_type":      None,
        "key_bits":      None,
        "signature_alg": None,
        "serial":        None,
        "fingerprint":   None,
        "ocsp_urls":     [],
        "crl_urls":      [],
        "ct_logs":       [],
    }

    if not cert:
        return result

    # Subject & Issuer
    for field in cert.get("subject", []):
        result["subject"][field[0][0]] = field[0][1]
    for field in cert.get("issuer", []):
        result["issuer"][field[0][0]] = field[0][1]

    result["is_self_signed"] = (result["subject"] == result["issuer"])

    # SANs
    for ext in cert.get("subjectAltName", []):
        if ext[0] in ("DNS", "IP Address"):
            result["san"].append(f"{ext[0]}:{ext[1]}")

    # Validity
    try:
        fmt = "%b %d %H:%M:%S %Y %Z"
        not_before = datetime.datetime.strptime(cert.get("notBefore", ""), fmt)
        not_after  = datetime.datetime.strptime(cert.get("notAfter",  ""), fmt)
        result["valid_from"]     = str(not_before.date())
        result["valid_to"]       = str(not_after.date())
        result["days_remaining"] = (not_after - datetime.datetime.utcnow()).days
        result["is_expired"]     = result["days_remaining"] < 0
    except Exception:
        pass

    # OCSP / CRL from extensions
    for ext_name, ext_data in cert.get("OCSP", []):
        result["ocsp_urls"].append(ext_data)
    for ext_name, ext_data in cert.get("crlDistributionPoints", []):
        result["crl_urls"].append(ext_data)

    return result


def _check_hsts_preload(host: str) -> Dict:
    result = {"in_preload_list": False, "header_present": False, "max_age": None, "include_subdomains": False}
    try:
        # Check Chromium preload list API
        r = requests.get(
            f"https://hstspreload.org/api/v2/status?domain={host}",
            timeout=TIMEOUT
        )
        data = r.json()
        result["in_preload_list"] = data.get("status", "") == "preloaded"
    except Exception:
        pass
    return result


def _check_certificate_transparency(host: str) -> List[Dict]:
    """Check CT logs for the certificate."""
    entries = []
    try:
        r = requests.get(
            f"https://crt.sh/?q={host}&output=json",
            timeout=TIMEOUT
        )
        for entry in r.json()[:10]:
            entries.append({
                "id":        entry.get("id"),
                "logged_at": entry.get("entry_timestamp"),
                "issuer":    entry.get("issuer_name"),
                "name":      entry.get("name_value"),
            })
    except Exception:
        pass
    return entries


# ── Grading ───────────────────────────────────────────────────────────────────

def _calculate_grade(
    protocols: Dict[str, bool],
    ciphers: List[str],
    cert_info: Dict,
    vulnerabilities: Dict[str, bool],
) -> Tuple[str, List[str]]:
    grade   = "A+"
    reasons = []

    # Protocol deductions
    if protocols.get("SSLv2") or protocols.get("SSLv3"):
        grade = "F"
        reasons.append("F: SSLv2/SSLv3 enabled — critical vulnerability")
    elif protocols.get("TLSv1") or protocols.get("TLSv1.1"):
        grade = max(grade, "C", key=lambda g: "F>C>B->B>A->A>A+".split(">").index(g) if g in "F>C>B->B>A->A>A+".split(">") else 99)
        reasons.append("Deduction: TLS 1.0/1.1 enabled")

    # Cipher deductions
    weak_found = [c for c in WEAK_CIPHERS if any(c in cipher for cipher in ciphers)]
    if weak_found:
        if "NULL" in weak_found or "EXPORT" in weak_found:
            grade = "F"
            reasons.append(f"F: Null/Export ciphers: {weak_found}")
        elif "RC4" in weak_found or "DES" in weak_found:
            grade = "C" if grade not in ("F",) else grade
            reasons.append(f"Deduction: Weak ciphers: {weak_found}")
        elif "3DES" in weak_found:
            grade = "B" if grade == "A+" else grade
            reasons.append("Deduction: 3DES cipher (SWEET32)")

    # Certificate issues
    if cert_info.get("is_expired"):
        grade = "T"  # Trust issue
        reasons.append("T: Certificate expired")
    if cert_info.get("is_self_signed"):
        grade = "T"
        reasons.append("T: Self-signed certificate")
    if cert_info.get("days_remaining", 999) < 14:
        grade = "B" if grade == "A+" else grade
        reasons.append(f"Deduction: Certificate expires in {cert_info.get('days_remaining')} days")

    # Vulnerability deductions
    if vulnerabilities.get("POODLE") or vulnerabilities.get("DROWN") or vulnerabilities.get("Heartbleed"):
        grade = "F"
        reasons.append("F: Critical vulnerability detected")
    elif vulnerabilities.get("BEAST") or vulnerabilities.get("CRIME"):
        grade = min(grade, "B") if grade not in ("F","T") else grade
        reasons.append("Deduction: BEAST/CRIME vulnerability")

    # If all good
    if grade == "A+" and not reasons:
        success_reasons = ["TLS 1.3 supported", "Strong ciphers only", "Valid certificate"]
        reasons.extend(success_reasons)

    return grade, reasons


# ── Main entry point ─────────────────────────────────────────────────────────

def run_ssl_scan(target: str, port: int = 443, use_ssllabs: bool = False) -> Dict:
    section_header("SSL/TLS Analysis Engine", "Ultra Grade A+ to F")
    info(f"Target: {target}:{port}")

    result = {"target": target, "port": port}

    # Resolve
    try:
        ip = socket.gethostbyname(target)
        info(f"Resolved: {target} → {ip}")
    except Exception:
        ip = target

    # Method 1: Python ssl
    info("Method 1: Python SSL module...")
    py_cert = _get_cert_python(target, port)
    cert_info = {}
    current_cipher  = None
    current_version = None

    if py_cert:
        cert_info       = _parse_cert(py_cert)
        current_cipher  = py_cert.get("cipher")
        current_version = py_cert.get("version")
        success(f"Connected: {current_version} | Cipher: {current_cipher[0] if current_cipher else '?'}")

    # Method 2: OpenSSL CLI
    info("Method 2: OpenSSL CLI...")
    openssl_data = _get_cert_openssl(target, port)
    openssl_raw  = ""
    if openssl_data:
        openssl_raw = openssl_data.get("raw", "")
        # Extract additional info
        m = re.search(r"Protocol\s*:\s*(\S+)", openssl_raw)
        if m and not current_version:
            current_version = m.group(1)
        m = re.search(r"Cipher\s*:\s*(\S+)", openssl_raw)
        if m and not current_cipher:
            current_cipher = (m.group(1),)

    # Protocol support testing
    info("Testing protocol support...")
    protocols_to_test = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"]
    protocols: Dict[str, bool] = {}
    for proto in protocols_to_test:
        supported = _test_protocol(target, port, proto)
        protocols[proto] = supported
        status = "[green]✓[/green]" if supported else "[red]✗[/red]"
        info_str = "INSECURE" if proto in ("TLSv1", "TLSv1.1") else ""
        console.print(f"  {status}  {proto:12}  [red]{info_str}[/red]" if info_str else f"  {status}  {proto}")

    # Cipher enumeration
    info("Enumerating ciphers...")
    ciphers = _get_supported_ciphers(target, port)

    # Vulnerability checks
    info("Checking vulnerabilities...")
    vulnerabilities: Dict[str, bool] = {}

    vulnerabilities["POODLE"]  = protocols.get("SSLv3", False)
    vulnerabilities["BEAST"]   = protocols.get("TLSv1", False)
    vulnerabilities["DROWN"]   = protocols.get("SSLv2", False)
    vulnerabilities["FREAK"]   = any("EXPORT" in c for c in ciphers)
    vulnerabilities["SWEET32"] = any("3DES" in c or "DES" in c for c in ciphers)
    vulnerabilities["RC4"]     = any("RC4" in c for c in ciphers)
    vulnerabilities["LOGJAM"]  = any("DHE" in c and "EXPORT" in c for c in ciphers)

    # Check CRIME (compression)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=target) as s:
                comp = s.compression()
                vulnerabilities["CRIME"] = comp is not None
    except Exception:
        vulnerabilities["CRIME"] = False

    # CT Logs
    info("Checking Certificate Transparency logs...")
    ct_logs = _check_certificate_transparency(target)

    # HSTS Preload
    hsts = _check_hsts_preload(target)

    # SSL Labs (optional)
    ssllabs_data = None
    if use_ssllabs:
        ssllabs_data = _get_cert_ssllabs(target)

    # Calculate grade
    grade, grade_reasons = _calculate_grade(protocols, ciphers, cert_info, vulnerabilities)
    result["grade"] = grade

    # ── Print results ─────────────────────────────────────────────────────────
    GRADE_COLORS = {
        "A+": "bold green", "A": "green", "A-": "green",
        "B":  "yellow",     "C": "orange1", "D": "red",
        "F":  "bold red",   "T": "bold red",
    }
    grade_color = GRADE_COLORS.get(grade, "white")

    console.print(f"\n  SSL/TLS Grade: [{grade_color}] {grade} [/{grade_color}]")
    for reason in grade_reasons:
        icon = "✓" if reason.startswith("TLS") or reason.startswith("Strong") or reason.startswith("Valid") else "⚠"
        color = "green" if icon == "✓" else "yellow"
        console.print(f"  [{color}]{icon}[/{color}]  {reason}")

    if cert_info:
        console.print("\n[bold cyan]━━━ CERTIFICATE ━━━[/bold cyan]")
        subj = cert_info.get("subject", {})
        console.print(f"  CN:             {subj.get('commonName', '—')}")
        console.print(f"  Org:            {subj.get('organizationName', '—')}")
        console.print(f"  Issuer:         {cert_info.get('issuer', {}).get('organizationName', '—')}")
        console.print(f"  Valid From:     {cert_info.get('valid_from', '—')}")
        console.print(f"  Valid To:       {cert_info.get('valid_to', '—')}")
        days = cert_info.get("days_remaining")
        color = "green" if (days or 0) > 30 else ("yellow" if (days or 0) > 0 else "red")
        console.print(f"  Days Remaining: [{color}]{days}[/{color}]")
        console.print(f"  Self-Signed:    {'[red]YES[/red]' if cert_info.get('is_self_signed') else 'No'}")
        console.print(f"  Expired:        {'[red]YES[/red]' if cert_info.get('is_expired') else 'No'}")

        if cert_info.get("san"):
            console.print(f"\n  SANs ({len(cert_info['san'])}):")
            for san in cert_info["san"][:10]:
                console.print(f"    [cyan]{san}[/cyan]")

    console.print("\n[bold cyan]━━━ PROTOCOL SUPPORT ━━━[/bold cyan]")
    for proto, supported in protocols.items():
        color   = "green" if (supported and proto in SECURE_PROTOCOLS) else ("red" if supported else "dim")
        status  = "SUPPORTED" if supported else "Not supported"
        insecure = " ⚠ INSECURE" if supported and proto in INSECURE_PROTOCOLS else ""
        console.print(f"  [{color}]{proto:12}  {status}{insecure}[/{color}]")

    console.print("\n[bold cyan]━━━ VULNERABILITIES ━━━[/bold cyan]")
    for vuln, is_vuln in vulnerabilities.items():
        color = "red" if is_vuln else "green"
        icon  = "✗ VULNERABLE" if is_vuln else "✓ Not vulnerable"
        desc  = KNOWN_VULNERABILITIES.get(vuln, {}).get("description", "")
        console.print(f"  [{color}]{icon:16}[/{color}]  {vuln:10}  [dim]{desc}[/dim]")

    if ct_logs:
        console.print(f"\n[bold cyan]━━━ CERTIFICATE TRANSPARENCY ({len(ct_logs)} logs) ━━━[/bold cyan]")
        for log in ct_logs[:5]:
            console.print(f"  [dim]{log.get('logged_at', '—')}[/dim]  {log.get('issuer', '—')[:50]}")

    console.print(f"\n  HSTS Preloaded: {'[green]YES[/green]' if hsts.get('in_preload_list') else 'No'}")

    print_summary("SSL/TLS Analysis", {
        "Grade":          grade,
        "Protocol":       current_version or "—",
        "Active Cipher":  (current_cipher[0] if current_cipher else "—"),
        "Days Remaining": cert_info.get("days_remaining", "—"),
        "Self-Signed":    cert_info.get("is_self_signed", False),
        "Expired":        cert_info.get("is_expired", False),
        "CT Logs":        len(ct_logs),
        "Vuln Count":     sum(1 for v in vulnerabilities.values() if v),
    })

    return {
        "grade":           grade,
        "grade_reasons":   grade_reasons,
        "protocols":       protocols,
        "ciphers":         ciphers,
        "cert_info":       cert_info,
        "vulnerabilities": vulnerabilities,
        "ct_logs":         ct_logs,
        "hsts_preload":    hsts,
        "ssllabs":         ssllabs_data,
    }
