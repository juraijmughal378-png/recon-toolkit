"""
ai_analyzer.py — Ultra AI Vulnerability Analyzer
Features: Smart scan result analysis, risk scoring (0-100),
          attack path generation, exploit suggestions,
          remediation advice, executive summary generation,
          CVSS correlation, threat modeling
"""

import json
import os
import time
from typing import Dict, List, Optional, Tuple

import requests

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 30

# ── Risk scoring weights ──────────────────────────────────────────────────────
RISK_WEIGHTS = {
    # Ports
    "port_critical": 15,   # Docker, Redis, MongoDB unauthenticated
    "port_high":      8,   # RDP, SMB, VNC
    "port_medium":    3,   # HTTP, FTP
    # Vulnerabilities
    "cve_critical":  20,
    "cve_high":      12,
    "cve_medium":     5,
    "cve_kev":       25,   # CISA KEV = actively exploited
    # Web vulns
    "xss":           10,
    "sqli":          20,
    "lfi":           15,
    "ssrf":          15,
    "xxe":           15,
    "ssti":          20,
    "idor":          10,
    "open_redirect":  5,
    # Infrastructure
    "subdomain_takeover": 20,
    "cloud_public":       20,
    "default_creds":      25,
    "ssl_grade_f":        15,
    "ssl_grade_c":         8,
    "waf_none":            5,
    "secrets_critical":   25,
    "secrets_high":       15,
    # OSINT
    "emails_found":        2,
    "github_critical":    20,
}

ATTACK_PATHS = {
    "web_rce": {
        "name": "Web Application → RCE",
        "steps": [
            "1. SQLi → Read /etc/passwd via LOAD_FILE()",
            "2. SQLi → Write webshell via INTO OUTFILE",
            "3. SSTI → Direct RCE via template engine",
            "4. LFI + Log Poisoning → PHP execution",
            "5. XXE → SSRF → Internal service access",
            "6. Deserialization → RCE payload",
        ],
        "conditions": ["sqli", "ssti", "lfi", "xxe"],
    },
    "cloud_takeover": {
        "name": "Cloud Misconfiguration → Data Breach",
        "steps": [
            "1. Open S3/Azure/GCP bucket → Download sensitive files",
            "2. SSRF → AWS metadata → IAM credentials",
            "3. Leaked AWS keys → Full cloud account access",
            "4. Firebase open DB → User data dump",
            "5. Subdomain takeover → Phishing / cookie theft",
        ],
        "conditions": ["cloud_public", "ssrf", "secrets_critical"],
    },
    "network_pivot": {
        "name": "Exposed Services → Network Pivot",
        "steps": [
            "1. Redis unauthenticated → Write SSH key → RCE",
            "2. MongoDB unauthenticated → Data dump",
            "3. Elasticsearch open → Index dump",
            "4. Docker API → Container escape → Host RCE",
            "5. Kubernetes API → Pod exec → Node takeover",
        ],
        "conditions": ["port_critical"],
    },
    "credential_attack": {
        "name": "Credential Attacks → Account Takeover",
        "steps": [
            "1. Default credentials → Admin panel access",
            "2. GitHub leaked creds → Source code / DB access",
            "3. Email harvesting → Phishing / password spray",
            "4. IDOR → Account enumeration → Credential stuffing",
            "5. Brute force SSH/FTP → System access",
        ],
        "conditions": ["default_creds", "github_critical", "idor"],
    },
    "supply_chain": {
        "name": "Supply Chain / Third-Party Attack",
        "steps": [
            "1. JS secrets → API keys → Third-party access",
            "2. Subdomain takeover → Malicious content injection",
            "3. Open redirect → Phishing chain",
            "4. Outdated libraries → Known CVE exploitation",
            "5. Cloud bucket write → Malicious file hosting",
        ],
        "conditions": ["secrets_critical", "subdomain_takeover", "open_redirect"],
    },
}


def _calculate_risk_score(scan_results: Dict) -> Tuple[int, Dict, List[str]]:
    """Calculate comprehensive risk score from all scan results."""
    score   = 0
    factors = {}
    flags: List[str] = []

    # Port scan
    portscan = scan_results.get("portscan", {})
    risk_summary = portscan.get("risk_summary", {})
    crit = risk_summary.get("CRITICAL", 0)
    high = risk_summary.get("HIGH", 0)
    if crit:
        score += crit * RISK_WEIGHTS["port_critical"]
        factors["Critical Ports"] = crit
        flags.append("port_critical")
    if high:
        score += min(high * RISK_WEIGHTS["port_high"], 30)
        factors["High Risk Ports"] = high
        flags.append("port_high")

    # CVEs
    cve_data = scan_results.get("cve", {})
    sev_count = cve_data.get("severity_count", {})
    kev = cve_data.get("kev_count", 0)
    if sev_count.get("CRITICAL", 0):
        score += min(sev_count["CRITICAL"] * RISK_WEIGHTS["cve_critical"], 40)
        factors["Critical CVEs"] = sev_count["CRITICAL"]
    if sev_count.get("HIGH", 0):
        score += min(sev_count["HIGH"] * RISK_WEIGHTS["cve_high"], 25)
        factors["High CVEs"] = sev_count["HIGH"]
    if kev:
        score += min(kev * RISK_WEIGHTS["cve_kev"], 50)
        factors["CISA KEV CVEs"] = kev
        flags.append("cve_kev")

    # Web vulnerabilities
    vuln_map = {
        "xss":     ("xss",     "XSS"),
        "sqli":    ("sqli",    "SQLi"),
        "lfi":     ("lfi",     "LFI"),
        "ssrf":    ("ssrf",    "SSRF"),
        "xxe":     ("xxe",     "XXE"),
        "ssti":    ("ssti",    "SSTI"),
        "idor":    ("idor",    "IDOR"),
        "redirect":("open_redirect","Open Redirect"),
    }
    for key, (weight_key, label) in vuln_map.items():
        data = scan_results.get(key, {})
        total = data.get("total", 0)
        if total:
            score += min(total * RISK_WEIGHTS.get(weight_key, 5), 25)
            factors[f"{label} Found"] = total
            flags.append(weight_key)

    # SSL
    ssl_data = scan_results.get("ssl", {})
    grade = ssl_data.get("grade", "")
    if grade == "F":
        score += RISK_WEIGHTS["ssl_grade_f"]
        factors["SSL Grade F"] = True
    elif grade in ("C", "D"):
        score += RISK_WEIGHTS["ssl_grade_c"]
        factors[f"SSL Grade {grade}"] = True

    # WAF
    waf_data = scan_results.get("waf", {})
    if not waf_data.get("waf"):
        score += RISK_WEIGHTS["waf_none"]
        factors["No WAF"] = True

    # Cloud buckets
    cloud = scan_results.get("cloud", {})
    public = len(cloud.get("public", []))
    if public:
        score += public * RISK_WEIGHTS["cloud_public"]
        factors["Public Cloud Buckets"] = public
        flags.append("cloud_public")

    # Subdomain takeover
    takeover = scan_results.get("takeover", {})
    vuln_subs = len(takeover.get("vulnerable", []))
    if vuln_subs:
        score += vuln_subs * RISK_WEIGHTS["subdomain_takeover"]
        factors["Subdomain Takeovers"] = vuln_subs
        flags.append("subdomain_takeover")

    # Secrets in JS
    js_data = scan_results.get("js", {})
    js_sev  = js_data.get("sev_count", {})
    if js_sev.get("CRITICAL", 0):
        score += min(js_sev["CRITICAL"] * RISK_WEIGHTS["secrets_critical"], 30)
        factors["Critical JS Secrets"] = js_sev["CRITICAL"]
        flags.append("secrets_critical")

    # GitHub
    github = scan_results.get("github", {})
    gh_sev  = github.get("sev_count", {})
    if gh_sev.get("CRITICAL", 0):
        score += min(gh_sev["CRITICAL"] * RISK_WEIGHTS["github_critical"], 30)
        factors["GitHub Critical Leaks"] = gh_sev["CRITICAL"]
        flags.append("github_critical")

    # Default creds
    pw_data = scan_results.get("password", {})
    default_found = len(pw_data.get("default_creds", {}).get("credentials", []))
    if default_found:
        score += default_found * RISK_WEIGHTS["default_creds"]
        factors["Default Credentials"] = default_found
        flags.append("default_creds")

    score = min(score, 100)
    return score, factors, flags


def _get_risk_level(score: int) -> Tuple[str, str]:
    if score >= 75: return "CRITICAL", "bold red"
    if score >= 50: return "HIGH",     "red"
    if score >= 25: return "MEDIUM",   "yellow"
    return "LOW", "green"


def _get_attack_paths(flags: List[str]) -> List[Dict]:
    """Determine applicable attack paths."""
    applicable = []
    for path_key, path in ATTACK_PATHS.items():
        conditions = path["conditions"]
        matches = sum(1 for c in conditions if c in flags)
        if matches >= 1:
            path_copy = dict(path)
            path_copy["match_score"] = matches / len(conditions)
            applicable.append(path_copy)
    return sorted(applicable, key=lambda x: x["match_score"], reverse=True)


def _generate_remediation(factors: Dict, flags: List[str]) -> List[Dict]:
    """Generate remediation recommendations."""
    remediations = []

    remap = {
        "default_creds":      ("CRITICAL", "Change default credentials immediately",
                               "Enumerate all services, change all default passwords, implement MFA"),
        "cve_kev":            ("CRITICAL", "Patch CISA KEV vulnerabilities immediately",
                               "These are actively exploited in the wild — emergency patching required"),
        "sqli":               ("CRITICAL", "Fix SQL injection vulnerabilities",
                               "Use parameterized queries/prepared statements, input validation, WAF rules"),
        "ssti":               ("CRITICAL", "Fix SSTI — can lead to RCE",
                               "Sandbox template engines, avoid user input in templates"),
        "cloud_public":       ("CRITICAL", "Secure open cloud buckets",
                               "Remove public ACLs, enable bucket policies, audit S3/Azure/GCP permissions"),
        "secrets_critical":   ("CRITICAL", "Rotate all exposed credentials",
                               "Invalidate leaked keys immediately, audit git history, use secret managers"),
        "port_critical":      ("HIGH",     "Secure exposed critical services",
                               "Firewall Redis/MongoDB/Docker APIs, require authentication, use VPN"),
        "lfi":                ("HIGH",     "Fix LFI vulnerabilities",
                               "Whitelist allowed files, disable PHP wrappers, input sanitization"),
        "ssrf":               ("HIGH",     "Fix SSRF vulnerabilities",
                               "Whitelist allowed URLs, block internal IP ranges, use cloud IMDS v2"),
        "xxe":                ("HIGH",     "Disable XXE in XML parsers",
                               "Disable external entity processing, use safe XML parsing libraries"),
        "subdomain_takeover": ("HIGH",     "Fix subdomain takeovers",
                               "Remove dangling DNS records, claim unclaimed services, monitor DNS"),
        "xss":                ("MEDIUM",   "Fix XSS vulnerabilities",
                               "Output encoding, CSP headers, input validation"),
        "idor":               ("MEDIUM",   "Fix IDOR vulnerabilities",
                               "Implement proper authorization checks, use indirect references"),
        "open_redirect":      ("LOW",      "Fix open redirects",
                               "Whitelist redirect destinations, validate URL parameters"),
    }

    for flag in flags:
        if flag in remap:
            sev, title, detail = remap[flag]
            remediations.append({
                "severity": sev,
                "title":    title,
                "detail":   detail,
            })

    return sorted(remediations,
                  key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["severity"],4))


def _ai_analysis(target: str, scan_results: Dict) -> Optional[str]:
    """Use Claude API for intelligent analysis if available."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    # Build summary for AI
    summary = {
        "target":     target,
        "open_ports": len(scan_results.get("portscan", {}).get("tcp_open", [])),
        "cves":       scan_results.get("cve", {}).get("total", 0),
        "kev_cves":   scan_results.get("cve", {}).get("kev_count", 0),
        "xss":        scan_results.get("xss", {}).get("total", 0),
        "sqli":       scan_results.get("sqli", {}).get("total", 0),
        "subdomains": scan_results.get("subdomain", {}).get("total", 0),
        "ssl_grade":  scan_results.get("ssl", {}).get("grade", "N/A"),
        "waf":        scan_results.get("waf", {}).get("waf", []),
        "cloud_open": len(scan_results.get("cloud", {}).get("public", [])),
        "secrets":    scan_results.get("js", {}).get("sev_count", {}).get("CRITICAL", 0),
    }

    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5",
                "max_tokens": 500,
                "messages": [{
                    "role": "user",
                    "content": f"""You are a senior penetration tester. Analyze this scan summary and provide:
1. Top 3 critical findings
2. Most likely attack vector
3. One-line executive summary

Scan data: {json.dumps(summary)}

Be concise and technical."""
                }]
            },
            timeout=30
        )
        data = r.json()
        return data.get("content", [{}])[0].get("text", "")
    except Exception:
        return None


def run_ai_analyzer(target: str, scan_results: Dict) -> Dict:
    section_header("AI Vulnerability Analyzer", "Ultra Risk Scoring + Attack Paths + Remediation")
    info(f"Target: {target}")

    if not scan_results or len(scan_results) <= 2:
        warning("No scan results found — run other modules first")
        warning("Recommended: Run modules 1-10 first, then module 24")
        return {}

    # Calculate risk score
    info("Calculating risk score...")
    score, factors, flags = _calculate_risk_score(scan_results)
    risk_level, risk_color = _get_risk_level(score)

    # Get attack paths
    attack_paths = _get_attack_paths(flags)

    # Get remediation
    remediations = _generate_remediation(factors, flags)

    # AI analysis (if API key available)
    ai_insight = _ai_analysis(target, scan_results)

    # ── Print results ─────────────────────────────────────────────────────────

    # Risk score banner
    console.print()
    console.print(f"  ┌{'─'*50}┐")
    console.print(f"  │  OVERALL RISK SCORE: [{risk_color}]{score}/100 — {risk_level}[/{risk_color}]{'':>12}│")
    console.print(f"  └{'─'*50}┘")
    console.print()

    # Risk bar
    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    console.print(f"  [{risk_color}]{bar}[/{risk_color}]  {score}%")
    console.print()

    # Contributing factors
    console.print("[bold cyan]━━━ RISK FACTORS ━━━[/bold cyan]")
    for factor, value in sorted(factors.items(), key=lambda x: str(x[1]), reverse=True):
        console.print(f"  [yellow]►[/yellow]  {factor:35}  [red]{value}[/red]")

    # Attack paths
    console.print(f"\n[bold cyan]━━━ ATTACK PATHS ({len(attack_paths)}) ━━━[/bold cyan]")
    for i, path in enumerate(attack_paths[:3], 1):
        match_pct = int(path["match_score"] * 100)
        console.print(f"\n  [bold red]{i}. {path['name']}[/bold red]  [dim](match: {match_pct}%)[/dim]")
        for step in path["steps"]:
            console.print(f"     [dim]{step}[/dim]")

    # Remediation
    console.print(f"\n[bold cyan]━━━ REMEDIATION ({len(remediations)}) ━━━[/bold cyan]")
    SEV_COLORS = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"green"}
    for r in remediations:
        color = SEV_COLORS.get(r["severity"], "white")
        console.print(f"\n  [{color}][{r['severity']}][/{color}]  [bold]{r['title']}[/bold]")
        console.print(f"  [dim]{r['detail']}[/dim]")

    # AI Insight
    if ai_insight:
        console.print(f"\n[bold cyan]━━━ AI ANALYSIS ━━━[/bold cyan]")
        console.print(f"  [cyan]{ai_insight}[/cyan]")
    else:
        console.print(f"\n[dim]Tip: Set ANTHROPIC_API_KEY env var for AI-powered analysis[/dim]")

    # Executive summary
    console.print(f"\n[bold cyan]━━━ EXECUTIVE SUMMARY ━━━[/bold cyan]")
    vuln_count = sum(1 for k in ["xss","sqli","lfi","ssrf","xxe","ssti","idor"]
                     if scan_results.get(k, {}).get("total", 0) > 0)
    console.print(
        f"  Target [bold]{target}[/bold] scored [bold {risk_color}]{score}/100 ({risk_level})[/bold {risk_color}]. "
        f"Found [red]{len(factors)}[/red] risk factors including "
        f"[red]{vuln_count}[/red] web vulnerability types. "
        f"[red]{len(attack_paths)}[/red] viable attack paths identified. "
        f"Immediate action required on [red]{sum(1 for r in remediations if r['severity']=='CRITICAL')}[/red] critical items."
    )

    print_summary("AI Analyzer", {
        "Risk Score":      f"{score}/100",
        "Risk Level":      risk_level,
        "Risk Factors":    len(factors),
        "Attack Paths":    len(attack_paths),
        "Remediations":    len(remediations),
        "Critical Items":  sum(1 for r in remediations if r["severity"] == "CRITICAL"),
    })

    return {
        "risk_score":    score,
        "risk_level":    risk_level,
        "factors":       factors,
        "flags":         flags,
        "attack_paths":  attack_paths,
        "remediations":  remediations,
        "ai_insight":    ai_insight,
    }
