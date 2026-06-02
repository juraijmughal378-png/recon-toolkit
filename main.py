"""
main.py — Recon Toolkit Pro v3.2 Ultra
31 modules + Stealth + Profiles + Notifications + Config
"""

import os
import sys
import time
from typing import Dict, Optional

from modules.config import load_config, get, get_profile, is_stealth_mode
from modules.notify import get_notifier
from ui.rich_ui import (
    console, print_banner, info, warning, error, success
)
from reports.report_gen import save_all
from rich.rule import Rule
from rich.table import Table
from rich import box

# Load config on startup
load_config()

RECON_MODULES = [
    ("1",  "🔍 Subdomain Enum",      "15-source + DNS brute + permutations"),
    ("2",  "🔌 Port Scanner",        "TCP+UDP, 1000+ ports, OS fingerprint"),
    ("3",  "🌐 WHOIS & DNS",         "WHOIS + GeoIP + ASN + SPF/DMARC/DKIM"),
    ("4",  "🔎 Google Dorking",      "80+ dorks, 12 categories, multi-engine"),
    ("5",  "🛡  WAF Detection",       "35+ vendors + bypass techniques"),
    ("6",  "📧 Email Harvesting",     "10-source + pattern gen + MX validation"),
    ("7",  "👁  Shodan Intel",        "Full API + exposure score + CVEs"),
    ("8",  "🖥  Tech Fingerprint",    "80+ technologies + security headers"),
    ("9",  "🔒 SSL/TLS Analysis",     "Grade A+→F + POODLE/BEAST/CRIME"),
    ("10", "💀 CVE Correlation",      "NVD API v2 + CISA KEV + CVSS v3"),
]
ADVANCED_MODULES = [
    ("11", "🎯 Subdomain Takeover",  "50+ services + CNAME chain + PoC"),
    ("12", "📂 Directory Fuzzer",    "500+ wordlist + gobuster-style"),
    ("13", "🔑 JS Analyzer",         "80+ secret patterns + DOM XSS"),
    ("14", "🐙 GitHub Dorking",      "60+ dorks + credential hunter"),
    ("15", "☁  Cloud Buckets",       "AWS S3 + Azure + GCP + Firebase"),
]
ATTACK_MODULES = [
    ("16", "🎭 XSS Scanner",         "Reflected + DOM + Stored | 500+ payloads"),
    ("17", "💉 SQLi Scanner",        "Error + Boolean + Time + Union | 10 DBs"),
    ("18", "📁 LFI Scanner",         "200+ payloads + PHP wrappers + RFI"),
    ("19", "🌐 SSRF Scanner",        "Cloud metadata + blind + protocols"),
    ("20", "📦 XXE Scanner",         "Classic + Blind + OOB + SVG + XInclude"),
    ("21", "🧨 SSTI Scanner",        "15 engines + math detect + auto RCE"),
    ("22", "↪  Open Redirect",       "100+ payloads + SSRF chain + headers"),
    ("23", "🔓 IDOR Scanner",        "ID fuzzing + API + mass assignment"),
]
POWER_MODULES = [
    ("24", "🤖 AI Analyzer",         "Risk score + attack paths + remediation"),
    ("25", "🔐 Password Attacks",    "Hash crack + brute force + default creds"),
    ("26", "🌍 Network Scanner",     "Host discovery + ARP + SNMP + NetBIOS"),
    ("27", "💣 Exploit Suggester",   "CVE + port + tech → MSF + PoC auto-map"),
]
ULTRA_MODULES = [
    ("28", "⚛  Nuclei Scanner",      "5000+ templates | CVE + misconfig"),
    ("29", "🗺  Nmap Scanner",        "Full NSE scripts + OS detect + vuln"),
    ("30", "🌐 Web Dashboard",       "Live browser dashboard + monitor"),
    ("31", "📸 Auto Screenshots",    "Headless browser + bulk + gallery"),
]

PROFILES = {
    "bb":      ("Bug Bounty",   [1,2,3,8,9,11,12,13,14,15,16,17,18,19,20,21,22,23]),
    "pentest": ("Pentest",      [1,2,3,5,6,7,8,9,10,11,12,16,17,18,19,24,25,26,27,28,29]),
    "ctf":     ("CTF",          [1,2,3,8,9,12,16,17,18,19,20,21]),
    "quick":   ("Quick Recon",  [1,2,3,8,9,10]),
    "stealth": ("Stealth OSINT",[1,3,4,6,14]),
}


def _print_menu():
    console.print()
    def _tbl(title, items, color):
        t = Table(title=f"[bold {color}]{title}[/bold {color}]",
                  box=box.SIMPLE, show_header=False, pad_edge=False,
                  padding=(0, 2), expand=False)
        t.add_column("n",  style="bold yellow", width=4,  justify="right")
        t.add_column("nm", style="bold white",  width=24)
        t.add_column("d",  style="dim",         width=38)
        t.add_column("n2", style="bold yellow", width=4,  justify="right")
        t.add_column("nm2","bold white",        width=24)
        t.add_column("d2", style="dim",         width=38)
        for i in range(0, len(items), 2):
            n1,nm1,d1 = items[i]
            n2,nm2,d2 = items[i+1] if i+1 < len(items) else ("","","")
            t.add_row(n1,nm1,d1,n2,nm2,d2)
        console.print(t)

    _tbl("RECON (1-10)",     RECON_MODULES,    "cyan")
    _tbl("ADVANCED (11-15)", ADVANCED_MODULES, "magenta")
    _tbl("ATTACK (16-23)",   ATTACK_MODULES,   "red")
    _tbl("POWER (24-27)",    POWER_MODULES,    "yellow")
    _tbl("ULTRA (28-31)",    ULTRA_MODULES,    "green")

    console.print()
    console.print(Rule(style="dim"))

    # Special options + profiles
    sp = Table(box=box.SIMPLE, show_header=False, pad_edge=False, padding=(0,2))
    for _ in range(6): sp.add_column(width=14)
    sp.add_row(
        "[bold yellow]88[/bold yellow]","[bold green]⚡ Full Recon[/bold green]",
        "[bold yellow]00[/bold yellow]","[bold red]🔥 Full Attack[/bold red]",
        "[bold yellow]99[/bold yellow]","[bold blue]⚙  Custom[/bold blue]",
    )
    sp.add_row(
        "[bold yellow]bb[/bold yellow]","[cyan]Bug Bounty[/cyan]",
        "[bold yellow]pt[/bold yellow]","[cyan]Pentest[/cyan]",
        "[bold yellow]ctf[/bold yellow]","[cyan]CTF Mode[/cyan]",
    )
    sp.add_row(
        "[bold yellow]qs[/bold yellow]","[cyan]Quick Scan[/cyan]",
        "[bold yellow]st[/bold yellow]","[cyan]Stealth OSINT[/cyan]",
        "[bold yellow]0[/bold yellow]","[red]✖ Exit[/red]",
    )
    console.print(sp)

    # Status indicators
    stealth_on = is_stealth_mode()
    notif_on   = get("notifications", "enabled", False)
    console.print(
        f"\n  [dim]Stealth:[/dim] {'[green]ON[/green]' if stealth_on else '[red]OFF[/red]'}  "
        f"[dim]Notifications:[/dim] {'[green]ON[/green]' if notif_on else '[red]OFF[/red]'}  "
        f"[dim]Config:[/dim] [cyan]config.yaml[/cyan]"
    )
    console.print()


def _run_module(num: str, target: str, all_results: Dict) -> Optional[Dict]:
    try:
        if num=="1":
            from modules.subdomain import run_subdomain_enum
            r=run_subdomain_enum(target); all_results["subdomain"]=r; return r
        elif num=="2":
            from modules.portscan import run_port_scan
            r=run_port_scan(target); all_results["portscan"]=r; return r
        elif num=="3":
            from modules.whois_info import run_whois_lookup
            r=run_whois_lookup(target); all_results["whois"]=r; return r
        elif num=="4":
            from modules.dorking import run_dorking
            r=run_dorking(target); all_results["dorking"]=r; return r
        elif num=="5":
            from modules.waf_detect import run_waf_detect
            r=run_waf_detect(target); all_results["waf"]=r; return r
        elif num=="6":
            from modules.email_harvest import run_email_harvest
            r=run_email_harvest(target); all_results["email"]=r; return r
        elif num=="7":
            from modules.shodan_lookup import run_shodan_lookup
            r=run_shodan_lookup(target); all_results["shodan"]=r; return r
        elif num=="8":
            from modules.fingerprint import run_fingerprint
            r=run_fingerprint(target); all_results["fingerprint"]=r; return r
        elif num=="9":
            from modules.ssl_scan import run_ssl_scan
            r=run_ssl_scan(target); all_results["ssl"]=r; return r
        elif num=="10":
            from modules.cve_check import run_cve_check
            ctx={**all_results.get("portscan",{}),**all_results.get("fingerprint",{})}
            r=run_cve_check(target,scan_results=ctx or None); all_results["cve"]=r; return r
        elif num=="11":
            from modules.takeover import run_takeover_check
            subs=[s["subdomain"] for s in all_results.get("subdomain",{}).get("subdomains",[])]
            r=run_takeover_check(target,subs or None); all_results["takeover"]=r; return r
        elif num=="12":
            from modules.fuzzer import run_fuzzer
            r=run_fuzzer(target); all_results["fuzzer"]=r; return r
        elif num=="13":
            from modules.js_analyzer import run_js_analyzer
            r=run_js_analyzer(target); all_results["js"]=r; return r
        elif num=="14":
            from modules.github_dork import run_github_dork
            r=run_github_dork(target); all_results["github"]=r; return r
        elif num=="15":
            from modules.cloud_enum import run_cloud_enum
            r=run_cloud_enum(target); all_results["cloud"]=r; return r
        elif num=="16":
            from modules.xss_scanner import run_xss_scanner
            r=run_xss_scanner(target); all_results["xss"]=r; return r
        elif num=="17":
            from modules.sqli_scanner import run_sqli_scanner
            r=run_sqli_scanner(target); all_results["sqli"]=r; return r
        elif num=="18":
            from modules.lfi_scanner import run_lfi_scanner
            r=run_lfi_scanner(target); all_results["lfi"]=r; return r
        elif num=="19":
            from modules.ssrf_scanner import run_ssrf_scanner
            r=run_ssrf_scanner(target); all_results["ssrf"]=r; return r
        elif num=="20":
            from modules.xxe_scanner import run_xxe_scanner
            r=run_xxe_scanner(target); all_results["xxe"]=r; return r
        elif num=="21":
            from modules.ssti_scanner import run_ssti_scanner
            r=run_ssti_scanner(target); all_results["ssti"]=r; return r
        elif num=="22":
            from modules.open_redirect import run_open_redirect
            r=run_open_redirect(target); all_results["redirect"]=r; return r
        elif num=="23":
            from modules.idor_scanner import run_idor_scanner
            r=run_idor_scanner(target); all_results["idor"]=r; return r
        elif num=="24":
            from modules.ai_analyzer import run_ai_analyzer
            r=run_ai_analyzer(target,all_results); all_results["ai"]=r; return r
        elif num=="25":
            from modules.password_attacks import run_password_attacks
            r=run_password_attacks(target,all_results.get("portscan",{})); all_results["password"]=r; return r
        elif num=="26":
            from modules.network_scanner import run_network_scanner
            r=run_network_scanner(target); all_results["network"]=r; return r
        elif num=="27":
            from modules.exploit_suggester import run_exploit_suggester
            r=run_exploit_suggester(target,all_results); all_results["exploits"]=r; return r
        elif num=="28":
            from modules.nuclei_scan import run_nuclei_scan
            r=run_nuclei_scan(target); all_results["nuclei"]=r; return r
        elif num=="29":
            from modules.nmap_scan import run_nmap_scan
            r=run_nmap_scan(target); all_results["nmap"]=r; return r
        elif num=="30":
            from modules.web_dashboard import run_web_dashboard
            r=run_web_dashboard(); all_results["dashboard"]=r; return r
        elif num=="31":
            from modules.screenshot import run_screenshots
            r=run_screenshots(target,all_results); all_results["screenshots"]=r; return r
    except KeyboardInterrupt:
        warning("Module interrupted")
        return None
    except Exception as e:
        error(f"Module {num} error: {e}")
        console.print_exception(show_locals=False)
        return None


def _run_modules(mods: list, target: str, all_results: Dict, label: str = ""):
    total = len(mods)
    notifier = get_notifier()
    notifier.scan_started(target)

    for i, mod in enumerate(mods, 1):
        console.rule(f"[bold cyan]Module {mod} ({i}/{total}) {label}[/bold cyan]")
        result = _run_module(str(mod), target, all_results)

        # Notify critical findings
        for key in ["xss","sqli","lfi","ssrf","ssti","xxe"]:
            if str(mod) in {"16":"xss","17":"sqli","18":"lfi","19":"ssrf","21":"ssti","20":"xxe"}.get(str(mod),{}):
                findings = (result or {}).get("findings", [])
                for f in findings:
                    if f.get("severity") in ("CRITICAL","HIGH"):
                        notifier.critical_finding(target, f)


def main():
    print_banner()
    while True:
        _print_menu()
        choice = console.input(" [bold yellow]Select[/bold yellow] [bold cyan]>[/bold cyan] ").strip().lower()

        if choice == "0":
            console.print("\n[bold cyan]Goodbye![/bold cyan]\n"); sys.exit(0)

        valid = [str(i) for i in range(1,32)] + ["88","99","00","bb","pt","ctf","qs","st"]
        if choice not in valid:
            warning(f"Invalid: {choice}"); continue

        target = console.input(
            "\n [bold cyan]Target[/bold cyan] [dim](domain/IP/network)[/dim] [bold cyan]>[/bold cyan] "
        ).strip()
        if not target:
            warning("No target provided"); continue

        console.print(f"\n  [bold green]Target:[/bold green] [bold]{target}[/bold]")
        if is_stealth_mode():
            console.print("  [yellow]⚠ Stealth mode active — slower but quieter[/yellow]")
        console.print()

        all_results: Dict = {
            "_target":  target,
            "_started": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        start_time = time.time()

        # Profile & mode selection
        if choice == "88":
            info("Full Recon — modules 1-10")
            _run_modules(list(range(1,11)), target, all_results, "Full Recon")

        elif choice == "00":
            info("Full Attack — all 31 modules")
            _run_modules(list(range(1,32)), target, all_results, "Full Attack")

        elif choice == "bb":
            name, mods = PROFILES["bb"]
            info(f"Profile: {name}")
            _run_modules(mods, target, all_results, name)

        elif choice == "pt":
            name, mods = PROFILES["pentest"]
            info(f"Profile: {name}")
            _run_modules(mods, target, all_results, name)

        elif choice == "ctf":
            name, mods = PROFILES["ctf"]
            info(f"Profile: {name}")
            _run_modules(mods, target, all_results, name)

        elif choice == "qs":
            name, mods = PROFILES["quick"]
            info(f"Profile: {name}")
            _run_modules(mods, target, all_results, name)

        elif choice == "st":
            name, mods = PROFILES["stealth"]
            info(f"Profile: {name} — passive only")
            _run_modules(mods, target, all_results, name)

        elif choice == "99":
            console.print(" [dim]Enter module numbers  e.g. 1 2 28 29[/dim]")
            line = console.input(" [bold yellow]Modules[/bold yellow] [bold cyan]>[/bold cyan] ").strip()
            mods = [int(x) for x in line.split() if x.strip().isdigit() and 1 <= int(x) <= 31]
            _run_modules(mods, target, all_results, "Custom")
        else:
            _run_module(choice, target, all_results)

        elapsed = time.time() - start_time
        all_results["_elapsed"] = f"{elapsed:.1f}s"

        # Scan complete notification
        notifier = get_notifier()
        summary = {
            "open_ports": len(all_results.get("portscan",{}).get("tcp_open",[])),
            "total_cves": all_results.get("cve",{}).get("total",0),
            "web_vulns":  sum(all_results.get(k,{}).get("total",0)
                             for k in ["xss","sqli","lfi","ssrf","xxe","ssti","idor"]),
            "risk_score": all_results.get("ai",{}).get("risk_score",0),
            "risk_level": all_results.get("ai",{}).get("risk_level","—"),
        }
        notifier.scan_complete(target, summary)

        if len(all_results) > 3:
            console.rule("[bold green]Complete[/bold green]")
            console.print(f"\n  [bold green]Elapsed:[/bold green] {elapsed:.1f}s\n")
            save = console.input(
                "  [bold cyan]Save HTML report?[/bold cyan] [y/N] > "
            ).strip().lower()
            if save in ("y","yes"):
                save_all(all_results, target)
        console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Interrupted[/bold yellow]\n")
        sys.exit(0)
