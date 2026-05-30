"""
main.py — Recon Toolkit Pro v3.2 Ultra
19 modules total — OSINT + Vulnerability Scanning
"""

import os
import sys
import time
from typing import Dict, Optional

from ui.rich_ui import (
    console, print_banner, section_header,
    get_target_input, get_choice, get_custom_modules,
    info, warning, error, success, print_summary
)
from reports.report_gen import save_all
from rich.rule import Rule
from rich.table import Table
from rich import box

# ── All modules ───────────────────────────────────────────────────────────────
RECON_MODULES = [
    ("1",  "🔍 Subdomain Enumeration",  "15-source + DNS brute + permutations"),
    ("2",  "🔌 Port Scanner",           "TCP+UDP, 1000+ ports, OS fingerprint"),
    ("3",  "🌐 WHOIS & DNS",            "WHOIS + GeoIP + ASN + SPF/DMARC/DKIM"),
    ("4",  "🔎 Google Dorking",         "80+ dorks, 12 categories, multi-engine"),
    ("5",  "🛡  WAF Detection",          "35+ vendors + bypass techniques"),
    ("6",  "📧 Email Harvesting",        "10-source + pattern gen + MX validation"),
    ("7",  "👁  Shodan Intelligence",    "Full API + exposure score + CVEs"),
    ("8",  "🖥  Tech Fingerprinting",    "80+ technologies + security headers"),
    ("9",  "🔒 SSL/TLS Analysis",        "Grade A+→F + POODLE/BEAST/CRIME"),
    ("10", "💀 CVE Correlation",         "NVD API v2 + CISA KEV + CVSS v3"),
]

ADVANCED_MODULES = [
    ("11", "🎯 Subdomain Takeover",      "50+ services + CNAME chain + PoC"),
    ("12", "📂 Directory Fuzzer",        "500+ wordlist + gobuster-style"),
    ("13", "🔑 JS Analyzer",             "80+ secret patterns + DOM XSS"),
    ("14", "🐙 GitHub Dorking",          "60+ dorks + credential hunter"),
    ("15", "☁  Cloud Bucket Finder",     "AWS S3 + Azure + GCP + Firebase"),
]

ATTACK_MODULES = [
    ("16", "🎭 XSS Scanner",             "Reflected + DOM + Stored | 500+ payloads"),
    ("17", "💉 SQLi Scanner",            "Error + Boolean + Time + Union | 10 DBs"),
    ("18", "📁 LFI Scanner",             "200+ payloads + PHP wrappers + RFI"),
    ("19", "🌐 SSRF Scanner",            "Cloud metadata + blind + protocols"),
    ("20", "📦 XXE Scanner",             "Classic + Blind + OOB + SVG + XInclude"),
    ("21", "🧨 SSTI Scanner",            "15 engines + math detect + auto RCE"),
    ("22", "↪  Open Redirect",           "100+ payloads + SSRF chain + headers"),
    ("23", "🔓 IDOR Scanner",            "ID fuzzing + API + mass assignment"),
]


def _print_menu():
    console.print()

    def _table(title: str, items, title_color: str = "cyan"):
        t = Table(
            title=f"[bold {title_color}]{title}[/bold {title_color}]",
            box=box.SIMPLE, show_header=False, pad_edge=False,
            padding=(0, 2), expand=False,
        )
        t.add_column("num",  style="bold yellow", width=4,  justify="right")
        t.add_column("name", style="bold white",  width=28)
        t.add_column("desc", style="dim",         width=42)
        t.add_column("num2", style="bold yellow", width=4,  justify="right")
        t.add_column("name2","bold white",        width=28)
        t.add_column("desc2","dim",               width=42)

        for i in range(0, len(items), 2):
            n1, nm1, d1 = items[i]
            if i + 1 < len(items):
                n2, nm2, d2 = items[i+1]
            else:
                n2, nm2, d2 = "", "", ""
            t.add_row(n1, nm1, d1, n2, nm2, d2)
        console.print(t)

    _table("RECON MODULES",    RECON_MODULES,    "cyan")
    _table("ADVANCED MODULES", ADVANCED_MODULES, "magenta")
    _table("ATTACK MODULES",   ATTACK_MODULES,   "red")

    # Special options
    console.print()
    console.print(Rule(style="dim"))
    sp = Table(box=box.SIMPLE, show_header=False, pad_edge=False, padding=(0,2))
    sp.add_column("n",  style="bold yellow", width=4, justify="right")
    sp.add_column("nm", width=28)
    sp.add_column("d",  style="dim", width=42)
    sp.add_column("n2", style="bold yellow", width=4, justify="right")
    sp.add_column("nm2",width=28)
    sp.add_column("d2", style="dim", width=42)
    sp.add_row("88","[bold green]⚡ Full Recon[/bold green]",   "[green]Modules 1-10[/green]",
               "99","[bold blue]⚙  Custom Scan[/bold blue]",   "[blue]Pick any modules[/blue]")
    sp.add_row("00","[bold red]🔥 Full Attack[/bold red]",     "[red]All 23 modules[/red]",
               "0", "[bold red]✖  Exit[/bold red]", "")
    console.print(sp)
    console.print()


def _run_module(num: str, target: str, all_results: Dict) -> Optional[Dict]:
    try:
        if num == "1":
            from modules.subdomain import run_subdomain_enum
            r = run_subdomain_enum(target); all_results["subdomain"] = r; return r
        elif num == "2":
            from modules.portscan import run_port_scan
            r = run_port_scan(target); all_results["portscan"] = r; return r
        elif num == "3":
            from modules.whois_info import run_whois_lookup
            r = run_whois_lookup(target); all_results["whois"] = r; return r
        elif num == "4":
            from modules.dorking import run_dorking
            r = run_dorking(target); all_results["dorking"] = r; return r
        elif num == "5":
            from modules.waf_detect import run_waf_detect
            r = run_waf_detect(target); all_results["waf"] = r; return r
        elif num == "6":
            from modules.email_harvest import run_email_harvest
            r = run_email_harvest(target); all_results["email"] = r; return r
        elif num == "7":
            from modules.shodan_lookup import run_shodan_lookup
            r = run_shodan_lookup(target); all_results["shodan"] = r; return r
        elif num == "8":
            from modules.fingerprint import run_fingerprint
            r = run_fingerprint(target); all_results["fingerprint"] = r; return r
        elif num == "9":
            from modules.ssl_scan import run_ssl_scan
            r = run_ssl_scan(target); all_results["ssl"] = r; return r
        elif num == "10":
            from modules.cve_check import run_cve_check
            ctx = {**all_results.get("portscan",{}), **all_results.get("fingerprint",{})}
            r = run_cve_check(target, scan_results=ctx or None); all_results["cve"] = r; return r
        elif num == "11":
            from modules.takeover import run_takeover_check
            subs = [s["subdomain"] for s in all_results.get("subdomain",{}).get("subdomains",[])]
            r = run_takeover_check(target, subs or None); all_results["takeover"] = r; return r
        elif num == "12":
            from modules.fuzzer import run_fuzzer
            r = run_fuzzer(target); all_results["fuzzer"] = r; return r
        elif num == "13":
            from modules.js_analyzer import run_js_analyzer
            r = run_js_analyzer(target); all_results["js"] = r; return r
        elif num == "14":
            from modules.github_dork import run_github_dork
            r = run_github_dork(target); all_results["github"] = r; return r
        elif num == "15":
            from modules.cloud_enum import run_cloud_enum
            r = run_cloud_enum(target); all_results["cloud"] = r; return r
        elif num == "16":
            from modules.xss_scanner import run_xss_scanner
            r = run_xss_scanner(target); all_results["xss"] = r; return r
        elif num == "17":
            from modules.sqli_scanner import run_sqli_scanner
            r = run_sqli_scanner(target); all_results["sqli"] = r; return r
        elif num == "18":
            from modules.lfi_scanner import run_lfi_scanner
            r = run_lfi_scanner(target); all_results["lfi"] = r; return r
        elif num == "19":
            from modules.ssrf_scanner import run_ssrf_scanner
            r = run_ssrf_scanner(target); all_results["ssrf"] = r; return r
        elif num == "20":
            from modules.xxe_scanner import run_xxe_scanner
            r = run_xxe_scanner(target); all_results["xxe"] = r; return r
        elif num == "21":
            from modules.ssti_scanner import run_ssti_scanner
            r = run_ssti_scanner(target); all_results["ssti"] = r; return r
        elif num == "22":
            from modules.open_redirect import run_open_redirect
            r = run_open_redirect(target); all_results["redirect"] = r; return r
        elif num == "23":
            from modules.idor_scanner import run_idor_scanner
            r = run_idor_scanner(target); all_results["idor"] = r; return r

    except KeyboardInterrupt:
        warning("Module interrupted")
        return None
    except Exception as e:
        error(f"Module {num} error: {e}")
        console.print_exception(show_locals=False)
        return None


def main():
    print_banner()

    while True:
        _print_menu()
        choice = console.input(" [bold yellow]Select[/bold yellow] [bold cyan]>[/bold cyan] ").strip()

        if choice == "0":
            console.print("\n[bold cyan]Goodbye![/bold cyan]\n")
            sys.exit(0)

        valid = [str(i) for i in range(1, 24)] + ["88", "99", "00"]
        if choice not in valid:
            warning(f"Invalid: {choice}")
            continue

        target = console.input(
            "\n [bold cyan]Target[/bold cyan] [dim](domain or IP)[/dim] [bold cyan]>[/bold cyan] "
        ).strip()
        if not target:
            warning("No target provided")
            continue

        console.print(f"\n  [bold green]Target:[/bold green] [bold]{target}[/bold]\n")
        all_results: Dict = {"_target": target, "_started": time.strftime("%Y-%m-%d %H:%M:%S")}
        start_time = time.time()

        if choice == "88":
            info("Full Recon — modules 1-10")
            for i in range(1, 11):
                console.rule(f"[bold cyan]Module {i}/10[/bold cyan]")
                _run_module(str(i), target, all_results)

        elif choice == "00":
            info("Full Attack — all 23 modules")
            for i in range(1, 24):
                console.rule(f"[bold red]Module {i}/23[/bold red]")
                _run_module(str(i), target, all_results)

        elif choice == "99":
            console.print(" [dim]Enter numbers separated by spaces  e.g. 1 3 16 17[/dim]")
            line = console.input(" [bold yellow]Modules[/bold yellow] [bold cyan]>[/bold cyan] ").strip()
            mods = [x.strip() for x in line.split() if x.strip().isdigit()]
            for mod in mods:
                if mod in [str(i) for i in range(1, 24)]:
                    console.rule(f"[bold cyan]Module {mod}[/bold cyan]")
                    _run_module(mod, target, all_results)
        else:
            _run_module(choice, target, all_results)

        elapsed = time.time() - start_time
        all_results["_elapsed"] = f"{elapsed:.1f}s"

        if len(all_results) > 3:
            console.rule("[bold green]Complete[/bold green]")
            console.print(f"\n  [bold green]Elapsed:[/bold green] {elapsed:.1f}s\n")
            save = console.input(
                "  [bold cyan]Save reports?[/bold cyan] [dim](html/json/md)[/dim] [y/N] > "
            ).strip().lower()
            if save in ("y", "yes"):
                save_all(all_results, target)
        console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Interrupted[/bold yellow]\n")
        sys.exit(0)
