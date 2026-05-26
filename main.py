"""
main.py — Recon Toolkit Pro v3.2 Ultra
Entry point + interactive menu — 15 modules total
"""

import sys
import time
from typing import Dict, Optional

from ui.rich_ui import (
    console, print_banner, print_menu, section_header,
    get_target_input, get_choice, get_custom_modules,
    info, warning, error, success, print_summary
)
from reports.report_gen import save_all

MENU_ITEMS_EXTRA = [
    ("11", "🎯 Subdomain Takeover",   "50+ service fingerprints + PoC generation"),
    ("12", "📂 Directory Fuzzer",     "5000+ wordlist, gobuster-style, risk scoring"),
    ("13", "🔑 JS File Analyzer",     "80+ secret patterns, endpoints, DOM XSS sinks"),
    ("14", "🐙 GitHub Dorking",       "60+ dorks, credential hunting, repo analysis"),
    ("15", "☁  Cloud Bucket Finder",  "AWS S3 + Azure + GCP + Firebase + 4 more"),
]


def _run_module(num: str, target: str, all_results: Dict) -> Optional[Dict]:
    try:
        if num == "1":
            from modules.subdomain import run_subdomain_enum
            r = run_subdomain_enum(target)
            all_results["subdomain"] = r
            return r
        elif num == "2":
            from modules.portscan import run_port_scan
            r = run_port_scan(target)
            all_results["portscan"] = r
            return r
        elif num == "3":
            from modules.whois_info import run_whois_lookup
            r = run_whois_lookup(target)
            all_results["whois"] = r
            return r
        elif num == "4":
            from modules.dorking import run_dorking
            r = run_dorking(target)
            all_results["dorking"] = r
            return r
        elif num == "5":
            from modules.waf_detect import run_waf_detect
            r = run_waf_detect(target)
            all_results["waf"] = r
            return r
        elif num == "6":
            from modules.email_harvest import run_email_harvest
            r = run_email_harvest(target)
            all_results["email"] = r
            return r
        elif num == "7":
            from modules.shodan_lookup import run_shodan_lookup
            r = run_shodan_lookup(target)
            all_results["shodan"] = r
            return r
        elif num == "8":
            from modules.fingerprint import run_fingerprint
            r = run_fingerprint(target)
            all_results["fingerprint"] = r
            return r
        elif num == "9":
            from modules.ssl_scan import run_ssl_scan
            r = run_ssl_scan(target)
            all_results["ssl"] = r
            return r
        elif num == "10":
            from modules.cve_check import run_cve_check
            scan_ctx = {**all_results.get("portscan", {}), **all_results.get("fingerprint", {})}
            r = run_cve_check(target, scan_results=scan_ctx if scan_ctx else None)
            all_results["cve"] = r
            return r
        elif num == "11":
            from modules.takeover import run_takeover_check
            subs = [s["subdomain"] for s in all_results.get("subdomain", {}).get("subdomains", [])]
            r = run_takeover_check(target, subs if subs else None)
            all_results["takeover"] = r
            return r
        elif num == "12":
            from modules.fuzzer import run_fuzzer
            r = run_fuzzer(target)
            all_results["fuzzer"] = r
            return r
        elif num == "13":
            from modules.js_analyzer import run_js_analyzer
            r = run_js_analyzer(target)
            all_results["js"] = r
            return r
        elif num == "14":
            from modules.github_dork import run_github_dork
            r = run_github_dork(target)
            all_results["github"] = r
            return r
        elif num == "15":
            from modules.cloud_enum import run_cloud_enum
            r = run_cloud_enum(target)
            all_results["cloud"] = r
            return r
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
        print_menu()

        # Show new modules
        console.print("  [bold magenta]━━━ NEW MODULES ━━━[/bold magenta]")
        for num, name, desc in MENU_ITEMS_EXTRA:
            console.print(f"  [bold yellow]{num:>3}[/bold yellow]  {name:28}  [dim]{desc}[/dim]")
        console.print()

        choice = get_choice()

        if choice == "0":
            console.print("\n[bold cyan]Goodbye![/bold cyan]\n")
            sys.exit(0)

        valid = [str(i) for i in range(1, 16)] + ["88", "99"]
        if choice not in valid:
            warning(f"Invalid choice: {choice}")
            continue

        target = get_target_input()
        if not target:
            warning("No target provided")
            continue

        console.print(f"\n  [bold green]Target:[/bold green] [bold]{target}[/bold]\n")
        all_results: Dict = {
            "_target":  target,
            "_started": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        start_time = time.time()

        if choice == "88":
            info("Full scan — all 15 modules")
            for i in range(1, 16):
                console.rule(f"[bold cyan]Module {i}/15[/bold cyan]")
                _run_module(str(i), target, all_results)

        elif choice == "99":
            mods = get_custom_modules()
            if not mods:
                warning("No modules selected")
                continue
            for mod in mods:
                if mod in [str(i) for i in range(1, 16)]:
                    console.rule(f"[bold cyan]Module {mod}[/bold cyan]")
                    _run_module(mod, target, all_results)
                else:
                    warning(f"Unknown module: {mod}")
        else:
            _run_module(choice, target, all_results)

        elapsed = time.time() - start_time
        all_results["_elapsed"] = f"{elapsed:.1f}s"

        if len(all_results) > 3:
            console.rule("[bold green]Scan Complete[/bold green]")
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
