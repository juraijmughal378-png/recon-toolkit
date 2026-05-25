"""
main.py — Recon Toolkit Pro v3.2 Ultra
Entry point + interactive menu
"""

import sys
import time
import traceback
from typing import Dict, Optional

from ui.rich_ui import (
    console, print_banner, print_menu, section_header,
    get_target_input, get_choice, get_custom_modules,
    info, warning, error, success, print_summary
)
from reports.report_gen import save_all


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
            # Pass combined scan results for better correlation
            scan_context = {**all_results.get("portscan", {}), **all_results.get("fingerprint", {})}
            r = run_cve_check(target, scan_results=scan_context if scan_context else None)
            all_results["cve"] = r
            return r
    except KeyboardInterrupt:
        warning("Module interrupted by user")
        return None
    except Exception as e:
        error(f"Module {num} error: {e}")
        console.print_exception(show_locals=False)
        return None


def main():
    print_banner()

    while True:
        print_menu()
        choice = get_choice()

        if choice == "0":
            console.print("\n[bold cyan]Goodbye![/bold cyan]\n")
            sys.exit(0)

        if choice not in [str(i) for i in range(1, 11)] + ["88", "99"]:
            warning(f"Invalid choice: {choice}")
            continue

        target = get_target_input()
        if not target:
            warning("No target provided")
            continue

        console.print(f"\n  [bold green]Target:[/bold green] [bold]{target}[/bold]\n")
        all_results: Dict = {"_target": target, "_started": time.strftime("%Y-%m-%d %H:%M:%S")}

        start_time = time.time()

        # ── Full scan ─────────────────────────────────────────────────────────
        if choice == "88":
            info("Starting full scan — all 10 modules")
            console.print()
            modules = [str(i) for i in range(1, 11)]
            for i, mod in enumerate(modules, 1):
                console.rule(f"[bold cyan]Module {mod}/10[/bold cyan]")
                _run_module(mod, target, all_results)

        # ── Custom scan ───────────────────────────────────────────────────────
        elif choice == "99":
            mods = get_custom_modules()
            if not mods:
                warning("No modules selected")
                continue
            info(f"Running modules: {', '.join(mods)}")
            for mod in mods:
                if mod in [str(i) for i in range(1, 11)]:
                    console.rule(f"[bold cyan]Module {mod}[/bold cyan]")
                    _run_module(mod, target, all_results)
                else:
                    warning(f"Unknown module: {mod}")

        # ── Single module ─────────────────────────────────────────────────────
        else:
            _run_module(choice, target, all_results)

        elapsed = time.time() - start_time
        all_results["_elapsed"] = f"{elapsed:.1f}s"

        # ── Save reports ──────────────────────────────────────────────────────
        if len(all_results) > 3:  # More than just metadata
            console.rule("[bold green]Scan Complete[/bold green]")
            console.print(f"\n  [bold green]Elapsed:[/bold green] {elapsed:.1f}s\n")
            save = console.input(
                "  [bold cyan]Save reports?[/bold cyan] [dim](html/json/md)[/dim] [y/N] > "
            ).strip().lower()
            if save in ("y", "yes"):
                paths = save_all(all_results, target)
                console.print()

        console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Interrupted by user[/bold yellow]\n")
        sys.exit(0)
