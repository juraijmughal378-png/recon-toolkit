"""
rich_ui.py — Ultra Terminal UI
Rich-powered colored console, banners, menus, progress bars, tables
"""

from datetime import datetime
from typing import Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝  
"""

SUBTITLE = "OSINT & Attack Surface Intelligence Platform  |  v3.2 Ultra"

MENU_ITEMS = [
    ("1",  "Subdomain Enumeration",    "15-source enumeration + DNS brute + permutations"),
    ("2",  "Port Scanner",             "TCP+UDP, 1000+ ports, banners, OS fingerprint, CVE hints"),
    ("3",  "WHOIS & DNS Intelligence", "WHOIS + all DNS types + GeoIP + ASN + SPF/DMARC/DKIM"),
    ("4",  "Google Dorking",           "80+ dorks, 12 categories, multi-engine, severity rated"),
    ("5",  "WAF Detection",            "35+ vendors, behavioral analysis, bypass techniques"),
    ("6",  "Email Harvesting",         "10-source harvester, pattern gen, MX validation"),
    ("7",  "Shodan Intelligence",      "Full API, exposure scoring, honeypot detection, CVEs"),
    ("8",  "Tech Fingerprinting",      "80+ technologies, security headers, favicon hash"),
    ("9",  "SSL/TLS Analysis",         "Grade A+ to F, 3-method, POODLE/BEAST/CRIME checks"),
    ("10", "CVE Correlation",          "NVD API v2 + offline DB + CISA KEV, CVSS v3 scoring"),
    ("88", "Full Scan",                "Run all 10 modules sequentially"),
    ("99", "Custom Scan",              "Select specific modules to run"),
    ("0",  "Exit",                     ""),
]


def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(f"[bold cyan]  {SUBTITLE}[/bold cyan]")
    console.print(f"  [dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")


def print_menu():
    table = Table(
        title="",
        box=box.DOUBLE_EDGE,
        border_style="cyan",
        header_style="bold magenta",
        show_header=True,
        pad_edge=True,
    )
    table.add_column("#",       style="bold yellow",  width=5,  justify="center")
    table.add_column("Module",  style="bold white",   width=30)
    table.add_column("Description", style="dim cyan", width=55)

    for num, name, desc in MENU_ITEMS:
        if num == "88":
            table.add_row("", "", "")
            table.add_row(num, f"[bold green]{name}[/bold green]", f"[green]{desc}[/green]")
        elif num == "99":
            table.add_row(num, f"[bold blue]{name}[/bold blue]",  f"[blue]{desc}[/blue]")
        elif num == "0":
            table.add_row(num, f"[red]{name}[/red]", "")
        else:
            table.add_row(num, name, desc)

    console.print(table)
    console.print()


def section_header(title: str, subtitle: str = ""):
    ts = datetime.now().strftime("%H:%M:%S")
    panel_text = Text()
    panel_text.append(f"  {title}  ", style="bold white")
    if subtitle:
        panel_text.append(f"\n  {subtitle}", style="dim cyan")
    panel_text.append(f"\n  [{ts}]", style="dim")
    console.print(
        Panel(panel_text, border_style="bold cyan", expand=False, padding=(0, 2))
    )
    console.print()


def print_summary(module: str, data: Dict):
    table = Table(
        title=f"  {module} — Summary",
        box=box.ROUNDED,
        border_style="green",
        header_style="bold green",
        show_header=False,
        pad_edge=True,
    )
    table.add_column("Key",   style="bold cyan",   width=22)
    table.add_column("Value", style="bold white",  width=30)

    for k, v in data.items():
        if isinstance(v, bool):
            v_str = "[green]Yes[/green]" if v else "[red]No[/red]"
        elif isinstance(v, int) and v > 0 and "CRITICAL" in k.upper():
            v_str = f"[bold red]{v}[/bold red]"
        elif isinstance(v, int) and v > 0 and "HIGH" in k.upper():
            v_str = f"[red]{v}[/red]"
        else:
            v_str = str(v)
        table.add_row(k, v_str)

    console.print()
    console.print(table)
    console.print()


def info(msg: str):
    console.print(f"  [bold blue][*][/bold blue]  {msg}")


def warning(msg: str):
    console.print(f"  [bold yellow][!][/bold yellow]  {msg}")


def error(msg: str):
    console.print(f"  [bold red][-][/bold red]  {msg}")


def found(msg: str):
    console.print(f"  [bold green][+][/bold green]  {msg}")


def success(msg: str):
    console.print(f"  [bold green][✓][/bold green]  {msg}")


def get_target_input() -> str:
    console.print()
    target = console.input(
        "  [bold cyan]Enter target[/bold cyan] [dim](domain or IP)[/dim]: "
    ).strip()
    return target


def get_choice() -> str:
    console.print()
    return console.input("  [bold yellow]Select module[/bold yellow] > ").strip()


def get_custom_modules() -> list:
    console.print("  [dim]Enter module numbers separated by spaces (e.g. 1 3 5 9)[/dim]")
    line = console.input("  [bold yellow]Modules[/bold yellow] > ").strip()
    return [x.strip() for x in line.split() if x.strip().isdigit()]


def progress_bar(description: str):
    """Return a Rich Progress context manager."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
