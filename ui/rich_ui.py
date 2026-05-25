"""
rich_ui.py — Recon Toolkit Pro v3.2 Ultra
Professional terminal UI — clean, compact, no extra spaces
"""

from datetime import datetime
from typing import Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule

console = Console()

BANNER = """[bold red]
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bold red]
  [bold cyan]████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
  ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
     ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
     ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║
     ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║
     ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝[/bold cyan]"""

MENU_ITEMS = [
    ("1",  "🔍 Subdomain Enumeration",    "15-source + DNS brute + permutations"),
    ("2",  "🔌 Port Scanner",             "TCP+UDP, 1000+ ports, OS fingerprint"),
    ("3",  "🌐 WHOIS & DNS",              "WHOIS + GeoIP + ASN + SPF/DMARC/DKIM"),
    ("4",  "🔎 Google Dorking",           "80+ dorks, 12 categories, multi-engine"),
    ("5",  "🛡  WAF Detection",           "35+ vendors + bypass techniques"),
    ("6",  "📧 Email Harvesting",         "10-source + pattern gen + MX validation"),
    ("7",  "👁  Shodan Intelligence",     "Full API + exposure score + CVEs"),
    ("8",  "🖥  Tech Fingerprinting",     "80+ technologies + security headers"),
    ("9",  "🔒 SSL/TLS Analysis",         "Grade A+→F + POODLE/BEAST/CRIME"),
    ("10", "💀 CVE Correlation",          "NVD API v2 + CISA KEV + CVSS v3"),
]


def print_banner():
    console.print(BANNER)
    console.print()
    console.print(
        Panel.fit(
            "[bold white]OSINT & Attack Surface Intelligence Platform[/bold white]  "
            "[dim]|[/dim]  [bold yellow]v3.2 Ultra[/bold yellow]  "
            "[dim]|[/dim]  [dim]" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )
    console.print()


def print_menu():
    console.print(Rule("[bold cyan] MODULES [/bold cyan]", style="cyan"))
    console.print()

    # Two-column layout
    table = Table(
        box=box.SIMPLE,
        show_header=False,
        pad_edge=False,
        padding=(0, 2),
        expand=False,
    )
    table.add_column("num",  style="bold yellow",  width=4,  justify="right")
    table.add_column("name", style="bold white",   width=26)
    table.add_column("desc", style="dim",          width=38)
    table.add_column("num2", style="bold yellow",  width=4,  justify="right")
    table.add_column("name2","bold white",         width=26)
    table.add_column("desc2","dim",                width=38)

    # Pair up items into rows (2 per row)
    items = MENU_ITEMS
    for i in range(0, len(items), 2):
        n1, nm1, d1 = items[i]
        if i + 1 < len(items):
            n2, nm2, d2 = items[i + 1]
        else:
            n2, nm2, d2 = "", "", ""
        table.add_row(n1, nm1, d1, n2, nm2, d2)

    console.print(table)
    console.print()
    console.print(Rule(style="dim"))
    console.print()

    # Special options
    special = Table(
        box=box.SIMPLE,
        show_header=False,
        pad_edge=False,
        padding=(0, 2),
        expand=False,
    )
    special.add_column("num",  style="bold yellow", width=4, justify="right")
    special.add_column("name", width=26)
    special.add_column("desc", style="dim",         width=38)
    special.add_column("num2", style="bold yellow", width=4, justify="right")
    special.add_column("name2",width=26)
    special.add_column("desc2",style="dim",         width=38)

    special.add_row(
        "88", "[bold green]⚡ Full Scan[/bold green]",       "[green]Run all 10 modules[/green]",
        "99", "[bold blue]⚙  Custom Scan[/bold blue]",       "[blue]Pick specific modules[/blue]",
    )
    special.add_row(
        "0",  "[bold red]✖  Exit[/bold red]", "",
        "", "", "",
    )
    console.print(special)
    console.print()


def section_header(title: str, subtitle: str = ""):
    ts = datetime.now().strftime("%H:%M:%S")
    content = f"[bold white]{title}[/bold white]"
    if subtitle:
        content += f"  [dim]—  {subtitle}[/dim]"
    content += f"  [dim][{ts}][/dim]"
    console.print()
    console.print(Rule(f"[bold cyan] {title} [/bold cyan]", style="cyan"))
    if subtitle:
        console.print(f"  [dim]{subtitle}[/dim]  [dim][{ts}][/dim]")
    console.print()


def print_summary(module: str, data: Dict):
    table = Table(
        title=f"[bold green] {module} — Summary [/bold green]",
        box=box.ROUNDED,
        border_style="green",
        show_header=False,
        pad_edge=True,
        padding=(0, 2),
    )
    table.add_column("key",   style="bold cyan",  width=22)
    table.add_column("value", style="bold white", width=28)

    for k, v in data.items():
        if isinstance(v, bool):
            v_str = "[bold green]Yes[/bold green]" if v else "[red]No[/red]"
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
    console.print(f" [bold blue][*][/bold blue] {msg}")

def warning(msg: str):
    console.print(f" [bold yellow][!][/bold yellow] {msg}")

def error(msg: str):
    console.print(f" [bold red][-][/bold red] {msg}")

def found(msg: str):
    console.print(f" [bold green][+][/bold green] {msg}")

def success(msg: str):
    console.print(f" [bold green][✓][/bold green] {msg}")


def get_target_input() -> str:
    console.print()
    target = console.input(
        " [bold cyan]Target[/bold cyan] [dim](domain or IP)[/dim] [bold cyan]>[/bold cyan] "
    ).strip()
    return target


def get_choice() -> str:
    console.print()
    return console.input(" [bold yellow]Select[/bold yellow] [bold cyan]>[/bold cyan] ").strip()


def get_custom_modules() -> list:
    console.print(" [dim]Enter numbers separated by spaces  e.g. 1 3 5 9[/dim]")
    line = console.input(" [bold yellow]Modules[/bold yellow] [bold cyan]>[/bold cyan] ").strip()
    return [x.strip() for x in line.split() if x.strip().isdigit()]


def progress_bar(description: str):
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
