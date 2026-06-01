"""
nuclei_scan.py — Ultra Nuclei Integration
Features: Auto-install nuclei, 5000+ templates, custom templates,
          severity filtering, JSON output parsing, CVE templates,
          tech detection, exposed panels, misconfigs, auto-update
"""

import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Dict, List, Optional

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

NUCLEI_BINARY = "nuclei"
TEMPLATES_DIR = os.path.expanduser("~/.nuclei-templates")

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "green",
    "info":     "cyan",
    "unknown":  "dim",
}

# Template categories to run
DEFAULT_TAGS = [
    "cve", "exposed-panels", "misconfig", "default-login",
    "takeover", "exposure", "xss", "sqli", "ssrf", "lfi",
    "rce", "xxe", "ssti", "idor", "cors", "csrf",
    "tech", "network", "cloud", "api", "jwt",
]


def _is_nuclei_installed() -> bool:
    return shutil.which(NUCLEI_BINARY) is not None


def _install_nuclei() -> bool:
    """Auto-install nuclei binary."""
    info("Nuclei not found — attempting auto-install...")
    system = platform.system().lower()

    try:
        if system == "linux":
            # Try Go install
            if shutil.which("go"):
                info("Installing via Go...")
                result = subprocess.run(
                    ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode == 0:
                    success("Nuclei installed via Go")
                    return True

            # Try apt/package manager
            info("Trying apt install...")
            subprocess.run(["apt-get", "install", "-y", "nuclei"],
                          capture_output=True, timeout=60)
            if _is_nuclei_installed():
                success("Nuclei installed via apt")
                return True

            # Download binary directly
            info("Downloading nuclei binary...")
            import urllib.request
            url = "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip"
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
                urllib.request.urlretrieve(url, f.name)
                subprocess.run(["unzip", "-o", f.name, "-d", "/usr/local/bin/"],
                              capture_output=True)
                subprocess.run(["chmod", "+x", "/usr/local/bin/nuclei"])
            if _is_nuclei_installed():
                success("Nuclei binary installed")
                return True

        elif system == "darwin":
            subprocess.run(["brew", "install", "nuclei"], capture_output=True, timeout=120)
            if _is_nuclei_installed():
                success("Nuclei installed via Homebrew")
                return True

    except Exception as e:
        warning(f"Auto-install failed: {e}")

    error("Could not install nuclei automatically")
    console.print("  [yellow]Manual install:[/yellow]")
    console.print("  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    console.print("  or: https://github.com/projectdiscovery/nuclei/releases")
    return False


def _update_templates() -> bool:
    """Update nuclei templates."""
    info("Updating nuclei templates...")
    try:
        result = subprocess.run(
            [NUCLEI_BINARY, "-update-templates"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            success("Templates updated successfully")
            return True
        else:
            warning(f"Template update warning: {result.stderr[:100]}")
            return True  # Continue anyway
    except Exception as e:
        warning(f"Template update failed: {e}")
        return False


def _count_templates() -> int:
    """Count available templates."""
    count = 0
    if os.path.exists(TEMPLATES_DIR):
        for root, dirs, files in os.walk(TEMPLATES_DIR):
            count += sum(1 for f in files if f.endswith(".yaml"))
    return count


def _run_nuclei(target: str, tags: List[str] = None,
                severity: List[str] = None,
                templates: List[str] = None,
                rate_limit: int = 150,
                timeout: int = 300) -> List[Dict]:
    """Run nuclei scan and parse results."""
    findings: List[Dict] = []

    if not _is_nuclei_installed():
        if not _install_nuclei():
            return []

    # Build command
    cmd = [
        NUCLEI_BINARY,
        "-u", target,
        "-json",
        "-silent",
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-retries", "2",
        "-no-color",
    ]

    # Tags filter
    if tags:
        cmd += ["-tags", ",".join(tags)]

    # Severity filter
    if severity:
        cmd += ["-severity", ",".join(severity)]

    # Custom templates
    if templates:
        for t in templates:
            cmd += ["-t", t]

    # Output file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False, suffix=".jsonl") as f:
        outfile = f.name

    cmd += ["-output", outfile]

    info(f"Running nuclei: {len(tags or DEFAULT_TAGS)} tag categories | Rate: {rate_limit}/s")
    console.print(f"  [dim]Command: {' '.join(cmd[:6])}...[/dim]")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Live output monitoring
        def _monitor():
            for line in proc.stderr:
                line = line.strip()
                if "[INF]" in line:
                    console.print(f"  [dim]{line}[/dim]")
                elif "[WRN]" in line:
                    warning(line)

        monitor_thread = threading.Thread(target=_monitor, daemon=True)
        monitor_thread.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            warning(f"Nuclei scan timed out after {timeout}s")

        # Parse results
        if os.path.exists(outfile):
            with open(outfile, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        result = json.loads(line)
                        findings.append(result)
                    except json.JSONDecodeError:
                        pass
            os.unlink(outfile)

    except FileNotFoundError:
        error("Nuclei binary not found in PATH")
    except Exception as e:
        error(f"Nuclei error: {e}")

    return findings


def _parse_finding(f: Dict) -> Dict:
    """Parse nuclei JSON finding into clean format."""
    info_block = f.get("info", {})
    matcher    = f.get("matcher-name", "")
    extracted  = f.get("extracted-results", [])

    return {
        "template_id": f.get("template-id", ""),
        "name":        info_block.get("name", ""),
        "severity":    info_block.get("severity", "info").lower(),
        "description": info_block.get("description", ""),
        "reference":   info_block.get("reference", []),
        "tags":        info_block.get("tags", []),
        "cvss_score":  info_block.get("classification", {}).get("cvss-score"),
        "cve_id":      info_block.get("classification", {}).get("cve-id", []),
        "url":         f.get("matched-at", f.get("host", "")),
        "matched":     f.get("matched-at", ""),
        "matcher":     matcher,
        "extracted":   extracted[:5],
        "type":        f.get("type", ""),
        "timestamp":   f.get("timestamp", ""),
    }


def run_nuclei_scan(target: str,
                    tags: List[str] = None,
                    severity: List[str] = None,
                    update_first: bool = True) -> Dict:

    section_header("Nuclei Scanner", "Ultra 5000+ Templates | CVE + Misconfig + Exposure")
    info(f"Target: {target}")

    # Check/install nuclei
    if not _is_nuclei_installed():
        if not _install_nuclei():
            error("Nuclei unavailable — skipping")
            return {}

    # Update templates
    if update_first:
        _update_templates()

    # Template count
    tpl_count = _count_templates()
    info(f"Templates available: {tpl_count:,}")

    # Default tags if not specified
    tags     = tags or DEFAULT_TAGS
    severity = severity or ["critical", "high", "medium", "low", "info"]

    # Run scan
    raw_findings = _run_nuclei(target, tags=tags, severity=severity)
    info(f"Nuclei scan complete — {len(raw_findings)} findings")

    # Parse findings
    findings = [_parse_finding(f) for f in raw_findings]

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 5))

    # Severity breakdown
    sev_count = {}
    for f in findings:
        s = f["severity"]
        sev_count[s] = sev_count.get(s, 0) + 1

    # Print results
    console.print(f"\n[bold cyan]━━━ NUCLEI FINDINGS ({len(findings)}) ━━━[/bold cyan]")
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        cve_str = ", ".join(f["cve_id"][:2]) if f["cve_id"] else ""

        console.print(
            f"\n  [{color}][{f['severity'].upper():8}][/{color}]  "
            f"[bold]{f['name']}[/bold]"
            + (f"  [red]{cve_str}[/red]" if cve_str else "")
        )
        console.print(f"  Template: [dim]{f['template_id']}[/dim]")
        console.print(f"  URL:      [cyan]{f['url'][:80]}[/cyan]")
        if f["description"]:
            console.print(f"  Desc:     [dim]{f['description'][:100]}[/dim]")
        if f["extracted"]:
            console.print(f"  Extracted:[red]{f['extracted'][:3]}[/red]")
        if f.get("cvss_score"):
            console.print(f"  CVSS:     {f['cvss_score']}")

    print_summary("Nuclei Scanner", {
        "Templates Run":  tpl_count,
        "Total Found":    len(findings),
        "Critical":       sev_count.get("critical", 0),
        "High":           sev_count.get("high", 0),
        "Medium":         sev_count.get("medium", 0),
        "Low":            sev_count.get("low", 0),
        "Info":           sev_count.get("info", 0),
    })

    return {
        "findings":   findings,
        "total":      len(findings),
        "sev_count":  sev_count,
        "templates":  tpl_count,
    }
