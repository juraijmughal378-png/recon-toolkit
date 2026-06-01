"""
nmap_scan.py — Ultra Nmap Integration
Features: Full nmap scan, NSE scripts, OS detection, version scan,
          vuln scripts, service enumeration, XML parsing, stealth scan
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

NMAP_BINARY = "nmap"

RISK_PORTS = {
    23, 21, 2375, 6379, 27017, 9200, 5900, 3389, 445, 135,
    512, 513, 514, 4444, 7001, 10250, 50070, 11211,
}

SCAN_PROFILES = {
    "quick": {
        "args":    ["-T4", "--top-ports", "1000", "-sV", "--version-intensity", "5"],
        "desc":    "Fast scan — top 1000 ports",
        "timeout": 120,
    },
    "full": {
        "args":    ["-T4", "-p-", "-sV", "-sC", "--version-intensity", "7"],
        "desc":    "Full scan — all 65535 ports",
        "timeout": 600,
    },
    "stealth": {
        "args":    ["-T2", "-sS", "--top-ports", "1000", "-sV"],
        "desc":    "Stealth SYN scan",
        "timeout": 300,
    },
    "vuln": {
        "args":    ["-T4", "--top-ports", "1000", "-sV", "--script=vuln"],
        "desc":    "Vulnerability scripts",
        "timeout": 300,
    },
    "aggressive": {
        "args":    ["-T4", "-A", "-p-", "--script=default,vuln,safe"],
        "desc":    "Aggressive — OS + version + scripts",
        "timeout": 900,
    },
    "udp": {
        "args":    ["-sU", "-T4", "--top-ports", "200", "-sV"],
        "desc":    "UDP scan — top 200 ports",
        "timeout": 300,
    },
}

# NSE script categories
NSE_SCRIPTS = {
    "default":   "default",
    "vuln":      "vuln",
    "auth":      "auth",
    "brute":     "brute",
    "discovery": "discovery",
    "exploit":   "exploit",
    "safe":      "safe",
}

# Service-specific scripts
SERVICE_SCRIPTS = {
    "http":    ["http-title", "http-headers", "http-methods", "http-auth-finder",
                "http-robots.txt", "http-shellshock", "http-sql-injection",
                "http-xssed", "http-wordpress-enum"],
    "ftp":     ["ftp-anon", "ftp-brute", "ftp-bounce"],
    "ssh":     ["ssh-auth-methods", "ssh-brute", "ssh-hostkey"],
    "smb":     ["smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-security-mode",
                "smb-enum-shares", "smb-enum-users", "smb2-security-mode"],
    "mysql":   ["mysql-empty-password", "mysql-info", "mysql-databases"],
    "mssql":   ["ms-sql-info", "ms-sql-empty-password", "ms-sql-config"],
    "rdp":     ["rdp-vuln-ms12-020", "rdp-enum-encryption"],
    "smtp":    ["smtp-enum-users", "smtp-commands", "smtp-open-relay"],
    "snmp":    ["snmp-info", "snmp-brute", "snmp-walk"],
    "ldap":    ["ldap-rootdse", "ldap-brute", "ldap-search"],
    "redis":   ["redis-info", "redis-brute"],
    "mongodb": ["mongodb-info", "mongodb-databases"],
}


def _is_nmap_installed() -> bool:
    return shutil.which(NMAP_BINARY) is not None


def _install_nmap() -> bool:
    """Try to install nmap."""
    info("Nmap not found — attempting install...")
    try:
        result = subprocess.run(
            ["apt-get", "install", "-y", "nmap"],
            capture_output=True, timeout=60
        )
        if _is_nmap_installed():
            success("Nmap installed")
            return True
    except Exception:
        pass
    error("Could not install nmap — please run: apt install nmap")
    return False


def _parse_xml_output(xml_file: str) -> Dict:
    """Parse nmap XML output into structured data."""
    result = {
        "hosts": [],
        "scan_stats": {},
        "command": "",
    }

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        result["command"] = root.get("args", "")

        # Scan stats
        stats = root.find("runstats")
        if stats is not None:
            finished = stats.find("finished")
            hosts_el = stats.find("hosts")
            if finished is not None:
                result["scan_stats"]["elapsed"] = finished.get("elapsed", "")
                result["scan_stats"]["summary"] = finished.get("summary", "")
            if hosts_el is not None:
                result["scan_stats"]["up"]   = hosts_el.get("up", "0")
                result["scan_stats"]["down"] = hosts_el.get("down", "0")

        # Parse hosts
        for host in root.findall("host"):
            host_data = {
                "ip":       "",
                "hostname": "",
                "status":   "",
                "os":       [],
                "ports":    [],
                "scripts":  [],
            }

            # Status
            status = host.find("status")
            if status is not None:
                host_data["status"] = status.get("state", "")

            # Addresses
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    host_data["ip"] = addr.get("addr", "")
                elif addr.get("addrtype") == "mac":
                    host_data["mac"]    = addr.get("addr", "")
                    host_data["vendor"] = addr.get("vendor", "")

            # Hostnames
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    host_data["hostname"] = hn.get("name", "")

            # OS detection
            os_el = host.find("os")
            if os_el is not None:
                for osmatch in os_el.findall("osmatch"):
                    host_data["os"].append({
                        "name":     osmatch.get("name", ""),
                        "accuracy": osmatch.get("accuracy", ""),
                    })

            # Ports
            ports_el = host.find("ports")
            if ports_el is not None:
                for port in ports_el.findall("port"):
                    port_num  = int(port.get("portid", 0))
                    protocol  = port.get("protocol", "tcp")
                    state_el  = port.find("state")
                    service_el = port.find("service")

                    if state_el is None or state_el.get("state") != "open":
                        continue

                    port_data = {
                        "port":     port_num,
                        "protocol": protocol,
                        "state":    "open",
                        "service":  "",
                        "product":  "",
                        "version":  "",
                        "extrainfo":"",
                        "cpe":      [],
                        "scripts":  [],
                        "risk":     "CRITICAL" if port_num in RISK_PORTS else "INFO",
                    }

                    if service_el is not None:
                        port_data["service"]   = service_el.get("name", "")
                        port_data["product"]   = service_el.get("product", "")
                        port_data["version"]   = service_el.get("version", "")
                        port_data["extrainfo"] = service_el.get("extrainfo", "")
                        for cpe in service_el.findall("cpe"):
                            port_data["cpe"].append(cpe.text or "")

                    # Port scripts
                    for script in port.findall("script"):
                        script_data = {
                            "id":     script.get("id", ""),
                            "output": script.get("output", "")[:300],
                        }
                        port_data["scripts"].append(script_data)

                    host_data["ports"].append(port_data)

            # Host scripts
            hostscript = host.find("hostscript")
            if hostscript is not None:
                for script in hostscript.findall("script"):
                    host_data["scripts"].append({
                        "id":     script.get("id", ""),
                        "output": script.get("output", "")[:500],
                    })

            result["hosts"].append(host_data)

    except Exception as e:
        warning(f"XML parse error: {e}")

    return result


def _run_nmap(target: str, args: List[str], timeout: int = 300) -> Optional[Dict]:
    """Execute nmap and return parsed results."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_out = f.name

    cmd = [NMAP_BINARY] + args + ["-oX", xml_out, target]
    info(f"Running: {' '.join(cmd[:8])}...")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        # Live output
        for line in proc.stdout:
            line = line.strip()
            if line and not line.startswith("#"):
                console.print(f"  [dim]{line}[/dim]")

        proc.wait(timeout=timeout)

        if os.path.exists(xml_out):
            result = _parse_xml_output(xml_out)
            os.unlink(xml_out)
            return result

    except subprocess.TimeoutExpired:
        proc.kill()
        warning(f"Nmap timed out after {timeout}s — partial results")
        if os.path.exists(xml_out):
            return _parse_xml_output(xml_out)
    except Exception as e:
        error(f"Nmap error: {e}")
    finally:
        if os.path.exists(xml_out):
            try: os.unlink(xml_out)
            except: pass

    return None


def _get_service_scripts(open_ports: List[Dict]) -> List[str]:
    """Get relevant NSE scripts for detected services."""
    scripts = set()
    for p in open_ports:
        svc = p.get("service", "").lower()
        for svc_key, svc_scripts in SERVICE_SCRIPTS.items():
            if svc_key in svc:
                scripts.update(svc_scripts)
    return list(scripts)


def run_nmap_scan(target: str, profile: str = "quick",
                  custom_args: List[str] = None) -> Dict:

    section_header("Nmap Scanner", f"Ultra Profile: {profile.upper()} | NSE Scripts | OS Detection")
    info(f"Target: {target}")

    if not _is_nmap_installed():
        if not _install_nmap():
            return {}

    # Get nmap version
    try:
        ver = subprocess.run([NMAP_BINARY, "--version"],
                            capture_output=True, text=True).stdout.split("\n")[0]
        info(f"Nmap: {ver}")
    except Exception:
        pass

    # Select profile
    scan_profile = SCAN_PROFILES.get(profile, SCAN_PROFILES["quick"])
    args = custom_args or scan_profile["args"]
    info(f"Profile: {scan_profile['desc']}")

    # Run initial scan
    result = _run_nmap(target, args, timeout=scan_profile["timeout"])
    if not result:
        error("Nmap scan failed")
        return {}

    all_hosts  = result.get("hosts", [])
    all_ports  = []
    vuln_findings: List[Dict] = []

    for host in all_hosts:
        all_ports.extend(host.get("ports", []))

        # Check script output for vulnerabilities
        for port in host.get("ports", []):
            for script in port.get("scripts", []):
                output = script.get("output", "")
                if any(kw in output.lower() for kw in
                       ["vulnerable", "exploit", "cve-", "dangerous", "critical"]):
                    vuln_findings.append({
                        "host":   host["ip"],
                        "port":   port["port"],
                        "script": script["id"],
                        "output": output[:300],
                    })

        # Host-level scripts
        for script in host.get("scripts", []):
            output = script.get("output", "")
            if any(kw in output.lower() for kw in ["vulnerable", "exploit", "cve-"]):
                vuln_findings.append({
                    "host":   host["ip"],
                    "port":   None,
                    "script": script["id"],
                    "output": output[:300],
                })

    # Run targeted vuln scripts if we found open ports
    if all_ports and profile in ("quick", "full"):
        info("Running targeted NSE vulnerability scripts...")
        svc_scripts = _get_service_scripts(all_ports)
        if svc_scripts:
            script_str = ",".join(svc_scripts[:20])
            vuln_args  = ["-sV", f"--script={script_str}", "-p",
                         ",".join(str(p["port"]) for p in all_ports[:50])]
            vuln_result = _run_nmap(target, vuln_args, timeout=180)
            if vuln_result:
                for host in vuln_result.get("hosts", []):
                    for port in host.get("ports", []):
                        for script in port.get("scripts", []):
                            if script["output"]:
                                vuln_findings.append({
                                    "host":   host["ip"],
                                    "port":   port["port"],
                                    "script": script["id"],
                                    "output": script["output"][:300],
                                })

    # Print results
    console.print(f"\n[bold cyan]━━━ NMAP RESULTS ━━━[/bold cyan]")
    for host in all_hosts:
        os_guess = host["os"][0]["name"] if host["os"] else "Unknown"
        console.print(f"\n  [bold green]Host:[/bold green] {host['ip']}  "
                     f"[dim]{host.get('hostname','')}[/dim]  OS: {os_guess}")

        for p in sorted(host.get("ports", []), key=lambda x: x["port"]):
            risk  = p.get("risk", "INFO")
            rc    = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","INFO":"cyan"}.get(risk,"white")
            svc   = f"{p.get('product','')} {p.get('version','')}".strip()
            cpe   = p.get("cpe",[""])[0] if p.get("cpe") else ""

            found(
                f"  [{rc}]{p['port']:6}/{p['protocol']}[/{rc}]  "
                f"[cyan]{p.get('service',''):15}[/cyan]  "
                f"{svc[:40]}  [dim]{cpe[:40]}[/dim]"
            )

            for script in p.get("scripts", [])[:3]:
                out = script["output"].replace("\n", " ")[:80]
                console.print(f"          [dim][{script['id']}] {out}[/dim]")

    if vuln_findings:
        console.print(f"\n[bold red]━━━ VULNERABILITY FINDINGS ({len(vuln_findings)}) ━━━[/bold red]")
        for v in vuln_findings:
            port_str = f":{v['port']}" if v["port"] else ""
            console.print(f"\n  [red][VULN][/red]  {v['host']}{port_str}  [{v['script']}]")
            console.print(f"  [dim]{v['output'][:200]}[/dim]")

    # Stats
    stats = result.get("scan_stats", {})
    print_summary("Nmap Scanner", {
        "Target":        target,
        "Profile":       profile,
        "Hosts Up":      stats.get("up", len(all_hosts)),
        "Open Ports":    len(all_ports),
        "Vuln Scripts":  len(vuln_findings),
        "Elapsed":       stats.get("elapsed", "—") + "s",
    })

    return {
        "hosts":         all_hosts,
        "open_ports":    all_ports,
        "vuln_findings": vuln_findings,
        "scan_stats":    stats,
        "profile":       profile,
    }
