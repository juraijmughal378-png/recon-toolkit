"""
network_scanner.py — Ultra Network Scanner
Features: Host discovery, ARP scan, service detection,
          network mapping, OS fingerprint, traceroute,
          SNMP enumeration, NetBIOS scan, WiFi detection
"""

import ipaddress
import os
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

import requests
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT    = 3
MAX_WORKERS = 100

# ── Common ports for quick scan ───────────────────────────────────────────────
QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161,
    443, 445, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306,
    3389, 5432, 5900, 5985, 6379, 7001, 8080, 8443, 9200, 27017,
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2375: "Docker", 3000: "Dev", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
    7001: "WebLogic", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

CRITICAL_PORTS = {2375, 6379, 27017, 9200, 5900, 23, 3389, 445}


def _ping(host: str) -> bool:
    """ICMP ping check."""
    try:
        param = "-n" if os.name == "nt" else "-c"
        result = subprocess.run(
            ["ping", param, "1", "-W", "1", host],
            capture_output=True, timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False


def _tcp_ping(host: str, port: int = 80) -> bool:
    """TCP connect check as alternative to ICMP."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except Exception:
        return False


def _is_host_up(host: str) -> bool:
    """Check if host is alive via ping or TCP."""
    if _ping(host):
        return True
    # Try common ports
    for port in [80, 443, 22, 445]:
        if _tcp_ping(host, port):
            return True
    return False


def _get_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _get_mac(ip: str) -> Optional[str]:
    """Get MAC address via ARP (Linux only)."""
    try:
        result = subprocess.run(
            ["arp", "-n", ip], capture_output=True, text=True, timeout=3
        )
        m = re.search(r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",
                     result.stdout, re.I)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def _get_vendor(mac: str) -> Optional[str]:
    """Get vendor from MAC OUI."""
    if not mac:
        return None
    oui = mac.replace(":", "").upper()[:6]
    # Common OUI prefixes
    vendors = {
        "000C29": "VMware", "001C42": "Parallels", "080027": "VirtualBox",
        "00505600": "VMware", "001A11": "Google", "DC4F22": "Amazon",
        "0050F2": "Microsoft", "001DD8": "Microsoft", "B88D12": "Apple",
        "3C5AB4": "Google", "ACDE48": "Random/Local",
    }
    for prefix, vendor in vendors.items():
        if oui.startswith(prefix[:6]):
            return vendor
    return None


def _quick_port_scan(host: str, ports: List[int] = None) -> List[Dict]:
    """Quick TCP port scan on a host."""
    ports = ports or QUICK_PORTS
    open_ports = []
    lock = threading.Lock()

    def _check(port: int):
        try:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                svc = SERVICE_NAMES.get(port, "Unknown")
                risk = "CRITICAL" if port in CRITICAL_PORTS else "INFO"
                with lock:
                    open_ports.append({
                        "port":    port,
                        "service": svc,
                        "risk":    risk,
                    })
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(_check, ports)

    return sorted(open_ports, key=lambda x: x["port"])


def _get_os_hint(open_ports: List[int]) -> str:
    """Heuristic OS detection from ports."""
    if 3389 in open_ports or 135 in open_ports:
        return "Windows"
    if 22 in open_ports and 111 in open_ports:
        return "Linux/Unix"
    if 22 in open_ports:
        return "Linux/Unix"
    if 548 in open_ports:
        return "macOS"
    return "Unknown"


def _traceroute(host: str) -> List[str]:
    """Run traceroute."""
    hops = []
    try:
        cmd = ["tracert", "-h", "10", host] if os.name == "nt" else \
              ["traceroute", "-m", "10", "-w", "1", host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        for line in result.stdout.splitlines()[1:]:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                hops.append(m.group(1))
    except Exception:
        pass
    return hops[:10]


def _snmp_check(host: str) -> Optional[Dict]:
    """Check SNMP community strings."""
    communities = ["public", "private", "community", "manager", "admin", "default"]
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        for community in communities:
            # SNMP v1 GetRequest for sysDescr
            oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
            community_b = community.encode()
            pkt = (
                b"\x30" +
                bytes([29 + len(community_b)]) +
                b"\x02\x01\x00" +
                b"\x04" + bytes([len(community_b)]) + community_b +
                b"\xa0\x1c\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
                b"\x30\x0e\x30\x0c\x06\x08" + oid + b"\x05\x00"
            )
            sock.sendto(pkt, (host, 161))
            try:
                data, _ = sock.recvfrom(1024)
                if data:
                    return {"community": community, "response": data[:50].hex()}
            except socket.timeout:
                pass
        sock.close()
    except Exception:
        pass
    return None


def _netbios_scan(host: str) -> Optional[Dict]:
    """NetBIOS name scan."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # NetBIOS Name Service query
        query = b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20"
        query += b"\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        query += b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        query += b"\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
        sock.sendto(query, (host, 137))
        data, _ = sock.recvfrom(1024)
        if data and len(data) > 56:
            # Parse NetBIOS names
            num_names = data[56]
            names = []
            for i in range(num_names):
                offset = 57 + (i * 18)
                if offset + 15 < len(data):
                    name = data[offset:offset+15].decode("ascii", errors="ignore").strip()
                    if name:
                        names.append(name)
            return {"names": names, "raw": data[:60].hex()}
        sock.close()
    except Exception:
        pass
    return None


def discover_hosts(network: str) -> List[str]:
    """Discover live hosts in a network range."""
    section_header("Host Discovery", f"Network: {network}")
    live_hosts = []
    lock = threading.Lock()

    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())
        info(f"Scanning {len(hosts)} hosts in {network}...")

        def _check_host(ip):
            ip_str = str(ip)
            if _is_host_up(ip_str):
                with lock:
                    live_hosts.append(ip_str)
                    found(f"[+] Live: {ip_str}")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            ex.map(_check_host, hosts)

    except ValueError as e:
        error(f"Invalid network: {e}")

    success(f"Found {len(live_hosts)} live hosts")
    return sorted(live_hosts)


def run_network_scanner(target: str, scan_network: bool = False) -> Dict:
    section_header("Network Scanner", "Ultra Host Discovery + Service Detection + SNMP")
    info(f"Target: {target}")

    results = {"target": target, "hosts": []}

    # Determine if scanning a network range or single host
    if "/" in target:
        # Network range
        live_hosts = discover_hosts(target)
    else:
        # Single host or auto-detect local network
        try:
            ip = socket.gethostbyname(target)
            live_hosts = [ip]
            info(f"Resolved: {target} → {ip}")

            # Also scan local /24 if requested
            if scan_network:
                network = ".".join(ip.split(".")[:3]) + ".0/24"
                info(f"Auto-scanning local network: {network}")
                live_hosts = discover_hosts(network)
        except Exception:
            live_hosts = [target]

    # Detailed scan each live host
    for host in live_hosts[:20]:
        info(f"Scanning host: {host}")
        host_data = {
            "ip":       host,
            "hostname": _get_hostname(host),
            "mac":      None,
            "vendor":   None,
            "os_hint":  "Unknown",
            "ports":    [],
            "snmp":     None,
            "netbios":  None,
            "risk":     "LOW",
        }

        # MAC + vendor
        mac = _get_mac(host)
        if mac:
            host_data["mac"]    = mac
            host_data["vendor"] = _get_vendor(mac)

        # Port scan
        open_ports = _quick_port_scan(host)
        host_data["ports"] = open_ports
        port_nums = [p["port"] for p in open_ports]

        # OS hint
        host_data["os_hint"] = _get_os_hint(port_nums)

        # Risk level
        critical = [p for p in open_ports if p["risk"] == "CRITICAL"]
        if critical:
            host_data["risk"] = "CRITICAL"
        elif len(open_ports) > 5:
            host_data["risk"] = "HIGH"
        elif open_ports:
            host_data["risk"] = "MEDIUM"

        # SNMP check
        if 161 in port_nums:
            snmp = _snmp_check(host)
            if snmp:
                host_data["snmp"] = snmp
                warning(f"  SNMP community '{snmp['community']}' accessible!")

        # NetBIOS
        if 139 in port_nums or 445 in port_nums:
            nb = _netbios_scan(host)
            if nb:
                host_data["netbios"] = nb

        results["hosts"].append(host_data)

        # Print host info
        risk_color = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"green"}.get(
            host_data["risk"], "white")
        console.print(f"\n  [{risk_color}]▶ {host}[/{risk_color}]  "
                     f"[dim]{host_data['hostname'] or ''}[/dim]  "
                     f"OS: {host_data['os_hint']}  "
                     f"MAC: {host_data['mac'] or '—'}  "
                     f"({host_data['vendor'] or '—'})")

        for p in open_ports:
            pc = "red" if p["risk"] == "CRITICAL" else "cyan"
            console.print(f"    [{pc}]{p['port']:6}[/{pc}]  {p['service']}")

        if host_data["snmp"]:
            console.print(f"    [red]SNMP: community='{host_data['snmp']['community']}'[/red]")

    print_summary("Network Scanner", {
        "Hosts Scanned":   len(live_hosts),
        "Live Hosts":      len(results["hosts"]),
        "Critical Hosts":  sum(1 for h in results["hosts"] if h["risk"] == "CRITICAL"),
        "SNMP Exposed":    sum(1 for h in results["hosts"] if h["snmp"]),
        "Total Open Ports":sum(len(h["ports"]) for h in results["hosts"]),
    })

    return results
