"""
portscan.py — Ultra Port Scanner
Features: TCP + UDP, 1000+ ports, banner grabbing, OS fingerprinting,
          service detection, risk scoring, CVE hints, NSE-style scripts
"""

import ipaddress
import json
import re
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

# ── Port definitions ─────────────────────────────────────────────────────────
TOP_1000_PORTS = list(range(1, 1025)) + [
    1433,1434,1521,1522,1723,1900,2049,2082,2083,2086,2087,2095,2096,
    2121,2181,2375,2376,3000,3001,3128,3268,3269,3306,3389,3690,4000,
    4444,4445,4848,5000,5001,5432,5555,5601,5672,5900,5985,5986,6000,
    6379,6443,6881,7000,7001,7070,7443,7474,8000,8001,8008,8009,8080,
    8081,8082,8083,8088,8089,8090,8091,8161,8180,8443,8444,8500,8983,
    9000,9001,9042,9090,9091,9200,9300,9418,9443,9999,10000,10250,10255,
    11211,15672,16379,27017,27018,27019,28017,49152,49153,50000,50070,50090,
]

SERVICE_MAP = {
    21: ("FTP", "HIGH"),          22: ("SSH", "MEDIUM"),
    23: ("Telnet", "CRITICAL"),   25: ("SMTP", "MEDIUM"),
    53: ("DNS", "MEDIUM"),        80: ("HTTP", "LOW"),
    110: ("POP3", "MEDIUM"),      111: ("RPC", "HIGH"),
    135: ("MSRPC", "HIGH"),       139: ("NetBIOS", "HIGH"),
    143: ("IMAP", "MEDIUM"),      161: ("SNMP", "HIGH"),
    389: ("LDAP", "HIGH"),        443: ("HTTPS", "LOW"),
    445: ("SMB", "CRITICAL"),     512: ("rexec", "CRITICAL"),
    513: ("rlogin", "CRITICAL"),  514: ("rsh/syslog", "CRITICAL"),
    873: ("rsync", "HIGH"),       993: ("IMAPS", "LOW"),
    995: ("POP3S", "LOW"),        1433: ("MSSQL", "HIGH"),
    1521: ("Oracle", "HIGH"),     1723: ("PPTP", "MEDIUM"),
    2049: ("NFS", "HIGH"),        2375: ("Docker", "CRITICAL"),
    2376: ("Docker TLS", "HIGH"), 3000: ("Dev Server", "MEDIUM"),
    3306: ("MySQL", "HIGH"),      3389: ("RDP", "HIGH"),
    3690: ("SVN", "HIGH"),        4444: ("Metasploit", "CRITICAL"),
    5432: ("PostgreSQL", "HIGH"), 5555: ("ADB/Dev", "CRITICAL"),
    5900: ("VNC", "HIGH"),        5985: ("WinRM HTTP", "HIGH"),
    5986: ("WinRM HTTPS", "HIGH"),6379: ("Redis", "CRITICAL"),
    7001: ("WebLogic", "CRITICAL"),8080: ("HTTP-Alt", "LOW"),
    8443: ("HTTPS-Alt", "LOW"),   9200: ("Elasticsearch", "CRITICAL"),
    9300: ("Elasticsearch", "CRITICAL"),10250: ("Kubelet", "CRITICAL"),
    11211: ("Memcached", "HIGH"), 27017: ("MongoDB", "CRITICAL"),
    50070: ("HDFS", "HIGH"),
}

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "cyan",
}

BANNER_PROBES = {
    21:  b"",
    22:  b"",
    25:  b"EHLO recon.local\r\n",
    80:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110: b"",
    143: b"",
    443: None,  # TLS
    3306: b"",
    5432: b"",
    6379: b"*1\r\n$4\r\nINFO\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00"
            b"admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff"
            b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00",
}

# CVE hints by service
CVE_HINTS = {
    "SMB":           ["CVE-2017-0144 (EternalBlue)", "CVE-2020-0796 (SMBGhost)"],
    "RDP":           ["CVE-2019-0708 (BlueKeep)", "CVE-2020-0609 (DejaBlue)"],
    "Telnet":        ["Cleartext credentials"],
    "Redis":         ["CVE-2022-0543 (Lua sandbox escape)", "Unauthenticated access"],
    "Elasticsearch": ["CVE-2021-44228 (Log4Shell)", "Unauthenticated access"],
    "MongoDB":       ["Unauthenticated access (default config)"],
    "Docker":        ["CVE-2019-5736 (runc escape)", "Remote code execution"],
    "Kubelet":       ["CVE-2018-1002105 (privilege escalation)"],
    "WebLogic":      ["CVE-2021-2109", "CVE-2020-14882"],
    "FTP":           ["CVE-2011-2523 (vsftpd backdoor)", "Anonymous login check"],
}


# ── Core scanning functions ──────────────────────────────────────────────────

def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    banner = None
    try:
        # TLS ports
        if port in (443, 8443, 993, 995, 465):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    banner = s.recv(2048).decode(errors="ignore")
        else:
            probe = BANNER_PROBES.get(port, b"\r\n")
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                if probe:
                    time.sleep(0.3)
                    s.send(probe)
                banner = s.recv(2048).decode(errors="ignore")
    except Exception:
        pass
    return banner.strip() if banner else None


def _ssl_cert_info(host: str, port: int) -> Optional[Dict]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=4) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                cipher = s.cipher()
                return {
                    "subject":  dict(x[0] for x in cert.get("subject", [])),
                    "issuer":   dict(x[0] for x in cert.get("issuer", [])),
                    "expires":  cert.get("notAfter"),
                    "cipher":   cipher[0] if cipher else None,
                    "version":  cipher[1] if cipher else None,
                }
    except Exception:
        return None


def _detect_service(port: int, banner: Optional[str]) -> Tuple[str, str]:
    """Return (service_name, risk_level)"""
    # Check known map
    if port in SERVICE_MAP:
        svc, risk = SERVICE_MAP[port]
        # Refine from banner
        if banner:
            b = banner.lower()
            if "openssh" in b:  svc = f"SSH ({re.search(r'openssh[_\s]+([\d.]+)', b, re.I) and re.search(r'openssh[_\s]+([\d.]+)', b, re.I).group(1) or ''})"
            if "apache" in b:   svc = f"Apache ({re.search(r'apache/([\d.]+)', b, re.I) and re.search(r'apache/([\d.]+)', b, re.I).group(1) or ''})"
            if "nginx" in b:    svc = f"Nginx ({re.search(r'nginx/([\d.]+)', b, re.I) and re.search(r'nginx/([\d.]+)', b, re.I).group(1) or ''})"
            if "iis" in b:      svc = f"IIS ({re.search(r'iis/([\d.]+)', b, re.I) and re.search(r'iis/([\d.]+)', b, re.I).group(1) or ''})"
            if "ftp" in b and "vsftpd" in b: svc = "vsftpd FTP"
        return svc, risk

    # Banner-based detection
    if banner:
        b = banner.lower()
        if "ssh"        in b: return "SSH", "MEDIUM"
        if "http"       in b: return "HTTP", "LOW"
        if "smtp"       in b: return "SMTP", "MEDIUM"
        if "ftp"        in b: return "FTP", "HIGH"
        if "redis"      in b: return "Redis", "CRITICAL"
        if "mongodb"    in b: return "MongoDB", "CRITICAL"
        if "mysql"      in b: return "MySQL", "HIGH"
        if "postgresql" in b: return "PostgreSQL", "HIGH"

    return "Unknown", "INFO"


def _os_fingerprint(host: str, open_ports: List[int]) -> str:
    """Heuristic OS guess from open ports."""
    if 3389 in open_ports or 135 in open_ports or 445 in open_ports:
        if 5985 in open_ports or 5986 in open_ports:
            return "Windows Server (WinRM detected)"
        return "Windows"
    if 22 in open_ports:
        if 111 in open_ports or 2049 in open_ports:
            return "Linux/Unix (NFS detected)"
        if 7001 in open_ports:
            return "Linux (WebLogic)"
        return "Linux/Unix"
    if 548 in open_ports or 5900 in open_ports:
        return "macOS (AFP/VNC)"
    if 2375 in open_ports or 10250 in open_ports:
        return "Linux (Container Host)"
    return "Unknown"


def _udp_scan(host: str, ports: List[int] = None, timeout: float = 2.0) -> List[int]:
    """Lightweight UDP scan for common ports."""
    if ports is None:
        ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 4500, 5353]

    open_udp: List[int] = []
    PROBES = {
        53:   b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        161:  b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x71\x68\xfb\x98\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        123:  b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00" + b"\x00" * 36,
        1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
    }

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            probe = PROBES.get(port, b"\x00")
            sock.sendto(probe, (host, port))
            data, _ = sock.recvfrom(1024)
            if data:
                open_udp.append(port)
        except socket.timeout:
            pass  # No response = filtered/closed
        except Exception:
            pass
        finally:
            sock.close()

    return open_udp


# ── Main scan function ───────────────────────────────────────────────────────

def run_port_scan(target: str, ports: List[int] = None,
                  udp: bool = True, aggressive: bool = False) -> Dict:
    section_header("Port Scanner", "Ultra TCP+UDP Engine")

    # Resolve hostname
    try:
        ip = socket.gethostbyname(target)
        info(f"Target: {target} → {ip}")
    except socket.gaierror:
        error(f"Cannot resolve: {target}")
        return {}

    ports = ports or TOP_1000_PORTS
    info(f"Scanning {len(ports)} ports on {ip}...")

    open_ports: List[Dict] = []
    lock = threading.Lock()
    scanned = [0]

    def _scan_port(port: int):
        if _tcp_connect(ip, port):
            banner = _grab_banner(ip, port)
            svc, risk = _detect_service(port, banner)
            ssl_info = _ssl_cert_info(ip, port) if port in (443, 8443, 993, 995) else None
            cve_list = CVE_HINTS.get(svc.split(" ")[0], [])

            result = {
                "port":    port,
                "proto":   "TCP",
                "service": svc,
                "risk":    risk,
                "banner":  (banner[:200] if banner else None),
                "ssl":     ssl_info,
                "cves":    cve_list,
            }
            with lock:
                open_ports.append(result)
                color = RISK_COLORS.get(risk, "white")
                found(
                    f"[TCP {port:5d}] [{color}]{risk:8}[/{color}] "
                    f"{svc}  {banner[:60] if banner else ''}"
                )
        with lock:
            scanned[0] += 1

    with ThreadPoolExecutor(max_workers=200) as ex:
        futures = {ex.submit(_scan_port, p): p for p in ports}
        for _ in as_completed(futures):
            pass

    # UDP scan
    udp_open: List[int] = []
    if udp:
        info("Running UDP scan on common ports...")
        udp_open = _udp_scan(ip)
        for port in udp_open:
            svc = SERVICE_MAP.get(port, ("Unknown", "INFO"))[0]
            found(f"[UDP {port:5d}] OPEN  {svc}")

    # OS fingerprint
    open_tcp = [p["port"] for p in open_ports]
    os_guess = _os_fingerprint(ip, open_tcp)

    # Risk breakdown
    risk_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for p in open_ports:
        risk_count[p["risk"]] = risk_count.get(p["risk"], 0) + 1

    # Print results table
    console.print("\n[bold cyan]━━━ PORT SCAN RESULTS ━━━[/bold cyan]")
    open_ports.sort(key=lambda x: x["port"])
    for p in open_ports:
        color = RISK_COLORS.get(p["risk"], "white")
        console.print(
            f"  [bold]{p['port']:5d}/TCP[/bold]  "
            f"[{color}]{p['risk']:8}[/{color}]  "
            f"[cyan]{p['service']:30}[/cyan]  "
            f"[dim]{(p['banner'] or '')[:50]}[/dim]"
        )
        if p["cves"]:
            for cve in p["cves"]:
                console.print(f"             [red]⚠  {cve}[/red]")
        if p["ssl"]:
            s = p["ssl"]
            console.print(f"             [dim]SSL: {s.get('cipher')} | Expires: {s.get('expires')}[/dim]")

    console.print(f"\n  [yellow]OS Guess:[/yellow] {os_guess}")

    print_summary("Port Scan", {
        "Target":         f"{target} ({ip})",
        "Ports Scanned":  len(ports),
        "TCP Open":       len(open_ports),
        "UDP Open":       len(udp_open),
        "OS Guess":       os_guess,
        "CRITICAL":       risk_count["CRITICAL"],
        "HIGH":           risk_count["HIGH"],
        "MEDIUM":         risk_count["MEDIUM"],
    })

    return {
        "target": target,
        "ip": ip,
        "tcp_open": open_ports,
        "udp_open": udp_open,
        "os_guess": os_guess,
        "risk_summary": risk_count,
    }
