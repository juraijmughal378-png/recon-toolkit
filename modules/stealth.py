"""
stealth.py — Ultra Stealth & Evasion Engine
Features: User-agent rotation, IP rotation via Tor, random delays,
          header randomization, traffic mimicry, fingerprint evasion,
          rate limit detection + backoff, proxy pool management
"""

import random
import time
import socket
import threading
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import info, warning, success

# ── User Agent Pool ───────────────────────────────────────────────────────────
USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Mobile Chrome
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    # Googlebot (sometimes bypasses WAF)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    # BingBot
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8,en-US;q=0.7",
    "en-US,en;q=0.8",
    "en;q=0.9",
]

ACCEPT_ENCODINGS = [
    "gzip, deflate, br",
    "gzip, deflate",
    "br, gzip",
]


class StealthSession:
    """Rate-aware stealth session with evasion capabilities."""

    def __init__(self, use_tor: bool = False, proxy: str = "",
                 min_delay: float = 0.3, max_delay: float = 2.0,
                 rotate_ua: bool = True):
        self.use_tor    = use_tor
        self.proxy      = proxy
        self.min_delay  = min_delay
        self.max_delay  = max_delay
        self.rotate_ua  = rotate_ua
        self._lock      = threading.Lock()
        self._last_req  = 0.0
        self._req_count = 0
        self._errors    = 0
        self._backoff   = 1.0

    def _build_headers(self) -> Dict:
        ua = random.choice(USER_AGENTS) if self.rotate_ua else USER_AGENTS[0]
        return {
            "User-Agent":      ua,
            "Accept":          random.choice(ACCEPT_HEADERS),
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": random.choice(ACCEPT_ENCODINGS),
            "Connection":      "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest":  "document",
            "Sec-Fetch-Mode":  "navigate",
            "Sec-Fetch-Site":  "none",
            "Cache-Control":   random.choice(["no-cache", "max-age=0", ""]),
        }

    def _get_proxy(self) -> Optional[Dict]:
        if self.use_tor:
            return {"http": "socks5://127.0.0.1:9050",
                    "https": "socks5://127.0.0.1:9050"}
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        return None

    def _rate_limit(self):
        with self._lock:
            now     = time.time()
            elapsed = now - self._last_req
            delay   = random.uniform(self.min_delay, self.max_delay) * self._backoff
            if elapsed < delay:
                time.sleep(delay - elapsed)
            self._last_req  = time.time()
            self._req_count += 1

    def _handle_response(self, r: requests.Response):
        """Detect rate limiting and adjust."""
        if r.status_code == 429:
            retry_after = int(r.headers.get("Retry-After", 30))
            warning(f"Rate limited! Waiting {retry_after}s...")
            time.sleep(retry_after)
            self._backoff = min(self._backoff * 2, 10.0)
        elif r.status_code in (503, 502, 504):
            self._backoff = min(self._backoff * 1.5, 5.0)
        elif r.status_code < 400:
            self._backoff = max(self._backoff * 0.9, 1.0)

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        self._rate_limit()
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)

        headers = self._build_headers()
        headers.update(kwargs.pop("headers", {}))

        proxies = self._get_proxy()

        for attempt in range(3):
            try:
                r = requests.get(url, headers=headers, proxies=proxies, **kwargs)
                self._handle_response(r)
                self._errors = 0
                return r
            except requests.exceptions.ProxyError:
                warning("Proxy error — check Tor/proxy settings")
                break
            except requests.exceptions.ConnectionError:
                self._errors += 1
                if attempt < 2:
                    time.sleep(2 ** attempt)
            except Exception as e:
                self._errors += 1
                break

        return None

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        self._rate_limit()
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("verify", False)

        headers = self._build_headers()
        headers.update(kwargs.pop("headers", {}))
        proxies = self._get_proxy()

        try:
            r = requests.post(url, headers=headers, proxies=proxies, **kwargs)
            self._handle_response(r)
            return r
        except Exception:
            return None

    @property
    def stats(self) -> Dict:
        return {
            "requests":  self._req_count,
            "errors":    self._errors,
            "backoff":   self._backoff,
        }


# ── Tor management ────────────────────────────────────────────────────────────

def is_tor_running() -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=2)
        s.close()
        return True
    except Exception:
        return False


def get_tor_ip() -> Optional[str]:
    try:
        r = requests.get(
            "https://api.ipify.org",
            proxies={"http": "socks5://127.0.0.1:9050",
                     "https": "socks5://127.0.0.1:9050"},
            timeout=10
        )
        return r.text.strip()
    except Exception:
        return None


def rotate_tor_identity():
    """Request new Tor circuit."""
    try:
        import socket
        s = socket.socket()
        s.connect(("127.0.0.1", 9051))
        s.send(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\n')
        s.close()
        time.sleep(2)
        success("Tor identity rotated")
        return True
    except Exception as e:
        warning(f"Tor rotation failed: {e}")
        return False


# ── WAF Evasion ───────────────────────────────────────────────────────────────

def encode_payload(payload: str, method: str = "url") -> str:
    """Encode payload to evade WAF."""
    import urllib.parse

    if method == "url":
        return urllib.parse.quote(payload)
    elif method == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif method == "html":
        return payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    elif method == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    elif method == "hex":
        return "".join(f"%{ord(c):02x}" for c in payload)
    elif method == "base64":
        import base64
        return base64.b64encode(payload.encode()).decode()
    elif method == "case":
        result = ""
        for i, c in enumerate(payload):
            result += c.upper() if i % 2 else c.lower()
        return result
    return payload


EVASION_TECHNIQUES = {
    "comment_injection": lambda p: p.replace(" ", "/**/"),
    "case_variation":    lambda p: "".join(c.upper() if i%2 else c.lower() for i,c in enumerate(p)),
    "url_encoding":      lambda p: "".join(f"%{ord(c):02x}" if c in "'\";=<>" else c for c in p),
    "double_encoding":   lambda p: "".join(f"%25{ord(c):02x}" if c in "'\";=<>" else c for c in p),
    "null_byte":         lambda p: p.replace(" ", "%00"),
    "tab_substitution":  lambda p: p.replace(" ", "\t"),
    "newline_inject":    lambda p: p.replace(" ", "%0a"),
}


def generate_evasion_variants(payload: str) -> List[str]:
    """Generate WAF evasion variants of a payload."""
    variants = [payload]
    for name, transform in EVASION_TECHNIQUES.items():
        try:
            variants.append(transform(payload))
        except Exception:
            pass
    return list(set(variants))


# ── IP Spoofing Headers ───────────────────────────────────────────────────────

def get_spoof_headers(real_ip: str = None) -> Dict:
    """Generate IP spoofing headers."""
    fake_ips = [
        "127.0.0.1", "10.0.0.1", "192.168.1.1",
        "172.16.0.1", "localhost",
    ]
    if not real_ip:
        real_ip = random.choice(fake_ips)

    return {
        "X-Forwarded-For":        real_ip,
        "X-Real-IP":              real_ip,
        "X-Originating-IP":       real_ip,
        "X-Remote-IP":            real_ip,
        "X-Remote-Addr":          real_ip,
        "X-Client-IP":            real_ip,
        "X-Host":                 real_ip,
        "X-Custom-IP-Authorization": real_ip,
        "True-Client-IP":         real_ip,
        "CF-Connecting-IP":       real_ip,
    }


# ── Session factory ───────────────────────────────────────────────────────────

def create_stealth_session(level: str = "medium") -> StealthSession:
    """Create session with stealth level: low/medium/high/paranoid."""
    configs = {
        "low":      {"min_delay": 0.1, "max_delay": 0.5, "rotate_ua": False},
        "medium":   {"min_delay": 0.3, "max_delay": 1.5, "rotate_ua": True},
        "high":     {"min_delay": 1.0, "max_delay": 3.0, "rotate_ua": True},
        "paranoid": {"min_delay": 3.0, "max_delay": 8.0, "rotate_ua": True,
                     "use_tor": is_tor_running()},
    }
    cfg = configs.get(level, configs["medium"])

    from modules.config import get
    if get("stealth", "use_tor", False) and is_tor_running():
        cfg["use_tor"] = True
    if get("stealth", "proxy", ""):
        cfg["proxy"] = get("stealth", "proxy", "")

    session = StealthSession(**cfg)
    if cfg.get("use_tor"):
        tor_ip = get_tor_ip()
        if tor_ip:
            info(f"Tor active — exit IP: {tor_ip}")
    return session
