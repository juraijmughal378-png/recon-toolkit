"""
config.py — Centralized configuration loader
Loads config.yaml + environment variables + CLI args
"""

import os
import yaml
from typing import Any, Dict, Optional

_CONFIG: Dict = {}
_CONFIG_FILE = "config.yaml"

DEFAULT_CONFIG = {
    "api_keys": {
        "shodan": "", "nvd": "", "github": "",
        "anthropic": "", "virustotal": "",
    },
    "scan": {
        "threads": 50, "timeout": 10, "rate_limit": 100,
        "delay": 0.3, "retries": 3, "max_depth": 3,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "verify_ssl": False, "follow_redirects": True,
    },
    "stealth": {
        "enabled": False, "random_delay": True, "rotate_ua": True,
        "use_tor": False, "tor_port": 9050, "proxy": "",
    },
    "auth": {
        "cookies": "", "headers": {}, "username": "",
        "password": "", "auth_type": "",
    },
    "output": {
        "reports_dir": "reports", "screenshots_dir": "screenshots",
        "save_html": True, "open_browser": False,
    },
    "notifications": {
        "enabled": False, "discord_webhook": "", "slack_webhook": "",
    },
    "profiles": {
        "bug_bounty": {"modules": [1,2,3,8,9,11,12,13,14,15,16,17,18,19,20,21,22,23]},
        "pentest":    {"modules": [1,2,3,5,6,7,8,9,10,11,12,16,17,18,19,24,25,26,27,28,29]},
        "ctf":        {"modules": [1,2,3,8,9,12,16,17,18,19,20,21]},
        "quick":      {"modules": [1,2,3,8,9,10]},
        "stealth":    {"modules": [1,3,4,6,14]},
    },
}


def load_config(path: str = _CONFIG_FILE) -> Dict:
    """Load config from YAML file + env vars."""
    global _CONFIG
    _CONFIG = dict(DEFAULT_CONFIG)

    # Load from YAML
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                file_cfg = yaml.safe_load(f) or {}
            _deep_merge(_CONFIG, file_cfg)
        except Exception as e:
            pass

    # Override with environment variables
    env_map = {
        "SHODAN_API_KEY":     ("api_keys", "shodan"),
        "NVD_API_KEY":        ("api_keys", "nvd"),
        "GITHUB_TOKEN":       ("api_keys", "github"),
        "ANTHROPIC_API_KEY":  ("api_keys", "anthropic"),
        "VIRUSTOTAL_API_KEY": ("api_keys", "virustotal"),
        "PROXY":              ("stealth",  "proxy"),
        "USE_TOR":            ("stealth",  "use_tor"),
        "AUTH_COOKIES":       ("auth",     "cookies"),
        "DISCORD_WEBHOOK":    ("notifications", "discord_webhook"),
        "SLACK_WEBHOOK":      ("notifications", "slack_webhook"),
    }
    for env_key, (section, key) in env_map.items():
        val = os.environ.get(env_key)
        if val:
            if section not in _CONFIG:
                _CONFIG[section] = {}
            _CONFIG[section][key] = val

    return _CONFIG


def _deep_merge(base: Dict, override: Dict):
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


def get(section: str, key: str, default: Any = None) -> Any:
    if not _CONFIG:
        load_config()
    return _CONFIG.get(section, {}).get(key, default)


def get_api_key(name: str) -> Optional[str]:
    key = get("api_keys", name, "")
    return key if key else None


def get_auth_headers() -> Dict:
    """Build auth headers from config."""
    headers = {}
    auth_type = get("auth", "auth_type", "")
    cookies   = get("auth", "cookies", "")
    token     = get("auth", "headers", {}).get("Authorization", "")

    if cookies:
        headers["Cookie"] = cookies
    if token:
        headers["Authorization"] = token
    if auth_type == "basic":
        import base64
        u = get("auth", "username", "")
        p = get("auth", "password", "")
        if u and p:
            cred = base64.b64encode(f"{u}:{p}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"

    return headers


def get_session():
    """Build authenticated requests session from config."""
    import requests
    import random

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ]

    s = requests.Session()

    # User agent
    rotate = get("stealth", "rotate_ua", True)
    ua     = random.choice(USER_AGENTS) if rotate else get("scan", "user_agent", USER_AGENTS[0])
    s.headers["User-Agent"] = ua

    # Auth headers
    s.headers.update(get_auth_headers())

    # Proxy
    proxy = get("stealth", "proxy", "")
    if get("stealth", "use_tor", False):
        proxy = f"socks5://127.0.0.1:{get('stealth','tor_port',9050)}"
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}

    return s


def get_delay() -> float:
    """Get request delay with optional randomization."""
    import random
    base = get("scan", "delay", 0.3)
    if get("stealth", "random_delay", False):
        return random.uniform(base, base * 5)
    return base


def get_profile(name: str) -> Optional[Dict]:
    return get("profiles", name)


def is_stealth_mode() -> bool:
    return get("stealth", "enabled", False)


# Auto-load on import
load_config()
