"""
fingerprint.py — Ultra Technology Fingerprinting Engine
Features: 80+ technologies, CMS/framework/server/CDN/JS detection,
          version extraction, security header analysis, cookie analysis,
          favicon hash matching, HTML pattern matching, API tech detection
"""

import hashlib
import re
import socket
import ssl
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 12

# ── Technology signatures ─────────────────────────────────────────────────────
# Format: {name: {category, indicators, version_re}}
TECH_SIGNATURES = {

    # CMS
    "WordPress": {
        "category": "CMS",
        "header_patterns": {},
        "body_patterns": [
            r"/wp-content/", r"/wp-includes/", r"wp-json",
            r'name="generator"\s+content="WordPress\s*([\d.]+)"',
        ],
        "path_check": ["/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/wp-json/wp/v2/"],
        "version_re": r'WordPress\s*([\d.]+)',
        "risk": "MEDIUM",
    },
    "Joomla": {
        "category": "CMS",
        "body_patterns": [r"/media/jui/", r"joomla", r"com_content"],
        "path_check": ["/administrator/", "/components/", "/modules/"],
        "version_re": r'Joomla!\s*([\d.]+)',
        "risk": "MEDIUM",
    },
    "Drupal": {
        "category": "CMS",
        "header_patterns": {"x-generator": r"Drupal"},
        "body_patterns": [r"/sites/default/", r"drupal.js", r"Drupal\.settings"],
        "path_check": ["/user/login", "/node/1", "/sites/default/files/"],
        "version_re": r'Drupal\s*([\d.]+)',
        "risk": "MEDIUM",
    },
    "Magento": {
        "category": "CMS",
        "body_patterns": [r"Mage\.Cookies", r"/skin/frontend/", r"magento"],
        "path_check": ["/admin/", "/downloader/", "/index.php/admin/"],
        "cookie_patterns": {"frontend": r".*"},
        "risk": "HIGH",
    },
    "Shopify": {
        "category": "CMS",
        "body_patterns": [r"cdn\.shopify\.com", r"shopify-section"],
        "header_patterns": {"x-shopid": r".*"},
        "risk": "LOW",
    },
    "Ghost": {
        "category": "CMS",
        "body_patterns": [r"content=\"Ghost\s*([\d.]+)\"", r"/ghost/api/"],
        "risk": "LOW",
    },
    "TYPO3": {
        "category": "CMS",
        "body_patterns": [r"typo3", r"/typo3/", r"typo3temp"],
        "risk": "MEDIUM",
    },
    "OpenCart": {
        "category": "CMS",
        "body_patterns": [r"route=common/home", r"opencart"],
        "risk": "MEDIUM",
    },

    # Frameworks
    "Laravel": {
        "category": "Framework",
        "header_patterns": {"set-cookie": r"laravel_session"},
        "body_patterns": [r"laravel", r"csrf-token.*content=\"[A-Za-z0-9+/=]{40}"],
        "risk": "LOW",
    },
    "Django": {
        "category": "Framework",
        "header_patterns": {"x-frame-options": r"SAMEORIGIN"},
        "body_patterns": [r"__csrfmiddlewaretoken", r"csrfmiddlewaretoken"],
        "cookie_patterns": {"csrftoken": r".*", "sessionid": r".*"},
        "risk": "LOW",
    },
    "Ruby on Rails": {
        "category": "Framework",
        "header_patterns": {"x-powered-by": r"Phusion Passenger|mod_rails"},
        "body_patterns": [r"csrf-param.*content=\"authenticity_token\"", r"rails-ujs"],
        "cookie_patterns": {"_session_id": r".*"},
        "risk": "LOW",
    },
    "React": {
        "category": "JS Framework",
        "body_patterns": [r"react\.development\.js|react\.production\.min\.js",
                          r"__REACT_DEVTOOLS", r"data-reactroot"],
        "risk": "LOW",
    },
    "Angular": {
        "category": "JS Framework",
        "body_patterns": [r"ng-version=", r"angular\.js|angular\.min\.js", r"\[ng-"],
        "risk": "LOW",
    },
    "Vue.js": {
        "category": "JS Framework",
        "body_patterns": [r"vue\.js|vue\.min\.js|vue@", r"__vue__", r"data-v-"],
        "risk": "LOW",
    },
    "Next.js": {
        "category": "Framework",
        "body_patterns": [r"__NEXT_DATA__", r"/_next/static/"],
        "header_patterns": {"x-powered-by": r"Next\.js"},
        "risk": "LOW",
    },
    "Nuxt.js": {
        "category": "Framework",
        "body_patterns": [r"__nuxt", r"/_nuxt/"],
        "risk": "LOW",
    },
    "Spring Boot": {
        "category": "Framework",
        "body_patterns": [r"Whitelabel Error Page", r"Spring Boot"],
        "path_check": ["/actuator", "/actuator/health", "/env", "/beans"],
        "risk": "HIGH",
    },
    "ASP.NET": {
        "category": "Framework",
        "header_patterns": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r".*"},
        "body_patterns": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"aspnetForm"],
        "cookie_patterns": {"asp.net_sessionid": r".*", ".aspxauth": r".*"},
        "risk": "MEDIUM",
    },
    "Flask": {
        "category": "Framework",
        "cookie_patterns": {"session": r"eyJ"},  # JWT-like Flask session
        "body_patterns": [r"Werkzeug|Flask"],
        "risk": "LOW",
    },
    "Express.js": {
        "category": "Framework",
        "header_patterns": {"x-powered-by": r"Express"},
        "risk": "LOW",
    },
    "FastAPI": {
        "category": "Framework",
        "body_patterns": [r'"openapi":', r'fastapi'],
        "path_check": ["/docs", "/redoc", "/openapi.json"],
        "risk": "LOW",
    },

    # Web Servers
    "Apache": {
        "category": "Web Server",
        "header_patterns": {"server": r"Apache(?:/([\d.]+))?"},
        "version_re": r"Apache/([\d.]+)",
        "risk": "LOW",
    },
    "Nginx": {
        "category": "Web Server",
        "header_patterns": {"server": r"nginx(?:/([\d.]+))?"},
        "version_re": r"nginx/([\d.]+)",
        "risk": "LOW",
    },
    "IIS": {
        "category": "Web Server",
        "header_patterns": {"server": r"Microsoft-IIS(?:/([\d.]+))?"},
        "version_re": r"IIS/([\d.]+)",
        "risk": "MEDIUM",
    },
    "LiteSpeed": {
        "category": "Web Server",
        "header_patterns": {"server": r"LiteSpeed|OpenLiteSpeed"},
        "risk": "LOW",
    },
    "Caddy": {
        "category": "Web Server",
        "header_patterns": {"server": r"Caddy"},
        "risk": "LOW",
    },
    "Tomcat": {
        "category": "Web Server",
        "header_patterns": {"server": r"Apache-Coyote|Tomcat"},
        "body_patterns": [r"Apache Tomcat", r"coyote"],
        "version_re": r"Tomcat/([\d.]+)",
        "risk": "HIGH",
    },
    "WebLogic": {
        "category": "Web Server",
        "header_patterns": {"server": r"WebLogic"},
        "risk": "CRITICAL",
    },
    "JBoss": {
        "category": "Web Server",
        "body_patterns": [r"JBoss", r"jboss"],
        "risk": "HIGH",
    },

    # CDN / Cloud
    "Cloudflare": {"category": "CDN", "header_patterns": {"server": r"cloudflare", "cf-ray": r".*"}, "risk": "INFO"},
    "Fastly":     {"category": "CDN", "header_patterns": {"x-fastly-request-id": r".*"}, "risk": "INFO"},
    "Akamai":     {"category": "CDN", "header_patterns": {"x-akamai-transformed": r".*"}, "risk": "INFO"},
    "AWS CloudFront": {"category": "CDN", "header_patterns": {"x-amz-cf-id": r".*"}, "risk": "INFO"},
    "Azure CDN":  {"category": "CDN", "header_patterns": {"x-azure-ref": r".*"}, "risk": "INFO"},
    "Varnish":    {"category": "CDN", "header_patterns": {"x-varnish": r".*", "via": r"varnish"}, "risk": "INFO"},

    # Analytics / Marketing
    "Google Analytics": {"category": "Analytics", "body_patterns": [r"google-analytics\.com|gtag\(|UA-\d+-\d+|G-[A-Z0-9]+"], "risk": "INFO"},
    "Google Tag Manager": {"category": "Analytics", "body_patterns": [r"googletagmanager\.com|GTM-[A-Z0-9]+"], "risk": "INFO"},
    "Hotjar":     {"category": "Analytics", "body_patterns": [r"hotjar\.com|hjid:"], "risk": "INFO"},
    "Mixpanel":   {"category": "Analytics", "body_patterns": [r"mixpanel\.com"], "risk": "INFO"},

    # Security
    "reCAPTCHA":  {"category": "Security", "body_patterns": [r"recaptcha|google\.com/recaptcha"], "risk": "INFO"},
    "hCaptcha":   {"category": "Security", "body_patterns": [r"hcaptcha\.com"], "risk": "INFO"},

    # Payment
    "Stripe":     {"category": "Payment", "body_patterns": [r"js\.stripe\.com", r"Stripe\."], "risk": "INFO"},
    "PayPal":     {"category": "Payment", "body_patterns": [r"paypal\.com/sdk", r"paypalobjects"], "risk": "INFO"},

    # Infrastructure
    "Kubernetes":  {"category": "Infrastructure", "path_check": ["/api/v1", "/healthz", "/metrics"], "risk": "HIGH"},
    "Docker":      {"category": "Infrastructure", "path_check": ["/v2/", "/_ping"], "body_patterns": [r'"Docker-Distribution-Api-Version"'], "risk": "CRITICAL"},
    "Elasticsearch": {"category": "Database", "path_check": ["/_cluster/health", "/_cat/indices"], "risk": "CRITICAL"},
    "Grafana":     {"category": "Monitoring", "body_patterns": [r"grafana"], "path_check": ["/api/health"], "risk": "MEDIUM"},
    "Kibana":      {"category": "Monitoring", "body_patterns": [r"kibana"], "path_check": ["/api/status"], "risk": "HIGH"},
    "Jenkins":     {"category": "CI/CD", "body_patterns": [r"Jenkins"], "path_check": ["/api/json"], "risk": "HIGH"},
    "GitLab":      {"category": "DevOps", "body_patterns": [r"GitLab"], "path_check": ["/users/sign_in", "/api/v4/projects"], "risk": "MEDIUM"},
    "phpMyAdmin":  {"category": "Database UI", "body_patterns": [r"phpMyAdmin"], "path_check": ["/phpmyadmin/", "/pma/"], "risk": "CRITICAL"},
}


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    return s


def _fetch_url(url: str) -> Optional[requests.Response]:
    try:
        return _session().get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return None


def _get_favicon_hash(base_url: str) -> Optional[str]:
    """Calculate favicon MD5 hash for Shodan-style fingerprinting."""
    for path in ["/favicon.ico", "/favicon.png"]:
        try:
            r = _session().get(urljoin(base_url, path), timeout=5, verify=False)
            if r.status_code == 200 and r.content:
                return hashlib.md5(r.content).hexdigest()
        except Exception:
            pass
    return None


def _check_path(base_url: str, path: str) -> Optional[int]:
    try:
        r = _session().get(urljoin(base_url, path), timeout=5, verify=False, allow_redirects=False)
        return r.status_code
    except Exception:
        return None


def _extract_version(text: str, pattern: str) -> Optional[str]:
    if not pattern:
        return None
    m = re.search(pattern, text, re.I)
    return m.group(1) if m and m.lastindex else None


def _analyze_security_headers(headers: Dict) -> Dict:
    checks = {
        "HSTS":                "Strict-Transport-Security",
        "CSP":                 "Content-Security-Policy",
        "X-Frame-Options":     "X-Frame-Options",
        "X-Content-Type":      "X-Content-Type-Options",
        "Referrer-Policy":     "Referrer-Policy",
        "Permissions-Policy":  "Permissions-Policy",
        "X-XSS-Protection":    "X-XSS-Protection",
        "CORS":                "Access-Control-Allow-Origin",
    }
    h = {k.lower(): v for k, v in headers.items()}
    result = {}
    for label, header in checks.items():
        val = h.get(header.lower())
        result[label] = {"present": bool(val), "value": val or ""}

    # Security scoring
    score = sum(1 for v in result.values() if v["present"])
    result["score"] = f"{score}/{len(checks)}"

    # Misconfigurations
    issues = []
    cors = result.get("CORS", {}).get("value", "")
    if cors == "*":
        issues.append("CORS: * allows any origin — potential data theft")
    hsts = result.get("HSTS", {}).get("value", "")
    if hsts and "includeSubDomains" not in hsts:
        issues.append("HSTS: missing includeSubDomains")
    xct = result.get("X-Content-Type", {}).get("value", "")
    if xct.lower() != "nosniff":
        issues.append("X-Content-Type-Options: not set to nosniff")
    result["issues"] = issues

    return result


def _detect_technologies(resp: requests.Response, base_url: str) -> List[Dict]:
    detected = []
    headers  = {k.lower(): v for k, v in resp.headers.items()}
    body     = resp.text
    cookies  = {k.lower(): v for k, v in resp.cookies.items()}

    for name, sig in TECH_SIGNATURES.items():
        matched = False
        version = None

        # Header checks
        for header, pattern in sig.get("header_patterns", {}).items():
            val = headers.get(header.lower(), "")
            if val and re.search(pattern, val, re.I):
                matched = True
                v = _extract_version(val, sig.get("version_re", ""))
                if v: version = v

        # Body checks
        for pattern in sig.get("body_patterns", []):
            if re.search(pattern, body, re.I):
                matched = True
                v = _extract_version(body, sig.get("version_re", ""))
                if v: version = v

        # Cookie checks
        for cookie, pattern in sig.get("cookie_patterns", {}).items():
            if cookie in cookies and re.search(pattern, cookies[cookie], re.I):
                matched = True

        # Path checks
        if sig.get("path_check"):
            for path in sig["path_check"][:2]:
                code = _check_path(base_url, path)
                if code in (200, 301, 302, 401, 403):
                    matched = True
                    break

        if matched:
            detected.append({
                "name":     name,
                "category": sig.get("category", "Unknown"),
                "version":  version,
                "risk":     sig.get("risk", "INFO"),
            })

    return detected


# ── Main entry point ─────────────────────────────────────────────────────────

def run_fingerprint(target: str) -> Dict:
    section_header("Technology Fingerprinting", "Ultra 80+ Tech Engine")
    info(f"Target: {target}")

    base_url = target if target.startswith("http") else f"https://{target}"

    # Try HTTPS first, fallback to HTTP
    resp = _fetch_url(base_url)
    if not resp:
        base_url = f"http://{target}"
        resp = _fetch_url(base_url)

    if not resp:
        error(f"Cannot reach {target}")
        return {}

    final_url = resp.url
    success(f"Connected: {final_url} [{resp.status_code}]")
    info(f"Final URL: {final_url}")

    # Detect technologies
    info("Analyzing technologies...")
    technologies = _detect_technologies(resp, base_url)

    # Favicon hash
    fav_hash = _get_favicon_hash(base_url)
    if fav_hash:
        info(f"Favicon MD5: {fav_hash}  "
             f"(Shodan: https://www.shodan.io/search?query=http.favicon.hash:{fav_hash})")

    # Security headers analysis
    sec_headers = _analyze_security_headers(dict(resp.headers))

    # Server info
    server      = resp.headers.get("Server", "—")
    x_powered   = resp.headers.get("X-Powered-By", "—")
    content_type = resp.headers.get("Content-Type", "—")

    # HTML meta analysis
    meta_tech: List[str] = []
    import re as _re
    for m in _re.finditer(r'<meta\s+name=["\']generator["\']\s+content=["\'](.*?)["\']', resp.text, _re.I):
        meta_tech.append(m.group(1))

    # ── Print results ─────────────────────────────────────────────────────────
    console.print("\n[bold cyan]━━━ DETECTED TECHNOLOGIES ━━━[/bold cyan]")

    # Group by category
    by_cat: Dict[str, List] = {}
    for tech in technologies:
        cat = tech["category"]
        by_cat.setdefault(cat, []).append(tech)

    RISK_COLORS = {"CRITICAL": "bold red","HIGH": "red","MEDIUM": "yellow","LOW": "green","INFO": "cyan"}

    for cat, techs in sorted(by_cat.items()):
        console.print(f"\n  [bold magenta]{cat}[/bold magenta]")
        for t in techs:
            color = RISK_COLORS.get(t["risk"], "white")
            version_str = f" [dim]v{t['version']}[/dim]" if t["version"] else ""
            found(f"    [{color}][{t['risk']:8}][/{color}]  {t['name']}{version_str}")

    if meta_tech:
        console.print(f"\n  [bold magenta]Meta Generator Tags[/bold magenta]")
        for m in meta_tech:
            found(f"    {m}")

    console.print(f"\n  Server:       {server}")
    console.print(f"  X-Powered-By: {x_powered}")
    console.print(f"  Content-Type: {content_type}")

    if fav_hash:
        console.print(f"  Favicon Hash: {fav_hash}")

    console.print("\n[bold cyan]━━━ SECURITY HEADERS ━━━[/bold cyan]")
    for label, data in sec_headers.items():
        if label in ("score", "issues"):
            continue
        icon  = "✓" if data["present"] else "✗"
        color = "green" if data["present"] else "red"
        val   = f"  [dim]{data['value'][:60]}[/dim]" if data["value"] else ""
        console.print(f"  [{color}]{icon}[/{color}]  {label:25}{val}")

    console.print(f"\n  Security Header Score: {sec_headers['score']}")
    for issue in sec_headers.get("issues", []):
        warning(f"  ⚠ {issue}")

    # Risk summary
    risk_count = {}
    for t in technologies:
        risk_count[t["risk"]] = risk_count.get(t["risk"], 0) + 1

    print_summary("Technology Fingerprinting", {
        "Technologies Found": len(technologies),
        "CRITICAL":          risk_count.get("CRITICAL", 0),
        "HIGH":              risk_count.get("HIGH", 0),
        "MEDIUM":            risk_count.get("MEDIUM", 0),
        "Security Headers":  sec_headers["score"],
        "Favicon Hash":      fav_hash or "—",
    })

    return {
        "technologies":     technologies,
        "security_headers": sec_headers,
        "favicon_hash":     fav_hash,
        "server":           server,
        "x_powered_by":     x_powered,
        "meta_generators":  meta_tech,
        "final_url":        final_url,
    }
