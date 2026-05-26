"""
takeover.py — Ultra Subdomain Takeover Checker
Features: 50+ service fingerprints, CNAME chain analysis, DNS validation,
          HTTP response matching, confidence scoring, PoC generation
"""

import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

import dns.resolver
import requests
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 10

# ── 50+ Service fingerprints ──────────────────────────────────────────────────
TAKEOVER_SIGNATURES = [
    {"service": "GitHub Pages",       "cname": ["github.io"],                        "body": ["There isn't a GitHub Pages site here", "For root URLs"], "status": [404], "confidence": "HIGH"},
    {"service": "Heroku",             "cname": ["herokudns.com","herokussl.com"],     "body": ["No such app","herokucdn.com/error-pages"], "status": [404], "confidence": "HIGH"},
    {"service": "Shopify",            "cname": ["myshopify.com","shopify.com"],       "body": ["Sorry, this shop is currently unavailable"], "status": [404], "confidence": "HIGH"},
    {"service": "Amazon S3",          "cname": ["s3.amazonaws.com","s3-website"],     "body": ["NoSuchBucket","The specified bucket does not exist"], "status": [404,403], "confidence": "HIGH"},
    {"service": "Amazon CloudFront",  "cname": ["cloudfront.net"],                   "body": ["Bad request","ERROR: The request could not be satisfied"], "status": [403], "confidence": "MEDIUM"},
    {"service": "Fastly",             "cname": ["fastly.net"],                        "body": ["Fastly error: unknown domain","Please check that this domain has been added"], "status": [404], "confidence": "HIGH"},
    {"service": "Azure",              "cname": ["azurewebsites.net","azure.com","cloudapp.net","trafficmanager.net"], "body": ["404 Web Site not found","does not exist"], "status": [404], "confidence": "HIGH"},
    {"service": "Zendesk",            "cname": ["zendesk.com"],                       "body": ["Help Center Closed","Oops, this help center no longer exists"], "status": [404], "confidence": "HIGH"},
    {"service": "Tumblr",             "cname": ["tumblr.com"],                        "body": ["Whatever you were looking for doesn't currently exist","There's nothing here"], "status": [404], "confidence": "HIGH"},
    {"service": "WordPress.com",      "cname": ["wordpress.com"],                     "body": ["Do you want to register","doesn't exist"], "status": [404], "confidence": "HIGH"},
    {"service": "Pantheon",           "cname": ["pantheonsite.io","getpantheon.com"], "body": ["404 error unknown site!","The gods are wise"], "status": [404], "confidence": "HIGH"},
    {"service": "Ghost",              "cname": ["ghost.io"],                          "body": ["The thing you were looking for is no longer here"], "status": [404], "confidence": "HIGH"},
    {"service": "Surge.sh",           "cname": ["surge.sh"],                          "body": ["project not found"], "status": [404], "confidence": "HIGH"},
    {"service": "Bitbucket",          "cname": ["bitbucket.io"],                      "body": ["Repository not found"], "status": [404], "confidence": "HIGH"},
    {"service": "HubSpot",            "cname": ["hubspot.com","hs-sites.com"],        "body": ["does not exist in our system","Domain not found"], "status": [404], "confidence": "HIGH"},
    {"service": "Squarespace",        "cname": ["squarespace.com"],                   "body": ["No Such Account","You may have mistyped"], "status": [404], "confidence": "MEDIUM"},
    {"service": "Wix",                "cname": ["wixdns.net","wix.com"],              "body": ["Error ConnectWebsiteToWix","Looks like there's no site at this address"], "status": [404], "confidence": "HIGH"},
    {"service": "Webflow",            "cname": ["webflow.io"],                        "body": ["The page you are looking for doesn't exist"], "status": [404], "confidence": "HIGH"},
    {"service": "Netlify",            "cname": ["netlify.app","netlify.com"],         "body": ["Not Found - Request ID"], "status": [404], "confidence": "HIGH"},
    {"service": "Vercel",             "cname": ["vercel.app","now.sh"],               "body": ["The deployment could not be found","DEPLOYMENT_NOT_FOUND"], "status": [404], "confidence": "HIGH"},
    {"service": "ReadMe.io",          "cname": ["readme.io"],                         "body": ["Project doesnt exist... yet!"], "status": [404], "confidence": "HIGH"},
    {"service": "Statuspage.io",      "cname": ["statuspage.io"],                     "body": ["You are being redirected","page not found"], "status": [404], "confidence": "MEDIUM"},
    {"service": "Intercom",           "cname": ["intercom.io","custom.intercom.io"],  "body": ["This page doesn't exist","Uh oh. That page doesn't exist"], "status": [404], "confidence": "HIGH"},
    {"service": "Helpjuice",          "cname": ["helpjuice.com"],                     "body": ["We could not find what you're looking for"], "status": [404], "confidence": "HIGH"},
    {"service": "Help Scout",         "cname": ["helpscoutdocs.com"],                 "body": ["No settings were found for this company"], "status": [404], "confidence": "HIGH"},
    {"service": "Cargo",              "cname": ["cargocollective.com"],               "body": ["404 Not Found"], "status": [404], "confidence": "MEDIUM"},
    {"service": "UserVoice",          "cname": ["uservoice.com"],                     "body": ["This UserVoice subdomain is currently available!"], "status": [404], "confidence": "HIGH"},
    {"service": "Desk.com",           "cname": ["desk.com"],                          "body": ["Please try again or try Desk.com free for 14 days"], "status": [404], "confidence": "HIGH"},
    {"service": "Tave",               "cname": ["tave.com"],                          "body": ["tave.com"], "status": [404], "confidence": "LOW"},
    {"service": "Teamwork",           "cname": ["teamwork.com"],                      "body": ["Oops - We didn't find your site"], "status": [404], "confidence": "HIGH"},
    {"service": "Smartling",          "cname": ["smartling.com"],                     "body": ["Domain is not configured"], "status": [404], "confidence": "MEDIUM"},
    {"service": "Pingdom",            "cname": ["pingdom.com"],                       "body": ["This public report page has not been activated"], "status": [404], "confidence": "HIGH"},
    {"service": "Tilda",              "cname": ["tilda.ws"],                          "body": ["Domain is not connected","Please go to site settings"], "status": [404], "confidence": "HIGH"},
    {"service": "Strikingly",         "cname": ["strikingly.com","s.strikinglydns.com"], "body": ["page not found","But if you're looking to build your own"], "status": [404], "confidence": "HIGH"},
    {"service": "Uberflip",           "cname": ["uberflip.com"],                      "body": ["Non-hub domain, The URL you've accessed does not provide"], "status": [404], "confidence": "HIGH"},
    {"service": "Proposify",          "cname": ["proposify.biz"],                     "body": ["If you need immediate assistance"], "status": [404], "confidence": "MEDIUM"},
    {"service": "Simplebooklet",      "cname": ["simplebooklet.com"],                 "body": ["We can't find this flipbook"], "status": [404], "confidence": "HIGH"},
    {"service": "Getresponse",        "cname": ["gr8.com"],                           "body": ["With GetResponse Landing Pages"], "status": [404], "confidence": "MEDIUM"},
    {"service": "Acquia",             "cname": ["acquia-sites.com"],                  "body": ["If you are an Acquia Cloud customer"], "status": [404], "confidence": "HIGH"},
    {"service": "Feedpress",          "cname": ["feedpress.me"],                      "body": ["The feed has not been found"], "status": [404], "confidence": "HIGH"},
    {"service": "Freshdesk",          "cname": ["freshdesk.com"],                     "body": ["There is no helpdesk here with that URL"], "status": [404], "confidence": "HIGH"},
    {"service": "Unbounce",           "cname": ["unbouncepages.com"],                 "body": ["The requested URL was not found on this server"], "status": [404], "confidence": "MEDIUM"},
    {"service": "Leadpages",          "cname": ["leadpages.net","pageserve.co"],      "body": ["Uh oh. This page doesn't exist"], "status": [404], "confidence": "HIGH"},
    {"service": "Launchrock",         "cname": ["launchrock.com"],                    "body": ["It looks like you may have taken a wrong turn somewhere"], "status": [404], "confidence": "HIGH"},
    {"service": "Campaign Monitor",   "cname": ["createsend.com"],                    "body": ["Double check the URL"], "status": [404], "confidence": "MEDIUM"},
    {"service": "Kajabi",             "cname": ["kajabi.com"],                        "body": ["The page you were looking for doesn't exist"], "status": [404], "confidence": "HIGH"},
    {"service": "Clickfunnels",       "cname": ["clickfunnels.com"],                  "body": ["The page you were looking for"], "status": [404], "confidence": "MEDIUM"},
    {"service": "Aftership",          "cname": ["aftership.com"],                     "body": ["Oops.<br>Looks like you followed a bad link"], "status": [404], "confidence": "HIGH"},
    {"service": "Airee",              "cname": ["airee.ru"],                          "body": ["Ошибка: Сервис не найден"], "status": [402], "confidence": "HIGH"},
    {"service": "Anima",              "cname": ["animaapp.io"],                       "body": ["The page you're looking for doesn't exist"], "status": [404], "confidence": "HIGH"},
]

NXDOMAIN_TAKEOVER_SERVICES = [
    "github.io", "herokudns.com", "s3.amazonaws.com",
    "azurewebsites.net", "cloudapp.net", "trafficmanager.net",
]

CONFIDENCE_COLORS = {
    "HIGH":   "bold red",
    "MEDIUM": "yellow",
    "LOW":    "cyan",
}


def _get_cname_chain(domain: str) -> List[str]:
    """Follow full CNAME chain."""
    chain = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.lifetime = 5
    current = domain
    for _ in range(10):
        try:
            ans = resolver.resolve(current, "CNAME")
            cname = str(ans[0].target).rstrip(".")
            chain.append(cname)
            current = cname
        except Exception:
            break
    return chain


def _is_nxdomain(domain: str) -> bool:
    """Check if domain resolves to NXDOMAIN."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.lifetime = 5
    try:
        resolver.resolve(domain, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


def _http_probe(domain: str) -> Dict:
    """Probe HTTP/HTTPS and return status + body."""
    result = {"status": None, "body": "", "url": None}
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{domain}", timeout=TIMEOUT,
                verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            result["status"] = r.status_code
            result["body"]   = r.text[:3000]
            result["url"]    = r.url
            break
        except Exception:
            pass
    return result


def _check_takeover(subdomain: str) -> Optional[Dict]:
    """Check a single subdomain for takeover vulnerability."""
    # Get CNAME chain
    cname_chain = _get_cname_chain(subdomain)
    if not cname_chain:
        return None

    final_cname = cname_chain[-1]

    # Check NXDOMAIN on final CNAME
    nxdomain = _is_nxdomain(final_cname)

    # HTTP probe
    http = _http_probe(subdomain)

    # Match against signatures
    for sig in TAKEOVER_SIGNATURES:
        # CNAME match
        cname_match = any(
            s in final_cname or any(s in c for c in cname_chain)
            for s in sig["cname"]
        )
        if not cname_match:
            continue

        # Body match
        body_match = any(
            pattern.lower() in http["body"].lower()
            for pattern in sig["body"]
        )

        # Status match
        status_match = http["status"] in sig["status"] if http["status"] else False

        if body_match or (nxdomain and cname_match) or (status_match and cname_match):
            return {
                "subdomain":   subdomain,
                "service":     sig["service"],
                "cname_chain": cname_chain,
                "final_cname": final_cname,
                "nxdomain":    nxdomain,
                "http_status": http["status"],
                "confidence":  sig["confidence"],
                "poc":         _generate_poc(subdomain, sig["service"], final_cname),
            }

    return None


def _generate_poc(subdomain: str, service: str, cname: str) -> str:
    """Generate PoC instructions for the takeover."""
    pocs = {
        "GitHub Pages":  f"Create GitHub repo → Settings → Pages → Custom domain: {subdomain}",
        "Heroku":        f"heroku create → heroku domains:add {subdomain}",
        "Amazon S3":     f"aws s3api create-bucket --bucket {subdomain.split('.')[0]}",
        "Netlify":       f"Add custom domain {subdomain} to new Netlify site",
        "Vercel":        f"vercel domains add {subdomain}",
        "Azure":         f"Create Azure App Service → Add custom domain: {subdomain}",
        "Shopify":       f"Create Shopify store → Add domain: {subdomain}",
        "Fastly":        f"Add domain {subdomain} to Fastly service",
    }
    return pocs.get(service, f"Register {cname} on {service} and point to {subdomain}")


def run_takeover_check(target: str, subdomains: List[str] = None) -> Dict:
    section_header("Subdomain Takeover Checker", "Ultra 50+ Service Fingerprints")
    info(f"Target: {target}")

    # If no subdomains provided, enumerate first
    if not subdomains:
        info("No subdomains provided — running quick enumeration...")
        from modules.subdomain import _crtsh, _hackertarget
        subs = _crtsh(target) | _hackertarget(target)
        subdomains = list(subs)
        info(f"Found {len(subdomains)} subdomains to check")

    if not subdomains:
        warning("No subdomains to check")
        return {}

    info(f"Checking {len(subdomains)} subdomains for takeover...")
    vulnerable: List[Dict] = []
    lock = threading.Lock()

    def _check(sub: str):
        result = _check_takeover(sub)
        if result:
            with lock:
                vulnerable.append(result)
                color = CONFIDENCE_COLORS.get(result["confidence"], "white")
                found(
                    f"[{color}][VULNERABLE][/{color}]  {sub}  →  "
                    f"{result['service']}  [{result['confidence']}]"
                )

    with ThreadPoolExecutor(max_workers=30) as ex:
        list(ex.map(_check, subdomains))

    # Print results
    console.print(f"\n[bold cyan]━━━ TAKEOVER RESULTS ━━━[/bold cyan]")
    if vulnerable:
        for v in vulnerable:
            color = CONFIDENCE_COLORS.get(v["confidence"], "white")
            console.print(f"\n  [{color}]▶ {v['subdomain']}[/{color}]")
            console.print(f"    Service:    {v['service']}")
            console.print(f"    CNAME:      {' → '.join(v['cname_chain'])}")
            console.print(f"    NXDOMAIN:   {v['nxdomain']}")
            console.print(f"    HTTP:       {v['http_status']}")
            console.print(f"    Confidence: [{color}]{v['confidence']}[/{color}]")
            console.print(f"    [bold yellow]PoC:[/bold yellow] {v['poc']}")
    else:
        success("No takeover vulnerabilities found")

    print_summary("Subdomain Takeover", {
        "Subdomains Checked": len(subdomains),
        "Vulnerable":         len(vulnerable),
        "HIGH Confidence":    sum(1 for v in vulnerable if v["confidence"] == "HIGH"),
        "MEDIUM Confidence":  sum(1 for v in vulnerable if v["confidence"] == "MEDIUM"),
    })

    return {"vulnerable": vulnerable, "checked": len(subdomains)}
