"""
report_gen.py — Ultra Professional HTML Report Generator
Single file, dark theme, interactive, charts, severity badges
"""

import json
import os
from datetime import datetime
from typing import Dict, Any


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _slug(target):
    return target.replace(".", "_").replace(":", "_").replace("/", "_")

def _j(obj):
    try:
        return json.dumps(obj, indent=2, default=str)
    except Exception:
        return str(obj)

def _safe(val, default="—"):
    if val is None or val == "" or val == [] or val == {}:
        return default
    return val


# ── Data extractors ───────────────────────────────────────────────────────────

def _extract_summary(data: Dict) -> Dict:
    target  = data.get("_target", "Unknown")
    started = data.get("_started", _now())
    elapsed = data.get("_elapsed", "—")

    # Subdomains
    sub = data.get("subdomain", {})
    total_subs = sub.get("total", 0)
    live_subs  = sub.get("live", 0)

    # Ports
    port = data.get("portscan", {})
    open_ports   = len(port.get("tcp_open", []))
    risk_summary = port.get("risk_summary", {})

    # CVEs
    cve = data.get("cve", {})
    total_cves = cve.get("total", 0)
    kev_count  = cve.get("kev_count", 0)
    cve_sev    = cve.get("severity_count", {})

    # Web vulns
    xss_count  = data.get("xss",  {}).get("total", 0)
    sqli_count = data.get("sqli", {}).get("total", 0)
    lfi_count  = data.get("lfi",  {}).get("total", 0)
    ssrf_count = data.get("ssrf", {}).get("total", 0)
    xxe_count  = data.get("xxe",  {}).get("total", 0)
    ssti_count = data.get("ssti", {}).get("total", 0)
    idor_count = data.get("idor", {}).get("total", 0)
    redir_count= data.get("redirect", {}).get("total", 0)

    # SSL
    ssl  = data.get("ssl", {})
    grade = ssl.get("grade", "N/A")

    # WAF
    waf  = data.get("waf", {})
    waf_detected = ", ".join(waf.get("waf", [])) or "None"

    # Cloud
    cloud = data.get("cloud", {})
    public_buckets = len(cloud.get("public", []))

    # Emails
    email = data.get("email", {})
    email_count = len(email.get("all_emails", []))

    # Takeover
    takeover = data.get("takeover", {})
    takeover_count = len(takeover.get("vulnerable", []))

    # JS Secrets
    js = data.get("js", {})
    js_secrets = len(js.get("secrets", []))

    # GitHub
    github = data.get("github", {})
    github_findings = len(github.get("findings", []))

    # AI score
    ai = data.get("ai", {})
    risk_score = ai.get("risk_score", 0)
    risk_level = ai.get("risk_level", "—")

    # Password
    pw = data.get("password", {})
    pw_found = len(pw.get("default_creds", {}).get("credentials", []))

    # Exploit
    exp = data.get("exploits", {})
    exploit_count = exp.get("total", 0)

    return {
        "target": target, "started": started, "elapsed": elapsed,
        "subdomains": total_subs, "live_subs": live_subs,
        "open_ports": open_ports, "risk_summary": risk_summary,
        "total_cves": total_cves, "kev_count": kev_count, "cve_sev": cve_sev,
        "xss": xss_count, "sqli": sqli_count, "lfi": lfi_count,
        "ssrf": ssrf_count, "xxe": xxe_count, "ssti": ssti_count,
        "idor": idor_count, "redirect": redir_count,
        "ssl_grade": grade, "waf": waf_detected,
        "public_buckets": public_buckets, "emails": email_count,
        "takeovers": takeover_count, "js_secrets": js_secrets,
        "github_findings": github_findings, "risk_score": risk_score,
        "risk_level": risk_level, "pw_found": pw_found,
        "exploit_count": exploit_count,
    }


def _build_sections(data: Dict) -> str:
    sections = ""

    # ── Subdomains ────────────────────────────────────────────────────────────
    sub = data.get("subdomain", {})
    if sub:
        subs_html = ""
        for s in sub.get("subdomains", [])[:100]:
            alive = s.get("alive", False)
            ips   = ", ".join(s.get("A", [])[:2]) or "—"
            http  = s.get("http_status", "") or ""
            title = s.get("title", "") or ""
            badge = '<span class="badge green">LIVE</span>' if alive else '<span class="badge red">DEAD</span>'
            subs_html += f"""
            <tr>
              <td>{badge}</td>
              <td class="mono">{s.get("subdomain","")}</td>
              <td class="mono">{ips}</td>
              <td>{http}</td>
              <td class="dim">{title[:50]}</td>
            </tr>"""
        sections += f"""
        <div class="section" id="subdomains">
          <div class="section-header"><span class="icon">🔍</span>Subdomain Enumeration
            <span class="count">{sub.get("total",0)} found | {sub.get("live",0)} live</span>
          </div>
          <div class="section-body">
            <table><thead><tr><th>Status</th><th>Subdomain</th><th>IP</th><th>HTTP</th><th>Title</th></tr></thead>
            <tbody>{subs_html}</tbody></table>
          </div>
        </div>"""

    # ── Port Scan ─────────────────────────────────────────────────────────────
    port = data.get("portscan", {})
    if port:
        ports_html = ""
        for p in port.get("tcp_open", []):
            risk = p.get("risk", "INFO")
            rc   = {"CRITICAL":"red","HIGH":"orange","MEDIUM":"yellow","LOW":"green","INFO":"blue"}.get(risk,"blue")
            banner = (p.get("banner") or "")[:60]
            cves   = ", ".join(p.get("cves", [])[:2])
            ports_html += f"""
            <tr>
              <td class="mono">{p.get("port")}/TCP</td>
              <td><span class="badge {rc}">{risk}</span></td>
              <td>{p.get("service","")}</td>
              <td class="dim mono">{banner}</td>
              <td class="dim">{cves}</td>
            </tr>"""
        for p in port.get("udp_open", []):
            ports_html += f"""
            <tr>
              <td class="mono">{p}/UDP</td>
              <td><span class="badge blue">INFO</span></td>
              <td>UDP Service</td><td></td><td></td>
            </tr>"""
        sections += f"""
        <div class="section" id="ports">
          <div class="section-header"><span class="icon">🔌</span>Port Scanner
            <span class="count">{len(port.get("tcp_open",[]))} open | OS: {port.get("os_guess","—")}</span>
          </div>
          <div class="section-body">
            <table><thead><tr><th>Port</th><th>Risk</th><th>Service</th><th>Banner</th><th>CVE Hints</th></tr></thead>
            <tbody>{ports_html}</tbody></table>
          </div>
        </div>"""

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    whois = data.get("whois", {})
    if whois:
        w = whois
        geo = w.get("geoip", {})
        asn = w.get("asn", {})
        spf   = w.get("email_security", {}).get("spf", {})
        dmarc = w.get("email_security", {}).get("dmarc", {})
        dns   = w.get("dns", {})
        dns_rows = ""
        for rtype, vals in dns.items():
            for v in (vals if isinstance(vals, list) else [vals]):
                dns_rows += f"<tr><td class='mono yellow'>{rtype}</td><td class='mono'>{v}</td></tr>"
        sections += f"""
        <div class="section" id="whois">
          <div class="section-header"><span class="icon">🌐</span>WHOIS & DNS Intelligence</div>
          <div class="section-body">
            <div class="grid2">
              <div>
                <h4>WHOIS</h4>
                <table>
                  <tr><td>Registrar</td><td>{_safe(w.get("whois",{}).get("registrar"))}</td></tr>
                  <tr><td>Org</td><td>{_safe(w.get("whois",{}).get("org"))}</td></tr>
                  <tr><td>Registered</td><td>{_safe(w.get("whois",{}).get("registered"))}</td></tr>
                  <tr><td>Expires</td><td>{_safe(w.get("whois",{}).get("expires"))}</td></tr>
                  <tr><td>Age</td><td>{_safe(w.get("whois",{}).get("age_days"))} days</td></tr>
                </table>
                <h4>GeoIP / ASN</h4>
                <table>
                  <tr><td>IP</td><td class="mono">{_safe(w.get("ip"))}</td></tr>
                  <tr><td>Location</td><td>{_safe(geo.get("city"))}, {_safe(geo.get("country"))}</td></tr>
                  <tr><td>ISP</td><td>{_safe(geo.get("isp"))}</td></tr>
                  <tr><td>ASN</td><td>AS{_safe(asn.get("asn"))} — {_safe(asn.get("name"))}</td></tr>
                  <tr><td>Hosting</td><td>{"Yes" if geo.get("hosting") else "No"}</td></tr>
                  <tr><td>Proxy</td><td>{"Yes" if geo.get("proxy") else "No"}</td></tr>
                </table>
              </div>
              <div>
                <h4>Email Security</h4>
                <table>
                  <tr><td>SPF</td><td>{"✅ Found" if spf.get("found") else "❌ Missing"}</td></tr>
                  <tr><td>DMARC</td><td>{"✅ p="+str(dmarc.get("policy")) if dmarc.get("found") else "❌ Missing"}</td></tr>
                  <tr><td>DNSSEC</td><td>{"✅ Enabled" if w.get("dnssec",{}).get("enabled") else "⚠️ Disabled"}</td></tr>
                  <tr><td>Wildcard DNS</td><td>{"⚠️ Yes" if w.get("wildcard_dns") else "✅ No"}</td></tr>
                </table>
                <h4>DNS Records</h4>
                <table><thead><tr><th>Type</th><th>Value</th></tr></thead>
                <tbody>{dns_rows}</tbody></table>
              </div>
            </div>
          </div>
        </div>"""

    # ── CVEs ──────────────────────────────────────────────────────────────────
    cve = data.get("cve", {})
    if cve and cve.get("flat_cves"):
        cve_rows = ""
        for c in cve.get("flat_cves", [])[:50]:
            sev  = c.get("cvss_severity","UNKNOWN")
            sc   = {"CRITICAL":"red","HIGH":"orange","MEDIUM":"yellow","LOW":"green"}.get(sev,"blue")
            kev  = '<span class="badge red">KEV</span>' if c.get("kev",{}).get("in_kev") else ""
            exp  = '<span class="badge orange">EXPLOIT</span>' if c.get("has_exploit") else ""
            cve_rows += f"""
            <tr>
              <td><span class="badge {sc}">{sev}</span></td>
              <td class="mono red">{c.get("cve_id","")}</td>
              <td>{c.get("cvss_score","")}</td>
              <td>{kev}{exp}</td>
              <td class="dim">{(c.get("description") or "")[:80]}</td>
              <td class="dim">{c.get("_product","")}</td>
            </tr>"""
        sections += f"""
        <div class="section" id="cves">
          <div class="section-header"><span class="icon">💀</span>CVE Correlation
            <span class="count">{cve.get("total",0)} CVEs | {cve.get("kev_count",0)} KEV</span>
          </div>
          <div class="section-body">
            <table><thead><tr><th>Severity</th><th>CVE ID</th><th>CVSS</th><th>Flags</th><th>Description</th><th>Product</th></tr></thead>
            <tbody>{cve_rows}</tbody></table>
          </div>
        </div>"""

    # ── Web Vulnerabilities ───────────────────────────────────────────────────
    vuln_sections = [
        ("xss",      "🎭", "XSS Scanner"),
        ("sqli",     "💉", "SQL Injection"),
        ("lfi",      "📁", "LFI / Path Traversal"),
        ("ssrf",     "🌐", "SSRF"),
        ("xxe",      "📦", "XXE"),
        ("ssti",     "🧨", "SSTI"),
        ("idor",     "🔓", "IDOR"),
        ("redirect", "↪",  "Open Redirect"),
    ]
    for key, icon, title in vuln_sections:
        vdata = data.get(key, {})
        findings = vdata.get("findings", [])
        if not findings:
            continue
        rows = ""
        for f in findings[:20]:
            sev   = f.get("severity","MEDIUM")
            sc    = {"CRITICAL":"red","HIGH":"orange","MEDIUM":"yellow","LOW":"green"}.get(sev,"blue")
            ftype = f.get("type", key.upper())
            url   = (f.get("url") or "")[:70]
            param = f.get("param","")
            payload = (f.get("payload") or "")[:50]
            rows += f"""
            <tr>
              <td><span class="badge {sc}">{sev}</span></td>
              <td class="dim">{ftype}</td>
              <td class="mono dim">{url}</td>
              <td class="mono">{param}</td>
              <td class="mono dim red">{payload}</td>
            </tr>"""
        sections += f"""
        <div class="section" id="{key}">
          <div class="section-header"><span class="icon">{icon}</span>{title}
            <span class="count">{len(findings)} found</span>
          </div>
          <div class="section-body">
            <table><thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Param</th><th>Payload</th></tr></thead>
            <tbody>{rows}</tbody></table>
          </div>
        </div>"""

    # ── SSL ───────────────────────────────────────────────────────────────────
    ssl = data.get("ssl", {})
    if ssl:
        grade = ssl.get("grade","N/A")
        gc    = {"A+":"green","A":"green","B":"yellow","C":"orange","D":"orange","F":"red","T":"red"}.get(grade,"blue")
        cert  = ssl.get("cert_info", {})
        vulns = ssl.get("vulnerabilities", {})
        vuln_rows = ""
        for vname, is_vuln in vulns.items():
            vc = "red" if is_vuln else "green"
            icon_v = "✗ VULNERABLE" if is_vuln else "✓ Safe"
            vuln_rows += f"<tr><td>{vname}</td><td><span class='badge {vc}'>{icon_v}</span></td></tr>"
        sections += f"""
        <div class="section" id="ssl">
          <div class="section-header"><span class="icon">🔒</span>SSL/TLS Analysis
            <span class="count">Grade: <span class="badge {gc}">{grade}</span></span>
          </div>
          <div class="section-body">
            <div class="grid2">
              <div>
                <h4>Certificate</h4>
                <table>
                  <tr><td>CN</td><td class="mono">{_safe(cert.get("subject",{}).get("commonName"))}</td></tr>
                  <tr><td>Issuer</td><td>{_safe(cert.get("issuer",{}).get("organizationName"))}</td></tr>
                  <tr><td>Valid To</td><td>{_safe(cert.get("valid_to"))}</td></tr>
                  <tr><td>Days Left</td><td>{_safe(cert.get("days_remaining"))}</td></tr>
                  <tr><td>Self-Signed</td><td>{"⚠️ YES" if cert.get("is_self_signed") else "✅ No"}</td></tr>
                  <tr><td>Expired</td><td>{"⚠️ YES" if cert.get("is_expired") else "✅ No"}</td></tr>
                </table>
              </div>
              <div>
                <h4>Vulnerabilities</h4>
                <table><tbody>{vuln_rows}</tbody></table>
              </div>
            </div>
          </div>
        </div>"""

    # ── Email Harvest ─────────────────────────────────────────────────────────
    email = data.get("email", {})
    if email and email.get("all_emails"):
        email_rows = ""
        for e in email.get("all_emails", [])[:50]:
            email_rows += f"<tr><td class='mono'>{e}</td></tr>"
        sections += f"""
        <div class="section" id="emails">
          <div class="section-header"><span class="icon">📧</span>Email Harvesting
            <span class="count">{len(email.get("all_emails",[]))} emails</span>
          </div>
          <div class="section-body">
            <table><thead><tr><th>Email Address</th></tr></thead>
            <tbody>{email_rows}</tbody></table>
          </div>
        </div>"""

    # ── Cloud Buckets ─────────────────────────────────────────────────────────
    cloud = data.get("cloud", {})
    if cloud and cloud.get("found"):
        cloud_rows = ""
        for b in cloud.get("found", []):
            ac = "red" if b.get("access") == "PUBLIC_READ" else "yellow"
            cloud_rows += f"""
            <tr>
              <td class="mono">{b.get("bucket","")}</td>
              <td>{b.get("provider","")}</td>
              <td><span class="badge {ac}">{b.get("access","")}</span></td>
              <td>{b.get("file_count",0)}</td>
              <td class="dim">{", ".join(b.get("sensitive",[])[:3])}</td>
            </tr>"""
        sections += f"""
        <div class="section" id="cloud">
          <div class="section-header"><span class="icon">☁</span>Cloud Bucket Finder
            <span class="count">{len(cloud.get("found",[]))} buckets</span>
          </div>
          <div class="section-body">
            <table><thead><tr><th>Bucket</th><th>Provider</th><th>Access</th><th>Files</th><th>Sensitive</th></tr></thead>
            <tbody>{cloud_rows}</tbody></table>
          </div>
        </div>"""

    # ── JS Secrets ────────────────────────────────────────────────────────────
    js = data.get("js", {})
    if js and js.get("secrets"):
        js_rows = ""
        for s in js.get("secrets", [])[:30]:
            sc = {"CRITICAL":"red","HIGH":"orange","MEDIUM":"yellow","LOW":"green"}.get(s.get("severity",""),"blue")
            js_rows += f"""
            <tr>
              <td><span class="badge {sc}">{s.get("severity","")}</span></td>
              <td>{s.get("type","")}</td>
              <td class="mono red">{(s.get("value") or "")[:60]}</td>
              <td>Line {s.get("line","")}</td>
            </tr>"""
        sections += f"""
        <div class="section" id="js">
          <div class="section-header"><span class="icon">🔑</span>JS File Analyzer
            <span class="count">{len(js.get("secrets",[]))} secrets | {len(js.get("endpoints",[]))} endpoints</span>
          </div>
          <div class="section-body">
            <table><thead><tr><th>Severity</th><th>Type</th><th>Value</th><th>Location</th></tr></thead>
            <tbody>{js_rows}</tbody></table>
          </div>
        </div>"""

    # ── AI Analysis ───────────────────────────────────────────────────────────
    ai = data.get("ai", {})
    if ai:
        score = ai.get("risk_score", 0)
        level = ai.get("risk_level", "—")
        lc    = {"CRITICAL":"red","HIGH":"orange","MEDIUM":"yellow","LOW":"green"}.get(level,"blue")
        bar   = int(score / 5)
        bar_html = f'<div class="risk-bar"><div class="risk-fill" style="width:{score}%;background:var(--{lc})"></div></div>'

        factor_rows = ""
        for k, v in (ai.get("factors") or {}).items():
            factor_rows += f"<tr><td>{k}</td><td class='red'>{v}</td></tr>"

        path_html = ""
        for i, path in enumerate((ai.get("attack_paths") or [])[:3], 1):
            steps = "".join(f"<li>{s}</li>" for s in path.get("steps",[]))
            path_html += f"<div class='attack-path'><h4>{i}. {path.get('name','')}</h4><ol>{steps}</ol></div>"

        remed_html = ""
        for r in (ai.get("remediations") or []):
            rc2 = {"CRITICAL":"red","HIGH":"orange","MEDIUM":"yellow","LOW":"green"}.get(r.get("severity",""),"blue")
            remed_html += f"""
            <div class="remed-item">
              <span class="badge {rc2}">{r.get("severity","")}</span>
              <strong>{r.get("title","")}</strong>
              <p class="dim">{r.get("detail","")}</p>
            </div>"""

        sections += f"""
        <div class="section" id="ai">
          <div class="section-header"><span class="icon">🤖</span>AI Vulnerability Analyzer</div>
          <div class="section-body">
            <div class="risk-score-box">
              <div class="risk-number" style="color:var(--{lc})">{score}</div>
              <div class="risk-label">/ 100 — <span style="color:var(--{lc})">{level}</span></div>
              {bar_html}
            </div>
            <div class="grid2">
              <div><h4>Risk Factors</h4><table><tbody>{factor_rows}</tbody></table></div>
              <div><h4>Remediation</h4>{remed_html}</div>
            </div>
            <h4>Attack Paths</h4>{path_html}
          </div>
        </div>"""

    # ── Exploit Suggester ─────────────────────────────────────────────────────
    exp = data.get("exploits", {})
    if exp and exp.get("exploits"):
        exp_rows = ""
        for e in exp.get("exploits", [])[:30]:
            dc = {"EASY":"green","MEDIUM":"yellow","HARD":"red"}.get(e.get("difficulty",""),"blue")
            msf = e.get("msf","")
            poc = e.get("poc","")
            exp_rows += f"""
            <tr>
              <td class="mono">{e.get("cve","") or e.get("port","") or e.get("technology","")}</td>
              <td><b>{e.get("name","")}</b></td>
              <td><span class="badge {dc}">{e.get("difficulty","")}</span></td>
              <td class="orange">{e.get("impact","")}</td>
              <td class="dim mono">{msf[:50]}</td>
            </tr>"""
        sections += f"""
        <div class="section" id="exploits">
          <div class="section-header"><span class="icon">💣</span>Exploit Suggester
            <span class="count">{exp.get("total",0)} exploits | {len(exp.get("easy",[]))} easy wins</span>
          </div>
          <div class="section-body">
            <table><thead><tr><th>Source</th><th>Name</th><th>Difficulty</th><th>Impact</th><th>MSF Module</th></tr></thead>
            <tbody>{exp_rows}</tbody></table>
          </div>
        </div>"""

    return sections


def save_html(data: Dict, target: str, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"recon_{_slug(target)}_{ts}.html")
    s        = _extract_summary(data)
    sections = _build_sections(data)

    # Risk score color
    rs = s["risk_score"]
    rc = "var(--red)" if rs >= 75 else ("var(--orange)" if rs >= 50 else ("var(--yellow)" if rs >= 25 else "var(--green)"))

    # Nav items
    nav_map = {
        "subdomain": "Subdomains", "ports": "Ports", "whois": "WHOIS",
        "cves": "CVEs", "ssl": "SSL", "emails": "Emails",
        "xss": "XSS", "sqli": "SQLi", "lfi": "LFI", "ssrf": "SSRF",
        "xxe": "XXE", "ssti": "SSTI", "idor": "IDOR", "redirect": "Redirect",
        "cloud": "Cloud", "js": "JS Secrets", "ai": "AI Analysis",
        "exploits": "Exploits",
    }
    nav_html = ""
    for key, label in nav_map.items():
        if data.get(key) or data.get(key.replace("s","")) :
            nav_html += f'<a href="#{key}">{label}</a>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon Report — {s["target"]}</title>
<style>
:root {{
  --bg:      #0d1117;
  --bg2:     #161b22;
  --bg3:     #1f2937;
  --border:  #30363d;
  --text:    #e6edf3;
  --dim:     #8b949e;
  --red:     #f85149;
  --orange:  #d29922;
  --yellow:  #e3b341;
  --green:   #3fb950;
  --blue:    #58a6ff;
  --cyan:    #39d0d8;
  --purple:  #bc8cff;
}}
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; font-size:14px; }}

/* Header */
.header {{ background:linear-gradient(135deg,#0d1117,#1a2035); border-bottom:2px solid var(--blue); padding:28px 32px; }}
.header-top {{ display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px; }}
.logo {{ font-size:22px; font-weight:700; color:var(--blue); letter-spacing:1px; }}
.logo span {{ color:var(--red); }}
.target-badge {{ background:var(--bg3); border:1px solid var(--border); border-radius:6px; padding:6px 14px; font-family:monospace; font-size:13px; color:var(--cyan); }}
.meta {{ margin-top:12px; color:var(--dim); font-size:12px; }}

/* Risk Score */
.risk-hero {{ background:var(--bg2); border:1px solid var(--border); border-radius:10px; padding:20px 28px; margin:20px 32px 0; display:flex; align-items:center; gap:32px; flex-wrap:wrap; }}
.risk-circle {{ width:80px; height:80px; border-radius:50%; border:3px solid {rc}; display:flex; flex-direction:column; align-items:center; justify-content:center; }}
.risk-circle .num {{ font-size:26px; font-weight:700; color:{rc}; line-height:1; }}
.risk-circle .lbl {{ font-size:10px; color:var(--dim); }}
.risk-level {{ font-size:18px; font-weight:700; color:{rc}; }}
.stat-grid {{ display:flex; gap:20px; flex-wrap:wrap; margin-left:auto; }}
.stat {{ text-align:center; background:var(--bg3); border-radius:8px; padding:10px 16px; min-width:80px; }}
.stat-num {{ font-size:22px; font-weight:700; }}
.stat-lbl {{ font-size:11px; color:var(--dim); margin-top:2px; }}
.red {{ color:var(--red) !important; }}
.orange {{ color:var(--orange) !important; }}
.yellow {{ color:var(--yellow) !important; }}
.green {{ color:var(--green) !important; }}
.blue {{ color:var(--blue) !important; }}
.cyan {{ color:var(--cyan) !important; }}

/* Nav */
.nav {{ background:var(--bg2); border-bottom:1px solid var(--border); padding:10px 32px; display:flex; gap:4px; flex-wrap:wrap; position:sticky; top:0; z-index:100; }}
.nav a {{ color:var(--dim); text-decoration:none; padding:5px 12px; border-radius:5px; font-size:12px; transition:all .2s; }}
.nav a:hover {{ background:var(--bg3); color:var(--text); }}

/* Content */
.container {{ max-width:1400px; margin:0 auto; padding:24px 32px; }}

/* Sections */
.section {{ background:var(--bg2); border:1px solid var(--border); border-radius:10px; margin-bottom:20px; overflow:hidden; }}
.section-header {{ background:var(--bg3); padding:12px 20px; font-size:14px; font-weight:600; display:flex; align-items:center; gap:10px; border-bottom:1px solid var(--border); }}
.icon {{ font-size:16px; }}
.count {{ margin-left:auto; font-size:12px; color:var(--dim); font-weight:400; background:var(--bg); padding:3px 10px; border-radius:12px; }}
.section-body {{ padding:16px 20px; overflow-x:auto; }}

/* Table */
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ text-align:left; padding:8px 12px; color:var(--dim); font-weight:600; border-bottom:1px solid var(--border); font-size:12px; text-transform:uppercase; }}
td {{ padding:7px 12px; border-bottom:1px solid rgba(48,54,61,.5); vertical-align:middle; }}
tr:last-child td {{ border-bottom:none; }}
tr:hover td {{ background:rgba(255,255,255,.02); }}
.mono {{ font-family:monospace; }}
.dim {{ color:var(--dim); }}

/* Badges */
.badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; text-transform:uppercase; }}
.badge.red    {{ background:rgba(248,81,73,.2);  color:var(--red);    border:1px solid rgba(248,81,73,.3); }}
.badge.orange {{ background:rgba(210,153,34,.2); color:var(--orange); border:1px solid rgba(210,153,34,.3); }}
.badge.yellow {{ background:rgba(227,179,65,.2); color:var(--yellow); border:1px solid rgba(227,179,65,.3); }}
.badge.green  {{ background:rgba(63,185,80,.2);  color:var(--green);  border:1px solid rgba(63,185,80,.3); }}
.badge.blue   {{ background:rgba(88,166,255,.2); color:var(--blue);   border:1px solid rgba(88,166,255,.3); }}

/* Grid */
.grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
h4 {{ color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.8px; margin:12px 0 8px; }}

/* Risk Bar */
.risk-bar {{ background:var(--bg3); border-radius:4px; height:8px; overflow:hidden; margin-top:8px; width:200px; }}
.risk-fill {{ height:100%; border-radius:4px; transition:width .5s; }}
.risk-score-box {{ text-align:center; padding:20px; background:var(--bg3); border-radius:8px; margin-bottom:20px; display:inline-block; min-width:200px; }}
.risk-number {{ font-size:48px; font-weight:800; line-height:1; }}
.risk-label {{ font-size:16px; margin:4px 0 8px; }}

/* Attack paths */
.attack-path {{ background:var(--bg3); border-radius:8px; padding:14px 18px; margin-bottom:12px; border-left:3px solid var(--red); }}
.attack-path h4 {{ color:var(--red); margin:0 0 8px; font-size:13px; text-transform:none; letter-spacing:0; }}
.attack-path ol {{ padding-left:18px; }}
.attack-path li {{ color:var(--dim); font-size:12px; margin-bottom:4px; }}

/* Remediation */
.remed-item {{ background:var(--bg3); border-radius:6px; padding:10px 14px; margin-bottom:8px; }}
.remed-item strong {{ display:block; margin:4px 0; }}
.remed-item p {{ font-size:12px; color:var(--dim); }}

/* Footer */
footer {{ text-align:center; padding:24px; color:var(--dim); font-size:12px; border-top:1px solid var(--border); margin-top:20px; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="logo">RECON<span>TOOLKIT</span> PRO <span style="font-size:14px;color:var(--dim)">v3.2 Ultra</span></div>
    <div class="target-badge">🎯 {s["target"]}</div>
  </div>
  <div class="meta">
    Generated: {s["started"]} &nbsp;|&nbsp; Elapsed: {s["elapsed"]} &nbsp;|&nbsp;
    Modules run: {sum(1 for k in data if not k.startswith("_"))} &nbsp;|&nbsp;
    For authorized security testing only
  </div>
</div>

<div class="risk-hero">
  <div class="risk-circle">
    <span class="num">{s["risk_score"]}</span>
    <span class="lbl">RISK</span>
  </div>
  <div>
    <div class="risk-level">{s["risk_level"]}</div>
    <div style="color:var(--dim);font-size:12px;margin-top:4px">Overall Risk Score</div>
  </div>
  <div class="stat-grid">
    <div class="stat"><div class="stat-num red">{s["subdomains"]}</div><div class="stat-lbl">Subdomains</div></div>
    <div class="stat"><div class="stat-num orange">{s["open_ports"]}</div><div class="stat-lbl">Open Ports</div></div>
    <div class="stat"><div class="stat-num red">{s["total_cves"]}</div><div class="stat-lbl">CVEs</div></div>
    <div class="stat"><div class="stat-num red">{s["kev_count"]}</div><div class="stat-lbl">KEV</div></div>
    <div class="stat"><div class="stat-num orange">{s["emails"]}</div><div class="stat-lbl">Emails</div></div>
    <div class="stat"><div class="stat-num {'red' if s['ssl_grade'] in ('F','T') else 'green'}">{s["ssl_grade"]}</div><div class="stat-lbl">SSL Grade</div></div>
    <div class="stat"><div class="stat-num red">{s["xss"]+s["sqli"]+s["lfi"]+s["ssrf"]+s["xxe"]+s["ssti"]}</div><div class="stat-lbl">Web Vulns</div></div>
    <div class="stat"><div class="stat-num orange">{s["exploit_count"]}</div><div class="stat-lbl">Exploits</div></div>
  </div>
</div>

<nav class="nav">{nav_html}</nav>

<div class="container">
  {sections}
</div>

<footer>
  Generated by Recon Toolkit Pro v3.2 Ultra &nbsp;|&nbsp;
  Target: {s["target"]} &nbsp;|&nbsp;
  {s["started"]} &nbsp;|&nbsp;
  For authorized penetration testing only
</footer>

</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename


def save_all(data: Dict, target: str, output_dir: str = "reports"):
    from ui.rich_ui import console, success
    os.makedirs(output_dir, exist_ok=True)
    path = save_html(data, target, output_dir)
    success(f"HTML Report: {path}")
    console.print(f"  [dim]Open in browser: {path}[/dim]")
    return {"html": path}
