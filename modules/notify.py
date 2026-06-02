"""
notify.py — Ultra Notification System
Features: Discord webhook, Slack webhook, Email (SMTP),
          desktop notifications, sound alerts, scan complete alerts
"""

import json
import os
import platform
import smtplib
import socket
import subprocess
import threading
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional

import requests

from ui.rich_ui import info, warning, success, error

SEVERITY_COLORS = {
    "CRITICAL": 0xFF0000,   # Red
    "HIGH":     0xFF6600,   # Orange
    "MEDIUM":   0xFFCC00,   # Yellow
    "LOW":      0x00CC44,   # Green
    "INFO":     0x0099FF,   # Blue
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}


# ── Discord ───────────────────────────────────────────────────────────────────

def notify_discord(webhook_url: str, title: str, description: str,
                   fields: List[Dict] = None,
                   color: int = 0x58A6FF,
                   severity: str = "INFO") -> bool:
    if not webhook_url:
        return False

    color = SEVERITY_COLORS.get(severity, color)
    emoji = SEVERITY_EMOJI.get(severity, "🔵")

    embed = {
        "title":       f"{emoji} {title}",
        "description": description[:2000],
        "color":       color,
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "footer":      {"text": "Recon Toolkit Pro v3.2 Ultra"},
        "fields":      [],
    }

    if fields:
        for f in fields[:25]:
            embed["fields"].append({
                "name":   str(f.get("name", ""))[:256],
                "value":  str(f.get("value", ""))[:1024],
                "inline": f.get("inline", True),
            })

    payload = {
        "username":   "Recon Toolkit Pro",
        "avatar_url": "https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/hackthebox.svg",
        "embeds":     [embed],
    }

    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        if r.status_code in (200, 204):
            success("Discord notification sent")
            return True
        else:
            warning(f"Discord webhook failed: {r.status_code}")
    except Exception as e:
        warning(f"Discord error: {e}")
    return False


def notify_discord_finding(webhook_url: str, finding: Dict, target: str):
    """Send a specific finding to Discord."""
    if not webhook_url:
        return

    sev  = finding.get("severity", "INFO").upper()
    ftype = finding.get("type", "Finding")
    url  = finding.get("url", "")
    payload_str = finding.get("payload", "")[:200]

    fields = [
        {"name": "Target",   "value": f"`{target}`",       "inline": True},
        {"name": "Type",     "value": ftype,                "inline": True},
        {"name": "Severity", "value": sev,                  "inline": True},
    ]
    if url:
        fields.append({"name": "URL", "value": f"`{url[:200]}`", "inline": False})
    if payload_str:
        fields.append({"name": "Payload", "value": f"```{payload_str}```", "inline": False})

    notify_discord(
        webhook_url,
        title=f"Vulnerability Found — {ftype}",
        description=finding.get("description", f"A {sev} severity issue was detected"),
        fields=fields,
        severity=sev,
    )


# ── Slack ─────────────────────────────────────────────────────────────────────

def notify_slack(webhook_url: str, title: str, message: str,
                 severity: str = "INFO") -> bool:
    if not webhook_url:
        return False

    emoji = SEVERITY_EMOJI.get(severity, "🔵")
    color_map = {"CRITICAL": "danger", "HIGH": "warning",
                 "MEDIUM": "warning", "LOW": "good", "INFO": "#0099FF"}
    color = color_map.get(severity, "#0099FF")

    payload = {
        "attachments": [{
            "color":      color,
            "title":      f"{emoji} {title}",
            "text":       message[:3000],
            "footer":     "Recon Toolkit Pro v3.2 Ultra",
            "ts":         int(time.time()),
            "mrkdwn_in":  ["text"],
        }]
    }

    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        if r.status_code == 200:
            success("Slack notification sent")
            return True
    except Exception as e:
        warning(f"Slack error: {e}")
    return False


# ── Email ─────────────────────────────────────────────────────────────────────

def notify_email(smtp_host: str, smtp_port: int, smtp_user: str,
                 smtp_pass: str, to_email: str,
                 subject: str, body_html: str) -> bool:
    if not all([smtp_host, smtp_user, smtp_pass, to_email]):
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = smtp_user
        msg["To"]      = to_email
        msg.attach(MIMEText(body_html, "html"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(smtp_user, smtp_pass)
            srv.sendmail(smtp_user, to_email, msg.as_string())

        success(f"Email sent to {to_email}")
        return True
    except Exception as e:
        warning(f"Email error: {e}")
        return False


# ── Desktop notification ──────────────────────────────────────────────────────

def notify_desktop(title: str, message: str, urgency: str = "normal"):
    """Send desktop notification (Linux/Mac/Windows)."""
    system = platform.system().lower()
    try:
        if system == "linux":
            subprocess.run([
                "notify-send",
                f"--urgency={urgency}",
                "--app-name=Recon Toolkit Pro",
                title, message[:200]
            ], capture_output=True, timeout=5)
        elif system == "darwin":
            script = f'display notification "{message[:200]}" with title "{title}"'
            subprocess.run(["osascript", "-e", script],
                          capture_output=True, timeout=5)
        elif system == "windows":
            # Windows toast via PowerShell
            ps_cmd = f"""
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
            $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
            $xml.GetElementsByTagName('text')[0].AppendChild($xml.CreateTextNode('{title}')) | Out-Null
            $xml.GetElementsByTagName('text')[1].AppendChild($xml.CreateTextNode('{message[:100]}')) | Out-Null
            $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Recon Toolkit Pro').Show($toast)
            """
            subprocess.run(["powershell", "-Command", ps_cmd],
                          capture_output=True, timeout=10)
    except Exception:
        pass


# ── Sound alert ───────────────────────────────────────────────────────────────

def play_alert(alert_type: str = "success"):
    """Play system sound alert."""
    system = platform.system().lower()
    try:
        if system == "linux":
            if alert_type == "critical":
                subprocess.run(["paplay", "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"],
                              capture_output=True, timeout=3)
            else:
                subprocess.run(["paplay", "/usr/share/sounds/freedesktop/stereo/complete.oga"],
                              capture_output=True, timeout=3)
        elif system == "darwin":
            subprocess.run(["afplay", "/System/Library/Sounds/Ping.aiff"],
                          capture_output=True, timeout=3)
        elif system == "windows":
            import winsound
            freq = 880 if alert_type == "critical" else 440
            winsound.Beep(freq, 500)
    except Exception:
        # ASCII bell fallback
        print("\a", end="", flush=True)


# ── Main notification dispatcher ──────────────────────────────────────────────

class NotificationManager:
    def __init__(self):
        from modules.config import get
        self.discord  = get("notifications", "discord_webhook", "")
        self.slack    = get("notifications", "slack_webhook", "")
        self.enabled  = get("notifications", "enabled", False)
        self.email_cfg = {
            "host": get("notifications", "smtp_host", ""),
            "port": get("notifications", "smtp_port", 587),
            "user": get("notifications", "smtp_user", ""),
            "pass": get("notifications", "smtp_pass", ""),
            "to":   get("notifications", "email", ""),
        }

    def scan_started(self, target: str):
        if not self.enabled:
            return
        msg = f"Scan started on **{target}**"
        threading.Thread(target=self._send_all,
                        args=("🚀 Scan Started", msg, "INFO"),
                        daemon=True).start()

    def scan_complete(self, target: str, summary: Dict):
        msg = (f"Scan of **{target}** complete!\n"
               f"• Open Ports: {summary.get('open_ports',0)}\n"
               f"• CVEs: {summary.get('total_cves',0)}\n"
               f"• Web Vulns: {summary.get('web_vulns',0)}\n"
               f"• Risk Score: {summary.get('risk_score',0)}/100")

        sev = summary.get("risk_level", "INFO")
        threading.Thread(target=self._send_all,
                        args=("✅ Scan Complete", msg, sev),
                        daemon=True).start()
        notify_desktop("Recon Toolkit Pro", f"Scan complete: {target}", "normal")
        play_alert("success")

    def critical_finding(self, target: str, finding: Dict):
        if not self.enabled:
            return
        sev = finding.get("severity", "INFO").upper()
        if sev in ("CRITICAL", "HIGH"):
            if self.discord:
                threading.Thread(
                    target=notify_discord_finding,
                    args=(self.discord, finding, target),
                    daemon=True
                ).start()
            notify_desktop(
                f"[{sev}] {finding.get('type','')}",
                f"{finding.get('url','')[:100]}",
                "critical" if sev == "CRITICAL" else "normal"
            )
            if sev == "CRITICAL":
                play_alert("critical")

    def _send_all(self, title: str, message: str, severity: str):
        if self.discord:
            notify_discord(self.discord, title, message, severity=severity)
        if self.slack:
            notify_slack(self.slack, title, message, severity=severity)


# Global instance
_notifier: Optional[NotificationManager] = None

def get_notifier() -> NotificationManager:
    global _notifier
    if _notifier is None:
        _notifier = NotificationManager()
    return _notifier
