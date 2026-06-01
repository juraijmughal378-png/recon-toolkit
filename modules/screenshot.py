"""
screenshot.py — Ultra Auto Screenshot Module
Features: Headless browser screenshots, bulk URL capture,
          subdomain screenshots, visual diff, thumbnail generation,
          automatic report embedding, gowitness integration
"""

import base64
import os
import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
from urllib.parse import urljoin

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT      = 15
MAX_WORKERS  = 5
SCREENSHOT_DIR = "screenshots"


def _is_tool(name: str) -> bool:
    return shutil.which(name) is not None


def _install_gowitness() -> bool:
    """Try to install gowitness."""
    info("Trying to install gowitness...")
    try:
        if _is_tool("go"):
            result = subprocess.run(
                ["go", "install", "github.com/sensepost/gowitness@latest"],
                capture_output=True, timeout=120
            )
            if _is_tool("gowitness"):
                success("gowitness installed")
                return True
    except Exception:
        pass

    # Try direct download
    try:
        import urllib.request, platform
        system = platform.system().lower()
        arch   = "amd64"
        ext    = ".zip" if system == "windows" else ".tar.gz"
        url    = f"https://github.com/sensepost/gowitness/releases/latest/download/gowitness-{system}-{arch}{ext}"
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as f:
            urllib.request.urlretrieve(url, f.name)
            if ext == ".tar.gz":
                subprocess.run(["tar", "xzf", f.name, "-C", "/usr/local/bin/"])
            subprocess.run(["chmod", "+x", "/usr/local/bin/gowitness"])
        if _is_tool("gowitness"):
            success("gowitness installed")
            return True
    except Exception as e:
        warning(f"gowitness install failed: {e}")

    return False


def _screenshot_gowitness(urls: List[str], out_dir: str,
                           threads: int = 5) -> List[str]:
    """Use gowitness for bulk screenshots."""
    if not _is_tool("gowitness"):
        if not _install_gowitness():
            return []

    # Write URL list
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        url_file = f.name
        f.write("\n".join(urls))

    try:
        cmd = [
            "gowitness", "file",
            "-f", url_file,
            "--destination", out_dir,
            "--threads", str(threads),
            "--timeout", str(TIMEOUT),
            "--disable-logging",
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=300)
        os.unlink(url_file)

        # Return screenshot files
        return [
            os.path.join(out_dir, f)
            for f in os.listdir(out_dir)
            if f.endswith(".png")
        ]
    except Exception as e:
        warning(f"gowitness error: {e}")
        return []


def _screenshot_chromium(url: str, out_path: str) -> bool:
    """Take screenshot using chromium/chrome headless."""
    for browser in ["chromium", "chromium-browser", "google-chrome",
                    "google-chrome-stable", "chrome"]:
        if not _is_tool(browser):
            continue
        try:
            cmd = [
                browser,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                f"--screenshot={out_path}",
                "--window-size=1280,720",
                "--virtual-time-budget=5000",
                "--timeout=10000",
                url,
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=20)
            if os.path.exists(out_path):
                return True
        except Exception:
            pass

    return False


def _screenshot_selenium(url: str, out_path: str) -> bool:
    """Screenshot via selenium (fallback)."""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.support.ui import WebDriverWait

        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--window-size=1280,720")
        opts.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(15)

        try:
            driver.get(url)
            time.sleep(2)
            driver.save_screenshot(out_path)
            return os.path.exists(out_path)
        finally:
            driver.quit()
    except ImportError:
        pass
    except Exception as e:
        warning(f"Selenium error: {e}")
    return False


def _take_screenshot(url: str, out_dir: str) -> Optional[str]:
    """Take screenshot using best available method."""
    safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")[:80]
    out_path  = os.path.join(out_dir, f"{safe_name}.png")

    # Try gowitness first (best)
    if _is_tool("gowitness"):
        results = _screenshot_gowitness([url], out_dir, threads=1)
        if results:
            return results[0]

    # Try chromium
    if _screenshot_chromium(url, out_path):
        return out_path

    # Try selenium
    if _screenshot_selenium(url, out_path):
        return out_path

    return None


def _img_to_base64(path: str) -> Optional[str]:
    """Convert image to base64 for embedding in HTML."""
    try:
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception:
        return None


def run_screenshots(target: str, scan_results: Dict = None,
                    urls: List[str] = None) -> Dict:
    section_header("Auto Screenshot", "Ultra Headless Browser | Bulk Capture")
    info(f"Target: {target}")

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    # Build URL list from scan results
    if not urls:
        urls = set()

        # Main target
        for scheme in ["https", "http"]:
            urls.add(f"{scheme}://{target}")

        # From subdomains
        if scan_results:
            for sub in scan_results.get("subdomain", {}).get("subdomains", [])[:30]:
                if sub.get("alive"):
                    status = sub.get("http_status")
                    if status and status < 400:
                        for scheme in ["https", "http"]:
                            urls.add(f"{scheme}://{sub['subdomain']}")

            # From fuzzer (found paths)
            for result in scan_results.get("fuzzer", {}).get("results", [])[:20]:
                if result.get("status") == 200:
                    urls.add(result.get("url", ""))

            # From XSS/SQLi findings
            for key in ["xss", "sqli", "lfi", "ssrf"]:
                for f in scan_results.get(key, {}).get("findings", [])[:5]:
                    if f.get("url"):
                        urls.add(f["url"])

        urls = [u for u in urls if u.startswith("http")]

    info(f"Taking screenshots of {len(urls)} URLs...")

    taken: List[Dict] = []
    failed: List[str] = []
    lock = threading.Lock()

    def _capture(url: str):
        info(f"Screenshotting: {url[:60]}")
        path = _take_screenshot(url, SCREENSHOT_DIR)
        with lock:
            if path:
                b64 = _img_to_base64(path)
                taken.append({
                    "url":    url,
                    "path":   path,
                    "base64": b64,
                    "size":   os.path.getsize(path) if os.path.exists(path) else 0,
                })
                found(f"  ✓ {url[:60]}")
            else:
                failed.append(url)
                warning(f"  ✗ {url[:60]}")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        ex.map(_capture, list(urls)[:50])

    # Generate screenshot gallery HTML
    gallery_html = _generate_gallery(taken, target)
    gallery_path = os.path.join(SCREENSHOT_DIR, f"gallery_{target.replace('.','_')}.html")
    with open(gallery_path, "w") as f:
        f.write(gallery_html)
    success(f"Gallery saved: {gallery_path}")

    print_summary("Screenshots", {
        "URLs Attempted": len(list(urls)[:50]),
        "Successful":     len(taken),
        "Failed":         len(failed),
        "Gallery":        gallery_path,
    })

    return {
        "screenshots": taken,
        "failed":      failed,
        "gallery":     gallery_path,
        "total":       len(taken),
    }


def _generate_gallery(screenshots: List[Dict], target: str) -> str:
    """Generate HTML gallery of screenshots."""
    cards = ""
    for s in screenshots:
        img_src = f"data:image/png;base64,{s['base64']}" if s.get("base64") else ""
        url     = s["url"]
        fname   = os.path.basename(s.get("path", ""))
        size_kb = round(s.get("size", 0) / 1024, 1)

        cards += f"""
        <div class="card">
          <div class="card-img">
            {"<img src='" + img_src + "' loading='lazy'>" if img_src else "<div class='no-img'>No screenshot</div>"}
          </div>
          <div class="card-info">
            <a href="{url}" target="_blank" class="url">{url[:60]}</a>
            <div class="meta">{fname} | {size_kb}KB</div>
          </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Screenshots — {target}</title>
<style>
body {{ background:#0d1117; color:#e6edf3; font-family:'Segoe UI',sans-serif; margin:0; padding:20px; }}
h1 {{ color:#58a6ff; margin-bottom:20px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:16px; }}
.card {{ background:#161b22; border:1px solid #30363d; border-radius:10px; overflow:hidden; }}
.card-img {{ height:200px; overflow:hidden; background:#0d1117; display:flex; align-items:center; justify-content:center; }}
.card-img img {{ width:100%; height:200px; object-fit:cover; }}
.no-img {{ color:#8b949e; font-size:12px; }}
.card-info {{ padding:10px 14px; }}
.url {{ color:#58a6ff; text-decoration:none; font-size:12px; font-family:monospace; display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.meta {{ color:#8b949e; font-size:11px; margin-top:4px; }}
</style>
</head>
<body>
<h1>📸 Screenshot Gallery — {target}</h1>
<p style="color:#8b949e;margin-bottom:20px">{len(screenshots)} screenshots captured</p>
<div class="grid">{cards}</div>
</body>
</html>"""
