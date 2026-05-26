"""
cloud_enum.py — Ultra Cloud Bucket Finder
Features: AWS S3, Azure Blob, GCP Storage, Firebase, DigitalOcean Spaces,
          Alibaba OSS, Backblaze B2, MinIO detection, permission testing,
          bucket enumeration, content listing, sensitive file detection
"""

import itertools
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

import requests
import urllib3
urllib3.disable_warnings()

from ui.rich_ui import (
    console, info, warning, error, found, success, section_header, print_summary
)

TIMEOUT = 8

# ── Bucket name mutations ─────────────────────────────────────────────────────
MUTATIONS = [
    "", "-dev", "-development", "-staging", "-stage", "-stg", "-prod",
    "-production", "-test", "-testing", "-beta", "-alpha", "-demo",
    "-backup", "-backups", "-bak", "-old", "-archive", "-data",
    "-assets", "-static", "-media", "-images", "-img", "-files",
    "-uploads", "-upload", "-downloads", "-download", "-cdn",
    "-public", "-private", "-internal", "-external",
    "-api", "-app", "-web", "-site", "-www",
    "-logs", "-log", "-reports", "-report", "-analytics",
    "-config", "-configs", "-secrets", "-secret",
    "-db", "-database", "-sql", "-mongo",
    "-admin", "-administrator", "-management",
    "-uat", "-qa", "-sandbox", "-temp",
    "-2024", "-2025", "-2026",
    "dev", "staging", "prod", "test", "backup",
    "assets", "static", "media", "files", "data",
]

PREFIXES = ["", "www-", "dev-", "staging-", "prod-", "api-", "cdn-",
            "assets-", "static-", "media-", "backup-", "data-"]

# ── Cloud provider configurations ─────────────────────────────────────────────
CLOUD_PROVIDERS = {
    "AWS S3": {
        "urls": [
            "https://{bucket}.s3.amazonaws.com",
            "https://s3.amazonaws.com/{bucket}",
            "https://{bucket}.s3-website.us-east-1.amazonaws.com",
            "https://{bucket}.s3-website-us-east-1.amazonaws.com",
            "https://{bucket}.s3.us-west-2.amazonaws.com",
            "https://{bucket}.s3.eu-west-1.amazonaws.com",
            "https://{bucket}.s3.ap-southeast-1.amazonaws.com",
        ],
        "error_bodies": ["NoSuchBucket", "InvalidBucketName"],
        "public_body":  ["ListBucketResult", "<Contents>", "<Key>"],
        "forbidden_body": ["AccessDenied", "AllAccessDisabled"],
        "regions": ["us-east-1","us-east-2","us-west-1","us-west-2",
                    "eu-west-1","eu-west-2","eu-central-1",
                    "ap-southeast-1","ap-northeast-1","ap-south-1"],
    },
    "Azure Blob": {
        "urls": [
            "https://{bucket}.blob.core.windows.net",
            "https://{bucket}.blob.core.windows.net/?restype=container&comp=list",
        ],
        "error_bodies": ["The specified resource does not exist", "BlobNotFound"],
        "public_body":  ["EnumerationResults", "<Blob>", "<Name>"],
        "forbidden_body": ["AuthorizationFailure", "PublicAccessNotPermitted"],
    },
    "GCP Storage": {
        "urls": [
            "https://storage.googleapis.com/{bucket}",
            "https://{bucket}.storage.googleapis.com",
        ],
        "error_bodies": ["NoSuchBucket", "The specified bucket does not exist"],
        "public_body":  ["ListBucketResult", "<Contents>", "items"],
        "forbidden_body": ["AccessDenied", "Forbidden"],
    },
    "Firebase": {
        "urls": [
            "https://{bucket}.firebaseio.com/.json",
            "https://{bucket}-default-rtdb.firebaseio.com/.json",
        ],
        "error_bodies": ["Permission denied", "Could not parse auth token"],
        "public_body":  ["{", "[", "null"],
        "forbidden_body": ["Permission denied"],
    },
    "DigitalOcean Spaces": {
        "urls": [
            "https://{bucket}.nyc3.digitaloceanspaces.com",
            "https://{bucket}.sfo2.digitaloceanspaces.com",
            "https://{bucket}.ams3.digitaloceanspaces.com",
            "https://{bucket}.sgp1.digitaloceanspaces.com",
        ],
        "error_bodies": ["NoSuchBucket"],
        "public_body":  ["ListBucketResult", "<Contents>"],
        "forbidden_body": ["AccessDenied"],
    },
    "Alibaba OSS": {
        "urls": [
            "https://{bucket}.oss-cn-hangzhou.aliyuncs.com",
            "https://{bucket}.oss-cn-shanghai.aliyuncs.com",
            "https://{bucket}.oss-us-west-1.aliyuncs.com",
        ],
        "error_bodies": ["NoSuchBucket"],
        "public_body":  ["ListBucketResult"],
        "forbidden_body": ["AccessDenied"],
    },
    "Backblaze B2": {
        "urls": [
            "https://f001.backblazeb2.com/file/{bucket}/",
            "https://{bucket}.s3.us-west-004.backblazeb2.com",
        ],
        "error_bodies": ["bucket_not_found", "NoSuchBucket"],
        "public_body":  ["<Key>", "ListBucketResult"],
        "forbidden_body": ["Unauthorized", "AccessDenied"],
    },
}

SENSITIVE_FILE_PATTERNS = [
    ".env", "config", "backup", "database", "credentials", "secret",
    "password", "key", "token", "private", "id_rsa", ".pem", ".p12",
    "dump", ".sql", "shadow", "passwd", ".htpasswd",
]


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; BucketFinder/1.0)",
    })
    return s


def _generate_bucket_names(domain: str) -> List[str]:
    """Generate bucket name candidates from domain."""
    names: Set[str] = set()
    base_parts = []

    # Extract meaningful parts from domain
    clean = domain.replace("www.", "").split(".")[0]
    base_parts.append(clean)

    # Also try full domain without TLD
    parts = domain.replace("www.", "").split(".")
    if len(parts) >= 2:
        base_parts.append("-".join(parts[:-1]))
        base_parts.append(parts[0])

    for base in base_parts:
        # With mutations
        for mut in MUTATIONS:
            names.add(f"{base}{mut}")
            names.add(f"{base.replace('-', '')}{mut}")

        # With prefixes
        for prefix in PREFIXES:
            names.add(f"{prefix}{base}")

        # Common combos
        names.add(base)
        names.add(f"{base}-bucket")
        names.add(f"{base}-storage")
        names.add(f"{base}-s3")

    # Filter: S3 bucket names 3-63 chars, lowercase, alphanumeric + hyphens
    valid = set()
    for name in names:
        name = name.lower()
        if 3 <= len(name) <= 63 and re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', name):
            valid.add(name)

    return sorted(valid)


def _check_bucket(bucket: str, provider_name: str, provider: Dict) -> Optional[Dict]:
    """Check if a bucket exists and its permissions."""
    session = _session()

    for url_template in provider["urls"][:2]:  # Check first 2 URLs per provider
        url = url_template.replace("{bucket}", bucket)
        try:
            r = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            status  = r.status_code
            body    = r.text[:2000]
            headers = dict(r.headers)

            # Bucket doesn't exist
            if any(err in body for err in provider.get("error_bodies", [])):
                continue
            if status in (404, 400):
                continue

            # Determine access level
            access = "UNKNOWN"
            if any(pub in body for pub in provider.get("public_body", [])):
                access = "PUBLIC_READ"  # Bucket is open!
            elif any(fb in body for fb in provider.get("forbidden_body", [])):
                access = "EXISTS_PRIVATE"
            elif status == 200:
                access = "PUBLIC_READ"
            elif status in (403, 401):
                access = "EXISTS_PRIVATE"

            if access == "UNKNOWN":
                continue

            # Extract file listing if public
            files = []
            if access == "PUBLIC_READ":
                # AWS/GCP/DO XML listing
                for m in re.finditer(r"<Key>([^<]+)</Key>", body):
                    files.append(m.group(1))
                # Azure listing
                for m in re.finditer(r"<Name>([^<]+)</Name>", body):
                    files.append(m.group(1))
                # Firebase JSON
                if provider_name == "Firebase" and body not in ("null", ""):
                    files.append("[Firebase data exposed]")

            # Check for sensitive files
            sensitive = [f for f in files
                        if any(s in f.lower() for s in SENSITIVE_FILE_PATTERNS)]

            return {
                "bucket":    bucket,
                "provider":  provider_name,
                "url":       url,
                "status":    status,
                "access":    access,
                "files":     files[:20],
                "sensitive": sensitive,
                "file_count": len(files),
                "risk":      "CRITICAL" if access == "PUBLIC_READ" else "MEDIUM",
            }

        except Exception:
            continue

    return None


def _test_write_access(result: Dict) -> bool:
    """Test if bucket allows public write (very dangerous)."""
    if result["access"] != "PUBLIC_READ":
        return False
    try:
        r = _session().put(
            result["url"] + "/recon-test-file.txt",
            data=b"recon-test",
            timeout=5
        )
        if r.status_code in (200, 201, 204):
            # Clean up
            _session().delete(result["url"] + "/recon-test-file.txt", timeout=5)
            return True
    except Exception:
        pass
    return False


def run_cloud_enum(domain: str) -> Dict:
    section_header("Cloud Bucket Finder", "Ultra AWS S3 + Azure + GCP + Firebase + More")
    info(f"Target: {domain}")

    # Generate bucket names
    bucket_names = _generate_bucket_names(domain)
    info(f"Generated {len(bucket_names)} bucket name candidates")

    # Show sample
    console.print(f"  [dim]Sample: {', '.join(list(bucket_names)[:8])}...[/dim]")

    all_found: List[Dict] = []
    lock = threading.Lock()
    checked = [0]
    total = len(bucket_names) * len(CLOUD_PROVIDERS)

    info(f"Checking {total} combinations across {len(CLOUD_PROVIDERS)} cloud providers...")

    def _check(args: Tuple):
        bucket, provider_name = args
        provider = CLOUD_PROVIDERS[provider_name]
        result = _check_bucket(bucket, provider_name, provider)
        with lock:
            checked[0] += 1
            if result:
                all_found.append(result)
                color = "bold red" if result["access"] == "PUBLIC_READ" else "yellow"
                access_label = "🔓 PUBLIC" if result["access"] == "PUBLIC_READ" else "🔒 PRIVATE"
                found(
                    f"[{color}][{result['risk']}][/{color}]  "
                    f"{access_label}  [bold]{result['bucket']}[/bold]  "
                    f"[cyan]{result['provider']}[/cyan]  "
                    f"{result['file_count']} files"
                )

    # Create all combinations
    combinations = [
        (bucket, provider)
        for bucket in bucket_names
        for provider in CLOUD_PROVIDERS.keys()
    ]

    with ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(_check, combinations))

    # Test write access on public buckets
    public_buckets = [r for r in all_found if r["access"] == "PUBLIC_READ"]
    for bucket in public_buckets:
        info(f"Testing write access: {bucket['bucket']} ({bucket['provider']})")
        writable = _test_write_access(bucket)
        bucket["writable"] = writable
        if writable:
            error(f"  [WRITE ACCESS] {bucket['url']} — CRITICAL! Public write enabled!")

    # ── Print results ─────────────────────────────────────────────────────────
    console.print(f"\n[bold cyan]━━━ CLOUD BUCKETS FOUND ({len(all_found)}) ━━━[/bold cyan]")

    if all_found:
        for r in sorted(all_found, key=lambda x: x["risk"] == "CRITICAL", reverse=True):
            color = "bold red" if r["access"] == "PUBLIC_READ" else "yellow"
            console.print(f"\n  [{color}]▶ {r['bucket']} — {r['provider']}[/{color}]")
            console.print(f"    URL:      {r['url']}")
            console.print(f"    Access:   [{color}]{r['access']}[/{color}]")
            console.print(f"    Risk:     {r['risk']}")
            console.print(f"    Files:    {r['file_count']}")

            if r.get("writable"):
                console.print(f"    [bold red]⚠ WRITABLE — Anyone can upload files![/bold red]")

            if r["files"]:
                console.print(f"    [dim]Contents:[/dim]")
                for f in r["files"][:10]:
                    icon = "🔴" if any(s in f.lower() for s in SENSITIVE_FILE_PATTERNS) else "📄"
                    console.print(f"      {icon} {f}")

            if r["sensitive"]:
                console.print(f"    [bold red]⚠ SENSITIVE FILES:[/bold red]")
                for f in r["sensitive"]:
                    console.print(f"      [red]{f}[/red]")
    else:
        success("No exposed cloud buckets found")

    print_summary("Cloud Bucket Finder", {
        "Buckets Checked":  total,
        "Buckets Found":    len(all_found),
        "Public (Open)":    sum(1 for r in all_found if r["access"] == "PUBLIC_READ"),
        "Private (Exist)":  sum(1 for r in all_found if r["access"] == "EXISTS_PRIVATE"),
        "Writable":         sum(1 for r in all_found if r.get("writable")),
        "Sensitive Files":  sum(len(r["sensitive"]) for r in all_found),
        "Providers Checked":len(CLOUD_PROVIDERS),
    })

    return {
        "found":       all_found,
        "public":      [r for r in all_found if r["access"] == "PUBLIC_READ"],
        "private":     [r for r in all_found if r["access"] == "EXISTS_PRIVATE"],
        "bucket_names":bucket_names,
    }
