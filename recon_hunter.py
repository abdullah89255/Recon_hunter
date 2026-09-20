#!/usr/bin/env python3
"""
recon_hunter.py — Purpose-built bug bounty recon tool.

Does three things reliably:
1. Fingerprints web technologies (versions, CMS, frameworks, servers)
2. Extracts secrets + endpoints from JavaScript files
3. Probes for exposed database services

Plus: prints a manual testing roadmap based on what it finds.

Usage:
    python recon_hunter.py -u https://target.com
    python recon_hunter.py -u https://target.com --js-only
    python recon_hunter.py -u https://target.com --db-only
"""

import argparse
import json
import re
import socket
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from bs4 import BeautifulSoup

try:
    from Wappalyzer import Wappalyzer, WebPage
    HAS_WAPPALYZER = True
except ImportError:
    HAS_WAPPALYZER = False


# ============================================================
# CONFIG
# ============================================================

COMMON_DB_PORTS = {
    3306: "MySQL / MariaDB",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5984: "CouchDB",
    11211: "Memcached",
    1433: "MSSQL",
    1521: "Oracle DB",
    9042: "Cassandra",
}

# Ports that, if open to the internet, are almost always a finding
HIGH_RISK_DB_PORTS = {27017, 6379, 9200, 5984, 11211}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# JS secret patterns (curated, high-signal)
JS_SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    ("AWS Secret Key", r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "MEDIUM"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,255}", "CRITICAL"),
    ("GitLab PAT", r"glpat-[A-Za-z0-9\-_]{20}", "CRITICAL"),
    ("Slack Token", r"xox[baprs]-[0-9a-zA-Z]{10,48}", "CRITICAL"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}", "CRITICAL"),
    ("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL"),
    ("Stripe Test Key", r"sk_test_[0-9a-zA-Z]{24}", "MEDIUM"),
    ("SendGrid Key", r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "CRITICAL"),
    ("Mailgun Key", r"key-[0-9a-zA-Z]{32}", "HIGH"),
    ("Twilio SID", r"AC[a-z0-9]{32}", "MEDIUM"),
    ("Firebase URL", r"https://[a-z0-9-]+\.firebaseio\.com", "MEDIUM"),
    ("Firebase FCM", r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "HIGH"),
    ("DigitalOcean Token", r"dop_v1_[a-f0-9]{64}", "CRITICAL"),
    ("Shopify Token", r"shpat_[a-fA-F0-9]{32}", "CRITICAL"),
    ("Discord Webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "HIGH"),
    ("Telegram Bot", r"[0-9]{8,10}:[A-Za-z0-9_-]{35}", "HIGH"),
    ("Private Key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    ("JWT", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "MEDIUM"),
    ("MongoDB URI", r"mongodb(?:\+srv)?://[^\s'\"]+", "CRITICAL"),
    ("PostgreSQL URI", r"postgres(?:ql)?://[^\s'\"]+", "CRITICAL"),
    ("MySQL URI", r"mysql://[^\s'\"]+", "CRITICAL"),
    ("Redis URI", r"redis://[^\s'\"]+", "CRITICAL"),
    ("Basic Auth URL", r"https?://[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.@]+@[a-zA-Z0-9_\-\.]+", "CRITICAL"),
    ("Generic API Key", r"(?i)(api[_\-]?key|apikey)['\"\s:=]+['\"]?([a-zA-Z0-9_\-]{16,64})", "MEDIUM"),
    ("Generic Secret", r"(?i)(secret|passwd|password|pwd|token)['\"\s:=]+['\"]([a-zA-Z0-9_\-!@#$%^&*]{8,64})['\"]", "MEDIUM"),
]

# Endpoint extraction patterns
ENDPOINT_PATTERNS = [
    r"""["'](/(?:api|v\d|graphql|rest|auth|user|admin|internal|debug|config|upload|download|export|webhook)[^"'\s]{0,120})["']""",
    r"""["'](https?://[^"'\s]*(?:api|internal|staging|dev|admin)[^"'\s]*)["']""",
    r"""["'](/[a-zA-Z0-9_\-/]{3,80}\.(?:json|xml|php|asp|jsp|do))["']""",
]

COMPILED_SECRETS = [(n, re.compile(p), s) for n, p, s in JS_SECRET_PATTERNS]
COMPILED_ENDPOINTS = [re.compile(p) for p in ENDPOINT_PATTERNS]


# ============================================================
# RESULT STORAGE
# ============================================================

class Results:
    def __init__(self):
        self.technologies = {}
        self.secrets = []
        self.endpoints = set()
        self.js_files = []
        self.db_findings = []
        self.headers = {}
        self.cookies = []
        self.errors = []

    def add_secret(self, source, name, match, severity):
        self.secrets.append({
            "source": source,
            "type": name,
            "match": match[:200],
            "severity": severity,
        })

    def to_dict(self):
        return {
            "technologies": self.technologies,
            "secrets": self.secrets,
            "endpoints": sorted(self.endpoints),
            "js_files": self.js_files,
            "database_findings": self.db_findings,
            "headers": self.headers,
            "cookies": self.cookies,
            "errors": self.errors,
        }


# ============================================================
# MODULE 1: TECHNOLOGY FINGERPRINTING
# ============================================================

def fingerprint_tech(url: str, results: Results, timeout: int = 15):
    """Detect web technologies using Wappalyzer fingerprints."""
    print(f"\n[1/3] Fingerprinting technologies...")

    if not HAS_WAPPALYZER:
        print("  [!] wappalyzer-python3 not installed. Install: pip install wappalyzer-python3")
        return

    try:
        # Fetch the page first so we can reuse the content
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        results.headers = dict(resp.headers)
        results.cookies = [c.name for c in resp.cookies]

        # Build WebPage from already-fetched content
        webpage = WebPage(
            url,
            html=resp.text,
            headers=dict(resp.headers),
        )

        wappalyzer = Wappalyzer.latest()
        detected = wappalyzer.analyze_with_versions_and_categories(webpage)

        for tech, info in detected.items():
            results.technologies[tech] = {
                "versions": info.get("versions", []),
                "categories": info.get("categories", []),
            }

        print(f"  [+] Detected {len(results.technologies)} technologies:")
        for tech, info in sorted(results.technologies.items()):
            ver = f" v{', '.join(info['versions'])}" if info["versions"] else ""
            cats = ", ".join(info["categories"][:2])
            print(f"      - {tech}{ver}  [{cats}]")

    except Exception as e:
        results.errors.append(f"fingerprint: {e}")
        print(f"  [!] Fingerprinting error: {e}")


# ============================================================
# MODULE 2: JAVASCRIPT ANALYSIS
# ============================================================

def find_js_urls(base_url: str, html: str, timeout: int = 15):
    """Extract JS file URLs from HTML + try common paths."""
    js_urls = set()
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # From <script src="...">
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        full = urllib.parse.urljoin(base_url, src)
        if full.endswith(".js") or ".js?" in full:
            js_urls.add(full)

    # From inline script content — look for .js references
    for script in soup.find_all("script", src=False):
        if script.string:
            for m in re.finditer(r"""["']([^"']+\.js(?:\?[^"']*)?)["']""", script.string):
                full = urllib.parse.urljoin(base_url, m.group(1))
                js_urls.add(full)

    # Common paths
    common_js = [
        "/static/js/main.js", "/static/js/app.js", "/js/app.js",
        "/assets/js/main.js", "/dist/bundle.js", "/build.js",
        "/main.js", "/app.js", "/bundle.js",
        "/static/js/main.chunk.js", "/static/js/runtime-main.js",
    ]
    for path in common_js:
        try:
            r = requests.head(f"{base}{path}", timeout=5, verify=False,
                              headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                js_urls.add(f"{base}{path}")
        except Exception:
            pass

    return js_urls


def scan_js_content(content: str, source: str, results: Results):
    """Scan a single JS file for secrets and endpoints."""
    # Secrets
    for name, pattern, severity in COMPILED_SECRETS:
        for match in pattern.finditer(content):
            matched = match.group(0)
            # Skip obvious placeholders
            lower = matched.lower()
            if any(p in lower for p in ["your_", "example", "placeholder",
                                         "xxxx", "aaaa", "changeme",
                                         "insert_", "replace_"]):
                continue
            if len(set(matched)) < 5:
                continue
            results.add_secret(source, name, matched, severity)

    # Endpoints
    for pattern in COMPILED_ENDPOINTS:
        for match in pattern.finditer(content):
            ep = match.group(1)
            if len(ep) > 4 and not ep.startswith(("data:", "blob:")):
                results.endpoints.add(ep)


def analyze_javascript(base_url: str, html: str, results: Results,
                       timeout: int = 15, max_files: int = 50):
    """Download and analyze all JS files found on the page."""
    print(f"\n[2/3] Analyzing JavaScript files...")

    js_urls = find_js_urls(base_url, html, timeout)
    print(f"  [*] Found {len(js_urls)} JS files to analyze")

    if not js_urls:
        print("  [!] No JS files found. The page may require authentication.")
        return

    def fetch_and_scan(js_url):
        try:
            r = requests.get(
                js_url,
                headers={"User-Agent": USER_AGENT},
                timeout=timeout,
                verify=False,
            )
            if r.status_code == 200 and len(r.text) > 0:
                return js_url, r.text
        except Exception:
            pass
        return js_url, None

    scanned = 0
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_and_scan, u): u for u in list(js_urls)[:max_files]}
        for future in as_completed(futures):
            js_url, content = future.result()
            if content:
                results.js_files.append(js_url)
                scan_js_content(content, js_url, results)
                scanned += 1

    print(f"  [+] Scanned {scanned} JS files")
    if results.secrets:
        print(f"  [!!] Found {len(results.secrets)} potential secrets:")
        for s in results.secrets[:10]:
            print(f"      [{s['severity']}] {s['type']}: {s['match'][:80]}")
    if results.endpoints:
        print(f"  [+] Discovered {len(results.endpoints)} unique endpoints")


# ============================================================
# MODULE 3: DATABASE EXPOSURE CHECK
# ============================================================

def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """TCP connect check."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def probe_database(host: str, port: int, service: str) -> Optional[dict]:
    """Probe a database service for unauthenticated access."""
    finding = {
        "host": host,
        "port": port,
        "service": service,
        "severity": "HIGH" if port in HIGH_RISK_DB_PORTS else "MEDIUM",
        "evidence": "",
    }

    try:
        if port == 6379:  # Redis
            sock = socket.create_connection((host, port), timeout=5)
            sock.sendall(b"PING\r\n")
            resp = sock.recv(1024)
            sock.close()
            if b"PONG" in resp or b"+PONG" in resp:
                finding["evidence"] = "Redis responds to PING without auth"
                finding["severity"] = "CRITICAL"
                return finding

        elif port == 27017:  # MongoDB
            sock = socket.create_connection((host, port), timeout=5)
            sock.sendall(bytes.fromhex("3a0000000100000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000"))
            resp = sock.recv(1024)
            sock.close()
            if resp and len(resp) > 16:
                finding["evidence"] = "MongoDB responds to isMaster without auth"
                finding["severity"] = "CRITICAL"
                return finding

        elif port == 9200:  # Elasticsearch
            r = requests.get(f"http://{host}:{port}/", timeout=5, verify=False)
            if r.status_code == 200 and "tagline" in r.text.lower():
                finding["evidence"] = f"Elasticsearch info exposed: {r.text[:150]}"
                finding["severity"] = "CRITICAL"
                return finding

        elif port == 3306:  # MySQL
            sock = socket.create_connection((host, port), timeout=5)
            banner = sock.recv(1024)
            sock.close()
            if banner and len(banner) > 5:
                version = banner[5:].split(b"\x00")[0].decode(errors="ignore")
                finding["evidence"] = f"MySQL banner: {version}"
                return finding

        elif port == 5432:  # PostgreSQL
            sock = socket.create_connection((host, port), timeout=5)
            # Send SSLRequest
            sock.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            resp = sock.recv(1024)
            sock.close()
            if resp:
                finding["evidence"] = "PostgreSQL accepts connections"
                return finding

    except Exception:
        pass

    return None


def check_databases(host: str, results: Results):
    """Probe common database ports on the target host."""
    print(f"\n[3/3] Checking for exposed database services...")

    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_port, host, p): (p, svc)
                   for p, svc in COMMON_DB_PORTS.items()}
        for future in as_completed(futures):
            port, service = futures[future]
            if future.result():
                open_ports.append((port, service))

    if not open_ports:
        print("  [+] No common database ports open (good)")
        return

    print(f"  [!] Found {len(open_ports)} open DB ports:")
    for port, service in open_ports:
        print(f"      - {port}/tcp ({service})")
        finding = probe_database(host, port, service)
        if finding:
            results.db_findings.append(finding)
            color = "CRITICAL" if finding["severity"] == "CRITICAL" else "MEDIUM"
            print(f"        [{color}] {finding['evidence']}")


# ============================================================
# MANUAL TESTING ROADMAP
# ============================================================

def print_manual_roadmap(results: Results, url: str):
    """Print tailored next steps based on findings."""
    print(f"\n{'=' * 70}")
    print("  MANUAL TESTING ROADMAP — What to do next")
    print(f"{'=' * 70}")

    print(f"""
Your recon is done. Scanners generate candidates, not findings. Every
report you submit must be manually verified. Here is where to focus
based on what was found.
""")

    # --- Based on technologies ---
    print("┌─ 1. BASED ON DETECTED TECHNOLOGIES ─────────────────────────┐")
    tech_lower = {k.lower(): k for k in results.technologies}
    checks = []

    if any("wordpress" in t for t in tech_lower):
        checks.append(
            "WordPress detected → Enumerate users with `wpscan --url <url> --enumerate u`.\n"
            "     Check /wp-json/wp/v2/users for user enumeration. Test xmlrpc.php for brute force amplification."
        )
    if any("drupal" in t for t in tech_lower):
        checks.append(
            "Drupal detected → Check /CHANGELOG.txt for version. Cross-reference with Drupalgeddon CVEs."
        )
    if any("joomla" in t for t in tech_lower):
        checks.append(
            "Joomla detected → Check /administrator/ for admin panel. Look for configuration.php exposure."
        )
    if any(t in tech_lower for t in ["react", "vue", "angular", "next.js"]):
        checks.append(
            "SPA framework detected → The real attack surface is in the API, not the HTML.\n"
            "     Open DevTools Network tab, interact with the app, capture all API calls.\n"
            "     Test each API endpoint for IDOR, missing auth, and mass assignment."
        )
    if any("nginx" in t for t in tech_lower):
        checks.append("Nginx detected → Test for path traversal with encoded slashes (%2e%2e%2f), alias misconfig.")
    if any("apache" in t for t in tech_lower):
        checks.append("Apache detected → Check /server-status, /server-info. Test for .htaccess bypass.")
    if any("cloudflare" in t for t in tech_lower):
        checks.append(
            "Cloudflare detected → Find origin IP via Shodan/Censys. Test origin directly to bypass WAF."
        )

    if checks:
        for c in checks:
            print(f"  • {c}")
    else:
        print("  • No high-value CMS detected. Focus on the application logic instead.")

    # --- Based on secrets ---
    print("\n┌─ 2. BASED ON JS SECRETS FOUND ──────────────────────────────┐")
    if results.secrets:
        print(f"  Found {len(results.secrets)} secrets. For each one:")
        print("     • Verify it works: try the key against the actual service API")
        print("     • Determine scope: what can this key access?")
        print("     • Check if it's a test/staging key or production")
        print("     • If valid → report immediately with proof (curl output)")
        print("     • If invalid → note it, might still indicate a pattern")
    else:
        print("  • No secrets found in JS. Try:")
        print("     • Check all JS files manually at /static/js/, /assets/, /dist/")
        print("     • Look at source maps (.js.map) — they often contain original source")
        print("     • Check the mobile app's APK/IPA if in scope")

    # --- Based on endpoints ---
    print("\n┌─ 3. BASED ON DISCOVERED ENDPOINTS ──────────────────────────┐")
    if results.endpoints:
        print(f"  Found {len(results.endpoints)} endpoints. For each one:")
        print("     • Visit it without auth → does it leak data?")
        print("     • Visit it with a low-priv account → can you access admin data?")
        print("     • Change IDs in the path/params → IDOR?")
        print("     • Change HTTP method (GET → POST/PUT/DELETE) → method bypass?")
        print("     • Add ?debug=1, ?admin=true, ?test=1 → debug mode activation?")
    else:
        print("  • No endpoints extracted. Manually map the app:")
        print("     • Use Burp Suite, click every button, capture every request")
        print("     • Check /robots.txt, /sitemap.xml, /api/docs, /swagger.json")

    # --- Based on DB findings ---
    print("\n┌─ 4. BASED ON DATABASE FINDINGS ─────────────────────────────┐")
    if results.db_findings:
        print("  [!] Database services exposed! This is a high-priority finding.")
        print("     • For MongoDB: try `mongosh --host <ip> --port 27017` with no auth")
        print("     • For Redis: try `redis-cli -h <ip> -p 6379` → `INFO` → `KEYS *`")
        print("     • For Elasticsearch: visit http://<ip>:9200/_cat/indices")
        print("     • Document EVERYTHING before reporting — take screenshots")
        print("     • Do NOT dump more data than needed to prove access")
    else:
        print("  • No DB ports open directly. That's normal — databases are usually internal.")
        print("     • Instead, look for SQL injection in web parameters")
        print("     • Check for .env, .git/config, backup.sql file exposure")
        print("     • Try GraphQL introspection at /graphql, /api/graphql")

    # --- Universal manual checklist ---
    print("\n┌─ 5. UNIVERSAL MANUAL CHECKLIST ─────────────────────────────┐")
    print("""
  Regardless of automated findings, always manually test:

  [ ] Authentication
      - Password reset flow: does the token expire? Is it predictable?
      - Email change: can you change email without confirmation?
      - 2FA bypass: can you skip the 2FA step by direct navigation?
      - Session fixation: does the session ID change after login?

  [ ] Access Control (IDOR / BOLA)
      - Create two accounts. Use account A's session to access account B's objects.
      - Change every numeric/UUID identifier in every request.
      - Check horizontal (same role, different user) and vertical (user → admin) escalation.

  [ ] Business Logic
      - Negative quantities in carts, price manipulation
      - Race conditions: send the same request 20 times concurrently
      - Coupon reuse, referral abuse, unlimited free trials

  [ ] Information Disclosure
      - Error pages with stack traces (trigger 500s with malformed input)
      - /phpinfo.php, /.env, /.git/config, /backup/, /debug/
      - Response headers leaking internal IPs, paths, or versions

  [ ] API-Specific
      - Mass assignment: send extra fields in JSON bodies (role, isAdmin, balance)
      - GraphQL: introspection query, then test every mutation for auth
      - Rate limiting: is it absent on login, OTP, password reset?

  [ ] Client-Side
      - DOM XSS: check postMessage handlers, innerHTML sinks
      - CORS: test with Origin: https://evil.com and credentials
      - Clickjacking: does the app set X-Frame-Options or CSP frame-ancestors?
""")

    print(f"{'=' * 70}")
    print("  Remember: scanners find candidates. YOU verify and report findings.")
    print(f"{'=' * 70}\n")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Recon tool: tech fingerprinting + JS secrets + DB exposure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="recon_report", help="Output file prefix")
    parser.add_argument("--js-only", action="store_true", help="Only run JS analysis")
    parser.add_argument("--db-only", action="store_true", help="Only run DB check")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--no-verify", action="store_true", default=True,
                        help="Skip SSL verification (default: on)")

    args = parser.parse_args()

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.split(":")[0]

    print(f"""
╔══════════════════════════════════════════════════════════╗
║              RECON HUNTER — Bug Bounty Recon             ║
╠══════════════════════════════════════════════════════════╣
║  Target: {url:<48}║
║  Host:   {host:<48}║
╚══════════════════════════════════════════════════════════╝
""")

    results = Results()

    # Fetch the page once for reuse
    html = ""
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                            timeout=args.timeout, verify=False, allow_redirects=True)
        html = resp.text
        results.headers = dict(resp.headers)
        results.cookies = [c.name for c in resp.cookies]
        print(f"[+] Fetched page: {resp.status_code}, {len(html)} bytes")
    except Exception as e:
        print(f"[!] Could not fetch page: {e}")
        sys.exit(1)

    # Run selected modules
    if not args.js_only and not args.db_only:
        fingerprint_tech(url, results, args.timeout)
        analyze_javascript(url, html, results, args.timeout)
        check_databases(host, results)
    elif args.js_only:
        analyze_javascript(url, html, results, args.timeout)
    elif args.db_only:
        check_databases(host, results)

    # Save JSON report
    out_path = Path(f"{args.output}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_path, "w") as f:
        json.dump(results.to_dict(), f, indent=2, default=str)
    print(f"\n[+] JSON report saved: {out_path}")

    # Print manual roadmap
    print_manual_roadmap(results, url)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
