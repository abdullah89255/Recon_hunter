#!/usr/bin/env python3
"""
🔍 recon_hunter.py — Bug Bounty Recon Tool (Python 3)

Does three things reliably:
  1. 🛠️  Fingerprints web technologies (server, CMS, frameworks, WAF, analytics)
  2. 📜  Extracts secrets + endpoints from JavaScript files
  3. 🗄️  Probes for exposed database services

Plus: prints a tailored manual testing roadmap.

Usage:
    python3 recon_hunter.py -u https://target.com
    python3 recon_hunter.py -u https://target.com --js-only
    python3 recon_hunter.py -u https://target.com --db-only
"""

import argparse
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---- Version check ----
if sys.version_info < (3, 7):
    print("❌ Python 3.7+ is required.")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("❌ Missing dependency: requests")
    print("   Install with: pip3 install requests beautifulsoup4")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("❌ Missing dependency: beautifulsoup4")
    print("   Install with: pip3 install beautifulsoup4")
    sys.exit(1)

# ---- Suppress SSL warnings (many bug bounty targets have cert issues) ----
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# 🎨 TERMINAL COLORS + EMOJIS
# ============================================================

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


def log_info(msg):    print(f"{C.CYAN}ℹ️  {msg}{C.RESET}")
def log_ok(msg):      print(f"{C.GREEN}✅ {msg}{C.RESET}")
def log_warn(msg):    print(f"{C.YELLOW}⚠️  {msg}{C.RESET}")
def log_err(msg):     print(f"{C.RED}❌ {msg}{C.RESET}")
def log_critical(msg):print(f"{C.MAGENTA}{C.BOLD}🚨 {msg}{C.RESET}")
def log_arrow(msg):   print(f"{C.BLUE}➡️  {msg}{C.RESET}")


# ============================================================
# ⚙️ CONFIG
# ============================================================

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

COMMON_DB_PORTS = {
    3306:  "MySQL / MariaDB",
    5432:  "PostgreSQL",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    5984:  "CouchDB",
    11211: "Memcached",
    1433:  "MSSQL",
    1521:  "Oracle DB",
    9042:  "Cassandra",
}

HIGH_RISK_DB_PORTS = {27017, 6379, 9200, 5984, 11211}


# ============================================================
# 🛠️ TECHNOLOGY SIGNATURES (self-contained, no external DB)
# ============================================================
# Format: "Technology Name": {
#   "headers": {header: regex},
#   "cookies": [cookie_name_regex],
#   "html": [regex],
#   "script": [regex],
#   "meta": {meta_name: regex},
#   "category": "CMS|Framework|Server|CDN|Analytics|WAF|Language|Library"
# }

TECH_SIGNATURES = {
    # ---- Web Servers ----
    "Nginx":       {"headers": {"Server": r"nginx(?:/([\d.]+))?"}, "category": "Server"},
    "Apache":      {"headers": {"Server": r"Apache(?:/([\d.]+))?"}, "category": "Server"},
    "IIS":         {"headers": {"Server": r"Microsoft-IIS(?:/([\d.]+))?"}, "category": "Server"},
    "LiteSpeed":   {"headers": {"Server": r"LiteSpeed"}, "category": "Server"},
    "Caddy":       {"headers": {"Server": r"Caddy"}, "category": "Server"},

    # ---- Languages ----
    "PHP":         {"headers": {"X-Powered-By": r"PHP(?:/([\d.]+))?"}, "category": "Language"},
    "ASP.NET":     {"headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r"([\d.]+)"}, "category": "Framework"},
    "Express":     {"headers": {"X-Powered-By": r"Express"}, "category": "Framework"},
    "Node.js":     {"headers": {"X-Powered-By": r"Node"}, "category": "Language"},

    # ---- CMS ----
    "WordPress":   {
        "html": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "meta": {"generator": r"WordPress ?([\d.]+)?"},
        "category": "CMS"
    },
    "Drupal":      {
        "html": [r"Drupal\.settings", r"/sites/default/files/", r"sites/all/"],
        "meta": {"generator": r"Drupal ?([\d.]+)?"},
        "category": "CMS"
    },
    "Joomla":      {
        "html": [r"/components/com_", r"/modules/mod_", r"Joomla!"],
        "meta": {"generator": r"Joomla!? ?([\d.]+)?"},
        "category": "CMS"
    },
    "Magento":     {
        "html": [r"Mage\.Cookies", r"/skin/frontend/", r"/mage/"],
        "category": "E-commerce"
    },
    "Shopify":     {
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "headers": {"X-ShopId": r".+"},
        "category": "E-commerce"
    },
    "Ghost":       {"meta": {"generator": r"Ghost ?([\d.]+)?"}, "category": "CMS"},
    "TYPO3":       {"meta": {"generator": r"TYPO3 ?([\d.]+)?"}, "category": "CMS"},
    "PrestaShop":  {"meta": {"generator": r"PrestaShop"}, "category": "E-commerce"},

    # ---- Frontend Frameworks ----
    "React":       {"html": [r"data-reactroot", r"__REACT_DEVTOOLS", r"_reactRootContainer"], "category": "Framework"},
    "Next.js":     {"html": [r"__NEXT_DATA__", r"/_next/static/"], "headers": {"X-Powered-By": r"Next\.js"}, "category": "Framework"},
    "Vue.js":      {"html": [r"data-v-[a-f0-9]{8}", r"__vue__"], "script": [r"vue(?:\.min)?\.js"], "category": "Framework"},
    "Nuxt.js":     {"html": [r"__NUXT__", r"/_nuxt/"], "category": "Framework"},
    "Angular":     {"html": [r"ng-version=\"([\d.]+)\"", r"ng-app"], "category": "Framework"},
    "Svelte":      {"html": [r"__svelte", r"svelte-"], "category": "Framework"},
    "Ember.js":    {"html": [r"ember-view", r"data-ember-action"], "category": "Framework"},
    "Backbone.js": {"script": [r"backbone(?:\.min)?\.js"], "category": "Framework"},
    "jQuery":      {"script": [r"jquery[.-]?([\d.]+)?(?:\.min)?\.js"], "category": "Library"},
    "Bootstrap":   {"html": [r"bootstrap(?:\.min)?\.(?:css|js)"], "category": "Library"},
    "Tailwind CSS":{"html": [r"tailwind"], "category": "Library"},
    "Alpine.js":   {"script": [r"alpine(?:\.min)?\.js"], "category": "Library"},

    # ---- CDN / WAF ----
    "Cloudflare":  {"headers": {"Server": r"cloudflare", "CF-RAY": r".+"}, "category": "CDN/WAF"},
    "Akamai":      {"headers": {"Server": r"AkamaiGHost", "X-Akamai-Transformed": r".+"}, "category": "CDN/WAF"},
    "Fastly":      {"headers": {"X-Served-By": r"cache-", "X-Fastly-Request-ID": r".+"}, "category": "CDN"},
    "Sucuri":      {"headers": {"X-Sucuri-ID": r".+", "Server": r"Sucuri"}, "category": "WAF"},
    "AWS CloudFront": {"headers": {"X-Amz-Cf-Id": r".+", "Via": r".*CloudFront"}, "category": "CDN"},
    "Imperva":     {"headers": {"X-Iinfo": r".+"}, "category": "WAF"},
    "F5 BIG-IP":   {"cookies": [r"^BIGipServer", r"^TS[0-9a-f]{8}$"], "category": "Load Balancer"},
    "Varnish":     {"headers": {"X-Varnish": r".+", "Via": r".*varnish"}, "category": "Cache"},

    # ---- Analytics / Tracking ----
    "Google Analytics": {"script": [r"google-analytics\.com/analytics\.js", r"googletagmanager\.com/gtag"], "category": "Analytics"},
    "Google Tag Manager": {"script": [r"googletagmanager\.com/gtm\.js"], "category": "Analytics"},
    "Hotjar":      {"script": [r"static\.hotjar\.com"], "category": "Analytics"},
    "Segment":     {"script": [r"cdn\.segment\.com"], "category": "Analytics"},
    "Mixpanel":    {"script": [r"cdn\.mxpanel\.com", r"mixpanel\.com"], "category": "Analytics"},
    "Facebook Pixel": {"script": [r"connect\.facebook\.net.*fbevents"], "category": "Analytics"},

    # ---- JS Runtimes / Hosting ----
    "Vercel":      {"headers": {"Server": r"Vercel", "X-Vercel-Id": r".+"}, "category": "Hosting"},
    "Netlify":     {"headers": {"Server": r"Netlify", "X-Nf-Request-Id": r".+"}, "category": "Hosting"},
    "GitHub Pages":{"headers": {"Server": r"GitHub\.com"}, "category": "Hosting"},
    "Heroku":      {"headers": {"Server": r"Heroku", "Via": r".*heroku"}, "category": "Hosting"},

    # ---- Security headers presence ----
    "HSTS Enabled":   {"headers": {"Strict-Transport-Security": r".+"}, "category": "Security"},
    "CSP Enabled":    {"headers": {"Content-Security-Policy": r".+"}, "category": "Security"},
}


# ============================================================
# 🔑 SECRET PATTERNS
# ============================================================

JS_SECRET_PATTERNS = [
    ("AWS Access Key",      r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    ("AWS Secret Key",      r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
    ("Google API Key",      r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    ("Google OAuth",        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "MEDIUM"),
    ("GitHub Token",        r"gh[pousr]_[A-Za-z0-9_]{36,255}", "CRITICAL"),
    ("GitLab PAT",          r"glpat-[A-Za-z0-9\-_]{20}", "CRITICAL"),
    ("Slack Token",         r"xox[baprs]-[0-9a-zA-Z]{10,48}", "CRITICAL"),
    ("Slack Webhook",       r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}", "CRITICAL"),
    ("Stripe Live Key",     r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL"),
    ("Stripe Test Key",     r"sk_test_[0-9a-zA-Z]{24}", "MEDIUM"),
    ("SendGrid Key",        r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "CRITICAL"),
    ("Mailgun Key",         r"key-[0-9a-zA-Z]{32}", "HIGH"),
    ("Twilio SID",          r"AC[a-z0-9]{32}", "MEDIUM"),
    ("Firebase URL",        r"https://[a-z0-9-]+\.firebaseio\.com", "MEDIUM"),
    ("Firebase FCM",        r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "HIGH"),
    ("DigitalOcean Token",  r"dop_v1_[a-f0-9]{64}", "CRITICAL"),
    ("Shopify Token",       r"shpat_[a-fA-F0-9]{32}", "CRITICAL"),
    ("Discord Webhook",     r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "HIGH"),
    ("Telegram Bot",        r"[0-9]{8,10}:[A-Za-z0-9_-]{35}", "HIGH"),
    ("Private Key",         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    ("JWT",                 r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "MEDIUM"),
    ("MongoDB URI",         r"mongodb(?:\+srv)?://[^\s'\"]+", "CRITICAL"),
    ("PostgreSQL URI",      r"postgres(?:ql)?://[^\s'\"]+", "CRITICAL"),
    ("MySQL URI",           r"mysql://[^\s'\"]+", "CRITICAL"),
    ("Redis URI",           r"redis://[^\s'\"]+", "CRITICAL"),
    ("Basic Auth URL",      r"https?://[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.@]+@[a-zA-Z0-9_\-\.]+", "CRITICAL"),
    ("Generic API Key",     r"(?i)(api[_\-]?key|apikey)['\"\s:=]+['\"]?([a-zA-Z0-9_\-]{16,64})", "MEDIUM"),
    ("Generic Secret",      r"(?i)(secret|passwd|password|pwd|token)['\"\s:=]+['\"]([a-zA-Z0-9_\-!@#$%^&*]{8,64})['\"]", "MEDIUM"),
]

ENDPOINT_PATTERNS = [
    r"""["'](/(?:api|v\d|graphql|rest|auth|user|admin|internal|debug|config|upload|download|export|webhook)[^"'\s]{0,120})["']""",
    r"""["'](https?://[^"'\s]*(?:api|internal|staging|dev|admin)[^"'\s]*)["']""",
    r"""["'](/[a-zA-Z0-9_\-/]{3,80}\.(?:json|xml|php|asp|jsp|do))["']""",
]

COMPILED_SECRETS = [(n, re.compile(p), s) for n, p, s in JS_SECRET_PATTERNS]
COMPILED_ENDPOINTS = [re.compile(p) for p in ENDPOINT_PATTERNS]

# Pre-compile tech signatures
COMPILED_TECH = {}
for name, sig in TECH_SIGNATURES.items():
    compiled = {"category": sig.get("category", "Other")}
    if "headers" in sig:
        compiled["headers"] = {h: re.compile(p, re.I) for h, p in sig["headers"].items()}
    if "cookies" in sig:
        compiled["cookies"] = [re.compile(p, re.I) for p in sig["cookies"]]
    if "html" in sig:
        compiled["html"] = [re.compile(p, re.I) for p in sig["html"]]
    if "script" in sig:
        compiled["script"] = [re.compile(p, re.I) for p in sig["script"]]
    if "meta" in sig:
        compiled["meta"] = {k: re.compile(v, re.I) for k, v in sig["meta"].items()}
    COMPILED_TECH[name] = compiled


# ============================================================
# 📦 RESULT STORAGE
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
            "source": source, "type": name,
            "match": match[:200], "severity": severity,
        })

    def to_dict(self):
        return {
            "target_url": getattr(self, "target_url", ""),
            "scan_time": datetime.utcnow().isoformat(),
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
# 🛠️ MODULE 1: TECHNOLOGY FINGERPRINTING
# ============================================================

def fingerprint_tech(url: str, resp: requests.Response, results: Results):
    """Detect web technologies from response headers, cookies, HTML, and scripts."""
    print(f"\n{C.BOLD}🛠️  [1/3] Fingerprinting technologies...{C.RESET}")

    html = resp.text or ""
    headers = resp.headers
    cookies = resp.cookies

    detected = {}

    for tech, sig in COMPILED_TECH.items():
        versions = set()
        matched_via = []

        # Header check
        for hname, hpattern in sig.get("headers", {}).items():
            if hname in headers:
                m = hpattern.search(headers[hname])
                if m:
                    if m.groups() and m.group(1):
                        versions.add(m.group(1))
                    matched_via.append(f"header:{hname}")
                    break

        # Cookie check
        for cpattern in sig.get("cookies", []):
            for c in cookies:
                if cpattern.search(c.name):
                    matched_via.append(f"cookie:{c.name}")
                    break

        # HTML body check
        for hpattern in sig.get("html", []):
            m = hpattern.search(html)
            if m:
                if m.groups() and m.group(1):
                    versions.add(m.group(1))
                matched_via.append("html")
                break

        # Script src check
        for spattern in sig.get("script", []):
            m = spattern.search(html)
            if m:
                if m.groups() and m.group(1):
                    versions.add(m.group(1))
                matched_via.append("script")
                break

        # Meta tag check
        if "meta" in sig:
            soup = BeautifulSoup(html, "html.parser")
            for meta_name, mpattern in sig["meta"].items():
                tag = soup.find("meta", attrs={"name": meta_name})
                if tag and tag.get("content"):
                    m = mpattern.search(tag["content"])
                    if m:
                        if m.groups() and m.group(1):
                            versions.add(m.group(1))
                        matched_via.append(f"meta:{meta_name}")
                        break

        if matched_via:
            detected[tech] = {
                "category": sig["category"],
                "versions": sorted(v for v in versions if v),
                "matched_via": matched_via,
            }

    results.technologies = detected

    if not detected:
        log_warn("No technologies identified.")
        return

    # Group by category for pretty output
    by_cat = {}
    for tech, info in detected.items():
        by_cat.setdefault(info["category"], []).append((tech, info["versions"]))

    for cat in sorted(by_cat):
        print(f"  {C.YELLOW}📁 {cat}{C.RESET}")
        for tech, versions in sorted(by_cat[cat]):
            ver = f" {C.GRAY}v{', v'.join(versions)}{C.RESET}" if versions else ""
            print(f"     • {C.BOLD}{tech}{C.RESET}{ver}")

    log_ok(f"Detected {len(detected)} technologies across {len(by_cat)} categories")


# ============================================================
# 📜 MODULE 2: JAVASCRIPT ANALYSIS
# ============================================================

def find_js_urls(base_url: str, html: str, timeout: int = 10):
    """Extract JS file URLs from HTML + probe common paths."""
    js_urls = set()
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        full = urllib.parse.urljoin(base_url, src)
        if ".js" in full.lower():
            js_urls.add(full.split("#")[0])

    # Inline script references
    for script in soup.find_all("script", src=False):
        if script.string:
            for m in re.finditer(r"""["']([^"']+\.js(?:\?[^"']*)?)["']""", script.string):
                full = urllib.parse.urljoin(base_url, m.group(1))
                js_urls.add(full.split("#")[0])

    # Common paths probe (HEAD requests)
    common_paths = [
        "/static/js/main.js", "/static/js/app.js", "/js/app.js",
        "/assets/js/main.js", "/dist/bundle.js", "/build.js",
        "/main.js", "/app.js", "/bundle.js",
        "/static/js/main.chunk.js", "/static/js/runtime-main.js",
        "/assets/index.js", "/js/index.js",
    ]
    for path in common_paths:
        try:
            r = requests.head(f"{base}{path}", timeout=4, verify=False,
                              headers={"User-Agent": USER_AGENT},
                              allow_redirects=True)
            if r.status_code == 200 and "text/html" not in r.headers.get("Content-Type", ""):
                js_urls.add(f"{base}{path}")
        except Exception:
            continue

    return js_urls


def scan_js_content(content: str, source: str, results: Results):
    """Scan a single JS file for secrets and endpoints."""
    # Secrets
    for name, pattern, severity in COMPILED_SECRETS:
        for match in pattern.finditer(content):
            matched = match.group(0)
            lower = matched.lower()
            if any(p in lower for p in ["your_", "example", "placeholder",
                                         "xxxx", "aaaa", "changeme",
                                         "insert_", "replace_", "dummy"]):
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
                       timeout: int = 10, max_files: int = 50):
    """Download and analyze all JS files found on the page."""
    print(f"\n{C.BOLD}📜 [2/3] Analyzing JavaScript files...{C.RESET}")

    js_urls = find_js_urls(base_url, html, timeout)
    print(f"  {C.CYAN}🔎 Discovered {len(js_urls)} JS file(s) to fetch{C.RESET}")

    if not js_urls:
        log_warn("No JS files found. Page may require authentication.")
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
        futures = {executor.submit(fetch_and_scan, u): u
                   for u in list(js_urls)[:max_files]}
        for future in as_completed(futures):
            try:
                js_url, content = future.result()
            except Exception:
                continue
            if content:
                results.js_files.append(js_url)
                scan_js_content(content, js_url, results)
                scanned += 1

    log_ok(f"Scanned {scanned}/{len(js_urls)} JS files successfully")

    # Report secrets
    if results.secrets:
        log_critical(f"Found {len(results.secrets)} potential secret(s)!")
        by_sev = {}
        for s in results.secrets:
            by_sev.setdefault(s["severity"], []).append(s)
        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            if sev in by_sev:
                emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡"}[sev]
                color = {"CRITICAL": C.MAGENTA, "HIGH": C.RED, "MEDIUM": C.YELLOW}[sev]
                print(f"    {emoji} {color}{sev}{C.RESET}:")
                for s in by_sev[sev][:5]:
                    print(f"       • {s['type']}: {C.GRAY}{s['match'][:80]}{C.RESET}")
    else:
        log_ok("No secrets detected in JS files")

    if results.endpoints:
        log_info(f"Discovered {len(results.endpoints)} unique endpoint(s)")
        for ep in sorted(results.endpoints)[:10]:
            print(f"    🔗 {ep}")
        if len(results.endpoints) > 10:
            print(f"    {C.GRAY}... and {len(results.endpoints) - 10} more{C.RESET}")


# ============================================================
# 🗄️ MODULE 3: DATABASE EXPOSURE CHECK
# ============================================================

def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def probe_database(host: str, port: int, service: str) -> Optional[dict]:
    """Probe a database service for unauthenticated access."""
    finding = {
        "host": host, "port": port, "service": service,
        "severity": "HIGH" if port in HIGH_RISK_DB_PORTS else "MEDIUM",
        "evidence": "",
    }

    try:
        if port == 6379:  # Redis
            sock = socket.create_connection((host, port), timeout=5)
            sock.sendall(b"PING\r\n")
            resp = sock.recv(1024)
            sock.close()
            if b"PONG" in resp:
                finding["evidence"] = "Redis responds to PING without auth"
                finding["severity"] = "CRITICAL"
                return finding

        elif port == 27017:  # MongoDB — isMaster handshake
            sock = socket.create_connection((host, port), timeout=5)
            payload = bytes.fromhex(
                "3a0000000100000000000000d407000000000000"
                "61646d696e2e24636d640000000000ffffffff"
                "130000001069736d6173746572000100000000"
            )
            sock.sendall(payload)
            resp = sock.recv(2048)
            sock.close()
            if resp and len(resp) > 16:
                finding["evidence"] = "MongoDB responds to isMaster without auth"
                finding["severity"] = "CRITICAL"
                return finding

        elif port == 9200:  # Elasticsearch
            r = requests.get(f"http://{host}:{port}/", timeout=5, verify=False)
            if r.status_code == 200 and "tagline" in r.text.lower():
                finding["evidence"] = f"Elasticsearch info exposed: {r.text[:120]}"
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
            sock.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")  # SSLRequest
            resp = sock.recv(1024)
            sock.close()
            if resp:
                finding["evidence"] = "PostgreSQL accepts connections"
                return finding

        elif port == 11211:  # Memcached
            sock = socket.create_connection((host, port), timeout=5)
            sock.sendall(b"stats\r\n")
            resp = sock.recv(2048)
            sock.close()
            if b"STAT" in resp:
                finding["evidence"] = "Memcached responds to stats without auth"
                finding["severity"] = "CRITICAL"
                return finding

        elif port == 5984:  # CouchDB
            r = requests.get(f"http://{host}:{port}/", timeout=5, verify=False)
            if r.status_code == 200 and "couchdb" in r.text.lower():
                finding["evidence"] = f"CouchDB welcome: {r.text[:120]}"
                finding["severity"] = "CRITICAL"
                return finding

    except Exception:
        pass

    return None


def check_databases(host: str, results: Results):
    """Probe common database ports on the target host."""
    print(f"\n{C.BOLD}🗄️  [3/3] Checking for exposed database services...{C.RESET}")

    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_port, host, p): (p, svc)
                   for p, svc in COMMON_DB_PORTS.items()}
        for future in as_completed(futures):
            port, service = futures[future]
            try:
                if future.result():
                    open_ports.append((port, service))
            except Exception:
                continue

    if not open_ports:
        log_ok("No common database ports open to the internet (good)")
        return

    log_warn(f"Found {len(open_ports)} open database port(s):")
    for port, service in open_ports:
        print(f"  🔓 {port}/tcp — {service}")
        finding = probe_database(host, port, service)
        if finding:
            results.db_findings.append(finding)
            if finding["severity"] == "CRITICAL":
                log_critical(f"{finding['evidence']}")
            else:
                log_warn(f"{finding['evidence']}")


# ============================================================
# 📋 MANUAL TESTING ROADMAP
# ============================================================

def print_manual_roadmap(results: Results, url: str):
    print(f"\n{C.BOLD}{'═' * 68}{C.RESET}")
    print(f"{C.BOLD}📋 MANUAL TESTING ROADMAP — What to do next{C.RESET}")
    print(f"{C.BOLD}{'═' * 68}{C.RESET}")

    print(f"""
{C.GRAY}Your recon is done. Scanners generate candidates, not findings.
Every report you submit must be manually verified. Here's where to focus.{C.RESET}
""")

    # --- Technologies ---
    print(f"{C.CYAN}┌─ 1️⃣  BASED ON DETECTED TECHNOLOGIES {'─' * 30}┐{C.RESET}")
    tech_lower = {k.lower(): k for k in results.technologies}
    checks = []

    if any("wordpress" in t for t in tech_lower):
        checks.append("WordPress → `wpscan --url <url> --enumerate u,vp` for users & vulnerable plugins. "
                      "Check /wp-json/wp/v2/users and xmlrpc.php.")
    if any("drupal" in t for t in tech_lower):
        checks.append("Drupal → Check /CHANGELOG.txt for version. Cross-reference with Drupalgeddon CVEs.")
    if any("joomla" in t for t in tech_lower):
        checks.append("Joomla → Check /administrator/ and configuration.php exposure.")
    if any("magento" in t for t in tech_lower):
        checks.append("Magento → Check /admin, /downloader. Test for SQLi in product filters.")
    if any(t in tech_lower for t in ["react", "vue", "angular", "next.js", "nuxt.js", "svelte"]):
        checks.append("SPA framework → Real attack surface is the API. Open DevTools, click everything, "
                      "capture ALL API calls, then test each for IDOR/missing auth/mass assignment.")
    if any("shopify" in t for t in tech_lower):
        checks.append("Shopify → Test for price manipulation, discount code reuse, checkout logic bugs.")
    if any("nginx" in t for t in tech_lower):
        checks.append("Nginx → Test for path traversal with %2e%2e%2f, alias misconfig, off-by-slash.")
    if any("apache" in t for t in tech_lower):
        checks.append("Apache → Check /server-status, /server-info. Test .htaccess bypass.")
    if any(t in tech_lower for t in ["cloudflare", "akamai", "imperva", "sucuri"]):
        checks.append("WAF/CDN detected → Find origin IP via Shodan/Censys/crt.sh. Test origin directly to bypass WAF.")
    if any("graphql" in t for t in tech_lower):
        checks.append("GraphQL → Run introspection query. Test every mutation for auth.")

    if checks:
        for c in checks:
            print(f"  {C.YELLOW}➜{C.RESET} {c}")
    else:
        print(f"  {C.GRAY}• No high-value CMS/framework detected. Focus on application logic instead.{C.RESET}")

    # --- Secrets ---
    print(f"\n{C.CYAN}┌─ 2️⃣  BASED ON JS SECRETS {'─' * 41}┐{C.RESET}")
    if results.secrets:
        print(f"  {C.RED}Found {len(results.secrets)} secret(s). For EACH one:{C.RESET}")
        print("     🔹 Verify it works — try the key against the actual service API")
        print("     🔹 Determine scope — what can this key access?")
        print("     🔹 Check if it's test/staging vs production")
        print("     🔹 If valid → report immediately with proof (curl output as screenshot)")
        print("     🔹 If invalid → note it, might still indicate a pattern for escalation")
    else:
        print(f"  {C.GRAY}• No secrets found in JS. Try:{C.RESET}")
        print("     🔹 Check all JS files manually: /static/js/, /assets/, /dist/")
        print("     🔹 Look for source maps (.js.map) — often contain original unminified source")
        print("     🔹 Check the mobile app's APK/IPA if in scope (decompile with jadx/apktool)")

    # --- Endpoints ---
    print(f"\n{C.CYAN}┌─ 3️⃣  BASED ON DISCOVERED ENDPOINTS {'─' * 31}┐{C.RESET}")
    if results.endpoints:
        print(f"  {C.YELLOW}Found {len(results.endpoints)} endpoint(s). For EACH one:{C.RESET}")
        print("     🔹 Visit without auth → does it leak data?")
        print("     🔹 Visit with low-priv account → can you access higher-priv data?")
        print("     🔹 Change IDs in path/params → IDOR?")
        print("     🔹 Change HTTP method (GET → POST/PUT/DELETE) → method bypass?")
        print("     🔹 Add ?debug=1, ?admin=true, ?test=1 → debug mode activation?")
    else:
        print(f"  {C.GRAY}• No endpoints extracted. Manually map:{C.RESET}")
        print("     🔹 Use Burp Suite, click every button, capture every request")
        print("     🔹 Check /robots.txt, /sitemap.xml, /api/docs, /swagger.json, /openapi.json")

    # --- Database ---
    print(f"\n{C.CYAN}┌─ 4️⃣  BASED ON DATABASE FINDINGS {'─' * 34}┐{C.RESET}")
    if results.db_findings:
        print(f"  {C.MAGENTA}{C.BOLD}🚨 Database services exposed! High-priority finding.{C.RESET}")
        print("     🔹 MongoDB: `mongosh --host <ip> --port 27017` with no auth")
        print("     🔹 Redis: `redis-cli -h <ip> -p 6379` → INFO → KEYS *")
        print("     🔹 Elasticsearch: visit http://<ip>:9200/_cat/indices")
        print("     🔹 Document EVERYTHING — screenshot before reporting")
        print("     🔹 Do NOT dump more data than needed to prove access")
    else:
        print(f"  {C.GRAY}• No DB ports open directly (normal — DBs are usually internal){C.RESET}")
        print("     🔹 Instead, hunt for SQL injection in web parameters")
        print("     🔹 Check for .env, .git/config, backup.sql file exposure")
        print("     🔹 Try GraphQL introspection at /graphql, /api/graphql")

    # --- Universal checklist ---
    print(f"\n{C.CYAN}┌─ 5️⃣  UNIVERSAL MANUAL CHECKLIST {'─' * 34}┐{C.RESET}")
    print(f"""
  {C.BOLD}🔐 Authentication{C.RESET}
     [ ] Password reset: does token expire? Is it predictable?
     [ ] Email change: can you change it without confirmation?
     [ ] 2FA bypass: can you skip the 2FA step by direct navigation?
     [ ] Session fixation: does session ID change after login?

  {C.BOLD}🚪 Access Control (IDOR / BOLA){C.RESET}
     [ ] Create two accounts. Use A's session to access B's objects.
     [ ] Change every numeric/UUID identifier in every request.
     [ ] Check horizontal (same role) and vertical (user → admin) escalation.

  {C.BOLD}💼 Business Logic{C.RESET}
     [ ] Negative quantities in carts, price manipulation
     [ ] Race conditions: send the same request 20x concurrently
     [ ] Coupon reuse, referral abuse, unlimited free trials

  {C.BOLD}🔍 Information Disclosure{C.RESET}
     [ ] Error pages with stack traces (trigger 500s with malformed input)
     [ ] /phpinfo.php, /.env, /.git/config, /backup/, /debug/
     [ ] Response headers leaking internal IPs, paths, or versions

  {C.BOLD}🌐 API-Specific{C.RESET}
     [ ] Mass assignment: send extra fields in JSON (role, isAdmin, balance)
     [ ] GraphQL: introspection, then test every mutation for auth
     [ ] Rate limiting: is it absent on login, OTP, password reset?

  {C.BOLD}💻 Client-Side{C.RESET}
     [ ] DOM XSS: check postMessage handlers, innerHTML sinks
     [ ] CORS: test with Origin: https://evil.com + credentials
     [ ] Clickjacking: does app set X-Frame-Options or CSP frame-ancestors?
""")

    print(f"{C.BOLD}{'═' * 68}{C.RESET}")
    print(f"{C.GREEN}💡 Remember: scanners find candidates. YOU verify and report.{C.RESET}")
    print(f"{C.BOLD}{'═' * 68}{C.RESET}\n")


# ============================================================
# 🚀 MAIN
# ============================================================

def print_banner(url: str, host: str):
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║  🔍  RECON HUNTER — Bug Bounty Recon Tool (Python 3)         ║
╠══════════════════════════════════════════════════════════════╣
║  🎯 Target: {url:<49}║
║  🌐 Host:   {host:<49}║
║  ⏰ Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<49}║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")


def main():
    parser = argparse.ArgumentParser(
        description="🔍 Recon tool: tech fingerprinting + JS secrets + DB exposure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon_hunter.py -u https://target.com
  python3 recon_hunter.py -u https://target.com --js-only
  python3 recon_hunter.py -u https://target.com --db-only
  python3 recon_hunter.py -u target.com -o my_scan
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="🎯 Target URL")
    parser.add_argument("-o", "--output", default="recon_report",
                        help="📁 Output file prefix (default: recon_report)")
    parser.add_argument("--js-only", action="store_true",
                        help="📜 Only run JS analysis")
    parser.add_argument("--db-only", action="store_true",
                        help="🗄️  Only run DB port check")
    parser.add_argument("--timeout", type=int, default=15,
                        help="⏱️  Request timeout in seconds (default: 15)")
    parser.add_argument("--insecure", action="store_true", default=True,
                        help="🔓 Skip SSL verification (default: on for bug bounty)")

    args = parser.parse_args()

    # Normalize URL
    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.split(":")[0]

    print_banner(url, host)

    results = Results()
    results.target_url = url

    # Fetch the page once
    html = ""
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=args.timeout,
            verify=False,
            allow_redirects=True,
        )
        html = resp.text
        results.headers = dict(resp.headers)
        results.cookies = [c.name for c in resp.cookies]
        log_ok(f"Fetched page: HTTP {resp.status_code}, {len(html):,} bytes")
    except requests.exceptions.SSLError:
        log_err(f"SSL error fetching {url}. Try a different scheme or check the cert.")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        log_err(f"Cannot connect to {url}. Check the URL and network.")
        sys.exit(1)
    except requests.exceptions.Timeout:
        log_err(f"Timeout after {args.timeout}s. Increase with --timeout.")
        sys.exit(1)
    except Exception as e:
        log_err(f"Failed to fetch {url}: {e}")
        sys.exit(1)

    # Run selected modules
    try:
        if not args.js_only and not args.db_only:
            fingerprint_tech(url, resp, results)
            analyze_javascript(url, html, results, args.timeout)
            check_databases(host, results)
        elif args.js_only:
            analyze_javascript(url, html, results, args.timeout)
        elif args.db_only:
            check_databases(host, results)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        log_err(f"Scanner error: {e}")
        results.errors.append(str(e))

    # Save report
    out_path = Path(f"{args.output}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results.to_dict(), f, indent=2, default=str)
        log_ok(f"JSON report saved: {out_path}")
    except Exception as e:
        log_err(f"Could not save report: {e}")

    # Print roadmap
    print_manual_roadmap(results, url)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}⚠️  Interrupted by user.{C.RESET}")
        sys.exit(130)
