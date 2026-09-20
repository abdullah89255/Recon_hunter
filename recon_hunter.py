#!/usr/bin/env python3
"""
🔍 recon.py — Simple, reliable bug bounty recon tool.

Checks:
  • Web technologies (headers + HTML patterns)
  • JavaScript secrets and endpoints
  • Exposed database ports

Usage:
    python3 recon.py -u https://example.com
    python3 recon.py -u https://example.com --debug
"""

import argparse
import json
import re
import socket
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------- dependency check ----------
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("❌ Missing: requests")
    print("   Install: pip3 install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("❌ Missing: beautifulsoup4")
    print("   Install: pip3 install beautifulsoup4")
    sys.exit(1)


# ---------- colors ----------
G, R, Y, B, C, M, D, X = (
    "\033[92m", "\033[91m", "\033[93m",
    "\033[94m", "\033[96m", "\033[95m",
    "\033[90m", "\033[0m",
)


# ---------- tech signatures (simple substring match) ----------
TECH = {
    # Server / Language
    "Nginx":         {"headers": ["server:nginx"], "cat": "Server"},
    "Apache":        {"headers": ["server:apache"], "cat": "Server"},
    "IIS":           {"headers": ["server:Microsoft-IIS"], "cat": "Server"},
    "LiteSpeed":     {"headers": ["server:LiteSpeed"], "cat": "Server"},
    "PHP":           {"headers": ["x-powered-by:PHP"], "cat": "Language"},
    "ASP.NET":       {"headers": ["x-powered-by:ASP.NET", "x-aspnet-version"], "cat": "Framework"},
    "Express":       {"headers": ["x-powered-by:Express"], "cat": "Framework"},

    # CMS
    "WordPress":     {"html": ["/wp-content/", "/wp-includes/", "wp-json"], "cat": "CMS"},
    "Drupal":        {"html": ["Drupal.settings", "/sites/default/files/"], "cat": "CMS"},
    "Joomla":        {"html": ["/components/com_", "Joomla!"], "cat": "CMS"},
    "Magento":       {"html": ["Mage.Cookies", "/skin/frontend/"], "cat": "E-commerce"},
    "Shopify":       {"html": ["cdn.shopify.com", "Shopify.theme"], "cat": "E-commerce"},
    "Ghost":         {"html": ["ghost.org", "content=\"Ghost"], "cat": "CMS"},

    # Frameworks
    "React":         {"html": ["data-reactroot", "__REACT_DEVTOOLS"], "cat": "Framework"},
    "Next.js":       {"html": ["__NEXT_DATA__", "/_next/static/"], "cat": "Framework"},
    "Vue.js":        {"html": ["data-v-", "__vue__"], "cat": "Framework"},
    "Nuxt.js":       {"html": ["__NUXT__", "/_nuxt/"], "cat": "Framework"},
    "Angular":       {"html": ["ng-version=", "ng-app"], "cat": "Framework"},
    "Svelte":        {"html": ["__svelte", "svelte-"], "cat": "Framework"},
    "jQuery":        {"html": ["jquery.min.js", "jquery.js", "jquery-"], "cat": "Library"},
    "Bootstrap":     {"html": ["bootstrap.min.css", "bootstrap.min.js"], "cat": "Library"},
    "Tailwind":      {"html": ["tailwind"], "cat": "Library"},

    # CDN / WAF
    "Cloudflare":    {"headers": ["server:cloudflare", "cf-ray"], "cat": "CDN/WAF"},
    "Akamai":        {"headers": ["server:AkamaiGHost", "x-akamai"], "cat": "CDN/WAF"},
    "Fastly":        {"headers": ["x-served-by:cache-", "x-fastly"], "cat": "CDN"},
    "Sucuri":        {"headers": ["x-sucuri-id", "server:Sucuri"], "cat": "WAF"},
    "CloudFront":    {"headers": ["x-amz-cf-id"], "cat": "CDN"},

    # Hosting
    "Vercel":        {"headers": ["server:Vercel", "x-vercel-id"], "cat": "Hosting"},
    "Netlify":       {"headers": ["server:Netlify", "x-nf-request-id"], "cat": "Hosting"},
    "GitHub Pages":  {"headers": ["server:GitHub.com"], "cat": "Hosting"},
    "Heroku":        {"headers": ["via:1.1 vegur", "server:Heroku"], "cat": "Hosting"},

    # Analytics
    "Google Analytics": {"html": ["google-analytics.com", "gtag/js"], "cat": "Analytics"},
    "Google Tag Manager": {"html": ["googletagmanager.com"], "cat": "Analytics"},
    "Hotjar":        {"html": ["static.hotjar.com"], "cat": "Analytics"},
    "Segment":       {"html": ["cdn.segment.com"], "cat": "Analytics"},
}


# ---------- secret patterns ----------
SECRETS = [
    ("AWS Access Key",   r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",   r"aws.{0,30}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Google API Key",   r"AIza[0-9A-Za-z_\-]{35}"),
    ("GitHub Token",     r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    ("Slack Token",      r"xox[baprs]-[0-9a-zA-Z\-]{10,48}"),
    ("Stripe Live Key",  r"sk_live_[0-9a-zA-Z]{24}"),
    ("Stripe Test Key",  r"sk_test_[0-9a-zA-Z]{24}"),
    ("SendGrid Key",     r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"),
    ("Mailgun Key",      r"key-[0-9a-zA-Z]{32}"),
    ("Firebase URL",     r"https://[a-z0-9\-]+\.firebaseio\.com"),
    ("Firebase FCM",     r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}"),
    ("MongoDB URI",      r"mongodb(?:\+srv)?://[^\s'\"]+"),
    ("PostgreSQL URI",   r"postgres(?:ql)?://[^\s'\"]+"),
    ("MySQL URI",        r"mysql://[^\s'\"]+"),
    ("Redis URI",        r"redis://[^\s'\"]+"),
    ("Private Key",      r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("JWT",              r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("Basic Auth URL",   r"https?://[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.@]{3,}@[a-zA-Z0-9_\-\.]+"),
    ("Discord Webhook",  r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"),
    ("Telegram Bot",     r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}"),
]

ENDPOINT_RE = re.compile(
    r"""["'](/(?:api|v\d|graphql|rest|auth|user|admin|internal|upload|download)[^"'\s<>]{0,100})["']"""
)

DB_PORTS = {
    3306:  "MySQL / MariaDB",
    5432:  "PostgreSQL",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    5984:  "CouchDB",
    11211: "Memcached",
}

HIGH_RISK = {27017, 6379, 9200, 5984, 11211}

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


# ============================================================
# MODULE 1 — FINGERPRINT
# ============================================================

def fingerprint(url, resp, debug=False):
    """Return dict of detected technologies."""
    detected = {}
    header_str = "\n".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
    html = (resp.text or "")[:500_000]  # cap for perf
    html_lower = html.lower()

    for name, sig in TECH.items():
        matched = False

        for h in sig.get("headers", []):
            if h.lower() in header_str:
                detected[name] = sig["cat"]
                matched = True
                break

        if not matched:
            for h in sig.get("html", []):
                if h.lower() in html_lower:
                    detected[name] = sig["cat"]
                    break

    if debug:
        print(f"{D}    [debug] headers scanned: {len(resp.headers)}, html len: {len(html)}{X}")

    return detected


# ============================================================
# MODULE 2 — JAVASCRIPT
# ============================================================

def find_js_urls(base_url, html, timeout=10, debug=False):
    """Return set of JS URLs found on page + common paths."""
    js_urls = set()
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "")
            if src:
                full = urllib.parse.urljoin(base_url, src)
                if ".js" in full.lower():
                    js_urls.add(full.split("#")[0])
    except Exception as e:
        if debug:
            print(f"{D}    [debug] bs4 script parse failed: {e}{X}")

    # common paths
    for path in ["/main.js", "/app.js", "/bundle.js", "/static/js/main.js",
                 "/assets/js/main.js", "/dist/bundle.js"]:
        js_urls.add(f"{base}{path}")

    return js_urls


def scan_js(url, content, debug=False):
    """Return (secrets, endpoints) found in JS content."""
    secrets = []
    endpoints = set()

    for name, pattern in SECRETS:
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                val = m.group(0)
                # Skip placeholders
                low = val.lower()
                if any(p in low for p in ["example", "your_", "xxxx", "placeholder",
                                           "dummy", "changeme", "test_key"]):
                    continue
                if len(set(val)) < 5:
                    continue
                secrets.append({"type": name, "value": val[:120], "source": url})
                break  # one per type per file
        except re.error as e:
            if debug:
                print(f"{D}    [debug] regex error {name}: {e}{X}")

    try:
        for m in ENDPOINT_RE.finditer(content):
            endpoints.add(m.group(1))
    except Exception as e:
        if debug:
            print(f"{D}    [debug] endpoint regex error: {e}{X}")

    return secrets, endpoints


def analyze_js(base_url, html, timeout=10, debug=False):
    """Find, download, scan JS files."""
    print(f"\n{B}📜 [2/3] Analyzing JavaScript...{X}")

    js_urls = find_js_urls(base_url, html, timeout, debug)
    print(f"  {C}Found {len(js_urls)} JS URL(s){X}")

    all_secrets = []
    all_endpoints = set()
    scanned = []

    def fetch(u):
        try:
            r = requests.get(u, headers={"User-Agent": UA},
                             timeout=timeout, verify=False)
            if r.status_code == 200 and len(r.text) > 0:
                return u, r.text
        except Exception as e:
            if debug:
                print(f"{D}    [debug] fetch {u} failed: {type(e).__name__}: {e}{X}")
        return u, None

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(fetch, u): u for u in js_urls}
        for fut in as_completed(futures):
            try:
                u, content = fut.result()
                if content:
                    scanned.append(u)
                    s, e = scan_js(u, content, debug)
                    all_secrets.extend(s)
                    all_endpoints.update(e)
            except Exception as e:
                if debug:
                    print(f"{D}    [debug] worker error: {e}{X}")

    print(f"  {G}✅ Scanned {len(scanned)} JS file(s){X}")

    if all_secrets:
        print(f"  {M}🚨 {len(all_secrets)} potential secret(s):{X}")
        for s in all_secrets:
            print(f"     {R}•{X} {s['type']}: {D}{s['value']}{X}")
    else:
        print(f"  {G}✅ No secrets found{X}")

    if all_endpoints:
        print(f"  {C}🔗 {len(all_endpoints)} endpoint(s):{X}")
        for e in sorted(all_endpoints)[:15]:
            print(f"     • {e}")

    return all_secrets, all_endpoints, scanned


# ============================================================
# MODULE 3 — DATABASES
# ============================================================

def port_open(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def probe(host, port, debug=False):
    """Return dict finding or None."""
    try:
        if port == 6379:  # Redis
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(b"PING\r\n")
            resp = s.recv(512)
            s.close()
            if b"PONG" in resp:
                return {"port": port, "service": "Redis",
                        "severity": "CRITICAL",
                        "evidence": "Redis responds to PING without auth"}

        elif port == 11211:  # Memcached
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(b"stats\r\n")
            resp = s.recv(2048)
            s.close()
            if b"STAT" in resp:
                return {"port": port, "service": "Memcached",
                        "severity": "CRITICAL",
                        "evidence": "Memcached responds to stats without auth"}

        elif port == 9200:  # Elasticsearch
            r = requests.get(f"http://{host}:{port}/", timeout=5, verify=False)
            if r.status_code == 200 and "tagline" in r.text.lower():
                return {"port": port, "service": "Elasticsearch",
                        "severity": "CRITICAL",
                        "evidence": r.text[:150]}

        elif port == 5984:  # CouchDB
            r = requests.get(f"http://{host}:{port}/", timeout=5, verify=False)
            if r.status_code == 200 and "couchdb" in r.text.lower():
                return {"port": port, "service": "CouchDB",
                        "severity": "CRITICAL",
                        "evidence": r.text[:150]}

        elif port == 27017:  # MongoDB — just check if TCP accepts AND sends data
            s = socket.create_connection((host, port), timeout=5)
            # Minimal isMaster (correct length: 58 bytes = 0x3a)
            payload = bytes.fromhex(
                "3a000000"                          # messageLength = 58
                "01000000"                          # requestID
                "00000000"                          # responseTo
                "d4070000"                          # opCode = 2004 (OP_QUERY)
                "00000000"                          # flags
                "61646d696e"                        # "admin"
                "2e24636d64"                        # ".$cmd"
                "00000000"                          # skip
                "ffffffff"                          # return -1
                "13000000"                          # doc length
                "1069736d6173746572000100000000"   # {"ismaster": 1}
            )
            s.sendall(payload)
            resp = s.recv(2048)
            s.close()
            if resp and len(resp) > 16:
                return {"port": port, "service": "MongoDB",
                        "severity": "CRITICAL",
                        "evidence": f"MongoDB isMaster response ({len(resp)} bytes)"}

    except Exception as e:
        if debug:
            print(f"{D}    [debug] probe {port} error: {type(e).__name__}: {e}{X}")

    return None


def check_dbs(host, debug=False):
    print(f"\n{B}🗄️  [3/3] Checking database ports...{X}")

    open_ports = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(port_open, host, p): (p, n) for p, n in DB_PORTS.items()}
        for fut in as_completed(futures):
            try:
                if fut.result():
                    open_ports.append(futures[fut])
            except Exception:
                continue

    if not open_ports:
        print(f"  {G}✅ No common DB ports open{X}")
        return []

    print(f"  {Y}⚠️  {len(open_ports)} open port(s):{X}")
    findings = []
    for port, name in sorted(open_ports):
        print(f"     {Y}🔓 {port}/tcp — {name}{X}")
        f = probe(host, port, debug)
        if f:
            findings.append(f)
            print(f"        {M}🚨 {f['evidence']}{X}")

    return findings


# ============================================================
# ROADMAP
# ============================================================

def roadmap(techs, secrets, endpoints, dbs):
    print(f"\n{B}{'═' * 66}{X}")
    print(f"{B}📋 MANUAL TESTING ROADMAP{X}")
    print(f"{B}{'═' * 66}{X}\n")

    # Tech-based
    print(f"{C}1️⃣  By technology:{X}")
    tl = {k.lower(): k for k in techs}
    hints = []
    if "wordpress" in tl:
        hints.append("WordPress → wpscan --url <url> --enumerate u,vp")
    if "drupal" in tl:
        hints.append("Drupal → check /CHANGELOG.txt, Drupalgeddon CVEs")
    if "joomla" in tl:
        hints.append("Joomla → check /administrator/, configuration.php")
    if any(k in tl for k in ["react", "vue", "angular", "next.js", "nuxt.js", "svelte"]):
        hints.append("SPA → real attack surface is the API. Open DevTools, capture all XHR/fetch calls")
    if any(k in tl for k in ["cloudflare", "akamai", "sucuri"]):
        hints.append("WAF detected → find origin IP via Shodan/Censys/crt.sh, test origin directly")
    if "nginx" in tl:
        hints.append("Nginx → test %2e%2e%2f traversal, alias misconfig, off-by-slash")
    if not hints:
        hints.append("No CMS/framework → focus on application logic and API endpoints")
    for h in hints:
        print(f"   {Y}➜{X} {h}")

    # Secrets
    print(f"\n{C}2️⃣  By secrets ({len(secrets)}):{X}")
    if secrets:
        print(f"   {R}For each secret:{X}")
        print("     1. Verify it actually works (curl the service API)")
        print("     2. Determine its scope — what can it access?")
        print("     3. Test vs prod? Check the account/project name")
        print("     4. If valid → report immediately with screenshot of curl output")
    else:
        print("   • Check source maps (.js.map) for unminified source")
        print("   • Decompile the mobile app (jadx for Android, class-dump for iOS) if in scope")

    # Endpoints
    print(f"\n{C}3️⃣  By endpoints ({len(endpoints)}):{X}")
    if endpoints:
        print("   For each endpoint:")
        print("     • Visit without auth — does it leak data?")
        print("     • Visit with a low-priv account — can you see other users' data?")
        print("     • Change IDs in path/params — IDOR?")
        print("     • Change method (GET→POST/PUT/DELETE) — method bypass?")
        print("     • Add ?debug=1, ?admin=true — debug mode?")
    else:
        print("   • Use Burp Suite. Click every button. Capture every request.")

    # DBs
    print(f"\n{C}4️⃣  Databases:{X}")
    if dbs:
        print(f"   {M}🚨 Exposed database confirmed! Top-priority report.{X}")
        print("     • Screenshot proof BEFORE exploring further")
        print("     • Only read enough to prove access (e.g., SHOW DATABASES)")
        print("     • Do NOT dump user data")
    else:
        print("   • No direct DB exposure (normal). Hunt for SQLi in parameters instead.")
        print("   • Check /.env, /.git/config, /backup.sql")

    # Universal
    print(f"\n{C}5️⃣  Universal manual checklist:{X}")
    print(f"""   {B}Auth:{X} password reset tokens expire? 2FA skip? session fixation?
   {B}IDOR:{X} create 2 accounts, swap IDs everywhere
   {B}Logic:{X} negative quantities, race conditions, coupon reuse
   {B}Info:{X} trigger 500s, check /.env /.git/ /.DS_Store
   {B}API:{X} mass assignment (send role/isAdmin), rate limit bypass
   {B}Client:{X} DOM XSS via postMessage, CORS with evil origin
""")
    print(f"{B}{'═' * 66}{X}\n")


# ============================================================
# MAIN
# ============================================================

def main():
    p = argparse.ArgumentParser(description="🔍 Bug bounty recon tool")
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument("-o", "--output", default="recon_report", help="Output prefix")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout (s)")
    p.add_argument("--debug", action="store_true", help="Show debug output")
    p.add_argument("--skip-db", action="store_true", help="Skip DB port check")
    args = p.parse_args()

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    host = urllib.parse.urlparse(url).netloc.split(":")[0]

    print(f"""
{C}{B}╔══════════════════════════════════════════════════════════╗
║  🔍  RECON — Bug Bounty Recon Tool                       ║
╠══════════════════════════════════════════════════════════╣
║  🎯 Target: {url:<45}║
║  🌐 Host:   {host:<45}║
║  ⏰ Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<45}║
╚══════════════════════════════════════════════════════════╝{X}
""")

    # ---- Fetch page ----
    print(f"{B}🌐 [1/3] Fetching target...{X}")
    try:
        resp = requests.get(url, headers={"User-Agent": UA},
                            timeout=args.timeout, verify=False,
                            allow_redirects=True)
        print(f"  {G}✅ HTTP {resp.status_code} — {len(resp.content):,} bytes{X}")
    except requests.exceptions.SSLError as e:
        print(f"  {R}❌ SSL error: {e}{X}")
        print(f"  {Y}Try http:// instead of https://{X}")
        sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        print(f"  {R}❌ Connection failed: {e}{X}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"  {R}❌ Timeout after {args.timeout}s. Try --timeout 30{X}")
        sys.exit(1)
    except Exception as e:
        print(f"  {R}❌ {type(e).__name__}: {e}{X}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # ---- Fingerprint ----
    print(f"\n{B}🛠️  [1.5/3] Fingerprinting tech...{X}")
    try:
        techs = fingerprint(url, resp, args.debug)
        if techs:
            grouped = {}
            for name, cat in techs.items():
                grouped.setdefault(cat, []).append(name)
            for cat in sorted(grouped):
                print(f"  {Y}📁 {cat}{X}")
                for t in sorted(grouped[cat]):
                    print(f"     • {t}")
            print(f"  {G}✅ {len(techs)} tech detected{X}")
        else:
            print(f"  {Y}⚠️  No tech detected from headers/HTML{X}")
    except Exception as e:
        print(f"  {R}❌ fingerprint error: {e}{X}")
        if args.debug:
            import traceback; traceback.print_exc()
        techs = {}

    # ---- JS ----
    try:
        secrets, endpoints, js_files = analyze_js(url, resp.text, args.timeout, args.debug)
    except Exception as e:
        print(f"{R}❌ JS analysis error: {e}{X}")
        if args.debug:
            import traceback; traceback.print_exc()
        secrets, endpoints, js_files = [], set(), []

    # ---- DB ----
    if not args.skip_db:
        try:
            dbs = check_dbs(host, args.debug)
        except Exception as e:
            print(f"{R}❌ DB check error: {e}{X}")
            if args.debug:
                import traceback; traceback.print_exc()
            dbs = []
    else:
        dbs = []

    # ---- Save report ----
    report = {
        "target": url,
        "scanned_at": datetime.utcnow().isoformat(),
        "technologies": techs,
        "secrets": secrets,
        "endpoints": sorted(endpoints),
        "js_files": js_files,
        "databases": dbs,
    }
    out = f"{args.output}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n{G}✅ Report saved: {out}{X}")
    except Exception as e:
        print(f"\n{R}❌ Could not save report: {e}{X}")

    # ---- Roadmap ----
    roadmap(techs, secrets, endpoints, dbs)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}⚠️  Interrupted.{X}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{R}❌ Fatal: {type(e).__name__}: {e}{X}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
