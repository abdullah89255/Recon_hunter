## Installation

```bash
# Python dependencies
pip3 install requests beautifulsoup4

# Optional: external tools for --nuclei / --katana / --subfinder
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

## Usage examples

```bash
# Full scan (all modules)
python3 recon_hunter_v2.py -u https://target.com --full

# Focused: BOLA + GraphQL
python3 recon_hunter_v2.py -u https://target.com --bola --graphql

# Add SSRF metadata probing
python3 recon_hunter_v2.py -u https://target.com --ssrf --race

# Full pipeline with Nuclei + Katana
python3 recon_hunter_v2.py -u https://target.com --full --nuclei --katana
```

---

## What each new module actually does

**BOLA/IDOR Scanner** — Takes every numeric ID found in query params or path segments and swaps them (base ± 1, 2, 10, 100). It checks whether the response contains PII (email, phone, SSN, credit card patterns) and whether the object "not found" message is absent. This mirrors the exact methodology behind the 38% of validated submissions that are IDOR/BOLA.

**GraphQL Introspection** — Sends the full `__schema` query to common GraphQL paths (`/graphql`, `/api/graphql`, `/v1/graphql`). If the schema leaks, it extracts all query and mutation names, flags sensitive fields (password, token, admin, internal, etc.), then tests depth limits (nested `__typename` up to 15 levels) and batching (10 aliased queries in one request).

**Race Condition Tester** — Fires N concurrent requests (default 20) using a thread pool against the same endpoint. It analyzes response status distribution and body variation. If multiple 2xx responses come back with different bodies and limit-related keywords ("already used", "redeemed", "expired"), it flags a potential TOCTOU/limit overrun — the same class of bug that consistently pays in bug bounties.

**Cloud Metadata SSRF Prober** — For every param whose name matches known SSRF targets (`url`, `redirect`, `callback`, `webhook`, etc.), it substitutes the cloud metadata endpoints: AWS IMDSv1 (`169.254.169.254`), AWS IMDSv2 (PUT with token header), GCP (`metadata.google.internal` with `Metadata-Flavor: Google`), Azure (with `Metadata: true`), Alibaba (`100.100.100.200`), and DigitalOcean. It checks responses for metadata signatures like `ami-id`, `iam`, `security-credentials`, `project-id`.

**Vulnerable Library Detection** — Regex-matches known vulnerable jQuery, Bootstrap, Angular, Lodash, and Vue versions in JS files. Reports the CVE and tells you to upgrade.

**Exploit Scaffold Generator** — For every confirmed BOLA/IDOR or SSRF finding, it writes a ready-to-run Python PoC script to `./exploits/`. For command injection it also generates reverse shell payloads (bash, Python, PowerShell).

**Activity Logger** — Every request is logged to `activity_logs/session_*.md` in Obsidian-compatible markdown. Every finding gets its own section with URL, payload, evidence, remediation, and CWE. Every raw request is also saved to JSONL for programmatic analysis.

**Tool Orchestration** — If Nuclei, Katana, and Subfinder are installed, the script runs them automatically, merges their output into the final report, and logs everything. This matches the multi-tool orchestration architecture used by professional bug bounty platforms.

---

## What's still manual (by design)

The script deliberately does **not** auto-exploit. It generates scaffolds and stops. Every finding must be verified by you because:

1. **HackerOne requires proof of impact.** A scanner flag is not a report.
2. **False positives waste everyone's time.** The BOLA detector uses heuristics; you confirm with two real accounts.
3. **Ethical boundaries.** The race condition tester fires 20 requests — you decide if the target's scope allows it. The SSRF prober does not exfiltrate credentials, only detects access.

Run it, triage the output, verify manually, and submit only what you can prove.
