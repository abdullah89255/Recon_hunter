🔍 recon_hunter.py — Simple, reliable bug bounty recon tool.

Checks:
  • Web technologies (headers + HTML patterns)
  • JavaScript secrets and endpoints
  • Exposed database ports

Usage:
```
    python3 recon_hunter.py -u https://example.com
    python3 recon_hunter.py -u https://example.com --debug
```



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


