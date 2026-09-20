# Recon_hunter

recon_hunter.py — Purpose-built bug bounty recon tool.

Does three things reliably:
1. Fingerprints web technologies (versions, CMS, frameworks, servers)
2. Extracts secrets + endpoints from JavaScript files
3. Probes for exposed database services

Plus: prints a manual testing roadmap based on what it finds.

Usage:
```
    python recon_hunter.py -u https://target.com
```
```
    python recon_hunter.py -u https://target.com --js-only
```
```
    python recon_hunter.py -u https://target.com --db-only
```

