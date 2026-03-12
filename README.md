# RECON-DZ v3 — Advanced Security Reconnaissance Framework

> **Authorized security assessment use only. Unauthorized use is illegal.**

---

## What's New in v3

### Bugs Fixed (from v2)

| # | Bug | Fix |
|---|-----|-----|
| 1 | `#!/usr/bin/env python3` on line 2 (invalid shebang) | Moved to line 1 |
| 2 | `aiohttp` `timeout=10` as raw int (raises `ValueError`) | Changed to `aiohttp.ClientTimeout(total=10)` |
| 3 | `asyncio.Semaphore()` in `PortScanner.__init__` (no event loop) | Created lazily inside `scan()` |
| 4 | `server_fingerprint.py` typed `List[PortInfo]` but received `List[Dict]` | Accepts both via `isinstance` check |
| 5 | `{tuple(d.items()) for d in ...}` crashes on nested dicts/lists | Replaced with JSON-key deduplication |
| 6 | `self.engine.stats` passed directly to JSON (mutable internal dict) | Uses `self.engine.get_stats()` snapshot |
| 7 | PrestaShop regex `"PS_VERSION_\\', \\'"` invalid escape | Fixed to `r"_PS_VERSION_['\"],\s*['\"]..."` |
| 8 | `crtsh` `timeout=10` (raw int in `aiohttp` session) | `ClientTimeout(total=20, connect=8)` |
| 9 | Broken UTF-8 mojibake in Arabic comments throughout codebase | Replaced with clean English comments |
| 10 | `engine.stats` accessed as dict property but never serialized safely | `get_stats()` returns a clean snapshot dict |

### New Features

- **`core/vuln_scanner.py`** — Full vulnerability scanning module:
  - Security header analysis with grading (A–F)
  - Server version disclosure + EOL detection
  - Sensitive file exposure (`.env`, `.git`, backups, etc.)
  - Directory listing detection
  - Mixed content detection
  - Cookie security flags (HttpOnly/Secure/SameSite)
  - Algeria Decree 26-07 compliance checks
  - Information disclosure patterns (passwords, API keys, DB strings)

- **SSL/TLS Analysis** — Protocol version, cipher suite, cert CN/SAN, expiry, self-signed detection

- **HackerTarget subdomain source** — Additional CT log source alongside crt.sh

- **Colorized output** — Severity-colored terminal output (degrades gracefully without colorama)

- **`--vuln` CLI flag** — Enable full vulnerability scanning

- **`--version` flag** — Print version and exit

- **Improved CDN detection** — Added Fastly, AWS CloudFront, Azure CDN ranges

- **Origin IP bypass** — Checks HTTP headers for leaked origin IPs behind CDNs

---

## Installation

```bash
# Clone or extract the archive
cd recon_dz_v3/

# Install dependencies
pip install -r requirements.txt

# Run a basic scan
python recon_dz_v3.py -t target.dz
```

### Termux (Android)

```bash
pkg install python
pip install aiohttp cryptography colorama
python recon_dz_v3.py -t target.dz
```

---

## Usage

```
python recon_dz_v3.py -t <target> [options]
```

### Arguments

| Flag | Description |
|------|-------------|
| `-t, --target` | Target domain or IP (required) |
| `-v, --verbose` | Verbose output |
| `--internal` | Internal network mode (faster, shorter delays) |
| `--depth` | Scan depth: `quick`, `normal`, `deep` |
| `--max-concurrent` | Max concurrent requests (default: 30) |
| `--output-dir` | Output directory for reports (default: `./results`) |
| `--version` | Show version and exit |

### Module Flags

| Flag | Description |
|------|-------------|
| `-e, --enumerate` | Enable ALL modules |
| `--reverse-ip` | Co-hosted domain enumeration via reverse IP |
| `--subdomains` | Subdomain enumeration (crt.sh + HackerTarget + bruteforce) |
| `--ports` | TCP port scanning with banner grabbing |
| `--cms` | CMS detection (WordPress, Joomla, Drupal, Moodle, Magento, etc.) |
| `--fingerprint` | Server fingerprinting + SSL/TLS analysis |
| `--vuln` | Full vulnerability and compliance scanning |

### Examples

```bash
# Basic scan
python recon_dz_v3.py -t univ-medea.dz

# Full scan (all modules)
python recon_dz_v3.py -t ministere.gov.dz -e

# Subdomains + ports + vuln scan
python recon_dz_v3.py -t target.dz --subdomains --ports --vuln

# Internal network (fast, no stealth delay)
python recon_dz_v3.py -t 192.168.1.100 --internal --ports --fingerprint

# Custom output directory
python recon_dz_v3.py -t target.dz -e --output-dir /tmp/assessment
```

---

## Project Structure

```
recon_dz_v3/
├── recon_dz_v3.py          # Main CLI entrypoint
├── requirements.txt
├── wordlists/
│   └── subdomains.txt
├── results/                # Auto-created scan reports
└── core/
    ├── __init__.py
    ├── async_engine.py      # Async HTTP + DNS-over-HTTPS engine
    ├── algeria_threats.py   # Algeria threat intelligence database
    ├── cms_detector.py      # CMS detection (10 platforms)
    ├── domain_validator.py  # Domain liveness validation
    ├── ip_enumerator.py     # Reverse IP / SSL cert extraction
    ├── ip_utils.py          # CDN detection + origin IP bypass
    ├── port_scanner.py      # Async TCP port scanner
    ├── server_fingerprint.py# OS/service fingerprinting + SSL analysis
    ├── subdomain_enum.py    # Subdomain enumeration
    └── vuln_scanner.py      # Vulnerability & compliance scanning (NEW)
```

---

## Algeria-Specific Intelligence

RECON-DZ automatically classifies `.dz` targets by sector:

| Sector | Examples | Compliance |
|--------|----------|------------|
| Government | `*.gov.dz`, ministère, wilaya | Decree 26-07 |
| Banking | BNA, CPA, BADR | Bank of Algeria Circulars, PCI-DSS |
| Telecom | Algérie Télécom, Mobilis, Djezzy | ARPT, Decree 26-07 |
| Energy | Sonatrach, Sonelgaz | Energy Sector Directive |
| Education | univ-*, USTHB, ESI | Ministry HE Guidelines |
| Health | EPH, CHU, clinique | Health Data Protection |

---

## Output Format

Reports are saved in `./results/` (or `--output-dir`):
- `YYYYMMDD_HHMMSS_target.json` — Full structured JSON report
- `YYYYMMDD_HHMMSS_target.txt` — Human-readable executive summary

---

**RECON-DZ v3 — For authorized security assessment only.**
