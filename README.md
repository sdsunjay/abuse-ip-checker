# Abuse IP Checker

A multi-source threat intelligence CLI tool that checks IP addresses against AbuseIPDB, VirusTotal, Shodan, DNS blocklists, WHOIS, and ipinfo.io. Includes built-in Little Snitch integration for auditing macOS firewall rules.

## Setup

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd abuse-ip-checker
   ```

2. Install dependencies (Python 3.10+ required):
   ```bash
   pip install -r requirements.txt
   ```
   Or with pyproject.toml:
   ```bash
   pip install .
   ```

3. Configure API keys:
   ```bash
   python solution.py configure
   ```
   This saves keys to `~/.abuse-ip-checker/config.yaml` (file `0600`, dir `0700`, so only your user can read it). You can also set environment variables, which **override** any value in the YAML config:
   - `ABUSEIPDB_API_KEY`
   - `VIRUSTOTAL_API_KEY` (optional)
   - `SHODAN_API_KEY` (optional)

   Free sources (DNS blocklists, WHOIS, ipinfo.io) always run and need no API key.

   > **Note:** `constants.py` exists only as a backwards-compatibility shim that re-exports the resolved AbuseIPDB key from the config layer. It is not a hardcoded-key file — do not put secrets in it.

## Usage

### Check IP Addresses

```bash
# Check a single IP
python solution.py check --ip 1.2.3.4

# Check a domain
python solution.py check --domain example.com

# Check IPs from a file (one per line, IPs or domains)
python solution.py check -f ips.txt

# JSON output (for piping to other tools)
python solution.py check -f ips.txt --json

# Verbose output (full details per IP)
python solution.py check -f ips.txt -v
```

### Scan Little Snitch Rules

Audit all allowed connections in a Little Snitch export:

```bash
# Export your Little Snitch rules (requires sudo):
sudo /Applications/Little\ Snitch.app/Contents/Components/littlesnitch export-model /tmp/ls_rules.json

# Scan all allowed IPs:
python solution.py scan-littlesnitch /tmp/ls_rules.json

# With JSON or verbose output:
python solution.py scan-littlesnitch /tmp/ls_rules.json --json
python solution.py scan-littlesnitch /tmp/ls_rules.json -v
```

### Download Blacklist

Download the AbuseIPDB blacklist (top 10,000 most reported IPs):

```bash
python solution.py blacklist
```

### Configure API Keys

```bash
python solution.py configure
```

## Threat Intelligence Sources

| Source | API Key Required | What It Checks |
|--------|-----------------|----------------|
| DNS Blocklists | No | DroneBL, SpamCop, SORBS, UCEProtect |
| WHOIS / Reverse DNS | No | Org name, hostname |
| ipinfo.io | No | Geolocation, ISP, org |
| AbuseIPDB | Yes | Abuse score, reports, ISP |
| VirusTotal | Yes (optional) | Malware detections |
| Shodan | Yes (optional) | Open ports, services |

> **DNSBL caveat:** A DNS blocklist lookup that comes back empty is reported as "not listed", but this is indistinguishable from the case where the DNSBL server is unreachable or rate-limiting us. Treat a clean DNSBL result as "no positive evidence of listing", not as a guarantee the IP is absent from the list.

## Threat Levels

Each IP gets a computed threat level based on combined findings:

| Level | Criteria |
|-------|----------|
| CRITICAL | Abuse score >= 75, or VT score >= 10, or on 3+ blocklists |
| WARNING | Abuse score >= 25, or VT score >= 5, or on 1-2 blocklists |
| LOW | Any abuse score > 0, or any reports, or VT score > 0 |
| CLEAN | No indicators from any source |

## Output Formats

- **Default**: Summary table with threat level, score, org, country
- **`--verbose` / `-v`**: Full details including reports, blocklists, WHOIS
- **`--json`**: JSON array for programmatic use

## License

MIT
