# Abuse IP Checker

A multi-source threat intelligence CLI tool that checks IP addresses against AbuseIPDB, VirusTotal, Shodan, DNS blocklists, WHOIS, and ipinfo.io. Includes built-in Little Snitch integration for auditing macOS firewall rules.

## Setup

This project is managed with [uv](https://docs.astral.sh/uv/). Install uv first if you don't have it:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd abuse-ip-checker
   ```

2. Create a venv and install the project (Python 3.12+ required):
   ```bash
   uv venv
   uv pip install -e .
   ```
   This installs the `abuse-ip-checker` console script into `.venv/bin`. Use `uv run abuse-ip-checker ...` to invoke it without activating the venv.

3. Configure API keys:
   ```bash
   uv run abuse-ip-checker configure
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
uv run abuse-ip-checker check --ip 8.8.8.8

# Check a domain
uv run abuse-ip-checker check --domain example.com

# Check IPs/domains from a file (one per line)
uv run abuse-ip-checker check -f ips.txt

# JSON output (for piping to other tools)
uv run abuse-ip-checker check -f ips.txt --json

# Verbose output (full details per IP)
uv run abuse-ip-checker check -f ips.txt -v
```

### Scan Little Snitch Rules

Audit all allowed connections in a Little Snitch export:

```bash
# Export your Little Snitch rules (requires sudo):
sudo /Applications/Little\ Snitch.app/Contents/Components/littlesnitch export-model /tmp/ls_rules.json

# Scan all allowed IPs:
uv run abuse-ip-checker scan-littlesnitch /tmp/ls_rules.json

# With JSON or verbose output:
uv run abuse-ip-checker scan-littlesnitch /tmp/ls_rules.json --json
uv run abuse-ip-checker scan-littlesnitch /tmp/ls_rules.json -v
```

### Download Blacklist

Download the AbuseIPDB blacklist (top 10,000 most reported IPs):

```bash
uv run abuse-ip-checker blacklist
```

### Configure API Keys

```bash
uv run abuse-ip-checker configure
```

## Example Output

```bash
$ uv run abuse-ip-checker scan-littlesnitch /tmp/ls_model.json
```
```text
Parsing Little Snitch export: /tmp/ls_rules.json

Found 251 unique targets in allow rules.
Checking 209 public IPs...

-------------------------------------------------------------------------------------------
IP                   Threat     Score   Reports   Org                            Country
-------------------------------------------------------------------------------------------
#.#.#.#              CRITICAL   94      140       Resource Quality Assurance     -
160.79.104.10        WARNING    38      30        AS399358 Anthropic, PBC        -
185.199.108.153      WARNING    30      8         AS54113 Fastly, Inc.           -
104.16.175.226       LOW        0       6         AS13335 Cloudflare, Inc.       -
8.8.8.8              LOW        0       52        AS15169 Google LLC             -
140.82.113.17        CLEAN      0       0         AS36459 GitHub, Inc.           -
...
-------------------------------------------------------------------------------------------
209 IPs checked  154 CLEAN  48 LOW  6 WARNING  1 CRITICAL
-------------------------------------------------------------------------------------------
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

## Development

Install dev tooling and pre-commit hooks:

```bash
uv tool install pre-commit
pre-commit install
```

Run the test suite:

```bash
uv run --with pytest pytest tests/
```

Lint and format manually (pre-commit runs both on every commit):

```bash
uv tool run --from ruff ruff check --fix .
uv tool run --from ruff ruff format .
```

## License

MIT
