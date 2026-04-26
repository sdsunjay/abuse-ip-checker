import time
import subprocess
import socket
import requests
from abuse_ip_checker.domain.models import IPResult
from abuse_ip_checker.config.config import get_api_key

# --- Retry wrapper ---

def retry_with_backoff(func, max_retries=3, base_delay=1.0):
    """Call func(). On exception, retry with exponential backoff. Returns None if all retries fail."""
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                time.sleep(delay)
            else:
                print(f"  Warning: {e} (after {max_retries} attempts)")
                return None


# --- Helper ---

def reverse_ip(ip):
    """Reverse IP octets for DNSBL lookup."""
    return ".".join(ip.split(".")[::-1])


# --- Response parsers ---

def parse_abuseipdb_response(api_data, result):
    """Parse AbuseIPDB check response into IPResult."""
    data = api_data.get("data", {})
    result.abuse_score = data.get("abuseConfidenceScore")
    result.total_reports = data.get("totalReports", 0)
    result.is_whitelisted = data.get("isWhitelisted")
    result.last_reported = data.get("lastReportedAt")
    result.isp = data.get("isp")
    result.usage_type = data.get("usageType")
    result.domain = data.get("domain")
    result.country = data.get("countryName")
    result.city = data.get("city")


def parse_ipinfo_response(api_data, result):
    """Parse ipinfo.io response into IPResult."""
    result.hostname = api_data.get("hostname")
    result.org = api_data.get("org")
    if not result.city:
        result.city = api_data.get("city")
    if not result.country:
        result.country = api_data.get("country")


def parse_abuseipdb_reports(api_data, result):
    """Parse AbuseIPDB reports response into IPResult."""
    data = api_data.get("data", {})
    reports = data.get("results", [])
    for report in reports:
        result.reports.append({
            "reported_at": report.get("reportedAt"),
            "comment": report.get("comment"),
            "categories": report.get("categories"),
            "reporter_country": report.get("reporterCountryCode"),
        })


# --- Source functions ---

def check_abuseipdb(ip, result, config_path=None):
    """Check IP against AbuseIPDB. Requires API key."""
    api_key = get_api_key("abuseipdb", config_path)
    if not api_key:
        return

    def do_check():
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": api_key},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    data = retry_with_backoff(do_check)
    if data:
        parse_abuseipdb_response(data, result)

    # Fetch detailed reports if there are any
    if result.total_reports and result.total_reports > 0 and not result.is_whitelisted:
        def do_reports():
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/reports",
                headers={"Accept": "application/json", "Key": api_key},
                params={"ipAddress": ip, "maxAgeInDays": "90", "perPage": "25", "page": "1"},
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()

        reports_data = retry_with_backoff(do_reports)
        if reports_data:
            parse_abuseipdb_reports(reports_data, result)


def check_virustotal(ip, result, config_path=None):
    """Check IP against VirusTotal. Requires API key."""
    api_key = get_api_key("virustotal", config_path)
    if not api_key:
        return

    def do_check():
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    data = retry_with_backoff(do_check)
    if data:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result.virustotal_score = stats.get("malicious", 0)


def check_shodan(ip, result, config_path=None):
    """Check IP against Shodan. Requires API key."""
    api_key = get_api_key("shodan", config_path)
    if not api_key:
        return

    def do_check():
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    data = retry_with_backoff(do_check)
    if data:
        result.shodan_ports = data.get("ports", [])


def check_dns_blocklists(ip, result):
    """Check IP against DNS-based blocklists. No API key needed."""
    blocklists = [
        "dnsbl.dronebl.org",
        "bl.spamcop.net",
        "dnsbl-1.uceprotect.net",
        "dnsbl.sorbs.net",
    ]
    rev = reverse_ip(ip)
    for bl in blocklists:
        try:
            query = f"{rev}.{bl}"
            socket.setdefaulttimeout(3)
            socket.gethostbyname(query)
            # If it resolves, the IP is listed
            result.dns_blocklists.append(bl)
        except socket.gaierror:
            pass  # Not listed
        except socket.timeout:
            pass  # Timeout, skip


def check_whois(ip, result):
    """Get reverse DNS and WHOIS org for an IP. No API key needed."""
    try:
        proc = subprocess.run(
            ["dig", "+short", "-x", ip],
            capture_output=True, text=True, timeout=5,
        )
        rdns = proc.stdout.strip()
        if rdns and not result.hostname:
            result.hostname = rdns
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["whois", ip],
            capture_output=True, text=True, timeout=10,
        )
        for line in proc.stdout.splitlines():
            lower = line.lower()
            if lower.startswith("orgname:") and not result.org:
                result.org = line.split(":", 1)[1].strip()
            elif lower.startswith("org-name:") and not result.org:
                result.org = line.split(":", 1)[1].strip()
    except Exception:
        pass


def check_ipinfo(ip, result):
    """Get geolocation and org from ipinfo.io. No API key needed."""
    def do_check():
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        resp.raise_for_status()
        return resp.json()

    data = retry_with_backoff(do_check, max_retries=2, base_delay=0.5)
    if data:
        parse_ipinfo_response(data, result)


def check_all_sources(ip, config_path=None):
    """Run all configured sources against an IP. Returns populated IPResult."""
    result = IPResult(ip=ip)

    # Free sources (always run)
    check_dns_blocklists(ip, result)
    check_ipinfo(ip, result)
    check_whois(ip, result)

    # Paid sources (run if key configured)
    check_abuseipdb(ip, result, config_path)
    check_virustotal(ip, result, config_path)
    check_shodan(ip, result, config_path)

    return result
