import socket
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any, cast

import requests

from abuse_ip_checker.config.config import get_api_key
from abuse_ip_checker.domain.models import IPResult

DNSBLS: tuple[str, ...] = (
    "dnsbl.dronebl.org",
    "bl.spamcop.net",
    "dnsbl-1.uceprotect.net",
    "dnsbl.sorbs.net",
)

# --- Retry wrapper ---


def retry_with_backoff[T](
    func: Callable[[], T], max_retries: int = 3, base_delay: float = 1.0
) -> T | None:
    """Call func(). On exception, retry with exponential backoff. Returns None if all retries fail."""
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt < max_retries - 1:
                delay = base_delay * (2**attempt)
                time.sleep(delay)
            else:
                print(f"  Warning: {e} (after {max_retries} attempts)", file=sys.stderr)
                return None
    return None


# --- Helper ---


def reverse_ip(ip: str) -> str:
    """Reverse IP octets for DNSBL lookup."""
    return ".".join(ip.split(".")[::-1])


# --- Response parsers ---


def parse_abuseipdb_response(api_data: dict[str, Any], result: IPResult) -> None:
    """Parse AbuseIPDB check response into IPResult."""
    data = cast(dict[str, Any], api_data.get("data", {}))
    result.abuse_score = data.get("abuseConfidenceScore")
    result.total_reports = data.get("totalReports", 0)
    result.is_whitelisted = data.get("isWhitelisted")
    result.last_reported = data.get("lastReportedAt")
    result.isp = data.get("isp")
    result.usage_type = data.get("usageType")
    result.domain = data.get("domain")
    result.country = data.get("countryName")
    result.city = data.get("city")


def parse_ipinfo_response(api_data: dict[str, Any], result: IPResult) -> None:
    """Parse ipinfo.io response into IPResult."""
    result.hostname = api_data.get("hostname")
    result.org = api_data.get("org")
    if not result.city:
        result.city = api_data.get("city")
    if not result.country:
        result.country = api_data.get("country")


def parse_abuseipdb_reports(api_data: dict[str, Any], result: IPResult) -> None:
    """Parse AbuseIPDB reports response into IPResult."""
    data = cast(dict[str, Any], api_data.get("data", {}))
    reports = cast(list[dict[str, Any]], data.get("results", []))
    for report in reports:
        result.reports.append(
            {
                "reported_at": report.get("reportedAt"),
                "comment": report.get("comment"),
                "categories": report.get("categories"),
                "reporter_country": report.get("reporterCountryCode"),
            }
        )


# --- Source functions ---


def check_abuseipdb(ip: str, result: IPResult, config_path: str | None = None) -> None:
    """Check IP against AbuseIPDB. Requires API key."""
    api_key = get_api_key("abuseipdb", config_path)
    if not api_key:
        return

    def do_check() -> dict[str, Any]:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": api_key},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=10,
        )
        resp.raise_for_status()
        return cast(dict[str, Any], resp.json())

    data = retry_with_backoff(do_check)
    if data:
        parse_abuseipdb_response(data, result)

    # Fetch detailed reports if there are any
    if result.total_reports and result.total_reports > 0 and not result.is_whitelisted:

        def do_reports() -> dict[str, Any]:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/reports",
                headers={"Accept": "application/json", "Key": api_key},
                params={"ipAddress": ip, "maxAgeInDays": "90", "perPage": "25", "page": "1"},
                timeout=10,
            )
            resp.raise_for_status()
            return cast(dict[str, Any], resp.json())

        reports_data = retry_with_backoff(do_reports)
        if reports_data:
            parse_abuseipdb_reports(reports_data, result)


def check_virustotal(ip: str, result: IPResult, config_path: str | None = None) -> None:
    """Check IP against VirusTotal. Requires API key."""
    api_key = get_api_key("virustotal", config_path)
    if not api_key:
        return

    def do_check() -> dict[str, Any]:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        resp.raise_for_status()
        return cast(dict[str, Any], resp.json())

    data = retry_with_backoff(do_check)
    if data:
        attrs = cast(dict[str, Any], data.get("data", {})).get("attributes", {})
        stats = cast(dict[str, Any], attrs).get("last_analysis_stats", {})
        result.virustotal_score = cast(dict[str, Any], stats).get("malicious", 0)


def check_shodan(ip: str, result: IPResult, config_path: str | None = None) -> None:
    """Check IP against Shodan. Requires API key."""
    api_key = get_api_key("shodan", config_path)
    if not api_key:
        return

    def do_check() -> dict[str, Any]:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=10,
        )
        resp.raise_for_status()
        return cast(dict[str, Any], resp.json())

    data = retry_with_backoff(do_check)
    if data:
        result.shodan_ports = cast(list[int], data.get("ports", []))


def check_dns_blocklists(ip: str, result: IPResult) -> None:
    """Check IP against DNS-based blocklists. No API key needed.

    Limitation: gethostbyname can't distinguish "not listed" (NXDOMAIN)
    from "DNSBL unreachable". Both surface as gaierror and we treat them
    both as "not listed", so a DNSBL outage will silently undercount.
    """
    rev = reverse_ip(ip)
    prev_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3)
    try:
        for bl in DNSBLS:
            try:
                socket.gethostbyname(f"{rev}.{bl}")
                result.dns_blocklists.append(bl)
            except socket.gaierror:
                pass  # Not listed (or DNSBL unreachable — see docstring)
            except TimeoutError:
                pass
    finally:
        socket.setdefaulttimeout(prev_timeout)


def check_whois(ip: str, result: IPResult) -> None:
    """Get reverse DNS and WHOIS org for an IP. No API key needed.

    The `ip` argument is validated by `is_valid_ip` (ipaddress.ip_address)
    upstream before reaching this function, so it can never contain shell
    metacharacters — bandit's B603/B607 warnings are false positives here.
    Failures of dig/whois (binary missing, network down) are deliberately
    silent: this is enrichment, not a hard requirement.
    """
    try:
        proc = subprocess.run(  # nosec B603 B607
            ["dig", "+short", "-x", ip],
            capture_output=True,
            text=True,
            timeout=5,
        )
        rdns = proc.stdout.strip()
        if rdns and not result.hostname:
            result.hostname = rdns
    except Exception:  # nosec B110
        pass

    try:
        proc = subprocess.run(  # nosec B603 B607
            ["whois", ip],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in proc.stdout.splitlines():
            lower = line.lower()
            if (
                lower.startswith("orgname:")
                and not result.org
                or lower.startswith("org-name:")
                and not result.org
            ):
                result.org = line.split(":", 1)[1].strip()
    except Exception:  # nosec B110
        pass


def check_ipinfo(ip: str, result: IPResult) -> None:
    """Get geolocation and org from ipinfo.io. No API key needed."""

    def do_check() -> dict[str, Any]:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        resp.raise_for_status()
        return cast(dict[str, Any], resp.json())

    data = retry_with_backoff(do_check, max_retries=2, base_delay=0.5)
    if data:
        parse_ipinfo_response(data, result)


def fetch_abuseipdb_blacklist(
    api_key: str, confidence_minimum: int = 75
) -> list[dict[str, Any]] | None:
    """Fetch the AbuseIPDB blacklist (IPs at >= confidence_minimum). Returns list or None."""

    def do_fetch() -> list[dict[str, Any]]:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"confidenceMinimum": confidence_minimum},
            timeout=30,
        )
        resp.raise_for_status()
        body = cast(dict[str, Any], resp.json())
        return cast(list[dict[str, Any]], body.get("data", []))

    return retry_with_backoff(do_fetch)


def check_all_sources(ip: str, config_path: str | None = None) -> IPResult:
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
