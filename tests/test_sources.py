import time
from unittest.mock import patch, MagicMock
from abuse_ip_checker.clients.sources import retry_with_backoff, parse_abuseipdb_response, parse_ipinfo_response, reverse_ip, check_dns_blocklists
from abuse_ip_checker.domain.models import IPResult


def test_reverse_ip():
    assert reverse_ip("1.2.3.4") == "4.3.2.1"
    assert reverse_ip("192.168.0.1") == "1.0.168.192"


def test_retry_with_backoff_succeeds_first_try():
    func = MagicMock(return_value={"data": "ok"})
    result = retry_with_backoff(func, max_retries=3, base_delay=0.01)
    assert result == {"data": "ok"}
    assert func.call_count == 1


def test_retry_with_backoff_succeeds_after_failure():
    func = MagicMock(side_effect=[Exception("fail"), Exception("fail"), {"data": "ok"}])
    result = retry_with_backoff(func, max_retries=3, base_delay=0.01)
    assert result == {"data": "ok"}
    assert func.call_count == 3


def test_retry_with_backoff_all_retries_exhausted():
    func = MagicMock(side_effect=Exception("always fails"))
    result = retry_with_backoff(func, max_retries=3, base_delay=0.01)
    assert result is None
    assert func.call_count == 3


def test_retry_with_backoff_delays_increase():
    call_times = []
    def timed_func():
        call_times.append(time.time())
        raise Exception("fail")
    retry_with_backoff(timed_func, max_retries=3, base_delay=0.05)
    # Second gap should be roughly 2x the first gap
    if len(call_times) == 3:
        gap1 = call_times[1] - call_times[0]
        gap2 = call_times[2] - call_times[1]
        assert gap2 > gap1 * 1.5  # allow some tolerance


def test_parse_abuseipdb_response():
    api_data = {
        "data": {
            "ipAddress": "1.2.3.4",
            "isWhitelisted": True,
            "abuseConfidenceScore": 0,
            "totalReports": 1,
            "lastReportedAt": "2026-04-01T00:00:00+00:00",
            "isp": "Google LLC",
            "usageType": "Data Center/Web Hosting/Transit",
            "domain": "google.com",
            "countryName": "United States",
            "city": "Mountain View",
        }
    }
    result = IPResult(ip="1.2.3.4")
    parse_abuseipdb_response(api_data, result)
    assert result.abuse_score == 0
    assert result.is_whitelisted is True
    assert result.isp == "Google LLC"
    assert result.domain == "google.com"
    assert result.country == "United States"


def test_parse_ipinfo_response():
    api_data = {
        "ip": "1.2.3.4",
        "hostname": "server.example.com",
        "org": "AS15169 Google LLC",
        "city": "Mountain View",
        "region": "California",
        "country": "US",
    }
    result = IPResult(ip="1.2.3.4")
    parse_ipinfo_response(api_data, result)
    assert result.hostname == "server.example.com"
    assert result.org == "AS15169 Google LLC"
    assert result.city == "Mountain View"
    assert result.country == "US"
