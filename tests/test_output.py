import json

from abuse_ip_checker.domain.models import IPResult
from abuse_ip_checker.utils.output import format_json, format_table, format_verbose


def _make_results():
    clean = IPResult(
        ip="8.8.8.8", isp="Google LLC", org="Google", country="US", abuse_score=0, total_reports=0
    )
    warning = IPResult(
        ip="1.2.3.4", isp="Bad ISP", org="Bad Org", country="RU", abuse_score=38, total_reports=30
    )
    critical = IPResult(
        ip="5.6.7.8",
        isp="Worst ISP",
        org="Worst",
        country="CN",
        abuse_score=90,
        total_reports=100,
        dns_blocklists=["dnsbl.dronebl.org"],
    )
    return [clean, warning, critical]


def test_format_table_contains_all_ips():
    results = _make_results()
    output = format_table(results)
    assert "8.8.8.8" in output
    assert "1.2.3.4" in output
    assert "5.6.7.8" in output


def test_format_table_contains_threat_levels():
    results = _make_results()
    output = format_table(results)
    assert "CLEAN" in output
    assert "WARNING" in output
    assert "CRITICAL" in output


def test_format_table_summary_line():
    results = _make_results()
    output = format_table(results)
    assert "3 IPs checked" in output
    assert "1 CLEAN" in output


def test_format_verbose_contains_details():
    results = [
        IPResult(
            ip="1.2.3.4",
            isp="Test ISP",
            abuse_score=50,
            total_reports=10,
            dns_blocklists=["dnsbl.dronebl.org"],
            reports=[
                {
                    "reported_at": "2026-01-01",
                    "comment": "Bad actor",
                    "categories": [14],
                    "reporter_country": "US",
                }
            ],
        )
    ]
    output = format_verbose(results)
    assert "1.2.3.4" in output
    assert "Test ISP" in output
    assert "Bad actor" in output
    assert "dnsbl.dronebl.org" in output


def test_format_json_valid():
    results = _make_results()
    output = format_json(results)
    parsed = json.loads(output)
    assert len(parsed) == 3
    assert parsed[0]["ip"] == "8.8.8.8"
    assert parsed[1]["threat_level"] == "WARNING"
    assert parsed[2]["threat_level"] == "CRITICAL"


def test_format_json_roundtrip():
    results = [IPResult(ip="1.2.3.4", abuse_score=50, total_reports=5, dns_blocklists=["a"])]
    output = format_json(results)
    parsed = json.loads(output)
    assert parsed[0]["abuse_score"] == 50
    assert parsed[0]["dns_blocklists"] == ["a"]
