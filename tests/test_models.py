from abuse_ip_checker.domain.models import IPResult, compute_threat_level


def test_ip_result_defaults():
    result = IPResult(ip="1.2.3.4")
    assert result.ip == "1.2.3.4"
    assert result.hostname is None
    assert result.abuse_score is None
    assert result.total_reports == 0
    assert result.dns_blocklists == []
    assert result.reports == []
    assert result.threat_level == "CLEAN"
    assert result.associated_processes is None


def test_threat_level_clean():
    assert compute_threat_level(abuse_score=0, total_reports=0, virustotal_score=None, dns_blocklists=[]) == "CLEAN"
    assert compute_threat_level(abuse_score=None, total_reports=0, virustotal_score=None, dns_blocklists=[]) == "CLEAN"


def test_threat_level_low():
    assert compute_threat_level(abuse_score=5, total_reports=1, virustotal_score=None, dns_blocklists=[]) == "LOW"
    assert compute_threat_level(abuse_score=0, total_reports=3, virustotal_score=None, dns_blocklists=[]) == "LOW"
    assert compute_threat_level(abuse_score=None, total_reports=0, virustotal_score=2, dns_blocklists=[]) == "LOW"


def test_threat_level_warning():
    assert compute_threat_level(abuse_score=25, total_reports=10, virustotal_score=None, dns_blocklists=[]) == "WARNING"
    assert compute_threat_level(abuse_score=0, total_reports=0, virustotal_score=5, dns_blocklists=[]) == "WARNING"
    assert compute_threat_level(abuse_score=0, total_reports=0, virustotal_score=None, dns_blocklists=["dnsbl.dronebl.org"]) == "WARNING"
    assert compute_threat_level(abuse_score=0, total_reports=0, virustotal_score=None, dns_blocklists=["a", "b"]) == "WARNING"


def test_threat_level_critical():
    assert compute_threat_level(abuse_score=75, total_reports=50, virustotal_score=None, dns_blocklists=[]) == "CRITICAL"
    assert compute_threat_level(abuse_score=0, total_reports=0, virustotal_score=10, dns_blocklists=[]) == "CRITICAL"
    assert compute_threat_level(abuse_score=0, total_reports=0, virustotal_score=None, dns_blocklists=["a", "b", "c"]) == "CRITICAL"


def test_threat_level_highest_wins():
    assert compute_threat_level(abuse_score=80, total_reports=5, virustotal_score=12, dns_blocklists=["a", "b", "c"]) == "CRITICAL"


def test_ip_result_to_dict():
    result = IPResult(ip="1.2.3.4", isp="Google LLC", abuse_score=38, total_reports=5)
    d = result.to_dict()
    assert d["ip"] == "1.2.3.4"
    assert d["isp"] == "Google LLC"
    assert d["abuse_score"] == 38
    assert d["threat_level"] == "WARNING"
