import json
import tempfile
import os
from abuse_ip_checker.services.littlesnitch import parse_littlesnitch_export, is_public_ip, is_domain


def _make_export(rules):
    """Helper: create a minimal LS export JSON with given rules."""
    return {"rules": rules}


def test_extracts_public_ips_from_allow_rules():
    export = _make_export([
        {"action": "allow", "remote-addresses": "1.2.3.4", "process": "com.example.app"},
        {"action": "deny", "remote-addresses": "5.6.7.8", "process": "com.example.app"},
    ])
    results = parse_littlesnitch_export(export)
    ips = [r["ip"] for r in results]
    assert "1.2.3.4" in ips
    assert "5.6.7.8" not in ips  # deny rules are excluded


def test_filters_out_private_ips():
    export = _make_export([
        {"action": "allow", "remote-addresses": "192.168.0.1", "process": "com.example.app"},
        {"action": "allow", "remote-addresses": "10.0.0.1", "process": "com.example.app"},
        {"action": "allow", "remote-addresses": "127.0.0.1", "process": "com.example.app"},
        {"action": "allow", "remote-addresses": "8.8.8.8", "process": "com.example.app"},
    ])
    results = parse_littlesnitch_export(export)
    ips = [r["ip"] for r in results]
    assert ips == ["8.8.8.8"]


def test_filters_out_ipv6_link_local():
    export = _make_export([
        {"action": "allow", "remote-addresses": "fe80::1", "process": "com.example.app"},
        {"action": "allow", "remote-addresses": "8.8.8.8", "process": "com.example.app"},
    ])
    results = parse_littlesnitch_export(export)
    ips = [r["ip"] for r in results]
    assert ips == ["8.8.8.8"]


def test_extracts_domains_from_remote_hosts():
    export = _make_export([
        {"action": "allow", "remote-hosts": "example.com", "process": "com.example.app"},
    ])
    results = parse_littlesnitch_export(export)
    assert len(results) == 1
    assert results[0]["domain"] == "example.com"


def test_deduplicates_ips():
    export = _make_export([
        {"action": "allow", "remote-addresses": "8.8.8.8", "process": "com.app1"},
        {"action": "allow", "remote-addresses": "8.8.8.8", "process": "com.app2"},
    ])
    results = parse_littlesnitch_export(export)
    ips = [r["ip"] for r in results]
    assert ips.count("8.8.8.8") == 1


def test_collects_associated_processes():
    export = _make_export([
        {"action": "allow", "remote-addresses": "8.8.8.8", "process": "com.app1"},
        {"action": "allow", "remote-addresses": "8.8.8.8", "process": "com.app2"},
    ])
    results = parse_littlesnitch_export(export)
    assert len(results) == 1
    assert "com.app1" in results[0]["processes"]
    assert "com.app2" in results[0]["processes"]


def test_load_from_file():
    export = _make_export([
        {"action": "allow", "remote-addresses": "1.2.3.4", "process": "com.example.app"},
    ])
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(export, f)
        path = f.name
    try:
        from abuse_ip_checker.services.littlesnitch import load_littlesnitch_file
        results = load_littlesnitch_file(path)
        assert len(results) == 1
        assert results[0]["ip"] == "1.2.3.4"
    finally:
        os.unlink(path)


def test_filters_full_rfc1918_172_range():
    # RFC 1918 reserves 172.16.0.0/12 = 172.16.0.0 - 172.31.255.255
    assert is_public_ip("172.16.0.1") is False
    assert is_public_ip("172.20.0.1") is False
    assert is_public_ip("172.31.255.254") is False
    # Just outside the range is public
    assert is_public_ip("172.32.0.1") is True


def test_filters_link_local_169_254():
    # IPv4 link-local / APIPA, includes the AWS/Azure metadata IP
    assert is_public_ip("169.254.0.1") is False
    assert is_public_ip("169.254.169.254") is False


def test_filters_full_multicast_range():
    # IANA multicast is 224.0.0.0/4 = 224 through 239
    assert is_public_ip("224.0.0.1") is False
    assert is_public_ip("239.255.255.250") is False  # SSDP
    assert is_public_ip("225.0.0.1") is False


def test_is_domain_accepts_leading_digit_hostnames():
    # RFC 1123 allows hostnames to start with a digit
    assert is_domain("1example.com") is True
    assert is_domain("3com.com") is True
    # IPs are not domains
    assert is_domain("8.8.8.8") is False
