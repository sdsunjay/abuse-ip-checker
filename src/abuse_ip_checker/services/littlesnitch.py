import ipaddress
import json
import socket
from typing import Any, cast


def is_public_ip(addr: str | None) -> bool:
    """Return True iff addr is a routable public IPv4 address.

    IPv6 is intentionally skipped — this checker is IPv4-only.
    Uses ipaddress for classification so RFC 1918 (10/8, 172.16/12,
    192.168/16), loopback (127/8), link-local (169.254/16),
    multicast (224/4), reserved (240/4), and 0.0.0.0 are all caught.
    """
    if not addr or ":" in addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_domain(val: str | None) -> bool:
    """Return True iff val looks like a domain rather than an IP literal."""
    if not val or ":" in val or "." not in val:
        return False
    try:
        ipaddress.ip_address(val)
        return False  # Parses as an IP, not a domain
    except ValueError:
        return True


def parse_littlesnitch_export(export_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a Little Snitch export dict. Returns list of dicts with ip/domain and processes.

    Returns: [{"ip": "1.2.3.4", "domain": None, "processes": ["com.app1"]}, ...]
    """
    rules = cast(list[dict[str, Any]], export_data.get("rules", []))
    allow_rules = [r for r in rules if r.get("action") == "allow"]

    # Collect targets: key is ip or domain, value is set of processes
    ip_targets: dict[str, set[str]] = {}
    domain_targets: dict[str, set[str]] = {}

    for rule in allow_rules:
        process = str(rule.get("process", "unknown"))

        for key in ["remote-addresses", "remote-hosts", "remote-domains"]:
            val = str(rule.get(key, ""))
            if not val:
                continue

            for raw_part in val.split(","):
                part = raw_part.strip().strip("'\"[]")
                if not part:
                    continue

                if is_public_ip(part):
                    ip_targets.setdefault(part, set()).add(process)
                elif is_domain(part):
                    domain_targets.setdefault(part, set()).add(process)

    results: list[dict[str, Any]] = []
    for ip, procs in sorted(ip_targets.items()):
        results.append({"ip": ip, "domain": None, "processes": sorted(procs)})
    for domain, procs in sorted(domain_targets.items()):
        results.append({"ip": None, "domain": domain, "processes": sorted(procs)})

    return results


def load_littlesnitch_file(filepath: str) -> list[dict[str, Any]]:
    """Load a Little Snitch export JSON file and parse it."""
    with open(filepath, encoding="utf-8") as f:
        data = cast(dict[str, Any], json.load(f))
    return parse_littlesnitch_export(data)


def resolve_domain(domain: str) -> str | None:
    """Resolve a domain to an IP address. Returns None on failure."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None
