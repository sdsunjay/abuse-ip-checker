import json
import ipaddress
import socket


PRIVATE_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "192.168.", "127.", "0.0.0.0", "224.", "255."]


def is_public_ip(addr):
    """Check if an address is a public IPv4 address."""
    if not addr or ":" in addr:  # skip IPv6 including fe80::
        return False
    for prefix in PRIVATE_PREFIXES:
        if addr.startswith(prefix):
            return False
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def is_domain(val):
    """Check if a value looks like a domain (not an IP)."""
    if not val:
        return False
    return not val[0].isdigit() and "." in val and ":" not in val


def parse_littlesnitch_export(export_data):
    """Parse a Little Snitch export dict. Returns list of dicts with ip/domain and processes.

    Returns: [{"ip": "1.2.3.4", "domain": None, "processes": ["com.app1"]}, ...]
    """
    rules = export_data.get("rules", [])
    allow_rules = [r for r in rules if r.get("action") == "allow"]

    # Collect targets: key is ip or domain, value is set of processes
    ip_targets = {}   # ip -> set of processes
    domain_targets = {}  # domain -> set of processes

    for rule in allow_rules:
        process = rule.get("process", "unknown")

        for field in ["remote-addresses", "remote-hosts", "remote-domains"]:
            val = str(rule.get(field, ""))
            if not val:
                continue

            for part in val.split(","):
                part = part.strip().strip("'\"[]")
                if not part:
                    continue

                if is_public_ip(part):
                    ip_targets.setdefault(part, set()).add(process)
                elif is_domain(part):
                    domain_targets.setdefault(part, set()).add(process)

    results = []
    for ip, procs in sorted(ip_targets.items()):
        results.append({"ip": ip, "domain": None, "processes": sorted(procs)})
    for domain, procs in sorted(domain_targets.items()):
        results.append({"ip": None, "domain": domain, "processes": sorted(procs)})

    return results


def load_littlesnitch_file(filepath):
    """Load a Little Snitch export JSON file and parse it."""
    with open(filepath, "r") as f:
        data = json.load(f)
    return parse_littlesnitch_export(data)


def resolve_domain(domain):
    """Resolve a domain to an IP address. Returns None on failure."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None
