import json
from abuse_ip_checker.domain.models import IPResult


def format_table(results):
    """Format results as a summary table with threat levels."""
    if not results:
        return "No IPs to display."

    # Header
    header = f"{'IP':<20} {'Threat':<10} {'Score':<7} {'Reports':<9} {'Org':<30} {'Country':<10}"
    separator = "-" * len(header)
    lines = [separator, header, separator]

    for r in sorted(results, key=lambda x: _threat_sort_key(x.threat_level)):
        score = str(r.abuse_score) if r.abuse_score is not None else "-"
        org = (r.org or r.isp or "-")[:29]
        country = r.country or "-"
        lines.append(f"{r.ip:<20} {r.threat_level:<10} {score:<7} {r.total_reports:<9} {org:<30} {country:<10}")

    lines.append(separator)

    # Summary
    total = len(results)
    counts = {}
    for r in results:
        counts[r.threat_level] = counts.get(r.threat_level, 0) + 1

    summary_parts = [f"{total} IPs checked"]
    for level in ["CLEAN", "LOW", "WARNING", "CRITICAL"]:
        if level in counts:
            summary_parts.append(f"{counts[level]} {level}")
    lines.append("  ".join(summary_parts))
    lines.append(separator)

    return "\n".join(lines)


def format_verbose(results):
    """Format results with full detail per IP."""
    if not results:
        return "No IPs to display."

    sections = []
    for r in sorted(results, key=lambda x: _threat_sort_key(x.threat_level)):
        lines = [f"{'='*60}", f"IP: {r.ip}  [{r.threat_level}]", f"{'='*60}"]

        if r.hostname:
            lines.append(f"  Hostname:     {r.hostname}")
        if r.isp:
            lines.append(f"  ISP:          {r.isp}")
        if r.org:
            lines.append(f"  Org:          {r.org}")
        if r.domain:
            lines.append(f"  Domain:       {r.domain}")
        if r.country:
            lines.append(f"  Country:      {r.country}")
        if r.city:
            lines.append(f"  City:         {r.city}")
        if r.usage_type:
            lines.append(f"  Usage Type:   {r.usage_type}")

        lines.append("")
        lines.append(f"  Abuse Score:  {r.abuse_score if r.abuse_score is not None else 'N/A'}")
        lines.append(f"  Reports:      {r.total_reports}")
        lines.append(f"  Whitelisted:  {r.is_whitelisted if r.is_whitelisted is not None else 'N/A'}")
        lines.append(f"  Last Report:  {r.last_reported or 'N/A'}")

        if r.virustotal_score is not None:
            lines.append(f"  VT Score:     {r.virustotal_score}")
        if r.shodan_ports:
            lines.append(f"  Open Ports:   {', '.join(str(p) for p in r.shodan_ports)}")

        if r.dns_blocklists:
            lines.append(f"\n  DNS Blocklists ({len(r.dns_blocklists)}):")
            for bl in r.dns_blocklists:
                lines.append(f"    - {bl}")

        if r.reports:
            lines.append(f"\n  Abuse Reports ({len(r.reports)}):")
            for report in r.reports[:10]:  # Cap at 10 for readability
                lines.append(f"    [{report.get('reported_at', '?')}] {report.get('comment', 'No comment')}")
                lines.append(f"      Categories: {report.get('categories', [])}, Country: {report.get('reporter_country', '?')}")

        if r.associated_processes:
            lines.append(f"\n  Associated Processes:")
            for proc in r.associated_processes:
                lines.append(f"    - {proc}")

        sections.append("\n".join(lines))

    return "\n\n".join(sections)


def format_json(results):
    """Format results as a JSON array."""
    return json.dumps([r.to_dict() for r in results], indent=2, default=str)


def _threat_sort_key(level):
    """Sort order: CRITICAL first, CLEAN last."""
    order = {"CRITICAL": 0, "WARNING": 1, "LOW": 2, "CLEAN": 3}
    return order.get(level, 4)
