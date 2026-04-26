import json
import re
from typing import Any

from abuse_ip_checker.domain.models import IPResult

_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _safe(s: object) -> str:
    """Strip control characters from third-party / attacker-controlled strings.

    AbuseIPDB report comments are user-submitted; an unsanitized comment with
    ANSI escapes or carriage returns can rewrite or hide terminal output.
    """
    if s is None:
        return ""
    return _CTRL_RE.sub("?", str(s)).replace("\r", " ").replace("\n", " ")


def _truncate(s: str, width: int) -> str:
    if len(s) <= width:
        return s
    return s[: width - 1] + "…"


def format_table(results: list[IPResult]) -> str:
    """Format results as a summary table with threat levels."""
    if not results:
        return "No IPs to display."

    # Header
    header = f"{'IP':<20} {'Threat':<10} {'Score':<7} {'Reports':<9} {'Org':<30} {'Country':<10}"
    separator = "-" * len(header)
    lines = [separator, header, separator]

    for r in sorted(results, key=lambda x: _threat_sort_key(x.threat_level)):
        score = str(r.abuse_score) if r.abuse_score is not None else "-"
        org = _truncate(_safe(r.org or r.isp or "-"), 29)
        country = _safe(r.country or "-")
        lines.append(
            f"{r.ip:<20} {r.threat_level:<10} {score:<7} {r.total_reports:<9} {org:<30} {country:<10}"
        )

    lines.append(separator)

    # Summary
    total = len(results)
    counts: dict[str, int] = {}
    for r in results:
        counts[r.threat_level] = counts.get(r.threat_level, 0) + 1

    summary_parts = [f"{total} IPs checked"]
    for level in ["CLEAN", "LOW", "WARNING", "CRITICAL"]:
        if level in counts:
            summary_parts.append(f"{counts[level]} {level}")
    lines.append("  ".join(summary_parts))
    lines.append(separator)

    return "\n".join(lines)


def format_verbose(results: list[IPResult]) -> str:
    """Format results with full detail per IP."""
    if not results:
        return "No IPs to display."

    sections: list[str] = []
    for r in sorted(results, key=lambda x: _threat_sort_key(x.threat_level)):
        lines = [f"{'=' * 60}", f"IP: {r.ip}  [{r.threat_level}]", f"{'=' * 60}"]

        if r.hostname:
            lines.append(f"  Hostname:     {_safe(r.hostname)}")
        if r.isp:
            lines.append(f"  ISP:          {_safe(r.isp)}")
        if r.org:
            lines.append(f"  Org:          {_safe(r.org)}")
        if r.domain:
            lines.append(f"  Domain:       {_safe(r.domain)}")
        if r.country:
            lines.append(f"  Country:      {_safe(r.country)}")
        if r.city:
            lines.append(f"  City:         {_safe(r.city)}")
        if r.usage_type:
            lines.append(f"  Usage Type:   {_safe(r.usage_type)}")

        lines.append("")
        lines.append(f"  Abuse Score:  {r.abuse_score if r.abuse_score is not None else 'N/A'}")
        lines.append(f"  Reports:      {r.total_reports}")
        lines.append(
            f"  Whitelisted:  {r.is_whitelisted if r.is_whitelisted is not None else 'N/A'}"
        )
        lines.append(f"  Last Report:  {_safe(r.last_reported) or 'N/A'}")

        if r.virustotal_score is not None:
            lines.append(f"  VT Score:     {r.virustotal_score}")
        if r.shodan_ports:
            lines.append(f"  Open Ports:   {', '.join(str(p) for p in r.shodan_ports)}")

        if r.dns_blocklists:
            lines.append(f"\n  DNS Blocklists ({len(r.dns_blocklists)}):")
            for bl in r.dns_blocklists:
                lines.append(f"    - {_safe(bl)}")

        if r.reports:
            lines.append(f"\n  Abuse Reports ({len(r.reports)}):")
            for report in r.reports[:10]:
                reported_at = _safe(report.get("reported_at")) or "?"
                comment = _safe(report.get("comment")) or "No comment"
                country = _safe(report.get("reporter_country")) or "?"
                categories: list[Any] = list(report.get("categories") or [])
                lines.append(f"    [{reported_at}] {comment}")
                lines.append(f"      Categories: {categories}, Country: {country}")
            if len(r.reports) > 10:
                lines.append(f"    ... and {len(r.reports) - 10} more")

        if r.associated_processes:
            lines.append("\n  Associated Processes:")
            for proc in r.associated_processes:
                lines.append(f"    - {_safe(proc)}")

        sections.append("\n".join(lines))

    return "\n\n".join(sections)


def format_json(results: list[IPResult]) -> str:
    """Format results as a JSON array."""
    return json.dumps([r.to_dict() for r in results], indent=2, default=str)


def _threat_sort_key(level: str) -> int:
    """Sort order: CRITICAL first, CLEAN last."""
    order = {"CRITICAL": 0, "WARNING": 1, "LOW": 2, "CLEAN": 3}
    return order.get(level, 4)
