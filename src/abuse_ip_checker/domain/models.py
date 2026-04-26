from dataclasses import dataclass, field
from typing import Any


def _empty_str_list() -> list[str]:
    return []


def _empty_report_list() -> list[dict[str, Any]]:
    return []


def compute_threat_level(
    abuse_score: int | None,
    total_reports: int | None,
    virustotal_score: int | None,
    dns_blocklists: list[str] | None,
) -> str:
    """Compute threat level from combined source findings."""
    abuse = abuse_score or 0
    vt = virustotal_score or 0
    bl_count = len(dns_blocklists) if dns_blocklists else 0

    if abuse >= 75 or vt >= 10 or bl_count >= 3:
        return "CRITICAL"
    if abuse >= 25 or vt >= 5 or bl_count >= 1:
        return "WARNING"
    if abuse > 0 or (total_reports or 0) > 0 or vt > 0:
        return "LOW"
    return "CLEAN"


@dataclass
class IPResult:
    ip: str
    hostname: str | None = None
    isp: str | None = None
    org: str | None = None
    domain: str | None = None
    country: str | None = None
    city: str | None = None
    usage_type: str | None = None
    abuse_score: int | None = None
    total_reports: int = 0
    is_whitelisted: bool | None = None
    last_reported: str | None = None
    virustotal_score: int | None = None
    shodan_ports: list[int] | None = None
    dns_blocklists: list[str] = field(default_factory=_empty_str_list)
    reports: list[dict[str, Any]] = field(default_factory=_empty_report_list)
    associated_processes: list[str] | None = None

    @property
    def threat_level(self) -> str:
        return compute_threat_level(
            self.abuse_score, self.total_reports, self.virustotal_score, self.dns_blocklists
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "isp": self.isp,
            "org": self.org,
            "domain": self.domain,
            "country": self.country,
            "city": self.city,
            "usage_type": self.usage_type,
            "abuse_score": self.abuse_score,
            "total_reports": self.total_reports,
            "is_whitelisted": self.is_whitelisted,
            "last_reported": self.last_reported,
            "virustotal_score": self.virustotal_score,
            "shodan_ports": self.shodan_ports,
            "dns_blocklists": self.dns_blocklists,
            "reports": self.reports,
            "threat_level": self.threat_level,
            "associated_processes": self.associated_processes,
        }
