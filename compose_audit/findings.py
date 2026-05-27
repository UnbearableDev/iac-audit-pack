"""Core data types: Finding and ComposeDoc."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Iterator, Literal

Severity = Literal['high', 'medium', 'low', 'info']

SEVERITY_RANK: dict[Severity, int] = {
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
}


@dataclass
class Finding:
    """One security finding from a check."""
    id: str                       # e.g. "DCS-001"
    category: str                 # e.g. "privilege"
    severity: Severity
    title: str
    description: str
    remediation: str
    service: str | None = None    # which compose service (None for top-level findings)
    fix_yaml_snippet: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'category': self.category,
            'severity': self.severity,
            'service': self.service,
            'title': self.title,
            'description': self.description,
            'remediation': self.remediation,
            'fix_yaml_snippet': self.fix_yaml_snippet,
            'references': self.references,
        }


@dataclass
class ComposeDoc:
    """Parsed docker-compose document with helpers."""
    raw: dict[str, Any]

    @property
    def services(self) -> dict[str, dict[str, Any]]:
        s = self.raw.get('services')
        return dict(s) if isinstance(s, dict) else {}

    @property
    def networks(self) -> dict[str, Any]:
        n = self.raw.get('networks')
        return dict(n) if isinstance(n, dict) else {}

    @property
    def volumes(self) -> dict[str, Any]:
        v = self.raw.get('volumes')
        return dict(v) if isinstance(v, dict) else {}

    @property
    def version(self) -> str | None:
        v = self.raw.get('version')
        return str(v) if v is not None else None

    def iter_services(self) -> Iterator[tuple[str, dict[str, Any]]]:
        """Yield (service_name, service_dict) pairs."""
        for name, svc in self.services.items():
            yield name, (svc if isinstance(svc, dict) else {})


def filter_by_min_severity(findings: list[Finding], min_severity: Severity) -> list[Finding]:
    """Drop findings whose severity is below the minimum."""
    threshold = SEVERITY_RANK[min_severity]
    return [f for f in findings if SEVERITY_RANK[f.severity] >= threshold]


def check_meta(*, id: str, severity: Severity, title: str) -> Callable:
    """Decorator that attaches catalog metadata to a check function.

    Lives here (rather than in checks/__init__.py) to avoid a circular import
    when check modules try to grab it during package initialization.
    """
    def decorator(fn):
        fn.__check_meta__ = {'id': id, 'severity': severity, 'title': title}
        return fn
    return decorator


def summarize(findings: list[Finding]) -> dict[str, Any]:
    """Build the summary block for an audit response."""
    by_sev: dict[str, int] = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    by_cat: dict[str, int] = {}
    services_with_findings: set[str] = set()
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
        if f.service:
            services_with_findings.add(f.service)
    return {
        'total_findings': len(findings),
        'by_severity': by_sev,
        'by_category': by_cat,
        'services_with_findings': sorted(services_with_findings),
    }
