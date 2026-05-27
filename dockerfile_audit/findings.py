"""Core data types for dockerfile-audit: Finding + DockerfileDoc + check_meta decorator."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["high", "medium", "low", "info"]

SEVERITY_RANK: dict[Severity, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class Finding:
    """One audit finding."""
    id: str                                  # e.g. "DFA-001"
    category: str                            # e.g. "base_image"
    severity: Severity
    title: str
    description: str
    remediation: str
    instruction: str | None = None           # which instruction triggered (e.g. "FROM", "RUN")
    line_number: int | None = None           # 1-based line in the Dockerfile
    fix_dockerfile_snippet: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "instruction": self.instruction,
            "line_number": self.line_number,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "fix_dockerfile_snippet": self.fix_dockerfile_snippet,
            "references": self.references,
        }


@dataclass
class DockerfileDoc:
    """Parsed Dockerfile with helpers.

    `instructions` is a list of dicts from dockerfile-parse:
      [{'instruction': 'FROM', 'value': 'python:3.14', 'startline': 0, 'endline': 0, ...}, ...]
    """
    instructions: list[dict[str, Any]]
    raw_content: str

    def iter_instructions(self, cmd: str | None = None) -> Iterator[dict[str, Any]]:
        """Yield instruction dicts, optionally filtered by command name (e.g. 'RUN')."""
        for inst in self.instructions:
            if cmd is None or inst.get("instruction", "").upper() == cmd.upper():
                yield inst

    def has_instruction(self, cmd: str) -> bool:
        return any(self.iter_instructions(cmd))

    @property
    def from_lines(self) -> list[dict[str, Any]]:
        return list(self.iter_instructions("FROM"))


def check_meta(*, id: str, severity: Severity, title: str) -> Callable:
    """Decorator that attaches catalog metadata to a check function."""
    def decorator(fn):
        fn.__check_meta__ = {"id": id, "severity": severity, "title": title}
        return fn
    return decorator


def filter_by_min_severity(findings: list[Finding], min_severity: Severity) -> list[Finding]:
    threshold = SEVERITY_RANK[min_severity]
    return [f for f in findings if SEVERITY_RANK[f.severity] >= threshold]


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_sev = {"high": 0, "medium": 0, "low": 0, "info": 0}
    by_cat: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {
        "total_findings": len(findings),
        "by_severity": by_sev,
        "by_category": by_cat,
    }
