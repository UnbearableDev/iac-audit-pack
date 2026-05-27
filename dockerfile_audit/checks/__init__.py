"""Check registry and dispatch."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from dockerfile_audit.findings import DockerfileDoc, Finding

from . import base_image, efficiency, instructions, secrets, security

CheckFn = Callable[[DockerfileDoc], Iterable[Finding]]

CATEGORY_REGISTRY: dict[str, list[CheckFn]] = {
    "base_image": base_image.CHECKS,
    "instructions": instructions.CHECKS,
    "security": security.CHECKS,
    "efficiency": efficiency.CHECKS,
    "secrets": secrets.CHECKS,
}

ALL_CATEGORIES: list[str] = list(CATEGORY_REGISTRY.keys())


def run_category(category: str, doc: DockerfileDoc) -> list[Finding]:
    checks = CATEGORY_REGISTRY.get(category)
    if checks is None:
        raise ValueError(f"Unknown category: {category!r}. Valid: {ALL_CATEGORIES}")
    findings: list[Finding] = []
    for check in checks:
        try:
            findings.extend(check(doc))
        except Exception as e:
            findings.append(
                Finding(
                    id="DFA-INTERNAL-001",
                    category=category,
                    severity="info",
                    title=f"Check {check.__name__} raised: {type(e).__name__}",
                    description=str(e),
                    remediation="Report this as a bug in dockerfile-audit MCP.",
                )
            )
    return findings


def run_all(doc: DockerfileDoc) -> list[Finding]:
    findings: list[Finding] = []
    for category in ALL_CATEGORIES:
        findings.extend(run_category(category, doc))
    return findings


def catalog() -> list[dict]:
    entries: list[dict] = []
    for category, checks in CATEGORY_REGISTRY.items():
        for check in checks:
            meta = getattr(check, "__check_meta__", None)
            if meta is None:
                continue
            entries.append({
                "id": meta["id"],
                "category": category,
                "severity": meta["severity"],
                "title": meta["title"],
            })
    entries.sort(key=lambda e: e["id"])
    return entries
