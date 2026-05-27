"""Check registry and dispatch.

Each category module exposes:
    CHECKS: list[CheckFn]

where CheckFn signature is: (ComposeDoc) -> Iterable[Finding].

The category name (e.g. 'privilege', 'network') comes from the module's
__category__ attribute. Importing this package eagerly imports all
category modules and builds the registry.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from compose_audit.findings import ComposeDoc, Finding

from . import (
    compose_hygiene,
    filesystem,
    image_hygiene,
    logging as logging_checks,  # local module, aliased to avoid stdlib name clash
    network,
    privilege,
    resources,
    runtime_lifecycle,
    secrets,
)

CheckFn = Callable[[ComposeDoc], Iterable[Finding]]

# Map: category name -> list of check functions
CATEGORY_REGISTRY: dict[str, list[CheckFn]] = {
    'privilege': privilege.CHECKS,
    'network': network.CHECKS,
    'filesystem': filesystem.CHECKS,
    'secrets': secrets.CHECKS,
    'resources': resources.CHECKS,
    'image_hygiene': image_hygiene.CHECKS,
    'runtime_lifecycle': runtime_lifecycle.CHECKS,
    'logging': logging_checks.CHECKS,
    'compose_hygiene': compose_hygiene.CHECKS,
}

ALL_CATEGORIES: list[str] = list(CATEGORY_REGISTRY.keys())


def run_category(category: str, doc: ComposeDoc) -> list[Finding]:
    """Run all checks in a category, returning a flat list of findings."""
    checks = CATEGORY_REGISTRY.get(category)
    if checks is None:
        raise ValueError(f'Unknown category: {category!r}. Valid: {ALL_CATEGORIES}')
    findings: list[Finding] = []
    for check in checks:
        try:
            findings.extend(check(doc))
        except Exception as e:
            # A buggy check should not blow up the entire audit.
            findings.append(
                Finding(
                    id='DCS-INTERNAL-001',
                    category=category,
                    severity='info',
                    title=f'Check {check.__name__} raised: {type(e).__name__}',
                    description=str(e),
                    remediation='Report this as a bug in docker-compose-audit MCP.',
                )
            )
    return findings


def run_all(doc: ComposeDoc) -> list[Finding]:
    """Run every category. Findings ordered by category insertion order."""
    findings: list[Finding] = []
    for category in ALL_CATEGORIES:
        findings.extend(run_category(category, doc))
    return findings


def catalog() -> list[dict]:
    """Return the full check catalog (id, category, severity, title) for list_checks."""
    entries: list[dict] = []
    for category, checks in CATEGORY_REGISTRY.items():
        for check in checks:
            meta = getattr(check, '__check_meta__', None)
            if meta is None:
                continue
            entries.append({
                'id': meta['id'],
                'category': category,
                'severity': meta['severity'],
                'title': meta['title'],
            })
    entries.sort(key=lambda e: e['id'])
    return entries


# check_meta lives in compose_audit.findings to avoid circular import.
