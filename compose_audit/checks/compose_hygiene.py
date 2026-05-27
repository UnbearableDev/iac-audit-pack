"""Compose-spec hygiene checks (DCS-051 to DCS-054)."""

from __future__ import annotations

from collections.abc import Iterable

from compose_audit.findings import ComposeDoc, Finding

from compose_audit.findings import check_meta

CATEGORY = 'compose_hygiene'


@check_meta(id='DCS-051', severity='info', title='Deprecated `version:` field')
def check_deprecated_version(doc: ComposeDoc) -> Iterable[Finding]:
    if doc.version is None:
        return
    yield Finding(
        id='DCS-051',
        category=CATEGORY,
        severity='info',
        service=None,
        title='Deprecated `version:` field at top level',
        description=(
            f"The top-level `version: {doc.version!r}` field is deprecated in modern Compose "
            f"Spec implementations (Compose V2+). It is ignored and produces a warning. The "
            f"compose file format is now versionless."
        ),
        remediation="Remove the `version:` field entirely.",
        fix_yaml_snippet='# remove the top-level `version: ...` line',
        references=['Compose-Spec-Versionless'],
    )


@check_meta(id='DCS-052', severity='low', title='depends_on without service_healthy condition')
def check_depends_on_no_healthy(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        depends = svc.get('depends_on')
        if not depends:
            continue
        if isinstance(depends, list):
            # Short form: just service names, no condition. Implies service_started which
            # is rarely what you actually want (the dependency may not be ready yet).
            yield Finding(
                id='DCS-052',
                category=CATEGORY,
                severity='low',
                service=name,
                title='`depends_on` uses short form (no startup condition)',
                description=(
                    f"Service '{name}' lists dependencies as a plain list. Short-form "
                    f"`depends_on` waits only for the dependency *container* to start, not "
                    f"for the *service inside* to be ready. The classic 'web starts before "
                    f"db is accepting connections' race."
                ),
                remediation=(
                    "Use the long form with `condition: service_healthy` (requires the "
                    "dependency to have a `healthcheck:`). Falls back to `service_started` "
                    "if no healthcheck is realistic for that dependency."
                ),
                fix_yaml_snippet=(
                    '    depends_on:\n'
                    '      db:\n'
                    '        condition: service_healthy'
                ),
                references=['Compose-depends_on-Docs'],
            )
        elif isinstance(depends, dict):
            for dep_name, dep_config in depends.items():
                if not isinstance(dep_config, dict):
                    continue
                condition = dep_config.get('condition')
                if condition == 'service_healthy':
                    continue
                yield Finding(
                    id='DCS-052',
                    category=CATEGORY,
                    severity='low',
                    service=name,
                    title=f"depends_on '{dep_name}' uses condition={condition!r}",
                    description=(
                        f"Service '{name}' depends on '{dep_name}' with condition "
                        f"{condition!r}. Only `service_healthy` guarantees the dependency is "
                        f"actually ready to receive traffic."
                    ),
                    remediation=(
                        f"Set `condition: service_healthy` on the '{dep_name}' dependency. "
                        f"Make sure '{dep_name}' has a working `healthcheck:` (see DCS-043)."
                    ),
                    fix_yaml_snippet=(
                        f'    depends_on:\n'
                        f'      {dep_name}:\n'
                        f'        condition: service_healthy'
                    ),
                    references=['Compose-depends_on-Docs'],
                )


CHECKS = [
    check_deprecated_version,
    check_depends_on_no_healthy,
]
