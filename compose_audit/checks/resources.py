"""Resource limit checks (DCS-032 to DCS-036)."""

from __future__ import annotations

from collections.abc import Iterable

from compose_audit.findings import ComposeDoc, Finding

from compose_audit.findings import check_meta

CATEGORY = 'resources'


def _deploy_limits(svc: dict) -> dict:
    deploy = svc.get('deploy') or {}
    resources = (deploy.get('resources') if isinstance(deploy, dict) else None) or {}
    return (resources.get('limits') if isinstance(resources, dict) else None) or {}


def _has_memory_limit(svc: dict) -> bool:
    if svc.get('mem_limit'):
        return True
    return bool(_deploy_limits(svc).get('memory'))


def _has_cpu_limit(svc: dict) -> bool:
    if svc.get('cpus') or svc.get('cpu_quota') or svc.get('cpu_shares'):
        return True
    return bool(_deploy_limits(svc).get('cpus'))


def _has_pid_limit(svc: dict) -> bool:
    if svc.get('pids_limit') is not None:
        return True
    return bool(_deploy_limits(svc).get('pids'))


@check_meta(id='DCS-032', severity='low', title='No memory limit set')
def check_no_memory_limit(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        if _has_memory_limit(svc):
            continue
        yield Finding(
            id='DCS-032',
            category=CATEGORY,
            severity='low',
            service=name,
            title='No memory limit configured',
            description=(
                f"Service '{name}' has no memory limit. A runaway process (or container "
                f"exploit) can consume all host memory, OOM-killing other containers and "
                f"the host."
            ),
            remediation=(
                "Set a memory limit appropriate to your workload. Either `mem_limit` (legacy) "
                "or `deploy.resources.limits.memory` (modern)."
            ),
            fix_yaml_snippet=(
                '    deploy:\n'
                '      resources:\n'
                '        limits:\n'
                '          memory: 512M'
            ),
            references=['CIS-Docker-5.10'],
        )


@check_meta(id='DCS-033', severity='low', title='No CPU limit set')
def check_no_cpu_limit(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        if _has_cpu_limit(svc):
            continue
        yield Finding(
            id='DCS-033',
            category=CATEGORY,
            severity='low',
            service=name,
            title='No CPU limit configured',
            description=(
                f"Service '{name}' has no CPU limit. A runaway or compromised process can "
                f"saturate all host CPU cores, degrading every other container and the host."
            ),
            remediation=(
                "Set a CPU limit appropriate to your workload. Either the legacy `cpus:` field "
                "or `deploy.resources.limits.cpus` (Compose Spec)."
            ),
            fix_yaml_snippet=(
                '    deploy:\n'
                '      resources:\n'
                '        limits:\n'
                '          cpus: "1.0"'
            ),
            references=['CIS-Docker-5.11'],
        )


@check_meta(id='DCS-034', severity='low', title='No PID limit set')
def check_no_pid_limit(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        if _has_pid_limit(svc):
            continue
        yield Finding(
            id='DCS-034',
            category=CATEGORY,
            severity='low',
            service=name,
            title='No PID limit configured',
            description=(
                f"Service '{name}' has no PID limit. A fork bomb (intentional or accidental) "
                f"can exhaust the host's process table, hanging every service on the host."
            ),
            remediation=(
                "Set `pids_limit` to a value appropriate for your workload (a few hundred is "
                "usually plenty for typical services)."
            ),
            fix_yaml_snippet='    pids_limit: 200',
            references=['CIS-Docker-5.28'],
        )


CHECKS = [
    check_no_memory_limit,
    check_no_cpu_limit,
    check_no_pid_limit,
]
