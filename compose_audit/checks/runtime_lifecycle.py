"""Runtime lifecycle checks (DCS-043 to DCS-047)."""

from __future__ import annotations

from collections.abc import Iterable

from compose_audit.findings import ComposeDoc, Finding

from compose_audit.findings import check_meta

CATEGORY = 'runtime_lifecycle'


@check_meta(id='DCS-043', severity='low', title='No healthcheck defined')
def check_no_healthcheck(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        # Skip if image likely has built-in healthcheck (we can't really tell, but skip if explicitly disabled)
        hc = svc.get('healthcheck')
        if hc:
            # if it's `disable: true`, that's intentional — also report? for now, no
            continue
        yield Finding(
            id='DCS-043',
            category=CATEGORY,
            severity='low',
            service=name,
            title='No healthcheck configured',
            description=(
                f"Service '{name}' has no `healthcheck:` directive. Without one, compose "
                f"can't tell the difference between 'process running' and 'service healthy', "
                f"so `depends_on: condition: service_healthy` won't work, restart policies "
                f"don't recover from hangs, and orchestrators can't route around bad pods."
            ),
            remediation=(
                "Add a healthcheck that verifies the service actually responds. For HTTP "
                "services use curl/wget on the health endpoint; for databases use the native "
                "ping command."
            ),
            fix_yaml_snippet=(
                '    healthcheck:\n'
                '      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]\n'
                '      interval: 30s\n'
                '      timeout: 5s\n'
                '      retries: 3\n'
                '      start_period: 10s'
            ),
            references=['Docker-Healthcheck-Docs'],
        )


@check_meta(id='DCS-044', severity='low', title='No restart policy configured')
def check_no_restart(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        if svc.get('restart'):
            continue
        deploy = svc.get('deploy') or {}
        if isinstance(deploy, dict) and deploy.get('restart_policy'):
            continue
        yield Finding(
            id='DCS-044',
            category=CATEGORY,
            severity='low',
            service=name,
            title='No restart policy configured',
            description=(
                f"Service '{name}' has no `restart:` policy. If the container crashes "
                f"(OOM, panic, killed by oom_score_adj, etc.) it stays down until a human "
                f"intervenes."
            ),
            remediation=(
                "Add `restart: unless-stopped` for most workloads (auto-recover but respect "
                "manual stops). Use `restart: on-failure:N` if you want bounded retries."
            ),
            fix_yaml_snippet='    restart: unless-stopped',
            references=['Compose-Restart-Docs'],
        )


CHECKS = [
    check_no_healthcheck,
    check_no_restart,
]
