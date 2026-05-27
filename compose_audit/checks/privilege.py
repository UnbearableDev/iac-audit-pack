"""Privilege & permission checks (DCS-001 to DCS-009)."""

from __future__ import annotations

from collections.abc import Iterable

from compose_audit.findings import ComposeDoc, Finding

from compose_audit.findings import check_meta

CATEGORY = 'privilege'

DANGEROUS_CAPS = {
    'SYS_ADMIN', 'NET_ADMIN', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_PTRACE',
    'SYS_TIME', 'NET_RAW', 'AUDIT_WRITE', 'DAC_READ_SEARCH', 'SYS_BOOT',
}


@check_meta(id='DCS-001', severity='medium', title='Container runs as root')
def check_root_user(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        if 'user' in svc:
            continue
        yield Finding(
            id='DCS-001',
            category=CATEGORY,
            severity='medium',
            service=name,
            title='Container runs as root',
            description=(
                f"Service '{name}' does not specify a `user:` directive. Containers default "
                f"to root; a container escape would expose host root capabilities. CIS Docker "
                f"Benchmark §4.1 recommends running as a non-root user."
            ),
            remediation=(
                "Add a `user:` directive with a non-root UID:GID. Define the user in the "
                "Dockerfile (e.g. `USER 10001:10001`) so volume permissions are consistent."
            ),
            fix_yaml_snippet='    user: "10001:10001"',
            references=['CIS-Docker-4.1'],
        )


@check_meta(id='DCS-002', severity='high', title='Privileged mode enabled')
def check_privileged(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        if svc.get('privileged') is True:
            yield Finding(
                id='DCS-002',
                category=CATEGORY,
                severity='high',
                service=name,
                title='Privileged mode enabled',
                description=(
                    f"Service '{name}' has `privileged: true`. Privileged containers have all "
                    f"Linux capabilities and direct device access — essentially equivalent to "
                    f"running as host root. A container escape becomes trivial."
                ),
                remediation=(
                    "Remove `privileged: true`. If you need specific capabilities, add them "
                    "explicitly with `cap_add:` (e.g. NET_ADMIN). If you need device access, "
                    "use `devices:` to expose only the necessary device."
                ),
                fix_yaml_snippet='    # remove `privileged: true`; if needed, use cap_add or devices selectively',
                references=['CIS-Docker-5.4', 'NIST-800-190'],
            )


@check_meta(id='DCS-003', severity='high', title='Dangerous capabilities added')
def check_dangerous_caps(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        cap_add = svc.get('cap_add') or []
        if not isinstance(cap_add, list):
            continue
        dangerous = [c for c in cap_add if isinstance(c, str) and c.upper().replace('CAP_', '') in DANGEROUS_CAPS]
        if not dangerous:
            continue
        yield Finding(
            id='DCS-003',
            category=CATEGORY,
            severity='high',
            service=name,
            title='Dangerous Linux capabilities granted',
            description=(
                f"Service '{name}' adds capabilities that can lead to host compromise: "
                f"{', '.join(dangerous)}. SYS_ADMIN in particular grants near-root powers "
                f"inside the container."
            ),
            remediation=(
                f"Review whether {dangerous} is actually required. Most workloads don't need "
                f"them. If you must add a capability, drop everything else with `cap_drop: [ALL]` "
                f"first, then add only what's needed."
            ),
            fix_yaml_snippet='    cap_drop:\n      - ALL\n    cap_add:\n      - <only-what-you-need>',
            references=['CIS-Docker-5.3', 'OWASP-CSVS-V8'],
        )


@check_meta(id='DCS-004', severity='high', title='All capabilities granted (cap_add: ALL)')
def check_cap_add_all(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        cap_add = svc.get('cap_add') or []
        if isinstance(cap_add, list) and any(
            isinstance(c, str) and c.upper().replace('CAP_', '') == 'ALL'
            for c in cap_add
        ):
            yield Finding(
                id='DCS-004',
                category=CATEGORY,
                severity='high',
                service=name,
                title='All Linux capabilities granted',
                description=(
                    f"Service '{name}' has `cap_add: ALL` (or equivalent), granting every Linux "
                    f"capability. Equivalent in practice to `privileged: true`."
                ),
                remediation=(
                    "Replace with the minimal set of capabilities. Start with `cap_drop: [ALL]` "
                    "and add back only what your workload requires."
                ),
                fix_yaml_snippet='    cap_drop:\n      - ALL\n    cap_add:\n      - <specific-cap>',
                references=['CIS-Docker-5.3'],
            )


@check_meta(id='DCS-005', severity='low', title='Capabilities not dropped (cap_drop: ALL missing)')
def check_cap_drop_all(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        cap_drop = svc.get('cap_drop') or []
        if not isinstance(cap_drop, list):
            continue
        has_drop_all = any(
            isinstance(c, str) and c.upper().replace('CAP_', '') == 'ALL'
            for c in cap_drop
        )
        if has_drop_all:
            continue
        yield Finding(
            id='DCS-005',
            category=CATEGORY,
            severity='low',
            service=name,
            title='Default Linux capabilities not dropped',
            description=(
                f"Service '{name}' does not drop default Linux capabilities. Docker grants "
                f"~14 capabilities by default (CHOWN, SETUID, NET_RAW, etc.); most workloads "
                f"need few or none of them. Defense-in-depth: drop everything, add back only "
                f"what's needed."
            ),
            remediation=(
                "Add `cap_drop: [ALL]`, then explicitly `cap_add:` only what your workload "
                "requires (often nothing)."
            ),
            fix_yaml_snippet='    cap_drop:\n      - ALL',
            references=['CIS-Docker-5.3'],
        )


@check_meta(id='DCS-006', severity='medium', title='no-new-privileges not set')
def check_no_new_privileges(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        sec_opt = svc.get('security_opt') or []
        if not isinstance(sec_opt, list):
            continue
        has_nnp = any(
            isinstance(s, str) and 'no-new-privileges' in s.lower() and ('true' in s.lower() or s.lower().endswith('no-new-privileges'))
            for s in sec_opt
        )
        if has_nnp:
            continue
        yield Finding(
            id='DCS-006',
            category=CATEGORY,
            severity='medium',
            service=name,
            title='no-new-privileges not enforced',
            description=(
                f"Service '{name}' does not set `security_opt: [no-new-privileges:true]`. "
                f"Without this, setuid binaries inside the container can elevate privileges, "
                f"even when running as a non-root user."
            ),
            remediation=(
                "Add `no-new-privileges:true` to `security_opt`. This is a defense-in-depth "
                "measure that complements running as non-root."
            ),
            fix_yaml_snippet='    security_opt:\n      - no-new-privileges:true',
            references=['CIS-Docker-5.25'],
        )


CHECKS = [
    check_root_user,
    check_privileged,
    check_dangerous_caps,
    check_cap_add_all,
    check_cap_drop_all,
    check_no_new_privileges,
]
