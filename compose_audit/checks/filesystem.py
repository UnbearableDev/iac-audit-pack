"""Filesystem mount checks (DCS-018 to DCS-025)."""

from __future__ import annotations

from collections.abc import Iterable

from compose_audit.findings import ComposeDoc, Finding

from compose_audit.findings import check_meta

CATEGORY = 'filesystem'

SENSITIVE_HOST_PATHS = {
    '/etc': 'host config (passwords, shadow, ssh keys)',
    '/proc': 'kernel/process state',
    '/sys': 'kernel parameter interface',
    '/root': 'root user home',
    '/var/lib/docker': 'docker engine state',
    '/var/lib/kubelet': 'kubelet state',
    '/boot': 'kernel/boot config',
}


def _iter_volume_strings(svc: dict) -> Iterable[str]:
    """Yield volume mapping strings from a service's `volumes:` list, handling both short and long syntax."""
    vols = svc.get('volumes') or []
    if not isinstance(vols, list):
        return
    for v in vols:
        if isinstance(v, str):
            yield v
        elif isinstance(v, dict):
            src = v.get('source')
            tgt = v.get('target')
            if src and tgt:
                yield f'{src}:{tgt}'


def _parse_volume(entry: str) -> tuple[str | None, str | None]:
    """Return (host_path, container_path) for a volume string; named volumes return (None, ...)."""
    parts = entry.split(':')
    if len(parts) < 2:
        return None, None
    src = parts[0]
    tgt = parts[1]
    # Named volume — src does not start with / or .
    if not (src.startswith('/') or src.startswith('.') or src.startswith('~')):
        return None, tgt
    return src, tgt


@check_meta(id='DCS-018', severity='high', title='/var/run/docker.sock mounted')
def check_docker_sock(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        for entry in _iter_volume_strings(svc):
            src, _ = _parse_volume(entry)
            if src is None:
                continue
            if src.rstrip('/').endswith('/docker.sock') or src in ('/var/run/docker.sock', '/run/docker.sock'):
                yield Finding(
                    id='DCS-018',
                    category=CATEGORY,
                    severity='high',
                    service=name,
                    title='Docker daemon socket mounted',
                    description=(
                        f"Service '{name}' mounts the Docker daemon socket ({src}). Any "
                        f"process inside this container can issue commands to the Docker daemon "
                        f"— launching privileged containers, mounting host paths, accessing "
                        f"any container's filesystem. This is equivalent to root on the host."
                    ),
                    remediation=(
                        "Avoid this if at all possible. If you genuinely need docker control "
                        "(e.g. CI runner, Portainer), use a proxy like `tecnativa/docker-socket-proxy` "
                        "to restrict the API surface to read-only or specific endpoints."
                    ),
                    fix_yaml_snippet='    # remove the docker.sock mount; consider docker-socket-proxy',
                    references=['CIS-Docker-5.31', 'KubeCon-2021-docker-sock-escape'],
                )


@check_meta(id='DCS-019', severity='high', title='Host root / mounted')
def check_host_root(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        for entry in _iter_volume_strings(svc):
            src, _ = _parse_volume(entry)
            if src is None:
                continue
            if src.rstrip('/') == '':  # '/' becomes '' after rstrip
                yield Finding(
                    id='DCS-019',
                    category=CATEGORY,
                    severity='high',
                    service=name,
                    title='Host root filesystem (/) mounted',
                    description=(
                        f"Service '{name}' mounts the host root `/`. The container has full "
                        f"read access to the entire host filesystem and (if not `:ro`) full "
                        f"write access — including system configs, user data, and credentials."
                    ),
                    remediation=(
                        "Mount only the specific host paths you need. Use `:ro` if read access "
                        "is sufficient."
                    ),
                    fix_yaml_snippet='    # mount specific paths instead of /',
                    references=['CIS-Docker-5.5'],
                )


@check_meta(id='DCS-020', severity='high', title='Sensitive host path mounted')
def check_sensitive_paths(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        for entry in _iter_volume_strings(svc):
            src, _ = _parse_volume(entry)
            if src is None:
                continue
            src_clean = src.rstrip('/')
            for sensitive, why in SENSITIVE_HOST_PATHS.items():
                if src_clean == sensitive or src_clean.startswith(sensitive + '/'):
                    yield Finding(
                        id='DCS-020',
                        category=CATEGORY,
                        severity='high',
                        service=name,
                        title=f'Sensitive host path {sensitive} mounted',
                        description=(
                            f"Service '{name}' mounts {src} from the host. {sensitive} contains "
                            f"{why} — exposing it to a container significantly weakens isolation."
                        ),
                        remediation=(
                            f"Mount only the specific files or subdirectories you need. Use `:ro` "
                            f"unless write access is required."
                        ),
                        fix_yaml_snippet=f'    # avoid mounting {sensitive}; mount specific files instead',
                        references=['CIS-Docker-5.5'],
                    )
                    break  # only one finding per volume entry


CHECKS = [
    check_docker_sock,
    check_host_root,
    check_sensitive_paths,
]
