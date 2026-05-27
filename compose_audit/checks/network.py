"""Network exposure checks (DCS-010 to DCS-017)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from compose_audit.findings import ComposeDoc, Finding

from compose_audit.findings import check_meta

CATEGORY = 'network'

DB_PORTS = {
    3306: 'MySQL/MariaDB',
    5432: 'PostgreSQL',
    27017: 'MongoDB',
    6379: 'Redis',
    9200: 'Elasticsearch',
    9300: 'Elasticsearch transport',
    11211: 'Memcached',
    1433: 'MSSQL',
    5984: 'CouchDB',
    7474: 'Neo4j',
}


def _parse_port_mapping(entry) -> tuple[str | None, int | None]:
    """Parse a compose `ports:` entry. Returns (host_ip, host_port) or (None, None) on parse failure."""
    if isinstance(entry, int):
        return None, entry
    if isinstance(entry, dict):
        return entry.get('host_ip'), entry.get('published')
    if not isinstance(entry, str):
        return None, None
    # Examples: "3306", "3306:3306", "127.0.0.1:3306:3306", "0.0.0.0:8080:8080"
    m = re.match(r'^(?:\[?([\d.:a-fA-F]+)\]?:)?(\d+)(?::\d+)?(?:/[a-z]+)?$', entry.strip())
    if not m:
        return None, None
    host_ip = m.group(1)
    host_port = int(m.group(2))
    return host_ip, host_port


@check_meta(id='DCS-010', severity='high', title='network_mode: host (no network isolation)')
def check_host_network(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        if svc.get('network_mode') == 'host':
            yield Finding(
                id='DCS-010',
                category=CATEGORY,
                severity='high',
                service=name,
                title='Service uses host network namespace',
                description=(
                    f"Service '{name}' is set to `network_mode: host`, sharing the host's "
                    f"network namespace. The container has direct access to the host's network "
                    f"interfaces, can bind to any host port, and can sniff/inject traffic."
                ),
                remediation=(
                    "Use a bridge network (the compose default) and publish only the ports "
                    "this service needs via `ports:`. Reserve `network_mode: host` for special "
                    "cases like monitoring agents that genuinely need raw host network access."
                ),
                fix_yaml_snippet='    # remove `network_mode: host`; use a bridge network and ports:',
                references=['CIS-Docker-5.9'],
            )


@check_meta(id='DCS-011', severity='medium', title='Port published without explicit bind address (0.0.0.0)')
def check_port_bind_address(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        ports = svc.get('ports') or []
        if not isinstance(ports, list):
            continue
        for entry in ports:
            host_ip, host_port = _parse_port_mapping(entry)
            if host_port is None:
                continue
            # If host_ip is None or 0.0.0.0, the port is bound to all interfaces
            if host_ip in (None, '0.0.0.0', '::'):
                yield Finding(
                    id='DCS-011',
                    category=CATEGORY,
                    severity='medium',
                    service=name,
                    title=f'Port {host_port} bound to all interfaces',
                    description=(
                        f"Service '{name}' publishes port {host_port} without specifying a host "
                        f"interface. The port is reachable from any network the host is on, "
                        f"including the public internet if the host has a public IP."
                    ),
                    remediation=(
                        f"Bind to a specific interface (e.g. `127.0.0.1` for local-only access). "
                        f"Use a reverse proxy in front for public services."
                    ),
                    fix_yaml_snippet=f'    ports:\n      - "127.0.0.1:{host_port}:{host_port}"',
                    references=['CIS-Docker-5.7'],
                )


@check_meta(id='DCS-013', severity='high', title='SSH port (22) exposed externally')
def check_ssh_exposed(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        ports = svc.get('ports') or []
        if not isinstance(ports, list):
            continue
        for entry in ports:
            host_ip, host_port = _parse_port_mapping(entry)
            if host_port == 22 and host_ip not in ('127.0.0.1', 'localhost', '::1'):
                yield Finding(
                    id='DCS-013',
                    category=CATEGORY,
                    severity='high',
                    service=name,
                    title='SSH port 22 exposed externally',
                    description=(
                        f"Service '{name}' publishes port 22 on a public-reachable interface. "
                        f"Exposed SSH is the single most-attacked surface on the internet."
                    ),
                    remediation=(
                        "Don't expose SSH from a container. SSH the host directly and use "
                        "`docker exec` to enter containers."
                    ),
                    fix_yaml_snippet='    # remove the 22:22 mapping entirely',
                    references=['CIS-Docker-5.6'],
                )


@check_meta(id='DCS-014', severity='high', title='Database port exposed externally')
def check_db_port_exposed(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        ports = svc.get('ports') or []
        if not isinstance(ports, list):
            continue
        for entry in ports:
            host_ip, host_port = _parse_port_mapping(entry)
            if host_port is None or host_port not in DB_PORTS:
                continue
            if host_ip in ('127.0.0.1', 'localhost', '::1'):
                continue
            db_name = DB_PORTS[host_port]
            yield Finding(
                id='DCS-014',
                category=CATEGORY,
                severity='high',
                service=name,
                title=f'{db_name} port {host_port} exposed externally',
                description=(
                    f"Service '{name}' publishes the {db_name} port {host_port} on a "
                    f"public-reachable interface. Internet-exposed databases are routinely "
                    f"scanned and brute-forced; many ransomware campaigns start here."
                ),
                remediation=(
                    f"Don't publish {db_name} externally. Other services in the same compose "
                    f"network can reach it via the service name ('{name}'). If external access "
                    f"is genuinely needed, bind to 127.0.0.1 and tunnel."
                ),
                fix_yaml_snippet=(
                    '    # remove the host port mapping; expose only the container port:\n'
                    f'    expose:\n      - "{host_port}"'
                ),
                references=['CIS-Docker-5.7'],
            )


CHECKS = [
    check_host_network,
    check_port_bind_address,
    check_ssh_exposed,
    check_db_port_exposed,
]
