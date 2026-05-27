"""Logging configuration checks (DCS-048 to DCS-050)."""

from __future__ import annotations

from collections.abc import Iterable

from compose_audit.findings import ComposeDoc, Finding
from compose_audit.findings import check_meta

CATEGORY = 'logging'


@check_meta(id='DCS-048', severity='low', title='No log driver configured')
def check_no_log_driver(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        logging_cfg = svc.get('logging') or {}
        if isinstance(logging_cfg, dict) and logging_cfg.get('driver'):
            continue
        yield Finding(
            id='DCS-048',
            category=CATEGORY,
            severity='low',
            service=name,
            title='No log driver explicitly configured',
            description=(
                f"Service '{name}' relies on the default log driver (`json-file`), which "
                f"writes container output to disk with no rotation. Long-running services "
                f"with chatty stdout will eventually fill the host disk."
            ),
            remediation=(
                "Either configure `logging.driver: json-file` with rotation options "
                "(`max-size`, `max-file`), or point at a centralized log collector "
                "(`gelf`, `syslog`, `awslogs`, `loki`, etc.)."
            ),
            fix_yaml_snippet=(
                '    logging:\n'
                '      driver: json-file\n'
                '      options:\n'
                '        max-size: "10m"\n'
                '        max-file: "3"'
            ),
            references=['Docker-Logging-Drivers'],
        )


@check_meta(id='DCS-049', severity='low', title='Log rotation not configured')
def check_no_log_rotation(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        logging_cfg = svc.get('logging') or {}
        if not isinstance(logging_cfg, dict):
            continue
        driver = logging_cfg.get('driver')
        # Only json-file (and local) need explicit rotation; remote drivers handle it
        if driver not in (None, 'json-file', 'local'):
            continue
        options = logging_cfg.get('options') or {}
        if not isinstance(options, dict):
            continue
        # Skip if the no-log-driver check (DCS-048) will already flag this service —
        # avoid double-reporting on services with no logging block at all.
        if driver is None and not logging_cfg:
            continue
        has_size_cap = options.get('max-size')
        has_file_cap = options.get('max-file')
        if has_size_cap and has_file_cap:
            continue
        yield Finding(
            id='DCS-049',
            category=CATEGORY,
            severity='low',
            service=name,
            title='Log rotation options not set',
            description=(
                f"Service '{name}' uses the `{driver or 'json-file'}` log driver but does "
                f"not set both `max-size` and `max-file` rotation options. Logs will grow "
                f"unbounded until the disk fills."
            ),
            remediation=(
                "Set both `max-size` (e.g. `10m`) and `max-file` (e.g. `3`) so logs rotate "
                "and old files get deleted automatically."
            ),
            fix_yaml_snippet=(
                '    logging:\n'
                '      driver: json-file\n'
                '      options:\n'
                '        max-size: "10m"\n'
                '        max-file: "3"'
            ),
            references=['Docker-json-file-Driver'],
        )


CHECKS = [
    check_no_log_driver,
    check_no_log_rotation,
]
