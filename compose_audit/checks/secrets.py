"""Secret hygiene checks (DCS-026 to DCS-031)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from compose_audit.findings import ComposeDoc, Finding

from compose_audit.findings import check_meta

CATEGORY = 'secrets'

# Env-var name patterns suggesting a credential
SECRET_NAME_RE = re.compile(
    r'(?i)(password|passwd|pwd|token|secret|api[_\-]?key|access[_\-]?key|'
    r'private[_\-]?key|auth|credential|bearer|jwt)'
)

# Values that look like environment-variable references (acceptable)
ENVVAR_REF_RE = re.compile(r'^\$\{?[A-Z_][A-Z0-9_]*(:-[^}]*)?\}?$')

# Values that look obviously placeholdered (acceptable)
PLACEHOLDER_RE = re.compile(r'(?i)^(your[_\-]?|changeme|placeholder|fixme|<.*>)')


def _iter_env(svc: dict) -> Iterable[tuple[str, str | None]]:
    """Yield (key, value) pairs from a service's `environment:` field."""
    env = svc.get('environment')
    if env is None:
        return
    if isinstance(env, dict):
        for k, v in env.items():
            yield str(k), None if v is None else str(v)
    elif isinstance(env, list):
        for item in env:
            if not isinstance(item, str):
                continue
            if '=' in item:
                k, v = item.split('=', 1)
                yield k, v
            else:
                yield item, None


@check_meta(id='DCS-026', severity='high', title='Hardcoded secret in environment')
def check_hardcoded_secrets(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        for key, val in _iter_env(svc):
            if val is None or val == '':
                continue
            if not SECRET_NAME_RE.search(key):
                continue
            # Skip env var references like ${DB_PASSWORD}
            if ENVVAR_REF_RE.match(val.strip()):
                continue
            # Skip obvious placeholders
            if PLACEHOLDER_RE.match(val.strip()):
                continue
            yield Finding(
                id='DCS-026',
                category=CATEGORY,
                severity='high',
                service=name,
                title=f'Hardcoded secret in env var {key}',
                description=(
                    f"Service '{name}' has `{key}=<literal>` set directly in `environment:`. "
                    f"Compose files are commonly committed to git; literal secrets in YAML "
                    f"end up in repository history and CI logs."
                ),
                remediation=(
                    f"Reference the value from a .env file or process environment: "
                    f"`{key}: ${{{key}}}`. For production, use Docker secrets or an external "
                    f"secret manager (Vault, AWS Secrets Manager, etc.)."
                ),
                fix_yaml_snippet=f'    environment:\n      {key}: ${{{key}}}',
                references=['OWASP-CSVS-V6', 'Twelve-Factor-III'],
            )


@check_meta(id='DCS-027', severity='medium', title='Env var matches secret pattern without secrets store')
def check_secret_pattern_no_store(doc: ComposeDoc) -> Iterable[Finding]:
    # Only fire if the compose file has NO top-level `secrets:` section
    if doc.raw.get('secrets'):
        return
    for name, svc in doc.iter_services():
        secret_envs = [k for k, _ in _iter_env(svc) if SECRET_NAME_RE.search(k)]
        if not secret_envs:
            continue
        yield Finding(
            id='DCS-027',
            category=CATEGORY,
            severity='medium',
            service=name,
            title='Credentials in environment, no docker secrets defined',
            description=(
                f"Service '{name}' has environment variables matching a secret pattern "
                f"({', '.join(secret_envs[:3])}{'...' if len(secret_envs) > 3 else ''}) but "
                f"the compose file has no top-level `secrets:` section. Env vars are visible "
                f"via `docker inspect`, in process listings inside the container, and to anyone "
                f"with read access to the compose file."
            ),
            remediation=(
                "Move credentials to Docker secrets. Define a top-level `secrets:` section, "
                "reference the secret in the service, and read the file at runtime."
            ),
            fix_yaml_snippet=(
                '# top-level:\n'
                'secrets:\n'
                '  db_password:\n'
                '    file: ./secrets/db_password\n'
                '# in service:\n'
                '    secrets:\n'
                '      - db_password\n'
                '    environment:\n'
                '      DB_PASSWORD_FILE: /run/secrets/db_password'
            ),
            references=['Docker-Secrets-Docs'],
        )


CHECKS = [
    check_hardcoded_secrets,
    check_secret_pattern_no_store,
]
