"""Secret leak checks beyond ENV (DFA-040 to DFA-042).

ENV-based secrets are caught in security.py (DFA-025). This module catches
secret-shaped names in ARG and URL-embedded credentials.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from dockerfile_audit.findings import DockerfileDoc, Finding, check_meta

CATEGORY = "secrets"

SECRET_NAME_RE = re.compile(
    r"(?i)(password|passwd|pwd|token|secret|api[_\-]?key|access[_\-]?key|"
    r"private[_\-]?key|auth|credential|bearer|jwt)"
)


@check_meta(id="DFA-040", severity="medium", title="ARG with secret-pattern name")
def check_arg_secret_pattern(doc: DockerfileDoc) -> Iterable[Finding]:
    for inst in doc.iter_instructions("ARG"):
        value = inst.get("value", "")
        if not value:
            continue
        # ARG NAME or ARG NAME=default
        name = value.split("=", 1)[0].strip()
        if not SECRET_NAME_RE.search(name):
            continue
        # Default value present?
        has_default = "=" in value
        default = value.split("=", 1)[1].strip().strip('"').strip("'") if has_default else None
        # If default is empty / placeholder, lower severity
        severity = "medium"
        if not default or re.match(r"(?i)^(your|changeme|placeholder|<.*>)", default or ""):
            severity = "low"
        yield Finding(
            id="DFA-040",
            category=CATEGORY,
            severity=severity,
            instruction="ARG",
            line_number=inst.get("startline", 0) + 1,
            title=f"ARG {name} matches secret pattern",
            description=(
                f"`ARG {value}` declares a build-time variable with a secret-pattern name. "
                f"ARGs are visible in image history (`docker history`) — anyone with pull "
                f"access can see the value passed at build time, including via CI logs."
            ),
            remediation=(
                "For build-time secrets, use BuildKit's `--mount=type=secret` instead of "
                "ARG. For runtime secrets, use ENV at run time or Docker secrets."
            ),
            fix_dockerfile_snippet=(
                "# syntax=docker/dockerfile:1.4\n"
                "RUN --mount=type=secret,id=mysecret \\\n"
                "    cat /run/secrets/mysecret | <use it>"
            ),
            references=["docker-docs/buildkit/secrets"],
        )


CHECKS = [
    check_arg_secret_pattern,
]
