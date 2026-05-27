"""Security checks (DFA-020 to DFA-027)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from dockerfile_audit.findings import DockerfileDoc, Finding, check_meta

CATEGORY = "security"


@check_meta(id="DFA-020", severity="medium", title="No USER directive (runs as root)")
def check_no_user(doc: DockerfileDoc) -> Iterable[Finding]:
    # Only report once at end-of-file if no USER appears AFTER the last FROM
    # (in multi-stage builds, USER in earlier stages doesn't carry over).
    from_indices = [i for i, inst in enumerate(doc.instructions) if inst.get("instruction", "").upper() == "FROM"]
    if not from_indices:
        return
    last_from_idx = from_indices[-1]
    user_after_last_from = any(
        inst.get("instruction", "").upper() == "USER"
        for inst in doc.instructions[last_from_idx:]
    )
    if user_after_last_from:
        return
    last_from = doc.instructions[last_from_idx]
    yield Finding(
        id="DFA-020",
        category=CATEGORY,
        severity="medium",
        instruction=None,
        line_number=None,
        title="No USER directive — container runs as root",
        description=(
            "The final image has no `USER` directive after the last `FROM`. Containers "
            "default to root; a container escape would expose host root capabilities. "
            "CIS Docker Benchmark §4.1 recommends running as a non-root user."
        ),
        remediation=(
            "Add a `USER` directive with a non-root UID:GID. Create the user in the same "
            "Dockerfile with `RUN adduser --uid 10001 --gid 10001 ...` if needed."
        ),
        fix_dockerfile_snippet="USER 10001:10001",
        references=["CIS-Docker-4.1"],
    )


@check_meta(id="DFA-021", severity="high", title="USER root set explicitly")
def check_user_root(doc: DockerfileDoc) -> Iterable[Finding]:
    for inst in doc.iter_instructions("USER"):
        value = inst.get("value", "").strip()
        if value.lower() in ("root", "0", "0:0"):
            yield Finding(
                id="DFA-021",
                category=CATEGORY,
                severity="high",
                instruction="USER",
                line_number=inst.get("startline", 0) + 1,
                title="USER root set explicitly",
                description=(
                    f"`USER {value}` explicitly sets the container user to root. "
                    "Unless this stage exists solely to perform root-required setup before "
                    "switching back to a non-root user, this is a security anti-pattern."
                ),
                remediation="Switch to a non-root UID after any root-required RUN steps.",
                fix_dockerfile_snippet="USER 10001:10001",
                references=["CIS-Docker-4.1"],
            )


@check_meta(id="DFA-022", severity="high", title="sudo invoked in RUN")
def check_sudo_in_run(doc: DockerfileDoc) -> Iterable[Finding]:
    sudo_re = re.compile(r"\bsudo\b")
    for inst in doc.iter_instructions("RUN"):
        value = inst.get("value", "")
        if not value or not sudo_re.search(value):
            continue
        yield Finding(
            id="DFA-022",
            category=CATEGORY,
            severity="high",
            instruction="RUN",
            line_number=inst.get("startline", 0) + 1,
            title="sudo invoked in RUN",
            description=(
                "Using `sudo` inside a container is a smell. Container build runs as root "
                "by default, so `sudo` is unnecessary and signals confusion about runtime "
                "context. It can also cause SIGTERM not to propagate at runtime."
            ),
            remediation=(
                "Remove `sudo`. If you need to perform root tasks during build, run them "
                "as root directly. If runtime needs privilege escalation, redesign the image."
            ),
            references=["Hadolint-DL3004"],
        )


@check_meta(id="DFA-023", severity="high", title="chmod 777 in RUN")
def check_chmod_777(doc: DockerfileDoc) -> Iterable[Finding]:
    chmod_re = re.compile(r"\bchmod\s+(?:-[A-Za-z]+\s+)*0?777\b")
    for inst in doc.iter_instructions("RUN"):
        value = inst.get("value", "")
        if not value or not chmod_re.search(value):
            continue
        yield Finding(
            id="DFA-023",
            category=CATEGORY,
            severity="high",
            instruction="RUN",
            line_number=inst.get("startline", 0) + 1,
            title="World-writable permissions (chmod 777) in RUN",
            description=(
                "`chmod 777` grants everyone read/write/execute. Inside a container this "
                "weakens isolation if the container is later breached or shared via volume."
            ),
            remediation=(
                "Use the minimum permissions needed. For a writable directory owned by the "
                "app user, prefer `chown user:group dir && chmod 750 dir`."
            ),
            references=["CIS-Docker-4.8"],
        )


@check_meta(id="DFA-024", severity="medium", title="curl | bash pattern in RUN")
def check_curl_pipe_bash(doc: DockerfileDoc) -> Iterable[Finding]:
    # Patterns like: curl ... | bash, wget ... | sh, curl ... | sudo bash
    pipe_re = re.compile(
        r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b",
        re.IGNORECASE,
    )
    for inst in doc.iter_instructions("RUN"):
        value = inst.get("value", "")
        if not value or not pipe_re.search(value):
            continue
        yield Finding(
            id="DFA-024",
            category=CATEGORY,
            severity="medium",
            instruction="RUN",
            line_number=inst.get("startline", 0) + 1,
            title="curl|bash (or wget|sh) supply-chain anti-pattern",
            description=(
                "Piping a remote script directly into a shell runs whatever the upstream "
                "serves at build time, with no verification. Supply-chain attacks against "
                "popular installers regularly exploit this pattern."
            ),
            remediation=(
                "Download the script, inspect or verify checksum, THEN run it. Or use the "
                "tool's package manager (apt/apk/yum) with a pinned version."
            ),
            fix_dockerfile_snippet=(
                "RUN curl -sLo /tmp/install.sh https://... && \\\n"
                "    echo '<sha256>  /tmp/install.sh' | sha256sum -c && \\\n"
                "    bash /tmp/install.sh && rm /tmp/install.sh"
            ),
            references=["OWASP-Container-Security"],
        )


@check_meta(id="DFA-025", severity="high", title="Hardcoded secret in ENV")
def check_hardcoded_secret_env(doc: DockerfileDoc) -> Iterable[Finding]:
    secret_re = re.compile(
        r"(?i)(password|passwd|pwd|token|secret|api[_\-]?key|access[_\-]?key|"
        r"private[_\-]?key|auth|credential|bearer|jwt)"
    )
    placeholder_re = re.compile(r"(?i)^(your[_\-]?|changeme|placeholder|fixme|<.*>)")
    envvar_ref_re = re.compile(r"^\$\{?[A-Z_][A-Z0-9_]*(:-[^}]*)?\}?$")

    for inst in doc.iter_instructions("ENV"):
        value = inst.get("value", "")
        if not value:
            continue
        # ENV can be: KEY=value or KEY value or KEY1=v1 KEY2=v2
        # dockerfile-parse normalizes — let's handle KEY=value pairs
        pairs = []
        # Simple split for KEY=value patterns (this covers the common case)
        for chunk in value.split():
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                pairs.append((k.strip(), v.strip().strip('"').strip("'")))
        if not pairs:
            # Old-style: ENV KEY value
            parts = value.split(None, 1)
            if len(parts) == 2:
                pairs = [(parts[0].strip(), parts[1].strip().strip('"').strip("'"))]

        for key, val in pairs:
            if not val:
                continue
            if not secret_re.search(key):
                continue
            if envvar_ref_re.match(val):
                continue
            if placeholder_re.match(val):
                continue
            yield Finding(
                id="DFA-025",
                category=CATEGORY,
                severity="high",
                instruction="ENV",
                line_number=inst.get("startline", 0) + 1,
                title=f"Hardcoded secret in ENV {key}",
                description=(
                    f"`ENV {key}={val[:8]}...` puts a literal secret into the image. Image "
                    f"layers are inspectable by anyone with pull access; secrets leak through "
                    f"`docker inspect`, registry caches, and CI build logs."
                ),
                remediation=(
                    "Pass secrets at runtime via `--env-file`, Docker secrets, or a "
                    "secret manager. For build-time secrets, use `--mount=type=secret` "
                    "with BuildKit."
                ),
                fix_dockerfile_snippet=f"# Remove this line; pass {key} at runtime",
                references=["OWASP-CSVS-V6"],
            )


@check_meta(id="DFA-027", severity="low", title="No HEALTHCHECK")
def check_no_healthcheck(doc: DockerfileDoc) -> Iterable[Finding]:
    if doc.has_instruction("HEALTHCHECK"):
        return
    yield Finding(
        id="DFA-027",
        category=CATEGORY,
        severity="low",
        instruction=None,
        line_number=None,
        title="No HEALTHCHECK directive",
        description=(
            "No `HEALTHCHECK` defined. Without one, orchestrators can't distinguish "
            "'process running' from 'service healthy', so failed dependencies, hung "
            "processes, and partial startups all look the same."
        ),
        remediation=(
            "Add a HEALTHCHECK that verifies the service actually responds (HTTP /healthz, "
            "DB ping, etc.). For images that have no useful healthcheck, explicitly opt out "
            "with `HEALTHCHECK NONE`."
        ),
        fix_dockerfile_snippet=(
            "HEALTHCHECK --interval=30s --timeout=5s --retries=3 "
            "CMD curl -f http://localhost:8080/healthz || exit 1"
        ),
        references=["docker-docs/builder/healthcheck"],
    )


CHECKS = [
    check_no_user,
    check_user_root,
    check_sudo_in_run,
    check_chmod_777,
    check_curl_pipe_bash,
    check_hardcoded_secret_env,
    check_no_healthcheck,
]
