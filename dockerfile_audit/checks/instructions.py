"""Instruction form / order checks (DFA-010 to DFA-015)."""

from __future__ import annotations

from collections.abc import Iterable

from dockerfile_audit.findings import DockerfileDoc, Finding, check_meta

CATEGORY = "instructions"


def _is_exec_form(value: str) -> bool:
    """Check if a CMD/ENTRYPOINT value uses exec form (JSON array)."""
    v = value.strip()
    return v.startswith("[") and v.endswith("]")


@check_meta(id="DFA-010", severity="low", title="CMD in shell form")
def check_cmd_shell_form(doc: DockerfileDoc) -> Iterable[Finding]:
    for inst in doc.iter_instructions("CMD"):
        value = inst.get("value", "")
        if not value or _is_exec_form(value):
            continue
        yield Finding(
            id="DFA-010",
            category=CATEGORY,
            severity="low",
            instruction="CMD",
            line_number=inst.get("startline", 0) + 1,
            title="CMD uses shell form",
            description=(
                "`CMD` in shell form spawns a `/bin/sh -c` wrapper, which breaks signal "
                "handling (SIGTERM doesn't reach the actual process). Exec form is the "
                "production-grade default."
            ),
            remediation=(
                "Convert to exec form (JSON array): use `CMD [\"cmd\", \"arg1\", \"arg2\"]` "
                "instead of `CMD cmd arg1 arg2`."
            ),
            fix_dockerfile_snippet='CMD ["executable", "arg1", "arg2"]',
            references=["docker-docs/builder/cmd"],
        )


@check_meta(id="DFA-011", severity="low", title="ENTRYPOINT in shell form")
def check_entrypoint_shell_form(doc: DockerfileDoc) -> Iterable[Finding]:
    for inst in doc.iter_instructions("ENTRYPOINT"):
        value = inst.get("value", "")
        if not value or _is_exec_form(value):
            continue
        yield Finding(
            id="DFA-011",
            category=CATEGORY,
            severity="low",
            instruction="ENTRYPOINT",
            line_number=inst.get("startline", 0) + 1,
            title="ENTRYPOINT uses shell form",
            description=(
                "`ENTRYPOINT` in shell form spawns a `/bin/sh -c` wrapper. Signals don't "
                "propagate cleanly to your actual process, breaking graceful shutdown."
            ),
            remediation="Convert to exec form: `ENTRYPOINT [\"cmd\", \"arg1\"]`",
            fix_dockerfile_snippet='ENTRYPOINT ["executable", "arg1"]',
            references=["docker-docs/builder/entrypoint"],
        )


@check_meta(id="DFA-012", severity="info", title="MAINTAINER instruction is deprecated")
def check_deprecated_maintainer(doc: DockerfileDoc) -> Iterable[Finding]:
    for inst in doc.iter_instructions("MAINTAINER"):
        yield Finding(
            id="DFA-012",
            category=CATEGORY,
            severity="info",
            instruction="MAINTAINER",
            line_number=inst.get("startline", 0) + 1,
            title="MAINTAINER is deprecated",
            description=(
                "The `MAINTAINER` instruction has been deprecated since Docker 1.13 (2017). "
                "Use a `LABEL maintainer=...` instead."
            ),
            remediation="Replace with a LABEL.",
            fix_dockerfile_snippet='LABEL maintainer="you@example.com"',
            references=["docker-docs/builder/maintainer-deprecated"],
        )


@check_meta(id="DFA-013", severity="medium", title="ADD used where COPY would suffice")
def check_add_vs_copy(doc: DockerfileDoc) -> Iterable[Finding]:
    for inst in doc.iter_instructions("ADD"):
        value = inst.get("value", "")
        if not value:
            continue
        # ADD is acceptable for: URLs (https?://), tarballs (auto-extract)
        first_arg = value.split()[0] if value.split() else ""
        if first_arg.lower().startswith(("http://", "https://")):
            continue  # URL fetch — ADD is appropriate (with caveats)
        if any(first_arg.endswith(ext) for ext in (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tar.zst")):
            continue  # Tarball auto-extract — ADD is appropriate
        yield Finding(
            id="DFA-013",
            category=CATEGORY,
            severity="medium",
            instruction="ADD",
            line_number=inst.get("startline", 0) + 1,
            title="ADD used for plain file copy — prefer COPY",
            description=(
                "`ADD` has implicit behaviors (auto-extract tarballs, fetch URLs) that can "
                "surprise readers and create supply-chain risk. For plain local file copy, "
                "use `COPY` — it's more explicit and the recommended default."
            ),
            remediation="Replace `ADD` with `COPY` for local file copies.",
            fix_dockerfile_snippet=f"COPY {value}",
            references=["docker-docs/builder/add-vs-copy", "Hadolint-DL3020"],
        )


CHECKS = [
    check_cmd_shell_form,
    check_entrypoint_shell_form,
    check_deprecated_maintainer,
    check_add_vs_copy,
]
