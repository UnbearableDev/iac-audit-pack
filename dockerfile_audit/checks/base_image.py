"""Base image checks (DFA-001 to DFA-005)."""

from __future__ import annotations

from collections.abc import Iterable

from dockerfile_audit.findings import DockerfileDoc, Finding, check_meta

CATEGORY = "base_image"

# Trusted public registries — others trigger DFA-003
TRUSTED_REGISTRIES = {
    "docker.io",
    "ghcr.io",
    "registry.k8s.io",
    "gcr.io",
    "public.ecr.aws",
    "mcr.microsoft.com",
    "quay.io",
    "registry.gitlab.com",
}


def _parse_from(value: str) -> tuple[str, str | None, str | None, str]:
    """Parse a FROM value into (image_ref, tag, digest, registry).

    Examples:
        'python:3.14' -> ('python', '3.14', None, 'docker.io')
        'ghcr.io/org/app:v1@sha256:abc' -> ('ghcr.io/org/app', 'v1', 'sha256:abc', 'ghcr.io')
        'nginx' -> ('nginx', None, None, 'docker.io')
        'apify/actor-python:3.14' -> ('apify/actor-python', '3.14', None, 'docker.io')
    """
    # Strip `AS <alias>` if present
    v = value.split(" AS ")[0].split(" as ")[0].strip()
    digest = None
    if "@" in v:
        v, digest = v.split("@", 1)
    # Split registry from rest — registry has '.' or ':' (port) in first segment
    parts = v.split("/")
    if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0]):
        registry = parts[0]
        rest = "/".join(parts[1:])
    else:
        registry = "docker.io"
        rest = v
    # Split tag
    if ":" in rest:
        image_ref_short, tag = rest.rsplit(":", 1)
        image_ref = parts[0] + "/" + image_ref_short if registry != "docker.io" else image_ref_short
        if registry != "docker.io":
            image_ref = f"{registry}/{image_ref_short}"
        else:
            image_ref = image_ref_short
    else:
        tag = None
        image_ref = v
    return image_ref, tag, digest, registry


@check_meta(id="DFA-001", severity="medium", title="Image uses :latest tag or no tag")
def check_latest_tag(doc: DockerfileDoc) -> Iterable[Finding]:
    for inst in doc.iter_instructions("FROM"):
        value = inst.get("value", "")
        if not value:
            continue
        # Skip `FROM scratch` and `FROM <alias>` references
        if value.strip().lower().startswith("scratch"):
            continue
        image_ref, tag, digest, _ = _parse_from(value)
        # If pinned by digest, tag-pinning matters less but still recommended
        if tag is None:
            sev = "medium"
            title_suffix = "no tag"
        elif tag == "latest":
            sev = "medium"
            title_suffix = ":latest tag"
        else:
            continue
        yield Finding(
            id="DFA-001",
            category=CATEGORY,
            severity=sev,
            instruction="FROM",
            line_number=inst.get("startline", 0) + 1,
            title=f"Image {image_ref!r} uses {title_suffix}",
            description=(
                f"`FROM {value}` uses {title_suffix}. Builds are not reproducible — "
                f"pulling the same Dockerfile weeks apart can yield different images, "
                f"including breaking changes or supply-chain swaps."
            ),
            remediation=(
                "Pin to a specific version tag. For maximum reproducibility and supply-chain "
                "safety, also pin to a SHA256 digest (see DFA-002)."
            ),
            fix_dockerfile_snippet=f"FROM {image_ref}:<specific-version>",
            references=["CIS-Docker-4.6"],
        )


@check_meta(id="DFA-002", severity="info", title="No SHA256 digest pin on FROM")
def check_no_digest_pin(doc: DockerfileDoc) -> Iterable[Finding]:
    for inst in doc.iter_instructions("FROM"):
        value = inst.get("value", "")
        if not value or value.strip().lower().startswith("scratch"):
            continue
        _, _, digest, _ = _parse_from(value)
        if digest:
            continue
        yield Finding(
            id="DFA-002",
            category=CATEGORY,
            severity="info",
            instruction="FROM",
            line_number=inst.get("startline", 0) + 1,
            title="No SHA256 digest pin on FROM",
            description=(
                f"`FROM {value}` does not pin to a content digest. Tag-based pins can be "
                f"silently retagged by the publisher; digest pins are immutable. Recommended "
                f"for production / supply-chain-sensitive builds."
            ),
            remediation=(
                "Add `@sha256:<digest>` after the tag. Get the digest from "
                "`docker inspect <image>` or the registry UI."
            ),
            fix_dockerfile_snippet=f"FROM {value}@sha256:<digest>",
            references=["CIS-Docker-4.7"],
        )


@check_meta(id="DFA-003", severity="medium", title="Untrusted registry")
def check_untrusted_registry(doc: DockerfileDoc) -> Iterable[Finding]:
    for inst in doc.iter_instructions("FROM"):
        value = inst.get("value", "")
        if not value or value.strip().lower().startswith("scratch"):
            continue
        _, _, _, registry = _parse_from(value)
        # Skip multi-stage aliases (no registry, e.g. `FROM builder`)
        if "/" not in value and ":" not in value and "." not in value:
            continue
        if registry in TRUSTED_REGISTRIES:
            continue
        yield Finding(
            id="DFA-003",
            category=CATEGORY,
            severity="medium",
            instruction="FROM",
            line_number=inst.get("startline", 0) + 1,
            title=f"Image from untrusted registry: {registry}",
            description=(
                f"`FROM {value}` pulls from {registry!r}, which is not in the trusted-publisher "
                f"allowlist ({sorted(TRUSTED_REGISTRIES)}). Supply-chain risk: this registry "
                f"may not enforce the same security standards as major providers."
            ),
            remediation=(
                f"If {registry!r} is a known/trusted internal registry, you can ignore this. "
                "Otherwise, mirror the image to a trusted registry or replace with an "
                "equivalent from docker.io / ghcr.io / quay.io."
            ),
            references=["CIS-Docker-4.1"],
        )


CHECKS = [
    check_latest_tag,
    check_no_digest_pin,
    check_untrusted_registry,
]
