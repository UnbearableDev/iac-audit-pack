"""Image hygiene checks (DCS-037 to DCS-042)."""

from __future__ import annotations

from collections.abc import Iterable

from compose_audit.findings import ComposeDoc, Finding

from compose_audit.findings import check_meta

CATEGORY = 'image_hygiene'


@check_meta(id='DCS-037', severity='medium', title='Image uses :latest tag or no tag')
def check_latest_tag(doc: ComposeDoc) -> Iterable[Finding]:
    for name, svc in doc.iter_services():
        image = svc.get('image')
        if not image or not isinstance(image, str):
            continue
        # Strip digest if present
        image_no_digest = image.split('@', 1)[0]
        # Find tag — last colon AFTER any port number in the registry
        # Simplest heuristic: split on last colon, if RHS contains '/' it's not a tag
        if ':' in image_no_digest:
            parts = image_no_digest.rsplit(':', 1)
            tag = parts[1] if '/' not in parts[1] else None
        else:
            tag = None

        if tag is None or tag == 'latest':
            yield Finding(
                id='DCS-037',
                category=CATEGORY,
                severity='medium',
                service=name,
                title=f'Image {image!r} is unpinned',
                description=(
                    f"Service '{name}' uses image {image!r} with "
                    f"{'no tag' if tag is None else 'the :latest tag'}. "
                    f"Builds are not reproducible — pulling the same compose file weeks apart "
                    f"can yield different images, including breaking changes or supply-chain swaps."
                ),
                remediation=(
                    "Pin to a specific version tag. For maximum reproducibility and supply-chain "
                    "safety, pin to a SHA256 digest."
                ),
                fix_yaml_snippet=f'    image: {image_no_digest}:<specific-version>',
                references=['CIS-Docker-4.6'],
            )


CHECKS = [
    check_latest_tag,
]
