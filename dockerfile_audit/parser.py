"""Input resolution + Dockerfile parsing."""

from __future__ import annotations

import httpx
from dockerfile_parse import DockerfileParser

from dockerfile_audit.findings import DockerfileDoc

MAX_DOCKERFILE_BYTES = 200_000  # 200 KB cap (real Dockerfiles are <10 KB)
FETCH_TIMEOUT = httpx.Timeout(5.0)
MAX_REDIRECTS = 3


class DockerfileInputError(ValueError):
    """Raised when input cannot be resolved or parsed."""


async def resolve_dockerfile_input(
    dockerfile_content: str | None,
    dockerfile_url: str | None,
) -> DockerfileDoc:
    if dockerfile_content and dockerfile_url:
        text = dockerfile_content  # prefer literal
    elif dockerfile_content:
        text = dockerfile_content
    elif dockerfile_url:
        text = await _fetch_url(dockerfile_url)
    else:
        raise DockerfileInputError(
            "Provide either `dockerfile_content` or `dockerfile_url`."
        )
    return _parse(text)


async def _fetch_url(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        raise DockerfileInputError(f"dockerfile_url must be HTTP(S), got: {url!r}")
    try:
        async with httpx.AsyncClient(
            timeout=FETCH_TIMEOUT,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
    except httpx.HTTPError as e:
        raise DockerfileInputError(f"Failed to fetch dockerfile_url: {e}") from e
    if len(resp.content) > MAX_DOCKERFILE_BYTES:
        raise DockerfileInputError(
            f"Fetched content exceeds {MAX_DOCKERFILE_BYTES} bytes; refusing to parse."
        )
    return resp.text


def _parse(text: str) -> DockerfileDoc:
    if len(text.encode("utf-8")) > MAX_DOCKERFILE_BYTES:
        raise DockerfileInputError(f"Dockerfile exceeds {MAX_DOCKERFILE_BYTES} bytes.")
    if not text.strip():
        raise DockerfileInputError("Dockerfile is empty.")

    dfp = DockerfileParser()
    dfp.content = text
    instructions = list(dfp.structure)
    return DockerfileDoc(instructions=instructions, raw_content=text)
