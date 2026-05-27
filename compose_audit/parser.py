"""Input resolution and YAML parsing for compose audit tools."""

from __future__ import annotations

import io

import httpx
import yaml

from compose_audit.findings import ComposeDoc

MAX_YAML_BYTES = 1_000_000  # 1 MB cap on fetched compose files
FETCH_TIMEOUT = httpx.Timeout(5.0)
MAX_REDIRECTS = 3


class ComposeInputError(ValueError):
    """Raised when input cannot be resolved or parsed."""


async def resolve_compose_input(
    compose_yaml: str | None,
    compose_url: str | None,
) -> ComposeDoc:
    """Resolve exactly-one-of input flavor into a parsed ComposeDoc.

    Raises ComposeInputError on any input or parsing problem.
    """
    if compose_yaml and compose_url:
        # Per design: prefer YAML, warn (caller can see warning in description)
        yaml_text = compose_yaml
    elif compose_yaml:
        yaml_text = compose_yaml
    elif compose_url:
        yaml_text = await _fetch_url(compose_url)
    else:
        raise ComposeInputError(
            'Provide either `compose_yaml` (YAML content) or `compose_url` (HTTPS URL).'
        )

    return _parse_yaml(yaml_text)


async def _fetch_url(url: str) -> str:
    if not url.lower().startswith(('https://', 'http://')):
        raise ComposeInputError(f'compose_url must be HTTP(S), got: {url!r}')

    try:
        async with httpx.AsyncClient(
            timeout=FETCH_TIMEOUT,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
    except httpx.HTTPError as e:
        raise ComposeInputError(f'Failed to fetch compose_url: {e}') from e

    if len(resp.content) > MAX_YAML_BYTES:
        raise ComposeInputError(
            f'Fetched content exceeds {MAX_YAML_BYTES} bytes; refusing to parse.'
        )

    return resp.text


def _parse_yaml(text: str) -> ComposeDoc:
    if len(text.encode('utf-8')) > MAX_YAML_BYTES:
        raise ComposeInputError(f'compose YAML exceeds {MAX_YAML_BYTES} bytes.')

    try:
        # safe_load — never instantiate arbitrary Python objects
        loaded = yaml.safe_load(io.StringIO(text))
    except yaml.YAMLError as e:
        raise ComposeInputError(f'Invalid YAML: {e}') from e

    if loaded is None:
        raise ComposeInputError('YAML parsed to None (empty document).')

    if not isinstance(loaded, dict):
        raise ComposeInputError(
            f'Expected a YAML mapping at top level, got {type(loaded).__name__}.'
        )

    return ComposeDoc(raw=loaded)
