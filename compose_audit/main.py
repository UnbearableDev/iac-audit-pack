"""Docker Compose Security Audit — MCP server entry point.

Exposes:
- `audit_compose` — run all checks
- `check_<category>` tools — run one category's checks
- `list_checks` — return the full check catalog
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Mapping, MutableMapping
from typing import Any, Literal

import uvicorn
from apify import Actor
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.types import Receive, Scope, Send

from compose_audit import checks as check_registry
from compose_audit.findings import (
    ComposeDoc,
    Finding,
    filter_by_min_severity,
    summarize,
)
from compose_audit.parser import ComposeInputError, resolve_compose_input

Severity = Literal['high', 'medium', 'low', 'info']
DEFAULT_MIN_SEVERITY: Severity = 'low'


def _findings_to_response(findings: list[Finding], doc: ComposeDoc, summary_label: str) -> dict[str, Any]:
    """Build the standard audit response envelope."""
    summary = summarize(findings)
    return {
        'type': 'text',
        'text': (
            f"{summary_label}: {summary['total_findings']} findings "
            f"({summary['by_severity']['high']} high, "
            f"{summary['by_severity']['medium']} medium, "
            f"{summary['by_severity']['low']} low, "
            f"{summary['by_severity']['info']} info)."
        ),
        'structuredContent': {
            'summary': summary,
            'findings': [f.to_dict() for f in findings],
            'compose_metadata': {
                'version': doc.version,
                'service_count': len(doc.services),
                'network_count': len(doc.networks),
                'volume_count': len(doc.volumes),
                'services': sorted(doc.services.keys()),
            },
        },
    }


def _error_response(message: str) -> dict[str, Any]:
    return {
        'type': 'text',
        'text': f'Audit failed: {message}',
        'structuredContent': {'error': message, 'findings': []},
    }


def get_server() -> FastMCP:
    """Create the FastMCP server with all audit tools."""
    server = FastMCP('docker-compose-audit', '0.1.0')

    async def _run_audit(
        compose_yaml: str | None,
        compose_url: str | None,
        min_severity: Severity,
        category: str | None,
    ) -> dict[str, Any]:
        await Actor.charge('audit-call')

        try:
            doc = await resolve_compose_input(compose_yaml, compose_url)
        except ComposeInputError as e:
            return _error_response(str(e))

        if category is None:
            findings = check_registry.run_all(doc)
            label = 'Full audit'
        else:
            try:
                findings = check_registry.run_category(category, doc)
            except ValueError as e:
                return _error_response(str(e))
            label = f'Category {category!r}'

        findings = filter_by_min_severity(findings, min_severity)
        Actor.log.info(
            f'{label}: {len(findings)} findings (min_severity={min_severity}) '
            f'across {len(doc.services)} service(s)'
        )
        return _findings_to_response(findings, doc, label)

    @server.tool()
    async def audit_compose(
        compose_yaml: str | None = None,
        compose_url: str | None = None,
        min_severity: Severity = DEFAULT_MIN_SEVERITY,
    ) -> dict[str, Any]:
        """Run the full security audit against a docker-compose.yml.

        Provide exactly one of `compose_yaml` (paste the YAML) or `compose_url`
        (public HTTPS URL — e.g. a GitHub raw URL). Returns findings grouped by
        category, each with severity, description, remediation, and a YAML fix snippet.

        Args:
            compose_yaml: The docker-compose.yml content as a string.
            compose_url: HTTPS URL to fetch the compose file from (5s timeout, 1MB cap).
            min_severity: Drop findings below this severity. One of: 'info', 'low', 'medium', 'high'. Defaults to 'low'.
        """
        return await _run_audit(compose_yaml, compose_url, min_severity, category=None)

    # Generate per-category tools dynamically — same signature as audit_compose
    # but pinned to a specific category.
    def _make_category_tool(category: str):
        async def _tool(
            compose_yaml: str | None = None,
            compose_url: str | None = None,
            min_severity: Severity = DEFAULT_MIN_SEVERITY,
        ) -> dict[str, Any]:
            return await _run_audit(compose_yaml, compose_url, min_severity, category=category)

        _tool.__name__ = f'check_{category}'
        _tool.__doc__ = (
            f"Run only the {category} checks against a docker-compose.yml.\n\n"
            f"Args:\n"
            f"    compose_yaml: The docker-compose.yml content as a string.\n"
            f"    compose_url: HTTPS URL to fetch from (5s timeout, 1MB cap).\n"
            f"    min_severity: Drop findings below this severity. Defaults to 'low'."
        )
        return _tool

    for category in check_registry.ALL_CATEGORIES:
        tool_fn = _make_category_tool(category)
        server.tool()(tool_fn)

    @server.tool()
    async def list_checks(category: str | None = None) -> dict[str, Any]:
        """List the full catalog of available checks.

        Args:
            category: If provided, return only checks in that category. Otherwise return all.
        """
        await Actor.charge('list-checks')
        catalog = check_registry.catalog()
        if category is not None:
            catalog = [c for c in catalog if c['category'] == category]
        return {
            'type': 'text',
            'text': f'{len(catalog)} checks ({len(check_registry.ALL_CATEGORIES)} categories).',
            'structuredContent': {
                'categories': check_registry.ALL_CATEGORIES,
                'checks': catalog,
            },
        }

    @server.resource(
        uri='https://unbearabletechtips.com/docker-compose-audit',
        name='about',
    )
    def about() -> str:
        return (
            'Docker Compose Security Audit — MCP server by Unbearable TechTips.\n'
            'Trivy-grade docker-compose.yml hardening for AI agents.\n\n'
            f'Categories: {", ".join(check_registry.ALL_CATEGORIES)}\n'
            f'Total checks: {len(check_registry.catalog())}\n\n'
            'Pricing: pay-per-event. See the Apify Store listing for current rates.\n'
        )

    return server


# ── Landing page (for browser visits to /) ──────────────────────────────────

LANDING_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Docker Compose Security Audit — MCP server</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 680px; margin: 60px auto; padding: 0 24px; line-height: 1.55;
         color: #1a1a1a; background: #fafafa; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem 0; }
  .sub { color: #666; margin: 0 0 2rem 0; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
              background: #efefef; padding: 2px 6px; border-radius: 3px; font-size: .9rem; }
  pre { padding: 12px; overflow-x: auto; }
  a { color: #0366d6; text-decoration: none; }
  a:hover { text-decoration: underline; }
  footer { margin-top: 3rem; font-size: .85rem; color: #888; }
  ul { padding-left: 1.2rem; }
  li { margin: .35rem 0; }
</style>
</head>
<body>
<h1>Docker Compose Security Audit — MCP server</h1>
<p class="sub">This is a Model Context Protocol endpoint, not a website.</p>

<p>Point your MCP client at the <code>/mcp</code> path on this host:</p>
<pre>POST /mcp     (with Streamable HTTP transport)</pre>

<p>11 tools are available, including <code>audit_compose</code>, per-category checks (<code>check_privilege</code>, <code>check_network</code>, etc.), and <code>list_checks</code>. Every finding includes severity, remediation text, and a YAML fix snippet.</p>

<p><strong>Quick links:</strong></p>
<ul>
  <li><a href="https://apify.com/unbearable_dev/docker-compose-audit">Apify Store listing</a> — description, pricing, "Try for free"</li>
  <li><a href="https://modelcontextprotocol.io/clients">MCP client list</a> — Claude Desktop, Cursor, Continue, etc.</li>
</ul>

<footer>Built by Unbearable TechTips.</footer>
</body>
</html>
""".encode('utf-8')


# ── Session middleware (extended with landing-page handler) ─────────────────

def get_session_id(headers: Mapping[str, str]) -> str | None:
    """Extract session ID from request headers."""
    for key in ('mcp-session-id', 'mcp_session_id'):
        if value := headers.get(key):
            return value
    return None


class SessionTrackingMiddleware:
    """ASGI middleware that tracks MCP sessions and closes idle ones."""

    def __init__(self, app: Any, port: int, timeout_secs: int) -> None:
        self.app = app
        self.port = port
        self.timeout_secs = timeout_secs

        self._last_activity: dict[str, float] = {}
        self._timers: dict[str, asyncio.Task[None]] = {}

    def _session_cleanup(self, sid: str) -> None:
        self._last_activity.pop(sid, None)
        if (timer := self._timers.pop(sid, None)) and not timer.done():
            timer.cancel()

    def _touch(self, sid: str) -> None:
        self._last_activity[sid] = time.time()

        if (timer := self._timers.get(sid)) and not timer.done():
            timer.cancel()

        async def close_if_idle() -> None:
            try:
                await asyncio.sleep(self.timeout_secs)

                elapsed = time.time() - self._last_activity.get(sid, 0)
                if elapsed < self.timeout_secs * 0.9:
                    return

                Actor.log.info(f'Closing idle session: {sid}')

                scope: Scope = {
                    'type': 'http',
                    'http_version': '1.1',
                    'method': 'DELETE',
                    'scheme': 'http',
                    'path': '/mcp',
                    'raw_path': b'/mcp',
                    'query_string': b'',
                    'headers': [(b'mcp-session-id', sid.encode())],
                    'server': ('127.0.0.1', self.port),
                    'client': ('127.0.0.1', 0),
                    '_idle_close': True,
                }

                async def noop_receive() -> MutableMapping[str, Any]:
                    return {'type': 'http.request', 'body': b'', 'more_body': False}

                async def noop_send(_: MutableMapping[str, Any]) -> None:
                    pass

                await self(scope, noop_receive, noop_send)
                self._session_cleanup(sid)

            except asyncio.CancelledError:
                pass
            except Exception as e:
                Actor.log.exception(f'Failed to close idle session {sid}: {e}')

        self._timers[sid] = asyncio.create_task(close_if_idle())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get('path', '')

        # Friendly landing page for browser visits to the bare URL
        if (
            scope.get('type') == 'http'
            and scope.get('method') == 'GET'
            and path in ('', '/')
        ):
            await send({
                'type': 'http.response.start',
                'status': 200,
                'headers': [
                    (b'content-type', b'text/html; charset=utf-8'),
                    (b'cache-control', b'public, max-age=3600'),
                ],
            })
            await send({
                'type': 'http.response.body',
                'body': LANDING_HTML,
            })
            return

        if scope.get('type') != 'http' or path not in ('/mcp', '/mcp/'):
            await self.app(scope, receive, send)
            return

        if scope.get('_idle_close'):
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        sid = get_session_id(request.headers)
        is_delete = scope.get('method') == 'DELETE'

        if sid and not is_delete:
            self._touch(sid)

        new_sid: str | None = None

        async def capture_send(msg: MutableMapping[str, Any]) -> None:
            nonlocal new_sid
            if msg.get('type') == 'http.response.start':
                for k, v in msg.get('headers', []):
                    if k.decode().lower() == 'mcp-session-id':
                        new_sid = v.decode()
                        break
            await send(msg)

        await self.app(scope, receive, capture_send)

        if not sid and new_sid:
            Actor.log.info(f'New session: {new_sid}')
            self._touch(new_sid)

        if is_delete and sid:
            Actor.log.info(f'Session closed: {sid}')
            self._session_cleanup(sid)


async def main() -> None:
    await Actor.init()

    port = int(os.environ.get('APIFY_CONTAINER_PORT', '3000'))
    timeout_secs = int(os.environ.get('SESSION_TIMEOUT_SECS', '300'))

    server = get_server()
    app = server.http_app(transport='streamable-http')
    app = SessionTrackingMiddleware(app=app, port=port, timeout_secs=timeout_secs)

    try:
        Actor.log.info(f'Starting MCP server on port {port} (session timeout: {timeout_secs}s)')
        config = uvicorn.Config(app, host='0.0.0.0', port=port, log_level='info')  # noqa: S104
        await uvicorn.Server(config).serve()
    except KeyboardInterrupt:
        Actor.log.info('Shutting down...')
    except Exception as e:
        Actor.log.error(f'Server failed: {e}')
        raise
