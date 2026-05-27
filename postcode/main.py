"""hu-postcode-validator MCP server entry point.

5 tools backed by an embedded SQLite of HU postcodes (Magyar Posta + KSH data).
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Mapping, MutableMapping
from typing import Any

import uvicorn
from apify import Actor
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.types import Receive, Scope, Send

from postcode import tools


# ── Landing page (for browser visits to /) ──────────────────────────────────

LANDING_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>HU Postcode Validator — MCP server</title>
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
  ul { padding-left: 1.2rem; } li { margin: .35rem 0; }
</style>
</head>
<body>
<h1>Hungarian Postcode Validator — MCP server</h1>
<p class="sub">This is a Model Context Protocol endpoint, not a website.</p>

<p>Point your MCP client at the <code>/mcp</code> path on this host:</p>
<pre>POST /mcp     (Streamable HTTP transport)</pre>

<p>Five tools, all backed by the official Magyar Posta catalog + KSH settlement data:</p>
<ul>
  <li><code>lookup_postcode(postcode)</code> — settlement + county for a postcode</li>
  <li><code>lookup_city(city)</code> — all postcodes for a city (diacritic-insensitive)</li>
  <li><code>validate_address(postcode, city)</code> — yes/no with correction</li>
  <li><code>list_postcodes_in_county(county_name)</code> — bulk listing</li>
  <li><code>budapest_district_lookup(district_number)</code> — BP I-XXIII → postcode range</li>
</ul>

<p><strong>Quick links:</strong></p>
<ul>
  <li><a href="https://apify.com/unbearable_dev/hu-postcode-validator">Apify Store listing</a></li>
  <li><a href="https://modelcontextprotocol.io/clients">MCP client list</a></li>
</ul>

<footer>Built by Unbearable TechTips. Data: Magyar Posta + KSH (Hungarian Central Statistics Office).</footer>
</body>
</html>
""".encode("utf-8")


# ── MCP server ─────────────────────────────────────────────────────────────


def get_server() -> FastMCP:
    """Create the FastMCP server with all 5 tools and PPE charging wired in."""
    server = FastMCP("hu-postcode-validator", "0.1.0")

    # ── Cheap tools — $0.001 each (lookup-call) ──

    @server.tool()
    async def lookup_postcode(postcode: int | str) -> dict[str, Any]:
        """Return settlement(s) and county for a Hungarian postcode."""
        await Actor.charge("lookup-call")
        return await tools.lookup_postcode(postcode)

    @server.tool()
    async def lookup_city(city: str) -> dict[str, Any]:
        """Return all postcodes for a Hungarian city/settlement (diacritic-insensitive)."""
        await Actor.charge("lookup-call")
        return await tools.lookup_city(city)

    @server.tool()
    async def validate_address(postcode: int | str, city: str) -> dict[str, Any]:
        """Validate that postcode and city are a valid Hungarian pairing."""
        await Actor.charge("lookup-call")
        return await tools.validate_address(postcode, city)

    @server.tool()
    async def budapest_district_lookup(district_number: int | str) -> dict[str, Any]:
        """Return Budapest postcodes for a district (1-23 or roman I-XXIII)."""
        await Actor.charge("lookup-call")
        return await tools.budapest_district_lookup(district_number)

    # ── Bulk tool — $0.005 (bulk-call) — returns many rows ──

    @server.tool()
    async def list_postcodes_in_county(county_name: str) -> dict[str, Any]:
        """List all postcodes in a given Hungarian county (vármegye)."""
        await Actor.charge("bulk-call")
        return await tools.list_postcodes_in_county(county_name)

    @server.resource(
        uri="https://unbearabletechtips.com/hu-postcode-validator",
        name="about",
    )
    def about() -> str:
        return (
            "Hungarian Postcode Validator — MCP server by Unbearable TechTips.\n"
            "Data: Magyar Posta official catalog + KSH (Central Statistics Office) settlement data.\n\n"
            "5 tools: lookup_postcode, lookup_city, validate_address, "
            "list_postcodes_in_county, budapest_district_lookup.\n\n"
            "Pricing: pay-per-event ($0.001/call for lookups, $0.005 for county bulk listing). "
            "See the Apify Store listing for current rates."
        )

    return server


# ── Session middleware (lifted verbatim from compose_audit) ─────────────────


def get_session_id(headers: Mapping[str, str]) -> str | None:
    for key in ("mcp-session-id", "mcp_session_id"):
        if value := headers.get(key):
            return value
    return None


class SessionTrackingMiddleware:
    """ASGI middleware that tracks MCP sessions, closes idle ones, and serves
    a friendly HTML landing page for browser visits to /."""

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
                Actor.log.info(f"Closing idle session: {sid}")
                scope: Scope = {
                    "type": "http", "http_version": "1.1", "method": "DELETE",
                    "scheme": "http", "path": "/mcp", "raw_path": b"/mcp",
                    "query_string": b"",
                    "headers": [(b"mcp-session-id", sid.encode())],
                    "server": ("127.0.0.1", self.port),
                    "client": ("127.0.0.1", 0),
                    "_idle_close": True,
                }

                async def noop_receive() -> MutableMapping[str, Any]:
                    return {"type": "http.request", "body": b"", "more_body": False}

                async def noop_send(_: MutableMapping[str, Any]) -> None:
                    pass

                await self(scope, noop_receive, noop_send)
                self._session_cleanup(sid)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                Actor.log.exception(f"Failed to close idle session {sid}: {e}")

        self._timers[sid] = asyncio.create_task(close_if_idle())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")

        # Friendly landing page for GET /
        if (
            scope.get("type") == "http"
            and scope.get("method") == "GET"
            and path in ("", "/")
        ):
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"cache-control", b"public, max-age=3600"),
                ],
            })
            await send({"type": "http.response.body", "body": LANDING_HTML})
            return

        if scope.get("type") != "http" or path not in ("/mcp", "/mcp/"):
            await self.app(scope, receive, send)
            return

        if scope.get("_idle_close"):
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        sid = get_session_id(request.headers)
        is_delete = scope.get("method") == "DELETE"

        if sid and not is_delete:
            self._touch(sid)

        new_sid: str | None = None

        async def capture_send(msg: MutableMapping[str, Any]) -> None:
            nonlocal new_sid
            if msg.get("type") == "http.response.start":
                for k, v in msg.get("headers", []):
                    if k.decode().lower() == "mcp-session-id":
                        new_sid = v.decode()
                        break
            await send(msg)

        await self.app(scope, receive, capture_send)

        if not sid and new_sid:
            Actor.log.info(f"New session: {new_sid}")
            self._touch(new_sid)

        if is_delete and sid:
            Actor.log.info(f"Session closed: {sid}")
            self._session_cleanup(sid)


async def main() -> None:
    await Actor.init()
    port = int(os.environ.get("APIFY_CONTAINER_PORT", "3000"))
    timeout_secs = int(os.environ.get("SESSION_TIMEOUT_SECS", "300"))

    server = get_server()
    app = server.http_app(transport="streamable-http")
    app = SessionTrackingMiddleware(app=app, port=port, timeout_secs=timeout_secs)

    try:
        Actor.log.info(
            f"Starting hu-postcode-validator on port {port} (session timeout: {timeout_secs}s)"
        )
        config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")  # noqa: S104
        await uvicorn.Server(config).serve()
    except KeyboardInterrupt:
        Actor.log.info("Shutting down...")
    except Exception as e:
        Actor.log.error(f"Server failed: {e}")
        raise
