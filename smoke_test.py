#!/usr/bin/env python3
"""Local smoke test for iac-audit-pack.

Run after `apify run` is up (server on localhost:4321/4325).

Usage:
    python smoke_test.py [--port 4325]
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

PORT = 4321
if "--port" in sys.argv:
    PORT = int(sys.argv[sys.argv.index("--port") + 1])

BASE = f"http://localhost:{PORT}/mcp"

BAD_COMPOSE = """\
version: "3.8"
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
      - "22:22"
    privileged: true
    environment:
      DB_PASSWORD: "supersecret123"
      API_TOKEN: "ghp_actualtoken123abc"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host-etc:ro
  db:
    image: postgres
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: hardcoded-not-a-ref
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
    network_mode: host
  cache:
    image: redis:latest
    ports:
      - "6379:6379"
"""

BAD_DOCKERFILE = """\
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ADD . /app
USER root
"""

PASSES = 0
FAILURES = 0

_SESSION_ID: str | None = None


def rpc(method: str, params: dict) -> dict:
    """Send one JSON-RPC call, carrying the session ID automatically."""
    global _SESSION_ID
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if _SESSION_ID:
        headers["mcp-session-id"] = _SESSION_ID

    req = urllib.request.Request(BASE, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            # Capture session ID from response headers
            new_sid = resp.headers.get("mcp-session-id")
            if new_sid:
                _SESSION_ID = new_sid
            # Parse SSE (event:/data: envelope) or plain JSON
            data_lines = [
                line[5:].strip()
                for line in raw.splitlines()
                if line.startswith("data:") and line.strip() != "data:"
            ]
            if data_lines:
                return json.loads(data_lines[0])
            elif raw.strip():
                return json.loads(raw)
            return {}
    except urllib.error.HTTPError as e:
        body_err = e.read().decode()
        print(f"  HTTP {e.code}: {body_err[:300]}")
        return {}


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASSES, FAILURES
    if condition:
        PASSES += 1
        print(f"  PASS  {name}")
    else:
        FAILURES += 1
        print(f"  FAIL  {name}" + (f" -- {detail}" if detail else ""))


def get_structured_content(resp: dict) -> dict:
    """Extract structuredContent from MCP tools/call response."""
    content = resp.get("result", {}).get("content", [])
    if content:
        sc = content[0].get("structuredContent", {})
        if sc:
            return sc
        # Some versions wrap text as JSON string
        text = content[0].get("text", "")
        try:
            parsed = json.loads(text)
            return parsed.get("structuredContent", parsed)
        except (json.JSONDecodeError, AttributeError):
            pass
    # Also check top-level structuredContent (some FastMCP versions)
    sc = resp.get("result", {}).get("structuredContent", {})
    return sc


print(f"\n=== IaC Audit Pack smoke test (port {PORT}) ===\n")

# --- Step 1: Initialize ---
print("1. Protocol negotiation (initialize)")
init_resp = rpc("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "smoke-test", "version": "0.1"},
})
check("initialize returns result", "result" in init_resp, str(init_resp)[:100])
print(f"     session-id: {_SESSION_ID}")

# Notify initialized
rpc("notifications/initialized", {})

# --- Step 2: tools/list ---
print("\n2. tools/list — count and spot-check")
list_resp = rpc("tools/list", {})
tools = list_resp.get("result", {}).get("tools", [])
tool_names = {t["name"] for t in tools}

# Expected: 9 compose cats + 5 df cats + 5 gha cats + 3 primary audits
#           + audit_all + 3 list tools + 6 postcode tools + list_all_checks = 33
check(f"tool count >= 30 (got {len(tools)})", len(tools) >= 30)
check("audit_compose present", "audit_compose" in tool_names)
check("audit_dockerfile present", "audit_dockerfile" in tool_names)
check("audit_github_actions present", "audit_github_actions" in tool_names)
check("audit_all present", "audit_all" in tool_names)
check("list_all_checks present", "list_all_checks" in tool_names)
check("list_checks_compose present", "list_checks_compose" in tool_names)
check("list_checks_dockerfile present", "list_checks_dockerfile" in tool_names)
check("list_checks_github_actions present", "list_checks_github_actions" in tool_names)
check("validate_postcode present", "validate_postcode" in tool_names)
check("lookup_city present", "lookup_city" in tool_names)
check("budapest_district_lookup present", "budapest_district_lookup" in tool_names)
# compose category tools
for cat in ["check_privilege", "check_network", "check_secrets", "check_filesystem"]:
    check(f"{cat} present", cat in tool_names)
# dockerfile category tools (suffixed)
check("check_security_dockerfile present", "check_security_dockerfile" in tool_names)
check("check_base_image_dockerfile present", "check_base_image_dockerfile" in tool_names)
# GHA category tools (suffixed)
check("check_secrets_gha present", "check_secrets_gha" in tool_names)
check("check_permissions_gha present", "check_permissions_gha" in tool_names)

# --- Step 3: audit_compose regression (bad-compose fixture) ---
print("\n3. audit_compose regression (bad-compose fixture)")
audit_resp = rpc("tools/call", {
    "name": "audit_compose",
    "arguments": {"compose_yaml": BAD_COMPOSE, "min_severity": "low"},
})
sc = get_structured_content(audit_resp)
findings = sc.get("findings", [])
summary = sc.get("summary", {})
high_count = summary.get("by_severity", {}).get("high", 0)

check(f"audit_compose returns findings (got {len(findings)})", len(findings) > 0)
check(f"audit_compose finds high-severity issues (high={high_count})", high_count > 0)
check("privileged=true flagged", any(
    "privileged" in str(f).lower() for f in findings
))
check("hardcoded secret or password flagged", any(
    "secret" in str(f).lower() or "password" in str(f).lower() or "token" in str(f).lower()
    for f in findings
))

# --- Step 4: audit_all multi-file ---
print("\n4. audit_all multi-file (compose + dockerfile)")
all_resp = rpc("tools/call", {
    "name": "audit_all",
    "arguments": {
        "files": {
            "docker-compose.yml": BAD_COMPOSE,
            "Dockerfile": BAD_DOCKERFILE,
        },
        "min_severity": "low",
    },
})
all_sc = get_structured_content(all_resp)
all_results = all_sc.get("results", [])
all_types = {r.get("type") for r in all_results}
total_findings = all_sc.get("total_findings", 0)

check(f"audit_all returns 2 file results (got {len(all_results)})", len(all_results) == 2)
check("docker-compose type detected", "docker-compose" in all_types)
check("dockerfile type detected", "dockerfile" in all_types)
check(f"audit_all total_findings > 0 (got {total_findings})", total_findings > 0)

# --- Summary ---
total = PASSES + FAILURES
print(f"\n=== {PASSES}/{total} passed ===\n")
sys.exit(0 if FAILURES == 0 else 1)
