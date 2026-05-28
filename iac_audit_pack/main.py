"""Unbearable IaC Audit Pack — MCP server entry point.

All four Unbearable TechTips audit packages bundled under one FastMCP server:
  - compose_audit   (25 checks, 9 categories) -> audit_compose, check_<category>, list_checks_compose
  - dockerfile_audit (18 checks, 5 categories) -> audit_dockerfile, check_<category>_dockerfile, list_checks_dockerfile
  - gha_audit        (13 checks, 5 categories) -> audit_github_actions, check_<category>_gha, list_checks_github_actions
  - postcode         (5 tools)                 -> validate_postcode, lookup_postcode, lookup_city,
                                                  validate_address, list_postcodes_in_county,
                                                  budapest_district_lookup
  - PLUS: audit_all(files) aggregation tool
  - PLUS: list_all_checks  discovery mega-tool

Architecture: Package-import (Option B).  The sub-packages are copied directly
into this Actor's source tree at deploy time (see sync-packages.sh).  Zero
cross-Actor calls, single cold start, one billing rail.

Pricing: PPE placeholders ($0.02 audit, $0.005 list, $0.001 postcode lookup).
# TODO: switch to monthly rental ~$19/mo via Apify Console once Actor is public.
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

# Sub-package imports — these packages live in the bundle's own source tree
from compose_audit import checks as compose_checks
from compose_audit.findings import filter_by_min_severity as compose_filter, summarize as compose_summarize
from compose_audit.parser import ComposeInputError, resolve_compose_input

from dockerfile_audit import checks as df_checks
from dockerfile_audit.findings import filter_by_min_severity as df_filter, summarize as df_summarize
from dockerfile_audit.parser import DockerfileInputError, resolve_dockerfile_input

from gha_audit import checks as gha_checks
from gha_audit.findings import filter_by_min_severity as gha_filter, summarize as gha_summarize
from gha_audit.parser import WorkflowInputError, resolve_workflow_input

from postcode import tools as postcode_tools

Severity = Literal["high", "medium", "low", "info"]
DEFAULT_MIN_SEVERITY: Severity = "low"
_ANNOTATIONS = {    "readOnlyHint": True,    "destructiveHint": False,    "idempotentHint": True,    "openWorldHint": True,}

_ANNOTATIONS_LOCAL = {    "readOnlyHint": True,    "destructiveHint": False,    "idempotentHint": True,    "openWorldHint": False,}


# ---------------------------------------------------------------------------
# Helper: error envelope
# ---------------------------------------------------------------------------

def _error_response(message: str) -> dict[str, Any]:
    return {
        "type": "text",
        "text": f"Audit failed: {message}",
        "structuredContent": {"error": message, "findings": []},
    }


# ---------------------------------------------------------------------------
# Landing page HTML
# ---------------------------------------------------------------------------

LANDING_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Unbearable IaC Audit Pack — MCP server</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 700px; margin: 60px auto; padding: 0 24px; line-height: 1.55;
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
<h1>Unbearable IaC Audit Pack — MCP server</h1>
<p class="sub">All four audit Actors under one MCP endpoint. Snyk-comparable scope at 10x cheaper. $19/mo unlimited.</p>

<p>Point your MCP client at the <code>/mcp</code> path on this host:</p>
<pre>POST /mcp     (Streamable HTTP transport)</pre>

<p>50+ tools across four packages: docker-compose audit (25 checks), Dockerfile audit (18 checks),
GitHub Actions audit (13 checks), HU postcode validator (5 tools), plus <code>audit_all</code>
for multi-file detection and <code>list_all_checks</code> for discovery.</p>

<p><strong>Quick links:</strong></p>
<ul>
  <li><a href="https://apify.com/unbearable_dev/iac-audit-pack">Apify Store listing</a></li>
  <li><a href="https://modelcontextprotocol.io/clients">MCP client list</a></li>
</ul>

<footer>Built by Noel @ Unbearable TechTips — more like this in the weekly newsletter
<a href="https://unbearabletechtips.beehiiv.com">[link]</a>.</footer>
</body>
</html>
""".encode("utf-8")


# ---------------------------------------------------------------------------
# Server builder
# ---------------------------------------------------------------------------

def get_server() -> FastMCP:
    """Assemble all tools from all four sub-packages into one FastMCP server."""
    server = FastMCP("iac-audit-pack", "0.1.0")

    # ===================================================================
    # 1. COMPOSE AUDIT
    # ===================================================================

    async def _run_compose_audit(
        compose_yaml: str | None,
        compose_url: str | None,
        min_severity: Severity,
        category: str | None,
    ) -> dict[str, Any]:
        await Actor.charge("audit-call")
        try:
            doc = await resolve_compose_input(compose_yaml, compose_url)
        except ComposeInputError as e:
            return _error_response(str(e))

        if category is None:
            findings = compose_checks.run_all(doc)
            label = "Full compose audit"
        else:
            try:
                findings = compose_checks.run_category(category, doc)
            except ValueError as e:
                return _error_response(str(e))
            label = f"Compose category {category!r}"

        findings = compose_filter(findings, min_severity)
        summary = compose_summarize(findings)
        Actor.log.info(f"{label}: {len(findings)} findings across {len(doc.services)} service(s)")
        return {
            "type": "text",
            "text": (
                f"{label}: {summary['total_findings']} findings "
                f"({summary['by_severity']['high']} high, "
                f"{summary['by_severity']['medium']} medium, "
                f"{summary['by_severity']['low']} low, "
                f"{summary['by_severity']['info']} info)."
            ),
            "structuredContent": {
                "source": "compose_audit",
                "summary": summary,
                "findings": [f.to_dict() for f in findings],
                "compose_metadata": {
                    "version": doc.version,
                    "service_count": len(doc.services),
                    "network_count": len(doc.networks),
                    "volume_count": len(doc.volumes),
                    "services": sorted(doc.services.keys()),
                },
            },
        }

    @server.tool(annotations=_ANNOTATIONS)
    async def audit_compose(
        compose_yaml: str | None = None,
        compose_url: str | None = None,
        min_severity: Severity = DEFAULT_MIN_SEVERITY,
    ) -> dict[str, Any]:
        """Run the full security audit against a docker-compose.yml.

        Provide exactly one of compose_yaml (paste the YAML) or compose_url
        (public HTTPS URL). Returns 25 checks across 9 categories with severity,
        remediation, and YAML fix snippets.

        Args:
            compose_yaml: The docker-compose.yml content as a string.
            compose_url: HTTPS URL to fetch the compose file from (5s timeout, 1MB cap).
            min_severity: Drop findings below this severity. One of: info, low, medium, high. Default low.
        """
        return await _run_compose_audit(compose_yaml, compose_url, min_severity, None)

    def _make_compose_category_tool(category: str):
        async def _tool(
            compose_yaml: str | None = None,
            compose_url: str | None = None,
            min_severity: Severity = DEFAULT_MIN_SEVERITY,
        ) -> dict[str, Any]:
            return await _run_compose_audit(compose_yaml, compose_url, min_severity, category)
        _tool.__name__ = f"check_{category}"
        _tool.__doc__ = (
            f"Run only the compose {category!r} checks against a docker-compose.yml.\n\n"
            f"Args:\n"
            f"    compose_yaml: The docker-compose.yml content as a string.\n"
            f"    compose_url: HTTPS URL to fetch from (5s timeout, 1MB cap).\n"
            f"    min_severity: Drop findings below this severity. Default low."
        )
        return _tool

    for _cat in compose_checks.ALL_CATEGORIES:
        server.tool(annotations=_ANNOTATIONS)(_make_compose_category_tool(_cat))

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def list_checks_compose(category: str | None = None) -> dict[str, Any]:
        """List the full catalog of docker-compose audit checks (25 checks, 9 categories).

        Args:
            category: If provided, return only checks in that category.
        """
        await Actor.charge("list-checks")
        catalog = compose_checks.catalog()
        if category is not None:
            catalog = [c for c in catalog if c["category"] == category]
        return {
            "type": "text",
            "text": f"{len(catalog)} compose checks ({len(compose_checks.ALL_CATEGORIES)} categories).",
            "structuredContent": {
                "source": "compose_audit",
                "categories": compose_checks.ALL_CATEGORIES,
                "checks": catalog,
            },
        }

    # ===================================================================
    # 2. DOCKERFILE AUDIT
    # ===================================================================

    async def _run_dockerfile_audit(
        dockerfile_content: str | None,
        dockerfile_url: str | None,
        min_severity: Severity,
        category: str | None,
    ) -> dict[str, Any]:
        await Actor.charge("audit-call")
        try:
            doc = await resolve_dockerfile_input(dockerfile_content, dockerfile_url)
        except DockerfileInputError as e:
            return _error_response(str(e))

        if category is None:
            findings = df_checks.run_all(doc)
            label = "Full Dockerfile audit"
        else:
            try:
                findings = df_checks.run_category(category, doc)
            except ValueError as e:
                return _error_response(str(e))
            label = f"Dockerfile category {category!r}"

        findings = df_filter(findings, min_severity)
        summary = df_summarize(findings)
        Actor.log.info(f"{label}: {len(findings)} findings across {len(doc.instructions)} instructions")
        return {
            "type": "text",
            "text": (
                f"{label}: {summary['total_findings']} findings "
                f"({summary['by_severity']['high']} high, "
                f"{summary['by_severity']['medium']} medium, "
                f"{summary['by_severity']['low']} low, "
                f"{summary['by_severity']['info']} info)."
            ),
            "structuredContent": {
                "source": "dockerfile_audit",
                "summary": summary,
                "findings": [f.to_dict() for f in findings],
                "dockerfile_metadata": {
                    "instruction_count": len(doc.instructions),
                    "from_count": len(doc.from_lines),
                    "lines": doc.raw_content.count("\n") + 1,
                },
            },
        }

    @server.tool(annotations=_ANNOTATIONS)
    async def audit_dockerfile(
        dockerfile_content: str | None = None,
        dockerfile_url: str | None = None,
        min_severity: Severity = DEFAULT_MIN_SEVERITY,
    ) -> dict[str, Any]:
        """Run the full security and quality audit against a Dockerfile.

        Provide exactly one of dockerfile_content (paste the Dockerfile) or
        dockerfile_url (public HTTPS URL). Returns 18 checks across 5 categories
        with severity, line numbers, remediation, and fix snippets.

        Args:
            dockerfile_content: The Dockerfile content as a string.
            dockerfile_url: HTTPS URL to fetch the Dockerfile from (5s timeout, 200KB cap).
            min_severity: Drop findings below this severity. Default low.
        """
        return await _run_dockerfile_audit(dockerfile_content, dockerfile_url, min_severity, None)

    def _make_dockerfile_category_tool(category: str):
        async def _tool(
            dockerfile_content: str | None = None,
            dockerfile_url: str | None = None,
            min_severity: Severity = DEFAULT_MIN_SEVERITY,
        ) -> dict[str, Any]:
            return await _run_dockerfile_audit(dockerfile_content, dockerfile_url, min_severity, category)
        _tool.__name__ = f"check_{category}_dockerfile"
        _tool.__doc__ = (
            f"Run only the Dockerfile {category!r} checks against a Dockerfile.\n\n"
            f"Args:\n"
            f"    dockerfile_content: The Dockerfile content as a string.\n"
            f"    dockerfile_url: HTTPS URL to fetch from.\n"
            f"    min_severity: Drop findings below this severity. Default low."
        )
        return _tool

    for _cat in df_checks.ALL_CATEGORIES:
        server.tool(annotations=_ANNOTATIONS)(_make_dockerfile_category_tool(_cat))

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def list_checks_dockerfile(category: str | None = None) -> dict[str, Any]:
        """List the full catalog of Dockerfile audit checks (18 checks, 5 categories).

        Args:
            category: If provided, return only checks in that category.
        """
        await Actor.charge("list-checks")
        catalog = df_checks.catalog()
        if category is not None:
            catalog = [c for c in catalog if c["category"] == category]
        return {
            "type": "text",
            "text": f"{len(catalog)} Dockerfile checks ({len(df_checks.ALL_CATEGORIES)} categories).",
            "structuredContent": {
                "source": "dockerfile_audit",
                "categories": df_checks.ALL_CATEGORIES,
                "checks": catalog,
            },
        }

    # ===================================================================
    # 3. GITHUB ACTIONS AUDIT
    # ===================================================================

    async def _run_gha_audit(
        workflow_yaml: str | None,
        workflow_url: str | None,
        min_severity: Severity,
        category: str | None,
    ) -> dict[str, Any]:
        await Actor.charge("audit-call")
        try:
            doc = await resolve_workflow_input(workflow_yaml, workflow_url)
        except WorkflowInputError as e:
            return _error_response(str(e))

        if category is None:
            findings = gha_checks.run_all(doc)
            label = "Full GHA audit"
        else:
            try:
                findings = gha_checks.run_category(category, doc)
            except ValueError as e:
                return _error_response(str(e))
            label = f"GHA category {category!r}"

        findings = gha_filter(findings, min_severity)
        summary = gha_summarize(findings)
        Actor.log.info(f"{label}: {len(findings)} findings across {len(doc.jobs)} jobs")
        return {
            "type": "text",
            "text": (
                f"{label}: {summary['total_findings']} findings "
                f"({summary['by_severity']['high']} high, "
                f"{summary['by_severity']['medium']} medium, "
                f"{summary['by_severity']['low']} low, "
                f"{summary['by_severity']['info']} info)."
            ),
            "structuredContent": {
                "source": "gha_audit",
                "summary": summary,
                "findings": [f.to_dict() for f in findings],
                "workflow_metadata": {
                    "name": doc.name,
                    "job_count": len(doc.jobs),
                    "triggers": list(doc.on.keys()) if isinstance(doc.on, dict) else doc.on,
                },
            },
        }

    @server.tool(annotations=_ANNOTATIONS)
    async def audit_github_actions(
        workflow_yaml: str | None = None,
        workflow_url: str | None = None,
        min_severity: Severity = DEFAULT_MIN_SEVERITY,
    ) -> dict[str, Any]:
        """Run the full security audit against a GitHub Actions workflow file.

        Provide exactly one of workflow_yaml (paste the YAML) or workflow_url
        (public HTTPS URL to a .github/workflows/*.yml file). Returns 13 checks
        across 5 categories covering supply-chain, token leaks, permissions,
        and script injection.

        Args:
            workflow_yaml: The workflow YAML content as a string.
            workflow_url: HTTPS URL to a workflow file (5s timeout, 500KB cap).
            min_severity: Drop findings below this severity. Default low.
        """
        return await _run_gha_audit(workflow_yaml, workflow_url, min_severity, None)

    def _make_gha_category_tool(category: str):
        async def _tool(
            workflow_yaml: str | None = None,
            workflow_url: str | None = None,
            min_severity: Severity = DEFAULT_MIN_SEVERITY,
        ) -> dict[str, Any]:
            return await _run_gha_audit(workflow_yaml, workflow_url, min_severity, category)
        _tool.__name__ = f"check_{category}_gha"
        _tool.__doc__ = (
            f"Run only the GitHub Actions {category!r} checks against a workflow file.\n\n"
            f"Args:\n"
            f"    workflow_yaml: The workflow YAML content as a string.\n"
            f"    workflow_url: HTTPS URL to a workflow file.\n"
            f"    min_severity: Drop findings below this severity. Default low."
        )
        return _tool

    for _cat in gha_checks.ALL_CATEGORIES:
        server.tool(annotations=_ANNOTATIONS)(_make_gha_category_tool(_cat))

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def list_checks_github_actions(category: str | None = None) -> dict[str, Any]:
        """List the full catalog of GitHub Actions audit checks (13 checks, 5 categories).

        Args:
            category: If provided, return only checks in that category.
        """
        await Actor.charge("list-checks")
        catalog = gha_checks.catalog()
        if category is not None:
            catalog = [c for c in catalog if c["category"] == category]
        return {
            "type": "text",
            "text": f"{len(catalog)} GHA checks ({len(gha_checks.ALL_CATEGORIES)} categories).",
            "structuredContent": {
                "source": "gha_audit",
                "categories": gha_checks.ALL_CATEGORIES,
                "checks": catalog,
            },
        }

    # ===================================================================
    # 4. HU POSTCODE VALIDATOR
    # ===================================================================

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def validate_postcode(postcode: int | str) -> dict[str, Any]:
        """Return settlement(s) and county for a Hungarian postcode.

        Args:
            postcode: 4-digit Hungarian postcode (int or string of digits).
        """
        await Actor.charge("lookup-call")
        return await postcode_tools.lookup_postcode(postcode)

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def lookup_postcode(postcode: int | str) -> dict[str, Any]:
        """Alias for validate_postcode — return settlement(s) and county for a HU postcode.

        Args:
            postcode: 4-digit Hungarian postcode (int or string of digits).
        """
        await Actor.charge("lookup-call")
        return await postcode_tools.lookup_postcode(postcode)

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def lookup_city(city: str) -> dict[str, Any]:
        """Return all postcodes for a Hungarian city/settlement (diacritic-insensitive).

        Args:
            city: Hungarian settlement name (e.g. Szeged, Gyor, Budapest).
        """
        await Actor.charge("lookup-call")
        return await postcode_tools.lookup_city(city)

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def validate_address(postcode: int | str, city: str) -> dict[str, Any]:
        """Validate that postcode and city are a valid Hungarian pairing.

        Args:
            postcode: 4-digit HU postcode.
            city: Settlement name.
        """
        await Actor.charge("lookup-call")
        return await postcode_tools.validate_address(postcode, city)

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def list_postcodes_in_county(county_name: str) -> dict[str, Any]:
        """List all postcodes in a given Hungarian county (varmegye).

        Args:
            county_name: County name, e.g. Pest, Csongrad-Csanad, Budapest.
        """
        await Actor.charge("bulk-call")
        return await postcode_tools.list_postcodes_in_county(county_name)

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def budapest_district_lookup(district_number: int | str) -> dict[str, Any]:
        """Return Budapest postcodes for a district (I-XXIII or 1-23).

        Args:
            district_number: District as int (1-23) or roman numeral string (X, XIV).
        """
        await Actor.charge("lookup-call")
        return await postcode_tools.budapest_district_lookup(district_number)

    # ===================================================================
    # 5. AGGREGATION: audit_all
    # ===================================================================

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def audit_all(
        files: dict[str, str],
        min_severity: Severity = DEFAULT_MIN_SEVERITY,
    ) -> dict[str, Any]:
        """Detect file types and run the appropriate audit on each, returning a combined report.

        Detects: docker-compose.yml (compose audit), Dockerfile (dockerfile audit),
        .github/workflows/*.yml (GHA audit).  Runs all applicable audits and merges
        findings into a single response envelope.

        Args:
            files: Dict mapping filename -> file content (string).
                   e.g. {"docker-compose.yml": "...", "Dockerfile": "..."}
            min_severity: Drop findings below this severity across all audits. Default low.
        """
        if not files:
            return _error_response("files dict is empty — provide at least one file")

        results: list[dict[str, Any]] = []
        total_findings = 0
        errors: list[str] = []

        for filename, content in files.items():
            name_lower = filename.lower()
            fname_only = filename.rsplit("/", 1)[-1].lower()

            # --- detect file type ---
            is_compose = fname_only in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
            is_dockerfile = fname_only == "dockerfile" or fname_only.startswith("dockerfile.")
            is_workflow = (
                ".github/workflows/" in filename.lower()
                and (fname_only.endswith(".yml") or fname_only.endswith(".yaml"))
            )

            # fallback heuristic for bare filenames
            if not (is_compose or is_dockerfile or is_workflow):
                if "compose" in name_lower and (name_lower.endswith(".yml") or name_lower.endswith(".yaml")):
                    is_compose = True
                elif name_lower.endswith(".yml") or name_lower.endswith(".yaml"):
                    # peek inside: if it has "on:" / "jobs:" keys it's likely a workflow
                    is_workflow = ("jobs:" in content and ("on:" in content or "\"on\":" in content))
                    if not is_workflow:
                        is_compose = True  # assume compose if not workflow

            if is_compose:
                try:
                    doc = await resolve_compose_input(content, None)
                except ComposeInputError as e:
                    errors.append(f"{filename}: compose parse error — {e}")
                    continue
                await Actor.charge("audit-call")
                findings = compose_filter(compose_checks.run_all(doc), min_severity)
                summary = compose_summarize(findings)
                total_findings += summary["total_findings"]
                results.append({
                    "filename": filename,
                    "type": "docker-compose",
                    "summary": summary,
                    "findings": [f.to_dict() for f in findings],
                })

            elif is_dockerfile:
                try:
                    doc = await resolve_dockerfile_input(content, None)
                except DockerfileInputError as e:
                    errors.append(f"{filename}: dockerfile parse error — {e}")
                    continue
                await Actor.charge("audit-call")
                findings = df_filter(df_checks.run_all(doc), min_severity)
                summary = df_summarize(findings)
                total_findings += summary["total_findings"]
                results.append({
                    "filename": filename,
                    "type": "dockerfile",
                    "summary": summary,
                    "findings": [f.to_dict() for f in findings],
                })

            elif is_workflow:
                try:
                    doc = await resolve_workflow_input(content, None)
                except WorkflowInputError as e:
                    errors.append(f"{filename}: workflow parse error — {e}")
                    continue
                await Actor.charge("audit-call")
                findings = gha_filter(gha_checks.run_all(doc), min_severity)
                summary = gha_summarize(findings)
                total_findings += summary["total_findings"]
                results.append({
                    "filename": filename,
                    "type": "github-actions",
                    "summary": summary,
                    "findings": [f.to_dict() for f in findings],
                })

            else:
                errors.append(
                    f"{filename}: unrecognised file type — expected Dockerfile, "
                    "docker-compose.yml, or .github/workflows/*.yml"
                )

        files_audited = len(results)
        Actor.log.info(
            f"audit_all: {files_audited} file(s) audited, "
            f"{total_findings} total findings, {len(errors)} error(s)"
        )

        return {
            "type": "text",
            "text": (
                f"audit_all: {files_audited} file(s) audited, "
                f"{total_findings} total findings across all audits."
                + (f" {len(errors)} file(s) skipped — see errors." if errors else "")
            ),
            "structuredContent": {
                "files_audited": files_audited,
                "total_findings": total_findings,
                "results": results,
                "errors": errors,
            },
        }

    # ===================================================================
    # 6. DISCOVERY: list_all_checks
    # ===================================================================

    @server.tool(annotations=_ANNOTATIONS_LOCAL)
    async def list_all_checks() -> dict[str, Any]:
        """List every check across all three audit packages (compose, dockerfile, GHA).

        Returns the full check catalog with source package, id, category,
        severity, and title. 56 checks total across 19 categories.
        """
        await Actor.charge("list-checks")
        compose_catalog = [{"source": "compose_audit", **c} for c in compose_checks.catalog()]
        df_catalog = [{"source": "dockerfile_audit", **c} for c in df_checks.catalog()]
        gha_catalog = [{"source": "gha_audit", **c} for c in gha_checks.catalog()]
        all_checks = compose_catalog + df_catalog + gha_catalog

        return {
            "type": "text",
            "text": (
                f"{len(all_checks)} checks total — "
                f"{len(compose_catalog)} compose, "
                f"{len(df_catalog)} dockerfile, "
                f"{len(gha_catalog)} github-actions."
            ),
            "structuredContent": {
                "total": len(all_checks),
                "by_source": {
                    "compose_audit": len(compose_catalog),
                    "dockerfile_audit": len(df_catalog),
                    "gha_audit": len(gha_catalog),
                },
                "checks": all_checks,
            },
        }

    # ===================================================================
    # Resource: about
    # ===================================================================

    @server.resource(
        uri="https://unbearabletechtips.com/iac-audit-pack",
        name="about",
    )
    def about() -> str:
        n_compose = len(compose_checks.catalog())
        n_df = len(df_checks.catalog())
        n_gha = len(gha_checks.catalog())
        return (
            "Unbearable IaC Audit Pack — MCP server by Unbearable TechTips.\n"
            "All four audit packages under one endpoint. Snyk-comparable scope.\n\n"
            f"compose_audit:    {n_compose} checks ({len(compose_checks.ALL_CATEGORIES)} categories)\n"
            f"dockerfile_audit: {n_df} checks ({len(df_checks.ALL_CATEGORIES)} categories)\n"
            f"gha_audit:        {n_gha} checks ({len(gha_checks.ALL_CATEGORIES)} categories)\n"
            "postcode:         5 tools (HU postcode lookup & validation)\n\n"
            "Pricing: $19/mo flat (monthly rental via Apify Console).\n"
            "PPE placeholders: $0.02/audit, $0.005/list, $0.001/postcode lookup.\n"
        )

    return server


# ---------------------------------------------------------------------------
# Session tracking middleware (verbatim pattern from sibling Actors)
# ---------------------------------------------------------------------------

def get_session_id(headers: Mapping[str, str]) -> str | None:
    for key in ("mcp-session-id", "mcp_session_id"):
        if value := headers.get(key):
            return value
    return None


class SessionTrackingMiddleware:
    """ASGI middleware: tracks MCP sessions, closes idle ones, serves landing page on GET /."""

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

        if scope.get("type") == "http" and scope.get("method") == "GET" and path in ("", "/"):
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
            f"Starting iac-audit-pack on port {port} (session timeout: {timeout_secs}s)"
        )
        config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")  # noqa: S104
        await uvicorn.Server(config).serve()
    except KeyboardInterrupt:
        Actor.log.info("Shutting down...")
    except Exception as e:
        Actor.log.error(f"Server failed: {e}")
        raise
