# Unbearable IaC Audit Pack

**Unbearable IaC Audit Pack** — all four audit Actors under one MCP endpoint. Snyk-comparable scope at 10x cheaper. $19/mo unlimited individual audits.

56 checks. 19 categories. 4 audit engines. 1 MCP endpoint. One subscription.

---

## What's included

| Package | Checks | Categories | Primary tool |
|---------|--------|------------|--------------|
| Docker Compose audit | 25 | 9 | `audit_compose` |
| Dockerfile audit | 18 | 5 | `audit_dockerfile` |
| GitHub Actions audit | 13 | 5 | `audit_github_actions` |
| HU Postcode Validator | 5 tools | — | `validate_postcode`, `lookup_city`, … |

Plus two bundle-only tools:
- **`audit_all`** — paste a dict of filenames → content; auto-detects Dockerfile, compose, and workflow files and runs the right audit on each
- **`list_all_checks`** — full cross-package check catalog in one call

## Quick start (Claude Desktop)

```json
{
  "mcpServers": {
    "iac-audit-pack": {
      "type": "http",
      "url": "https://unbearable-dev--iac-audit-pack.apify.actor/mcp",
      "headers": {
        "Authorization": "Bearer <your-apify-token>"
      }
    }
  }
}
```

## Tool catalog

### Aggregation (bundle-only)

| Tool | Description |
|------|-------------|
| `audit_all(files, min_severity?)` | Multi-file detection + combined audit report |
| `list_all_checks()` | All 56 checks across all three audit packages |

### Docker Compose (25 checks, 9 categories)

| Tool | Description |
|------|-------------|
| `audit_compose(compose_yaml?, compose_url?, min_severity?)` | Full 25-check audit |
| `check_privilege` | Privileged mode, cap_add, user namespace |
| `check_network` | Host networking, exposed dangerous ports |
| `check_secrets` | Hardcoded passwords, tokens in env vars |
| `check_filesystem` | Docker socket mounts, host path mounts |
| `check_resources` | Missing memory/CPU limits |
| `check_image_hygiene` | Unpinned tags, `latest` usage |
| `check_runtime_lifecycle` | Restart policies, healthchecks |
| `check_logging` | Logging driver config |
| `check_compose_hygiene` | Version field, service naming |
| `list_checks_compose(category?)` | Check catalog |

### Dockerfile (18 checks, 5 categories)

| Tool | Description |
|------|-------------|
| `audit_dockerfile(dockerfile_content?, dockerfile_url?, min_severity?)` | Full 18-check audit |
| `check_base_image_dockerfile` | Unpinned base, `latest`, root user in FROM |
| `check_instructions_dockerfile` | ADD vs COPY, COPY ordering, ENV secrets |
| `check_security_dockerfile` | USER root, privilege escalation patterns |
| `check_efficiency_dockerfile` | Layer count, cache busting |
| `check_secrets_dockerfile` | Hardcoded secrets in RUN/ENV/ARG |
| `list_checks_dockerfile(category?)` | Check catalog |

### GitHub Actions (13 checks, 5 categories)

| Tool | Description |
|------|-------------|
| `audit_github_actions(workflow_yaml?, workflow_url?, min_severity?)` | Full 13-check audit |
| `check_secrets_gha` | Leaked tokens, secret in run: blocks |
| `check_permissions_gha` | Overly broad write-all permissions |
| `check_action_pinning_gha` | Unpinned action refs (not SHA-pinned) |
| `check_runner_security_gha` | Self-hosted runner risks |
| `check_workflow_config_gha` | pull_request_target misuse, script injection |
| `list_checks_github_actions(category?)` | Check catalog |

### HU Postcode Validator (5 tools)

| Tool | Description |
|------|-------------|
| `validate_postcode(postcode)` | Settlement + county for a HU postcode |
| `lookup_postcode(postcode)` | Alias for validate_postcode |
| `lookup_city(city)` | All postcodes for a city (diacritic-insensitive) |
| `validate_address(postcode, city)` | Postcode/city pairing validation |
| `list_postcodes_in_county(county_name)` | All postcodes in a county |
| `budapest_district_lookup(district_number)` | Budapest I-XXIII → postcodes |

## Pricing

**$19/mo unlimited individual audits** — flat monthly rental via Apify Console.

No per-call billing. Run as many audits as you need. Cancel anytime.

## Architecture

Package-import (not proxy): all four sub-packages are bundled directly into the
Actor image. Single cold start, single billing rail, no cross-Actor latency.
See `DESIGN.md` for the full rationale.

---

Built by Noel @ Unbearable TechTips — more like this in the weekly newsletter [link].
