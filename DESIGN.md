# IaC Audit Pack — Design Notes

## What this is

Single Apify MCP Actor that exposes **all tools** from four sibling Actors under
one endpoint:

| Sub-package       | Checks | Categories | Key tools                                              |
|-------------------|--------|------------|--------------------------------------------------------|
| `compose_audit`   | 25     | 9          | `audit_compose`, `check_<cat>`, `list_checks_compose`  |
| `dockerfile_audit`| 18     | 5          | `audit_dockerfile`, `check_<cat>_dockerfile`, `list_checks_dockerfile` |
| `gha_audit`       | 13     | 5          | `audit_github_actions`, `check_<cat>_gha`, `list_checks_github_actions` |
| `postcode`        | n/a    | n/a        | `validate_postcode`, `lookup_postcode`, `lookup_city`, `validate_address`, `list_postcodes_in_county`, `budapest_district_lookup` |

Plus two bundle-only tools:
- `audit_all(files: dict)` — multi-file detection, runs all applicable audits, merged report
- `list_all_checks()` — full cross-package check catalog

**Total tools: ~52** (9 compose category tools + 5 dockerfile category tools + 5 GHA category tools
+ 3 bundle-level audit tools + 6 postcode tools + 3 list/discovery tools)

## Architecture decision: Package-import (Option B)

Two options were evaluated:

**Option A — Proxy MCP**
Bundle Actor's `/mcp` forwards each tool call to the appropriate sub-Actor Standby URL.

Pros: zero code duplication, sub-Actor updates instantly reflected.
Cons:
- Each tool call incurs two cold starts (bundle + sub-Actor) unless both warm
- Cross-Actor auth: every forwarded call needs a valid Apify token
- PPE complexity: charging happens in both the bundle and the sub-Actor
- Extra latency (~200-500ms per hop)
- Network failure surface doubled

**Option B — Package-import** ← CHOSEN
Copy each sub-Actor's Python package (`compose_audit/`, `dockerfile_audit/`,
`gha_audit/`, `postcode/`) directly into this Actor's source tree. The bundle's
`main.py` imports them and re-registers every tool under one FastMCP server.

Pros:
- Single cold start
- Zero cross-Actor auth
- One PPE billing rail, simple reasoning
- Deterministic latency
- Pure-Python packages: no hosted state, no DB external to the container
  (postcode SQLite file is embedded in the image)

Cons:
- Must re-sync + re-deploy bundle when any sub-Actor's checks change
- Source duplication (~50KB of Python, negligible)

The audit packages are pure-Python local modules with no hosted state. The
duplication cost is minimal vs the operational complexity of multi-hop auth
and cold-start storms. **Option B wins.**

## Package sync

Sub-packages are rsync'd from their source Actors at build/deploy time:

```bash
# Run from /home/noelpi/apify/iac-audit-pack/
rsync -a --delete ../docker-compose-audit/compose_audit/ compose_audit/
rsync -a --delete ../dockerfile-audit/dockerfile_audit/ dockerfile_audit/
rsync -a --delete ../github-actions-audit/gha_audit/ gha_audit/
rsync -a --delete ../hu-postcode-validator/postcode/ postcode/
rsync -a ../hu-postcode-validator/data/ data/
```

The `data/` directory contains the `hu_postcodes.sqlite` file needed by postcode.
The bundle's `postcode/db.py` must be able to find it — the path resolution is
inherited from the sub-Actor and resolves relative to the package location.

## Pricing

Flat $19/mo individual subscription (monthly rental via Apify Console).

`pay_per_event.json` contains PPE placeholder prices matching the individual
Actor pattern so local `apify run` works without errors. Switch to monthly
rental in the Apify Console under Monetization settings once the Actor is public.

PPE placeholder rates (never charged in production monthly rental mode):
- `audit-call`: $0.02
- `list-checks`: $0.005
- `lookup-call`: $0.001
- `bulk-call`: $0.005

## Tool name collision avoidance

`list_checks` and per-category `check_<category>` exist in all three audit
packages. The bundle disambiguates:

- Compose category tools keep original names: `check_privilege`, `check_network`, etc.
  (9 tools with no suffix — these were in the first major Actor, keep them clean)
- Dockerfile category tools get `_dockerfile` suffix: `check_base_image_dockerfile`, etc.
- GHA category tools get `_gha` suffix: `check_secrets_gha`, etc.
- List tools get package prefixes: `list_checks_compose`, `list_checks_dockerfile`,
  `list_checks_github_actions`, `list_all_checks`
- Postcode `lookup_postcode` conflicts with nothing; `validate_postcode` is an alias.
