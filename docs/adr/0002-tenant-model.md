# ADR 0002 - Tenant model (global vs tenant data)

- Status: Accepted
- Date: 2026-11-19

## Context
The spec (section 5) stores `tenant_id` on `Asset` but is silent on which other data is tenant-scoped. Public vulnerability intelligence (CVE, CISA KEV, public advisories) is the same for every customer, while asset inventories are private. Mixing the two without a rule risks cross-tenant leaks.

## Decision
| Data | Scope | Notes |
|---|---|---|
| `Tenant` | tenant | `tenant_id` is unique |
| `Asset` | tenant | carries `tenant_id`; `(Tenant)-[:OWNS]->(Asset)` mirrors it |
| `RUNS` (Asset to Software) | tenant | the installation; carries `tenant_id` |
| `Software` | global catalogue | vendor, product, version, CPE 2.3; identical software is shared across tenants and holds no tenant data |
| `Vulnerability`, `Evidence` (public) | global | CVE, KEV, advisories |
| `AFFECTED_BY` (Software to Vulnerability) | global | records `match_status`, `match_reason`, `matched_by`, `matched_at`, `source_ref` |

Rules:
1. Every tenant-facing query starts from `(a:Asset {tenant_id: $tenant_id})` and also filters `RUNS.tenant_id = $tenant_id`.
2. `tenant_id` is a query parameter supplied by trusted server context, never taken from model or tool input.
3. Global nodes are never traversed backwards into other tenants' assets in a tenant-facing query; any path from global data to assets must go through the tenant-filtered `Asset`.
4. Tenant-private evidence (for example scanner results) will carry `tenant_id` and be filtered the same way; none exists in the MVP seed.
5. Match states are `confirmed`, `possible`, `not_affected`, `unknown` (spec 20.4). Unknown product or version identity yields `unknown`, never a guess.
6. All synthetic seed nodes carry `synthetic: true` so seed data can be reset without touching real data.

## Consequences
- Isolation is enforced in the graph query, and tests prove a second tenant sees none of the first tenant's data.
- Because `Software` is shared, `AFFECTED_BY` describes a product-version fact, not a tenant fact. Tenant-specific verdicts (scanner results) will need tenant-scoped relationships in a later module.
