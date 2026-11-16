# ThreatLens AI

ThreatLens AI is a defensive security-intelligence platform. It ingests public vulnerability data (NVD, CISA KEV), links it to an organization's asset inventory in a graph (Memgraph), and lets an AI analyst investigate through MCP tools, for example "which of my assets are affected by this CVE?".

Full design: [docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md). Build plan: [docs/ROADMAP.md](docs/ROADMAP.md).

## Safety boundary

- Defensive and read-only. No exploitation, scanning of third-party systems, or remediation actions.
- Demo data is synthetic. No real organization data is used.
- Matches between vulnerabilities, products and assets are never guessed; unclear matches stay `unknown`.
- Tenant identity comes from trusted server context, never from model or tool input.
- External threat-feed content is treated as untrusted data.
- Secrets live in `.env` (git-ignored); only placeholders are committed.

## Quick start

_Coming soon. Filled in as each module lands._
