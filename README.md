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

Prerequisite: Docker Desktop (WSL 2 backend, at least 8 GB RAM). On Windows, run the commands below from Git Bash or WSL.

```bash
cp .env.example .env              # first time only; edit passwords if you like
docker compose up -d --wait       # start Memgraph and PostgreSQL (localhost only)
bash scripts/verify-infra.sh      # RETURN 1 on Memgraph, SELECT 1 on PostgreSQL
```

Optional Memgraph Lab UI at http://127.0.0.1:3000:

```bash
docker compose --profile lab up -d
```

Stop (data kept):

```bash
docker compose down
```

Reset (deletes all local database data):

```bash
docker compose down -v
```

Services listen on `127.0.0.1` only: Memgraph `7687`, PostgreSQL `5432`, Lab `3000`.
