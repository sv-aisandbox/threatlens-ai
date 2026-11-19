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

Load the synthetic demo graph and run the tests (needs [uv](https://docs.astral.sh/uv/)):

```bash
cd intelligence-service
uv sync
uv run python -m ingestion.seed_loader   # idempotent; add --reset to start clean
uv run pytest                            # tests run against the local Memgraph
```

Real vulnerability data (NVD and CISA KEV). Create the `source_sync` table once, then sync on demand:

```bash
docker compose --profile migrate run --rm flyway        # apply database/migrations
cd intelligence-service
uv run python -m ingestion.cli sync kev                 # CISA KEV flags (no account needed)
uv run python -m ingestion.cli sync nvd --since 2026-11-18   # NVD changes since a date (UTC)
uv run python -m ingestion.cli import-cve CVE-2021-44228     # one CVE, for demos
uv run python -m ingestion.cli status                   # last sync times and counters
```

Set `NVD_API_KEY` in `.env` for the higher NVD rate limit (free key: https://nvd.nist.gov/developers/request-an-api-key). Without a key the client slows itself to 5 requests per 30 seconds. The first NVD sync without `--since` covers the last 7 days.

Import an asset inventory (CSV or JSON, tenant given by you, not read from the file) and match it to CVEs:

```bash
uv run python -m ingestion.cli import-inventory --tenant TENANT-DEMO --file my-inventory.csv
uv run python -m ingestion.cli match    # re-match all software after a new NVD sync
```

Match statuses are `confirmed`, `possible`, `not_affected` and `unknown` (see ADR 0003). Only `confirmed` counts as exposure; a missing or non-numeric version is reported as `unknown`, never guessed.

Tests use a disposable Memgraph on port 7688 (recorded fixtures, no live network):

```bash
docker compose --profile test up -d --wait memgraph-test
cd intelligence-service && uv run pytest
```

Internal sync API (localhost only, needs `INTERNAL_API_TOKEN` in `.env`, sent as the `X-Internal-Token` header):

```bash
uv run uvicorn app.api:create_app --factory --host 127.0.0.1 --port 8000
```

Services listen on `127.0.0.1` only: Memgraph `7687`, PostgreSQL `5432`, Lab `3000`.
