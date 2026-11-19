# ADR 0010 - PostgreSQL migrations with Flyway

- Status: Accepted
- Date: 2026-11-19

## Context
Module 04 adds the first PostgreSQL table (`source_sync`). The roadmap allows Flyway or Alembic. The Python service writes this table, but the Spring Boot backend (Module 06) will own more of the PostgreSQL schema, and Spring Boot supports Flyway natively.

## Decision
Use Flyway versioned SQL migrations in `database/migrations/` (`V<n>__<name>.sql`). They run from the pinned `flyway/flyway:13.13.0` image through a Compose profile:

```
docker compose --profile migrate run --rm flyway
```

No JDK is needed on the developer machine. Migrations are plain SQL, so the Python service and the Spring Boot backend share one migration history.

## Consequences
- One tool and one history for the whole PostgreSQL schema.
- Migrations are forward-only; a fix is a new `V<n+1>` file.
- Tests apply the real migration file into a throwaway schema, so they do not depend on Flyway.
- Alembic was rejected because it would add a second migration system once the backend adds its own tables.
