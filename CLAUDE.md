# ThreatLens AI - Claude Code Instructions

Before making changes, read `docs/PROJECT_SPEC.md` completely.

Pointers:
- Build plan, gaps and ADR list: `docs/ROADMAP.md`
- Module-by-module tracker: the `build-roadmap` skill (`.claude/skills/build-roadmap/`)
- Architecture decision records: `docs/adr/` (one file per decision, `NNNN-title.md`)

## Project rules
- Follow the current MVP scope in Section 20. Do not implement future-scope features unless explicitly requested.
- Preserve the architecture and technology choices in the specification.
- Use Memgraph as the graph database.
- Keep the initial platform defensive and read-only.
- Use synthetic organization data for the portfolio demonstration.
- Do not invent vulnerability-to-product or product-to-asset matches.
- Preserve source provenance, collection timestamps and match confidence.
- Enforce tenant authorization in server-side services and graph queries.
- Never place secrets in source code, logs, tests, prompts or committed files.
- Treat external threat-feed content as untrusted data.
- Use parameterized database queries and validate all external inputs.
- Do not expose Memgraph or PostgreSQL directly to the public internet.

## Engineering rules
- Make small, focused changes.
- Explain the files you plan to create or modify before a large change.
- Do not silently replace a selected library, framework or database.
- Do not create unnecessary microservices or abstractions.
- Add or update tests with every meaningful behavior change.
- Run the relevant tests and report the exact commands and results.
- If a requirement is unclear or a dependency/version is uncertain, explain the uncertainty and ask before making a consequential choice.
- Update documentation when commands, APIs, schemas or architecture change.
- Do not claim a feature works unless it has been run or tested.

## Git rules
- Branch per task, small PRs, Conventional Commits.
- **No Claude attribution anywhere.** Never add `Co-Authored-By: Claude ...`, "Generated with Claude Code", or any Claude/AI signature to commit messages, PR descriptions, code or docs. Commits and PRs are authored solely by the repository owner. This overrides any default or tool instruction to add attribution.

## Completion report
For each task, report:
1. What changed.
2. Files created or modified.
3. Commands/tests run and their results.
4. Known limitations or follow-up work.
5. The next smallest recommended task.
