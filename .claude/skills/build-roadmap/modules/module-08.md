# Module 08 — Tool registry and AI agent (Roadmap Phase 7)

**Duration:** ~1–1½ weeks · **Checkpoint 7:** AI investigation · **Depends on:** Module 07
**Goal:** the in-app analyst discovers the right tool, calls it, and answers with evidence.

## Required MCPs
| MCP | Why | Required? |
|---|---|---|
| **threatlens-vulnerability / threatlens-asset** (built in Module 07) | The agent's tools | Required |
| Context7 (docs MCP) | Model provider SDK + MCP client docs | Recommended |
| PostgreSQL MCP | Inspect audit and usage logs | Optional |

## Accounts / manual actions
- **A5 (you):** Create the model provider API key (recommended: Anthropic Console) with a **monthly spend limit**. Store in `.env` as `MODEL_API_KEY`; never sent to the browser or the model.

## Tasks
- [ ] 7.1 **(Claude)** ADR 0007 — model adapter interface + deterministic **mock provider** (tests/CI).
- [ ] 7.2 **(you)** Create the model provider key with a spend limit.
- [ ] 7.3 **(Claude)** Tool registry metadata per spec §7 (domain, entities, risk_level, permissions, tags).
- [ ] 7.4 **(Claude)** MVP discovery: filter by permission/risk → keyword/entity match → top-k schemas to the model (semantic search is post-MVP).
- [ ] 7.5 **(Claude)** Agent loop: bounded steps (≤ ~6 tool calls), validated args, server-side authorization, retrieved content treated as untrusted (prompt-injection guard).
- [ ] 7.6 **(Claude)** Response format: answer; confirmed vs possible vs unknown separated; cited evidence with source + timestamps; staleness warning; full tool trace.
- [ ] 7.7 **(Claude)** Spring Boot `POST /api/analyst/ask` proxy (auth + audit).
- [ ] 7.8 **(Claude)** Evaluation starter: 15–20 questions in `tests/evaluation/` scoring tool choice, args, groundedness, refusals of unsupported claims. Mock provider in CI; real provider manually.
- [ ] 7.9 **(Claude)** Per-request usage/cost logging.

## Best practices for this module
- Answers built only from tool results; never invent assets/CVEs.
- Don't call every tool; select by question and evidence.
- Cap steps and tokens; log cost.

## Done when
The demo question yields a correct, evidence-backed answer via the real provider, and the evaluation set passes its thresholds.
