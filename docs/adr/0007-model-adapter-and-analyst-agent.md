# ADR 0007 - Model adapter, deterministic mock provider and the analyst agent

- Status: Accepted
- Date: 2026-11-19
- Addresses roadmap gap G5 (where the agent runs)

## Context
The in-app analyst must discover the right tool, call it, and answer with evidence, without ever being the authority on who the caller is, which tenant they belong to, or what they may see. Tests and CI must run without network access or spend, and the model provider must be replaceable.

## Decision

### Where it runs
The agent runs in the **Python intelligence service** (the MCP SDK is Python). Spring Boot authenticates the user, then calls `POST /internal/v1/analyst/ask` with the 60-second service JWT (ADR 0004). Tenant and roles come from that token only.

### Model adapter interface
`agent/models.py` defines `ModelAdapter.create(system, messages, tools) -> ModelTurn`. A `ModelTurn` carries the text, the requested tool calls, token usage, the stop reason, and `assistant_content`, the exact blocks to append to the history **unchanged** (this keeps provider-specific blocks such as thinking valid). Two implementations:

| Adapter | Use |
|---|---|
| `AnthropicAdapter` | Real provider. Official `anthropic` SDK, model `claude-opus-5-5` (configurable via `MODEL_NAME`). Thinking is always on for this model, so `thinking` is omitted; `output_config.effort` is set explicitly (default `medium`). No sampling parameters and no forced `tool_choice` (both are rejected by this model); the loop enforces what forcing would have. Server-side refusal `fallbacks: "default"` is enabled by default (`MODEL_FALLBACKS=off` disables it). `stop_reason == "refusal"` is handled and returned as a refusal, not an error. The key is read from `MODEL_API_KEY` in the service environment only. |
| `MockAdapter` | Deterministic rule-based policy for tests and CI. Needs no key and costs nothing. It exercises the whole pipeline (discovery, MCP calls, guards, assembly, usage logging, evaluation scoring) but says nothing about real model quality, which is measured manually with the real adapter. |

`MODEL_PROVIDER=mock|anthropic` selects the adapter; the service refuses to start the analyst route with `anthropic` and no key.

### Tools: the same MCP tools, in process
The agent does not talk to a separate network service. For each request it builds the two MCP servers from Module 07 **in process** with a `TrustedContext` derived from the authenticated principal (tenant and roles from the JWT, actor = token subject) and connects an MCP client to them. Every tool call therefore passes through the same strict-argument checks, role re-check, tenant-scoped queries, error shape and `tool_call_audit` rows as any external MCP client. The model can neither choose the tenant nor reach a tool the registry did not offer.

### Registry and discovery
`agent/registry.py` holds metadata for every tool (domain, input and output entities, `risk_level`, required roles, tags), checked by a test against what the servers actually expose. Discovery per request: filter by role and risk (`read_only` only), detect entities in the question (CVE ids, asset ids, environment, KEV, exposure words), keyword and entity match against tags, descriptions and entities, then offer only the top-k schemas (default 5). After each tool round, discovery may add newly relevant tools (never remove), capped at 6. Semantic search is post-MVP.

### Loop bounds
At most **6 tool calls**, 8 model turns, a token budget and a wall-clock limit per request. A tool the model asks for that was not offered is refused and recorded; the model receives an error result. When a bound is hit the agent stops and answers from what it has, flagged `limit_reached`.

### Prompt-injection guard
- The system prompt states that tool results are data. Tool results appear only inside `tool_result` blocks, never in the system prompt or user turn.
- Fields that carry external or tenant-supplied text (`untrusted_fields` from each envelope) are sanitized (control characters removed, length capped) and scanned for instruction-like patterns. A hit adds a marker to the text and a `injection_suspected` flag to the trace.
- Authority never depends on model behaviour: tenant, roles, tool availability, argument validation and step limits are enforced in code. Tests include a scripted "compromised model" that obeys an injected instruction and still gets nowhere.

### Answer construction
The structured parts of the response are **built from tool results by code**, not written by the model: findings separated into `confirmed`, `possible` and `unknown`, de-duplicated evidence (source, URL, collection time), freshness and staleness warnings, and the full tool trace. The model supplies only the narrative. A grounding check compares every CVE id, asset id, evidence id and tenant id in the narrative with the identifiers seen in tool results and the question; unsupported identifiers are replaced by a marker and reported.

### Usage and cost
Each request writes one `analyst_request_log` row (Flyway V5): tenant, actor, provider, model, SHA-256 of the question (never the text), steps, tool calls, input/output/cache tokens, computed cost, latency, outcome. Cost uses a price table in `agent/cost.py`.

### Evaluation
`tests/evaluation/questions.json` holds 20 questions with expected tools, arguments, facts and refusals; `agent/evaluation.py` scores tool choice, arguments, groundedness and refusals. CI runs it with the mock; the real adapter is run manually.

## Consequences
- CI is deterministic and free; model quality is a separate, manual measurement.
- The agent cannot gain access the user does not have, whatever the model says.
- Adding a tool requires registry metadata (a test fails otherwise).
- In-process MCP means one request builds small server objects; that cost is negligible next to a model call.
