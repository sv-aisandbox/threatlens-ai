# The AI analyst

Design record: [ADR 0007](../adr/0007-model-adapter-and-analyst-agent.md). Tool reference: [docs/mcp/tools.md](../mcp/tools.md).

## What it does

A user asks a question in plain language ("Which of my production assets are affected by CVE-2021-44228, and how sure are we?"). The analyst picks the tools it needs, calls them, and answers from what they return, with the evidence, the data freshness and a complete trace of every tool call.

```text
Browser / client
   |  POST /api/analyst/ask   (Keycloak token, SECURITY_ANALYST or ADMIN)
   v
Spring Boot ---- validates the token, role, input; audits; rate limits (10 questions/min/user)
   |  POST /internal/v1/analyst/ask   (60 s service JWT carrying tenant + roles)
   v
Python intelligence service: AnalystAgent
   1. discover   registry -> filter by role and risk -> detect entities -> keyword/entity match -> top-k tool schemas
   2. ask model  ModelAdapter (Anthropic, or the deterministic mock)
   3. act        each requested tool: must be one that was offered -> MCP tool layer (strict args, tenant-scoped, audited)
   4. scrub      tool output = untrusted data: sanitized, scanned for instruction-like text, size-capped
   5. repeat     at most 6 tool calls and 8 model turns
   6. assemble   findings, evidence, freshness, warnings and trace are built from tool results by code
   7. verify     every CVE / asset / evidence / tenant id in the narrative must exist in a tool result
   8. log        one analyst_request_log row (tokens, cost, latency, outcome; question stored only as a hash)
```

## What the model can and cannot do

| The model can | The model cannot |
|---|---|
| Choose among the few tools discovery offered | Call a tool that was not offered (refused, recorded in the trace) |
| Choose tool arguments | Send arguments the MCP schema rejects, or any `tenant_id` (rejected) |
| Write the narrative | Change who the user is, their tenant, their role or the tools' permissions |
| Ask for more tool calls | Exceed 6 calls, 8 turns, the token budget or the time limit |
| | Invent identifiers: unsupported ones are replaced with `[unverified identifier]` and reported |
| | Decide what counts as evidence, findings or freshness: code builds those parts from tool results |

Tenant and roles come only from the verified service token. The same MCP servers external clients use run in process for the request, so the analyst gets exactly the controls, audit rows and error shapes any MCP client gets.

## Prompt-injection handling

Descriptions, asset names and match reasons come from public feeds or uploaded inventories and can contain text aimed at a model. They are treated as data:

- they appear only inside `tool_result` blocks, never in the system prompt or the user turn;
- invisible and control characters are removed, length is capped, and instruction-like text is flagged in the result and in the trace (`injection_suspected`);
- hostile text cannot influence which tools are offered next, or which identifiers count as grounded: only trusted structured fields are used for both;
- none of these controls relies on the model behaving. The tests run a scripted model that obeys injected instructions and show it still gets nowhere.

## The answer

`POST /api/analyst/ask` returns:

| Field | Content |
|---|---|
| `answer` | Narrative (after the grounding check) |
| `summary`, `findings` | `confirmed` / `possible` / `unknown` kept apart; only `confirmed` counts as exposure |
| `evidence` | De-duplicated evidence with source, URL and collection time |
| `freshness`, `warnings` | Intelligence and inventory freshness, staleness and limit warnings |
| `grounding` | `ok` and the identifiers that were removed |
| `trace` | Every tool call: step, tool, arguments, outcome (`ok`, `error:<code>`, `refused:not_offered`, `refused:limit`), latency, injection flag |
| `usage` | Provider, model, steps, tool calls, tokens, estimated cost, latency |
| `outcome` | `answered`, `refused`, or `limit_reached` |

## Configuration

| Variable | Meaning |
|---|---|
| `MODEL_PROVIDER` | `mock` (default; deterministic, no key, no cost) or `anthropic` |
| `MODEL_API_KEY` | Provider key. Read only by the Python service; never sent to the browser, the model or logs |
| `MODEL_NAME` | Default `claude-opus-5-5` |
| `MODEL_EFFORT` | `low` / `medium` (default) / `high` / `xhigh` / `max` |
| `MODEL_FALLBACKS` | `on` (default) enables server-side refusal fallbacks; `off` disables |

Set a monthly spend limit on the key in the provider console. Cost per request is estimated in `agent/cost.py` and stored in `analyst_request_log`.

## Evaluation

[`tests/evaluation/`](../../tests/evaluation/README.md) holds 20 questions scoring tool choice, arguments, groundedness and refusals. CI runs it with the mock. A real-provider run is manual.

## Known limitations

- The mock proves the pipeline, not model quality. The real-provider evaluation and demo run need a key and are run manually.
- The fictional `CVE-DEMO-*` ids do not match the CVE format that the tools accept, so only asset-side questions can reach their findings.
- Discovery is keyword and entity based; semantic search is post-MVP.
- The analyst answers one question at a time; there is no conversation memory yet.
- Attack-path analysis is not implemented, and the analyst says so.
