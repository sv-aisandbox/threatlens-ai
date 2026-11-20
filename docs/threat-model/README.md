# Threat model (MVP)

STRIDE-style review of ThreatLens AI as built for the portfolio MVP. It lists what we protect, where trust changes, what can go wrong at each boundary, and what the code does about it. Every control below points to a test or a file. Items marked **Gap** are known and not yet fixed.

## Scope and assumptions
- Local and single-host deployment (Docker Compose plus three processes), demo data only, no internet exposure. Production hosting is out of scope (post-MVP, ADR 0009).
- The product is defensive and read-only: no tool can write to the graph, scan a third party or change a system.
- Keycloak is the identity provider. Its realm export is demo-only (dummy users, password `demo-password`); it must never be used as-is outside a laptop.

## Assets worth protecting
| Asset | Why it matters |
|---|---|
| Tenant asset inventory (assets, software, versions, criticality) | A map of an organization's weaknesses |
| Tenant isolation | One customer reading another's inventory is the worst failure |
| Access and refresh tokens | Let someone act as a user |
| Internal service secret (`INTERNAL_JWT_SECRET`) | Lets a caller mint any identity toward the Python service |
| Model API key | Costs money; leaks if logged or sent to the browser |
| Audit trail | Evidence of who did what |
| Integrity of match results | A wrong "confirmed" or a hidden "unknown" misleads security decisions |

## Architecture and trust boundaries
```
 Browser ──(1)── Next.js server ──(2)── Spring Boot ──(3)── Python service ──(4)── Memgraph, PostgreSQL
                      │                      │                    │
                      └──(5) Keycloak ───────┘                    ├──(6) NVD, CISA KEV (public feeds)
                                                                  └──(7) Model provider (optional)
```
| Boundary | Trust change |
|---|---|
| 1 Browser to Next.js | Untrusted client; session cookie only |
| 2 Next.js to Spring | User access token forwarded; Spring re-validates everything |
| 3 Spring to Python | Service JWT (HS256, 60 s, ADR 0004); Python trusts only that token |
| 4 Python to databases | Parameterized queries; databases bound to 127.0.0.1 |
| 5 Keycloak | Issues tokens; Spring checks issuer, audience and signature |
| 6 Public feeds | Untrusted content (descriptions, URLs, names) |
| 7 Model provider | Untrusted output; sees only tool results already scrubbed |

## STRIDE

### Spoofing
| Threat | Control | Evidence |
|---|---|---|
| Forged or unsigned user token (alg none, wrong key, wrong audience, expired) | Spring resource server validates signature, issuer, audience, expiry | `SecurityBoundaryTest` |
| Forged service token to the Python service | HS256 only, issuer, audience, 120 s maximum life, tenant and role claim checks, secret at least 32 bytes | `tests/security/test_jwt_tampering.py` |
| Caller claims another tenant (header, query, body, tool argument, question text) | Tenant is read only from the token; extra fields are rejected, not ignored | `tests/security/test_tenant_isolation.py`, `AnalystApiTest`, `UiApiTest` |
| Stolen access token from the browser | Tokens never reach browser JavaScript (ADR 0012); 5-minute lifetime | `e2e/demo.spec.ts`, `frontend/src/lib/server.ts` |

### Tampering
| Threat | Control | Evidence |
|---|---|---|
| Edited token payload (role or tenant escalation) | Signature check; edited payloads fail | `test_editing_the_payload_of_a_real_token_breaks_the_signature` |
| Cypher or SQL injection through CVE ids, asset ids, search text | Strict patterns and length limits, parameterized queries only | `tests/security/test_malformed_input.py` |
| Hostile inventory file (formula text, huge file, bad encoding, other tenant in the file) | 5 MB cap, UTF-8 required, tenant taken from the token, allowlisted columns, per-row validation with a reject report | `InventoryApiTest`, `test_inventory_import.py` |
| A model or tool call modifies data | Tools are read-only; there is no write tool; extra arguments rejected | `test_mcp_tools.py` |
| Fake match status | Statuses computed by the matcher; missing version gives `unknown`, never `confirmed` (ADR 0003) | `test_matcher.py` |

### Repudiation
| Threat | Control | Evidence |
|---|---|---|
| A user denies an action | `audit_log` records actor, tenant, action, outcome, status and correlation id (no file names or content) | `ApiBehaviourTest`, `InventoryApiTest` |
| A tool call cannot be explained later | `tool_call_audit` stores tool, argument hash (not the arguments), tenant, latency, outcome | `test_mcp_tools.py` |
| An answer cannot be traced | Every analyst answer returns the full tool trace and a correlation id; usage is logged | `AnalystApiTest` |

### Information disclosure
| Threat | Control | Evidence |
|---|---|---|
| Cross-tenant read through REST, MCP or the agent | Tenant-scoped queries start from `Asset{tenant_id}`; a foreign asset looks exactly like a missing one | `tests/security/test_tenant_isolation.py` (131 security tests) |
| Secrets in logs | JSON logs pass through a redactor (bearer tokens, JWT shapes, key labels, configured secret values); Spring logs method, path and status only | `test_observability.py`, `ObservabilityTest` |
| Internals in errors (stack traces, driver names, SQL) | Fixed problem responses; upstream text never echoed | `tests/security/test_malformed_input.py`, `SecurityBoundaryTest` |
| Model key reaches browser or prompt | Key exists only in the Python process environment | ADR 0007; `frontend` has no `NEXT_PUBLIC_*` settings |
| Metrics or actuator leak | Only `health` is public; `metrics` is ADMIN only; other actuator paths are denied | `ObservabilityTest` |
| Databases reachable from the network | Compose binds Memgraph and PostgreSQL to 127.0.0.1 | `docker-compose.yml` |

### Denial of service
| Threat | Control | Evidence |
|---|---|---|
| Request floods | Per-user rate limits (general, sync, analyst), 429 with Retry-After | `RateLimitTest` |
| Runaway agent | 6 tool calls per question, 4 concurrent questions, model timeouts and a cost record | `test_agent_guard.py` |
| Huge uploads or results | 5 MB upload limit, result limits and truncation flags | `InventoryApiTest`, `test_asset_queries.py` |
| Feed outage or poisoning | Sync failures are recorded with sanitized text; the UI shows stale or never-synced sources | `test_sync_nvd.py`, overview tests |
| **Gap** | Rate limits are in memory per Spring instance; a multi-instance deployment needs a shared store |  |

### Elevation of privilege
| Threat | Control | Evidence |
|---|---|---|
| Viewer starts a sync or uploads | Roles checked in Spring (`@PreAuthorize`) and again in Python; UI hides the buttons but the server decides | `SecurityBoundaryTest`, `e2e/demo.spec.ts` |
| Prompt injection from feed text or a question makes the agent widen its search | Tool output is scrubbed; discovery uses trusted text only; tenant and tool list are not model-controlled; findings and evidence are built by code, not by the model | `test_agent_guard.py`, `test_agent.py` |
| Open path through the UI proxy | Method and path allowlist, traversal and encoding rejected, tenant parameters dropped | `frontend/src/lib/lib.test.ts`, `e2e/demo.spec.ts` |
| Malicious link in feed data | Only `http(s)` links are rendered, with `rel="noopener noreferrer"` | `lib.test.ts` |

## Specific risks of an AI analyst
| Risk | Position |
|---|---|
| The model invents an asset, CVE or match | A grounding check compares identifiers in the narrative with tool results and warns when they do not match. The findings list is built from tool results, not model text. |
| Over-confident wording | Confirmed, possible and unknown are separate groups. Empty results say "not proof of safety". Freshness warnings are always attached. |
| Cost abuse | Tool-call cap, per-user analyst rate limit, usage and cost logged per request. A provider-side spend limit is the user's to set (task 7.2). |

## Known gaps and accepted risks
1. Rate limiting is per instance (see above).
2. The demo realm uses a published password and runs Keycloak in dev mode; replace both before any shared deployment.
3. No malware or content scanning of uploaded files beyond format, size and column validation (CSV or JSON only, never executed).
4. The real-model path has not been exercised end to end (no key yet); the mock model is deterministic and offline.
5. No automated dependency-update merge policy beyond Dependabot pull requests and CodeQL alerts.
6. Secrets scanning in CI blocks known patterns; it cannot prove a repository was never exposed.

## Out of scope for the MVP
URL import and SSRF protection, third-party API connectors, response actions, multi-region deployment, and customer-managed encryption keys. Each needs its own threat review before being built.
