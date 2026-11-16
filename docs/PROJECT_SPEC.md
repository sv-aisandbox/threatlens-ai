# ThreatLens AI

## Cybersecurity Threat Intelligence & Attack Path Analysis Platform

**Project specification for VS Code development**\
**Graph database:** Memgraph\
**Stack:** Next.js, Java Spring Boot, Python FastAPI, MCP, agentic AI,
Memgraph, PostgreSQL

## 1. Project vision

ThreatLens AI is a defensive cybersecurity intelligence platform. It
ingests public threat intelligence and explicitly authorized
organization data, turns that information into a connected graph, and
helps analysts investigate vulnerabilities, indicators, incidents,
assets and possible attack paths.

It has three interfaces: 1. A web application for dashboards and graph
exploration. 2. An AI Security Analyst that answers questions by
discovering and calling tools. 3. MCP servers that expose the platform's
domain capabilities to compatible AI clients.

The project is not just a chatbot. Answers should be grounded in graph
relationships, source evidence, timestamps and confidence.

Example questions: - Which production assets are affected by a CVE? - Is
a vulnerability listed in CISA KEV? - Which critical assets are
connected to a suspicious endpoint? - What possible paths connect a
compromised endpoint to a critical server? - What evidence connects an
indicator to an incident? - Why was an asset assigned a high risk score?

**Safety boundary:** The initial platform is defensive and read-only. It
analyzes public threat intelligence and synthetic or explicitly
authorized asset data. It does not exploit vulnerabilities, attack
external systems, or automatically modify security controls.

## 2. What can a user give to ThreatLens?

ThreatLens should support more than question-and-answer chat. Treat
these as separate product workflows.

### A. Natural-language question

A user asks a question in the AI Analyst:

> Which critical production servers are affected by CVEs in the CISA KEV
> catalog?

The agent interprets the question, discovers relevant tools, invokes
them, checks the results and returns an evidence-backed answer.

A question does not add new facts. It queries information already
ingested or available through configured connectors.

### B. Website URL

A user can submit a URL from a supported public source, such as an NVD
CVE page, CISA catalog, MITRE ATT&CK technique page or vendor security
advisory.

Recommended workflow: 1. Validate URL scheme and hostname. 2. Allow only
approved domains or configured source connectors. 3. Block localhost,
private IP ranges, link-local addresses, cloud metadata endpoints and
unsafe redirects. 4. Fetch a supported page or machine-readable feed. 5.
Parse it with a source-specific parser. 6. Store source URL, retrieval
time and content hash. 7. Normalize and validate extracted facts. 8.
Show an import preview and report. 9. Save approved entities and
relationships to Memgraph.

Do not blindly scrape every website. Prefer official APIs and
machine-readable feeds. A URL is only a pointer to information; it is
not automatically trustworthy or structured.

### C. API integration

An administrator configures a connector with: - Provider name and
approved endpoint. - Authentication method. - API key/token stored as a
secret. - Refresh schedule or manual refresh. - Pagination/rate-limit
handling. - Data mapping and normalization rules.

Possible sources include NVD, CISA KEV, MITRE ATT&CK and an
organization's authorized asset inventory or vulnerability-management
export.

**Never ask users to paste API secrets into ordinary chat.** Use a
protected integrations page and a secret manager or protected
environment configuration. The AI model must not receive raw
credentials.

The connector calls the API, validates its response, normalizes records
and passes them to the ingestion pipeline.

### D. File upload

Support JSON, JSONL, CSV, STIX 2.1 JSON bundles and approved
asset/vulnerability exports. Validate file type, size and schema, report
rejected rows, and import only accepted records.

### E. Authorized internal integration

Later, connect to organization-owned SIEM, EDR, vulnerability
management, cloud inventory or ticketing systems using documented APIs
and explicitly authorized credentials. Apply least privilege, tenant
isolation and audit logging. A user-provided URL does not prove
permission to access a system.

### Input behavior summary

  -----------------------------------------------------------------------
  Input                   What ThreatLens does    Adds graph data?
  ----------------------- ----------------------- -----------------------
  Natural-language        Queries existing        Normally no
  question                information through     
                          tools                   

  Supported public URL    Fetches, parses and     Yes, after
                          validates source        validation/approval

  Configured API          Retrieves records on    Yes
  connector               demand or schedule      

  JSON/CSV/STIX upload    Validates and imports   Yes
                          records                 

  Authorized internal     Retrieves permitted     Yes
  connector               organization data       
  -----------------------------------------------------------------------

Create distinct UI workflows: **Ask a Question**, **Import URL/File**,
and **Manage Integrations**. Do not make one unrestricted chat box
responsible for all input types.

## 3. Product modules

1.  Security Overview: alerts, exposure, vulnerability counts and
    ingestion status.
2.  Asset Intelligence: servers, endpoints, applications, software and
    networks.
3.  Vulnerability Management: CVEs, severity, affected products and
    assets.
4.  Threat Intelligence: indicators, threat actors, malware and
    techniques.
5.  Threat Graph Explorer: interactive entity and relationship
    exploration.
6.  Attack Path Analysis: bounded possible paths through modeled assets.
7.  Incident Investigation: events, indicators, assets, evidence and
    timelines.
8.  AI Security Analyst: natural-language investigations with dynamic
    MCP tool discovery.
9.  Data Sources & Integrations: URL/file imports, API connectors and
    schedules.
10. Audit & Administration: users, roles, tenants and tool execution
    history.

## 4. Technology architecture

  -----------------------------------------------------------------------
  Layer                   Technology              Responsibility
  ----------------------- ----------------------- -----------------------
  Frontend                Next.js, React,         User interface
                          TypeScript              

  Styling                 Tailwind CSS            Layout and styling

  Graph visualization     Cytoscape.js            Interactive graph
                                                  display

  Main backend            Java 21, Spring Boot 3  REST APIs, users,
                                                  authorization,
                                                  incidents, audit

  Intelligence service    Python, FastAPI         Ingestion,
                                                  normalization,
                                                  enrichment, correlation

  MCP                     Official Python MCP SDK Domain tools for AI
                                                  clients

  Agent integration       Provider-independent    Planning and tool use
                          adapter; start with one 
                          model provider          

  Graph database          Memgraph                Nodes, relationships
                                                  and graph traversal

  Relational database     PostgreSQL              Users, tenants, jobs,
                                                  audit and app metadata

  Cache/jobs              Redis, when needed      Caching and background
                                                  jobs

  Containers              Docker, Docker Compose  Reproducible local
                                                  environment

  Tests                   JUnit 5, pytest,        Unit, integration and
                          Playwright,             UI tests
                          Testcontainers          

  CI/CD                   GitHub Actions          Build, test and
                                                  deployment
  -----------------------------------------------------------------------

### Logical architecture

``` text
                 Analyst / Security User
                          |
          +---------------+----------------+
          |                                |
     Next.js Web App                 MCP-compatible Host
          |                         (e.g. Claude Code)
          v                                v
   Spring Boot API                MCP Client / Agent
          |                                |
          |                         Tool Discovery
          |                                |
          +----------------+---------------+
                           |
                Python Intelligence Layer
                           |
        +------------------+-------------------+
        |                  |                   |
   Ingestion          Correlation         Graph Queries
        |                  |                   |
        +------------------+-------------------+
                           |
              +------------+------------+
              |                         |
           Memgraph                 PostgreSQL
       Threat relationships       Users, jobs, audit
```

Use a modular monolith initially. Keep domain boundaries clean, but do
not create a large microservice deployment before there is a real need.

### Responsibilities

**Next.js:** dashboards, graph display, chat and import UI.\
**Spring Boot:** authenticated application APIs, business workflows,
tenant/role authorization and audit.\
**Python:** source connectors, parsers, normalization, enrichment, graph
queries and risk calculations.\
**MCP servers:** expose domain tools and call reusable service
functions.\
**Memgraph:** connected security knowledge graph.\
**PostgreSQL:** users, tenants, connector metadata, jobs, audit and
workflow state.\
**Secret manager/environment:** API keys and credentials; never store
them as ordinary plaintext application data.

## 5. Memgraph graph model

Memgraph supports Cypher-style querying and the MAGE graph algorithms
library. Confirm exact syntax, indexes, constraints and procedures
against the Memgraph version selected.

### Node labels

  -----------------------------------------------------------------------
  Label                               Example properties
  ----------------------------------- -----------------------------------
  Asset                               asset_id, name, asset_type,
                                      environment, criticality,
                                      internet_exposed, tenant_id

  Software                            software_id, vendor, product,
                                      version

  Vulnerability                       cve_id, description, cvss_score,
                                      severity, published_at

  ThreatActor                         actor_id, name, aliases

  Indicator                           indicator_id, value,
                                      indicator_type, confidence,
                                      first_seen, last_seen

  Malware                             malware_id, name, family

  AttackTechnique                     technique_id, name, tactic

  SecurityEvent                       event_id, event_type, occurred_at,
                                      severity

  Incident                            incident_id, title, status,
                                      severity, created_at

  Network                             network_id, name, zone

  Evidence                            evidence_id, source_name,
                                      source_url, collected_at,
                                      content_hash

  Tenant                              tenant_id, name
  -----------------------------------------------------------------------

### Relationship types

``` text
(Asset)-[:RUNS]->(Software)
(Software)-[:AFFECTED_BY]->(Vulnerability)
(Asset)-[:CONNECTED_TO]->(Asset)
(Asset)-[:PART_OF]->(Network)
(Indicator)-[:OBSERVED_IN]->(SecurityEvent)
(ThreatActor)-[:USES]->(Malware)
(Malware)-[:USES_TECHNIQUE]->(AttackTechnique)
(ThreatActor)-[:ASSOCIATED_WITH]->(Indicator)
(SecurityEvent)-[:INVOLVES]->(Asset)
(Incident)-[:CONTAINS_EVENT]->(SecurityEvent)
(Evidence)-[:SUPPORTS]->(Vulnerability)
(Evidence)-[:SUPPORTS]->(Indicator)
(Evidence)-[:SUPPORTS]->(ThreatActor)
```

Use relationship names that express what is actually known. Association
does not prove attribution. A graph path does not prove compromise.

### Provenance and time

Track source_name, source_reference, source_url, collected_at,
observed_at, valid_from, valid_until, confidence, verification_status,
tenant_id and content_hash.

For important facts, use Evidence nodes so multiple sources can support
or contradict an assertion.

### Example seed data

Verify syntax against the selected Memgraph release. The CVE below is
fictional.

``` cypher
CREATE (a:Asset {
  asset_id: "ASSET-001",
  name: "payment-api-01",
  asset_type: "server",
  environment: "production",
  criticality: "critical",
  internet_exposed: true,
  tenant_id: "TENANT-DEMO"
});

CREATE (s:Software {
  software_id: "SOFTWARE-001",
  vendor: "Example Vendor",
  product: "Example Server",
  version: "1.2.3"
});

CREATE (v:Vulnerability {
  cve_id: "CVE-DEMO-0001",
  cvss_score: 9.1,
  severity: "critical"
});

MATCH (a:Asset {asset_id: "ASSET-001"})
MATCH (s:Software {software_id: "SOFTWARE-001"})
MATCH (v:Vulnerability {cve_id: "CVE-DEMO-0001"})
CREATE (a)-[:RUNS]->(s);
CREATE (s)-[:AFFECTED_BY]->(v);
```

Example query:

``` cypher
MATCH (a:Asset)-[:RUNS]->(s:Software)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE v.cve_id = $cve_id
  AND a.environment = "production"
  AND a.criticality = "critical"
RETURN a, s, v;
```

Use query parameters; never concatenate user input into Cypher.

### Graph integrity rules

-   Use stable IDs and uniqueness constraints/indexes supported by the
    selected release.
-   Make ingestion idempotent.
-   Preserve source and timestamps.
-   Enforce tenant boundaries in every query.
-   Handle stale and conflicting intelligence.
-   Separate observed facts from inferred relationships.
-   Test queries against expected results.

## 6. Domain-specific MCP servers

Create six domain groups. They may run as separate local MCP processes.
Deploy separately only when needed.

### Asset Intelligence MCP

``` text
search_assets
get_asset_details
get_asset_software
get_asset_network
get_connected_assets
get_asset_dependencies
get_critical_assets
get_asset_exposure
```

### Vulnerability Intelligence MCP

``` text
search_vulnerabilities
get_vulnerability_details
get_affected_software
get_affected_assets
get_vulnerability_exposure
get_critical_vulnerabilities
compare_vulnerabilities
get_vulnerability_evidence
```

### Threat Intelligence MCP

``` text
search_threat_actors
get_threat_actor_profile
search_indicators
get_indicator_details
find_related_indicators
get_malware_details
get_attack_techniques
get_actor_techniques
```

### Attack Path Analysis MCP

``` text
find_attack_paths
get_attack_path_details
find_paths_to_critical_assets
find_lateral_movement_paths
analyze_asset_reachability
get_attack_path_risk
find_common_attack_nodes
```

### Incident Investigation MCP

``` text
search_incidents
get_incident_details
get_incident_events
correlate_security_events
find_related_incidents
get_incident_assets
get_incident_evidence
build_investigation_timeline
```

### Risk & Reporting MCP

``` text
calculate_asset_risk
prioritize_vulnerabilities
get_organizational_risk
explain_risk_score
generate_threat_summary
get_security_posture
compare_risk_over_time
```

### Example tool contract

``` json
{
  "name": "get_affected_assets",
  "description": "Finds authorized organization assets running software versions affected by a specified CVE.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "cve_id": {
        "type": "string",
        "description": "CVE identifier"
      },
      "environment": {
        "type": "string",
        "enum": ["production", "staging", "development", "all"]
      }
    },
    "required": ["cve_id"]
  }
}
```

The authenticated tenant must come from trusted request context, not a
tenant ID invented by the model.

## 7. MCP and agentic AI

-   **MCP Host:** AI application or environment, such as an
    MCP-compatible coding assistant.
-   **MCP Client:** Component inside the host that connects to MCP
    servers.
-   **MCP Server:** Exposes tools and other supported capabilities.
-   **Tool:** Callable operation such as `get_affected_assets`.
-   **Tool discovery:** Finds tools and their schemas.
-   **Tool execution:** Calls the server, which validates and runs the
    operation.

MCP standardizes interaction. It does not automatically provide
intelligent discovery for thousands of tools. ThreatLens must build a
registry and ranking layer.

### Tool registry metadata

``` json
{
  "tool_name": "find_attack_paths",
  "domain": "attack_path",
  "description": "Finds possible graph paths between a source asset and a target asset.",
  "input_entities": ["Asset"],
  "output_entities": ["Asset", "AttackTechnique"],
  "risk_level": "read_only",
  "permissions": ["security_analyst"],
  "tags": ["graph", "path", "lateral-movement"]
}
```

### Discovery pipeline

1.  Interpret user intent and identify entities.
2.  Filter by tenant, permissions and risk level.
3.  Filter by domain and entity types.
4.  Retrieve candidates with keyword and/or semantic search.
5.  Rerank using descriptions, input/output types and intent.
6.  Provide only the best matching tool schemas to the model.
7.  Validate arguments.
8.  Execute with server-side authorization.
9.  Return structured data and evidence.
10. Log tool choice, execution, latency and outcome.

The LLM is not the authorization authority.

### Example agent investigation

User: "Investigate whether our production payment server is exposed to
known vulnerabilities and show possible paths to critical systems."

The agent may: 1. Discover asset tools and locate the server. 2.
Retrieve software and network connections. 3. Discover vulnerability
tools and find matching affected software. 4. Check CISA KEV status. 5.
Discover attack-path tools and search bounded paths. 6. Retrieve
supporting evidence and timestamps. 7. Explain confirmed exposure
separately from possible paths and uncertain associations.

The agent should not call every tool. It selects tools based on the
question and evidence.

## 8. Data sources and ingestion

Start with official public sources and a synthetic company environment.

  Source         Use
  -------------- ----------------------------------------------------------
  NVD API        CVE and vulnerability records
  CISA KEV       Known exploited vulnerabilities
  MITRE ATT&CK   Tactics, techniques and procedures
  STIX 2.1       Structured threat intelligence objects and relationships
  TAXII 2.1      Transport for supported threat intelligence collections
  FIRST CVSS     Vulnerability severity methodology

References: - NVD API: https://nvd.nist.gov/developers/vulnerabilities -
CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog -
MITRE ATT&CK: https://attack.mitre.org/ - STIX/TAXII:
https://oasis-open.github.io/cti-documentation/ - FIRST CVSS:
https://www.first.org/cvss/ - Memgraph docs: https://memgraph.com/docs/

### Ingestion flow

``` text
Public feeds / Approved APIs / Uploaded files / Approved URLs
                            |
                            v
                     Source connectors
                            |
                            v
                   Parse and validate
                            |
                            v
                 Normalize and deduplicate
                            |
                            v
                    Enrich and correlate
                            |
                            v
              Memgraph + PostgreSQL persistence
                            |
                            v
                 Import report and audit log
```

### URL ingestion security

URL ingestion can introduce SSRF and malicious content risks.
Implement: - Approved source-domain allowlists. - HTTPS-only by
default. - Block localhost, private, link-local and cloud metadata IP
ranges. - Revalidate every redirect destination. - Limit response size
and request time. - Validate content type. - Parse in a restricted
worker. - Never execute scripts or downloaded files. - Store URL and
content hash. - Require approval for new source domains.

### API connector security

Use least-privilege tokens, secure secret storage, rotation/revocation,
rate-limit handling, pagination, retry with backoff, response validation
and audit logging. Never log credentials.

## 9. Risk analysis and graph algorithms

Start with a transparent, rules-based score using: - CVSS severity. -
CISA KEV status. - Asset criticality. - Internet exposure. - Evidence
confidence. - Evidence freshness.

Display the factors separately and document the formula. Calibrate it
with test cases. Do not claim it is an industry-standard score or proof
of compromise.

Graph algorithms to explore: - Breadth-first search: reachable assets
within a hop limit. - Shortest path: connection between two entities. -
Connected components: connected groups. - Degree centrality: highly
connected nodes. - Community detection: clusters. - Weighted path
ranking: possible paths ranked by modeled risk factors.

A graph path is a modeled possible route, not proof that every step is
exploitable. Model prerequisites and evidence.

## 10. Frontend pages

1.  Security Overview.
2.  Threat Graph Explorer.
3.  Vulnerability Management.
4.  Attack Path Analysis.
5.  Threat Intelligence.
6.  Incident Investigation.
7.  AI Security Analyst.
8.  Data Sources and Integrations.
9.  Administration and Audit.

Use Cytoscape.js for graph visualization. The backend remains
responsible for authoritative queries and permission checks.

## 11. Repository structure for VS Code

``` text
threatlens-ai/
|
|-- frontend/
|   |-- app/
|   |-- components/
|   |-- features/
|   |   |-- dashboard/
|   |   |-- graph-explorer/
|   |   |-- vulnerabilities/
|   |   |-- attack-paths/
|   |   |-- incidents/
|   |   |-- ai-analyst/
|   |   |-- integrations/
|   |-- tests/
|
|-- backend/
|   |-- src/main/
|   |-- src/test/
|   |-- pom.xml
|
|-- intelligence-service/
|   |-- app/
|   |-- ingestion/
|   |-- normalization/
|   |-- enrichment/
|   |-- correlation/
|   |-- graph_queries/
|   |-- tests/
|
|-- mcp-servers/
|   |-- asset-intelligence/
|   |-- vulnerability-intelligence/
|   |-- threat-intelligence/
|   |-- attack-path/
|   |-- incident-investigation/
|   |-- risk-reporting/
|
|-- tool-discovery/
|   |-- registry/
|   |-- search/
|   |-- ranking/
|   |-- permissions/
|   |-- evaluation/
|
|-- database/
|   |-- memgraph/
|   |-- postgres/
|   |-- migrations/
|
|-- data/seed/
|-- data/fixtures/
|-- data/schemas/
|-- tests/integration/
|-- tests/security/
|-- tests/performance/
|-- tests/evaluation/
|-- docs/architecture/
|-- docs/api/
|-- docs/mcp/
|-- docs/threat-model/
|-- .github/workflows/
|-- docker-compose.yml
|-- .env.example
|-- .gitignore
|-- README.md
```

### VS Code extensions

-   Java Extension Pack.
-   Python and Pylance.
-   Docker.
-   GitHub Actions.
-   ESLint and Prettier.
-   YAML.
-   REST Client or equivalent API testing extension.

Use separate terminals for frontend, Spring Boot, Python and MCP
processes. Docker Compose starts shared infrastructure.

## 12. Local development

The first local environment should include: - Memgraph. - Memgraph Lab,
if supported by the selected image/version. - PostgreSQL. - Redis when
background jobs are added. - Spring Boot. - Python intelligence
service. - MCP processes. - Next.js.

Keep databases on a private Docker network. For local development, bind
database ports to localhost only.

Example `.env.example`:

``` dotenv
APP_ENV=local
MEMGRAPH_HOST=memgraph
MEMGRAPH_PORT=7687
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=threatlens
REDIS_HOST=redis
REDIS_PORT=6379
JWT_ISSUER=
JWT_AUDIENCE=
NVD_API_KEY=
MODEL_PROVIDER=
MODEL_API_KEY=
```

Commit placeholders only. Never commit `.env`, real keys, passwords,
private certificates or production data.

## 13. Testing strategy

  -----------------------------------------------------------------------
  Test level              Verify                  Tools
  ----------------------- ----------------------- -----------------------
  Unit                    Parsers, normalization, JUnit 5, pytest
                          risk formula            

  API                     Endpoints, validation,  REST Assured, pytest
                          authorization           

  Graph                   Relationships, paths,   Memgraph test
                          duplicates              environment

  MCP                     Discovery, schemas,     MCP client integration
                          execution and errors    tests

  AI evaluation           Tool choice, arguments, Custom evaluation suite
                          grounded answers        

  UI                      Dashboard, graph and    Playwright
                          workflows               

  Security                Tenant isolation, SSRF, OWASP ZAP and targeted
                          access control          tests

  Performance             Query latency and       k6
                          concurrency             
  -----------------------------------------------------------------------

Build 50--100 repeatable evaluation questions. Measure correct tool
selection, argument accuracy, successful execution, grounded answers,
false positives/negatives, unauthorized invocation rate, latency and
model usage.

Important test cases: - A matching CVE and installed software returns
the expected asset. - No matching software means no affected asset is
claimed. - Tenant A cannot access Tenant B's asset. - A URL resolving to
a private IP is blocked. - Reimporting a feed does not create duplicate
entities. - Malformed tool arguments are rejected. - Weak indicator
evidence is described as uncertain.

## 14. Security requirements

-   OAuth2/OIDC and JWT authentication.
-   Role-based access control: Admin, Security Analyst, Read-only
    Viewer.
-   Tenant isolation in every service and graph query.
-   Authenticated remote MCP clients.
-   Server-side authorization for every tool.
-   Input validation, rate limits, timeouts and bounded graph traversal.
-   Audit user, tenant, tool, time, outcome and correlation ID.
-   Treat external feed content and retrieved documents as untrusted.
-   Never allow retrieved content to override system/developer
    instructions.
-   Keep initial tools read-only.
-   Require human approval for any future action that changes external
    systems.

Authentication identifies the user. Authorization decides what they can
access. MCP does not replace either.

## 15. Development roadmap

Approximate part-time plan: 8--10 weeks, depending on available time and
familiarity.

### Phase 1 --- Foundation and graph model (Weeks 1--2)

-   Create GitHub repository and VS Code workspace.
-   Start Memgraph and PostgreSQL using Docker Compose.
-   Define labels, relationships and stable IDs.
-   Add synthetic assets, software and vulnerabilities.
-   Write and test Cypher queries.
-   Document the graph model.

**Deliverable:** Populated Memgraph graph with tested relationships.

### Phase 2 --- Ingestion and backend (Weeks 3--4)

-   Implement NVD, CISA KEV and MITRE ATT&CK importers.
-   Add CSV/JSON synthetic asset import.
-   Implement normalization and deduplication.
-   Build Spring Boot APIs.
-   Add evidence/provenance and explainable risk scoring.

**Deliverable:** Repeatable ingestion and working APIs.

### Phase 3 --- MCP domain tools (Week 5)

-   Implement domain MCP servers.
-   Add schemas and descriptions.
-   Connect tools to service functions.
-   Add authorization, audit and integration tests.

**Deliverable:** Independently testable MCP tools.

### Phase 4 --- Tool discovery and agent (Week 6)

-   Build registry.
-   Add metadata filters and keyword/semantic retrieval.
-   Add reranking and permission filtering.
-   Integrate one model provider behind an adapter.
-   Build multi-step investigation and evidence-grounded responses.

**Deliverable:** Agent dynamically discovers and calls relevant tools.

### Phase 5 --- Frontend (Weeks 7--8)

-   Build dashboard and graph explorer.
-   Build vulnerability, incident and attack-path pages.
-   Build AI Analyst with tool execution trace.
-   Build source import and integration screens.

**Deliverable:** Interactive web application.

### Phase 6 --- Quality and deployment (Weeks 9--10)

-   Complete automated tests and AI evaluation.
-   Add logs and metrics.
-   Add CI/CD and secure configuration.
-   Deploy portfolio demo.
-   Publish architecture and demo documentation.

**Deliverable:** Reproducible public portfolio demonstration.

## 16. Deployment

Possible portfolio hosting: - Next.js: Vercel. - Java/Python containers:
Render or another Docker-capable host. - Memgraph: suitable managed
Memgraph offering or secured VM/container. - PostgreSQL: managed
PostgreSQL. - Source/CI: GitHub and GitHub Actions.

Check current provider limits. Free services may sleep, pause, have
limited resources or lack backups and production SLAs. A free deployment
is a demo, not a production security service.

Suggested hostnames:

``` text
app.<your-domain>
api.<your-domain>
mcp.<your-domain>
```

Keep databases private. Expose only authenticated application endpoints.
Use HTTPS, secrets, backups and monitoring.

## 17. First end-to-end milestone

Do not build every screen and MCP server first. Build one vertical
slice:

1.  Import a real CVE from NVD.
2.  Import its CISA KEV status.
3.  Load synthetic company assets and software.
4.  Connect asset → software → vulnerability in Memgraph.
5.  Query critical production assets affected by that CVE.
6.  Expose the query as `get_affected_assets`.
7.  Connect an MCP client and an AI model.
8.  Ask the question in natural language.
9.  Verify that the agent discovers and calls the correct tool.
10. Display the answer with evidence, source and collection time.
11. Verify cross-tenant access is denied.

This proves the database, backend, MCP and AI layers work together.

## 18. Interview demonstration

Prepare a five-minute demo: 1. Show the threat graph. 2. Open a CVE and
its source evidence. 3. Show connected software and assets. 4. Ask the
AI Analyst which critical production assets are affected. 5. Show the
MCP tool selected and its arguments. 6. Show graph results and evidence.
7. Ask for possible paths to a critical asset. 8. Explain confirmed
facts versus inferred paths. 9. Demonstrate an unauthorized request
being denied. 10. Show tests and CI.

Be accurate about implemented features versus planned features.

## 19. Definition of success

A developer can clone the repository, start the local environment,
import sample intelligence, inspect the Memgraph graph, run domain MCP
tools, ask an AI investigation question and receive a traceable answer
with evidence.


---

# 20. Scope control: current build versus future scope

This section is the scope baseline for the first implementation. Keep the
project ambitious in its architecture, but implement it in small,
working increments. Do not attempt to build every module before the
first end-to-end workflow works.

## 20.1 Current scope: portfolio MVP

The first release should prove that ThreatLens can ingest threat data,
match it to an organization's assets, expose the result through MCP,
and let an AI assistant investigate it with evidence.

| Area | Include in the first release |
|---|---|
| Threat sources | NVD CVE data and CISA KEV status; MITRE ATT&CK can be added after the first CVE workflow is working |
| Internal data | Synthetic company assets and installed software, loaded from a documented CSV/JSON format |
| Import methods | Scheduled/manual source sync plus CSV/JSON upload; a restricted URL import can follow once API ingestion is stable |
| Graph | Memgraph nodes and relationships for assets, software, vulnerabilities and evidence |
| Relational data | PostgreSQL for application users, connector/sync status, jobs and audit records |
| Backend | Spring Boot APIs for the web application and security boundary |
| Intelligence layer | Python ingestion, normalization, product/version matching and graph query services |
| MCP | Begin with the Vulnerability and Asset Intelligence tool groups; implement the remaining domain groups as the corresponding product features are added |
| Agent | One model provider behind a provider-independent adapter; dynamic tool discovery from a small registry |
| UI | A basic overview, data-source/sync status, affected-assets view, and AI Analyst with a visible tool-call/evidence trace |
| Security | Read-only tools, authentication/authorization foundation, tenant-aware data access, input validation and audit events |
| Quality | Unit/integration tests for ingestion, matching, graph queries, MCP calls and tenant isolation |
| Delivery | Docker Compose local development, GitHub repository and a clear README with a repeatable demo |

### MVP acceptance criteria

The MVP is complete only when all of the following work:

1. A developer can clone the repository and start the required local services using the documented commands.
2. The NVD connector can retrieve and store vulnerability records, and the CISA KEV connector can add known-exploited status where applicable.
3. A sample organization asset file can be validated and imported without requiring access to a real company.
4. A supported product/version match connects the correct software and assets to a vulnerability. An uncertain or missing match must not be presented as confirmed exposure.
5. Re-running an import updates existing records rather than creating duplicates.
6. A query returns affected assets with the source, collection time and matching reason.
7. An MCP tool such as `get_affected_assets` exposes that same tested service operation.
8. An MCP-compatible AI client can discover and call the tool to answer a natural-language question.
9. The UI shows the answer, the tool used, and its supporting evidence.
10. Tests prove that a user/tenant cannot read another tenant's data.
11. The UI clearly shows the last successful sync time and does not describe stale data as live/current.

## 20.2 Future scope: later releases

Keep these in the architecture and backlog, but do not make them prerequisites for the MVP.

| Future capability | Possible later implementation |
|---|---|
| More threat sources | Additional vendor advisories, threat feeds, malware/indicator sources and supported STIX/TAXII collections |
| Internal security integrations | Authorized CMDB, vulnerability scanners, SIEM, EDR, cloud inventory and ticketing integrations |
| More import formats | STIX 2.1 bundles, JSONL, additional scanner-specific formats and richer import mapping |
| Full MCP domain coverage | Complete Threat Actor, Attack Path, Incident Investigation and Risk & Reporting tool groups |
| Advanced tool discovery | Semantic search, embeddings, reranking, tool usage analytics and evaluation-driven ranking |
| Advanced graph analysis | Bounded multi-hop paths, weighted path ranking, centrality, connected components and community detection |
| Richer AI investigations | Multi-step investigation plans, follow-up questions, citations, confidence explanations and repeatable investigation reports |
| Multi-model support | Additional hosted or local model providers, selected through configuration |
| Enterprise identity | OIDC/SSO, more granular RBAC, organization provisioning and stronger tenant administration |
| Operations | Background queues, retries, dead-letter handling, observability, alerting, backups and retention policies |
| Response workflows | Human-approved remediation recommendations or ticket creation; no autonomous changes by default |
| Production deployment | Hardened cloud deployment, managed services, infrastructure-as-code, disaster recovery and operational runbooks |

### Explicit non-goals for the initial release

- No vulnerability exploitation, penetration testing or offensive payload generation.
- No scanning of arbitrary public IP addresses or systems.
- No automatic firewall, endpoint, identity or cloud configuration changes.
- No claim that a graph path proves a system is compromised or exploitable.
- No claim that a CVE affects an asset unless product/version evidence or a trusted scanner result supports the match.
- No assumption that every external website is safe to fetch or parse.
- No requirement to connect to a real company's private systems for the portfolio demo.

## 20.3 Data freshness and source status

ThreatLens is only as current as its most recent successful source sync. Every
connector should record at least:

- `last_attempt_at`
- `last_success_at`
- `last_status` (success, partial, failed)
- `records_received`
- `records_created`
- `records_updated`
- `records_rejected`
- `error_summary` (with secrets and sensitive response data removed)
- `source_modified_at`, when the provider supplies it

Show this information in the Data Sources screen and include relevant
timestamps in AI answers. Support manual refresh first; add schedules and
background workers after the basic connector is reliable. Respect provider
rate limits, pagination and terms. If a source is unavailable, show the
last successful sync and state that the data may be stale.

External threat intelligence and internal asset inventory have different
freshness requirements. A recently synced CVE feed does not make an old
asset inventory current. Display both timestamps when explaining whether
an asset may be affected.

## 20.4 Product/version matching rules

Do not equate a matching product name with a confirmed vulnerable asset.
The matching service should:

1. Normalize vendor and product identifiers without discarding the original source values.
2. Preserve the installed version and the source's affected-version range.
3. Apply a documented comparison strategy for version ranges.
4. Record the source and reason for every match.
5. Distinguish `confirmed`, `possible`, `not_affected` and `unknown` states, or an equally clear status model.
6. Prefer validated vulnerability-scanner evidence when available, while retaining the original evidence.
7. Return `unknown` rather than guessing when product identity or version cannot be established.

The exact version-range rules vary by source and ecosystem. Implement and
test source-specific matching rather than assuming every vendor uses the
same version format.

# 21. Developing with VS Code and Claude Code

Use this document as the product and architecture reference. Claude Code
should help implement the project in small, reviewable tasks; it should not
be asked to generate the entire platform in one request.

## 21.1 Recommended working approach

1. Create the GitHub repository and open its root folder in VS Code.
2. Add this specification to the repository as `docs/PROJECT_SPEC.md`.
3. Create a short `CLAUDE.md` at the repository root. It should tell Claude Code to read `docs/PROJECT_SPEC.md` before making changes and to follow the current-scope boundary in Section 20.
4. Ask Claude Code to inspect the existing repository and propose the smallest next implementation step before writing code.
5. Implement one vertical slice at a time. Run tests and inspect the diff after each step.
6. Commit working milestones to GitHub. Do not wait until the entire project is complete.
7. Keep secrets in local environment variables or an appropriate secret store. Commit only `.env.example` placeholders.

## 21.2 Suggested initial `CLAUDE.md`

Create a file named `CLAUDE.md` in the repository root with guidance similar to this:

```markdown
# ThreatLens AI - Claude Code Instructions

Before making changes, read `docs/PROJECT_SPEC.md` completely.

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

## Completion report
For each task, report:
1. What changed.
2. Files created or modified.
3. Commands/tests run and their results.
4. Known limitations or follow-up work.
5. The next smallest recommended task.
```

## 21.3 First prompts to give Claude Code

Use these prompts in order. Wait for each task to finish, review its output, and test it before moving to the next.

**Prompt 1 — inspect and plan (no code yet)**

```text
Read CLAUDE.md and docs/PROJECT_SPEC.md. Inspect the repository.
Do not write or modify code yet. Summarize the architecture, identify
what is already present, and propose a small Phase 1 implementation
plan. List assumptions and any technology/version decisions that need
confirmation.
```

**Prompt 2 — establish the repository foundation**

```text
Implement only the repository foundation for Phase 1. Create the
agreed folder structure, root README, .gitignore, .env.example and
Docker Compose configuration for local Memgraph and PostgreSQL.
Do not implement the frontend, AI agent, MCP servers or ingestion yet.
Use safe local-only database port bindings. Validate the Compose
configuration and explain how to start and verify the containers.
```

**Prompt 3 — verify the databases**

```text
Help me verify the local Memgraph and PostgreSQL containers. Add only
the minimal health checks or setup files needed. Give me the exact
commands to connect, run a simple test query, and confirm both databases
are ready. Do not proceed to another phase until this works.
```

**Prompt 4 — define and seed the first graph slice**

```text
Implement the initial Memgraph schema and a small synthetic dataset
for one organization: assets, installed software, vulnerabilities and
evidence. Use stable IDs and make the seed operation safe to rerun.
Add a query that finds production assets affected by a specified CVE.
Add tests or a repeatable verification script. Do not add unrelated
node types or future-scope features.
```

**Prompt 5 — build the first ingestion connector**

```text
Implement the NVD ingestion slice described in docs/PROJECT_SPEC.md.
First explain the NVD fields needed and how they map to our internal
vulnerability/evidence model. Then implement a small, testable connector
with pagination, rate-limit handling, validation, idempotent persistence
and sync-status timestamps. Keep API credentials outside source code.
Do not infer affected internal assets from a CVE record alone.
```

After this first connector works, add CISA KEV status, synthetic asset
CSV/JSON import, the tested affected-assets service, its MCP tool, and
the AI client integration in that order.

## 21.4 How to work with Claude Code safely and efficiently

- Ask for a plan before a broad change; approve the plan before implementation.
- Give one bounded task at a time, such as “add the CISA KEV enrichment to the existing vulnerability model,” not “finish the whole threat intelligence platform.”
- Ask it to explain unfamiliar code in plain language before asking for changes.
- Ask it to show the exact files changed and the tests run.
- Review dependency additions and version changes rather than accepting them automatically.
- Do not paste production credentials, customer data, private incident details or confidential company exports into prompts.
- Do not let the model decide authorization. Authorization must be enforced by backend code.
- Treat AI-generated code as a proposal: run tests, inspect security-sensitive logic and review the Git diff before committing.
- Keep a working Git commit before each larger task so changes can be reverted safely.

## 21.5 Development checkpoints

Use these checkpoints to avoid building too much at once:

| Checkpoint | Demonstrable result | Move forward when |
|---|---|---|
| 1. Local foundation | Memgraph and PostgreSQL start locally | Both health checks and test queries pass |
| 2. Graph slice | Synthetic assets, software, CVE and evidence are connected | Seed can be rerun without duplicates and query returns expected data |
| 3. External intelligence | NVD and CISA KEV data can be refreshed | Sync status, source and timestamps are stored |
| 4. Asset matching | Imported inventory is matched to affected products/versions | Positive, negative and unknown cases are tested |
| 5. Backend API | Authenticated API returns affected assets | Validation, authorization and tenant tests pass |
| 6. MCP | `get_affected_assets` is callable by an MCP client | Schema, arguments, results and errors are tested |
| 7. AI investigation | AI discovers and calls the MCP tool | Tool trace and evidence are visible; unsupported claims are avoided |
| 8. Basic web UI | User can inspect sync, affected assets and ask the analyst | End-to-end demo works locally |
| 9. Portfolio readiness | README, screenshots/demo and CI are available | A new developer can reproduce the demo from the instructions |

---

# 22. Decisions intentionally left open

Do not guess these decisions prematurely. Record the selected option in the
repository README or an architecture decision record when it is time to
implement it.

- **AI provider:** No provider is mandated yet. Select one for the first working integration, keep it behind an adapter, and make API cost/usage visible. A mock provider can be used while building non-AI layers.
- **Claude Code versus runtime AI:** Claude Code is the development assistant used to write and review the project. It is not automatically the AI model or agent that the finished ThreatLens application will use. The deployed application needs its own configured model provider and MCP client/agent integration.
- **MCP deployment shape:** Start with clear domain modules and the first required MCP tool. Run separate MCP server processes when useful; do not add deployment complexity before there is a working use case.
- **Hosting provider:** Build and verify locally first. Choose hosting only after the resource requirements, persistent storage, network access and free-tier limits are checked.
- **Authentication provider:** Build the authorization boundaries early, then choose an OIDC provider when the UI and multi-user workflow are ready.
- **Scheduling technology:** Start with manual sync and reliable sync-status records. Add a scheduler/queue when connector behavior is tested.

The architecture should allow these decisions to evolve without changing the
core product purpose or the first vertical slice.
