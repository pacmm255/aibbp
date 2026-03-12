# AIBBP Complete Architecture Reference

## 1. System Overview

AIBBP (AI Bug Bounty Platform) is an autonomous pentesting agent built on a LangGraph state machine. It uses a ReAct (Reason + Act) loop where an LLM "brain" decides which security tools to invoke, processes results, and iterates until findings are exhausted or budget runs out.

**Core stack:** Python 3.12, LangGraph, Anthropic Claude API (OAuth), httpx, asyncio, structlog, PostgreSQL, Redis, Neo4j (optional), Playwright (browser), Docker (sandboxing).

**Cost model:** Supports three brain backends:
- **Claude** (paid): Opus ($15/$75 per MTok), Sonnet ($3/$15), Haiku ($0.25/$1.25) -- tiered by task criticality
- **Z.ai GLM-5** (free): via chat.z.ai with HMAC-SHA256 auth, proxy pool for rate limiting
- **ChatGPT** (free): anonymous chatgpt.com with Turnstile VM challenge pipeline via Goja TLS proxy

---

## 2. File Map (26 files)

### Core Graph Engine
| File | Lines | Purpose |
|------|-------|---------|
| `react_graph.py` | ~4800 | 3-node LangGraph: brain_node, tool_executor_node, context_compressor. All hooks, routing, dedup, chain discovery, compression |
| `react_state.py` | 172 | `PentestState` TypedDict with ~65 fields, custom `_messages_reducer` |
| `react_prompt.py` | ~2100 | Static system prompt, 43 tool schemas, phase contexts, dynamic state template, coverage matrix, Thompson sampling display |
| `react_tools.py` | ~2100 | `dispatch_tool()` router for ~50 tools, `ToolDeps` dataclass, evidence scoring, finding validation, working memory, attack chains |
| `react_main.py` | ~1500 | CLI entry point (argparse), infrastructure init, graph invocation |

### Infrastructure Components
| File | Lines | Purpose |
|------|-------|---------|
| `models.py` | ~550 | `ClaudeClient`: OAuth auth, tiered models, prompt caching, rate limiter, circuit breaker, budget check |
| `budget.py` | 369 | `BudgetManager`: phase allocation, adaptive reallocation, emergency reserve, cost attribution |
| `goja_manager.py` | 198 | Goja SOCKS5 TLS fingerprint proxy (Chrome 139 JA3/JA4/HTTP2) |
| `docker_executor.py` | 176 | Per-agent Kali container sandbox (asyncio docker CLI, 2GB limit, network=host) |
| `proxy_pool.py` | ~600 | 60+ proxy sources, per-proxy rate limiting, cross-process cache, auto-replacement |

### Brain Backends
| File | Lines | Purpose |
|------|-------|---------|
| `zai_client.py` | ~600 | Z.ai GLM-5 client: HMAC-SHA256 signed, streaming, tool call extraction via 6 regex patterns, JSON repair |
| `chatgpt_client.py` | ~800 | ChatGPT anonymous client: 5-token challenge pipeline (VM + Sentinel + PoW + Turnstile + Conduit), Goja TLS proxy |

### Intelligence & Analysis
| File | Lines | Purpose |
|------|-------|---------|
| `chain_discovery.py` | 715 | `ChainDiscoveryEngine` (15 chain templates, heuristic scoring) + `AdversarialReasoningEngine` (7 reasoning rules) |
| `advanced_attacks.py` | 848 | 7 attack modules: HTTP smuggling, cache poisoning, mass assignment, prototype pollution, CORS, open redirect, behavioral profiling |
| `waf_bypass.py` | 639 | WAF fingerprinting (60+ keyword probes, 11 encoding transforms, 12 vendor signatures), XSS/SQLi/CMDi/LFI bypass generation |
| `deterministic_tools.py` | ~2500 | 16+ zero-cost scanners: BlindSQLi, ResponseDiff, SystematicFuzzer, InfoDisclosure (66 paths), AuthBypass, CSRF, Error, CRLF, HostHeader, NoSQLi, XXE, Deserialization, DoS, GraphQL, Secrets, JWTDeep, SSRF, SSTI, RaceCondition, AuthzMatrix |

### Persistence & Learning
| File | Lines | Purpose |
|------|-------|---------|
| `findings_db.py` | 971 | PostgreSQL (asyncpg): findings table with dedup_hash, CVSS, CWE, bounty tracking; finding_updates audit trail; scans; proxy_traffic |
| `finding_dedup.py` | 185 | Semantic dedup via sentence-transformers/all-MiniLM-L6-v2 (cosine sim 0.85), MD5 fallback, Redis persistence |
| `session_learning.py` | 214 | Redis-backed cross-session: bandit state, WAF profiles, tech stack, technique priorities, agent heartbeat |
| `neo4j_knowledge_graph.py` | 548 | Graph DB: Target/Endpoint/Finding/Hypothesis/Account/Technology/Episode nodes, Graphiti-inspired search, strategic insights |

### Safety & Monitoring
| File | Lines | Purpose |
|------|-------|---------|
| `scope_guard.py` | 251 | `ActiveScopeGuard`: URL/request/tool/browser validation, never-test domains (Stripe, PayPal, etc.), destructive SQL detection |
| `react_health.py` | 354 | Preflight checks (7 components) + `ToolCircuitBreaker` (3 failures = 5 min disable, half-open reset) |
| `react_coverage.py` | 333 | `CoverageQueue`: UCB1 scoring, 13 core techniques, 60% coverage gate, endpoint value heuristics |
| `react_transcript.py` | 330 | JSONL transcript logger: thread-safe, 200KB caps, 15 event types |

### Output
| File | Lines | Purpose |
|------|-------|---------|
| `report_generator.py` | 390 | Multi-format reports (Markdown/HTML/JSON), CWE mapping (27 types), CVSS 3.1 scoring, remediation guidance, Mermaid chain diagrams |
| `api_server.py` | 777 | FastAPI dashboard: JWT auth, findings/scans/proxy CRUD, WebSocket live updates, scan launch/stop via subprocess, security headers |

---

## 3. Complete CLI-to-Completion Flow

```
react_main.py: parse_args()
  |
  +-- Initialize infrastructure:
  |   BrowserController, CaptchaSolver, EmailManager, GojaManager.start(),
  |   HexstrikeServerManager, TrafficInterceptor (mitmproxy :8085),
  |   TranscriptLogger, SessionLearning (Redis :6382),
  |   FindingsDB (Postgres :5433), DockerExecutor (optional),
  |   Neo4jKnowledgeGraph (optional), ProxyPool (optional),
  |   ZaiClient / ChatGPTClient / ClaudeClient (based on --zai / --chatgpt flags)
  |
  +-- TargetMemory.load() (warm start from ~/.aibbp/targets/<hash>/)
  +-- SessionLearning.warm_start() (bandit state, WAF profiles, tech stack)
  +-- ActiveScopeGuard(ScopeEnforcer(target, allowed_domains))
  +-- build_react_graph() -> compiled StateGraph
  +-- run_preflight_checks() -> tool_health dict
  |
  +-- graph.ainvoke(initial_state, config)
  |     config["configurable"] = {
  |       client, claude_client, browser, proxy, email_mgr, tool_runner,
  |       hexstrike_client, scope_guard, http_repeater, authz_tester,
  |       traffic_intelligence, traffic_analyzer, budget, findings_db,
  |       circuit_breaker, transcript, session_learning, _coverage_queue,
  |       _neo4j_kg, goja_socks5_url, docker_executor, deduplicator,
  |       captcha_solver, agent_c_research, default_headers, config, max_turns
  |     }
  |
  +-- Graph loop (up to max_turns or budget exhaustion):
  |     brain_node -> tool_executor_node -> context_compressor -> brain_node ...
  |
  +-- Cleanup:
      TargetMemory.save(), findings JSON to --output, GojaManager.stop(),
      DockerExecutor.stop(), BrowserController.close(), FindingsDB.close()
```

---

## 4. Graph Nodes & Edges

### Node 1: `brain_node`
**Checks (in order):** shutdown flag, RSS memory (--max-rss), budget exhaustion, turn limit

**System prompt construction:**
1. `AUTHORIZATION_BLOCK` (legal framing to reduce model refusals)
2. Mode prefix: `[REAL-WORLD BUG BOUNTY]` or `[CTF CHALLENGE]`
3. `STATIC_SYSTEM_PROMPT` (~8K tokens): methodology, tool priority hierarchy, attack decision trees (20+ patterns)
4. `_PHASE_CONTEXTS[current_phase]`: phase-specific instructions
5. `DYNAMIC_STATE_TEMPLATE`: live target info, budget, endpoints, findings, hypotheses, accounts, traffic intelligence, coverage matrix, Thompson sampling recommendations, working memory, phase budgets, attack chains, Sonnet app model
6. Coverage queue section (from `react_coverage.py`)
7. Health section (from `react_health.py`)
8. Neo4j strategic insights (if connected)
9. Free brain few-shot examples (if Z.ai/ChatGPT)
10. Strategy checkpoint (free brain, every 5 turns)
11. Tool diversity enforcement warning

**Tiered model selection (`_select_brain_tier`):**
- Turn 0: Opus (initial strategy)
- Every 8 turns: Opus (periodic review)
- New finding detected: Opus
- Stalled 5+ turns: Opus
- Escalation signal regex match: Opus
- Default: Sonnet

**Phase gate enforcement:** Blocks exploitation tools until recon phase complete. Blocks bookkeeping tools after 3+ consecutive. Blocks `finish_test` when >50% budget remains.

**Reflector pattern:** When brain returns text without tool calls, retries up to 3 times with contextual nudges (refusal detection, planning-without-action, state-based defaults). Sonnet refusal triggers Opus escalation.

**API call:** `client.messages.create()` with native tool schemas, streaming if supported.

### Node 2: `tool_executor_node`
**Per-tool-call processing:**
1. Repeating detector: blocks identical consecutive tool calls after threshold
2. Tool diversity: blocks `run_custom_exploit`/`send_http_request` after 5 consecutive
3. Technique dedup tracking: records `endpoint::tool` as tested
4. Circuit breaker check: `is_disabled()` before dispatch
5. `dispatch_tool()` with per-tool timeouts (45s default, 120s for custom exploits)
6. Result parsing: JSON with control-character sanitization fallback
7. State update extraction: `_state_update` and `_done` sentinel keys
8. Coverage queue update: marks (endpoint, technique) as tested
9. Thompson sampling: updates alpha/beta for bandit state
10. Adversarial reasoning: generates hypotheses from tool results (7 rules)
11. **Hook 2 (Sonnet Exploit Strategy):** fires when tool returns `vulnerable:true`/`injectable:true`, max 2 calls
12. Chain discovery: feeds new findings to `ChainDiscoveryEngine`
13. Self-validation injection: requires re-verification for unconfirmed findings

**Finding pipeline within tool_executor_node:**
- Finding dedup at merge time (canonical vuln_type + normalized endpoint)
- Per-type cap: max 10 findings of same canonical type per session
- Re-verification gate: lightweight HTTP check (endpoint exists?)
- Auto-differential testing gate: baseline/payload/control comparison for injection types
- DB push via `findings_db.bulk_upsert()`
- Redis publish for live dashboard

**Stopping conditions (after all tools):**
- No progress for 10 turns (25 in indefinite mode): stop or strategy reset
- 5 consecutive failures (15 in indefinite): stop or strategy reset
- Same result 3 times (5 in indefinite): stop or strategy reset
- Strategy resets rotate through 3 strategy sets to avoid repetition

### Node 3: `context_compressor`
**Periodic operations:**
- Auto-save TargetMemory every 10 turns
- Neo4j state sync + episode recording
- Budget rebalance every 5 turns (3 rules)
- Cross-session learning save every 10 turns + heartbeat every turn

**Strategic Intelligence Hooks:**
- **Hook 0 (`_recon_blitz_with_opus`):** Fires at turn >= 3 with >= 5 endpoints. Runs 12 parallel deterministic scanners (InfoDisclosure, AuthBypass, CSRF, ErrorResponse, CRLF, HostHeader, NoSQLi, XXE, Deserialization, DoS, GraphQL, JS Secrets), then Opus with 16K thinking for vulnerability detection
- **Hook 1 (`_sonnet_app_comprehension`):** Fires when endpoints >= 8 OR turn >= 12. Sonnet builds auth_matrix, business_workflows, high_value_targets, abuse_scenarios. Result in `state["app_model"]`
- **Hook 3 (`_opus_chain_reasoning`):** Fires at turn >= 30 OR findings >= 3. Opus with 8K thinking for chain building and hypothesis generation

**Auto-extraction to working memory:** Scans recent messages for JWTs, version strings, error paths, S3 buckets, API endpoints, credentials, status codes, form params, WAF patterns.

**Compression tiers:**
| Tier | Threshold | Method | LLM Cost |
|------|-----------|--------|----------|
| 1 | < 80K chars | Keep everything | $0 |
| 2 | 80K-160K | Truncate tool outputs to 2K chars | $0 |
| 2.5 | 160K-250K | AST structural compression (age-based: oldest=1-line, middle=500 chars, recent=untouched) | $0 |
| 3 | > 250K | Haiku summarization of old messages, keep 10-15 recent | ~$0.001 |

All compression tiers use `_sanitize_tool_pairing()` to ensure tool_use/tool_result pairs remain matched (prevents Anthropic API 400 errors).

### Routing Functions

**`_route_after_brain`:**
- `state.done` = True and not indefinite mode -> END
- `state._pending_tool_calls` -> "tools"
- Indefinite mode: never ends, always -> "tools"

**`_route_after_compress`:**
- `state.done` -> END
- Budget >= 90% (finite) or >= 98% (indefinite) -> END
- Confidence < 0.20 AND stalled >= 3 (8 indefinite) turns -> END (ADaPT policy)
- Otherwise -> "brain"

### Edge Summary
```
brain --[has tool calls]--> tools --[always]--> compress --[not done]--> brain
brain --[done/no action]--> END
compress --[done/budget/confidence]--> END
```

---

## 5. Tool Categories (43 schemas)

### Recon Tools (11)
`navigate_and_extract`, `crawl_target`, `run_nuclei_scan`, `run_content_discovery`, `detect_technologies`, `detect_waf`, `analyze_traffic`, `enumerate_subdomains`, `resolve_domains`, `scan_info_disclosure`, `scan_auth_bypass`

### Scanner Tools (7) -- deterministic, $0 cost
`scan_csrf`, `scan_error_responses`, `scan_crlf`, `scan_host_header`, `scan_nosqli`, `scan_xxe`, `scan_deserialization`, `scan_dos`, `scan_jwt_deep`

### Attack Tools (22)
`test_sqli` (sqlmap), `test_xss` (dalfox), `test_cmdi` (commix), `test_auth_bypass`, `test_idor`, `test_file_upload`, `send_http_request` (with Goja/CF bypass), `test_jwt`, `test_ssrf`, `test_ssti`, `test_race_condition`, `test_open_redirect`, `test_http_smuggling`, `test_cache_poisoning`, `test_ghost_params`, `test_prototype_pollution`, `test_authz_matrix`, `run_custom_exploit` (Docker sandbox), `waf_fingerprint`, `waf_generate_bypasses`, `analyze_graphql`, `analyze_js_bundle`, `blind_sqli_extract`, `response_diff_analyze`, `systematic_fuzz`, `profile_endpoint_behavior`

### Utility Tools (10)
`update_knowledge`, `update_working_memory`, `read_working_memory`, `formulate_strategy`, `manage_chain` (create/advance/fail/complete/abandon), `finish_test`, `build_app_model`, `plan_subtasks`, `discover_chains`, `deep_research` (Agent C), `solve_captcha`, `browser_interact`

---

## 6. Finding Pipeline: Detection to DB

```
1. DETECTION
   Brain calls attack tool (test_sqli, send_http_request, etc.)
   OR deterministic scanner auto-generates finding
                    |
2. EVIDENCE SCORING (_score_evidence, 0-5 scale)
   5 = definitive (root:x:0:0, OOB callback, etc.)
   4 = confirmed (SQL data dump, XSS fires in DOM)
   3 = strong (2+ signals, raw HTTP artifacts)
   2 = moderate
   1 = weak
   0 = none
   Score < 3: AUTO-REJECTED
                    |
3. EVIDENCE ENRICHMENT (_enrich_findings_with_tool_results)
   Appends raw HTTP data from deps.recent_tool_results
   _extract_http_snippet() pulls status/headers/body
   Enriched section marked with "--- RAW TOOL OUTPUT ---"
                    |
4. HYBRID VALIDATION (3 tiers)
   Score >= 5: auto-pass (definitive proof)
   Tool auto-confirm: _tool_output_confirms_vuln() checks vulnerable:true + payloads
   ALL other findings: Claude Haiku validates (~$0.001/call, bypasses BudgetManager)
                    |
5. TOOL_EXECUTOR_NODE MERGE (finding dedup at merge time)
   a. Canonical vuln_type normalization
   b. Endpoint normalization (strip trailing slash, fragments)
   c. Same (vuln_type, endpoint) = duplicate -> skip
   d. Per-type cap: max 10 per canonical type
   e. Re-verification gate: lightweight HTTP existence check
   f. Auto-differential testing: baseline/payload/control comparison
                    |
6. DB PUSH (findings_db.bulk_upsert)
   PostgreSQL with dedup_hash (MD5 of domain|vuln_type|endpoint|parameter)
   UNIQUE constraint prevents cross-session duplicates
                    |
7. LIVE EVENTS
   Redis publish to "aibbp:findings" channel
   WebSocket broadcast to dashboard
                    |
8. SELF-VALIDATION INJECTION
   Unconfirmed findings trigger re-verification directive to brain:
   "Send exact same request, vary payload, check if generic error page"
```

---

## 7. Hard Phase Gate System

Phases are deterministic (never backwards): `recon` -> `vuln_scan` -> `exploitation` -> `reporting`

### Turn Budgets
| Phase | % of max_turns | Purpose |
|-------|---------------|---------|
| recon | 20% | Crawling, subdomain enum, tech detection, traffic analysis |
| vuln_scan | 15% | Deterministic scanners, nuclei, content discovery |
| exploitation | 50% | Active attack tools, custom exploits, chain exploitation |
| reporting | 15% | Finding validation, report generation, finish |

### Phase Advancement Rules (`_should_advance_phase`)
1. Turn budget for current phase exhausted
2. Budget < 30% remaining
3. 3+ consecutive bookkeeping tool calls (rate limiter)

### Tool Blocking by Phase
- **recon phase:** Attack tools blocked (test_sqli, test_xss, etc.)
- **All phases:** Bookkeeping tools blocked after 3 consecutive (`update_knowledge`, `update_working_memory`, `read_working_memory`, `formulate_strategy`, `manage_chain`, `plan_subtasks`)
- **Early turns:** `finish_test` blocked when > 50% budget remains
- **App gate (real-world mode):** Exploitation tools locked until `build_app_model` called (CTF bypass: budget <= $5 or turns <= 150). `--no-app-gate` CLI flag.

---

## 8. Strategic Intelligence Hooks

| Hook | Where | Trigger | What | Cost |
|------|-------|---------|------|------|
| Hook 0: Recon Blitz | context_compressor | turn >= 3 AND endpoints >= 5, once | 12 parallel $0 scanners + Opus 16K thinking | ~$0.12 |
| Hook 1: Sonnet App Comprehension | context_compressor | endpoints >= 8 OR turn >= 12, once | auth_matrix, business_workflows, high_value_targets, abuse_scenarios | ~$0.05 |
| Hook 2: Sonnet Exploit Strategy | tool_executor_node | tool returns vulnerable:true, max 2 | Exploitation strategy injected as tool result addendum | ~$0.05 each |
| Hook 3: Opus Chain Reasoning | context_compressor | turn >= 30 OR findings >= 3, once | Chain building + hypothesis generation with 8K thinking | ~$0.10 |

All hooks use `_strategic_claude_call()` which bypasses BudgetManager via `raw_client.messages.create()`. JSON parsing uses `_parse_strategic_json()` with markdown code block extraction, json5 fallback, and regex repair for missing commas.

---

## 9. Thompson Sampling & UCB1 Coverage

### Thompson Sampling (Bayesian Bandit)
- State: `bandit_state` dict mapping `"{endpoint}::{technique}"` -> `[alpha, beta]`
- Updated in tool_executor_node: success (finding) increments alpha; failure increments beta
- `_thompson_sample_recommendations()`: Beta distribution sampling weighted by technique impact
- Displays top-5 untested recommendations in dynamic prompt

### UCB1 Coverage Queue (`react_coverage.py`)
- `CoverageQueue`: UCB1 scoring for (endpoint, technique) pairs
- Untested pairs get infinity priority (explore-first)
- Tested pairs scored: exploitation_score + exploration_bonus * endpoint_value * technique_impact
- Endpoint value heuristics: api/auth/admin/pay = 3x, dev/staging = 2x, static = 0.5x
- **Coverage gate:** Blocks deep exploitation on any single endpoint until >= 60% of endpoints have been tested
- 13 core techniques: xss, sqli, ssti, cmdi, ssrf, lfi, xxe, idor, auth_bypass, file_upload, jwt, race_condition, nosqli

---

## 10. Budget System (`budget.py`)

### BudgetManager
- Phase allocation from `BudgetConfig.total_dollars`
- Active testing mode: 95% to `active_testing` phase
- Normal mode: configurable per-phase percentages
- Emergency reserve at 15% triggers forced reporting
- Adaptive reallocation: takes max 30% from phases with < 50% utilization
- Per-target caps via `per_target_max_dollars`
- Cost log capped at 2000 entries

### Rebalance Rules (every 5 turns)
1. Last 5 exploitation turns = 0 info gain -> transfer 30% from exploitation to recon
2. Recon productive at turn 20+ (3+ new endpoints in last 10 turns) -> extend recon by 5%
3. Finding cluster (3+ finding turns in last 10) -> burst +10% exploitation

### Pricing
- Z.ai models: $0
- Haiku: $0.25/$1.25 per MTok
- Sonnet: $3/$15 per MTok
- Opus: $15/$75 per MTok
- Cache read: input_price * cache_read_multiplier

---

## 11. State Definition (`PentestState`)

### Target
`target_url`, `session_id`, `allowed_domains`

### Persistent Knowledge (NEVER compressed, always in system prompt)
- `endpoints`: url -> {method, params, auth_required, notes, status_codes, response_size}
- `findings`: finding_id -> {vuln_type, endpoint, parameter, evidence, severity, confirmed, chained_from, tool_used}
- `hypotheses`: hypothesis_id -> {description, status, evidence, related_endpoints}
- `accounts`: username -> {password, cookies, role, context_name, created_at}
- `tech_stack`: list of detected technologies

### Conversation History (compressed when large)
- `messages`: Annotated[list[dict], _messages_reducer] -- custom reducer: append by default, replace with `{"_replace_all": True}` sentinel
- `compressed_summary`: Haiku-generated summary

### Dedup & Progress Tracking
- `tested_techniques`: dict[str, bool] -- "endpoint::technique" already tested
- `failed_approaches`: dict[str, str] -- "tool::params_hash" -> error message
- `no_progress_count`, `consecutive_failures`, `last_result_hashes`
- `repeat_detector_state`: blocks identical consecutive tool calls

### Control Flow
- `phase` ("running" | "wrapping_up" | "done"), `budget_spent`, `budget_limit`
- `turn_count`, `max_turns` (0 = indefinite), `done`, `done_reason`
- `confidence`: ADaPT score 0.0-1.0

### Hard Phase Gates
- `current_phase`: "recon" | "vuln_scan" | "exploitation" | "reporting"
- `phase_turn_count`, `phase_history`, `consecutive_bookkeeping`

### Intelligence
- `working_memory`: 5+ sections (attack_surface, vuln_findings, credentials, attack_chain, lessons, response_signatures, waf_profiles, chain_evidence, parameter_map)
- `attack_chains`: chain_id -> {goal, steps, current_step, confidence}
- `app_model`: application comprehension (auth_matrix, data_flows, high_value_targets)
- `bandit_state`: Thompson sampling alpha/beta
- `coverage_queue`, `coverage_ratio`
- `traffic_intelligence`

### Strategic Flags
- `recon_blitz_done`, `sonnet_app_model_done`, `sonnet_exploit_calls`, `opus_chain_reasoning_done`
- `last_brain_tier`, `last_opus_turn`
- `reflector_retries`, `subtask_plan`
- `tool_health`: component status from preflight checks

---

## 12. Infrastructure Components

### Goja TLS Proxy (`goja_manager.py`)
- Binary at `/root/Goja/bin/goja-proxy`, port 1081
- Chrome 139 fingerprint: JA3, JA4r, HTTP2 fingerprint, header order
- Chain: httpx -> Goja SOCKS5 (:1081) -> target
- Optional upstream proxy support for chaining

### Docker Sandbox (`docker_executor.py`)
- Image: `kalilinux/kali-rolling` (configurable)
- Memory limit: 2GB, network: host
- File exchange via mounted `/tmp/aibbp_sandbox_{pid}` directory
- `execute()`: bash command with configurable timeout (120s default)
- `execute_python()`: writes to exchange dir, runs via python3

### Proxy Pool (`proxy_pool.py`)
- 60+ sources: proxyscrape, geonode, 5 GitHub repos, more
- `ProxyEntry` dataclass with health tracking and Z.ai session state
- Per-proxy rate limiting (default 3s between calls)
- Cross-process shared cache at `~/.aibbp/proxy_cache/validated_proxies.json`
- Background auto-replacement tasks
- CLI: `--enable-proxylist --proxy-ratelimit 3 --min-proxies 10 --max-proxies 100`

### Scope Guard (`scope_guard.py`)
- Wraps `ScopeEnforcer` with active-testing-specific validation
- Never-test domains: stripe.com, paypal.com, accounts.google.com, auth0.com, etc. (14 domains)
- Destructive method warnings (DELETE, PUT, PATCH)
- Destructive SQL pattern detection (DROP TABLE, TRUNCATE, etc.)
- Browser action validation (JS exfiltration check)
- Tool command URL extraction and validation

### Circuit Breaker (`react_health.py`)
- `FAIL_THRESHOLD = 3`: consecutive failures disable tool
- `RESET_TIMEOUT_SECONDS = 300`: 5-minute cooldown (half-open)
- `filter_tool_schemas()`: removes disabled tools from brain's available tool list
- Preflight checks: SOCKS proxy, mitmproxy, Docker, HexStrike, browser, tool_runner, email

### Transcript Logger (`react_transcript.py`)
- JSONL format at `~/.aibbp/targets/<hash>/transcript_<session>.jsonl`
- Thread-safe with `threading.Lock`, immediate flush
- 15 event methods: brain_response, tool_call, tool_result, state_update, finding, compression, hypothesis, chain_discovery, strategy_reset, error, memory_save, api_response_meta, state_snapshot, full_messages, custom
- Cap sizes: 200KB for tool results/inputs/fields

---

## 13. Knowledge Graph (`neo4j_knowledge_graph.py`)

### Node Types
Target, Endpoint, Finding, Hypothesis, Account, Technology, TestedTechnique, Episode, Parameter

### Relationships
- Target -[HAS_ENDPOINT]-> Endpoint
- Finding -[FOUND_ON]-> Target/Endpoint
- Finding -[EXPLOITS_PARAM]-> Parameter
- Hypothesis -[TARGETS]-> Target
- Account -[TARGETS]-> Target
- Target -[USES_TECH]-> Technology
- Endpoint -[TESTED_BY]-> TestedTechnique
- Episode -[FOLLOWS]-> Episode (temporal chain)

### Graphiti-Inspired Search
- `search_temporal_window()`: last N episodes
- `search_entity_relationships()`: all relationships for entity
- `search_diverse_results()`: balanced across node labels
- `search_episode_context()`: full context for a turn
- `search_successful_tools()`: tools that produced findings
- `search_recent_context()`: most recently modified entities
- `search_entity_by_label()`: filtered search

### Strategic Insights
- `generate_strategic_insights()`: injected into brain's system prompt
  - Untested endpoints
  - Low-coverage endpoints (< 3 techniques)
  - Multi-hop attack paths between findings
  - Successful tools ranking

---

## 14. API Dashboard (`api_server.py`)

**Stack:** FastAPI + uvicorn + GZip middleware + security headers (X-Frame-Options, X-Content-Type-Options, etc.)

### Endpoints
- `POST /api/auth/login`: JWT auth with rate limiting
- `GET /api/findings`: paginated, filterable (domain, severity, vuln_type, confirmed, is_fp), full-text search
- `GET /api/findings/timeline`: daily counts
- `POST /api/findings/{id}/false-positive`: mark FP with reason
- `POST /api/findings/{id}/confirm`: confirm finding
- `POST /api/findings/{id}/revalidate`: background re-validation
- `GET /api/stats`: aggregate statistics
- `GET/POST /api/scans/*`: list, detail, transcript, launch, stop
- `GET /api/proxy/traffic`: paginated proxy traffic with regex URL filter
- `GET /api/agents`: live agent status from Redis heartbeats
- `GET /api/domains`: scanned domains list
- `WS /ws`: WebSocket for live updates (findings, scan progress, revalidation)

### Scan Launch
`NewScanRequest` mirrors all CLI arguments. `_build_scan_cli_args()` converts to subprocess command. Scans run as background processes tracked by `_scan_processes` dict.

---

## 15. Report Generation (`report_generator.py`)

### CWE Mapping
27 vulnerability types mapped (CWE-79 through CWE-1321)

### CVSS 3.1 Scoring
Deterministic based on severity: critical=9.8, high=8.1, medium=5.3, low=3.1, info=0.0

### Formats
- **Markdown**: HackerOne-style with executive summary table, Mermaid attack chain diagrams, per-finding evidence/request/response/remediation
- **HTML**: Styled with severity color badges, responsive table, detail cards
- **JSON**: Enriched with by-severity/by-CWE summary, all fields

### Remediation
22 CWE-specific remediation paragraphs (CWE-79 through CWE-1321)

---

## 16. Chain Discovery & Adversarial Reasoning (`chain_discovery.py`)

### ChainDiscoveryEngine
- 15 chain templates (Info Disclosure -> SSRF -> RCE, XSS -> Account Takeover, SQLi -> Auth Bypass, etc.)
- 18 vuln-type compatibility mappings
- Severity escalation: chained findings always escalate by at least 1 level
- Pairwise evaluation: every new finding checked against all existing
- Template matching: when >= 2 template steps are covered by existing findings
- Co-location detection: different vuln types on same endpoint

### AdversarialReasoningEngine
7 reasoning rules, zero LLM cost:
1. **Error reasoning**: stack traces -> injection hypotheses
2. **Status code reasoning**: 403 = exists but protected -> auth bypass; 500 = input reaches backend
3. **Technology reasoning**: 10 tech-specific attack suggestions (Laravel, Django, Express, Spring, etc.)
4. **Parameter reasoning**: ID params -> IDOR; URL params -> SSRF/redirect; file params -> upload
5. **Auth reasoning**: JWT detection -> algorithm confusion; error message diff -> enumeration
6. **Timing reasoning**: slow response (> 5s) -> blind injection
7. **File exposure reasoning**: source code, credentials, git repos in responses

---

## 17. WAF Bypass Engine (`waf_bypass.py`)

### Fingerprinting
- 60+ keyword probes organized by category: HTML tags (18), event handlers (12), JS keywords (10), SQL keywords (20), command injection (6), SSTI (4), path traversal (3)
- 11 encoding transforms: URL, double URL, HTML entity, unicode escape, mixed case, null byte, tab/newline/plus/comment substitution
- 12 WAF vendor signatures: Cloudflare, Akamai, AWS WAF, ModSecurity, Sucuri, Imperva, F5, Barracuda, FortiWeb, nginx, Wordfence

### Bypass Generation
- **XSS**: allowed tag + allowed event handler combinations, confirm/prompt substitution, encoding bypasses, constructor-based execution, polyglot payloads (30 cap)
- **SQLi**: comment space bypass, tab/newline bypass, operator alternatives (||, &&), case variations, MySQL comment bypass, CHAR function, BETWEEN/IN, nested SLEEP, EXTRACTVALUE/UPDATEXML (30 cap)
- **CMDi**: allowed separator detection, IFS bypass, brace expansion, wildcard bypass, CRLF separator (20 cap)
- **Path Traversal**: 10 encoding variants (overlong UTF-8, fullwidth slash, null byte, etc.) targeting /etc/passwd, /FLAG, /FLAG.txt (20 cap)

---

## 18. Advanced Attack Modules (`advanced_attacks.py`)

| Module | Class | Method |
|--------|-------|--------|
| HTTP Request Smuggling | `HTTPSmugglingTester` | Raw socket CL.TE, TE.CL, TE.TE tests with header obfuscation |
| Cache Poisoning | `CachePoisonTester` | 7 unkeyed headers (X-Forwarded-Host, X-Original-URL, etc.), reflection + cache verification |
| Mass Assignment | `GhostParamDiscovery` | 40 privilege parameters (admin, role, verified, credits, debug, etc.), behavioral diff detection |
| Prototype Pollution | `PrototypePollutionTester` | 8 JSON payloads (__proto__, constructor.prototype), state change verification |
| CORS Exploitation | `CORSExploitTester` | 7 origin tests (evil.com, subdomain, null, HTTP downgrade), credentials check |
| Open Redirect | `OpenRedirectTester` | 28 redirect params x 12 payloads, Location header + meta refresh + JS redirect detection |
| Behavioral Profiling | `BehaviorProfiler` | Statistical baseline (timing, length, headers, cookies), anomaly detection (3x mean / 5 stddev), type confusion testing (30 test values) |

---

## 19. Session Learning (`session_learning.py`)

Redis-backed (port 6382) cross-session persistence:
- `save_bandit_state()` / `load_bandit_state()`: Thompson sampling state per domain (TTL 7 days)
- `save_waf_profile()` / `load_waf_profile()`: WAF fingerprints per domain (TTL 7 days)
- `save_tech_stack()` / `load_tech_stack()`: detected technologies (TTL 7 days)
- `warm_start()`: loads all available cross-session data for a domain
- `set_heartbeat()`: agent status for dashboard (session_id, target, turn, findings)
- Technique priorities from historical findings (TTL 30 days)

---

## 20. Semantic Dedup (`finding_dedup.py`)

- Model: sentence-transformers/all-MiniLM-L6-v2 (384 dimensions)
- Threshold: cosine similarity >= 0.85
- Fallback: exact MD5 hash matching if model unavailable
- `cluster_findings()`: groups similar findings
- Redis persistence for cross-session dedup

---

## 21. Key Constants & Configurations

| Constant | Location | Value | Purpose |
|----------|----------|-------|---------|
| `_PHASE_ORDER` | react_graph.py | ["recon", "vuln_scan", "exploitation", "reporting"] | Hard phase sequence |
| `_BOOKKEEPING_TOOLS` | react_graph.py | 6 tools | Rate-limited meta tools |
| `_EXPLOIT_TOOLS` | react_graph.py | {run_custom_exploit, send_http_request} | Diversity enforcement |
| `_PER_TYPE_CAP` | react_graph.py | 10 | Max findings per vuln type per session |
| `FAIL_THRESHOLD` | react_health.py | 3 | Circuit breaker trip count |
| `RESET_TIMEOUT_SECONDS` | react_health.py | 300 | Circuit breaker cooldown |
| `_HTTP_RATE_LIMIT_SECONDS` | react_tools.py | 1.0 | Global HTTP rate limit |
| `_GOJA_DEFAULT_PORT` | goja_manager.py | 1081 | Goja SOCKS5 proxy port |
| Proxy port | various | 8085 | mitmproxy traffic capture |
| DB DSN | findings_db.py | postgresql://aibbp:aibbp_dev@localhost:5433/aibbp | PostgreSQL |
| Redis | session_learning.py | localhost:6382 | Cross-session state |
| Coverage gate | react_coverage.py | 60% | Min endpoint coverage before deep exploitation |
| Evidence threshold | react_tools.py | score >= 3 | Minimum evidence quality for accepted findings |
| Compression thresholds | react_graph.py | 80K/160K/250K chars | Tier 1/2/2.5/3 boundaries |

---

## 22. Mermaid Flowcharts

### A. Main ReAct Graph Loop

```mermaid
graph TD
    CLI["react_main.py<br/>CLI Entry Point"] --> INIT["Initialize Infrastructure<br/>Browser, Proxy, Email, Docker,<br/>Redis, PostgreSQL, Neo4j"]
    INIT --> WARM["Warm Start<br/>TargetMemory.load()<br/>SessionLearning.warm_start()"]
    WARM --> SCOPE["ActiveScopeGuard<br/>ScopeEnforcer(target, domains)"]
    SCOPE --> BUILD["build_react_graph()<br/>Compile StateGraph"]
    BUILD --> PREFLIGHT["run_preflight_checks()<br/>7 components tested"]
    PREFLIGHT --> INVOKE["graph.ainvoke(initial_state, config)"]

    INVOKE --> BRAIN["🧠 brain_node"]
    BRAIN -->|"has tool_calls"| TOOLS["⚙️ tool_executor_node"]
    BRAIN -->|"done / no action"| END_NODE["🏁 END"]
    TOOLS --> COMPRESS["📦 context_compressor"]
    COMPRESS -->|"not done"| BRAIN
    COMPRESS -->|"done / budget / confidence"| END_NODE

    END_NODE --> CLEANUP["Cleanup<br/>TargetMemory.save()<br/>Findings JSON output<br/>Close connections"]

    style BRAIN fill:#3b82f6,color:#fff
    style TOOLS fill:#14b8a6,color:#fff
    style COMPRESS fill:#6b7280,color:#fff
    style END_NODE fill:#ef4444,color:#fff
    style CLI fill:#8b5cf6,color:#fff
```

### B. brain_node Internal Flow

```mermaid
graph TD
    START["brain_node entry"] --> CHK_SHUT{"Shutdown<br/>flag?"}
    CHK_SHUT -->|yes| DONE_SHUT["done=True<br/>reason=shutdown"]
    CHK_SHUT -->|no| CHK_RSS{"RSS ><br/>max_rss?"}
    CHK_RSS -->|yes| DONE_RSS["done=True<br/>reason=oom"]
    CHK_RSS -->|no| CHK_BUDGET{"Budget<br/>exhausted?"}
    CHK_BUDGET -->|yes| DONE_BUDGET["done=True<br/>reason=budget"]
    CHK_BUDGET -->|no| CHK_TURNS{"Turn limit<br/>reached?"}
    CHK_TURNS -->|yes| DONE_TURNS["done=True<br/>reason=max_turns"]
    CHK_TURNS -->|no| PHASE_GATE["Check Phase Gate<br/>Advance if budget exhausted"]

    PHASE_GATE --> BUILD_PROMPT["Build System Prompt<br/>1. AUTHORIZATION_BLOCK<br/>2. Mode prefix<br/>3. STATIC_PROMPT<br/>4. PHASE_CONTEXT<br/>5. DYNAMIC_STATE<br/>6. Coverage queue<br/>7. Health status<br/>8. Neo4j insights<br/>9. Few-shot (free brain)<br/>10. Strategy checkpoint<br/>11. Tool diversity warning"]

    BUILD_PROMPT --> SELECT_TIER{"Select Brain Tier<br/>_select_brain_tier()"}
    SELECT_TIER -->|"Turn 0 / every 8 / new finding /<br/>stalled 5+ / escalation"| OPUS["Opus"]
    SELECT_TIER -->|"default"| SONNET["Sonnet"]

    OPUS --> FILTER_TOOLS["Filter Tool Schemas<br/>Phase tools ∩ Circuit breaker<br/>Remove blocked bookkeeping"]
    SONNET --> FILTER_TOOLS

    FILTER_TOOLS --> API_CALL["client.messages.create()<br/>system + messages + tools"]
    API_CALL --> HAS_TOOLS{"Response has<br/>tool_use blocks?"}
    HAS_TOOLS -->|yes| STORE["Store pending_tool_calls<br/>→ route to tools"]
    HAS_TOOLS -->|no| REFLECTOR{"Reflector<br/>retry < 3?"}
    REFLECTOR -->|yes| NUDGE["Inject contextual nudge<br/>→ retry API call"]
    NUDGE --> API_CALL
    REFLECTOR -->|no| TEXT_ONLY["Text-only response<br/>→ route to compress"]

    style START fill:#3b82f6,color:#fff
    style OPUS fill:#a855f7,color:#fff
    style SONNET fill:#3b82f6,color:#fff
```

### C. tool_executor_node Internal Flow

```mermaid
graph TD
    ENTRY["tool_executor_node entry"] --> LOOP["For each tool_call"]
    LOOP --> REPEAT{"Repeating<br/>detector?"}
    REPEAT -->|blocked| SKIP["Skip: 'blocked repeated call'"]
    REPEAT -->|ok| DIVERSE{"Diversity<br/>check?"}
    DIVERSE -->|blocked| SKIP2["Skip: 'try different tool'"]
    DIVERSE -->|ok| CB{"Circuit<br/>breaker?"}
    CB -->|disabled| SKIP3["Skip: 'tool disabled'"]
    CB -->|ok| DISPATCH["dispatch_tool()<br/>45-120s timeout"]

    DISPATCH --> PARSE["Parse result<br/>JSON + sanitize"]
    PARSE --> EXTRACT["Extract _state_update<br/>+ _done sentinel"]
    EXTRACT --> COVERAGE["Update coverage queue<br/>mark (endpoint, technique)"]
    COVERAGE --> THOMPSON["Update Thompson sampling<br/>alpha/beta"]
    THOMPSON --> ADVERSARIAL["Adversarial reasoning<br/>7 rules → hypotheses"]

    ADVERSARIAL --> VULN{"Tool returned<br/>vulnerable:true?"}
    VULN -->|yes| HOOK2["Hook 2: Sonnet Exploit Strategy<br/>(max 2 calls)"]
    VULN -->|no| CHAINS

    HOOK2 --> CHAINS["Chain Discovery<br/>15 templates, pairwise eval"]
    CHAINS --> FINDINGS{"New findings<br/>in result?"}
    FINDINGS -->|yes| PIPELINE["Finding Pipeline:<br/>1. Evidence scoring (0-5)<br/>2. Evidence enrichment<br/>3. Hybrid validation<br/>4. Dedup at merge<br/>5. Per-type cap (10)<br/>6. Auto-differential test<br/>7. DB push<br/>8. Redis publish"]
    FINDINGS -->|no| NEXT
    PIPELINE --> NEXT["Next tool_call"]
    NEXT --> LOOP

    LOOP -->|"all done"| STOP_CHECK{"Stopping conditions?<br/>10 no-progress / 5 failures /<br/>3 same results"}
    STOP_CHECK -->|trigger| STRATEGY["Strategy reset<br/>(3 rotation sets)"]
    STOP_CHECK -->|ok| ROUTE_TOOLS["→ route to compress"]
    STRATEGY --> ROUTE_TOOLS

    SKIP --> NEXT
    SKIP2 --> NEXT
    SKIP3 --> NEXT

    style ENTRY fill:#14b8a6,color:#fff
    style DISPATCH fill:#3b82f6,color:#fff
    style PIPELINE fill:#22c55e,color:#fff
    style HOOK2 fill:#a855f7,color:#fff
```

### D. context_compressor Internal Flow

```mermaid
graph TD
    ENTRY["context_compressor entry"] --> PERIODIC["Periodic Operations<br/>• Auto-save TargetMemory (10 turns)<br/>• Neo4j sync<br/>• Budget rebalance (5 turns)<br/>• Session learning save (10 turns)<br/>• Heartbeat (every turn)"]

    PERIODIC --> HOOK0{"Hook 0 trigger?<br/>turn≥3 AND endpoints≥5<br/>(once)"}
    HOOK0 -->|yes| RECON_BLITZ["Recon Blitz<br/>12 parallel $0 scanners<br/>+ Opus 16K thinking"]
    HOOK0 -->|no| HOOK1_CHK
    RECON_BLITZ --> HOOK1_CHK

    HOOK1_CHK{"Hook 1 trigger?<br/>endpoints≥8 OR turn≥12<br/>(once)"}
    HOOK1_CHK -->|yes| SONNET_APP["Sonnet App Comprehension<br/>auth_matrix, workflows,<br/>high_value_targets, abuse_scenarios"]
    HOOK1_CHK -->|no| HOOK3_CHK
    SONNET_APP --> HOOK3_CHK

    HOOK3_CHK{"Hook 3 trigger?<br/>turn≥30 OR findings≥3<br/>(once)"}
    HOOK3_CHK -->|yes| OPUS_CHAIN["Opus Chain Reasoning<br/>8K thinking budget<br/>chains + hypotheses"]
    HOOK3_CHK -->|no| AUTO_EXTRACT
    OPUS_CHAIN --> AUTO_EXTRACT

    AUTO_EXTRACT["Auto-extract to working memory<br/>JWTs, versions, errors, S3,<br/>APIs, creds, status codes,<br/>params, WAF patterns"]

    AUTO_EXTRACT --> MEASURE{"Measure context<br/>size (chars)"}
    MEASURE -->|"< 80K"| TIER1["Tier 1: Keep all"]
    MEASURE -->|"80K-160K"| TIER2["Tier 2: Truncate<br/>tool outputs to 2K chars"]
    MEASURE -->|"160K-250K"| TIER25["Tier 2.5: AST structural<br/>age-based compression"]
    MEASURE -->|"> 250K"| TIER3["Tier 3: Haiku summarize<br/>old messages, keep 10-15 recent"]

    TIER1 --> SANITIZE["_sanitize_tool_pairing()<br/>Ensure tool_use/tool_result<br/>pairs matched"]
    TIER2 --> SANITIZE
    TIER25 --> SANITIZE
    TIER3 --> SANITIZE

    SANITIZE --> ROUTE["→ route to brain<br/>or END"]

    style ENTRY fill:#6b7280,color:#fff
    style RECON_BLITZ fill:#a855f7,color:#fff
    style SONNET_APP fill:#3b82f6,color:#fff
    style OPUS_CHAIN fill:#a855f7,color:#fff
    style TIER3 fill:#eab308,color:#000
```

### E. Finding Pipeline (Detection to DB)

```mermaid
graph TD
    DETECT["Detection<br/>Attack tool or deterministic scanner"] --> SCORE["Evidence Scoring<br/>_score_evidence() 0-5"]
    SCORE -->|"score < 3"| REJECT["❌ AUTO-REJECTED"]
    SCORE -->|"score ≥ 3"| ENRICH["Evidence Enrichment<br/>Append raw HTTP from<br/>deps.recent_tool_results"]

    ENRICH --> VALIDATE{"Hybrid Validation<br/>(3 tiers)"}
    VALIDATE -->|"score ≥ 5"| AUTO_PASS["✅ Auto-pass<br/>(definitive proof)"]
    VALIDATE -->|"tool confirms"| TOOL_PASS["✅ Tool auto-confirm<br/>vulnerable:true + payloads"]
    VALIDATE -->|"all other"| HAIKU["Claude Haiku validates<br/>~$0.001/call<br/>bypasses BudgetManager"]

    HAIKU -->|"rejected"| REJECT2["❌ Haiku rejected"]
    HAIKU -->|"confirmed"| MERGE

    AUTO_PASS --> MERGE["Merge Pipeline"]
    TOOL_PASS --> MERGE

    MERGE --> CANON["Canonical vuln_type<br/>normalization"]
    CANON --> ENDPOINT_NORM["Endpoint normalization<br/>strip trailing /, fragments"]
    ENDPOINT_NORM --> DEDUP{"Same (vuln_type,<br/>endpoint)?"}
    DEDUP -->|"duplicate"| SKIP["⏭ Skip"]
    DEDUP -->|"unique"| CAP{"Per-type cap<br/>(max 10)?"}
    CAP -->|"exceeded"| SKIP
    CAP -->|"ok"| REVERIFY["Re-verification gate<br/>HTTP existence check"]
    REVERIFY --> DIFF["Auto-differential test<br/>baseline vs payload vs control"]
    DIFF -->|"matches baseline"| REJECT3["❌ False positive"]
    DIFF -->|"differs"| DB["📊 DB Push<br/>findings_db.bulk_upsert()<br/>dedup_hash UNIQUE"]
    DB --> REDIS["📡 Redis publish<br/>aibbp:findings channel"]
    REDIS --> WS["🔌 WebSocket broadcast<br/>Live dashboard update"]
    WS --> SELF_VAL["Self-validation injection<br/>Directive to brain:<br/>'Re-verify with varied payload'"]

    style DETECT fill:#14b8a6,color:#fff
    style REJECT fill:#ef4444,color:#fff
    style REJECT2 fill:#ef4444,color:#fff
    style REJECT3 fill:#ef4444,color:#fff
    style DB fill:#22c55e,color:#fff
    style HAIKU fill:#eab308,color:#000
```

### F. Phase Gate System

```mermaid
graph LR
    RECON["🔍 Recon<br/>20% turns<br/>Crawl, enum, tech detect"] -->|"budget exhausted<br/>OR turns used"| VULN_SCAN["🔎 Vuln Scan<br/>15% turns<br/>Deterministic scanners"]
    VULN_SCAN -->|"budget exhausted<br/>OR turns used"| EXPLOIT["⚔️ Exploitation<br/>50% turns<br/>Active attacks, chains"]
    EXPLOIT -->|"budget exhausted<br/>OR turns used"| REPORT["📝 Reporting<br/>15% turns<br/>Validate, report, finish"]

    subgraph "Tool Blocking Rules"
        R1["Recon: attack tools blocked"]
        R2["All: bookkeeping blocked after 3 consecutive"]
        R3["Early: finish_test blocked when >50% budget"]
        R4["Real-world: exploit locked until build_app_model"]
    end

    style RECON fill:#06b6d4,color:#fff
    style VULN_SCAN fill:#3b82f6,color:#fff
    style EXPLOIT fill:#ef4444,color:#fff
    style REPORT fill:#22c55e,color:#fff
```

### G. Infrastructure & Data Flow

```mermaid
graph TB
    subgraph "Brain Backends"
        CLAUDE["Claude API<br/>Opus / Sonnet / Haiku<br/>(OAuth, paid)"]
        ZAI["Z.ai GLM-5<br/>HMAC-SHA256 auth<br/>(free)"]
        GPT["ChatGPT<br/>Turnstile VM pipeline<br/>(free, anonymous)"]
    end

    subgraph "Core Engine"
        BRAIN["🧠 brain_node"]
        TOOLS["⚙️ tool_executor_node"]
        COMPRESS["📦 context_compressor"]
    end

    subgraph "Tool Backends"
        BROWSER["Playwright<br/>Browser"]
        DOCKER["Docker<br/>Kali Sandbox"]
        DETERM["Deterministic<br/>Scanners (16+)"]
        HTTP["httpx<br/>HTTP Client"]
        SQLMAP["sqlmap"]
        DALFOX["dalfox"]
        NUCLEI["nuclei"]
        ADV["Advanced Attacks<br/>7 modules"]
        WAF["WAF Bypass<br/>Engine"]
    end

    subgraph "Infrastructure"
        GOJA["Goja TLS Proxy<br/>:1081<br/>Chrome 139 JA3"]
        MITM["mitmproxy<br/>:8085<br/>Traffic Capture"]
        PROXY["Proxy Pool<br/>60+ sources<br/>SOCKS/HTTP"]
    end

    subgraph "Persistence"
        PG["PostgreSQL :5433<br/>findings, scans,<br/>proxy_traffic"]
        REDIS["Redis :6382<br/>sessions, bandit,<br/>WAF, heartbeat"]
        NEO4J["Neo4j<br/>Knowledge Graph"]
        FS["Filesystem<br/>~/.aibbp/targets/<br/>transcripts, memory"]
    end

    subgraph "Output"
        API["FastAPI Dashboard<br/>:8080<br/>JWT + WebSocket"]
        REPORTS["Reports<br/>MD / HTML / JSON"]
        JSON_OUT["Findings JSON<br/>--output flag"]
    end

    CLAUDE --> BRAIN
    ZAI --> BRAIN
    GPT --> BRAIN

    BRAIN --> TOOLS
    TOOLS --> COMPRESS
    COMPRESS --> BRAIN

    TOOLS --> BROWSER
    TOOLS --> DOCKER
    TOOLS --> DETERM
    TOOLS --> HTTP
    TOOLS --> SQLMAP
    TOOLS --> DALFOX
    TOOLS --> NUCLEI
    TOOLS --> ADV
    TOOLS --> WAF

    HTTP --> GOJA
    BROWSER --> MITM
    ZAI --> PROXY

    TOOLS --> PG
    TOOLS --> REDIS
    COMPRESS --> NEO4J
    COMPRESS --> FS
    COMPRESS --> REDIS

    PG --> API
    REDIS --> API
    PG --> REPORTS
    PG --> JSON_OUT

    style BRAIN fill:#3b82f6,color:#fff
    style TOOLS fill:#14b8a6,color:#fff
    style COMPRESS fill:#6b7280,color:#fff
    style PG fill:#22c55e,color:#fff
    style REDIS fill:#ef4444,color:#fff
```

### H. Compression Tiers

```mermaid
graph TD
    MEASURE["Measure context_size<br/>(total chars in messages)"] --> T1{"< 80K?"}
    T1 -->|yes| TIER1["✅ Tier 1: Keep All<br/>No compression<br/>Cost: $0"]
    T1 -->|no| T2{"< 160K?"}
    T2 -->|yes| TIER2["📏 Tier 2: Truncate<br/>Tool outputs → 2K chars<br/>Cost: $0"]
    T2 -->|no| T25{"< 250K?"}
    T25 -->|yes| TIER25["🏗️ Tier 2.5: AST Structural<br/>Oldest → 1-line summary<br/>Middle → 500 chars<br/>Recent → untouched<br/>Cost: $0"]
    T25 -->|no| TIER3["🤖 Tier 3: Haiku Summarize<br/>Old messages → summary<br/>Keep 10-15 recent<br/>Cost: ~$0.001"]

    TIER1 --> SANITIZE["_sanitize_tool_pairing()<br/>Match tool_use ↔ tool_result<br/>Remove orphans"]
    TIER2 --> SANITIZE
    TIER25 --> SANITIZE
    TIER3 --> SANITIZE

    style TIER1 fill:#22c55e,color:#fff
    style TIER2 fill:#06b6d4,color:#fff
    style TIER25 fill:#eab308,color:#000
    style TIER3 fill:#ef4444,color:#fff
```

### I. Strategic Intelligence Hooks Timeline

```mermaid
gantt
    title Strategic Hook Firing Timeline
    dateFormat X
    axisFormat Turn %s

    section Hooks
    Hook 0 Recon Blitz (12 scanners + Opus 16K)     :milestone, h0, 3, 0
    Hook 1 Sonnet App Comprehension                   :milestone, h1, 12, 0
    Hook 2 Sonnet Exploit Strategy (on vuln:true)     :crit, h2a, 15, 40
    Hook 2 second call (max 2)                        :crit, h2b, 25, 40
    Hook 3 Opus Chain Reasoning (8K thinking)         :milestone, h3, 30, 0

    section Phases
    Recon (20%)           :active, recon, 0, 12
    Vuln Scan (15%)       :vuln, 12, 21
    Exploitation (50%)    :crit, exploit, 21, 51
    Reporting (15%)       :done, report, 51, 60
```

### J. Multi-Model Cost Routing

```mermaid
graph TD
    TASK["Incoming Task"] --> DECISION{"Task Type?"}

    DECISION -->|"Turn 0 / strategy /<br/>every 8th / stalled"| OPUS["Claude Opus<br/>$15/$75 per MTok<br/>Deep reasoning"]
    DECISION -->|"Default turn"| SONNET["Claude Sonnet<br/>$3/$15 per MTok<br/>Standard execution"]
    DECISION -->|"Compression"| HAIKU["Claude Haiku<br/>$0.25/$1.25 per MTok<br/>Summarization"]
    DECISION -->|"Finding validation"| HAIKU
    DECISION -->|"Free brain mode"| FREE{"Free Backend"}

    FREE -->|"--zai"| GLM["Z.ai GLM-5<br/>$0 / unlimited<br/>HMAC-SHA256 auth"]
    FREE -->|"--chatgpt"| CHATGPT["ChatGPT GPT-5.3<br/>$0 / anonymous<br/>Turnstile VM"]

    subgraph "Strategic Hooks (bypass BudgetManager)"
        HOOK0["Hook 0: Opus 16K thinking"]
        HOOK1["Hook 1: Sonnet comprehension"]
        HOOK2["Hook 2: Sonnet exploit strategy"]
        HOOK3["Hook 3: Opus 8K chain reasoning"]
        HAIKU_VAL["Haiku finding validation"]
    end

    style OPUS fill:#a855f7,color:#fff
    style SONNET fill:#3b82f6,color:#fff
    style HAIKU fill:#22c55e,color:#fff
    style GLM fill:#eab308,color:#000
    style CHATGPT fill:#14b8a6,color:#fff
```

### K. End-to-End Scan Lifecycle

```mermaid
sequenceDiagram
    participant CLI as react_main.py
    participant Graph as LangGraph
    participant Brain as brain_node
    participant Tools as tool_executor_node
    participant Compress as context_compressor
    participant DB as PostgreSQL
    participant Redis as Redis
    participant WS as WebSocket/Dashboard

    CLI->>CLI: Parse args, init infrastructure
    CLI->>CLI: Warm start (TargetMemory, SessionLearning)
    CLI->>CLI: run_preflight_checks()
    CLI->>Graph: ainvoke(initial_state, config)

    loop ReAct Loop (up to max_turns)
        Graph->>Brain: Execute brain_node
        Brain->>Brain: Check shutdown/RSS/budget/turns
        Brain->>Brain: Phase gate check
        Brain->>Brain: Build system prompt (10 sections)
        Brain->>Brain: Select tier (Opus/Sonnet)
        Brain->>Brain: Filter tools (phase + circuit breaker)
        Brain-->>Graph: tool_calls or done

        Graph->>Tools: Execute tool_executor_node
        loop For each tool_call
            Tools->>Tools: Repeat/diversity/CB checks
            Tools->>Tools: dispatch_tool() with timeout
            Tools->>Tools: Update coverage + Thompson sampling
            Tools->>Tools: Adversarial reasoning (7 rules)
            opt vulnerable:true detected
                Tools->>Tools: Hook 2: Sonnet exploit strategy
            end
            opt New findings
                Tools->>Tools: Evidence score + enrich + validate
                Tools->>DB: bulk_upsert() findings
                Tools->>Redis: publish aibbp:findings
                Redis-->>WS: Broadcast to dashboard
            end
        end
        Tools-->>Graph: tool results + state updates

        Graph->>Compress: Execute context_compressor
        Compress->>Compress: Periodic ops (save, sync, rebalance)
        opt Hook 0 trigger (turn≥3, endpoints≥5)
            Compress->>Compress: 12 scanners + Opus 16K
        end
        opt Hook 1 trigger (endpoints≥8 OR turn≥12)
            Compress->>Compress: Sonnet app comprehension
        end
        opt Hook 3 trigger (turn≥30 OR findings≥3)
            Compress->>Compress: Opus chain reasoning
        end
        Compress->>Compress: Auto-extract to working memory
        Compress->>Compress: Compression (Tier 1-3)
        Compress->>Compress: _sanitize_tool_pairing()
        Compress-->>Graph: compressed state
    end

    Graph-->>CLI: Final state
    CLI->>CLI: TargetMemory.save()
    CLI->>CLI: Write findings JSON
    CLI->>CLI: Cleanup (Goja, Docker, Browser, DB)
```
