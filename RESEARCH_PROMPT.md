# Deep Research Prompt: Transform AIBBP from CTF-Solver to Real-World Bug Finder

## Context for the Researcher

I have an autonomous penetration testing agent (AIBBP ReAct Agent) that achieves **95.6% on the XBOW CTF benchmark** (43/45 Level 1 challenges) but only **0.9% real finding rate** on production bug bounty targets (12 confirmed real out of 1530+ findings across 41 Bugcrowd targets like Tesla, Crypto.com, Robinhood, Okta, Pinterest). The agent excels at structured challenges with clear flags but fails at discovering genuine vulnerabilities in complex, production web applications.

I need you to deeply research every dimension of this problem — prompts, models, tools, flow, mechanisms, attack methodology — and provide **specific, implementable proposals** to close the gap between CTF performance and real-world bug-finding accuracy.

---

## 1. COMPLETE ARCHITECTURE (Read This Carefully)

### Stack
- **Language**: Python 3.12
- **Orchestration**: LangGraph state machine (3-node infinite loop)
- **AI Models**: Claude Sonnet 4.6 (main brain, $0.003/$0.015 per 1K tokens), Haiku 4.5 (compression), Opus 4.6 (strategic review every 8 turns + chain reasoning when findings exist), Z.ai GLM-5 (free alternative brain via chat.z.ai)
- **API**: Anthropic native tool-use API — NOT structured output, direct tool calling
- **Browser**: Playwright (headless Chromium) via BrowserController
- **Proxy**: mitmproxy v12 for traffic capture (port 8085)
- **External Tools**: sqlmap, dalfox, commix, nuclei, ffuf, gobuster, subfinder, dig, curl, httpx

### Graph Flow

```
bootstrap_message → brain_node → tool_executor_node → context_compressor → brain_node → ...
                                                                              ↓
                                                                          (every 8 turns)
                                                                     Opus strategic review
```

1. **brain_node**: Builds ~10-15K token system prompt from state, sends full conversation to Claude with 49 tool schemas, gets back tool_use blocks
2. **tool_executor_node**: Dispatches tool calls to backends, tracks dedup/failures, merges state updates, enforces anti-fabrication (tool provenance, evidence quality)
3. **context_compressor**: Tier 1 (<50K chars) keep all, Tier 2 (50-100K) truncate tool outputs to 2000 chars, Tier 3 (>100K) Haiku summarization

### 49 Tool Schemas (Current)

**Recon (9):** navigate_and_extract, crawl_target, run_nuclei_scan, run_content_discovery, detect_technologies, detect_waf, analyze_traffic, enumerate_subdomains, resolve_domains

**Attack (27):** test_sqli, test_xss, test_cmdi, test_auth_bypass, test_idor, test_file_upload, send_http_request, test_jwt, run_custom_exploit, test_ssrf, test_ssti, test_race_condition, analyze_graphql, analyze_js_bundle, test_authz_matrix, waf_fingerprint, test_http_smuggling, test_cache_poisoning, test_mass_assignment, test_prototype_pollution, test_cors_misconfig, test_open_redirect, behavioral_profiling, systematic_fuzz, response_diff_analyze, blind_sqli_extract, run_content_discovery

**Utility (13):** browser_interact, register_account, login_account, update_knowledge, get_proxy_traffic, formulate_strategy, get_playbook, finish_test, manage_session, get_target_memory, check_budget, get_full_state, get_endpoints

### Anti-Fabrication System
- Every finding must have tool_provenance (which tool produced the evidence)
- Evidence quality scoring (response content, status codes, timing data)
- Endpoint re-verification before accepting findings
- Per-vuln-type cap of 3 findings (prevents spam)
- Canonical dedup: vuln_type + normalized endpoint + param hash

### Key $0 Deterministic Tools (No LLM Cost)
- **SecretScanner**: 23 regex patterns (AWS keys, GitHub tokens, JWTs, internal URLs, etc.) — runs on JS bundles
- **SSRFTester**: 18 payloads (localhost variants, cloud metadata, protocol schemes)
- **SSTITester**: 11 polyglot probes, engine fingerprinting, auto-RCE escalation
- **RaceConditionTester**: N concurrent identical requests via asyncio+httpx
- **GraphQLAnalyzer**: Introspection, mutation enumeration, anonymous access testing
- **AuthorizationMatrixTester**: Every endpoint × every role, access gap detection
- **BlindSQLiExtractor**: Binary search character extraction
- **ResponseDiffAnalyzer**: Differential analysis between baseline and modified requests
- **SystematicFuzzer**: Wordlist-based path/parameter fuzzing
- **WafBypassEngine**: WAF fingerprinting + adaptive payload generation

### Auto-Mechanisms (Zero-Turn Cost)
- **Auto-WAF-fingerprint**: Before any attack tool (sqli, xss, cmdi, ssti, ssrf), auto-runs waf_fingerprint if no profile exists for domain
- **Auto-auth-check**: On navigate_and_extract, fires anonymous httpx GET and tags endpoint with auth_required
- **Auto-JS-bundle scanning**: During crawl_target BFS, scans discovered .js files with SecretScanner

### System Prompt Structure (~10-15K tokens)
1. Persona: "Elite pentester, methodical, evidence-driven"
2. Anti-fabrication rules (strict evidence requirements)
3. Methodology: RECON → HYPOTHESIZE → TEST → CHAIN → VALIDATE → REPORT
4. Tool priority hierarchy ($0 deterministic first, then specialized, then generic)
5. Phase-specific tool filtering (recon/auth/exploitation/post_exploit)
6. Decision trees for 12 vulnerability classes
7. Live state injection: all endpoints, findings, hypotheses, accounts, tech_stack, traffic_intelligence
8. Situational hints: app-type detection (e-commerce/SaaS/API/social), tunnel vision detection, JS bundle hints
9. Post-auth mandatory checklist (10 items)
10. Knowledge graph insights: untested endpoints, attack paths, tech-specific suggestions
11. Playbook: 7-step payload mutation fallback chain

### Model Routing
- **Sonnet**: Default brain (every turn)
- **Opus**: Strategic review (every 8 turns) + chain reasoning (when findings exist)
- **Haiku**: Context compression only
- **Z.ai GLM-5**: Free alternative brain (for $0 budget runs via proxy pool)
- **Extended thinking**: NOT enabled (single-pass reasoning only)

---

## 2. THE CORE PROBLEM: CTF vs Real-World Gap

### Why 95.6% CTF but 0.9% Real-World?

CTF challenges have:
- A single, intentional vulnerability to find
- Clear attack surface (usually 1-3 endpoints)
- No WAF, no rate limiting, no real business logic
- A "flag" file that proves exploitation (grep-friendly)
- Exploitable in 5-15 turns, $0.15-$2.00

Real-world targets have:
- Unknown if ANY vulnerability exists in your testing scope
- Hundreds of endpoints, most doing nothing interesting
- WAFs, rate limiters, CAPTCHAs, bot detection
- Complex business logic that requires deep understanding
- No "flag" — you must understand what constitutes a real vulnerability vs. intended behavior
- Require 50-200+ turns of patient exploration
- Most endpoints are NOT vulnerable

### What the Agent Gets Wrong on Real Targets

1. **Generates phantom vulnerabilities**: Reports XSS/SQLi/SSRF that don't actually exist — the tool returned ambiguous results and the agent interpreted noise as signal
2. **Tests surface-level only**: Tries `' OR 1=1--` on login forms, `<script>alert(1)</script>` on search fields, then declares the target secure. Never goes deeper.
3. **Doesn't understand the application**: Jumps to injection testing without understanding what the app does, what its valuable assets are, what its trust boundaries are
4. **No hypothesis quality**: "Maybe there's SQLi on /search" is not a real hypothesis. A real hypothesis: "The /api/v2/users endpoint accepts a `sort` parameter that's reflected in the response ordering — this suggests server-side sorting that may not be parameterized"
5. **Ignores business logic entirely**: Race conditions, payment manipulation, coupon abuse, workflow bypass, mass assignment — the highest-bounty categories are barely attempted
6. **Shallow auth exploitation**: Creates an account, logs in, then does the same surface-level injection testing on authenticated endpoints
7. **No creativity or novelty**: Every target gets the same generic testing playbook. No adaptation to the specific application's architecture, tech stack, or business domain
8. **Tunnel vision**: Spends 100+ turns on the same 3 endpoints instead of broadening the attack surface
9. **Missing info disclosure findings**: Doesn't systematically check for exposed .git, .env, debug pages, stack traces, verbose errors, internal IPs in headers, source maps
10. **No chaining**: Even when multiple low-severity issues are found, never attempts to chain them into higher-impact vulnerabilities

---

## 3. RESEARCH AXES — Investigate Each Thoroughly

### AXIS 1: PROMPT ENGINEERING & METHODOLOGY

**Current state**: The system prompt is ~10-15K tokens with methodology, decision trees, tool schemas, and state injection. The agent follows RECON → HYPOTHESIZE → TEST → CHAIN → VALIDATE → REPORT but in practice does shallow recon then jumps to generic injection testing.

**Research questions**:

1. **Hypothesis Quality**: How should the prompt teach the agent to form GOOD hypotheses? Real bug bounty hunters observe behavioral anomalies before testing. They notice: "this endpoint returns 200 for invalid input instead of 400", "this API response includes fields not shown in the UI", "this parameter name suggests it accepts a URL", "the error message reveals the backend framework". How do we encode this observational skill?

2. **Application Understanding**: Before any testing, the agent should deeply understand: What does this app DO? What are its most valuable assets? What trust boundaries exist? What's the authorization model? Current prompt mentions this but it's not enforced. How do we make app understanding a PREREQUISITE for exploitation?

3. **Decision Quality**: The agent makes hundreds of micro-decisions (which endpoint to test, which payload to try, when to pivot). How do top CTF/bug-bounty agents make these decisions? Is there research on LLM decision-making in adversarial/exploration settings?

4. **Prompt Architecture**: Is 10-15K tokens optimal? Should state be injected differently? Should tool schemas be dynamic (show only relevant tools per phase)? Should the system prompt be restructured (e.g., few-shot examples of good vs bad testing sessions)?

5. **Real Attack Patterns**: What are the TOP 20 most-paid vulnerability patterns on HackerOne/Bugcrowd in 2024-2025? For each, what's the detection methodology that an automated agent could follow? Categories to research:
   - Business logic flaws (price manipulation, race conditions, coupon abuse, workflow bypass)
   - Authorization gaps (IDOR, BFLA, tenant isolation, mass assignment)
   - API-specific (GraphQL mutations, REST mass assignment, API versioning bypass)
   - Second-order attacks (stored XSS triggered in admin, CSV injection, PDF SSRF)
   - OAuth/SSO attacks (redirect_uri bypass, state CSRF, token leakage)
   - Configuration chains (.git → source → secrets, actuator → data, metadata SSRF → keys)
   - Information disclosure (JS bundles, source maps, debug endpoints, verbose errors, internal headers)

6. **Bug Bounty Hunter Methodology**: Study the methodology of top hunters (@streaak, @nagli, @samwcyo, @lupin, @rez0__, @0xacb, @jhaddix). What's their recon-to-exploitation pipeline? How do they decide what to test? How do they recognize anomalies? What percentage of their time is recon vs exploitation?

### AXIS 2: MODEL CAPABILITIES & REASONING

**Current state**: Sonnet for all brain turns, Opus for strategic reviews (every 8 turns) and chain reasoning. No extended thinking. Single-pass reasoning only.

**Research questions**:

1. **Extended Thinking**: Claude supports extended thinking (budget_tokens parameter). Would enabling this for exploitation decisions improve accuracy? What's the cost-accuracy tradeoff? Should it be selective (only when stuck or for complex decisions)?

2. **Model Routing**: Is Sonnet sufficient for exploitation reasoning? When should Opus be used? Should the agent escalate to Opus when: (a) multiple failed attempts, (b) complex chaining needed, (c) ambiguous results requiring deeper analysis?

3. **Reasoning Depth**: For hard problems (blind SQLi extraction, filter bypass, multi-step chains), is single-pass reasoning fundamentally insufficient? Would chain-of-thought prompting, self-reflection, or tree-of-thought help?

4. **Multi-Agent vs Single-Agent**: The current design is a single brain with 49 tools. Would specialized sub-agents perform better? E.g., a "recon agent" that hands off to an "exploitation agent" that hands off to a "validation agent"? What does the research say about multi-agent pentesting?

5. **Self-Critique**: Should the agent critique its own findings before reporting? ("I think this is XSS — but let me verify: is the reflection actually in an executable context? Is this a false positive from encoding?")

### AXIS 3: TOOLS & CAPABILITIES

**Current state**: 49 tools (9 recon + 27 attack + 13 utility). Many are $0 deterministic (no LLM cost). The agent has browser, HTTP, and subprocess capabilities.

**Research questions**:

1. **Tool Quality vs Quantity**: We went from 26 to 49 tools. Is this too many? Does having 49 schemas overwhelm the model? Should tools be contextually filtered (only show recon tools during recon phase)?

2. **Missing Capabilities**: What attack capabilities are still missing? Research what tools commercial pentest platforms use (Burp Suite Pro, Caido, Nuclei, etc.) and identify gaps. Specific areas to investigate:
   - Subdomain takeover testing
   - CORS exploitation (beyond misconfiguration detection)
   - WebSocket testing
   - HTTP/2 specific attacks (request smuggling via H2)
   - DNS rebinding
   - Deserialization attacks (Java, PHP, Python pickle)
   - NoSQL injection (MongoDB, Redis)
   - Template injection in email templates
   - Server-side prototype pollution (Node.js)

3. **Browser vs HTTP**: When should the agent use the browser (Playwright) vs direct HTTP (httpx)? Currently this is left to the brain's judgment. Should there be guidance or auto-selection?

4. **Traffic Analysis**: mitmproxy captures all traffic but the `analyze_traffic` tool is basic. What advanced traffic analysis could find vulnerabilities? (Response timing anomalies, header inconsistencies, session fixation patterns, CORS misconfigurations in preflight responses)

5. **Wordlist Strategy**: The agent uses standard wordlists (common-dirs, common-files). Should there be application-specific wordlists? How do top hunters build custom wordlists from JS bundles, API docs, and response content?

### AXIS 4: FLOW & ARCHITECTURE

**Current state**: 3-node infinite loop with context compression. Bootstrap message provides a mandatory 8-step recon checklist. Opus strategic review every 8 turns. Strategy resets after 3 consecutive failure cycles.

**Research questions**:

1. **Exploration vs Exploitation Balance**: The agent either over-explores (200 turns of recon, no exploitation) or under-explores (5 turns of recon, jumps to testing the first endpoint). How do reinforcement learning agents balance explore/exploit? Can we apply multi-armed bandit or Thompson sampling to endpoint/technique selection?

2. **State Management**: Is the current state (endpoints, findings, hypotheses, accounts, tech_stack, traffic_intelligence) sufficient? What additional state would help? Should there be:
   - An "attack surface score" per endpoint (how promising it looks)?
   - A "confidence" per hypothesis (Bayesian updating based on test results)?
   - A "coverage matrix" (which endpoints × which techniques have been tested)?
   - An "anomaly log" (unexpected behaviors observed during testing)?

3. **Feedback Loops**: Currently, tool results go back to the brain as conversation messages. Should there be structured feedback? E.g., after every tool call, auto-analyze: "Was this result interesting? Did it reveal new information? Should we follow up?"

4. **Session Strategy**: For real targets, should the agent run multiple focused sessions (e.g., "Session 1: recon + info disclosure", "Session 2: auth testing", "Session 3: injection testing") rather than one long session?

5. **Adaptive Budget Allocation**: Should the agent plan upfront: "I have $10 budget. I'll spend $2 on recon, $5 on exploitation, $2 on validation, $1 reserve"? Should allocation adapt based on findings quality?

6. **Graph Architecture**: Should the LangGraph be more complex? E.g., separate subgraphs for recon/exploitation/validation? Decision nodes that route to specialized testing paths?

### AXIS 5: MECHANISMS & AUTOMATION

**Current state**: Auto-WAF-fingerprint, auto-auth-check, auto-JS-bundle scanning. Anti-fabrication with tool provenance and evidence quality scoring.

**Research questions**:

1. **Adaptive Testing**: Should the agent adapt its testing strategy based on early results? E.g., if first 3 injection tests all fail cleanly (no errors, no WAF blocks), should it pivot to business logic testing? If WAF blocks everything, should it focus on logic bugs and info disclosure?

2. **Anomaly Detection**: Should there be an automatic anomaly detector that watches all responses and flags: unusual status codes, response time variations, inconsistent headers, different response sizes for similar requests, error messages that reveal internals?

3. **Continuous Learning**: The target_memory system persists across sessions. How can past sessions inform future runs? Should the agent build a "target profile" that improves over repeated scans?

4. **Validation Pipeline**: Currently, findings are validated via anti-fabrication checks. Should there be a separate validation agent that independently verifies each finding before reporting?

5. **Rate Limit Management**: Real targets have rate limits. Should the agent detect rate limiting (429 responses, response time increases) and automatically slow down or switch techniques?

6. **Finding Chains**: The chain_discovery module has 15 templates but relies on existing findings. Should chaining be attempted more aggressively? Should the agent actively look for chain components?

### AXIS 6: REAL-WORLD ATTACK PATTERNS

This is the most critical axis. The agent needs to learn patterns from REAL paid bounty reports.

**Research deeply**:

1. **Top 20 Most-Paid Bug Categories (2024-2025)**: For each category, provide:
   - What to look for (indicators/signals)
   - How to test (specific requests/payloads)
   - Common false positive pitfalls
   - Estimated detection complexity for an automated agent

2. **Framework-Specific Patterns**: For each major framework, what are the TOP 5 exploitable patterns?
   - Node.js/Express/Next.js (prototype pollution, SSRF in SSR, NoSQL injection, JWT misconfig)
   - Python/Django/Flask (SSTI, debug mode, ORM injection, pickle deserialization)
   - PHP/Laravel (mass assignment, debug bar, artisan exposure, PHP object injection)
   - Ruby on Rails (mass assignment, CSRF token bypass, ERB injection, ActiveRecord SQLi)
   - Java/Spring Boot (actuator exposure, SpEL injection, deserialization, JNDI)
   - Go/Gin/Echo (template injection, SSRF in microservices, auth bypass)
   - GraphQL (introspection, batching attacks, nested query DoS, mutation authorization)

3. **Authenticated Testing Methodology**: Provide a complete, step-by-step methodology for testing AFTER authentication:
   - How to systematically find IDOR (not just increment IDs — study UUID patterns, encoded IDs, GraphQL node IDs)
   - How to test authorization matrix efficiently
   - How to find mass assignment vulnerabilities
   - How to discover admin-only functionality accessible to regular users
   - How to find data leakage in API responses

4. **Information Disclosure Patterns**: The highest ROI for automated agents. Provide exhaustive list of:
   - Files/paths to check (.git/HEAD, .env, .DS_Store, backup files, config files, swagger.json, etc.)
   - Headers that leak info (X-Powered-By, Server, X-Debug-Token, etc.)
   - Error page patterns that reveal framework/version
   - JS bundle analysis patterns (API keys, internal URLs, GraphQL operations)
   - Source map indicators
   - Debug/admin endpoints by framework

5. **Produce 15 Detailed Technique Cards**: For each card, include:
```
{
  "pattern_name": "...",
  "category": "business_logic|authorization|injection|info_disclosure|config|chain",
  "frequency_in_bounties": "common|uncommon|rare",
  "avg_bounty": "$X-$Y",
  "requires_auth": true|false,
  "applicable_to": ["tech_stack_1", "tech_stack_2"],
  "indicators": ["What signals suggest this bug might exist"],
  "detection_steps": [
    "Step 1: ...",
    "Step 2: ...",
    "..."
  ],
  "example_request": "Full HTTP request",
  "success_indicators": ["What confirms the bug"],
  "false_positive_indicators": ["What looks like a bug but isn't"],
  "tool_to_use": "which of our 49 tools to use",
  "automation_feasibility": "easy|medium|hard",
  "notes": "Any special considerations"
}
```

### AXIS 7: COMPETITIVE ANALYSIS

**Research these systems**:

1. **XBOW** (87.5% baseline on their own benchmark): What is their architecture? What techniques do they use that we don't?
2. **Burp Suite Pro Scanner**: What does commercial automated scanning look like? What do they check that we don't?
3. **Nuclei Templates**: There are 7000+ community templates. How could we leverage these better?
4. **HackerOne Copilot / Bugcrowd's VRT**: How do platforms classify and prioritize vulnerabilities?
5. **Academic Research**: Any papers on LLM-based penetration testing, CTF solving, or vulnerability discovery? (2023-2025)
6. **PentestGPT, AutoPentest-GPT, ReaperAI**: What do other LLM pentesting agents do differently?

---

## 4. DELIVERABLES

### Deliverable 1: What-to-Change Matrix

For each dimension (prompts, model, tools, flow, mechanisms), answer:
- **Should we change it?** (YES/NO with evidence)
- **What specifically to change?** (concrete proposals)
- **Expected impact on real-world finding rate?** (quantified estimate)
- **Implementation effort?** (hours/days/weeks)
- **Risk of regression on XBOW benchmark?**

### Deliverable 2: Top 20 Technique Cards

The 20 most impactful real-world attack patterns our agent should learn, formatted as structured technique cards (see AXIS 6 format above). Prioritize by: bounty frequency × automation feasibility × impact.

### Deliverable 3: Recommended Prompt Rewrite

If prompt changes are recommended, provide the EXACT new prompt sections (not just "improve the methodology section" — give me the actual text). Focus on:
- How to teach hypothesis formation
- How to teach application understanding
- How to teach anomaly recognition
- When to use which tool
- When to pivot vs dig deeper

### Deliverable 4: Architecture Recommendations

If flow/mechanism changes are recommended, provide:
- New graph topology (if different from current 3-node loop)
- New state fields (if any)
- New auto-mechanisms (if any)
- New tools to build (with input/output schemas)
- Model routing changes (if any)

### Deliverable 5: 90-Day Roadmap

Prioritized implementation plan:
- **Week 1-2**: Highest-impact, lowest-effort changes
- **Week 3-4**: Medium-effort changes
- **Month 2**: Major architectural changes
- **Month 3**: Advanced features + optimization

Include expected finding rate improvement at each milestone.

---

## 5. IMPORTANT CONSTRAINTS

- Must use Claude models (Anthropic API) — no OpenAI, no open-source models for the brain
- Must stay within LangGraph framework (can add nodes/edges/subgraphs)
- Budget per target: typically $2-10 (Z.ai mode is $0)
- Must not regress XBOW benchmark below 90%
- Must respect target scope (no port scanning, no DoS, no social engineering)
- Agent runs unattended — all proposals must work autonomously (no human-in-the-loop)
- Findings must be REAL — false positives are worse than no findings (reputation damage on bounty platforms)

---

## 6. CRITICAL SUCCESS METRIC

The agent's value is measured by: **confirmed real vulnerabilities found per dollar spent**.

Current: 12 real findings / ~$0 (Z.ai) across 41 targets = effectively infinite but quality is 0.9%
Target: 10%+ real finding rate (150+ real findings from same 1530)

Every proposal should be evaluated against this metric. A change that improves CTF scores but doesn't improve real-world finding rate is WORTHLESS. A change that reduces false positives from 99.1% to 90% is a 10x improvement in signal-to-noise ratio.

The ultimate question: **What would make this agent find bugs that earn bounties?**
