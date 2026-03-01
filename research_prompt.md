# Deep Research Prompt: Autonomous AI Bug Bounty Active Testing Engine

You are a world-class security research architect. I need you to do extremely deep research and thinking about building an **autonomous active testing engine** that operates identically to a top-ranked (Rank 1) HackerOne/Bugcrowd bug bounty hunter. This is NOT a scanner. This is an AI agent that actively interacts with live web applications — browsing, clicking, typing, registering, logging in, manipulating requests, chaining vulnerabilities, writing exploits, and generating proof-of-concept code.

I already have a passive scanning + AI analysis framework built (Go scanning engine + Python AI brain using Claude API with LangGraph orchestrator). Now I need to add the **active testing layer** — the "hands" that let the AI brain actually touch and test websites like a human would.

Take your time. Think step by step. Be exhaustive. I want a complete technical blueprint.

---

## PART 1: How Top Bug Bounty Hunters Actually Work

Research and describe in extreme detail how a rank-1 bug bounty hunter approaches a target. Cover:

1. **Mental model and methodology**: How do they think? What's their decision tree? When do they go deep vs. wide? How do they decide what to test next based on what they've seen? What patterns trigger their instincts?

2. **Recon-to-exploitation flow**: Map the exact steps from "I just got a new program" to "I submitted a critical finding." Include:
   - How they read the program scope and rules
   - How they do recon differently from automated tools (what do they look for that tools miss?)
   - How they identify "interesting" functionality (payment flows, admin panels, API endpoints, file uploads, invitation systems, OAuth flows, password resets)
   - How they test business logic (the #1 thing AI currently can't do)
   - How they chain low-severity bugs into critical findings
   - How they maintain state across testing sessions (notes, screenshots, request logs)

3. **Business logic testing specifically**: This is the hardest category. Research:
   - What are the top 50 business logic vulnerability patterns? (race conditions, price manipulation, coupon abuse, privilege escalation via workflow manipulation, IDOR chains, state machine bypasses, etc.)
   - How does a human tester identify these? What triggers suspicion?
   - What multi-step flows are commonly vulnerable? (registration → email verify → profile update → privilege check)
   - How do they test payment/billing logic without actually charging cards?
   - How do they test invitation/referral systems?
   - How do they test rate limiting and anti-automation?

4. **The "creative" part**: What separates a rank-1 hunter from an average one?
   - Novel attack chains that combine multiple low-severity issues
   - Thinking about what the developer probably did wrong (developer psychology)
   - Testing edge cases that automated tools never check
   - Understanding business context (what would be impactful to THIS company?)

---

## PART 2: Architecture for Autonomous Active Testing

Design a complete technical architecture for an AI agent that can do everything above. Cover:

### 2.1 Browser Automation Layer

The AI needs to control a real browser. Research:

1. **Chrome DevTools Protocol (CDP) vs Playwright vs Puppeteer vs Selenium**: Which is best for this use case and why? Consider:
   - Ability to intercept/modify network requests
   - Ability to handle complex JS-heavy SPAs (React, Angular, Vue)
   - Support for iframes, shadow DOM, web workers
   - Stealth (avoiding bot detection)
   - Performance and resource usage
   - Ability to take screenshots at any point
   - Ability to extract DOM state for AI analysis

2. **Browser state management**: How should the agent:
   - Maintain multiple sessions simultaneously (different users, different auth levels)
   - Handle cookies, localStorage, sessionStorage
   - Handle CSRF tokens automatically
   - Deal with CAPTCHAs (when to stop, when to use solving services)
   - Handle popups, alerts, confirms
   - Navigate complex multi-page flows

3. **Smart DOM interaction**: The AI needs to understand web pages like a human. Research:
   - How to extract a meaningful representation of a page for the AI (not raw HTML — that's too large)
   - How to identify interactive elements (forms, buttons, links, dropdowns)
   - How to identify "interesting" functionality from page content
   - How to handle dynamically loaded content (infinite scroll, AJAX)
   - How to map the application's navigation structure automatically

### 2.2 Proxy Integration (Burp Suite / mitmproxy / Custom)

The AI needs to see and manipulate HTTP traffic. Research:

1. **Burp Suite integration**:
   - Burp REST API capabilities and limitations
   - Burp extensions (Python/Java) for AI integration
   - Using Burp's scanner, repeater, intruder programmatically
   - Extracting Burp's site map, issue list, request/response history
   - Is Burp the best choice or is mitmproxy better for programmatic access?

2. **mitmproxy as an alternative**:
   - mitmproxy's Python API for real-time request/response interception
   - Writing mitmproxy addons that the AI controls
   - Advantages: fully open source, Python-native, scriptable
   - Disadvantages vs Burp: no built-in scanning, no GUI for human review

3. **Custom proxy approach**:
   - Building a lightweight intercepting proxy in Go or Python
   - Storing all requests/responses in PostgreSQL for AI analysis
   - Real-time request modification based on AI decisions
   - Handling HTTPS (certificate generation, MITM)

4. **What the proxy should capture and how the AI should use it**:
   - Full request/response pairs with headers, body, timing
   - Automatically identifying API patterns, auth tokens, session cookies
   - Detecting when responses contain interesting data (PII, internal paths, stack traces)
   - Building an API map automatically from observed traffic

### 2.3 Email Integration for Account Registration

The AI needs email access to register accounts and receive verification links. Research:

1. **Disposable email approaches**:
   - Self-hosted mail server (Mailcow, iRedMail, simple Postfix)
   - Programmatic email services (Mailgun, SendGrid for receiving)
   - Catch-all domains (buy a domain, point MX, receive all @yourdomain.com)
   - Temp email APIs (Guerrilla Mail API, Mailinator API)

2. **Email interaction workflow**:
   - Register with generated email → poll inbox → find verification link → click it
   - Handle password reset flows
   - Handle 2FA email codes
   - Handle invitation emails
   - Parse HTML emails to extract links and codes
   - How fast does polling need to be? Webhook vs polling?

3. **Multi-account management**:
   - Creating multiple accounts with different roles (user, admin, manager)
   - Testing horizontal privilege escalation between accounts
   - Testing vertical privilege escalation
   - Managing credentials securely

### 2.4 SQL Injection Testing (sqlmap Integration)

Research:

1. **sqlmap programmatic integration**:
   - sqlmap's Python API vs command-line integration
   - Feeding sqlmap specific parameters identified by the AI
   - Parsing sqlmap results
   - When to use sqlmap vs manual testing
   - Safe testing modes (don't drop tables, don't exfiltrate real data)

2. **Beyond sqlmap**:
   - When AI should craft custom SQL injection payloads
   - Blind SQLi detection without sqlmap
   - Second-order SQLi (the AI needs to understand where data flows)
   - NoSQL injection (MongoDB, etc.) — sqlmap doesn't cover this

### 2.5 PoC Generation and Exploit Writing

The AI needs to write proof-of-concept code. Research:

1. **PoC types needed**:
   - Python scripts that reproduce the vulnerability
   - cURL commands showing the exact request
   - HTML pages for CSRF/XSS PoCs
   - Browser console JavaScript snippets
   - Burp Repeater request templates
   - Step-by-step reproduction instructions

2. **Exploit complexity levels**:
   - Simple: Single request that demonstrates the bug
   - Medium: Multi-step flow (register → login → exploit)
   - Complex: Race condition exploits (concurrent requests)
   - Advanced: Chain exploits (combine 3-4 bugs into critical)

3. **How the AI should generate PoCs**:
   - Template-based generation for common vuln types
   - Custom code generation for novel findings
   - Self-testing: Run the PoC to verify it actually works
   - Cleanup: Undo any changes made during testing

### 2.6 Tool Integration Framework

Beyond sqlmap, what other tools should the AI be able to invoke? Research:

1. **Essential active testing tools**:
   - SQLMap (SQL injection)
   - Commix (command injection)
   - XSStrike / Dalfox (XSS)
   - Tplmap (template injection / SSTI)
   - SSRFmap (SSRF)
   - jwt_tool (JWT attacks)
   - Arjun (parameter discovery)
   - ParamSpider (parameter mining)
   - CRLFuzz (CRLF injection)
   - Corsy (CORS misconfiguration)
   - Smuggler (HTTP request smuggling)
   - race-the-web / turbo-intruder patterns (race conditions)
   - GitTools / trufflehog (secret scanning)
   - Linkfinder / SecretFinder (JS analysis)

2. **How the AI should decide which tool to use when**:
   - Decision tree based on observed behavior
   - When to use a specialized tool vs. craft a manual test
   - How to interpret tool output and decide next steps

---

## PART 3: AI Agent Design for Active Testing

### 3.1 Agent Architecture

Research the best architecture for an AI agent that does active security testing:

1. **ReAct (Reason + Act) pattern**: How should the agent alternate between:
   - Observing (reading page content, HTTP responses, tool output)
   - Thinking (reasoning about what to test next, what the response means)
   - Acting (clicking, typing, sending requests, running tools)

2. **Tool-use based agent**: Design the complete set of tools the AI agent should have access to. For each tool, define:
   - Name, description, input schema, output format
   - When the agent should use it
   - How results feed back into reasoning

3. **Memory and context management**: The agent needs to remember what it's done. Research:
   - Short-term memory: Current test session state
   - Medium-term memory: What's been tested on this target, findings so far
   - Long-term memory: Patterns from previous programs, vulnerability knowledge base
   - How to compress context efficiently (a 2-hour testing session generates massive data)

4. **Multi-agent architecture**: Should this be one agent or multiple specialized agents?
   - Recon agent (maps the attack surface)
   - Auth agent (handles registration, login, session management)
   - Fuzzing agent (tests parameters systematically)
   - Business logic agent (tests workflows and state machines)
   - Exploitation agent (writes PoCs, chains vulnerabilities)
   - Reporting agent (documents findings)
   - Orchestrator agent (coordinates all others)
   - How do they communicate? Shared state? Message passing?

### 3.2 Decision Making

How should the AI decide what to test? Research:

1. **Attack surface prioritization**: Given a web application, how does the AI decide:
   - Which pages/endpoints to focus on?
   - Which parameters to test?
   - Which vulnerability classes to test for?
   - When to go deeper vs. move on?

2. **Adaptive testing**: The AI should adjust its approach based on what it finds:
   - Found an IDOR? → Test every similar endpoint
   - Found auth bypass? → Check what else is accessible
   - Found information disclosure? → Use leaked info to find more bugs
   - Hit a WAF? → Try bypass techniques
   - Found nothing after 30 minutes? → Move to different functionality

3. **Risk-based testing**: How to test safely:
   - Never test destructive operations (DELETE, data modification) on production without confirmation
   - Rate limiting awareness (don't get IP banned)
   - Avoiding data corruption
   - Clean up test data after testing

### 3.3 Prompt Engineering for Active Testing

Design the prompts needed for the active testing agent. Consider:

1. **System prompt**: What persona, rules, and methodology should be embedded?
2. **Observation prompts**: How to present page content, HTTP traffic, and tool output to the AI efficiently
3. **Decision prompts**: How to ask the AI "what should we test next?"
4. **Analysis prompts**: How to ask the AI "what does this response mean? Is this a vulnerability?"
5. **PoC generation prompts**: How to ask the AI to write exploit code
6. **Anti-hallucination**: How to prevent the AI from claiming it found a bug when it didn't (require evidence)

---

## PART 4: Specific Attack Implementations

For each of the following attack types, research exactly how the AI agent should test for them autonomously. Include the exact sequence of actions, what to look for in responses, and how to confirm the finding:

1. **IDOR (Insecure Direct Object Reference)**: Register 2 accounts, access resources of Account A using Account B's session. How to detect numeric IDs, UUIDs, encoded IDs. How to test every CRUD operation.

2. **Authentication bypass**: Token manipulation, session fixation, password reset poisoning, OAuth misconfigurations, JWT attacks (none algorithm, key confusion, claim manipulation).

3. **Authorization flaws**: Horizontal and vertical privilege escalation, forced browsing, parameter-based access control, missing function-level access control.

4. **Business logic flaws**: Price manipulation, coupon/discount abuse, race conditions in financial operations, workflow bypasses, feature flag manipulation.

5. **XSS (all types)**: Reflected, stored, DOM-based, blind XSS. How to find injection points, test different contexts (HTML, JS, attribute, URL), bypass WAF/filters.

6. **SSRF**: Testing URL parameters, webhook features, file import, PDF generators. Internal service discovery. Cloud metadata access (169.254.169.254).

7. **SQL Injection**: Error-based, blind boolean, blind time-based, out-of-band. When to use sqlmap vs manual. Second-order SQLi.

8. **CSRF**: Identifying endpoints without CSRF protection, generating PoC HTML pages, testing with different content types.

9. **File Upload**: Testing file type restrictions, content type bypass, extension bypass, path traversal in filenames, SVG XSS, polyglot files.

10. **Race Conditions**: Identifying time-of-check/time-of-use bugs, implementing parallel request sending, testing financial operations, coupon redemption, follow/like operations.

11. **API-specific attacks**: Mass assignment, broken object-level authorization (BOLA), excessive data exposure, GraphQL-specific attacks (introspection, batching, nested queries).

12. **Subdomain takeover**: Dangling DNS records, unclaimed cloud resources, how to verify without actually taking over.

---

## PART 5: Integration with Existing System

I have an existing system with:
- **Go scanning engine**: Runs tools (nmap, nuclei, httpx, etc.), preprocesses data, publishes to NATS JetStream
- **Python AI brain**: Claude API client with model tiering (Haiku/Sonnet/Opus), LangGraph state machine, prompt library, scope enforcer, budget manager
- **Infrastructure**: PostgreSQL, Redis, NATS, Docker

Research how the active testing engine should integrate:

1. **Where does active testing fit in the pipeline?** After passive recon? In parallel? As a separate mode?
2. **How should findings from passive scanning feed into active testing priorities?**
3. **How should the active testing agent communicate with the existing orchestrator?**
4. **Database schema additions needed** for storing active testing sessions, request/response logs, PoCs
5. **New NATS topics/streams needed**
6. **Docker service additions** (browser container, proxy container, email service)
7. **Budget implications** — active testing uses more API calls (each page view → AI analysis). How to keep costs manageable?

---

## PART 6: Safety, Ethics, and Legal Considerations

Research:

1. **Scope enforcement during active testing**: How to ensure the agent NEVER:
   - Tests out-of-scope domains
   - Follows redirects to out-of-scope targets
   - Sends payloads to third-party services (OAuth providers, CDNs, payment processors)
   - Exfiltrates real user data
   - Causes denial of service
   - Modifies or deletes production data

2. **Rate limiting and stealth**:
   - How fast should the agent test? (requests per second)
   - How to detect and respect application rate limits
   - How to avoid triggering WAFs
   - How to rotate User-Agents, fingerprints
   - Should the agent try to be stealthy or is transparency better?

3. **Destructive action safeguards**:
   - How to test DELETE/PUT/PATCH endpoints safely
   - How to test admin functionality without breaking things
   - Rollback mechanisms for unintended changes
   - Kill switch for immediate stop

---

## PART 7: Output Format

For your response, structure it as:

1. **Executive Summary** (1 page): Key architectural decisions and why
2. **Detailed Technical Blueprint**: For each section above, provide:
   - Recommended approach with specific technologies
   - Architecture diagrams (describe in text/ASCII)
   - Data flow descriptions
   - API/interface definitions
   - Code structure recommendations
3. **Implementation Priority**: What to build first, second, third
4. **Risk Assessment**: What's hardest, what might not work, what are the fallback approaches
5. **Estimated Complexity**: For each component, rough estimate of effort

Be extremely detailed and specific. I want actual tool names, library names, API endpoints, data formats, and architectural patterns — not vague recommendations. Think like you're writing the technical design document that an engineering team will implement directly.
