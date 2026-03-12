#!/usr/bin/env python3
"""
Bulk finding validator v2 — strict validation with real HTTP requests.

Key principles:
- SSTI: differential testing with unique numbers (no incidental matches)
- XSS: canary must appear in HTML body (not in URL params, headers, or JSON strings)
- Open redirect: Location header must redirect to a DIFFERENT domain
- Info disclosure: must match specific sensitive content patterns, not just "200 OK"
- SSRF: evidence-only claims from Z.ai are FP; need actual HTTP response data proving internal access
- All validators: skeptical by default, FP unless proven otherwise

Usage: python validate_unconfirmed.py [--dry-run] [--limit N] [--type TYPE]
"""

import asyncio
import json
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, quote

import asyncpg
import httpx

DB_DSN = "postgresql://aibbp:aibbp_dev@localhost:5433/aibbp"
CONCURRENCY = 12
TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

stats = {"total": 0, "confirmed": 0, "fp": 0, "inconclusive": 0, "error": 0, "skipped": 0}


async def get_http_client():
    return httpx.AsyncClient(
        timeout=httpx.Timeout(TIMEOUT),
        follow_redirects=False,
        verify=False,
        headers={"User-Agent": USER_AGENT},
        limits=httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=10),
    )


def _build_url(target_url, endpoint):
    """Build full URL from target + endpoint."""
    if not endpoint:
        return None
    if endpoint.startswith("http"):
        return endpoint
    if not target_url:
        return None
    return urljoin(target_url.rstrip("/") + "/", endpoint.lstrip("/"))


# ══════════════════════════════════════════════════════════════════════
#  VALIDATORS — Each returns (result, reason) where result is one of:
#    "confirmed", "fp", "inconclusive", "error", "skip"
# ══════════════════════════════════════════════════════════════════════


async def validate_info_disclosure(client, finding):
    """Validate info disclosure — only confirm if specific sensitive content is found."""
    url = _build_url(finding["target_url"], finding["endpoint"])
    if not url:
        return "skip", "No URL"

    endpoint = (finding["endpoint"] or "").lower()

    # Reject vague/non-URL endpoints (Z.ai fabrications like "Multiple", "all endpoints", etc.)
    if not endpoint.startswith("/") and not endpoint.startswith("http"):
        if any(w in endpoint.lower() for w in ["multiple", "all ", "various", "endpoints"]):
            return "fp", f"Vague endpoint: '{finding['endpoint']}'"

    try:
        resp = await client.get(url, follow_redirects=True)
    except Exception as e:
        return "error", f"HTTP: {type(e).__name__}: {str(e)[:80]}"

    status = resp.status_code
    body = resp.text[:10000] if resp.text else ""
    ct = resp.headers.get("content-type", "").lower()

    if status == 404:
        return "fp", f"HTTP 404"
    if status in (301, 302, 303, 307, 308):
        return "fp", f"HTTP {status} redirect"
    if status in (401, 403):
        return "fp", f"HTTP {status} access denied"
    if status >= 500:
        return "fp", f"HTTP {status} server error"

    if status != 200:
        return "fp", f"HTTP {status}"

    # ── Specific file/path validators ──
    # Only confirm if we find the EXPECTED content for that specific resource

    # security.txt
    if "security.txt" in endpoint:
        if "contact:" in body.lower() and len(body) < 5000:
            return "confirmed", f"Valid security.txt with Contact: field ({len(body)} bytes)"
        return "fp", "No valid security.txt Contact: field"

    # robots.txt
    if "robots.txt" in endpoint:
        if "disallow:" in body.lower() and len(body) < 50000:
            return "confirmed", f"Valid robots.txt ({len(body)} bytes)"
        return "fp", "No valid robots.txt"

    # crossdomain.xml
    if "crossdomain.xml" in endpoint:
        if re.search(r"<cross-domain-policy|allow-access-from", body, re.IGNORECASE):
            if re.search(r'domain="\*"', body):
                return "confirmed", "crossdomain.xml with wildcard domain"
            return "confirmed", "crossdomain.xml exists"
        return "fp", "No crossdomain.xml content"

    # GraphQL introspection
    if "graphql" in endpoint:
        if '"__schema"' in body or '"__type"' in body:
            return "confirmed", f"GraphQL introspection enabled ({len(body)} bytes)"
        return "fp", "No GraphQL introspection"

    # Swagger/OpenAPI
    if any(x in endpoint for x in ["swagger", "api-docs", "openapi"]):
        if re.search(r'"swagger"|"openapi"|"paths"\s*:', body):
            return "confirmed", f"Swagger/OpenAPI spec exposed ({len(body)} bytes)"
        return "fp", "No Swagger content"

    # .env file
    if ".env" in endpoint and "/" not in endpoint.replace(".env", ""):
        if re.search(r"(DB_|APP_KEY|SECRET|PASSWORD|API_KEY|REDIS|DATABASE_URL)\s*=", body):
            return "confirmed", f".env with secrets ({len(body)} bytes)"
        return "fp", "No .env secrets"

    # .git
    if ".git/" in endpoint:
        if re.search(r"\[core\]|\[remote|ref: refs/", body):
            return "confirmed", f"Git config/HEAD exposed"
        return "fp", "No git content"

    # web.config
    if "web.config" in endpoint:
        if re.search(r"<configuration|<system\.web", body):
            return "confirmed", f"web.config exposed ({len(body)} bytes)"
        return "fp", "No web.config content"

    # package.json
    if "package.json" in endpoint:
        if re.search(r'"(name|version|dependencies)"\s*:', body) and "application/json" in ct:
            return "confirmed", f"package.json exposed ({len(body)} bytes)"
        return "fp", "No package.json content"

    # Actuator endpoints
    if "actuator" in endpoint:
        if re.search(r'"(status|health|beans|env|configprops)"', body):
            return "confirmed", f"Spring Actuator exposed ({len(body)} bytes)"
        return "fp", "No actuator content"

    # phpinfo
    if "phpinfo" in endpoint:
        if "PHP Version" in body or "phpinfo()" in body:
            return "confirmed", f"phpinfo exposed"
        return "fp", "No phpinfo content"

    # elmah.axd
    if "elmah" in endpoint:
        if re.search(r"Error Log|ELMAH|Error\s+Log", body, re.IGNORECASE):
            return "confirmed", f"ELMAH error log exposed"
        return "fp", "No ELMAH content"

    # server-status
    if "server-status" in endpoint:
        if "Apache Server Status" in body or "Total accesses" in body:
            return "confirmed", f"Apache server-status exposed"
        return "fp", "No server-status content"

    # S3 bucket listing
    if "s3.amazonaws.com" in url or "s3." in url:
        if "<ListBucketResult" in body or "<Contents>" in body:
            return "confirmed", f"S3 bucket listing enabled"
        return "fp", "No S3 listing"

    # config.json (check for actual sensitive config, not just any JSON)
    if "config.json" in endpoint or "config.js" in endpoint:
        if re.search(r"(api_key|secret|password|token|private|credentials)\s*[\":=]", body, re.IGNORECASE):
            return "confirmed", f"Config file with sensitive keys ({len(body)} bytes)"
        return "fp", "Config file without sensitive data"

    # ── For everything else: conservative — only confirm with very specific evidence ──
    # A generic 200 response does NOT confirm info disclosure
    return "fp", f"HTTP 200 but no sensitive content pattern matched"


async def validate_xss(client, finding):
    """Validate XSS — canary must appear in HTML body context, not just reflected in URLs/JSON."""
    url = _build_url(finding["target_url"], finding["endpoint"])
    if not url:
        return "skip", "No URL"

    canary = "xsscanary7r4nd0m"
    param = finding.get("parameter")
    test_params = ([param] if param else []) + ["q", "search", "query", "s", "keyword", "input", "name"]

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for pname in test_params[:5]:
        if not pname:
            continue
        test_url = f"{base_url}?{pname}={canary}"
        try:
            resp = await client.get(test_url, follow_redirects=True)
            body = resp.text or ""
            ct = resp.headers.get("content-type", "").lower()

            if canary not in body:
                continue

            # Canary is in the response. But WHERE?
            # FP cases: reflected in JSON response, URL canonicalization, meta tags, etc.

            # If response is JSON, reflection is not XSS
            if "application/json" in ct:
                continue

            # If response is not HTML, less likely to be exploitable
            if "text/html" not in ct and "text/xml" not in ct:
                continue

            # Check: is canary reflected in an HTML context where JS could execute?
            # Simple check: canary appears outside of quoted attribute values
            # and outside of <script src="..."> URLs
            lines_with_canary = [l for l in body.split("\n") if canary in l]

            for line in lines_with_canary:
                stripped = line.strip().lower()
                # Skip if canary is only in a URL/href
                if f'="{canary}"' in line or f"='{canary}'" in line:
                    # Canary is an attribute value — could be XSS in href/src
                    if "href=" in stripped or "action=" in stripped:
                        return "confirmed", f"XSS: canary in href/action attribute via '{pname}' (HTTP {resp.status_code})"
                elif f">{canary}<" in line or f">{canary}" in line:
                    # Canary between tags — definite reflection
                    return "confirmed", f"XSS: canary reflected in HTML body via '{pname}' (HTTP {resp.status_code})"
                elif canary in line:
                    # Any other reflection in HTML — still notable
                    return "confirmed", f"XSS: canary reflected in HTML context via '{pname}' (HTTP {resp.status_code})"

        except Exception:
            continue

    return "fp", "No XSS reflection in HTML context"


async def validate_open_redirect(client, finding):
    """Validate open redirect — Location must redirect to a truly EXTERNAL domain."""
    url = _build_url(finding["target_url"], finding["endpoint"])
    if not url:
        return "skip", "No URL"

    evil_url = "https://evil.example.com/stolen"
    redirect_params = ["url", "redirect", "redirect_uri", "next", "return", "returnTo",
                       "return_url", "goto", "target", "dest", "out", "continue", "forward"]

    parsed = urlparse(url)
    target_host = parsed.netloc.lower()

    # Extract the base domain (e.g., "robinhood.com" from "share.robinhood.com")
    parts = target_host.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else target_host

    # Try replacing existing redirect-like params
    if "=" in (parsed.query or ""):
        test_url = re.sub(
            r'(url|redirect|next|return|goto|dest|out|continue|forward|target)=[^&]*',
            r'\1=' + quote(evil_url), url, flags=re.IGNORECASE
        )
        if test_url != url:
            result = await _check_redirect(client, test_url, base_domain, "existing param")
            if result:
                return result

    # Try common redirect param names
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    for param in redirect_params[:8]:
        test_url = f"{base_url}?{param}={quote(evil_url)}"
        result = await _check_redirect(client, test_url, base_domain, param)
        if result:
            return result

    return "fp", "No open redirect to external domain"


async def _check_redirect(client, test_url, base_domain, param_name):
    """Check if a URL redirects to an external domain."""
    try:
        resp = await client.get(test_url)
        if resp.status_code not in (301, 302, 303, 307, 308):
            return None

        location = resp.headers.get("location", "")
        if not location:
            return None

        # Parse the redirect target
        redirect_parsed = urlparse(location)
        redirect_host = redirect_parsed.netloc.lower()

        # Check if it redirects to evil.example.com
        if "evil.example.com" in redirect_host:
            return "confirmed", f"Open redirect via '{param_name}' → {location[:80]} (HTTP {resp.status_code})"

        # Check if it redirects to a DIFFERENT external domain (not same base domain)
        if redirect_host and base_domain not in redirect_host and "evil.example.com" not in redirect_host:
            # Redirect goes somewhere else entirely — but is it an open redirect?
            # Only if evil.example.com is in the full URL (maybe nested)
            if "evil.example.com" in location:
                return "confirmed", f"Open redirect via '{param_name}' → {location[:80]} (HTTP {resp.status_code})"

        # Same-domain redirect = not an open redirect
        return None

    except Exception:
        return None


async def validate_subdomain_takeover(client, finding):
    """Validate subdomain takeover — must find specific service fingerprint or NXDOMAIN."""
    domain = finding.get("domain") or ""
    endpoint = finding["endpoint"] or ""

    # Get the actual subdomain to check
    if endpoint.startswith("http"):
        check_url = endpoint
    elif "." in endpoint and not endpoint.startswith("/"):
        check_url = f"https://{endpoint}"
    elif domain:
        check_url = f"https://{domain}"
    else:
        return "skip", "No domain to check"

    try:
        resp = await client.get(check_url, follow_redirects=True)
        body = (resp.text or "")[:3000].lower()

        takeover_fingerprints = [
            ("there isn't a github pages site here", "GitHub Pages"),
            ("nosuchbucket", "AWS S3"),
            ("the specified bucket does not exist", "AWS S3"),
            ("herokucdn.com/error-pages", "Heroku"),
            ("no such app", "Heroku"),
            ("this domain is not connected", "Tumblr"),
            ("whatever you were looking for doesn't currently exist", "Tumblr"),
            ("sorry, this shop is currently unavailable", "Shopify"),
            ("project not found", "Surge.sh"),
            ("repository not found", "Bitbucket"),
            ("do you want to register", "WordPress.com"),
        ]

        for pattern, service in takeover_fingerprints:
            if pattern in body:
                return "confirmed", f"Takeover fingerprint: {service}"

        if resp.status_code == 200 and len(body) > 500:
            return "fp", f"HTTP 200, site is live ({len(body)} bytes)"

        return "inconclusive", f"HTTP {resp.status_code}, no takeover fingerprint"

    except httpx.ConnectError as e:
        err = str(e).lower()
        if "name or service not known" in err or "nxdomain" in err or "no address" in err:
            return "confirmed", f"DNS NXDOMAIN — dangling record"
        return "inconclusive", f"Connect error: {str(e)[:80]}"
    except Exception as e:
        return "error", f"{type(e).__name__}: {str(e)[:80]}"


async def validate_ssrf(client, finding):
    """SSRF — can't verify externally. Only confirm with hard proof in evidence."""
    evidence = finding.get("evidence") or {}
    ev_str = json.dumps(evidence) if isinstance(evidence, dict) else str(evidence)

    # Z.ai narratives often MENTION these IPs without actually proving SSRF
    # We need to check if the evidence contains actual response DATA, not just narrative claims

    # Check if evidence has actual HTTP response body with internal data
    has_http_response = bool(re.search(r"HTTP/\d\.\d\s+\d{3}", ev_str))

    # Hard proof patterns (in actual response data, not narrative)
    if has_http_response:
        if "root:x:0:0" in ev_str:
            return "confirmed", "HTTP response contains /etc/passwd"
        if re.search(r'"(ami-id|instance-id|local-hostname)"', ev_str):
            return "confirmed", "HTTP response contains AWS metadata fields"
        if "latest/meta-data" in ev_str and re.search(r"ami-[a-f0-9]|i-[a-f0-9]|ip-\d+", ev_str):
            return "confirmed", "AWS metadata content in response"

    # Narrative claims like "tested with 169.254.169.254" without response proof → FP
    return "fp", "No verifiable SSRF proof (narrative-only evidence)"


async def validate_ssti(client, finding):
    """Validate SSTI — differential test with unique numbers."""
    url = _build_url(finding["target_url"], finding["endpoint"])
    if not url:
        return "skip", "No URL"

    param = finding.get("parameter")
    test_params = ([param] if param else []) + ["q", "search", "name", "input", "query", "template"]

    # Use unique numbers unlikely to appear in normal pages
    payloads = [
        ("{{97*83}}", "8051"),
        ("${97*83}", "8051"),
        ("<%= 97*83 %>", "8051"),
        ("{{71*89}}", "6319"),
    ]

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for pname in test_params[:4]:
        if not pname:
            continue
        try:
            # Baseline
            baseline_resp = await client.get(f"{base_url}?{pname}=normaltext456", follow_redirects=True)
            baseline_body = baseline_resp.text or ""
        except Exception:
            continue

        for payload, expected in payloads:
            try:
                resp = await client.get(f"{base_url}?{pname}={quote(payload)}", follow_redirects=True)
                body = resp.text or ""
                # Remove literal payload text to avoid false matches
                cleaned = body.replace(payload, "").replace(quote(payload), "")
                baseline_count = baseline_body.count(expected)
                payload_count = cleaned.count(expected)

                if payload_count > baseline_count:
                    # Double-check with a second unique number
                    resp2 = await client.get(f"{base_url}?{pname}={quote('{{71*89}}')}", follow_redirects=True)
                    body2 = (resp2.text or "").replace("{{71*89}}", "").replace(quote("{{71*89}}"), "")
                    baseline_6319 = baseline_body.count("6319")
                    if body2.count("6319") > baseline_6319:
                        return "confirmed", f"SSTI: {payload}→{expected} AND {{{{71*89}}}}→6319 via '{pname}' (double-confirmed)"
                    # Single match — still suspicious but could be coincidence
                    return "confirmed", f"SSTI: {payload}→{expected} via '{pname}' (baseline={baseline_count}, payload={payload_count})"
            except Exception:
                continue

    return "fp", "No SSTI evaluation (differential test)"


async def validate_sqli(client, finding):
    """Validate SQLi — check for database error messages in response."""
    url = _build_url(finding["target_url"], finding["endpoint"])
    if not url:
        return "skip", "No URL"

    param = finding.get("parameter")
    test_params = ([param] if param else []) + ["id", "q", "search", "page", "cat", "user"]

    sql_error_patterns = [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\bmysql_",
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\bpg_",
        r"OLE DB.*?SQL Server",
        r"Microsoft SQL Native Client",
        r"Oracle error",
        r"sqlite3\.OperationalError",
        r"SQLITE_ERROR",
        r"you have an error in your sql syntax",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"Syntax error.*?in query expression",
    ]

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # First check baseline — make sure error patterns don't appear normally
    try:
        baseline_resp = await client.get(f"{base_url}?{test_params[0] or 'id'}=1", follow_redirects=True)
        baseline_body = baseline_resp.text or ""
    except Exception:
        baseline_body = ""

    for pname in test_params[:4]:
        if not pname:
            continue
        for payload in ["'", '"', "' OR '1'='1", "1' AND '1'='2"]:
            try:
                resp = await client.get(f"{base_url}?{pname}={quote(payload)}", follow_redirects=True)
                body = resp.text or ""
                for pattern in sql_error_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        # Verify this error doesn't appear in baseline
                        if not re.search(pattern, baseline_body, re.IGNORECASE):
                            return "confirmed", f"SQL error via '{pname}' with '{payload}': {pattern}"
            except Exception:
                continue

    return "fp", "No SQL error indicators"


async def validate_auth_bypass(client, finding):
    """Auth bypass — can't verify without credentials. Conservative."""
    url = _build_url(finding["target_url"], finding["endpoint"])
    if not url:
        return "skip", "No URL"

    # Vague endpoints
    ep = finding["endpoint"] or ""
    if any(w in ep.lower() for w in ["multiple", "all ", "various"]):
        return "fp", f"Vague endpoint: '{ep}'"

    try:
        resp = await client.get(url, follow_redirects=False)
    except Exception as e:
        return "error", f"HTTP: {type(e).__name__}"

    status = resp.status_code
    location = resp.headers.get("location", "").lower()

    if status in (401, 403):
        return "fp", f"HTTP {status} — auth enforced"
    if 300 <= status < 400 and any(w in location for w in ["login", "auth", "signin", "sso"]):
        return "fp", f"HTTP {status} redirect to auth"
    if status == 200:
        body = (resp.text or "")[:3000].lower()
        if any(w in body for w in ["sign in", "log in", "login", "forgot password", "create account"]):
            return "fp", "Public login page"

    return "inconclusive", f"HTTP {status} — can't verify auth bypass without credentials"


async def validate_host_header_injection(client, finding):
    """Host header injection — check if evil host is reflected."""
    url = _build_url(finding["target_url"], finding["endpoint"]) or finding["target_url"]
    if not url:
        return "skip", "No URL"

    evil_host = "evil.example.com"
    try:
        resp = await client.get(url, headers={"Host": evil_host})
        body = (resp.text or "")[:5000]
        location = resp.headers.get("location", "")
        if evil_host in location:
            return "confirmed", f"Host header reflected in Location: {location[:80]}"
        if evil_host in body:
            return "confirmed", f"Host header reflected in body"
    except Exception as e:
        return "error", f"{type(e).__name__}: {str(e)[:60]}"
    return "fp", "Host header not reflected"


async def validate_cors(client, finding):
    """CORS misconfiguration — check if arbitrary origin is reflected."""
    url = _build_url(finding["target_url"], finding["endpoint"]) or finding["target_url"]
    if not url:
        return "skip", "No URL"

    evil_origin = "https://evil.example.com"
    try:
        resp = await client.get(url, headers={"Origin": evil_origin})
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if evil_origin == acao:
            if "true" in acac.lower():
                return "confirmed", f"CORS: reflects arbitrary origin WITH credentials"
            return "confirmed", f"CORS: reflects arbitrary origin (no credentials)"
        if acao == "null":
            if "true" in acac.lower():
                return "confirmed", "CORS: allows null origin with credentials"
            return "inconclusive", "CORS: null origin without credentials (low risk)"
    except Exception as e:
        return "error", f"{type(e).__name__}: {str(e)[:60]}"
    return "fp", "CORS properly configured"


async def validate_generic(finding):
    """For types without active validators — assess evidence quality strictly."""
    evidence = finding.get("evidence") or {}
    ev_str = json.dumps(evidence) if isinstance(evidence, dict) else str(evidence)
    vuln_type = (finding.get("vuln_type") or "").lower()

    # Non-vulnerability types → automatic FP
    non_vuln = {
        "waf", "waf_detection", "waf_protection", "waf_bypass", "waf_bypass_failed", "waf_block",
        "testing_complete", "testing_progress", "testing_summary", "security_assessment", "assessment",
        "comprehensive", "comprehensive_assessment", "scope_limitation", "recon", "none", "none_found",
        "false_positive", "informational", "info", "multiple", "chain", "anti_automation",
        "availability", "missing_controls", "brute_force", "rate_limiting", "rate_limit_bypass",
        "missing_rate_limit", "missing_rate_limiting", "waf_bypass_failed", "testing_complete",
        "security_misconfiguration", "missing_controls", "scope_limitation", "dos",
        "denial_of_service", "testing_summary", "testing_progress",
    }
    if vuln_type in non_vuln:
        return "fp", f"Non-vulnerability type: {vuln_type}"

    # Strong hard evidence artifacts (unfakeable)
    hard_proof = [
        (r"root:x:0:0:root", "passwd file"),
        (r"AKIA[A-Z0-9]{16}", "AWS access key ID"),
        (r"sk_live_[A-Za-z0-9]{20,}", "Stripe live key"),
        (r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----", "private key"),
    ]
    for pattern, desc in hard_proof:
        if re.search(pattern, ev_str):
            return "confirmed", f"Hard evidence: {desc}"

    # Z.ai narrative-only evidence with no HTTP response data → FP
    if "HTTP/" not in ev_str:
        return "fp", f"Narrative-only evidence for {vuln_type}"

    return "inconclusive", f"Cannot externally validate {vuln_type}"


# ── Dispatcher ────────────────────────────────────────────────────────

VALIDATORS = {
    "info_disclosure": validate_info_disclosure,
    "information_disclosure": validate_info_disclosure,
    "info_disc": validate_info_disclosure,
    "sensitive_data_exposure": validate_info_disclosure,
    "credential_exposure": validate_info_disclosure,
    "hardcoded_credentials": validate_info_disclosure,
    "xss": validate_xss,
    "xss_filter_bypass": validate_xss,
    "open_redirect": validate_open_redirect,
    "subdomain_takeover": validate_subdomain_takeover,
    "Subdomain Takeover": validate_subdomain_takeover,
    "dangling_dns": validate_subdomain_takeover,
    "ssrf": validate_ssrf,
    "SSRF": validate_ssrf,
    "ssti": validate_ssti,
    "sqli": validate_sqli,
    "nosqli": validate_sqli,
    "nosql_injection": validate_sqli,
    "auth_bypass": validate_auth_bypass,
    "access_control_bypass": validate_auth_bypass,
    "broken_access_control": validate_auth_bypass,
    "broken_authentication": validate_auth_bypass,
    "access_control": validate_auth_bypass,
    "host_header_injection": validate_host_header_injection,
    "header_injection": validate_host_header_injection,
    "cors": validate_cors,
}


async def validate_one(client, finding, pool):
    """Validate a single finding and update DB."""
    vuln_type = finding.get("vuln_type", "")
    validator = VALIDATORS.get(vuln_type)

    try:
        if validator:
            result, reason = await validator(client, finding)
        else:
            result, reason = await validate_generic(finding)
    except Exception as e:
        result, reason = "error", f"Crashed: {type(e).__name__}: {str(e)[:80]}"

    if result == "skip":
        stats["skipped"] += 1
        return

    now = datetime.now(timezone.utc)
    try:
        if result == "confirmed":
            stats["confirmed"] += 1
            await pool.execute(
                "UPDATE findings SET confirmed = true, is_false_positive = false, validated_at = $2, fp_reason = $3 WHERE id = $1",
                finding["id"], now, f"[v2-validated] {reason}",
            )
        elif result == "fp":
            stats["fp"] += 1
            await pool.execute(
                "UPDATE findings SET confirmed = false, is_false_positive = true, validated_at = $2, fp_reason = $3 WHERE id = $1",
                finding["id"], now, f"[v2-validated] {reason}",
            )
        elif result == "inconclusive":
            stats["inconclusive"] += 1
            await pool.execute(
                "UPDATE findings SET validated_at = $2, fp_reason = $3 WHERE id = $1",
                finding["id"], now, f"[v2-validated: inconclusive] {reason}",
            )
        else:
            stats["error"] += 1
    except Exception as e:
        stats["error"] += 1

    icons = {"confirmed": "\033[92m✓\033[0m", "fp": "\033[91m✗\033[0m",
             "inconclusive": "\033[93m?\033[0m", "error": "\033[91m!\033[0m"}
    icon = icons.get(result, "?")
    domain = (finding.get("domain") or "?")[:25]
    ep = (finding.get("endpoint") or "?")[:40]
    print(f"  {icon} [{vuln_type:25s}] {domain:25s} {ep:40s} → {result}: {reason[:70]}")


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Validate unconfirmed findings (strict, v2)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--type", type=str, default=None)
    args = parser.parse_args()

    print("Connecting to database...")
    pool = await asyncpg.create_pool(DB_DSN, min_size=2, max_size=5)

    query = """
        SELECT id, finding_key, domain, target_url, session_id, vuln_type, severity, title,
               endpoint, parameter, method, evidence, poc_code, request_dump, response_dump,
               confirmed, is_false_positive, confidence, tool_used
        FROM findings
        WHERE confirmed = false AND is_false_positive = false
    """
    params = []
    if args.type:
        query += " AND vuln_type = $1"
        params.append(args.type)

    query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, confidence DESC"

    rows = await pool.fetch(query, *params)
    findings = [dict(r) for r in rows]
    if args.limit > 0:
        findings = findings[:args.limit]

    stats["total"] = len(findings)
    print(f"\nFound {len(findings)} findings to validate (strict v2)\n{'='*120}\n")

    if args.dry_run:
        for f in findings[:30]:
            print(f"  [{f['severity']:8s}] {f['vuln_type']:25s} {(f['domain'] or '?'):25s} {(f['endpoint'] or '?')[:50]}")
        if len(findings) > 30:
            print(f"  ... and {len(findings) - 30} more")
        await pool.close()
        return

    client = await get_http_client()
    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded(f):
        async with sem:
            await validate_one(client, f, pool)

    await asyncio.gather(*[bounded(f) for f in findings], return_exceptions=True)

    await client.aclose()
    await pool.close()

    print(f"\n{'='*120}")
    print(f"\nValidation complete (strict v2)!")
    print(f"  Total:          {stats['total']}")
    print(f"  \033[92mConfirmed:      {stats['confirmed']}\033[0m")
    print(f"  \033[91mFalse Positive: {stats['fp']}\033[0m")
    print(f"  \033[93mInconclusive:   {stats['inconclusive']}\033[0m")
    print(f"  Errors:         {stats['error']}")
    print(f"  Skipped:        {stats['skipped']}")


if __name__ == "__main__":
    asyncio.run(main())
