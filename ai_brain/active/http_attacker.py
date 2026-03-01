"""HTTP-level testing engine for active testing.

Provides traffic analysis, request replay with modifications, differential
analysis, and authorization matrix testing. This replaces browser-level
testing with direct HTTP requests via httpx, similar to Burp Suite's
Repeater and Intruder.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import structlog

from ai_brain.active.scope_guard import ActiveScopeGuard
from ai_brain.active_schemas import HTTPTrafficEntry, TestAccount

logger = structlog.get_logger()

# Maximum concurrent requests for any single test
_MAX_CONCURRENCY = 10

# CSRF token field names to auto-refresh
_CSRF_FIELD_NAMES = frozenset({
    "_token", "csrf_token", "csrfmiddlewaretoken", "_csrf",
    "__RequestVerificationToken", "authenticity_token", "csrf",
    "xsrf_token", "_xsrf", "anticsrf",
})

# Parameter names that indicate access-control-relevant IDs
_ID_PARAM_PATTERNS = re.compile(
    r"(^id$|_id$|^uid$|^user|^account|^profile|^role|^plan|^price|"
    r"^amount|^quantity|^order|^invoice|^payment|^subscription)",
    re.IGNORECASE,
)

# Parameters to never fuzz (they're infrastructure, not user input)
_SKIP_PARAMS = frozenset({
    "_token", "csrf_token", "csrfmiddlewaretoken", "_csrf",
    "__RequestVerificationToken", "authenticity_token",
    "xsrf_token", "_xsrf", "anticsrf",
    "g-recaptcha-response", "h-captcha-response",
    "cf-turnstile-response", "captcha",
})


@dataclass
class InsertionPoint:
    """A single testable parameter extracted from captured traffic."""

    url: str
    method: str
    param_name: str
    param_type: Literal[
        "query", "body", "json", "cookie", "header", "path",
    ]
    original_value: str = ""
    content_type: str = ""
    # Full request template for replay
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    priority: int = 5  # 1=highest, 10=lowest


@dataclass
class ResponseSignature:
    """Baseline response metrics for differential analysis."""

    status_code: int
    body_length: int
    word_count: int
    elapsed_ms: int
    has_error: bool = False
    error_keywords: list[str] = field(default_factory=list)
    redirect_url: str = ""
    content_type: str = ""

    def deviation_from(self, other: ResponseSignature) -> float:
        """Calculate deviation score between two response signatures.

        Returns a 0-1 score where 0 = identical, 1 = completely different.
        """
        score = 0.0

        # Status code difference is a strong signal
        if self.status_code != other.status_code:
            score += 0.4

        # Body length difference (normalized)
        max_len = max(self.body_length, other.body_length, 1)
        len_diff = abs(self.body_length - other.body_length) / max_len
        score += len_diff * 0.2

        # Word count difference
        max_words = max(self.word_count, other.word_count, 1)
        word_diff = abs(self.word_count - other.word_count) / max_words
        score += word_diff * 0.1

        # Timing difference (> 3x slower is suspicious)
        if other.elapsed_ms > 0 and self.elapsed_ms > other.elapsed_ms * 3:
            score += 0.2

        # New errors appearing
        if self.has_error and not other.has_error:
            score += 0.1

        return min(score, 1.0)


class TrafficAnalyzer:
    """Analyzes captured proxy traffic to extract insertion points.

    Processes HTTPTrafficEntry objects from the proxy to find every
    testable parameter: URL query params, POST body params, JSON fields,
    cookies, headers, and path segments containing IDs.
    """

    def __init__(self, scope_guard: ActiveScopeGuard) -> None:
        self._scope_guard = scope_guard

    def extract_insertion_points(
        self,
        traffic: list[HTTPTrafficEntry],
        skip_static: bool = True,
    ) -> list[InsertionPoint]:
        """Extract all testable insertion points from captured traffic.

        Args:
            traffic: Captured HTTP flows from the proxy.
            skip_static: Skip static resources (images, CSS, JS, fonts).

        Returns:
            List of InsertionPoint sorted by priority (lowest = highest priority).
        """
        points: list[InsertionPoint] = []
        seen: set[str] = set()

        for entry in traffic:
            req = entry.request
            url = req.url

            # Skip static resources
            if skip_static and self._is_static(url):
                continue

            # Skip non-in-scope URLs
            try:
                self._scope_guard.validate_url(url)
            except Exception:
                continue

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # 1. URL query parameters
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for param_name, values in query_params.items():
                if param_name.lower() in _SKIP_PARAMS:
                    continue
                key = f"query:{base_url}:{param_name}"
                if key not in seen:
                    seen.add(key)
                    points.append(InsertionPoint(
                        url=url,
                        method=req.method,
                        param_name=param_name,
                        param_type="query",
                        original_value=values[0] if values else "",
                        content_type=req.content_type,
                        headers=dict(req.headers),
                        body=req.body,
                        priority=self._priority_for_param(param_name),
                    ))

            # 2. POST body parameters (form-encoded)
            if req.body and "form" in req.content_type.lower():
                body_params = parse_qs(req.body, keep_blank_values=True)
                for param_name, values in body_params.items():
                    if param_name.lower() in _SKIP_PARAMS:
                        continue
                    key = f"body:{base_url}:{param_name}"
                    if key not in seen:
                        seen.add(key)
                        points.append(InsertionPoint(
                            url=base_url,
                            method=req.method,
                            param_name=param_name,
                            param_type="body",
                            original_value=values[0] if values else "",
                            content_type=req.content_type,
                            headers=dict(req.headers),
                            body=req.body,
                            priority=self._priority_for_param(param_name),
                        ))

            # 3. JSON body fields (recursive extraction)
            if req.body and "json" in req.content_type.lower():
                try:
                    json_body = json.loads(req.body)
                    json_params = self._extract_json_params(json_body)
                    for param_path, value in json_params:
                        key = f"json:{base_url}:{param_path}"
                        if key not in seen:
                            seen.add(key)
                            points.append(InsertionPoint(
                                url=base_url,
                                method=req.method,
                                param_name=param_path,
                                param_type="json",
                                original_value=str(value),
                                content_type=req.content_type,
                                headers=dict(req.headers),
                                body=req.body,
                                priority=self._priority_for_param(param_path),
                            ))
                except (json.JSONDecodeError, TypeError):
                    pass

            # 4. Path segments containing IDs
            # Skip common API version segments (v1, v2, etc.) and
            # single-digit numbers at shallow depth (likely versions).
            _VERSION_SEGMENTS = frozenset({"v1", "v2", "v3", "v4", "v5"})
            path_parts = parsed.path.strip("/").split("/")
            for i, part in enumerate(path_parts):
                is_numeric = re.match(r"^\d+$", part)
                is_uuid = re.match(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}", part, re.IGNORECASE
                )
                if not (is_numeric or is_uuid):
                    continue
                # Filter out version-like segments (v1, v2, ...)
                if part.lower() in _VERSION_SEGMENTS:
                    continue
                # Single-digit numbers at depth <= 1 are likely API versions
                # (e.g., /api/2/users or /1/items)
                if is_numeric and len(part) == 1 and i <= 1:
                    continue
                # Only flag numeric path segments at depth > 1
                # (depth 0 = first segment, 1 = second, etc.)
                if is_numeric and i <= 1:
                    continue
                key = f"path:{base_url}:segment_{i}"
                if key not in seen:
                    seen.add(key)
                    points.append(InsertionPoint(
                        url=url,
                        method=req.method,
                        param_name=f"path_segment_{i}",
                        param_type="path",
                        original_value=part,
                        content_type=req.content_type,
                        headers=dict(req.headers),
                        body=req.body,
                        priority=2,  # Path IDs are high priority (IDOR)
                    ))

            # 5. Interesting headers
            for header_name in ("Authorization", "X-Forwarded-For",
                                "X-Original-URL", "X-Rewrite-URL"):
                if header_name in req.headers:
                    key = f"header:{base_url}:{header_name}"
                    if key not in seen:
                        seen.add(key)
                        points.append(InsertionPoint(
                            url=url,
                            method=req.method,
                            param_name=header_name,
                            param_type="header",
                            original_value=req.headers[header_name],
                            content_type=req.content_type,
                            headers=dict(req.headers),
                            body=req.body,
                            priority=3,
                        ))

        # Sort by priority (lowest number = highest priority)
        points.sort(key=lambda p: p.priority)
        return points

    def find_auth_sensitive_requests(
        self, traffic: list[HTTPTrafficEntry],
    ) -> list[HTTPTrafficEntry]:
        """Find requests that likely involve authorization decisions.

        These are POST/PUT/PATCH requests, requests with ID parameters,
        requests to admin/settings/account endpoints, and API calls.
        """
        sensitive = []
        for entry in traffic:
            req = entry.request
            is_sensitive = False

            # POST/PUT/PATCH are state-changing
            if req.method in ("POST", "PUT", "PATCH"):
                is_sensitive = True

            # URLs with ID-like path segments
            if re.search(r"/\d+(/|$)", urlparse(req.url).path):
                is_sensitive = True

            # Admin, settings, account, profile, dashboard paths
            path_lower = urlparse(req.url).path.lower()
            if any(kw in path_lower for kw in (
                "admin", "settings", "account", "profile",
                "dashboard", "manage", "user", "api",
            )):
                is_sensitive = True

            # Requests with interesting tags
            if any(tag in entry.tags for tag in ("api", "admin", "auth")):
                is_sensitive = True

            if is_sensitive:
                sensitive.append(entry)

        return sensitive

    def build_attack_surface_summary(
        self, traffic: list[HTTPTrafficEntry],
    ) -> dict[str, Any]:
        """Build a concise attack surface summary for Claude analysis.

        Returns a dict suitable for passing to Claude as context.
        """
        insertion_points = self.extract_insertion_points(traffic)
        auth_requests = self.find_auth_sensitive_requests(traffic)

        # Group insertion points by URL
        by_url: dict[str, list[dict[str, str]]] = {}
        for ip in insertion_points:
            base = urlparse(ip.url).path
            if base not in by_url:
                by_url[base] = []
            by_url[base].append({
                "param": ip.param_name,
                "type": ip.param_type,
                "value": ip.original_value[:100],
                "method": ip.method,
            })

        # Unique endpoints
        endpoints = set()
        for entry in traffic:
            parsed = urlparse(entry.request.url)
            endpoints.add(f"{entry.request.method} {parsed.path}")

        return {
            "total_requests": len(traffic),
            "unique_endpoints": len(endpoints),
            "insertion_points": len(insertion_points),
            "auth_sensitive_requests": len(auth_requests),
            "endpoints_with_params": {
                path: params[:5] for path, params in list(by_url.items())[:30]
            },
            "methods_observed": list(set(e.request.method for e in traffic)),
            "content_types": list(set(
                e.request.content_type for e in traffic if e.request.content_type
            ))[:10],
        }

    @staticmethod
    def _is_static(url: str) -> bool:
        """Check if a URL points to a static resource."""
        path = urlparse(url).path.lower()
        static_exts = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
            ".webp", ".mp4", ".mp3", ".pdf",
        )
        return any(path.endswith(ext) for ext in static_exts)

    @staticmethod
    def _priority_for_param(param_name: str) -> int:
        """Assign priority based on parameter name (1=highest, 10=lowest)."""
        name_lower = param_name.lower()

        # Highest priority: IDs and access control
        if _ID_PARAM_PATTERNS.search(name_lower):
            return 1

        # High priority: common injection targets
        if any(kw in name_lower for kw in (
            "search", "query", "q", "filter", "sort", "url",
            "redirect", "callback", "next", "return", "goto",
            "file", "path", "page", "template", "include",
        )):
            return 2

        # Medium priority: user input fields
        if any(kw in name_lower for kw in (
            "name", "email", "comment", "message", "title",
            "description", "text", "content", "value", "data",
        )):
            return 4

        # Default
        return 5

    @staticmethod
    def _extract_json_params(
        obj: Any, prefix: str = "",
    ) -> list[tuple[str, Any]]:
        """Recursively extract leaf values from a JSON object."""
        params = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    params.extend(
                        TrafficAnalyzer._extract_json_params(value, full_key)
                    )
                else:
                    params.append((full_key, value))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                full_key = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    params.extend(
                        TrafficAnalyzer._extract_json_params(item, full_key)
                    )
                else:
                    params.append((full_key, item))
        return params


async def _refresh_csrf_in_body(
    url: str,
    body: str,
    cookies: dict[str, str],
    timeout: float = 15.0,
) -> str:
    """Detect CSRF fields in a request body and fetch a fresh token.

    Fetches the page at *url* via GET, scans for hidden inputs whose name
    matches ``_CSRF_FIELD_NAMES``, and substitutes the stale token value in
    *body* with the fresh one.  Falls back to the original body on any error.
    """
    if not body:
        return body

    # Quick check: does the body contain any known CSRF field name?
    body_lower = body.lower()
    csrf_field: str | None = None
    for name in _CSRF_FIELD_NAMES:
        # Match both form-encoded (name=value) and JSON ("name": "value")
        if name.lower() in body_lower:
            csrf_field = name
            break

    if csrf_field is None:
        return body  # No CSRF token detected

    try:
        import httpx as _httpx

        async with _httpx.AsyncClient(
            cookies=cookies,
            timeout=timeout,
            verify=False,
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            page = resp.text

        # Extract fresh token from the page HTML.
        # Look for <input ... name="csrf_field" ... value="TOKEN">
        # Case-insensitive search for the matching hidden input.
        pattern = re.compile(
            rf'<input[^>]*\bname=["\']?({re.escape(csrf_field)})["\']?'
            rf'[^>]*\bvalue=["\']?([^"\'>\s]+)',
            re.IGNORECASE,
        )
        match = pattern.search(page)
        if not match:
            # Try reversed attribute order: value before name
            pattern_rev = re.compile(
                rf'<input[^>]*\bvalue=["\']?([^"\'>\s]+)["\']?'
                rf'[^>]*\bname=["\']?({re.escape(csrf_field)})["\']?',
                re.IGNORECASE,
            )
            match_rev = pattern_rev.search(page)
            if match_rev:
                fresh_token = match_rev.group(1)
            else:
                # Also try meta tag (common in SPAs):
                # <meta name="csrf-token" content="TOKEN">
                meta_pattern = re.compile(
                    rf'<meta[^>]*\bname=["\']?csrf[-_]?token["\']?'
                    rf'[^>]*\bcontent=["\']?([^"\'>\s]+)',
                    re.IGNORECASE,
                )
                meta_match = meta_pattern.search(page)
                if meta_match:
                    fresh_token = meta_match.group(1)
                else:
                    return body  # Could not find fresh token
        else:
            fresh_token = match.group(2)

        if not fresh_token:
            return body

        # Replace the stale token in the body.
        # Handle form-encoded bodies: csrf_field=OLD_VALUE
        form_pattern = re.compile(
            rf'({re.escape(csrf_field)}=)([^&]*)',
            re.IGNORECASE,
        )
        if form_pattern.search(body):
            body = form_pattern.sub(rf'\g<1>{fresh_token}', body)
            logger.debug("csrf_token_refreshed", field=csrf_field, url=url)
            return body

        # Handle JSON bodies: "csrf_field": "OLD_VALUE"
        json_pattern = re.compile(
            rf'("{re.escape(csrf_field)}"\s*:\s*")([^"]*)',
            re.IGNORECASE,
        )
        if json_pattern.search(body):
            body = json_pattern.sub(rf'\g<1>{fresh_token}', body)
            logger.debug("csrf_token_refreshed_json", field=csrf_field, url=url)
            return body

    except Exception as exc:
        logger.debug("csrf_refresh_failed", error=str(exc), url=url)

    return body


class HTTPRepeater:
    """Replays HTTP requests with modifications via httpx.

    Similar to Burp Suite's Repeater — takes a captured request,
    modifies specific parameters, sends it, and returns the response
    with differential analysis.
    """

    def __init__(
        self,
        scope_guard: ActiveScopeGuard,
        default_timeout: float = 15.0,
    ) -> None:
        self._scope_guard = scope_guard
        self._timeout = default_timeout

    async def send_request(
        self,
        insertion_point: InsertionPoint,
        payload: str,
        cookies: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[ResponseSignature, str]:
        """Send a modified request and return the response signature + body.

        Args:
            insertion_point: The parameter to modify.
            payload: The value to inject.
            cookies: Session cookies for authenticated requests.
            extra_headers: Additional headers to include.

        Returns:
            Tuple of (ResponseSignature, response_body).
        """
        import httpx

        url = insertion_point.url
        method = insertion_point.method
        headers = dict(insertion_point.headers)
        body = insertion_point.body

        # Remove hop-by-hop headers that httpx manages
        for h in ("host", "content-length", "transfer-encoding", "connection"):
            headers.pop(h, None)
            # Also check case-insensitive
            for k in list(headers.keys()):
                if k.lower() == h:
                    del headers[k]

        if extra_headers:
            headers.update(extra_headers)

        # Apply the payload to the correct insertion point
        url, headers, body = self._apply_payload(
            insertion_point, payload, url, headers, body,
        )

        # Refresh CSRF tokens in the body before replay
        body = await _refresh_csrf_in_body(
            url, body, cookies or {}, self._timeout,
        )

        # Validate scope before sending
        self._scope_guard.validate_request(method, url, body)

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                cookies=cookies or {},
                timeout=self._timeout,
                verify=False,
                follow_redirects=False,
            ) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body if method != "GET" else None,
                )

            elapsed_ms = int((time.monotonic() - start) * 1000)
            resp_body = response.text[:50_000]  # Cap body size

            # Build response signature
            sig = self._build_signature(response, resp_body, elapsed_ms)
            return sig, resp_body

        except httpx.TimeoutException:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ResponseSignature(
                status_code=0,
                body_length=0,
                word_count=0,
                elapsed_ms=elapsed_ms,
                has_error=True,
                error_keywords=["timeout"],
            ), ""
        except Exception as e:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ResponseSignature(
                status_code=0,
                body_length=0,
                word_count=0,
                elapsed_ms=elapsed_ms,
                has_error=True,
                error_keywords=[str(e)[:200]],
            ), ""

    async def get_baseline(
        self,
        insertion_point: InsertionPoint,
        cookies: dict[str, str] | None = None,
    ) -> ResponseSignature:
        """Get the baseline response for an insertion point (original value)."""
        sig, _ = await self.send_request(
            insertion_point, insertion_point.original_value, cookies,
        )
        return sig

    async def test_payloads(
        self,
        insertion_point: InsertionPoint,
        payloads: list[str],
        cookies: dict[str, str] | None = None,
        baseline: ResponseSignature | None = None,
    ) -> list[dict[str, Any]]:
        """Test multiple payloads against an insertion point.

        Returns findings (deviations from baseline that indicate vulnerabilities).
        """
        if baseline is None:
            baseline = await self.get_baseline(insertion_point, cookies)

        findings: list[dict[str, Any]] = []

        for payload in payloads:
            sig, body = await self.send_request(
                insertion_point, payload, cookies,
            )

            deviation = sig.deviation_from(baseline)

            # Check for specific vulnerability indicators
            vuln_indicators = self._check_vuln_indicators(
                sig, body, payload, insertion_point,
            )

            if deviation > 0.2 or vuln_indicators:
                finding = {
                    "insertion_point": {
                        "url": insertion_point.url,
                        "method": insertion_point.method,
                        "param": insertion_point.param_name,
                        "type": insertion_point.param_type,
                    },
                    "payload": payload,
                    "deviation": deviation,
                    "baseline_status": baseline.status_code,
                    "response_status": sig.status_code,
                    "baseline_length": baseline.body_length,
                    "response_length": sig.body_length,
                    "elapsed_ms": sig.elapsed_ms,
                    "indicators": vuln_indicators,
                    "evidence": body[:2000] if vuln_indicators else "",
                }
                findings.append(finding)

                logger.info(
                    "http_test_finding",
                    url=insertion_point.url,
                    param=insertion_point.param_name,
                    payload=payload[:80],
                    deviation=f"{deviation:.2f}",
                    indicators=vuln_indicators,
                )

        return findings

    def _apply_payload(
        self,
        ip: InsertionPoint,
        payload: str,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> tuple[str, dict[str, str], str]:
        """Apply a payload to the correct position in the request."""
        if ip.param_type == "query":
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[ip.param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

        elif ip.param_type == "body":
            params = parse_qs(body, keep_blank_values=True)
            params[ip.param_name] = [payload]
            body = urlencode(params, doseq=True)

        elif ip.param_type == "json":
            try:
                json_body = json.loads(body)
                self._set_json_value(json_body, ip.param_name, payload)
                body = json.dumps(json_body)
            except (json.JSONDecodeError, TypeError):
                pass

        elif ip.param_type == "header":
            headers[ip.param_name] = payload

        elif ip.param_type == "path":
            # Replace the path segment
            parsed = urlparse(url)
            parts = parsed.path.strip("/").split("/")
            # Extract segment index from param_name (path_segment_N)
            try:
                idx = int(ip.param_name.split("_")[-1])
                if 0 <= idx < len(parts):
                    parts[idx] = payload
                    new_path = "/" + "/".join(parts)
                    url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                    if parsed.query:
                        url += f"?{parsed.query}"
            except (ValueError, IndexError):
                pass

        return url, headers, body

    @staticmethod
    def _set_json_value(obj: Any, path: str, value: str) -> None:
        """Set a value in a nested JSON object using dot-notation path."""
        parts = path.replace("[", ".[").split(".")
        current = obj
        for i, part in enumerate(parts[:-1]):
            if part.startswith("[") and part.endswith("]"):
                idx = int(part[1:-1])
                current = current[idx]
            else:
                current = current[part]

        final = parts[-1]
        if final.startswith("[") and final.endswith("]"):
            idx = int(final[1:-1])
            current[idx] = value
        else:
            current[final] = value

    @staticmethod
    def _build_signature(
        response: Any, body: str, elapsed_ms: int,
    ) -> ResponseSignature:
        """Build a ResponseSignature from an httpx response."""
        error_keywords_found = []
        error_patterns = [
            "sql syntax", "mysql", "postgresql", "sqlite", "ora-",
            "traceback", "exception", "fatal error", "stack trace",
            "internal server error", "debug", "error",
        ]
        body_lower = body.lower()
        for pattern in error_patterns:
            if pattern in body_lower:
                error_keywords_found.append(pattern)

        redirect_url = ""
        if 300 <= response.status_code < 400:
            redirect_url = str(response.headers.get("location", ""))

        return ResponseSignature(
            status_code=response.status_code,
            body_length=len(body),
            word_count=len(body.split()),
            elapsed_ms=elapsed_ms,
            has_error=bool(error_keywords_found),
            error_keywords=error_keywords_found[:5],
            redirect_url=redirect_url,
            content_type=response.headers.get("content-type", ""),
        )

    @staticmethod
    def _check_vuln_indicators(
        sig: ResponseSignature,
        body: str,
        payload: str,
        ip: InsertionPoint,
    ) -> list[str]:
        """Check for specific vulnerability indicators in the response."""
        indicators = []
        body_lower = body.lower()

        # XSS: payload reflected in response
        if payload in body:
            indicators.append("xss_reflection")
        # Check for unescaped HTML tags from payload
        if "<script" in payload.lower() and "<script" in body_lower:
            indicators.append("xss_script_reflection")

        # SQLi: database error messages
        sqli_patterns = [
            "sql syntax", "mysql", "you have an error in your sql",
            "unclosed quotation", "postgresql", "sqlite3.operational",
            "ora-", "sql server", "mariadb", "sqlstate",
            "database error", "query failed",
        ]
        for pattern in sqli_patterns:
            if pattern in body_lower and pattern not in ip.original_value.lower():
                indicators.append(f"sqli_error:{pattern}")
                break

        # Command injection: command output patterns
        cmdi_patterns = [
            "uid=", "root:", "/bin/", "windows\\system32",
            "volume serial number",
        ]
        for pattern in cmdi_patterns:
            if pattern in body_lower:
                indicators.append(f"cmdi_output:{pattern}")
                break

        # SSTI: template engine errors
        ssti_patterns = [
            "jinja2", "twig", "smarty", "freemarker",
            "velocity", "mako", "template error",
        ]
        for pattern in ssti_patterns:
            if pattern in body_lower:
                indicators.append(f"ssti:{pattern}")
                break

        # Path traversal: sensitive file content
        if any(p in body_lower for p in ("root:x:0:", "[boot loader]", "<?php")):
            indicators.append("path_traversal")

        # Open redirect
        if sig.redirect_url and payload in sig.redirect_url:
            indicators.append("open_redirect")

        # Time-based blind (>5s response when baseline was fast)
        if sig.elapsed_ms > 5000:
            indicators.append("time_based_blind")

        return indicators


class AuthzTester:
    """Tests authorization by replaying requests across privilege levels.

    Similar to Burp's Autorize extension — captures requests made by a
    privileged user and replays them with lower-privilege or no credentials.
    """

    def __init__(
        self,
        scope_guard: ActiveScopeGuard,
        timeout: float = 15.0,
    ) -> None:
        self._scope_guard = scope_guard
        self._timeout = timeout

    async def test_authorization(
        self,
        request_entry: HTTPTrafficEntry,
        privilege_levels: dict[str, dict[str, str]],
    ) -> list[dict[str, Any]]:
        """Test a request across multiple privilege levels.

        Args:
            request_entry: The original captured request.
            privilege_levels: Dict of level_name -> cookies dict.
                e.g., {"admin": {...}, "user": {...}, "anonymous": {}}

        Returns:
            At most ONE finding per endpoint, with all affected privilege
            levels consolidated into the evidence.  Returns empty list if
            the endpoint appears to be public (all levels get the same
            response, including anonymous).
        """
        import httpx

        req = request_entry.request

        # Get baseline response (original cookies)
        original_cookies = {}
        cookie_header = req.headers.get("cookie", req.headers.get("Cookie", ""))
        if cookie_header:
            for part in cookie_header.split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    original_cookies[name.strip()] = value.strip()

        # Validate scope
        try:
            self._scope_guard.validate_request(req.method, req.url, req.body)
        except Exception:
            return []

        # Send the original request to get baseline
        baseline_sig, baseline_body = await self._send(
            req.method, req.url, req.headers, req.body, original_cookies,
        )

        if baseline_sig.status_code == 0:
            return []  # Original request failed

        # Replay with each privilege level and collect per-level evidence
        affected_levels: list[str] = []
        evidence_parts: list[str] = []

        for level_name, level_cookies in privilege_levels.items():
            test_sig, test_body = await self._send(
                req.method, req.url, req.headers, req.body, level_cookies,
            )

            # Access control issue: lower privilege got same/similar response
            authz_issue = self._detect_authz_issue(
                baseline_sig, baseline_body,
                test_sig, test_body,
                level_name,
            )

            if authz_issue:
                affected_levels.append(level_name)
                evidence_parts.append(authz_issue)

        if not affected_levels:
            return []

        # If anonymous is among the affected AND ALL tested levels are
        # affected, the endpoint is public — not an access control issue.
        if ("anonymous" in affected_levels
                and len(affected_levels) >= len(privilege_levels)):
            logger.info(
                "authz_public_page_skipped",
                endpoint=req.url,
                levels=len(affected_levels),
            )
            return []

        # Consolidate into a single finding per endpoint
        finding = {
            "vuln_type": "broken_access_control",
            "endpoint": req.url,
            "method": req.method,
            "affected_levels": affected_levels,
            "original_status": baseline_sig.status_code,
            "evidence": " | ".join(evidence_parts),
            "tool_used": "authz_tester",
            "confirmed": False,
        }

        logger.info(
            "authz_finding",
            endpoint=req.url,
            method=req.method,
            levels=affected_levels,
            evidence=evidence_parts[0][:200] if evidence_parts else "",
        )

        return [finding]

    async def _send(
        self,
        method: str,
        url: str,
        original_headers: dict[str, str],
        body: str,
        cookies: dict[str, str],
    ) -> tuple[ResponseSignature, str]:
        """Send an HTTP request with given cookies."""
        import httpx

        headers = dict(original_headers)
        # Remove hop-by-hop and cookie headers (httpx manages cookies)
        for h in ("host", "content-length", "transfer-encoding",
                   "connection", "cookie", "Cookie"):
            headers.pop(h, None)
            for k in list(headers.keys()):
                if k.lower() == h.lower():
                    del headers[k]

        # Refresh CSRF tokens in the body before replay
        body = await _refresh_csrf_in_body(
            url, body, cookies, self._timeout,
        )

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                cookies=cookies,
                timeout=self._timeout,
                verify=False,
                follow_redirects=False,
            ) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body if method != "GET" else None,
                )

            elapsed_ms = int((time.monotonic() - start) * 1000)
            resp_body = response.text[:50_000]

            return HTTPRepeater._build_signature(
                response, resp_body, elapsed_ms,
            ), resp_body

        except Exception:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ResponseSignature(
                status_code=0, body_length=0, word_count=0,
                elapsed_ms=elapsed_ms, has_error=True,
            ), ""

    @staticmethod
    def _detect_authz_issue(
        baseline_sig: ResponseSignature,
        baseline_body: str,
        test_sig: ResponseSignature,
        test_body: str,
        level_name: str,
    ) -> str:
        """Detect authorization issues by comparing responses.

        Returns evidence string if an issue is found, empty string otherwise.
        """
        # If original returned 200 and test also returns 200 with similar content
        if baseline_sig.status_code == 200 and test_sig.status_code == 200:
            # Check body similarity
            baseline_len = baseline_sig.body_length
            test_len = test_sig.body_length
            if baseline_len > 0 and test_len > 0:
                len_ratio = min(baseline_len, test_len) / max(baseline_len, test_len)
                if len_ratio > 0.8:
                    # Similar length — check content similarity
                    # Use word overlap as a proxy for content similarity
                    baseline_words = set(baseline_body.split()[:200])
                    test_words = set(test_body.split()[:200])
                    if baseline_words and test_words:
                        overlap = len(baseline_words & test_words)
                        similarity = overlap / max(len(baseline_words), len(test_words))
                        if similarity > 0.7:
                            return (
                                f"{level_name} got 200 OK with {similarity:.0%} content similarity "
                                f"(baseline: {baseline_len}B, test: {test_len}B). "
                                f"Expected 401/403 for lower privilege level."
                            )

        # If original returned 200 but test returned redirect (to login)
        # that's expected — NOT an issue
        if test_sig.status_code in (401, 403):
            return ""  # Correctly denied

        # If original had data and test also has data (different status)
        if (baseline_sig.status_code == 200
                and test_sig.status_code == 200
                and baseline_sig.body_length > 500
                and test_sig.body_length > 500):
            # Both return substantial content — possible issue
            return (
                f"{level_name} received 200 OK with {test_sig.body_length}B response "
                f"(baseline: {baseline_sig.body_length}B). "
                f"Both returned substantial content."
            )

        return ""


async def get_cookies_for_account(
    browser: Any, account: TestAccount,
) -> dict[str, str]:
    """Extract cookies from a browser context for an account."""
    cookies = {}
    try:
        context_name = account.context_name
        browser_cookies = await browser.get_cookies(context_name)
        if browser_cookies and isinstance(browser_cookies, list):
            for c in browser_cookies:
                if isinstance(c, dict) and c.get("name"):
                    cookies[c["name"]] = c.get("value", "")
        elif isinstance(browser_cookies, dict):
            cookies = browser_cookies
    except Exception:
        # Fall back to account's stored cookies
        if account.cookies:
            cookies = dict(account.cookies)
    return cookies


# ── Traffic Intelligence ────────────────────────────────────────────


@dataclass
class TrafficIntelligenceReport:
    """Structured intelligence extracted from captured HTTP traffic."""

    security_header_gaps: list[dict] = field(default_factory=list)
    id_params: list[dict] = field(default_factory=list)
    price_params: list[dict] = field(default_factory=list)
    role_params: list[dict] = field(default_factory=list)
    timing_anomalies: list[dict] = field(default_factory=list)
    cookie_issues: list[dict] = field(default_factory=list)
    error_patterns: dict[str, list[str]] = field(default_factory=dict)
    csrf_analysis: dict[str, Any] = field(default_factory=dict)
    waf_detected: bool = False
    waf_type: str = ""
    tech_signals: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)

    def to_prompt_text(self, max_chars: int = 6000) -> str:
        """Compact XML-tagged output for injection into Claude prompts."""
        sections: list[str] = []

        if self.waf_detected:
            sections.append(f"<waf>{self.waf_type}</waf>")

        if self.tech_signals:
            sections.append(f"<tech_stack>{', '.join(self.tech_signals[:10])}</tech_stack>")

        if self.id_params:
            items = [f"{p['param']} at {p['endpoint']}" for p in self.id_params[:10]]
            sections.append(f"<id_params>{'; '.join(items)}</id_params>")

        if self.price_params:
            items = [f"{p['param']}={p.get('sample_value','')} at {p['endpoint']}" for p in self.price_params[:10]]
            sections.append(f"<price_params>{'; '.join(items)}</price_params>")

        if self.role_params:
            items = [f"{p['param']}={p.get('sample_value','')} at {p['endpoint']}" for p in self.role_params[:10]]
            sections.append(f"<role_params>{'; '.join(items)}</role_params>")

        if self.timing_anomalies:
            items = [f"{a['endpoint']} avg={a['avg_ms']:.0f}ms stddev={a['stddev_ms']:.0f}ms" for a in self.timing_anomalies[:5]]
            sections.append(f"<timing_anomalies>{'; '.join(items)}</timing_anomalies>")

        if self.cookie_issues:
            items = [f"{c['name']}: missing {','.join(c['missing_flags'])}" for c in self.cookie_issues[:5]]
            sections.append(f"<cookie_issues>{'; '.join(items)}</cookie_issues>")

        if self.security_header_gaps:
            items = [f"{g['endpoint']}: missing {','.join(g['missing'])}" for g in self.security_header_gaps[:5]]
            sections.append(f"<header_gaps>{'; '.join(items)}</header_gaps>")

        if self.error_patterns:
            items = []
            for endpoint, msgs in list(self.error_patterns.items())[:5]:
                items.append(f"{endpoint}: {len(msgs)} different errors")
            sections.append(f"<error_patterns>{'; '.join(items)}</error_patterns>")

        if self.csrf_analysis:
            sections.append(f"<csrf>{json.dumps(self.csrf_analysis, default=str)[:500]}</csrf>")

        if self.observations:
            sections.append("<observations>\n" + "\n".join(f"- {o}" for o in self.observations) + "\n</observations>")

        result = "\n".join(sections)
        return result[:max_chars]


_SECURITY_HEADERS = {
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
}

_ID_REGEX = re.compile(
    r"(^id$|_id$|^uid$|^user_?id|^account_?id|^profile_?id|^item_?id|^product_?id|^order_?id)",
    re.IGNORECASE,
)
_PRICE_REGEX = re.compile(
    r"(^price$|^amount$|^total$|^cost$|^quantity$|^qty$|^discount$|^subtotal$|^fee$|^rate$)",
    re.IGNORECASE,
)
_ROLE_REGEX = re.compile(
    r"(^role$|^is_admin$|^admin$|^permission$|^level$|^tier$|^plan$|^plan_id$|^group$|^type$)",
    re.IGNORECASE,
)

_WAF_SIGNATURES: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "server: cloudflare": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-apigw-id": "AWS API Gateway",
    "x-akamai-transformed": "Akamai",
    "x-mod-security": "ModSecurity",
}


class TrafficIntelligence:
    """Analyzes captured HTTP traffic to produce actionable intelligence.

    Pure Python analysis — zero API cost. Turns 200+ raw HTTP flows
    into structured intelligence that Claude can reason about.
    """

    def __init__(self, scope_guard: ActiveScopeGuard) -> None:
        self._scope_guard = scope_guard

    def analyze(self, traffic: list[HTTPTrafficEntry]) -> TrafficIntelligenceReport:
        """Run all analyses on captured traffic."""
        report = TrafficIntelligenceReport()
        if not traffic:
            return report

        self._detect_waf(traffic, report)
        self._detect_tech_stack(traffic, report)
        self._analyze_security_headers(traffic, report)
        self._classify_parameters(traffic, report)
        self._analyze_timing(traffic, report)
        self._analyze_cookies(traffic, report)
        self._analyze_errors(traffic, report)
        self._analyze_csrf(traffic, report)
        self._generate_observations(report)

        logger.info(
            "traffic_intelligence_computed",
            observations=len(report.observations),
            id_params=len(report.id_params),
            price_params=len(report.price_params),
            timing_anomalies=len(report.timing_anomalies),
            waf=report.waf_type or "none",
        )
        return report

    # ── Individual analysis methods ─────────────────────────────────

    def _detect_waf(self, traffic: list[HTTPTrafficEntry], report: TrafficIntelligenceReport) -> None:
        for entry in traffic[:50]:
            resp_headers = entry.response.headers
            for hdr_key, hdr_val in resp_headers.items():
                key_lower = hdr_key.lower()
                # Check header name
                if key_lower in _WAF_SIGNATURES:
                    report.waf_detected = True
                    report.waf_type = _WAF_SIGNATURES[key_lower]
                    return
                # Check header name:value combos
                combo = f"{key_lower}: {hdr_val.lower()}"
                for sig, waf_name in _WAF_SIGNATURES.items():
                    if sig in combo:
                        report.waf_detected = True
                        report.waf_type = waf_name
                        return
            # Check response body for WAF block pages
            body_lower = entry.response.body[:2000].lower() if entry.response.body else ""
            if "cloudflare" in body_lower and ("ray id" in body_lower or "cf-ray" in body_lower):
                report.waf_detected = True
                report.waf_type = "Cloudflare"
                return

    def _detect_tech_stack(self, traffic: list[HTTPTrafficEntry], report: TrafficIntelligenceReport) -> None:
        signals: set[str] = set()
        for entry in traffic[:100]:
            resp_headers = entry.response.headers
            # Server header
            server = resp_headers.get("server", resp_headers.get("Server", ""))
            if server:
                signals.add(f"Server: {server}")
            # X-Powered-By
            powered = resp_headers.get("x-powered-by", resp_headers.get("X-Powered-By", ""))
            if powered:
                signals.add(f"X-Powered-By: {powered}")
            # Cookie names reveal framework
            for hdr_key, hdr_val in resp_headers.items():
                if hdr_key.lower() == "set-cookie":
                    cookie_lower = hdr_val.lower()
                    if "laravel_session" in cookie_lower:
                        signals.add("Laravel (PHP)")
                    elif "xsrf-token" in cookie_lower:
                        signals.add("Laravel/Angular XSRF")
                    elif "asp.net" in cookie_lower:
                        signals.add("ASP.NET")
                    elif "jsessionid" in cookie_lower:
                        signals.add("Java (Servlet)")
                    elif "connect.sid" in cookie_lower:
                        signals.add("Express.js (Node)")
                    elif "phpsessid" in cookie_lower:
                        signals.add("PHP")
                    elif "django" in cookie_lower or "csrftoken" in cookie_lower:
                        signals.add("Django (Python)")
            # Response body tech signals
            body = entry.response.body[:5000] if entry.response.body else ""
            if "livewire" in body.lower():
                signals.add("Livewire (Laravel)")
            if "window.__NEXT_DATA__" in body:
                signals.add("Next.js")
            if "window.__NUXT__" in body:
                signals.add("Nuxt.js")
            if "_token" in body and "csrf" in body.lower():
                signals.add("Laravel CSRF")
        report.tech_signals = sorted(signals)

    def _analyze_security_headers(self, traffic: list[HTTPTrafficEntry], report: TrafficIntelligenceReport) -> None:
        # Check unique endpoints for missing security headers
        seen_endpoints: set[str] = set()
        for entry in traffic:
            path = urlparse(entry.request.url).path
            if path in seen_endpoints:
                continue
            seen_endpoints.add(path)
            if entry.response.status != 200:
                continue

            resp_lower = {k.lower(): v for k, v in entry.response.headers.items()}
            missing = [h for h in _SECURITY_HEADERS if h not in resp_lower]
            if missing:
                report.security_header_gaps.append({
                    "endpoint": path,
                    "missing": missing,
                })
            if len(report.security_header_gaps) >= 10:
                break

    def _classify_parameters(self, traffic: list[HTTPTrafficEntry], report: TrafficIntelligenceReport) -> None:
        seen: set[str] = set()
        for entry in traffic:
            path = urlparse(entry.request.url).path
            # Gather params from query string and body
            params: dict[str, str] = {}
            qs = parse_qs(urlparse(entry.request.url).query)
            for k, vals in qs.items():
                params[k] = vals[0] if vals else ""
            # Parse body params
            if entry.request.body and entry.request.content_type:
                ct = entry.request.content_type.lower()
                if "form" in ct:
                    body_qs = parse_qs(entry.request.body)
                    for k, vals in body_qs.items():
                        params[k] = vals[0] if vals else ""
                elif "json" in ct:
                    try:
                        body_json = json.loads(entry.request.body)
                        if isinstance(body_json, dict):
                            for k, v in body_json.items():
                                params[k] = str(v) if v is not None else ""
                    except (json.JSONDecodeError, ValueError):
                        pass

            for param_name, param_value in params.items():
                key = f"{path}:{param_name}"
                if key in seen:
                    continue
                seen.add(key)

                item = {"param": param_name, "endpoint": path, "method": entry.request.method, "sample_value": param_value[:100]}

                if _ID_REGEX.search(param_name):
                    report.id_params.append(item)
                elif _PRICE_REGEX.search(param_name):
                    report.price_params.append(item)
                elif _ROLE_REGEX.search(param_name):
                    report.role_params.append(item)

    def _analyze_timing(self, traffic: list[HTTPTrafficEntry], report: TrafficIntelligenceReport) -> None:
        from statistics import mean, stdev

        # Group by endpoint path
        endpoint_times: dict[str, list[int]] = {}
        for entry in traffic:
            path = urlparse(entry.request.url).path
            if entry.duration_ms > 0:
                endpoint_times.setdefault(path, []).append(entry.duration_ms)

        for path, times in endpoint_times.items():
            if len(times) < 2:
                continue
            avg = mean(times)
            sd = stdev(times) if len(times) > 1 else 0
            # Flag if stddev > 3x average (high variance = potential blind injection)
            if sd > avg * 3 and avg > 100:
                report.timing_anomalies.append({
                    "endpoint": path,
                    "avg_ms": avg,
                    "stddev_ms": sd,
                    "sample_count": len(times),
                })
            # Also flag very slow endpoints
            elif avg > 2000:
                report.timing_anomalies.append({
                    "endpoint": path,
                    "avg_ms": avg,
                    "stddev_ms": sd,
                    "sample_count": len(times),
                })

    def _analyze_cookies(self, traffic: list[HTTPTrafficEntry], report: TrafficIntelligenceReport) -> None:
        seen_cookies: set[str] = set()
        for entry in traffic:
            for hdr_key, hdr_val in entry.response.headers.items():
                if hdr_key.lower() != "set-cookie":
                    continue
                # Parse cookie name
                cookie_name = hdr_val.split("=")[0].strip() if "=" in hdr_val else ""
                if not cookie_name or cookie_name in seen_cookies:
                    continue
                seen_cookies.add(cookie_name)

                val_lower = hdr_val.lower()
                missing_flags: list[str] = []
                if "httponly" not in val_lower:
                    missing_flags.append("HttpOnly")
                if "secure" not in val_lower:
                    missing_flags.append("Secure")
                if "samesite" not in val_lower:
                    missing_flags.append("SameSite")
                if missing_flags:
                    report.cookie_issues.append({
                        "name": cookie_name,
                        "missing_flags": missing_flags,
                        "endpoint": urlparse(entry.request.url).path,
                    })

    def _analyze_errors(self, traffic: list[HTTPTrafficEntry], report: TrafficIntelligenceReport) -> None:
        # Group error responses by endpoint to find enumeration vectors
        endpoint_errors: dict[str, set[str]] = {}
        for entry in traffic:
            if entry.response.status in (400, 401, 403, 404, 422, 500):
                path = urlparse(entry.request.url).path
                # Extract error message
                body = entry.response.body[:500] if entry.response.body else ""
                if body:
                    # Try JSON error
                    try:
                        err_json = json.loads(body)
                        msg = err_json.get("message", err_json.get("error", ""))
                        if isinstance(msg, str) and msg:
                            endpoint_errors.setdefault(path, set()).add(msg[:200])
                            continue
                    except (json.JSONDecodeError, ValueError, AttributeError):
                        pass
                    # Use first line as a fallback
                    first_line = body.split("\n")[0][:200].strip()
                    if first_line:
                        endpoint_errors.setdefault(path, set()).add(first_line)

        # Only report endpoints with >1 distinct error (= enumeration)
        for path, msgs in endpoint_errors.items():
            if len(msgs) > 1:
                report.error_patterns[path] = sorted(msgs)

    def _analyze_csrf(self, traffic: list[HTTPTrafficEntry], report: TrafficIntelligenceReport) -> None:
        csrf_tokens: list[str] = []
        csrf_field_name = ""
        for entry in traffic:
            body = entry.request.body or ""
            for field_name in _CSRF_FIELD_NAMES:
                if field_name in body:
                    # Extract token value
                    try:
                        parsed = parse_qs(body)
                        if field_name in parsed:
                            csrf_field_name = field_name
                            csrf_tokens.append(parsed[field_name][0])
                    except Exception:
                        pass

        if csrf_tokens:
            unique = set(csrf_tokens)
            report.csrf_analysis = {
                "field_name": csrf_field_name,
                "total_seen": len(csrf_tokens),
                "unique_values": len(unique),
                "tokens_rotate": len(unique) > 1,
                "sample_length": len(csrf_tokens[0]),
            }

    def _generate_observations(self, report: TrafficIntelligenceReport) -> None:
        """Generate human-readable bug-hunter insights."""
        obs: list[str] = []

        if report.waf_detected:
            obs.append(f"WAF detected: {report.waf_type}. Use encoding/obfuscation for injection payloads.")

        for p in report.price_params[:3]:
            obs.append(f"POST {p['endpoint']} has `{p['param']}` param (value: {p.get('sample_value','')}) — test price/quantity manipulation.")

        for p in report.id_params[:3]:
            obs.append(f"{p['method']} {p['endpoint']} has `{p['param']}` (value: {p.get('sample_value','')}) — test IDOR by incrementing/decrementing.")

        for p in report.role_params[:3]:
            obs.append(f"{p['method']} {p['endpoint']} has `{p['param']}`={p.get('sample_value','')} — test privilege escalation by changing value.")

        for endpoint, msgs in list(report.error_patterns.items())[:2]:
            obs.append(f"{endpoint} returns {len(msgs)} different error messages — possible enumeration vector.")

        if report.csrf_analysis:
            if not report.csrf_analysis.get("tokens_rotate"):
                obs.append(f"CSRF tokens ({report.csrf_analysis.get('field_name','')}) are STATIC across requests — token reuse possible.")
            else:
                obs.append(f"CSRF tokens rotate ({report.csrf_analysis.get('unique_values',0)} unique values seen).")

        for c in report.cookie_issues[:2]:
            obs.append(f"Cookie `{c['name']}` missing {', '.join(c['missing_flags'])} flags.")

        for a in report.timing_anomalies[:2]:
            obs.append(f"{a['endpoint']} has high timing variance (avg {a['avg_ms']:.0f}ms, stddev {a['stddev_ms']:.0f}ms) — possible blind injection target.")

        if report.tech_signals:
            obs.append(f"Tech stack: {', '.join(report.tech_signals[:5])}.")

        report.observations = obs[:12]
