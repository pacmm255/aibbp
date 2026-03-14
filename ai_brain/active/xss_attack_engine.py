"""Automated XSS vulnerability detection engine.

Zero LLM cost — pure deterministic HTTP testing.
Covers reflected (HTML body, attribute, JS context), stored, DOM-based, mXSS,
filter bypass, browser-specific, framework-specific, and nonstandard XSS
across 14 injection contexts with canary-based context detection and
CSP-aware severity classification.

Key CVE references:
- CVE-2020-26870, CVE-2019-16728 (DOMPurify bypass)
- CVE-2020-11022, CVE-2020-11023 (jQuery HTML injection)
- CVE-2020-6418 (Chrome V8 type confusion, exploited in-the-wild)
- CVE-2021-41184 (jQuery UI XSS)
- CVE-2023-29489 (cPanel reflected XSS, 1.4M servers)
- CVE-2024-21388 (Microsoft Edge extension install XSS)
- CVE-2024-4367 (PDF.js arbitrary JS execution)

Bounty references:
- PayPal $20,000 (stored XSS in checkout flow)
- Tesla $10,000 (reflected XSS in energy portal)
- Google $7,500 (DOM XSS in Google Maps)
- Shopify $5,000 (stored XSS in admin panel)
- HackerOne $3,000–$10,000 (various XSS in customer portals)
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from ai_brain.active.deterministic_tools import _make_client
from ai_brain.active.scope_guard import ActiveScopeGuard

logger = structlog.get_logger()

# Non-resolving attacker domain for payload generation — safe for detection.
_EVIL_DOMAIN = "evil.example.com"

# Canary prefix for context detection — unlikely to appear in normal responses.
_CANARY_PREFIX = "xSsC4n4ry"

# All injection contexts recognised by the engine.
_SUPPORTED_CONTEXTS = (
    "html_body",
    "attr_double",
    "attr_single",
    "attr_unquoted",
    "event_handler",
    "js_string_single",
    "js_string_double",
    "js_template_literal",
    "json_in_html",
    "html_comment",
    "svg_context",
    "mathml_context",
    "css_context",
    "url_context",
    "no_reflection",
)


def _make_xss_client(socks_proxy: str | None = None) -> httpx.AsyncClient:
    """Create an httpx client for XSS testing (follows redirects)."""
    return _make_client(
        socks_proxy=socks_proxy,
        timeout=15,
        follow_redirects=True,
    )


class XSSAttackEngine:
    """Automated XSS vulnerability detection. $0 LLM cost.

    Tests payloads across 10 categories (reflected HTML body, reflected
    attribute, reflected JS context, stored XSS, DOM XSS, mXSS, filter bypass,
    browser-specific, framework-specific, nonstandard) with canary-based
    injection context detection and CSP-aware severity scoring.
    """

    _SUPPORTED_CONTEXTS = _SUPPORTED_CONTEXTS

    # ── CVE mapping per technique category ────────────────────────────

    _CVE_MAP: dict[str, list[str]] = {
        "reflected_html_body": [
            "CVE-2023-29489",  # cPanel reflected XSS (1.4M servers)
        ],
        "reflected_attribute": [
            "CVE-2024-21388",  # MS Edge extension install XSS
        ],
        "reflected_js_context": [
            "CVE-2024-4367",   # PDF.js arbitrary JS execution
        ],
        "stored_xss": [
            "CVE-2021-41184",  # jQuery UI XSS
        ],
        "dom_xss": [
            "CVE-2020-11022",  # jQuery <3.5.0 HTML injection
            "CVE-2020-11023",  # jQuery <3.5.0 HTML injection
            "CVE-2020-6418",   # Chrome V8 type confusion
        ],
        "mxss": [
            "CVE-2020-26870",  # DOMPurify bypass
            "CVE-2019-16728",  # DOMPurify bypass
        ],
        "filter_bypass": [
            "CVE-2020-26870",  # DOMPurify bypass
            "CVE-2019-16728",  # DOMPurify bypass
        ],
        "framework_specific": [
            "CVE-2020-11022",  # jQuery <3.5.0
            "CVE-2020-11023",  # jQuery <3.5.0
            "CVE-2021-41184",  # jQuery UI
            "CVE-2024-4367",   # PDF.js
        ],
        "browser_specific": [
            "CVE-2020-6418",   # Chrome V8 type confusion
            "CVE-2024-21388",  # MS Edge extension XSS
        ],
        "nonstandard_xss": [],
    }

    # ── Bounty references ─────────────────────────────────────────────

    _BOUNTY_REFERENCES: dict[str, list[dict[str, Any]]] = {
        "reflected_html_body": [
            {
                "target": "Tesla",
                "amount": 10_000,
                "technique_used": "Reflected XSS",
                "source": "Bugcrowd",
            },
        ],
        "stored_xss": [
            {
                "target": "PayPal",
                "amount": 20_000,
                "technique_used": "Stored XSS in checkout flow",
                "source": "HackerOne",
            },
            {
                "target": "Shopify",
                "amount": 5_000,
                "technique_used": "Stored XSS in admin panel",
                "source": "HackerOne",
            },
        ],
        "dom_xss": [
            {
                "target": "Google",
                "amount": 7_500,
                "technique_used": "DOM XSS in Google Maps",
                "source": "Google VRP",
            },
        ],
    }

    # ── Severity mapping per context ──────────────────────────────────

    _SEVERITY_MAP: dict[str, str] = {
        "stored_xss": "critical",
        "dom_xss": "high",
        "mxss": "high",
        "reflected_html_body": "high",
        "reflected_attribute": "medium",
        "reflected_js_context": "high",
        "filter_bypass": "high",
        "framework_specific": "high",
        "browser_specific": "medium",
        "nonstandard_xss": "medium",
    }

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        rate_delay: float = 0.3,
        scope_domains: list[str] | None = None,
        scope_guard: ActiveScopeGuard | None = None,
        socks_proxy: str | None = None,
    ) -> None:
        self._client = client
        self._rate_delay = rate_delay
        self._scope_domains = scope_domains
        self._scope_guard = scope_guard
        self._socks_proxy = socks_proxy
        self._request_count = 0

    # ── Scope check ───────────────────────────────────────────────────

    def _in_scope(self, url: str) -> bool:
        """Check if a URL is in scope via scope_guard or domain whitelist."""
        if self._scope_guard:
            return self._scope_guard.is_in_scope(url)
        if self._scope_domains:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower().strip(".")
            return any(
                hostname == d or hostname.endswith("." + d)
                for d in self._scope_domains
            )
        # No scope constraints — allow all (testing/development mode).
        return True

    # ── Rate-limited HTTP sender ──────────────────────────────────────

    async def _send(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response | None:
        """Send an HTTP request with rate limiting and error handling."""
        if not self._in_scope(url):
            logger.warning("xss_scope_violation", url=url[:120])
            return None
        self._request_count += 1
        await asyncio.sleep(self._rate_delay)
        try:
            if self._client:
                return await self._client.request(method, url, **kwargs)
            async with _make_xss_client(self._socks_proxy) as client:
                return await client.request(method, url, **kwargs)
        except Exception as e:
            logger.debug(
                "xss_request_error", url=url[:120], error=str(e)[:100],
            )
            return None

    # ── Canary generation ─────────────────────────────────────────────

    @staticmethod
    def _generate_canary(url: str, param: str) -> str:
        """Generate a unique canary string for a URL+param combination.

        The canary is deterministic (same inputs produce same output) so
        repeated scans of the same endpoint can be correlated.
        """
        h = hashlib.md5(f"{url}:{param}".encode(), usedforsecurity=False)
        return f"{_CANARY_PREFIX}{h.hexdigest()[:12]}"

    # ── Context detection ─────────────────────────────────────────────

    def _detect_context(
        self, response_body: str, canary: str
    ) -> list[str]:
        """Determine injection contexts from where the canary reflects.

        Returns a list of context strings (one or more from
        ``_SUPPORTED_CONTEXTS``) describing every location where the
        canary appears in the response.  Returns ``["no_reflection"]``
        if the canary is absent.
        """
        if canary not in response_body:
            return ["no_reflection"]

        contexts: list[str] = []

        # --- HTML comment: <!-- ... canary ... --> ---
        for m in re.finditer(r"<!--(.*?)-->", response_body, re.DOTALL):
            if canary in m.group(1):
                contexts.append("html_comment")
                break

        # --- <script type="application/json"> ... canary ... </script> ---
        for m in re.finditer(
            r'<script[^>]*type\s*=\s*["\']application/json["\'][^>]*>'
            r"(.*?)</script>",
            response_body,
            re.DOTALL | re.IGNORECASE,
        ):
            if canary in m.group(1):
                contexts.append("json_in_html")
                break

        # --- SVG context ---
        for m in re.finditer(
            r"<svg[\s>](.*?)</svg>", response_body, re.DOTALL | re.IGNORECASE
        ):
            if canary in m.group(1):
                contexts.append("svg_context")
                break

        # --- MathML context ---
        for m in re.finditer(
            r"<math[\s>](.*?)</math>",
            response_body,
            re.DOTALL | re.IGNORECASE,
        ):
            if canary in m.group(1):
                contexts.append("mathml_context")
                break

        # --- CSS context: <style> or style="" ---
        for m in re.finditer(
            r"<style[^>]*>(.*?)</style>",
            response_body,
            re.DOTALL | re.IGNORECASE,
        ):
            if canary in m.group(1):
                contexts.append("css_context")
                break
        if "css_context" not in contexts:
            for m in re.finditer(
                r'style\s*=\s*["\']([^"\']*)',
                response_body,
                re.IGNORECASE,
            ):
                if canary in m.group(1):
                    contexts.append("css_context")
                    break

        # --- URL context: href= or src= ---
        for m in re.finditer(
            r'(?:href|src|action)\s*=\s*["\']([^"\']*)',
            response_body,
            re.IGNORECASE,
        ):
            if canary in m.group(1):
                contexts.append("url_context")
                break

        # --- Event handler: onXxx="...canary..." ---
        if re.search(
            r"on\w+\s*=\s*[\"']?[^\"'>]*" + re.escape(canary),
            response_body,
            re.IGNORECASE,
        ):
            contexts.append("event_handler")

        # --- JS template literal: `...canary...` inside <script> ---
        for m in re.finditer(
            r"<script[^>]*>(.*?)</script>",
            response_body,
            re.DOTALL | re.IGNORECASE,
        ):
            js_block = m.group(1)
            if canary not in js_block:
                continue
            # Template literal detection (backtick-delimited)
            if re.search(r"`[^`]*" + re.escape(canary) + r"[^`]*`", js_block):
                contexts.append("js_template_literal")
                break
            # Single-quoted JS string
            if re.search(r"'[^']*" + re.escape(canary) + r"[^']*'", js_block):
                contexts.append("js_string_single")
            # Double-quoted JS string
            if re.search(r'"[^"]*' + re.escape(canary) + r'[^"]*"', js_block):
                contexts.append("js_string_double")

        # --- Attribute contexts (non-event, non-URL, non-style) ---
        # Only check if not already captured by a more specific context.
        attr_contexts = {
            "event_handler", "url_context", "css_context",
        }
        if not (attr_contexts & set(contexts)):
            # Double-quoted attribute
            if re.search(
                r'=\s*"[^"]*' + re.escape(canary) + r'[^"]*"',
                response_body,
            ):
                contexts.append("attr_double")
            # Single-quoted attribute
            if re.search(
                r"=\s*'[^']*" + re.escape(canary) + r"[^']*'",
                response_body,
            ):
                contexts.append("attr_single")
            # Unquoted attribute
            if re.search(
                r"=\s*" + re.escape(canary) + r"[\s>]",
                response_body,
            ):
                contexts.append("attr_unquoted")

        # --- HTML body (between tags) ---
        # Strip all tags and check if canary is in text content.
        text_only = re.sub(r"<[^>]+>", " ", response_body)
        if canary in text_only and not contexts:
            # Canary is in body text but not captured by any specific context.
            contexts.append("html_body")

        # If the canary is reflected but no specific context matched,
        # default to html_body.
        if not contexts:
            contexts.append("html_body")

        # Deduplicate while preserving order.
        seen: set[str] = set()
        unique: list[str] = []
        for c in contexts:
            if c not in seen:
                seen.add(c)
                unique.append(c)
        return unique

    # ── Reflection check ──────────────────────────────────────────────

    @staticmethod
    def _check_reflection(response_body: str, payload: str) -> bool:
        """Check if a payload appears unencoded in the response body.

        A positive result indicates the server does not sanitise or encode
        the payload, making XSS exploitation likely.
        """
        if not payload or not response_body:
            return False
        return payload in response_body

    # ── CSP parser ────────────────────────────────────────────────────

    @staticmethod
    def _parse_csp(headers: httpx.Headers) -> dict[str, list[str]]:
        """Extract and parse CSP directives from response headers.

        Returns a dict mapping directive names to their value lists, e.g.
        ``{"default-src": ["'self'"], "script-src": ["'nonce-abc'", "'self'"]}``.
        If no CSP header is present, returns an empty dict.
        """
        raw = headers.get("content-security-policy", "")
        if not raw:
            # Also check the report-only variant.
            raw = headers.get("content-security-policy-report-only", "")
        if not raw:
            return {}

        directives: dict[str, list[str]] = {}
        for part in raw.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if not tokens:
                continue
            name = tokens[0].lower()
            values = tokens[1:]
            directives[name] = values
        return directives

    # ── Severity classifier ───────────────────────────────────────────

    @staticmethod
    def _classify_severity(technique: str, context: str | None = None) -> str:
        """Classify finding severity based on technique and injection context.

        Returns: ``"critical"``, ``"high"``, ``"medium"``, or ``"low"``.
        """
        # Stored XSS is always critical (fires on other users).
        if technique == "stored_xss":
            return "critical"

        # DOM XSS and mXSS are high — often bypass server-side sanitisation.
        if technique in ("dom_xss", "mxss"):
            return "high"

        # Context-aware escalation for reflected XSS:
        if context in (
            "html_body", "js_string_single", "js_string_double",
            "js_template_literal", "event_handler",
        ):
            return "high"

        if context in (
            "attr_double", "attr_single", "attr_unquoted",
            "svg_context", "mathml_context",
        ):
            return "medium"

        if context in ("html_comment", "css_context", "json_in_html"):
            return "low"

        # Default per-technique mapping.
        return XSSAttackEngine._SEVERITY_MAP.get(technique, "medium")

    # ── CVE lookup ────────────────────────────────────────────────────

    def _related_cves(self, technique: str) -> list[str]:
        """Return related CVE identifiers for a technique category."""
        return list(self._CVE_MAP.get(technique, []))

    # ── Finding builder helper ────────────────────────────────────────

    def _make_finding(
        self,
        *,
        vulnerable: bool,
        technique: str,
        description: str,
        payload: str = "",
        response_status: int | None = None,
        evidence: str = "",
        injection_context: str = "",
        csp: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        """Build a standardised finding dict."""
        severity = self._classify_severity(technique, injection_context)
        finding: dict[str, Any] = {
            "vulnerable": vulnerable,
            "technique": technique,
            "description": description,
            "payload": payload,
            "response_status": response_status,
            "severity": severity,
            "evidence": evidence,
            "cves": self._related_cves(technique),
            "injection_context": injection_context,
        }
        if csp is not None:
            finding["csp"] = csp
        return finding

    # ══════════════════════════════════════════════════════════════════
    # Test method stubs — to be implemented by other units.
    # Each returns a list of finding dicts.
    # ══════════════════════════════════════════════════════════════════

    async def test_reflected_html_body(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        """Test reflected XSS in HTML body context (between tags).

        Stub — returns empty list until implemented.
        """
        return []

    async def test_reflected_attribute(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        """Test reflected XSS in HTML attribute context.

        Stub — returns empty list until implemented.
        """
        return []

    async def test_reflected_js_context(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        """Test reflected XSS in JavaScript string/template literal context.

        Stub — returns empty list until implemented.
        """
        return []

    async def test_stored_xss(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        """Test stored (persistent) XSS.

        Stub — returns empty list until implemented.
        """
        return []

    async def test_dom_xss(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        """Test DOM-based XSS via client-side source/sink analysis.

        Stub — returns empty list until implemented.
        """
        return []

    async def test_mxss(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        """Test mutation XSS (mXSS) via browser HTML re-parsing.

        Stub — returns empty list until implemented.
        """
        return []

    async def test_filter_bypass(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        """Test XSS filter/WAF bypass techniques.

        Stub — returns empty list until implemented.
        """
        return []

    async def test_browser_specific(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        """Test browser-specific XSS vectors (IE, Edge legacy, etc.).

        Stub — returns empty list until implemented.
        """
        return []

    async def test_framework_specific(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        """Test framework-specific XSS (Angular, React, Vue, jQuery).

        Stub — returns empty list until implemented.
        """
        return []

    async def test_nonstandard_xss(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        """Test nonstandard XSS vectors (polyglot, content-type tricks, etc.).

        Stub — returns empty list until implemented.
        """
        return []

    # ══════════════════════════════════════════════════════════════════
    # Payload builder stubs — to be implemented by other units.
    # ══════════════════════════════════════════════════════════════════

    def _build_html_body_payloads(self) -> list[str]:
        """Build payloads for HTML body injection context.

        Stub — returns empty list until implemented.
        """
        return []

    def _build_attribute_payloads(self) -> list[str]:
        """Build payloads for HTML attribute injection context.

        Stub — returns empty list until implemented.
        """
        return []

    def _build_js_context_payloads(self) -> list[str]:
        """Build payloads for JavaScript context injection.

        Stub — returns empty list until implemented.
        """
        return []

    def _build_stored_payloads(self) -> list[str]:
        """Build payloads for stored XSS testing.

        Stub — returns empty list until implemented.
        """
        return []

    def _build_dom_payloads(self) -> list[str]:
        """Build payloads for DOM XSS testing.

        Stub — returns empty list until implemented.
        """
        return []

    def _build_mxss_payloads(self) -> list[str]:
        """Build payloads for mutation XSS testing.

        Stub — returns empty list until implemented.
        """
        return []

    def _build_filter_bypass_payloads(self) -> list[str]:
        """Build payloads for filter/WAF bypass testing.

        Stub — returns empty list until implemented.
        """
        return []

    def _build_nonstandard_payloads(self) -> list[str]:
        """Build payloads for nonstandard XSS testing.

        Stub — returns empty list until implemented.
        """
        return []

    # ══════════════════════════════════════════════════════════════════
    # Main orchestrator
    # ══════════════════════════════════════════════════════════════════

    async def full_scan(
        self,
        url: str,
        method: str = "GET",
        param: str | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Run all XSS test categories against a target parameter.

        Sends a canary first to detect injection context, then dispatches
        to the relevant test methods based on context.

        Args:
            url: Target URL to test.
            method: HTTP method (GET or POST).
            param: Primary parameter name to inject into.
            params: Additional query/body parameters to include.

        Returns:
            Consolidated results dict with findings per category.
        """
        start_time = time.monotonic()
        self._request_count = 0

        result: dict[str, Any] = {
            "target": url,
            "method": method,
            "param": param,
            "reflected_html_body": [],
            "reflected_attribute": [],
            "reflected_js_context": [],
            "stored_xss": [],
            "dom_xss": [],
            "mxss": [],
            "filter_bypass": [],
            "browser_specific": [],
            "framework_specific": [],
            "nonstandard_xss": [],
            "detected_contexts": [],
            "csp": {},
            "total_payloads_tested": 0,
            "vulnerabilities_found": 0,
            "total_requests": 0,
            "scan_duration_seconds": 0,
        }

        if not param:
            result["error"] = (
                "No parameter specified for injection testing. "
                "Provide param= to target a specific query/body parameter."
            )
            return result

        if not self._in_scope(url):
            result["error"] = f"URL not in scope: {url[:120]}"
            return result

        logger.info(
            "xss_scan_start",
            target=url[:80],
            method=method,
            param=param,
        )

        # ── Phase 1: Canary injection for context detection ───────────

        canary = self._generate_canary(url, param)
        canary_params = dict(params or {})
        canary_params[param] = canary

        if method.upper() == "GET":
            canary_resp = await self._send("GET", url, params=canary_params)
        else:
            canary_resp = await self._send("POST", url, data=canary_params)

        detected_contexts: list[str] = ["no_reflection"]
        csp: dict[str, list[str]] = {}

        if canary_resp is not None:
            detected_contexts = self._detect_context(canary_resp.text, canary)
            csp = self._parse_csp(canary_resp.headers)

        result["detected_contexts"] = detected_contexts
        result["csp"] = csp

        if detected_contexts == ["no_reflection"]:
            logger.info(
                "xss_no_reflection",
                target=url[:80],
                param=param,
            )
            # Still run DOM XSS and stored XSS — they don't need reflection.
            test_methods: list[tuple[str, Any]] = [
                ("dom_xss", self.test_dom_xss),
                ("stored_xss", self.test_stored_xss),
            ]
        else:
            # ── Phase 2: Context-aware test dispatch ──────────────────
            test_methods = self._select_tests_for_contexts(detected_contexts)

        # ── Phase 3: Run selected tests ───────────────────────────────

        total_payloads = 0
        vuln_count = 0

        for category, test_fn in test_methods:
            try:
                findings = await test_fn(url, method, param, params)
                result[category] = findings
                for f in findings:
                    total_payloads += 1
                    if f.get("vulnerable"):
                        vuln_count += 1
            except Exception as exc:
                logger.warning(
                    "xss_test_error",
                    category=category,
                    error=str(exc)[:200],
                )

        result["total_payloads_tested"] = total_payloads
        result["vulnerabilities_found"] = vuln_count
        result["total_requests"] = self._request_count
        result["scan_duration_seconds"] = round(
            time.monotonic() - start_time, 1,
        )

        logger.info(
            "xss_scan_complete",
            target=url[:80],
            findings=vuln_count,
            payloads_tested=total_payloads,
            requests=self._request_count,
            duration=result["scan_duration_seconds"],
            contexts=detected_contexts,
        )

        return result

    # ── Context-to-test mapping ───────────────────────────────────────

    def _select_tests_for_contexts(
        self, contexts: list[str]
    ) -> list[tuple[str, Any]]:
        """Map detected injection contexts to the appropriate test methods.

        Always includes stored XSS and DOM XSS regardless of context,
        then adds reflected tests based on where the canary was found.
        """
        tests: list[tuple[str, Any]] = []
        added: set[str] = set()

        # Context-specific reflected tests.
        context_map: dict[str, list[tuple[str, Any]]] = {
            "html_body": [
                ("reflected_html_body", self.test_reflected_html_body),
            ],
            "attr_double": [
                ("reflected_attribute", self.test_reflected_attribute),
            ],
            "attr_single": [
                ("reflected_attribute", self.test_reflected_attribute),
            ],
            "attr_unquoted": [
                ("reflected_attribute", self.test_reflected_attribute),
            ],
            "event_handler": [
                ("reflected_attribute", self.test_reflected_attribute),
                ("reflected_js_context", self.test_reflected_js_context),
            ],
            "js_string_single": [
                ("reflected_js_context", self.test_reflected_js_context),
            ],
            "js_string_double": [
                ("reflected_js_context", self.test_reflected_js_context),
            ],
            "js_template_literal": [
                ("reflected_js_context", self.test_reflected_js_context),
            ],
            "json_in_html": [
                ("reflected_js_context", self.test_reflected_js_context),
            ],
            "html_comment": [
                ("reflected_html_body", self.test_reflected_html_body),
            ],
            "svg_context": [
                ("reflected_html_body", self.test_reflected_html_body),
                ("nonstandard_xss", self.test_nonstandard_xss),
            ],
            "mathml_context": [
                ("reflected_html_body", self.test_reflected_html_body),
                ("nonstandard_xss", self.test_nonstandard_xss),
            ],
            "css_context": [
                ("nonstandard_xss", self.test_nonstandard_xss),
            ],
            "url_context": [
                ("reflected_attribute", self.test_reflected_attribute),
                ("nonstandard_xss", self.test_nonstandard_xss),
            ],
        }

        for ctx in contexts:
            for pair in context_map.get(ctx, []):
                if pair[0] not in added:
                    tests.append(pair)
                    added.add(pair[0])

        # Always run these regardless of context.
        always_run: list[tuple[str, Any]] = [
            ("stored_xss", self.test_stored_xss),
            ("dom_xss", self.test_dom_xss),
            ("mxss", self.test_mxss),
            ("filter_bypass", self.test_filter_bypass),
            ("browser_specific", self.test_browser_specific),
            ("framework_specific", self.test_framework_specific),
        ]
        for pair in always_run:
            if pair[0] not in added:
                tests.append(pair)
                added.add(pair[0])

        return tests
