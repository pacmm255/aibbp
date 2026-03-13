"""Tool dispatch router for the single-brain ReAct pentesting agent.

Routes brain tool calls to existing backends:
- BrowserController for web interactions
- ToolRunner for sqlmap/dalfox/commix/jwt_tool/custom PoC
- HexstrikeClient for nuclei/ffuf/gobuster/wafw00f/httpx/nmap
- HTTPRepeater for manual HTTP requests
- AuthzTester for IDOR/authz testing
- TrafficIntelligence for proxy traffic analysis
- TrafficInterceptor for proxy traffic retrieval
- EmailManager for account registration
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import re

import httpx
import structlog

from ai_brain.active.recon_engine import SubdomainEnumerator
from ai_brain.active.scope_guard import ActiveScopeGuard
from ai_brain.active.waf_bypass import WafBypassEngine
from ai_brain.active.advanced_attacks import (
    HTTPSmugglingTester,
    CachePoisonTester,
    GhostParamDiscovery,
    PrototypePollutionTester,
    CORSExploitTester,
    OpenRedirectTester,
    BehaviorProfiler,
)
from ai_brain.active.chain_discovery import ChainDiscoveryEngine, AdversarialReasoningEngine
from ai_brain.active.captcha_solver import CaptchaSolver
from ai_brain.active.observation_model import Observation, wrap_tool_result

logger = structlog.get_logger()

# Maximum tool output size to include inline (15KB).
# Larger outputs are written to temp files.
_MAX_INLINE_SIZE = 15_000

# ── Global HTTP rate limiter ───────────────────────────────────────────
# Enforces minimum delay between ALL outbound HTTP requests (tools, exploits,
# fuzzing) to avoid WAF/Cloudflare IP bans on production targets.
_HTTP_RATE_LIMIT_SECONDS = 1.0  # 1 request per second baseline
_last_http_request_time: float = 0.0
_http_rate_lock = asyncio.Lock()

# ── Global Observation store ─────────────────────────────────────────
# Structured Observation envelopes for every tool result (new architecture).
# Coexists with the legacy recent_tool_results on ToolDeps.
_GLOBAL_OBSERVATIONS: list[Observation] = []
_MAX_OBSERVATIONS = 200


async def _http_rate_limit() -> None:
    """Wait if needed to enforce global HTTP rate limit."""
    global _last_http_request_time
    async with _http_rate_lock:
        now = time.monotonic()
        elapsed = now - _last_http_request_time
        if elapsed < _HTTP_RATE_LIMIT_SECONDS:
            await asyncio.sleep(_HTTP_RATE_LIMIT_SECONDS - elapsed)
        _last_http_request_time = time.monotonic()


@dataclass
class ToolDeps:
    """All tool backends the dispatch router can call."""

    browser: Any  # BrowserController
    proxy: Any  # TrafficInterceptor
    email_mgr: Any  # EmailManager
    tool_runner: Any  # ToolRunner
    hexstrike_client: Any | None  # HexstrikeClient (may not be running)
    scope_guard: ActiveScopeGuard
    http_repeater: Any  # HTTPRepeater
    authz_tester: Any  # AuthzTester
    traffic_intelligence: Any  # TrafficIntelligence
    traffic_analyzer: Any  # TrafficAnalyzer
    client: Any  # ClaudeClient (for CAPTCHA solving)
    config: Any  # ActiveTestingConfig
    claude_client: Any | None = None  # ClaudeClient (always Claude — for hybrid validation)
    captcha_solver: CaptchaSolver | None = None  # Universal CAPTCHA solver
    waf_engine: Any | None = None  # WafBypassEngine
    chain_engine: Any | None = None  # ChainDiscoveryEngine
    reasoning_engine: Any | None = None  # AdversarialReasoningEngine
    behavior_profiler: Any | None = None  # BehaviorProfiler
    agent_c_research: Any | None = None  # AgentCResearch (deep research tool)
    docker_executor: Any | None = None  # DockerExecutor (sandboxed tool execution)
    deduplicator: Any | None = None  # FindingDeduplicator (semantic dedup)
    goja_socks5_url: str | None = None  # Goja SOCKS5 proxy for Chrome TLS fingerprinting
    current_state: dict[str, Any] | None = None  # For tools that need state read access
    tools_executed_this_turn: set[str] = field(default_factory=set)  # Provenance tracking
    recent_tool_results: list[tuple[str, str]] = field(default_factory=list)  # [(tool_name, result_str)] last N
    max_turns: int = 150  # 0 = indefinite mode
    default_headers: dict[str, str] = field(default_factory=dict)  # Custom headers for bug bounty programs
    verifier: Any | None = None  # Verifier (proof pack generator)
    policy_manifest: Any | None = None  # PolicyManifest
    _cf_cookie_jar: dict[str, tuple[float, dict[str, str]]] = field(default_factory=dict)  # domain -> (timestamp, cookies)


def _truncate(text: str, max_size: int = _MAX_INLINE_SIZE) -> str:
    """Truncate text to max_size with a note."""
    if len(text) <= max_size:
        return text
    return text[:max_size] + f"\n... [truncated, {len(text)} chars total]"


def _get_cf_cookies(deps: ToolDeps, domain: str) -> dict[str, str]:
    """Get cached CF cookies for a domain, respecting 25-min TTL."""
    entry = deps._cf_cookie_jar.get(domain)
    if not entry:
        return {}
    ts, cookies = entry
    if time.monotonic() - ts > 1500:  # 25 min — buffer before CF's 30-min expiry
        del deps._cf_cookie_jar[domain]
        return {}
    return cookies


def _is_goja_502(resp: httpx.Response) -> bool:
    """Detect Goja proxy error responses (502 with timeout/connection errors).

    When Goja's internal Go HTTP client fails (timeout, DNS, connection refused),
    it returns a 502 with a plain text body containing the Go error message.
    These must not be passed to the brain as real target responses.
    """
    if resp.status_code != 502:
        return False
    # Goja 502s have connection: close and text/plain content type
    ct = resp.headers.get("content-type", "")
    if "text/plain" not in ct:
        return False
    body = resp.text[:500] if resp.text else ""
    _GOJA_ERROR_PATTERNS = (
        "Client.Timeout exceeded",
        "net/http: request canceled",
        "dial tcp",
        "connection refused",
        "no such host",
        "TLS handshake timeout",
        "context deadline exceeded",
        "EOF",
        "connection reset by peer",
        "i/o timeout",
    )
    return any(p in body for p in _GOJA_ERROR_PATTERNS)


def _httpx_kwargs(deps: ToolDeps, **extra: Any) -> dict[str, Any]:
    """Build httpx.AsyncClient kwargs with Goja SOCKS5 proxy if available."""
    kwargs: dict[str, Any] = {"verify": False, "timeout": extra.pop("timeout", 15)}
    if deps.goja_socks5_url:
        kwargs["proxy"] = deps.goja_socks5_url
    elif getattr(deps.config, "upstream_proxy", ""):
        kwargs["proxy"] = deps.config.upstream_proxy
    # Merge default headers (bug bounty program headers) — skip if no_auth
    no_auth = extra.pop("no_auth", False)
    if deps.default_headers and not no_auth:
        headers = dict(deps.default_headers)
        headers.update(extra.pop("headers", {}))
        kwargs["headers"] = headers
    # Inject cached CF cookies when URL is provided
    url = extra.pop("cf_inject_url", None)
    if url and deps._cf_cookie_jar:
        from urllib.parse import urlparse
        domain = urlparse(url).hostname or ""
        cf_cookies = _get_cf_cookies(deps, domain)
        if cf_cookies:
            existing = extra.get("cookies") or {}
            extra["cookies"] = {**cf_cookies, **existing}  # explicit cookies win
    kwargs.update(extra)
    return kwargs


def _make_httpx_client(deps: ToolDeps, **extra: Any) -> httpx.AsyncClient:
    """Create an httpx client from deps with automatic Goja 502 fallback.

    Same as _httpx_kwargs() but returns a client directly. When Goja proxy
    is active, returns a client that auto-retries on Goja 502 errors.
    """
    kwargs = _httpx_kwargs(deps, **extra)
    proxy = kwargs.get("proxy")
    if proxy and deps.goja_socks5_url:
        from ai_brain.active.deterministic_tools import _GojaFallbackClient
        return _GojaFallbackClient(socks_proxy=deps.goja_socks5_url, **kwargs)
    return httpx.AsyncClient(**kwargs)


def _safe_json(obj: Any) -> str:
    """Convert obj to JSON string, handling non-serializable types.

    Uses ensure_ascii=True to escape control characters that would break
    json.loads() on the receiving end (e.g., binary data in proxy traffic).
    """
    try:
        return json.dumps(obj, default=str, ensure_ascii=True)
    except Exception:
        return json.dumps({"result": str(obj)}, ensure_ascii=True)


def _populate_http_dumps(info: dict[str, Any], tool_result_str: str) -> None:
    """Extract request/response dumps from tool result for DB storage."""
    if info.get("request_dump") and info.get("response_dump"):
        return  # Already populated
    try:
        result = json.loads(tool_result_str)
        if not isinstance(result, dict):
            return
    except (json.JSONDecodeError, TypeError):
        return

    # Build request dump
    method = result.get("method", info.get("method", "GET"))
    url = result.get("url", result.get("endpoint", info.get("endpoint", "")))
    req_headers = result.get("request_headers", {})
    req_body = result.get("request_body", result.get("payload", ""))
    if url:
        parts = [f"{method} {url}"]
        if isinstance(req_headers, dict):
            for k, v in list(req_headers.items())[:10]:
                parts.append(f"{k}: {v}")
        if req_body:
            parts.append(f"\n{str(req_body)[:1000]}")
        info.setdefault("request_dump", "\n".join(parts))

    # Build response dump
    status = result.get("status_code", result.get("status", ""))
    resp_headers = result.get("headers", result.get("response_headers", {}))
    body = result.get("body", result.get("stdout", result.get("output", "")))
    if status or body:
        parts = []
        if status:
            parts.append(f"HTTP {status}")
        if isinstance(resp_headers, dict):
            for k, v in list(resp_headers.items())[:10]:
                parts.append(f"{k}: {v}")
        if body:
            parts.append(f"\n{str(body)[:2048]}")
        info.setdefault("response_dump", "\n".join(parts))


def _enrich_findings_with_tool_results(
    findings: dict[str, Any], deps: ToolDeps
) -> None:
    """Auto-enrich finding evidence with raw HTTP data from recent tool results.

    When the brain (especially Z.ai) writes narrative evidence like "confirmed SSTI",
    we append actual HTTP response data from the most recent tool results so the
    evidence scoring can detect real HTTP artifacts.
    """
    if not deps.recent_tool_results:
        return

    for fid, info in findings.items():
        if not isinstance(info, dict):
            continue
        evidence = str(info.get("evidence", ""))

        # Enrich with matching tool result (3-pass: exact tool → endpoint match → any exploit tool)
        tool_result_str = _get_matching_tool_result(info, deps)
        if tool_result_str:
            # Populate request_dump / response_dump for DB storage
            _populate_http_dumps(info, tool_result_str)

            # Only enrich evidence text if it lacks raw HTTP data
            if not _has_raw_http_artifacts(evidence):
                snippet = _extract_http_snippet(tool_result_str)
                if snippet:
                    info["evidence"] = evidence + "\n\n--- RAW TOOL OUTPUT ---\n" + snippet


def _extract_http_snippet(result_str: str) -> str:
    """Extract HTTP-relevant snippet from a tool result string."""
    try:
        result = json.loads(result_str)
        if not isinstance(result, dict):
            return result_str[:1000] if len(result_str) > 20 else ""
    except (json.JSONDecodeError, TypeError):
        return result_str[:1000] if len(result_str) > 20 else ""

    parts = []

    # HTTP status
    status = result.get("status_code", result.get("status", ""))
    if status:
        parts.append(f"HTTP Status: {status}")

    # Headers
    headers = result.get("headers", {})
    if isinstance(headers, dict):
        for h in ("content-type", "location", "set-cookie", "server",
                   "x-powered-by", "access-control-allow-origin"):
            val = headers.get(h, headers.get(h.title(), ""))
            if val:
                parts.append(f"{h}: {val}")

    # Body (truncated)
    body = result.get("body", result.get("stdout", result.get("output", "")))
    if body:
        body_str = str(body)[:800]
        parts.append(f"Body: {body_str}")

    # Error
    error = result.get("error", "")
    if error:
        parts.append(f"Error: {str(error)[:200]}")

    return "\n".join(parts) if parts else ""


async def dispatch_tool(
    tool_name: str,
    tool_input: dict[str, Any],
    deps: ToolDeps,
) -> str:
    """Route a tool call to the appropriate backend.

    Args:
        tool_name: Name of the tool to invoke.
        tool_input: Tool input parameters from Claude.
        deps: All tool backends.

    Returns:
        JSON string of tool result (truncated to 15KB max).
        Special keys in result:
        - "_state_update": dict of state fields to merge
        - "_done": True signals test completion
    """
    try:
        result = await _dispatch(tool_name, tool_input, deps)
        result_str = _safe_json(result)

        # Wrap in Observation envelope
        try:
            obs = wrap_tool_result(
                tool_name=tool_name,
                result_dict=result if isinstance(result, dict) else {"result": result},
                turn=getattr(deps, '_current_turn', 0),
                auth_context=getattr(deps, '_current_auth', ''),
                subject=tool_input.get("url", tool_input.get("target", "")),
            )
            _GLOBAL_OBSERVATIONS.append(obs)
            # Cap at max
            if len(_GLOBAL_OBSERVATIONS) > _MAX_OBSERVATIONS:
                _GLOBAL_OBSERVATIONS[:] = _GLOBAL_OBSERVATIONS[-_MAX_OBSERVATIONS:]
        except Exception:
            pass  # Don't fail tool on observation wrapping

        return _truncate(result_str)
    except Exception as e:
        logger.error("tool_dispatch_error", tool=tool_name, error=str(e))
        return json.dumps({"error": f"{tool_name}: {e}"})


def _is_cloudflare_challenge(status: int, headers: dict[str, str], body: str) -> bool:
    """Detect Cloudflare JS challenge vs app-level 403."""
    if status != 403:
        return False
    # Must have cf-ray header (Cloudflare infrastructure)
    headers_lower = {k.lower(): v for k, v in headers.items()}
    if "cf-ray" not in headers_lower:
        return False
    # App-level 403 often returns JSON error bodies — skip those
    body_stripped = body.strip()
    if body_stripped.startswith("{") or body_stripped.startswith("["):
        return False
    # Look for Cloudflare challenge markers in HTML body
    cf_markers = ("challenge-platform", "Just a moment", "Checking your browser", "cf-chl-", "_cf_chl_opt")
    return any(marker in body for marker in cf_markers)


async def _solve_cloudflare_challenge(
    deps: ToolDeps, url: str,
) -> dict[str, str]:
    """Navigate browser to URL, wait for CF challenge to resolve, extract cookies."""
    from urllib.parse import urlparse

    domain = urlparse(url).hostname or ""
    ctx_name = "cf_solver"
    cookies: dict[str, str] = {}

    try:
        await _ensure_context(deps, ctx_name)
        await deps.browser.navigate(ctx_name, url, wait_until="networkidle")

        # Poll for cf_clearance cookie (CF sets it after JS challenge passes)
        for _ in range(30):  # 15s max (30 × 0.5s)
            raw_cookies = await deps.browser.get_cookies(ctx_name)
            for c in raw_cookies:
                if c.get("name") == "cf_clearance":
                    # Found it — grab all cookies for this domain
                    for cc in raw_cookies:
                        cookies[cc["name"]] = cc["value"]
                    deps._cf_cookie_jar[domain] = (time.monotonic(), cookies)
                    logger.info(
                        "cloudflare_bypass_success",
                        domain=domain,
                        cookie_count=len(cookies),
                    )
                    return cookies
            await asyncio.sleep(0.5)

        # Timeout — grab whatever cookies we have anyway
        raw_cookies = await deps.browser.get_cookies(ctx_name)
        for c in raw_cookies:
            cookies[c["name"]] = c["value"]
        if cookies:
            deps._cf_cookie_jar[domain] = (time.monotonic(), cookies)
        logger.warning(
            "cloudflare_bypass_timeout",
            domain=domain,
            cookie_count=len(cookies),
            note="cf_clearance not found within 15s",
        )
    except Exception as e:
        logger.error("cloudflare_bypass_error", domain=domain, error=str(e))

    return cookies


async def _dispatch(
    tool_name: str,
    inp: dict[str, Any],
    deps: ToolDeps,
) -> Any:
    """Internal dispatch — returns a dict/list result."""

    # ── Recon Tools ──────────────────────────────────────────────

    if tool_name == "navigate_and_extract":
        url = inp["url"]
        ctx = inp.get("context_name", "default")
        await _ensure_context(deps, ctx)
        nav_result = await deps.browser.navigate(ctx, url)
        page_info = await deps.browser.extract_page_info(ctx)

        # Extract JS-embedded API endpoints from page context
        js_endpoints = await _extract_js_endpoints(deps, ctx)

        result_data = {
            "url": nav_result.url if hasattr(nav_result, "url") else url,
            "title": page_info.get("title", ""),
            "forms": page_info.get("forms", []),
            "links": page_info.get("links", [])[:50],
            "scripts": page_info.get("scripts", [])[:20],
            "meta": page_info.get("meta", []),
            "status": "success",
        }
        if js_endpoints:
            result_data["js_api_endpoints"] = js_endpoints

        # Auto-auth-check: fire one unauthenticated request to tag auth requirement
        try:
            async with _make_httpx_client(deps, timeout=5) as _auth_check_client:
                anon_resp = await _auth_check_client.get(url)
                if anon_resp.status_code in (401, 403):
                    result_data["auth_required"] = True
                elif anon_resp.status_code in (301, 302, 307, 308):
                    location = anon_resp.headers.get("location", "").lower()
                    if any(kw in location for kw in ("login", "auth", "signin")):
                        result_data["auth_required"] = True
                    else:
                        result_data["auth_required"] = False
                else:
                    result_data["auth_required"] = False
        except Exception:
            pass  # Don't fail the tool on auth check error

        return result_data

    if tool_name == "crawl_target":
        url = inp["start_url"]
        max_pages = inp.get("max_pages", 30)
        ctx = inp.get("context_name", "default")
        await _ensure_context(deps, ctx)
        return await _crawl_bfs(deps, ctx, url, max_pages)

    if tool_name == "run_nuclei_scan":
        if not deps.hexstrike_client:
            return {"error": "HexStrike not available. Use browser-based testing instead."}
        return await deps.hexstrike_client.run_nuclei(
            target=inp["target"],
            severity=inp.get("severity", "critical,high,medium"),
        )

    if tool_name == "run_content_discovery":
        if not deps.hexstrike_client:
            return {"error": "HexStrike not available."}
        tool = inp.get("tool", "ffuf")
        if tool == "gobuster":
            return await deps.hexstrike_client.run_gobuster(
                url=inp["url"], mode=inp.get("mode", "dir"),
            )
        return await deps.hexstrike_client.run_ffuf(
            url=inp["url"], mode=inp.get("mode", "directory"),
        )

    if tool_name == "detect_technologies":
        if deps.hexstrike_client:
            return await deps.hexstrike_client.technology_detection(target=inp["target"])
        # Fallback: extract from page headers and scripts
        return {"error": "HexStrike not available. Check page headers and scripts manually."}

    if tool_name == "detect_waf":
        if not deps.hexstrike_client:
            return {"error": "HexStrike not available."}
        return await deps.hexstrike_client.run_wafw00f(target=inp["target"])

    if tool_name == "analyze_traffic":
        traffic = deps.proxy.get_traffic(limit=2000) if deps.proxy.is_running else []
        if not traffic:
            return {"message": "No traffic captured yet. Browse the site first."}
        report = deps.traffic_intelligence.analyze(traffic)
        # Convert Pydantic model or dataclass to dict
        if hasattr(report, "model_dump"):
            return report.model_dump()
        if hasattr(report, "__dict__"):
            return {k: v for k, v in report.__dict__.items() if not k.startswith("_")}
        return {"result": str(report)}

    if tool_name == "enumerate_subdomains":
        domain = inp["domain"]
        enumerator = SubdomainEnumerator(deps.scope_guard, deps.config.tools_timeout)
        result = await enumerator.enumerate(domain)
        # Auto-populate endpoints from discovered subdomains
        state_update: dict[str, Any] = {"endpoints": {}}
        for sub in result.get("subdomains", [])[:50]:
            url = f"https://{sub}"
            state_update["endpoints"][url] = {
                "method": "GET",
                "notes": "discovered via subdomain enum",
            }
        return {**result, "_state_update": state_update}

    if tool_name == "resolve_domains":
        subdomains = inp["subdomains"]
        enumerator = SubdomainEnumerator(deps.scope_guard, deps.config.tools_timeout)
        return await enumerator.resolve_domains(subdomains)

    if tool_name == "scan_info_disclosure":
        from ai_brain.active.deterministic_tools import InfoDisclosureScanner
        scanner = InfoDisclosureScanner(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        _state = deps.current_state or {}
        tech_stack = _state.get("tech_stack", [])
        result = await scanner.scan(inp["url"], tech_stack=tech_stack or None)

        # Auto-generate findings for critical verified disclosures
        auto_findings: dict[str, Any] = {}
        for item in result.get("verified", []):
            cat = item["category"]
            path = item["path"]
            preview = item.get("evidence_preview", "")
            severity = "high"
            if cat in ("creds", "backup") and any(kw in preview.lower() for kw in ("password", "secret", "private_key")):
                severity = "critical"
            elif cat in ("git", "env"):
                severity = "high"
            elif cat in ("api_docs", "robots", "sitemap", "sourcemap"):
                severity = "low"
                continue  # Don't auto-create findings for low-severity disclosures
            else:
                severity = "medium"

            fid = f"info_disc_{cat}_{path.replace('/', '_').strip('_')}"
            auto_findings[fid] = {
                "vuln_type": "information_disclosure",
                "endpoint": path,
                "parameter": "",
                "evidence": (
                    f"scan_info_disclosure found {path} (category={cat}) with HTTP 200. "
                    f"Content verification passed. Content-Length: {item['content_length']}. "
                    f"Preview: {preview[:300]}"
                ),
                "severity": severity,
                "confirmed": False,
                "tool_used": "scan_info_disclosure",
                "evidence_score": 4,
                "evidence_score_reason": f"confirmed: verified {cat} content pattern",
            }

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "scan_auth_bypass":
        from ai_brain.active.deterministic_tools import AuthBypassScanner
        scanner = AuthBypassScanner(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        _state = deps.current_state or {}
        endpoints = _state.get("endpoints", {})
        tech_stack = _state.get("tech_stack", [])
        result = await scanner.scan(inp["url"], endpoints, tech_stack=tech_stack or None)

        auto_findings: dict[str, Any] = {}
        for item in result.get("findings", []):
            fid = (
                f"auth_bypass_{item['bypass_type']}_"
                f"{hashlib.md5(item['endpoint'].encode()).hexdigest()[:8]}"
            )
            severity = "high"
            if item["bypass_type"] == "missing_auth":
                _ep_lower = item["endpoint"].lower()
                if any(kw in _ep_lower for kw in (
                    "admin", "user", "password", "2fa", "emulat", "token", "payment",
                )):
                    severity = "critical"
            auto_findings[fid] = {
                "vuln_type": "authentication_bypass",
                "endpoint": item["endpoint"],
                "parameter": "",
                "evidence": (
                    f"scan_auth_bypass: {item['bypass_type']} on "
                    f"{item['method']} {item['endpoint']}. "
                    f"Detail: {item['bypass_detail']}. "
                    f"Status: {item['status_code']}. "
                    f"Response: {item.get('response_preview', '')[:300]}"
                ),
                "severity": severity,
                "confirmed": False,
                "tool_used": "scan_auth_bypass",
                "evidence_score": 4,
                "evidence_score_reason": f"confirmed: auth bypass via {item['bypass_type']}",
                "request_dump": item.get("request_dump", ""),
                "response_dump": item.get("response_dump", ""),
            }

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "scan_csrf":
        from ai_brain.active.deterministic_tools import CSRFScanner
        scanner = CSRFScanner(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        _state = deps.current_state or {}
        # Get proxy traffic for replaying real requests
        proxy_traffic = []
        if deps.proxy and hasattr(deps.proxy, "get_traffic"):
            try:
                proxy_traffic = deps.proxy.get_traffic()
            except Exception:
                pass
        try:
            result = await scanner.scan(
                inp["url"],
                proxy_traffic=proxy_traffic or None,
                endpoints=_state.get("endpoints"),
            )
        finally:
            await scanner.close()

        # Auto-generate findings for CSRF vulnerabilities
        auto_findings: dict[str, Any] = {}
        for item in result.get("findings", []):
            fid = (
                f"csrf_{item['csrf_type']}_"
                f"{hashlib.md5(item['endpoint'].encode()).hexdigest()[:8]}"
            )
            severity = "high"
            ep_lower = item["endpoint"].lower()
            if any(kw in ep_lower for kw in (
                "admin", "payment", "transfer", "delete", "password", "2fa",
            )):
                severity = "critical"
            auto_findings[fid] = {
                "vuln_type": "csrf",
                "endpoint": item["endpoint"],
                "parameter": "",
                "evidence": (
                    f"scan_csrf: {item['csrf_type']} on "
                    f"{item['method']} {item['endpoint']}. "
                    f"Detail: {item['detail']}. "
                    f"Status: {item['status_code']} (baseline: {item['baseline_status']})"
                ),
                "severity": severity,
                "confirmed": False,
                "tool_used": "scan_csrf",
                "evidence_score": 4,
                "evidence_score_reason": f"confirmed: CSRF via {item['csrf_type']}",
                "request_dump": item.get("request_dump", ""),
                "response_dump": item.get("response_dump", ""),
            }

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "scan_error_responses":
        from ai_brain.active.deterministic_tools import ErrorResponseMiner
        miner = ErrorResponseMiner(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        _state = deps.current_state or {}
        try:
            result = await miner.scan(
                inp["url"],
                endpoints=_state.get("endpoints"),
            )
        finally:
            await miner.close()

        # Auto-generate findings for error info disclosures
        auto_findings: dict[str, Any] = {}
        for item in result.get("findings", []):
            cats = item.get("categories_found", [])
            fid = (
                f"error_disc_{'_'.join(cats[:2])}_"
                f"{hashlib.md5(item['endpoint'].encode()).hexdigest()[:8]}"
            )
            severity = "medium"
            if any(c in cats for c in ("internal_url", "database_type", "file_path")):
                severity = "high"
            auto_findings[fid] = {
                "vuln_type": "information_disclosure",
                "endpoint": item["endpoint"],
                "parameter": "",
                "evidence": (
                    f"scan_error_responses found leaked information on {item['endpoint']}. "
                    f"Categories: {', '.join(cats)}. "
                    f"Detail: {item['detail'][:500]}"
                ),
                "severity": severity,
                "confirmed": False,
                "tool_used": "scan_error_responses",
                "evidence_score": 4,
                "evidence_score_reason": f"confirmed: error disclosure ({', '.join(cats)})",
            }

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "scan_crlf":
        from ai_brain.active.deterministic_tools import CRLFScanner
        scanner = CRLFScanner(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        _state = deps.current_state or {}
        try:
            result = await scanner.scan(
                inp["url"],
                endpoints=_state.get("endpoints"),
            )
        finally:
            await scanner.close()

        auto_findings: dict[str, Any] = {}
        for item in result.get("findings", []):
            fid = (
                f"crlf_{item['parameter']}_"
                f"{hashlib.md5(item['endpoint'].encode()).hexdigest()[:8]}"
            )
            auto_findings[fid] = {
                "vuln_type": "crlf_injection",
                "endpoint": item["endpoint"],
                "parameter": item.get("parameter", ""),
                "evidence": (
                    f"scan_crlf: {item['detail']}. "
                    f"Payload: {item.get('payload', '')}. "
                    f"Status: {item['status_code']}"
                ),
                "severity": "high",
                "confirmed": True,
                "tool_used": "scan_crlf",
                "evidence_score": 5,
                "evidence_score_reason": "definitive: injected header confirmed in response",
                "request_dump": item.get("request_dump", ""),
                "response_dump": item.get("response_dump", ""),
            }

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "scan_host_header":
        from ai_brain.active.deterministic_tools import HostHeaderScanner
        scanner = HostHeaderScanner(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        _state = deps.current_state or {}
        try:
            result = await scanner.scan(
                inp["url"],
                endpoints=_state.get("endpoints"),
            )
        finally:
            await scanner.close()

        auto_findings: dict[str, Any] = {}
        for item in result.get("findings", []):
            fid = (
                f"host_header_{item['header_tested'].lower().replace('-', '_')}_"
                f"{hashlib.md5(item['endpoint'].encode()).hexdigest()[:8]}"
            )
            severity = "high"
            ep_lower = item["endpoint"].lower()
            if any(kw in ep_lower for kw in ("reset", "password", "forgot", "email")):
                severity = "critical"
            auto_findings[fid] = {
                "vuln_type": "host_header_injection",
                "endpoint": item["endpoint"],
                "parameter": item.get("header_tested", ""),
                "evidence": (
                    f"scan_host_header: {item['detail']}. "
                    f"Reflected in: {item['reflected_in']}. "
                    f"Status: {item['status_code']}"
                ),
                "severity": severity,
                "confirmed": False,
                "tool_used": "scan_host_header",
                "evidence_score": 4,
                "evidence_score_reason": f"confirmed: {item['header_tested']} reflected in {item['reflected_in']}",
                "request_dump": item.get("request_dump", ""),
                "response_dump": item.get("response_dump", ""),
            }

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "scan_nosqli":
        from ai_brain.active.deterministic_tools import NoSQLInjectionScanner
        scanner = NoSQLInjectionScanner(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        _state = deps.current_state or {}
        try:
            result = await scanner.scan(
                inp["url"],
                endpoints=_state.get("endpoints"),
                proxy_traffic=_state.get("traffic_intelligence", {}).get("raw_traffic"),
            )
        finally:
            await scanner.close()

        auto_findings: dict[str, Any] = {}
        for item in result.get("findings", []):
            fid = f"nosqli_{item['parameter']}_{hashlib.md5(item['endpoint'].encode()).hexdigest()[:8]}"
            severity = "critical" if "Auth bypass" in item.get("detail", "") else "high"
            auto_findings[fid] = {
                "vuln_type": "nosql_injection",
                "endpoint": item["endpoint"],
                "parameter": item.get("parameter", ""),
                "evidence": (
                    f"scan_nosqli: {item['detail']}. "
                    f"Payload: {item.get('payload', '')}. "
                    f"Status: {item['status_code']} (baseline: {item.get('baseline_status', '?')})"
                ),
                "severity": severity,
                "confirmed": True,
                "tool_used": "scan_nosqli",
                "evidence_score": item.get("evidence_score", 4),
                "evidence_score_reason": f"confirmed: NoSQL {item.get('payload_type', '')} on {item.get('parameter', '')}",
                "request_dump": item.get("request_dump", ""),
                "response_dump": item.get("response_dump", ""),
            }

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "scan_xxe":
        from ai_brain.active.deterministic_tools import XXEScanner
        scanner = XXEScanner(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        _state = deps.current_state or {}
        try:
            result = await scanner.scan(
                inp["url"],
                endpoints=_state.get("endpoints"),
            )
        finally:
            await scanner.close()

        auto_findings: dict[str, Any] = {}
        for item in result.get("findings", []):
            fid = f"xxe_{item['xxe_type']}_{hashlib.md5(item['endpoint'].encode()).hexdigest()[:8]}"
            severity = "critical" if item.get("evidence_score", 0) >= 5 else "high"
            auto_findings[fid] = {
                "vuln_type": "xxe",
                "endpoint": item["endpoint"],
                "parameter": item.get("xxe_type", ""),
                "evidence": (
                    f"scan_xxe: {item['detail']}. "
                    f"Status: {item['status_code']}"
                ),
                "severity": severity,
                "confirmed": severity == "critical",
                "tool_used": "scan_xxe",
                "evidence_score": item.get("evidence_score", 3),
                "evidence_score_reason": f"confirmed: XXE {item.get('xxe_type', '')} file read {item.get('file_target', '')}",
                "request_dump": item.get("request_dump", ""),
                "response_dump": item.get("response_dump", ""),
            }

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "scan_deserialization":
        from ai_brain.active.deterministic_tools import DeserializationScanner
        scanner = DeserializationScanner(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        _state = deps.current_state or {}
        try:
            result = await scanner.scan(
                inp["url"],
                endpoints=_state.get("endpoints"),
                proxy_traffic=_state.get("traffic_intelligence", {}).get("raw_traffic"),
                cookies=None,
            )
        finally:
            await scanner.close()

        auto_findings: dict[str, Any] = {}
        for item in result.get("findings", []):
            fid = f"deser_{item['format']}_{hashlib.md5(item['endpoint'].encode()).hexdigest()[:8]}"
            severity = "high" if item.get("controllable") else "medium"
            auto_findings[fid] = {
                "vuln_type": "insecure_deserialization",
                "endpoint": item["endpoint"],
                "parameter": item.get("format", ""),
                "evidence": (
                    f"scan_deserialization: {item['detail']}. "
                    f"Format: {item['format']}. "
                    f"Location: {item.get('location', '?')}. "
                    f"Matched: {item.get('matched_value', '')[:80]}"
                ),
                "severity": severity,
                "confirmed": False,
                "tool_used": "scan_deserialization",
                "evidence_score": item.get("evidence_score", 3),
                "evidence_score_reason": f"detection: {item['format']} in {item.get('location', '?')}",
                "request_dump": "",
                "response_dump": item.get("matched_value", "")[:300],
            }

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "scan_dos":
        from ai_brain.active.deterministic_tools import AppLevelDoSScanner
        scanner = AppLevelDoSScanner(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        _state = deps.current_state or {}
        try:
            result = await scanner.scan(
                inp["url"],
                endpoints=_state.get("endpoints"),
                graphql_url=inp.get("graphql_url"),
            )
        finally:
            await scanner.close()

        auto_findings: dict[str, Any] = {}
        for item in result.get("findings", []):
            fid = f"dos_{item['dos_type']}_{hashlib.md5(item['endpoint'].encode()).hexdigest()[:8]}"
            auto_findings[fid] = {
                "vuln_type": "denial_of_service",
                "endpoint": item["endpoint"],
                "parameter": item.get("dos_type", ""),
                "evidence": (
                    f"scan_dos: {item['detail']}. "
                    f"Baseline: {item.get('baseline_time_ms', '?')}ms, "
                    f"Test: {item.get('test_time_ms', '?')}ms, "
                    f"Ratio: {item.get('slowdown_ratio', '?')}x"
                ),
                "severity": "medium",
                "confirmed": False,
                "tool_used": "scan_dos",
                "evidence_score": item.get("evidence_score", 3),
                "evidence_score_reason": f"timing: {item.get('slowdown_ratio', '?')}x slowdown via {item['dos_type']}",
                "request_dump": item.get("request_dump", ""),
                "response_dump": item.get("response_dump", ""),
            }

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "scan_jwt_deep":
        from ai_brain.active.deterministic_tools import JWTDeepAnalyzer
        analyzer = JWTDeepAnalyzer(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        try:
            result = await analyzer.analyze(
                inp["token"],
                target_url=inp.get("url"),
                cookies=None,
            )
        finally:
            await analyzer.close()

        auto_findings: dict[str, Any] = {}
        for item in result.get("findings", []):
            attack = item.get("jwt_attack", "unknown")
            fid = f"jwt_{attack}_{hashlib.md5(item['endpoint'].encode()).hexdigest()[:8]}"
            severity = "critical" if item.get("evidence_score", 0) >= 5 else "high"
            auto_findings[fid] = {
                "vuln_type": "jwt_vulnerability",
                "endpoint": item["endpoint"],
                "parameter": attack,
                "evidence": (
                    f"scan_jwt_deep: {item['detail']}. "
                    f"Attack: {attack}. "
                    f"Original alg: {item.get('original_algorithm', '?')}"
                ),
                "severity": severity,
                "confirmed": item.get("evidence_score", 0) >= 5,
                "tool_used": "scan_jwt_deep",
                "evidence_score": item.get("evidence_score", 4),
                "evidence_score_reason": f"confirmed: JWT {attack} bypass",
                "request_dump": item.get("request_dump", ""),
                "response_dump": item.get("response_dump", ""),
            }
            if item.get("cracked_secret"):
                auto_findings[fid]["evidence"] += f". Cracked secret: {item['cracked_secret']}"

        state_update = {}
        if auto_findings:
            state_update["findings"] = auto_findings
        return {**result, "_state_update": state_update} if state_update else result

    if tool_name == "build_app_model":
        # If Sonnet already built a superior app model, return it
        if deps and deps.current_state:
            existing_model = deps.current_state.get("app_model", {})
            if isinstance(existing_model, dict) and existing_model.get("_sonnet_generated"):
                return json.dumps({
                    "status": "app_model_already_built_by_sonnet",
                    "message": "Sonnet has already built a comprehensive app model. It is visible in your system prompt under 'Sonnet Application Model'. Proceed to exploitation.",
                    "_state_update": {"app_model": existing_model},
                })
        # Validate substantive content (reject placeholders)
        errors = []
        app_type = inp.get("app_type", "")
        auth_mechanism = inp.get("auth_mechanism", "")
        data_flows = inp.get("data_flows", [])
        high_value_targets = inp.get("high_value_targets", [])

        if len(app_type) < 10:
            errors.append("app_type must be >=10 chars (describe what the app does)")
        if len(auth_mechanism) < 15:
            errors.append("auth_mechanism must be >=15 chars (describe how auth works)")
        if len(data_flows) < 2:
            errors.append("data_flows must have >=2 items (describe key data flows)")
        if len(high_value_targets) < 3:
            errors.append("high_value_targets must have >=3 items with reasons")

        # Reject placeholder/generic content
        _placeholders = {"tbd", "todo", "unknown", "n/a", "none", "placeholder", "test"}
        for field_val in [app_type, auth_mechanism]:
            if field_val.lower().strip() in _placeholders:
                errors.append(f"'{field_val}' looks like placeholder text — provide real analysis")

        if errors:
            return {"status": "rejected", "errors": errors, "message": "App model incomplete. Gather more recon data first."}

        model = {
            "app_type": app_type,
            "auth_mechanism": auth_mechanism,
            "data_flows": data_flows,
            "user_ref_patterns": inp.get("user_ref_patterns", ""),
            "high_value_targets": high_value_targets,
        }
        return {
            "status": "accepted",
            "message": "App model built. Exploitation tools are now unlocked.",
            "_state_update": {"app_model": model},
        }

    # ── Attack Tools ─────────────────────────────────────────────

    # Auto-WAF-fingerprint: before running attack tools, ensure WAF profile exists
    _WAF_ATTACK_TOOLS = {"test_sqli", "test_xss", "test_cmdi", "test_ssti", "test_ssrf"}
    if tool_name in _WAF_ATTACK_TOOLS and deps.waf_engine:
        url = inp.get("url", "")
        if url:
            from urllib.parse import urlparse as _waf_urlparse
            domain = _waf_urlparse(url).netloc
            if domain and not deps.waf_engine.has_profile(domain):
                try:
                    logger.info("auto_waf_fingerprint", domain=domain, tool=tool_name)
                    await deps.waf_engine.fingerprint(url)
                except Exception as e:
                    logger.debug("auto_waf_fingerprint_failed", error=str(e)[:80])

    if tool_name == "test_sqli":
        return await deps.tool_runner.run_sqlmap(
            url=inp["url"],
            params=inp.get("params"),
            options=inp.get("options"),
        )

    if tool_name == "test_xss":
        return await deps.tool_runner.run_dalfox(
            url=inp["url"],
            params=inp.get("params"),
        )

    if tool_name == "test_cmdi":
        return await deps.tool_runner.run_commix(
            url=inp["url"],
            params=inp.get("params"),
        )

    if tool_name == "test_auth_bypass":
        url = inp["url"]
        methods = inp.get("methods", ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        headers_extra = inp.get("headers", {})
        results = []

        # Test HTTP verb tampering (no_auth=True: don't inject default auth headers)
        for method in methods:
            try:
                await _http_rate_limit()  # Global rate limit
                async with _make_httpx_client(deps, no_auth=True, cf_inject_url=url) as client:
                    resp = await client.request(method, url, headers=headers_extra)
                    results.append({
                        "method": method,
                        "status": resp.status_code,
                        "body_length": len(resp.content),
                        "redirect": str(resp.headers.get("location", "")),
                    })
            except Exception as e:
                results.append({"method": method, "error": str(e)})

        # Test header-based bypasses (comprehensive list from research)
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        path = inp.get("path", parsed_url.path or "/admin")

        bypass_headers = [
            {"X-Original-URL": path},
            {"X-Rewrite-URL": path},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"X-Forwarded-For": "localhost"},
            {"X-Forwarded-For": "10.0.0.1"},
            {"X-Host": "localhost"},
            {"X-HTTP-Method-Override": "PUT"},
        ]
        body = inp.get("body", {})
        test_methods = ["GET"]
        if body or inp.get("method", "").upper() == "POST":
            test_methods.append("POST")

        async with _make_httpx_client(deps, no_auth=True, cf_inject_url=url) as client:
            for bh in bypass_headers:
                for test_method in test_methods:
                    try:
                        await _http_rate_limit()  # Global rate limit
                        merged = {**headers_extra, **bh}
                        if test_method == "POST":
                            resp = await client.post(url, headers=merged, data=body)
                        else:
                            resp = await client.get(url, headers=merged)
                        body_preview = resp.text[:500] if resp.text else ""
                        results.append({
                            "bypass_header": bh,
                            "method": test_method,
                            "status": resp.status_code,
                            "body_length": len(resp.content),
                            "body_preview": body_preview,
                        })
                    except Exception as e:
                        results.append({"bypass_header": bh, "method": test_method, "error": str(e)})

            # Test path mutation bypasses (403 bypass techniques)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            path_mutations = [
                f"{path}/", f"{path}//", f"{path}/.", f"{path}/..",
                f"{path};/", f"{path}..;/", f"/{path.strip('/')}/./",
                f"//{path.strip('/')}", f"/.;{path}",
                path.replace("/", "%2f"), path.replace("/", "%2F"),
                f"{path}%00", f"{path}%20", f"{path}%09",
                f"{path}.json", f"{path}.html", f"{path}.css",
            ]
            for mutation in path_mutations[:12]:  # Cap at 12 to avoid excess
                try:
                    await _http_rate_limit()  # Global rate limit
                    test_url = f"{base_url}{mutation}"
                    resp = await client.get(test_url, headers=headers_extra)
                    if resp.status_code != 403:  # Only report non-403 results
                        results.append({
                            "path_mutation": mutation,
                            "status": resp.status_code,
                            "body_length": len(resp.content),
                            "body_preview": resp.text[:300] if resp.text else "",
                        })
                except Exception:
                    pass

        return {"results": results}

    if tool_name == "test_idor":
        url = inp["url"]
        method = inp.get("method", "GET")
        # Use authz tester if we have multiple accounts
        # Otherwise do simple ID manipulation via HTTP repeater
        test_values = inp.get("test_values", [])
        id_param = inp.get("id_param", "")
        results = []

        for val in test_values:
            test_url = url
            if id_param:
                # Replace the parameter in URL
                from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[id_param] = [val]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
            try:
                await _http_rate_limit()  # Global rate limit
                async with _make_httpx_client(deps, cf_inject_url=test_url) as client:
                    resp = await client.request(method, test_url)
                    results.append({
                        "value": val,
                        "status": resp.status_code,
                        "body_length": len(resp.content),
                        "accessible": resp.status_code == 200,
                    })
            except Exception as e:
                results.append({"value": val, "error": str(e)})

        return {"id_param": id_param, "results": results}

    if tool_name == "test_file_upload":
        from ai_brain.active.file_payloads import generate_upload_payloads, write_payload_to_temp
        url = inp["url"]
        selector = inp.get("selector", "input[type=file]")
        max_payloads = inp.get("max_payloads", 10)
        ctx = inp.get("context_name", "default")
        await _ensure_context(deps, ctx)

        # Get tech stack for payload ranking
        tech = deps.config.technology_stack if hasattr(deps.config, "technology_stack") else []
        payloads = generate_upload_payloads(tech_stack=tech)[:max_payloads]

        results = []
        for payload in payloads:
            try:
                tmp_path = write_payload_to_temp(payload)
                await deps.browser.navigate(ctx, url)
                await deps.browser.upload_file(ctx, selector, tmp_path)
                # Try to submit the form
                await deps.browser.submit_form(ctx)
                page_info = await deps.browser.extract_page_info(ctx)
                results.append({
                    "payload": payload.filename,
                    "description": payload.description,
                    "status": "uploaded",
                    "page_title": page_info.get("title", ""),
                })
            except Exception as e:
                results.append({
                    "payload": payload.filename,
                    "error": str(e),
                })

        return {"upload_results": results}

    if tool_name == "send_http_request":
        from urllib.parse import urlparse as _urlparse

        url = inp["url"]
        method = inp.get("method", "GET")
        headers = inp.get("headers", {})
        body = inp.get("body")
        cookies = inp.get("cookies", {})
        follow = inp.get("follow_redirects", False)

        deps.scope_guard.validate_url(url)

        # Inject cached Cloudflare cookies for this domain
        domain = _urlparse(url).hostname or ""
        cf_cookies = _get_cf_cookies(deps, domain)
        if cf_cookies:
            merged_cookies = {**cf_cookies, **cookies}  # explicit cookies win
        else:
            merged_cookies = cookies

        # Merge default headers (e.g. Authorization from --header CLI arg)
        # Skip if no_auth=true (for genuine unauthenticated testing)
        no_auth = inp.get("no_auth", False)
        if deps.default_headers and not no_auth:
            merged_headers = dict(deps.default_headers)
            merged_headers.update(headers)
            headers = merged_headers

        # Route through Goja SOCKS5 proxy for Chrome TLS fingerprinting
        proxy_url = deps.goja_socks5_url or getattr(deps.config, "upstream_proxy", "") or None
        client_kwargs: dict[str, Any] = {
            "verify": False,
            "timeout": 30,
            "follow_redirects": follow,
            "cookies": merged_cookies,
        }
        if proxy_url:
            client_kwargs["proxy"] = proxy_url

        async def _do_request(req_headers: dict, req_cookies: dict | None = None) -> dict:
            await _http_rate_limit()  # Global rate limit
            kw = dict(client_kwargs)
            if req_cookies is not None:
                kw["cookies"] = req_cookies
            async with httpx.AsyncClient(**kw) as client:
                start = time.monotonic()
                resp = await client.request(
                    method, url, headers=req_headers, content=body,
                )
                elapsed = int((time.monotonic() - start) * 1000)
            body_text = resp.text[:10000]  # Cap response body
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": body_text,
                "body_length": len(resp.content),
                "elapsed_ms": elapsed,
                "redirect_url": str(resp.headers.get("location", "")),
            }

        try:
            result = await _do_request(headers)
        except Exception as e:
            if "decompressing" in str(e).lower():
                raw_headers = {**headers, "accept-encoding": "identity"}
                result = await _do_request(raw_headers)
            elif proxy_url:
                # Proxy may be dead — retry without proxy
                logger.warning("proxy_failed_retrying_direct", proxy=proxy_url, error=str(e)[:100])
                client_kwargs.pop("proxy", None)
                result = await _do_request(headers)
            else:
                raise

        # Detect Goja proxy 502 errors and retry without proxy
        if proxy_url and result["status_code"] == 502 and "proxy" in client_kwargs:
            body_snippet = result.get("body", "")[:500]
            _goja_markers = ("Client.Timeout exceeded", "net/http: request canceled",
                             "dial tcp", "connection refused", "no such host",
                             "TLS handshake timeout", "context deadline exceeded",
                             "i/o timeout", "connection reset by peer")
            ct = result.get("headers", {}).get("content-type", "")
            if "text/plain" in ct and any(m in body_snippet for m in _goja_markers):
                logger.warning("goja_502_retrying_direct", url=url, error=body_snippet[:120])
                client_kwargs.pop("proxy", None)
                result = await _do_request(headers)
                result["_goja_fallback"] = True

        # Auto-detect Cloudflare challenge and solve via browser
        if _is_cloudflare_challenge(
            result["status_code"], result["headers"], result["body"],
        ):
            logger.info("cloudflare_bypass_attempt", url=url, domain=domain)
            solved_cookies = await _solve_cloudflare_challenge(deps, url)
            if solved_cookies:
                retry_cookies = {**solved_cookies, **cookies}
                try:
                    result = await _do_request(headers, req_cookies=retry_cookies)
                    result["cloudflare_bypassed"] = True
                except Exception:
                    result["cloudflare_bypassed"] = False
            else:
                result["cloudflare_bypassed"] = False

        return result

    if tool_name == "test_jwt":
        token = inp.get("token", "")
        if not token:
            return {"error": "test_jwt requires a 'token' parameter (the JWT string to test)"}
        return await deps.tool_runner.run_jwt_tool(
            token=token,
            attacks=inp.get("attacks"),
        )

    if tool_name == "run_custom_exploit":
        # Route through Docker sandbox when available
        if deps.docker_executor and deps.docker_executor.is_running:
            result = await deps.docker_executor.execute_python(
                code=inp["code"],
                timeout=inp.get("timeout", 60),
            )
            return result
        return await deps.tool_runner.run_custom_poc(
            code=inp["code"],
            language="python",
            timeout=inp.get("timeout", 60),
        )

    # ── Utility Tools ────────────────────────────────────────────

    if tool_name == "browser_interact":
        action = inp["action"]
        ctx = inp.get("context_name", "default")
        selector = inp.get("selector", "")
        value = inp.get("value", "")
        await _ensure_context(deps, ctx)

        if action == "click":
            r = await deps.browser.click(ctx, selector)
            return {"action": "click", "selector": selector, "success": r.success if hasattr(r, "success") else True}
        elif action == "fill":
            r = await deps.browser.fill(ctx, selector, value)
            return {"action": "fill", "selector": selector, "success": r.success if hasattr(r, "success") else True}
        elif action == "submit_form":
            r = await deps.browser.submit_form(ctx, selector or "form")
            return {"action": "submit_form", "success": r.success if hasattr(r, "success") else True}
        elif action == "select_option":
            r = await deps.browser.select_option(ctx, selector, value)
            return {"action": "select_option", "success": r.success if hasattr(r, "success") else True}
        elif action == "check_checkbox":
            r = await deps.browser.check_checkbox(ctx, selector)
            return {"action": "check_checkbox", "success": r.success if hasattr(r, "success") else True}
        elif action == "screenshot":
            b64 = await deps.browser.screenshot(ctx)
            return {"action": "screenshot", "base64_length": len(b64), "note": "Screenshot captured (base64 too large to include)."}
        elif action == "screenshot_element":
            b64 = await deps.browser.screenshot_element(ctx, selector)
            return {"action": "screenshot_element", "selector": selector, "base64_length": len(b64)}
        elif action == "execute_js":
            result = await deps.browser.execute_js(ctx, value)
            return {"action": "execute_js", "result": str(result)[:5000]}
        elif action == "get_cookies":
            cookies = await deps.browser.get_cookies(ctx)
            return {"action": "get_cookies", "cookies": cookies}
        elif action == "set_cookies":
            cookies_data = json.loads(value) if isinstance(value, str) else value
            await deps.browser.set_cookies(ctx, cookies_data)
            return {"action": "set_cookies", "success": True}
        elif action == "wait_for_navigation":
            await deps.browser.wait_for_navigation(ctx)
            return {"action": "wait_for_navigation", "success": True}
        else:
            return {"error": f"Unknown browser action: {action}"}

    if tool_name == "discover_auth_endpoints":
        from ai_brain.active.deterministic_tools import AuthEndpointDiscovery
        scanner = AuthEndpointDiscovery(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        return await scanner.scan(inp["url"])

    if tool_name == "register_account":
        return await _register_account(deps, inp)

    if tool_name == "login_account":
        return await _login_account(deps, inp)

    if tool_name == "update_knowledge":
        # Special: returns state update directive
        validated_findings: dict[str, Any] = {}
        if "findings" in inp:
            # Auto-enrich: if evidence lacks raw HTTP data, append recent tool results
            _enrich_findings_with_tool_results(inp["findings"], deps)
            # Hybrid validation: score check → tool auto-confirm → Claude Haiku
            validated_findings = await _validate_findings(inp["findings"], source="brain", deps=deps)
            if not validated_findings and inp["findings"]:
                # All findings failed validation — give specific feedback
                return {
                    "error": (
                        "All findings rejected. Common reasons: "
                        "tool_used must be exact tool name (e.g. 'send_http_request', 'test_xss'), "
                        "evidence MUST contain raw HTTP response data (status lines, headers, body "
                        "snippets copied from tool output). Narrative-only claims are rejected. "
                        "Max 5 findings per call, no summary/meta vuln_types. "
                        "Run the testing tool, copy its HTTP output into evidence."
                    ),
                    "_state_update": {},
                }

        update: dict[str, Any] = {"_state_update": {}}
        if "endpoints" in inp:
            update["_state_update"]["endpoints"] = inp["endpoints"]
        if validated_findings:
            update["_state_update"]["findings"] = validated_findings
        if "hypotheses" in inp:
            update["_state_update"]["hypotheses"] = inp["hypotheses"]
        if "accounts" in inp:
            update["_state_update"]["accounts"] = inp["accounts"]
        if "tech_stack" in inp:
            update["_state_update"]["tech_stack"] = inp["tech_stack"]
        if "confidence" in inp:
            # ADaPT confidence score — clamp to 0.0-1.0
            try:
                conf = float(inp["confidence"])
                update["_state_update"]["confidence"] = max(0.0, min(1.0, conf))
            except (ValueError, TypeError):
                pass
        return update

    if tool_name == "get_playbook":
        # Retrieve detailed vulnerability bypass playbook section
        from ai_brain.active.react_playbooks import get_playbook_section, list_playbook_sections
        section = inp.get("section", "")
        if not section:
            sections = list_playbook_sections()
            return {"available_sections": sections}
        content = get_playbook_section(section)
        return {"section": section, "content": _truncate(content, 4000)}

    if tool_name == "formulate_strategy":
        # COA (Course of Action) analysis — forces explicit strategic reasoning
        strategy = {
            "problem": inp.get("problem", ""),
            "candidates": inp.get("candidates", []),
            "selected_action": inp.get("selected_action", ""),
            "next_steps": inp.get("next_steps", []),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        # Store in hypotheses as a strategic decision
        strategy_id = f"strategy_{int(time.time())}"
        return {
            "status": "Strategy formulated",
            "selected_action": strategy["selected_action"],
            "next_steps": strategy["next_steps"],
            "_state_update": {
                "hypotheses": {
                    strategy_id: {
                        "description": f"STRATEGY: {strategy['problem']} -> {strategy['selected_action']}",
                        "status": "pending",
                        "evidence": json.dumps({
                            "candidates": strategy["candidates"],
                            "next_steps": strategy["next_steps"],
                        }, default=str),
                    },
                },
            },
        }

    if tool_name == "get_proxy_traffic":
        if not deps.proxy.is_running:
            return {"entries": [], "message": "Proxy not running."}
        traffic = deps.proxy.get_traffic(
            url_filter=inp.get("url_filter"),
            method_filter=inp.get("method_filter"),
            status_filter=inp.get("status_filter"),
            limit=inp.get("limit", 50),
        )
        # Serialize traffic entries
        entries = []
        for t in traffic:
            entry = t.model_dump() if hasattr(t, "model_dump") else {"url": str(t)}
            entries.append(entry)
        return {"count": len(entries), "entries": entries[:50]}

    # ── Deterministic Attack Tools ──────────────────────────────

    if tool_name == "blind_sqli_extract":
        from ai_brain.active.deterministic_tools import BlindSQLiExtractor
        extractor = BlindSQLiExtractor(deps.scope_guard, deps.config.tools_timeout,
                                       socks_proxy=deps.goja_socks5_url)
        try:
            result = await extractor.extract(**inp)
            # Auto-update findings if extraction succeeded
            if result.get("extracted") and result.get("confidence", 0) > 0.8:
                finding_id = f"blind_sqli_{hashlib.md5(inp['url'].encode()).hexdigest()[:8]}"
                state_update: dict[str, Any] = {"findings": {finding_id: {
                    "vuln_type": "blind_sqli", "endpoint": inp["url"],
                    "parameter": inp["param"], "evidence": result["extracted"],
                    "severity": "critical", "confirmed": False, "tool_used": "blind_sqli_extract",
                }}}
                return {**result, "_state_update": state_update}
            return result
        finally:
            await extractor.close()

    if tool_name == "response_diff_analyze":
        from ai_brain.active.deterministic_tools import ResponseDiffAnalyzer
        analyzer = ResponseDiffAnalyzer(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        return await analyzer.analyze(**inp)

    if tool_name == "compare_responses":
        from ai_brain.active.deterministic_tools import ResponseFingerprinter
        _state = deps.current_state or {}
        # Get or create fingerprinter, load existing baselines from state
        fp = ResponseFingerprinter()
        fp.load_baselines(_state.get("baselines", {}))
        url = inp["url"]
        method = inp.get("method", "GET").upper()
        status = inp["status"]
        headers = inp.get("headers", {})
        body = inp.get("body", "")
        result = fp.compare(url, method, status, headers, body)
        if result.get("baseline") is None:
            # No baseline existed — store this response as the baseline
            fp.add_baseline(url, method, result["fingerprint"])
            result["action"] = "stored as new baseline"
            result["_state_update"] = {"baselines": fp.get_all_baselines()}
        elif not result.get("anomalous"):
            result["action"] = "response matches baseline — likely NOT a vulnerability"
        else:
            result["action"] = "response is ANOMALOUS vs baseline — worth investigating"
        return result

    if tool_name == "systematic_fuzz":
        from ai_brain.active.deterministic_tools import SystematicFuzzer
        fuzzer = SystematicFuzzer(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        result = await fuzzer.fuzz(**inp)
        # Auto-update endpoints from matches
        if result.get("matches"):
            state_update_ep: dict[str, Any] = {"endpoints": {}}
            for m in result["matches"][:20]:
                url = inp["url_template"].replace("{FUZZ}", m["word"])
                state_update_ep["endpoints"][url] = {
                    "method": inp.get("method", "GET"),
                    "notes": "discovered via fuzzing",
                }
            return {**result, "_state_update": state_update_ep}
        return result

    # ── Working Memory Tools ────────────────────────────────────

    if tool_name == "update_working_memory":
        section = inp["section"]
        key = inp["key"]
        value = inp["value"]
        valid_sections = {
            "attack_surface", "vuln_findings", "credentials", "attack_chain", "lessons",
            "response_signatures", "waf_profiles", "chain_evidence", "parameter_map",
        }
        if section not in valid_sections:
            return {"error": f"Invalid section '{section}'. Valid: {valid_sections}"}
        # Return state update that merges into working_memory
        return {"ok": True, "_state_update": {"working_memory": {section: {key: value}}}}

    if tool_name == "read_working_memory":
        section = inp.get("section")
        current_state = deps.current_state or {}
        wm = current_state.get("working_memory", {})
        if section:
            return {"section": section, "data": wm.get(section, {})}
        return {"data": wm}

    if tool_name == "manage_chain":
        action = inp["action"]
        chain_id = inp["chain_id"]
        current_state = deps.current_state or {}
        chains = dict(current_state.get("attack_chains", {}))

        if action == "create":
            goal = inp.get("goal", "")
            steps_input = inp.get("steps", [])
            if not steps_input:
                return {"error": "Steps are required for create action"}
            steps = [
                {"description": s.get("description", s) if isinstance(s, dict) else str(s),
                 "status": "pending", "output": ""}
                for s in steps_input
            ]
            steps[0]["status"] = "in_progress"  # First step starts immediately
            chains[chain_id] = {
                "goal": goal,
                "steps": steps,
                "current_step": 0,
                "confidence": inp.get("confidence", 0.5),
            }
            return {
                "_state_update": {"attack_chains": chains},
                "status": f"Chain '{chain_id}' created with {len(steps)} steps. Step 1 is now active.",
                "current_step": steps[0]["description"],
                "hint": "Execute the current step, then call manage_chain(advance) with the result.",
            }

        elif action == "advance":
            if chain_id not in chains:
                return {"error": f"Chain '{chain_id}' not found"}
            chain = dict(chains[chain_id])
            chain["steps"] = [dict(s) for s in chain["steps"]]
            current = chain["current_step"]
            step_output = inp.get("step_output", "")

            # Mark current step as completed
            if current < len(chain["steps"]):
                chain["steps"][current]["status"] = "completed"
                chain["steps"][current]["output"] = step_output

            # Move to next step
            next_step = current + 1
            if next_step < len(chain["steps"]):
                chain["current_step"] = next_step
                chain["steps"][next_step]["status"] = "in_progress"
                if inp.get("confidence"):
                    chain["confidence"] = inp["confidence"]
                chains[chain_id] = chain
                return {
                    "_state_update": {"attack_chains": chains},
                    "status": f"Step {current + 1} completed. Now on step {next_step + 1}/{len(chain['steps'])}.",
                    "completed_step": chain["steps"][current]["description"],
                    "current_step": chain["steps"][next_step]["description"],
                }
            else:
                chain["current_step"] = next_step
                if inp.get("confidence"):
                    chain["confidence"] = inp["confidence"]
                chains[chain_id] = chain
                return {
                    "_state_update": {"attack_chains": chains},
                    "status": f"All {len(chain['steps'])} steps completed! Chain '{chain_id}' is done.",
                }

        elif action == "fail_step":
            if chain_id not in chains:
                return {"error": f"Chain '{chain_id}' not found"}
            chain = dict(chains[chain_id])
            chain["steps"] = [dict(s) for s in chain["steps"]]
            current = chain["current_step"]
            if current < len(chain["steps"]):
                chain["steps"][current]["status"] = "failed"
                chain["steps"][current]["output"] = inp.get("step_output", "Failed")
            if inp.get("confidence"):
                chain["confidence"] = inp["confidence"]
            chains[chain_id] = chain
            return {
                "_state_update": {"attack_chains": chains},
                "status": f"Step {current + 1} marked as failed. Consider alternative approaches or abandon the chain.",
            }

        elif action == "complete":
            if chain_id in chains:
                chain = dict(chains[chain_id])
                chain["steps"] = [dict(s) for s in chain["steps"]]
                for step in chain["steps"]:
                    if step["status"] == "in_progress":
                        step["status"] = "completed"
                chain["confidence"] = 1.0
                chains[chain_id] = chain
            return {
                "_state_update": {"attack_chains": chains},
                "status": f"Chain '{chain_id}' marked as complete.",
            }

        elif action == "abandon":
            if chain_id in chains:
                del chains[chain_id]
            return {
                "_state_update": {"attack_chains": chains},
                "status": f"Chain '{chain_id}' abandoned.",
            }

        return {"error": f"Unknown action: {action}"}

    # ── Advanced Attack Tools ─────────────────────────────────────

    if tool_name == "waf_fingerprint":
        engine = deps.waf_engine or WafBypassEngine(deps.scope_guard)
        if not deps.waf_engine:
            deps.waf_engine = engine
        profile = await engine.fingerprint(
            target_url=inp["url"],
            test_param=inp.get("test_param", "q"),
            cookies=inp.get("cookies"),
        )
        return {
            "waf_vendor": profile.waf_vendor,
            "blocked_keywords": sorted(profile.blocked_keywords),
            "allowed_keywords": sorted(profile.allowed_keywords),
            "bypass_encodings": sorted(profile.allowed_encodings),
            "notes": profile.notes[:10],
            "summary": profile.summary(),
        }

    if tool_name == "waf_generate_bypasses":
        engine = deps.waf_engine or WafBypassEngine(deps.scope_guard)
        domain = inp["domain"]
        profile = engine.get_profile(domain)
        if not profile:
            return {"error": f"No WAF profile for {domain}. Run waf_fingerprint first."}
        attack_type = inp["attack_type"]
        if attack_type == "xss":
            bypasses = engine.generate_xss_bypasses(profile)
        elif attack_type == "sqli":
            bypasses = engine.generate_sqli_bypasses(profile)
        elif attack_type == "cmdi":
            bypasses = engine.generate_cmdi_bypasses(profile)
        elif attack_type == "path_traversal":
            bypasses = engine.generate_path_traversal_bypasses(profile)
        else:
            return {"error": f"Unsupported attack type: {attack_type}"}
        return {"bypasses": bypasses[:20], "total": len(bypasses)}

    if tool_name == "test_http_smuggling":
        tester = HTTPSmugglingTester(deps.scope_guard)
        findings = await tester.test(
            target_url=inp["url"],
            cookies=inp.get("cookies"),
        )
        return {"findings": findings, "count": len(findings)}

    if tool_name == "test_cache_poisoning":
        tester = CachePoisonTester(deps.scope_guard)
        findings = await tester.test(
            target_url=inp["url"],
            cookies=inp.get("cookies"),
        )
        return {"findings": findings, "count": len(findings)}

    if tool_name == "test_ghost_params":
        discovery = GhostParamDiscovery(deps.scope_guard)
        findings = await discovery.test(
            target_url=inp["url"],
            method=inp.get("method", "POST"),
            original_body=inp.get("original_body"),
            cookies=inp.get("cookies"),
        )
        return {"findings": findings, "count": len(findings)}

    if tool_name == "test_prototype_pollution":
        tester = PrototypePollutionTester(deps.scope_guard)
        findings = await tester.test(
            target_url=inp["url"],
            cookies=inp.get("cookies"),
        )
        return {"findings": findings, "count": len(findings)}

    if tool_name == "test_open_redirect":
        tester = OpenRedirectTester(deps.scope_guard)
        findings = await tester.test(
            target_url=inp["url"],
            cookies=inp.get("cookies"),
        )
        return {"findings": findings, "count": len(findings)}

    if tool_name == "profile_endpoint_behavior":
        profiler = deps.behavior_profiler or BehaviorProfiler(deps.scope_guard)
        if not deps.behavior_profiler:
            deps.behavior_profiler = profiler
        param = inp["param"]
        test_values = inp.get("test_values")
        if test_values:
            anomalies = await profiler.detect_anomalies(
                url=inp["url"],
                param=param,
                test_values=test_values,
                method=inp.get("method", "GET"),
                cookies=inp.get("cookies"),
            )
        else:
            # Default to type confusion testing
            anomalies = await profiler.test_type_confusion(
                url=inp["url"],
                param=param,
                method=inp.get("method", "GET"),
                cookies=inp.get("cookies"),
            )
        return {"anomalies": anomalies, "count": len(anomalies)}

    if tool_name == "discover_chains":
        engine = deps.chain_engine or ChainDiscoveryEngine()
        if not deps.chain_engine:
            deps.chain_engine = engine
        # Feed current findings into chain engine
        state = deps.current_state or {}
        findings = state.get("findings", {})
        for fid, fdata in findings.items():
            engine.add_finding(fdata)
        chains = engine.get_chains()
        suggestions = engine.get_chain_suggestions()
        return {
            "chains": chains,
            "chain_count": len(chains),
            "suggestions": suggestions[:10],
        }

    if tool_name == "deep_research":
        if not deps.agent_c_research:
            return {"error": "Deep research not available. Enable with --zai-research flag."}
        situation = inp.get("situation", "")
        if not situation:
            return {"error": "situation is required — describe what you're seeing in detail."}
        # Build context from current state
        state = deps.current_state or {}
        tech_stack = state.get("tech_stack", [])
        target_url = state.get("target_url", "")
        # Collect already-tried from state
        tested = state.get("tested_techniques", {})
        tried_str = inp.get("already_tried", "")
        if tested and not tried_str:
            tried_str = ", ".join(list(tested.keys())[:30])
        # Collect existing findings summary
        findings = state.get("findings", {})
        findings_str = ""
        if findings:
            f_lines = []
            for fid, fd in list(findings.items())[:10]:
                f_lines.append(f"- {fd.get('vuln_type', '?')}: {fd.get('endpoint', '?')} ({fd.get('severity', '?')})")
            findings_str = "\n".join(f_lines)
        result = await deps.agent_c_research.research(
            situation=situation,
            target_url=target_url,
            tech_stack=tech_stack,
            question=inp.get("question", ""),
            already_tried=tried_str,
            existing_findings=findings_str,
        )
        # Format for the agent
        if result.get("success"):
            output = {
                "status": "success",
                "research": result.get("research_text", "")[:8000],
                "techniques_found": len(result.get("techniques", [])),
                "cves_found": result.get("cves", []),
                "web_search_used": result.get("web_search_used", False),
                "duration_s": result.get("duration_s", 0),
            }
            # Include top techniques as structured data
            techniques = result.get("techniques", [])[:5]
            if techniques:
                output["top_techniques"] = techniques
            return output
        return {
            "status": "failed",
            "error": result.get("error", "Unknown error"),
            "partial_research": result.get("research_text", "")[:2000],
        }

    if tool_name == "solve_captcha":
        ctx = inp.get("context_name", "default")
        await _ensure_context(deps, ctx)
        solved = await _try_solve_captcha(deps, ctx)
        if solved:
            # Get detection type from solver's cached result (no re-detection)
            captcha_type = "unknown"
            if deps.captcha_solver and hasattr(deps.captcha_solver, "_last_detection"):
                det = deps.captcha_solver._last_detection
                if det:
                    captcha_type = det.captcha_type.value
            return {
                "status": "solved",
                "captcha_type": captcha_type,
                "message": "CAPTCHA solved and token injected. You can now submit the form.",
            }
        return {
            "status": "failed",
            "message": (
                "No CAPTCHA detected or solving failed. "
                "Check if the page has a visible CAPTCHA. "
                "For reCAPTCHA/hCaptcha/Turnstile, a --captcha-api-key is required."
            ),
        }

    if tool_name == "test_ssrf":
        from ai_brain.active.deterministic_tools import SSRFTester
        tester = SSRFTester(
            deps.scope_guard,
            timeout=deps.config.tools_timeout if hasattr(deps.config, 'tools_timeout') else 10,
            socks_proxy=deps.goja_socks5_url,
        )
        try:
            return await tester.test(
                url=inp["url"],
                param=inp["param"],
                method=inp.get("method", "GET"),
                cookies=inp.get("cookies"),
                headers=inp.get("headers"),
                body=inp.get("body"),
            )
        finally:
            await tester.close()

    if tool_name == "test_ssti":
        from ai_brain.active.deterministic_tools import SSTITester
        tester = SSTITester(
            deps.scope_guard,
            timeout=deps.config.tools_timeout if hasattr(deps.config, 'tools_timeout') else 10,
            socks_proxy=deps.goja_socks5_url,
        )
        _ssti_param = inp.get("param", "")
        if not _ssti_param:
            return {"error": "test_ssti requires a 'param' parameter (the query/body parameter to test)"}
        try:
            return await tester.test(
                url=inp["url"],
                param=_ssti_param,
                method=inp.get("method", "GET"),
                cookies=inp.get("cookies"),
                headers=inp.get("headers"),
                body=inp.get("body"),
            )
        finally:
            await tester.close()

    if tool_name == "test_race_condition":
        from ai_brain.active.deterministic_tools import RaceConditionTester
        tester = RaceConditionTester(
            deps.scope_guard,
            timeout=deps.config.tools_timeout if hasattr(deps.config, 'tools_timeout') else 15,
            socks_proxy=deps.goja_socks5_url,
        )
        concurrent = min(inp.get("concurrent_requests", 20), 50)
        return await tester.test(
            url=inp["url"],
            method=inp.get("method", "POST"),
            body=inp.get("body"),
            headers=inp.get("headers"),
            cookies=inp.get("cookies"),
            concurrent_requests=concurrent,
        )

    if tool_name == "analyze_graphql":
        from ai_brain.active.deterministic_tools import GraphQLAnalyzer
        analyzer = GraphQLAnalyzer(
            deps.scope_guard,
            timeout=deps.config.tools_timeout if hasattr(deps.config, 'tools_timeout') else 15,
            socks_proxy=deps.goja_socks5_url,
        )
        try:
            return await analyzer.analyze(
                url=inp["url"],
                cookies=inp.get("cookies"),
                headers=inp.get("headers"),
            )
        finally:
            await analyzer.close()

    if tool_name == "analyze_js_bundle":
        from ai_brain.active.deterministic_tools import SecretScanner
        scanner = SecretScanner()
        urls = inp.get("urls") or ([inp["url"]] if inp.get("url") else [])
        urls = urls[:15]  # Cap at 15

        async with _make_httpx_client(deps, timeout=15) as client:
            all_results = {"bundles_analyzed": 0, "secrets": [], "api_endpoints": [],
                          "internal_urls": [], "graphql_ops": [], "source_maps": [],
                          "debug_routes": [], "admin_paths": []}
            for js_url in urls:
                try:
                    resp = await client.get(js_url, headers=deps.default_headers or {})
                    if resp.status_code == 200 and len(resp.text) > 0:
                        scan = scanner.scan(resp.text)
                        all_results["bundles_analyzed"] += 1
                        for key in scan:
                            for item in scan[key]:
                                item["source_url"] = js_url
                                all_results[key].append(item)
                except Exception as e:
                    logger.debug("js_bundle_fetch_failed", url=js_url, error=str(e)[:80])
        return all_results

    if tool_name == "test_authz_matrix":
        from ai_brain.active.deterministic_tools import AuthorizationMatrixTester
        tester = AuthorizationMatrixTester(
            deps.scope_guard,
            timeout=deps.config.tools_timeout if hasattr(deps.config, 'tools_timeout') else 10,
            socks_proxy=deps.goja_socks5_url,
        )
        try:
            return await tester.test(
                endpoints=inp["endpoints"],
                auth_contexts=inp.get("auth_contexts", {}),
            )
        finally:
            await tester.close()

    if tool_name == "finish_test":
        # In indefinite mode, reject finish and tell brain to keep going
        max_turns = deps.max_turns if hasattr(deps, "max_turns") else 150
        if max_turns == 0:
            budget_spent = 0.0
            budget_limit = 999.0
            if deps.current_state:
                budget_spent = deps.current_state.get("budget_spent", 0.0)
                budget_limit = deps.current_state.get("budget_limit", 999.0)
            remaining = budget_limit - budget_spent
            return {
                "error": (
                    f"INDEFINITE MODE: You cannot finish. You have ${remaining:.0f} "
                    "budget remaining. Pivot strategy: try new subdomains, create "
                    "accounts, test authenticated surfaces, analyze JS bundles, "
                    "check for subdomain takeover, test API rate limiting, "
                    "or probe different attack vectors. KEEP GOING."
                )
            }
        return {
            "_done": True,
            "assessment": inp.get("assessment", ""),
            "confidence": inp.get("confidence", "medium"),
        }

    # ── Subtask Plan Tools ──────────────────────────────────────────
    if tool_name == "plan_subtasks":
        subtasks = inp.get("subtasks", [])
        if not subtasks:
            return {"error": "No subtasks provided"}
        plan = []
        for st in subtasks:
            plan.append({
                "id": st.get("id", f"task-{len(plan)+1}"),
                "description": st.get("description", ""),
                "priority": st.get("priority", "medium"),
                "status": "pending",
                "result_summary": "",
            })
        return {"_state_update": {"subtask_plan": plan}, "plan_created": len(plan)}

    if tool_name == "refine_plan":
        action = inp.get("action", "")
        subtask_id = inp.get("subtask_id", "")
        current_plan = list(deps.current_state.get("subtask_plan", [])) if deps.current_state else []

        if action == "add":
            new_st = inp.get("subtask", {})
            if not new_st:
                return {"error": "Missing 'subtask' for add action"}
            current_plan.append({
                "id": new_st.get("id", f"task-{len(current_plan)+1}"),
                "description": new_st.get("description", ""),
                "priority": new_st.get("priority", "medium"),
                "status": "pending",
                "result_summary": "",
            })
            return {"_state_update": {"subtask_plan": current_plan}, "added": new_st.get("id")}

        # Find the subtask by ID
        idx = next((i for i, s in enumerate(current_plan) if s.get("id") == subtask_id), -1)
        if idx == -1:
            return {"error": f"Subtask '{subtask_id}' not found"}

        if action == "complete":
            current_plan[idx]["status"] = "done"
            current_plan[idx]["result_summary"] = inp.get("result_summary", "completed")
        elif action == "skip":
            current_plan[idx]["status"] = "skipped"
            current_plan[idx]["result_summary"] = inp.get("result_summary", "skipped")
        elif action == "start":
            current_plan[idx]["status"] = "in_progress"
        elif action == "remove":
            current_plan.pop(idx)
        else:
            return {"error": f"Unknown action: {action}"}

        return {"_state_update": {"subtask_plan": current_plan}, "updated": subtask_id}

    # ── External Functions API ──────────────────────────────────────
    from ai_brain.active.react_prompt import _EXTERNAL_ENDPOINTS
    if tool_name in _EXTERNAL_ENDPOINTS:
        return await _call_external_tool(_EXTERNAL_ENDPOINTS[tool_name], inp, deps)

    return {"error": f"Unknown tool: {tool_name}"}


async def _call_external_tool(endpoint: str, params: dict, deps: ToolDeps) -> dict:
    """HTTP POST to an external tool endpoint. 60s timeout. JSON response."""
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(endpoint, json=params)
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        return {"error": f"External tool timeout (60s): {endpoint}"}
    except Exception as e:
        return {"error": f"External tool error: {e}"}


# ── Helper Functions ─────────────────────────────────────────────────


async def _ensure_context(deps: ToolDeps, context_name: str) -> None:
    """Ensure a browser context exists, creating it if needed."""
    if not deps.browser.is_started:
        return  # Dry run or not started
    try:
        # Check if context exists by trying to access it
        if context_name not in deps.browser._contexts:
            await deps.browser.create_context(context_name)
    except Exception:
        try:
            await deps.browser.create_context(context_name)
        except Exception:
            pass  # Context already exists


async def _crawl_bfs(
    deps: ToolDeps,
    context_name: str,
    start_url: str,
    max_pages: int,
) -> dict[str, Any]:
    """BFS crawl from start_url, extracting page info at each step."""
    from urllib.parse import urljoin, urlparse

    visited: set[str] = set()
    queue: list[str] = [start_url]
    pages: list[dict[str, Any]] = []
    all_forms: list[dict[str, Any]] = []
    all_js_endpoints: set[str] = set()

    allowed = deps.scope_guard._allowed_domains if hasattr(deps.scope_guard, "_allowed_domains") else []

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        normalized = url.split("#")[0].split("?")[0]  # Normalize
        if normalized in visited:
            continue
        visited.add(normalized)

        try:
            deps.scope_guard.validate_url(url)
        except Exception:
            continue

        try:
            await deps.browser.navigate(context_name, url)
            info = await deps.browser.extract_page_info(context_name)
            pages.append({
                "url": url,
                "title": info.get("title", ""),
                "forms_count": len(info.get("forms", [])),
            })

            # Collect forms
            for form in info.get("forms", []):
                form["page_url"] = url
                all_forms.append(form)

            # Add new links to queue
            for link in info.get("links", []):
                href = link if isinstance(link, str) else link.get("href", "")
                if not href:
                    continue
                full = urljoin(url, href)
                norm = full.split("#")[0].split("?")[0]
                if norm not in visited:
                    try:
                        deps.scope_guard.validate_url(full)
                        queue.append(full)
                    except Exception:
                        pass

            # Extract JS-embedded API endpoints from page context
            js_eps = await _extract_js_endpoints(deps, context_name)
            for ep in js_eps:
                if ep not in all_js_endpoints:
                    all_js_endpoints.add(ep)
                    # Also add full URLs to queue for crawling
                    full_ep = urljoin(url, ep)
                    norm_ep = full_ep.split("#")[0].split("?")[0]
                    if norm_ep not in visited:
                        try:
                            deps.scope_guard.validate_url(full_ep)
                            queue.append(full_ep)
                        except Exception:
                            pass

        except Exception as e:
            pages.append({"url": url, "error": str(e)})

    result = {
        "pages_visited": len(pages),
        "pages": pages,
        "forms_found": len(all_forms),
        "forms": all_forms[:30],
        "urls_in_queue": len(queue),
    }
    if all_js_endpoints:
        result["js_api_endpoints"] = sorted(all_js_endpoints)

    # ── Auto-JS-bundle secret scanning on crawl (Change 2c) ──
    # Extract JS bundle URLs from page scripts, scan top 10 by size for secrets
    try:
        from ai_brain.active.deterministic_tools import SecretScanner
        scanner = SecretScanner()
        js_urls = set()
        for page in pages:
            # Scripts are extracted during page visits but stored in page_info
            # We already have js_api_endpoints — also scan external .js src
            pass
        # Collect script src URLs from all visited pages
        for page in pages:
            url_base = page.get("url", start_url)
            # Re-check for script src in forms data
        # Scan any discovered JS bundles from inline script endpoints
        all_js_bundle_secrets = []
        if all_js_endpoints:
            js_bundle_urls = [
                urljoin(start_url, ep) for ep in all_js_endpoints
                if ep.endswith(".js") and not any(
                    skip in ep for skip in ("vendor", "polyfill", "chunk", "webpack", "runtime")
                )
            ][:10]
            if js_bundle_urls:
                async with _make_httpx_client(deps, timeout=10) as js_client:
                    for js_url in js_bundle_urls:
                        try:
                            resp = await js_client.get(js_url)
                            if resp.status_code == 200 and len(resp.text) > 100:
                                scan = scanner.scan(resp.text)
                                for category, items in scan.items():
                                    for item in items:
                                        item["source_url"] = js_url
                                        all_js_bundle_secrets.append(item)
                        except Exception:
                            pass
                if all_js_bundle_secrets:
                    result["js_secrets"] = all_js_bundle_secrets[:50]
    except Exception as e:
        logger.debug("auto_js_scan_failed", error=str(e)[:80])

    return result


async def _extract_js_endpoints(deps: ToolDeps, context_name: str) -> list[str]:
    """Extract API endpoints from JavaScript in the current page.

    Runs browser JS to scan inline scripts, __NEXT_DATA__, and DOM attributes
    for API routes and interesting paths.
    """
    # Simple JS endpoint extraction — uses string matching instead of complex regex
    # to avoid Python/JS escaping issues
    js_code = """(() => {
const eps = new Set();
// Extract from all script tags
document.querySelectorAll('script').forEach(s => {
  const t = s.textContent || '';
  // Find quoted strings that look like paths
  const re = /["'](\\/[a-z][a-z0-9\\/_-]{1,60})["']/gi;
  let m;
  while ((m = re.exec(t)) !== null) {
    const p = m[1];
    if (!p.includes('.css') && !p.includes('.png') && !p.includes('.jpg')
        && !p.includes('.svg') && !p.includes('.ico') && !p.includes('.woff')
        && !p.includes('webpack') && !p.includes('_next') && p.length < 80) {
      eps.add(p);
    }
  }
});
// __NEXT_DATA__
const nd = document.getElementById('__NEXT_DATA__');
if (nd) { try { const d = JSON.parse(nd.textContent); if (d.page) eps.add(d.page); } catch(e){} }
// Image/script src attributes
document.querySelectorAll('img[src],script[src]').forEach(el => {
  const s = el.getAttribute('src') || '';
  if (s.startsWith('/api/') || s.includes('/s3/') || s.includes('/storage/')) eps.add(s.split('?')[0]);
});
// Link hrefs
document.querySelectorAll('a[href]').forEach(el => {
  const h = el.getAttribute('href') || '';
  if (h.startsWith('/') && !h.startsWith('//')) eps.add(h.split('?')[0].split('#')[0]);
});
return Array.from(eps).filter(e => e.length > 1 && e.length < 80);
})()"""
    try:
        result = await deps.browser.execute_js(context_name, js_code)
        if isinstance(result, list):
            return [str(ep) for ep in result if isinstance(ep, str)]
        return []
    except Exception as e:
        logger.debug("js_endpoint_extraction_failed", error=str(e))
        return []


def _match_field(field_info: dict, target: str) -> int:
    """Score how well a form field matches a target (email/password/username). 0 = no match."""
    name = field_info.get("name", "").lower()
    ftype = field_info.get("type", "text").lower()
    placeholder = field_info.get("placeholder", "").lower()
    label = field_info.get("label", "").lower()
    all_text = f"{name} {placeholder} {label}"

    if target == "email":
        score = 0
        if ftype == "email":
            score += 10
        if "email" in name or "mail" in name:
            score += 5
        if "email" in placeholder or "mail" in placeholder:
            score += 3
        return score
    elif target == "password":
        score = 0
        if ftype == "password":
            score += 10
        if "pass" in name:
            score += 5
        if "password" in placeholder:
            score += 3
        return score
    elif target == "username":
        score = 0
        if "user" in name or "login" in name or "account" in name:
            score += 5
        if "user" in placeholder or "login" in placeholder:
            score += 3
        # Don't match generic "name" fields
        if name in ("first_name", "last_name", "company_name", "full_name",
                     "firstname", "lastname", "companyname", "fullname"):
            return 0
        if ftype == "text" and ("user" in all_text or "login" in all_text):
            score += 2
        return score
    elif target == "phone":
        score = 0
        if ftype == "tel":
            score += 10
        if any(kw in name for kw in ("phone", "mobile", "tel", "cell")):
            score += 5
        if any(kw in placeholder for kw in ("phone", "mobile")):
            score += 3
        return score
    elif target == "name":
        score = 0
        if name in ("name", "full_name", "fullname", "display_name", "displayname"):
            score += 5
        if "your name" in placeholder or "full name" in placeholder:
            score += 3
        return score
    return 0


async def _register_account(
    deps: ToolDeps,
    inp: dict[str, Any],
) -> dict[str, Any]:
    """Register a test account via browser + email verification."""
    reg_url = inp["registration_url"]
    username = inp.get("username") or f"test_{secrets.token_hex(5)}"
    password = inp.get("password") or f"T3st!{secrets.token_hex(8)}"
    role = inp.get("role_hint", "user")
    ctx_name = f"ctx_{role}_{secrets.token_hex(3)}"

    await _ensure_context(deps, ctx_name)

    # Generate email if email manager is configured
    email = ""
    if deps.email_mgr and deps.email_mgr.is_configured:
        email = deps.email_mgr.generate_email(prefix=role)

    # Navigate to registration page
    try:
        await deps.browser.navigate(ctx_name, reg_url)
        page_info = await deps.browser.extract_page_info(ctx_name)
    except Exception as e:
        return {"error": f"Failed to navigate to registration: {e}"}

    # Try to fill visible form fields
    forms = page_info.get("forms", [])
    if not forms:
        return {"error": "No forms found on registration page", "page_info": page_info}

    # Score-based field matching using name + type + placeholder
    email_val = email or f"{username}@example.com"
    filled_fields = []
    for form in forms:
        for field_info in form.get("fields", []):
            field_name = field_info.get("name", "")
            field_type = field_info.get("type", "text")

            # Skip unfillable and invisible fields
            if field_type in {"hidden", "submit", "button", "image", "reset"}:
                continue
            if not field_info.get("visible", True):
                continue

            # Score-based matching (highest priority first)
            value = None
            if _match_field(field_info, "email") > 0:
                value = email_val
            elif _match_field(field_info, "password") > 0:
                value = password
            elif _match_field(field_info, "username") > 0:
                value = username
            elif _match_field(field_info, "name") > 0:
                value = username
            elif _match_field(field_info, "phone") > 0:
                value = "+15551234567"
            elif field_type == "checkbox":
                fname_lower = field_name.lower()
                if any(kw in fname_lower for kw in ("terms", "agree", "accept", "tos", "consent")):
                    value = True

            if value is not None:
                try:
                    selector = f"[name='{field_name}']"
                    if value is True:
                        await deps.browser.click(ctx_name, selector)
                    else:
                        await deps.browser.fill(ctx_name, selector, str(value))
                    filled_fields.append(field_name)
                except Exception as e:
                    logger.warning("register_field_fill_failed",
                                   field=field_name, error=str(e)[:80])

    # Handle CAPTCHA if present
    captcha_solved = await _try_solve_captcha(deps, ctx_name)

    # Submit the form
    try:
        await deps.browser.submit_form(ctx_name)
        await asyncio.sleep(2)
    except Exception as e:
        return {"error": f"Form submission failed: {e}", "filled_fields": filled_fields}

    # Wait for email verification if configured
    verification_done = False
    if email and deps.email_mgr and deps.email_mgr.is_configured:
        try:
            email_data = await deps.email_mgr.wait_for_email(
                recipient=email, timeout=30,
            )
            if email_data:
                from ai_brain.active.email import EmailManager
                link = EmailManager.extract_verification_link(
                    email_data.get("body", ""),
                )
                if link:
                    await deps.browser.navigate(ctx_name, link)
                    verification_done = True
        except Exception as e:
            logger.warning("email_verification_failed", error=str(e))

    return {
        "status": "registered",
        "username": username,
        "password": password,
        "email": email,
        "context_name": ctx_name,
        "role": role,
        "filled_fields": filled_fields,
        "captcha_solved": captcha_solved,
        "email_verified": verification_done,
        "_state_update": {
            "accounts": {
                username: {
                    "password": password,
                    "email": email,
                    "role": role,
                    "context_name": ctx_name,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                },
            },
        },
    }


async def _login_account(
    deps: ToolDeps,
    inp: dict[str, Any],
) -> dict[str, Any]:
    """Log in to the target with existing credentials."""
    login_url = inp["login_url"]
    username = inp["username"]
    password = inp["password"]
    ctx_name = inp.get("context_name", "default")

    await _ensure_context(deps, ctx_name)

    try:
        await deps.browser.navigate(ctx_name, login_url)
        page_info = await deps.browser.extract_page_info(ctx_name)
    except Exception as e:
        return {"error": f"Failed to navigate to login: {e}"}

    # Fill login form using score-based field matching
    forms = page_info.get("forms", [])
    for form in forms:
        for field_info in form.get("fields", []):
            field_name = field_info.get("name", "")
            field_type = field_info.get("type", "text")
            if field_type in {"hidden", "submit", "button", "image", "reset"}:
                continue
            if not field_info.get("visible", True):
                continue

            value = None
            if _match_field(field_info, "password") > 0:
                value = password
            elif _match_field(field_info, "email") > 0:
                value = username  # Login with username/email
            elif _match_field(field_info, "username") > 0:
                value = username

            if value is not None:
                try:
                    await deps.browser.fill(ctx_name, f"[name='{field_name}']", value)
                except Exception as e:
                    logger.warning("login_field_fill_failed",
                                   field=field_name, error=str(e)[:80])

    # Handle CAPTCHA
    await _try_solve_captcha(deps, ctx_name)

    # Submit
    try:
        await deps.browser.submit_form(ctx_name)
        await asyncio.sleep(2)
        post_login = await deps.browser.extract_page_info(ctx_name)
    except Exception as e:
        return {"error": f"Login submission failed: {e}"}

    # Check if we're still on the login page
    cookies = await deps.browser.get_cookies(ctx_name)
    session_cookies = [c for c in cookies if "session" in c.get("name", "").lower()]

    return {
        "status": "logged_in",
        "username": username,
        "context_name": ctx_name,
        "post_login_url": post_login.get("url", ""),
        "post_login_title": post_login.get("title", ""),
        "session_cookies": len(session_cookies),
        "total_cookies": len(cookies),
    }


_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_REQUIRED_FINDING_FIELDS = ("vuln_type", "endpoint", "severity")

# ── Anti-fabrication: tool provenance allowlist ──
_REAL_TOOL_NAMES = frozenset({
    "test_sqli", "test_xss", "test_cmdi", "test_ssrf", "test_ssti",
    "test_auth_bypass", "test_idor", "test_jwt", "test_file_upload",
    "test_race_condition", "test_authz_matrix",
    "blind_sqli_extract", "systematic_fuzz", "response_diff_analyze",
    "run_content_discovery", "send_http_request", "run_custom_exploit",
    "navigate_and_extract", "browser_interact", "run_dalfox", "run_sqlmap",
    "cors_tester", "open_redirect_tester", "cache_poison_tester",
    "http_smuggling_tester", "ghost_param_discovery", "behavioral_profiler",
    "run_commix", "deep_research", "crawl_target", "enumerate_subdomains",
    "test_http_smuggling", "test_cache_poisoning", "test_ghost_params",
    "test_prototype_pollution", "test_open_redirect", "test_cors",
    "profile_endpoint_behavior", "waf_fingerprint", "waf_generate_bypasses",
    "analyze_graphql", "analyze_js_bundle",
    "scan_info_disclosure", "scan_auth_bypass", "scan_csrf", "scan_error_responses",
    "scan_crlf", "scan_host_header",
    "scan_nosqli", "scan_xxe", "scan_deserialization", "scan_dos", "scan_jwt_deep",
    "discover_auth_endpoints",
    "build_app_model",
    "recon_blitz_opus",
})

# ── Anti-fabrication: reject summary/meta vuln types ──
_REJECT_VULN_TYPE_WORDS = frozenset({
    "multiple", "assessment", "summary", "complete", "overview",
    "general", "comprehensive", "final", "testing_complete",
})

# ── Evidence quality: at least one concrete indicator must be present ──
_EVIDENCE_INDICATORS = re.compile(
    r"HTTP/[12][\.\d]*\s+\d{3}"  # HTTP status line (strict — not just any 3 digits)
    r"|https?://\S+"    # URL
    r"|<[a-zA-Z][^>]*>" # HTML/XML tag
    r'|\{"\w+'          # JSON object with a key
    r"|<script"         # XSS payload
    r"|UNION\s+SELECT"  # SQLi payload (strict)
    r"|\{\{7\*7\}\}"    # SSTI payload (strict)
    r"|alert\("         # XSS indicator
    r"|Location:\s*\S+" # HTTP redirect header with value
    r"|Content-Type:\s*\S+" # HTTP header with value
    r"|Set-Cookie:\s*\S+" # HTTP header with value
    r"|sleep\s*\(\s*\d" # Time-based injection (function call)
    , re.IGNORECASE,
)

_MIN_EVIDENCE_LENGTH = 100  # Must have room for HTTP status + header + body snippet

# ── Vuln type canonicalization for dedup ──
_VULN_TYPE_CANONICAL: dict[str, str] = {
    "reflected_xss": "xss", "stored_xss": "xss", "cross_site_scripting": "xss",
    "dom_xss": "xss", "dom_based_xss": "xss",
    "sql_injection": "sqli", "blind_sqli": "sqli", "union_sqli": "sqli",
    "time_based_sqli": "sqli", "error_based_sqli": "sqli",
    "command_injection": "cmdi", "os_command_injection": "cmdi",
    "server_side_request_forgery": "ssrf", "open_redirect": "redirect",
    "url_redirect": "redirect", "unvalidated_redirect": "redirect",
    "cors_misconfiguration": "cors", "cors_bypass": "cors",
    "account_takeover": "ato", "path_traversal": "lfi",
    "directory_traversal": "lfi", "local_file_inclusion": "lfi",
    "nosql_injection": "nosqli",
    "information_disclosure": "info_disclosure", "info": "info_disclosure",
    "sensitive_data_exposure": "info_disclosure",
    "broken_authentication": "auth_bypass", "auth_bypass": "auth_bypass",
    "authentication_bypass": "auth_bypass",
    "broken_access_control": "access_control", "access_control_bypass": "access_control",
    "privilege_escalation": "privesc", "idor": "idor",
    "insecure_direct_object_reference": "idor",
    "host_header_injection": "host_header", "http_header_injection": "header_injection",
    "credential_exposure": "info_disclosure", "token_exposure": "info_disclosure",
    "oauth_token_theft": "oauth", "oauth_bypass": "oauth",
    "subdomain_takeover": "subdomain_takeover",
    "missing_rate_limit": "rate_limit", "rate_limiting": "rate_limit",
    "session_fixation": "session",
    "multiple_vulnerabilities": "REJECT",
    "multiple_critical_vulnerabilities": "REJECT",
    "multiple_critical": "REJECT",
}


def _canonicalize_vuln_type(vt: str) -> str:
    """Normalize vuln_type to a canonical form for dedup."""
    vt_lower = vt.lower().strip()
    return _VULN_TYPE_CANONICAL.get(vt_lower, vt_lower)


def _has_raw_http_artifacts(evidence: str) -> bool:
    """Check if evidence contains actual HTTP response data vs narrative description.

    Returns True if evidence has real HTTP artifacts — status lines, headers,
    JSON/HTML response bodies — not just prose claims about what happened.
    """
    # Actual HTTP status line: "HTTP/1.1 200 OK"
    if re.search(r"HTTP/[12](?:\.\d)?\s+\d{3}", evidence):
        return True
    # Actual response headers (Header-Name: value) at start of line
    if re.search(
        r"^(?:Content-Type|Set-Cookie|Location|X-[A-Za-z-]+|Server|Date|"
        r"Cache-Control|WWW-Authenticate|Access-Control|Strict-Transport"
        r"):\s+\S",
        evidence, re.MULTILINE | re.IGNORECASE,
    ):
        return True
    # JSON response body (key-value pairs with quoted keys)
    if re.search(r'"[a-zA-Z_]\w*"\s*:\s*["\d\[{tnf]', evidence):
        return True
    # HTML response (multiple distinct tags — not just one mentioned in prose)
    html_tags = set(re.findall(
        r"<(html|head|body|div|span|form|input|meta|link|script|style|"
        r"table|tr|td|p|a|img|iframe|header|footer|nav|ul|li|h[1-6])\b",
        evidence, re.IGNORECASE,
    ))
    if len(html_tags) >= 3:
        return True
    # curl-style verbose output
    if re.search(r"[<>]\s+(?:HTTP/|GET |POST |PUT |DELETE |HEAD )", evidence):
        return True
    # Raw response with content-length numbers in context
    if re.search(r"Content-Length:\s*\d+", evidence, re.IGNORECASE):
        return True
    return False


def _score_evidence(finding: dict) -> tuple[int, str]:
    """Score evidence quality 0-5. Returns (score, reason).

    5 = DEFINITIVE: OOB callback confirmed, extracted data from blind channel
    4 = CONFIRMED: Payload reflected in executable context, data extracted
    3 = STRONG: ≥2 distinct anomaly signals WITH raw HTTP data
    2 = MODERATE: Single anomalous signal or narrative-only claims
    1 = WEAK: Describes intent without response data
    0 = NONE: Empty or purely request-side data

    IMPORTANT: Narrative claims ("confirmed", "returns 49") are NOT trusted
    unless accompanied by actual HTTP response data (headers, body, status line).
    """
    evidence = str(finding.get("evidence", ""))
    if not evidence or len(evidence) < 20:
        return 0, "no evidence"

    # Check for actual HTTP response artifacts (not narrative)
    has_http = _has_raw_http_artifacts(evidence)

    # Anti-patterns: force score ≤1 if evidence only describes intent
    _INTENT_ONLY = re.compile(
        r"^(?:.*(?:might be|possibly|could indicate|may be|appears to|"
        r"potentially|suggests?|likely|probably|seems|i think|i believe).*)$",
        re.IGNORECASE | re.DOTALL,
    )
    if _INTENT_ONLY.search(evidence) and not has_http:
        return 1, "intent-only description without response data"

    # Score 5: Definitive indicators — actual extracted data (hard to fabricate)
    _DEFINITIVE = [
        re.compile(r"root:x:0:0"),
        re.compile(r"uid=\d+.*gid=\d+"),
        re.compile(r"callback.*received|oob.*confirmed|interactsh.*hit", re.IGNORECASE),
        re.compile(r"\|\s*\w+\s*\|\s*\w+\s*\|"),  # pipe-delimited table rows
        re.compile(r"(?:sleep|delay)\s*\d+\s*(?:=|caused|resulted)\s*\d+\.?\d*\s*s", re.IGNORECASE),
    ]
    for pat in _DEFINITIVE:
        if pat.search(evidence):
            return 5, f"definitive: {pat.pattern[:40]}"

    # Score 5 for secrets/tokens ONLY if they look like real data (long, high-entropy)
    secret_match = re.search(r"(?:password|secret|token|api_key|apikey)\s*[:=]\s*(\S{8,})", evidence, re.IGNORECASE)
    if secret_match:
        val = secret_match.group(1).strip("\"'")
        # Real secrets have mixed chars; fabricated ones are often descriptive
        has_digit = bool(re.search(r"\d", val))
        has_upper = bool(re.search(r"[A-Z]", val))
        has_lower = bool(re.search(r"[a-z]", val))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", val))
        entropy_signals = sum([has_digit, has_upper, has_lower, has_special])
        if entropy_signals >= 3 and len(val) >= 16:
            return 5, f"definitive: high-entropy secret ({len(val)} chars)"

    # Score 4: Confirmed indicators — actual data content (hard to fabricate)
    # These patterns match on actual response DATA, not narrative claims
    _CONFIRMED_DATA = [
        re.compile(r"<script[^>]*>.*?alert\s*\(", re.IGNORECASE | re.DOTALL),
        re.compile(r"<img[^>]+onerror\s*=", re.IGNORECASE),
        re.compile(r"<\?php|<\?=", re.IGNORECASE),
        re.compile(r"(?:total|drwx|lrwx)[\s\-]", re.IGNORECASE),  # directory listing
        re.compile(r"(?:BEGIN|-----BEGIN)\s+(?:RSA|CERTIFICATE|PRIVATE)", re.IGNORECASE),
        re.compile(r"(?:DB_|API_|SECRET|AWS_)[A-Z_]+=\S+", re.IGNORECASE),  # env file
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT token
        re.compile(r"flag\{[^}]+\}", re.IGNORECASE),  # CTF flag
    ]
    for pat in _CONFIRMED_DATA:
        if pat.search(evidence):
            if has_http:
                return 4, f"confirmed_data: {pat.pattern[:40]}"
            # Narrative-only score 4 pattern — cap at 3
            return 3, f"confirmed_data_no_http: {pat.pattern[:40]} (capped: no raw HTTP)"

    # Score 4 claim-based patterns — verify claims against ACTUAL response body
    # Split evidence into raw HTTP portion (after enrichment marker) vs narrative
    _RAW_MARKER = "--- RAW TOOL OUTPUT ---"
    raw_portion = ""
    if _RAW_MARKER in evidence:
        raw_portion = evidence[evidence.index(_RAW_MARKER):]
    elif has_http:
        raw_portion = evidence  # All evidence may be HTTP data (from Claude)

    if raw_portion:
        # SSTI: {{7*7}} claim → verify "49" appears in raw response body
        if re.search(r"\{\{7\*7\}\}", evidence) and re.search(r"49", raw_portion):
            return 4, "confirmed_with_http: SSTI {{7*7}}=49 in response"
        # SQLi: UNION SELECT → verify SQL output patterns in raw response
        if re.search(r"UNION\s+SELECT", evidence, re.IGNORECASE) and re.search(
            r"(?:mysql|postgres|sqlite|column|table_name|\|.*\|)", raw_portion, re.IGNORECASE
        ):
            return 4, "confirmed_with_http: SQLi output in response"
        # XSS: verify <script or alert( in raw response body
        if re.search(r"<script|alert\(|onerror\s*=|javascript:", raw_portion, re.IGNORECASE):
            return 4, "confirmed_with_http: XSS payload in response"
        # Open redirect: verify Location header with external URL
        if re.search(r"(?:Location|redirect).*https?://(?!.*(?:self|same))", raw_portion, re.IGNORECASE):
            return 4, "confirmed_with_http: redirect to external URL"
        # Token/credential in response
        if re.search(r"(?:access_token|api_key|authorization)\s*[=:]\s*\S{10,}", raw_portion, re.IGNORECASE):
            return 4, "confirmed_with_http: credential in response"

    # Score 3: Count distinct signal types — only objective signals, NOT narrative claims
    signals = 0
    signal_details = []
    # Status code anomaly (actual code number)
    if re.search(r"(?:status|code)\s*[:=]?\s*(?:[45]\d{2}|302|301)|HTTP/[12][\.\d]*\s+\d{3}", evidence, re.IGNORECASE):
        signals += 1
        signal_details.append("status_anomaly")
    # Body content change (with actual numbers)
    if re.search(r"(?:content.?length|body.?size|response.?(?:length|size|bytes))\s*(?:changed|differ|!=|<>|\d+\s*vs)|Content-Length:\s*\d+", evidence, re.IGNORECASE):
        signals += 1
        signal_details.append("body_change")
    # Error keywords from the application (actual error messages, not claims)
    if re.search(r"(?:syntax error|mysql_|pg_|sqlite3\.|ORA-\d|SQLSTATE|traceback \(most recent|stack trace|internal server error|500 internal)", evidence, re.IGNORECASE):
        signals += 1
        signal_details.append("error_in_response")
    # Timing anomaly (with specific measurements)
    if re.search(r"(?:elapsed|response.?time|round.?trip)\s*[:=]?\s*\d+\.?\d*\s*(?:ms|s\b)|(?:\d+\.?\d+s\s+vs\s+\d+\.?\d+s)", evidence, re.IGNORECASE):
        signals += 1
        signal_details.append("timing_anomaly")
    # Header anomaly (actual header content)
    if re.search(r"(?:Access-Control-Allow-Origin:\s*\*|Location:\s*https?://|Set-Cookie:\s*\S+=)", evidence, re.IGNORECASE):
        signals += 1
        signal_details.append("header_anomaly")

    if signals >= 2:
        return 3, f"strong: {signals} signals ({', '.join(signal_details)})"

    # Score 2: single objective signal OR has raw HTTP data with some length
    if signals == 1:
        return 2, f"moderate: single signal ({', '.join(signal_details)})"
    if has_http and len(evidence) >= 150:
        return 2, "moderate: has raw HTTP data but no clear vulnerability signals"

    # Narrative-only evidence with keywords but no HTTP data
    if re.search(r"(?:confirmed|verified|vulnerable|exploitable|reflected|injected)", evidence, re.IGNORECASE):
        return 1, "weak: narrative claims without raw HTTP data"

    return 1, "weak: no concrete response signals detected"


def _get_matching_tool_result(finding: dict, deps: ToolDeps | None) -> str:
    """Get the most relevant tool result for a finding.

    Tries: exact tool_used match → endpoint URL match → any exploitation tool result.
    GLM-5 often sets tool_used incorrectly, so we fall back to content matching.
    """
    if not deps or not deps.recent_tool_results:
        return ""
    tool_used = finding.get("tool_used", "")
    endpoint = finding.get("endpoint", "")

    # Pass 1: exact tool name match
    if tool_used:
        for tname, tresult in reversed(deps.recent_tool_results):
            if tname == tool_used:
                return tresult

    # Pass 2: find a result that mentions the finding's endpoint
    if endpoint:
        ep_path = endpoint.split("?")[0].rstrip("/").lower()
        if ep_path and len(ep_path) > 3:
            for _tname, tresult in reversed(deps.recent_tool_results):
                if ep_path in tresult.lower():
                    return tresult

    # Pass 3: return the most recent exploitation tool result (better than nothing)
    _exploit_tools = {"test_xss", "test_sqli", "test_ssrf", "test_ssti", "test_cmdi",
                      "test_idor", "test_auth_bypass", "test_race_condition", "test_jwt",
                      "test_file_upload", "test_authz_matrix", "run_custom_exploit",
                      "send_http_request", "response_diff_analyze", "blind_sqli_extract",
                      "scan_auth_bypass"}
    for tname, tresult in reversed(deps.recent_tool_results):
        if tname in _exploit_tools:
            return tresult

    return ""


def _tool_output_confirms_vuln(finding: dict, deps: ToolDeps | None) -> tuple[bool, str]:
    """Check if the deterministic tool output itself confirms a vulnerability.

    Trusted tools (test_ssrf, test_xss, test_sqli, etc.) return structured
    results with explicit vulnerable=true/false.  When the tool says it's
    vulnerable AND provides successful payloads, we trust it over the brain's
    evidence formatting.

    Returns (confirmed, reason).
    """
    tool_result_str = _get_matching_tool_result(finding, deps)
    if not tool_result_str:
        return False, "no matching tool result"

    try:
        data = json.loads(tool_result_str)
        if not isinstance(data, dict):
            return False, "tool result not a dict"
    except (json.JSONDecodeError, TypeError):
        return False, "tool result not JSON"

    tool_used = finding.get("tool_used", "")

    # ── Explicit "vulnerable: true" with successful payloads ──
    if data.get("vulnerable") is True:
        payloads = data.get("successful_payloads", [])
        if payloads and len(payloads) >= 1:
            return True, f"tool_confirmed: vulnerable=true, {len(payloads)} successful payloads"
        # vulnerable=true but no payload list — require injectable flag too for sqli
        if tool_used in ("test_sqli", "blind_sqli_extract") and data.get("injectable"):
            return True, "tool_confirmed: sqli vulnerable+injectable=true"

    # ── test_xss / dalfox: findings with actual payloads ──
    if tool_used == "test_xss":
        xss_findings = data.get("findings", [])
        if isinstance(xss_findings, list):
            real = [f for f in xss_findings if isinstance(f, dict)
                    and (f.get("payload") or f.get("poc") or f.get("data"))]
            if real:
                return True, f"tool_confirmed: test_xss found {len(real)} XSS with payloads"

    # ── test_sqli / sqlmap: injectable or extracted data ──
    if tool_used in ("test_sqli", "blind_sqli_extract"):
        if data.get("injectable"):
            return True, "tool_confirmed: sqlmap injectable=true"
        if data.get("extracted_data") or data.get("extracted"):
            return True, "tool_confirmed: SQL data extracted"

    # ── scan_info_disclosure: deterministic scanner findings ──
    if tool_used == "scan_info_disclosure" and data.get("findings"):
        disc_findings = data["findings"]
        if isinstance(disc_findings, list) and len(disc_findings) > 0:
            return True, f"tool_confirmed: info_disclosure found {len(disc_findings)} issues"

    # ── test_ssrf without successful_payloads: check response content ──
    if tool_used == "test_ssrf" and data.get("vulnerable") is True:
        # SSRF tools sometimes report vulnerable based on status code diff
        # Only auto-confirm if response contains internal data indicators
        resp_body = str(data.get("response_body", data.get("body", "")))
        internal_indicators = ("root:x:", "169.254.169.254", "ec2",
                               "computeMetadata", "latest/meta-data")
        if any(ind in resp_body for ind in internal_indicators):
            return True, "tool_confirmed: SSRF with internal data in response"
        # Don't auto-confirm SSRF that just got a normal page back
        return False, "ssrf_vulnerable_but_no_internal_data"

    return False, ""


async def _claude_validate_finding(
    finding: dict,
    tool_result_str: str,
    deps: ToolDeps | None,
) -> tuple[bool, str]:
    """Call Claude Haiku to evaluate whether a finding is real.

    Cost: ~$0.001 per call (Haiku — 500 input, 150 output tokens).
    Used as final arbiter when deterministic scoring is inconclusive.

    Returns (is_real, reasoning).
    """
    claude = getattr(deps, "claude_client", None) if deps else None
    if not claude:
        return False, "no_claude_client"

    vuln_type = finding.get("vuln_type", "unknown")
    endpoint = finding.get("endpoint", "unknown")
    parameter = finding.get("parameter", "")
    severity = finding.get("severity", "unknown")
    evidence = str(finding.get("evidence", ""))[:2000]
    tool_output = tool_result_str[:3000] if tool_result_str else "NO TOOL OUTPUT"

    prompt = (
        f"FINDING CLAIM:\n"
        f"  Type: {vuln_type} | Endpoint: {endpoint} | Param: {parameter} | Severity: {severity}\n"
        f"  Agent evidence: {evidence}\n\n"
        f"ACTUAL TOOL OUTPUT:\n{tool_output}\n\n"
        "Is this a REAL exploitable vulnerability? You must be SKEPTICAL. Default to FALSE_POSITIVE.\n\n"
        "COMMON FALSE POSITIVES — reject these:\n"
        "- SSRF: tool got normal page content, not internal/cloud metadata (169.254.169.254)\n"
        "- SSTI: '49' appears in page but is normal content, not {{7*7}} eval result\n"
        "- SQLi: response size differs but no SQL data/errors extracted\n"
        "- XSS: payload in response but inside HTML attribute/comment/JSON (not executable)\n"
        "- Open Redirect: standard login/OAuth redirect to SAME domain, or ReturnUrl to internal page\n"
        "- Auth Bypass: public pages are not auth bypass, login pages are public by design\n"
        "- Info Disclosure: generic error pages, version numbers, public API keys (Algolia, Google Maps)\n"
        "- Broken Auth: login forms existing is not broken auth, CAPTCHA not being rate-limited\n"
        "- Account Takeover: password reset existing is not ATO, requires actual exploit proof\n"
        "- Missing Rate Limit: not exploitable without actual abuse demonstration\n"
        "- Session Fixation: pre-auth session tokens alone are not exploitable\n"
        "- Host Header: response doesn't use injected host value\n"
        "- CORS: Access-Control-Allow-Origin:* on public API without credentials\n"
        "- Subdomain Takeover: CNAME exists but no dangling/unclaimed service proof\n\n"
        "ONLY confirm if tool output shows CLEAR exploitation impact "
        "(data extracted, payload executed, unauthorized access gained).\n\n"
        "Answer EXACTLY: REAL|<one-line-reason> or FALSE_POSITIVE|<one-line-reason>"
    )

    try:
        # Call Anthropic API directly — bypass BudgetManager which may be $0 in Z.ai mode.
        # Cost: ~$0.001 per call (Haiku, ~500 input + 150 output tokens).
        raw_client = getattr(claude, "_client", None)
        if not raw_client:
            return False, "no_raw_anthropic_client"

        resp = await raw_client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=150,
            system=(
                "You validate vulnerability findings for a bug bounty program. "
                "You MUST be extremely skeptical — a false positive wastes the researcher's reputation. "
                "Default to FALSE_POSITIVE unless the TOOL OUTPUT contains undeniable proof of exploitation. "
                "Narrative claims from the agent are NOT evidence — only raw HTTP data matters. "
                "Respond in exactly the format requested."
            ),
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.content[0].text.strip() if resp.content else ""
        if not text:
            return False, "claude_empty_response"

        if text.startswith("REAL|") or text.startswith("REAL "):
            reason = text.split("|", 1)[-1].strip() if "|" in text else text[5:].strip()
            return True, f"claude_confirmed: {reason[:120]}"
        elif text.startswith("FALSE_POSITIVE|") or text.startswith("FALSE_POSITIVE "):
            reason = text.split("|", 1)[-1].strip() if "|" in text else text[15:].strip()
            return False, f"claude_rejected: {reason[:120]}"
        else:
            # Try to infer from free-form response
            lower = text.lower()
            if "real" in lower[:20] and "false" not in lower[:20]:
                return True, f"claude_confirmed: {text[:120]}"
            return False, f"claude_unclear: {text[:120]}"
    except Exception as e:
        err_str = str(e)
        logger.warning("claude_validate_error", error=err_str[:100])
        # Transient errors (429, 529, timeout, connection) → don't reject, let score decide
        if any(code in err_str for code in ("429", "529", "timeout", "timed out", "ConnectionError")):
            return False, f"claude_unavailable_retry_later: {err_str[:60]}"
        return False, f"claude_error: {err_str[:80]}"


_VULN_TYPE_CWE: dict[str, str] = {
    "xss": "CWE-79", "reflected_xss": "CWE-79", "stored_xss": "CWE-79",
    "cross_site_scripting": "CWE-79",
    "sqli": "CWE-89", "sql_injection": "CWE-89", "blind_sqli": "CWE-89",
    "nosqli": "CWE-943", "nosql_injection": "CWE-943",
    "cmdi": "CWE-78", "command_injection": "CWE-78", "os_command_injection": "CWE-78",
    "ssti": "CWE-1336", "server_side_template_injection": "CWE-1336",
    "ssrf": "CWE-918", "server_side_request_forgery": "CWE-918",
    "lfi": "CWE-22", "path_traversal": "CWE-22", "directory_traversal": "CWE-22",
    "idor": "CWE-639", "insecure_direct_object_reference": "CWE-639",
    "csrf": "CWE-352", "cross_site_request_forgery": "CWE-352",
    "xxe": "CWE-611", "xml_external_entity": "CWE-611",
    "open_redirect": "CWE-601", "redirect": "CWE-601",
    "cors": "CWE-942", "cors_misconfiguration": "CWE-942",
    "auth_bypass": "CWE-287", "authentication_bypass": "CWE-287",
    "broken_access_control": "CWE-284", "access_control_bypass": "CWE-284",
    "info_disclosure": "CWE-200", "information_disclosure": "CWE-200",
    "sensitive_data_exposure": "CWE-200",
    "file_upload": "CWE-434",
    "jwt": "CWE-347", "jwt_misconfiguration": "CWE-347",
    "race_condition": "CWE-362",
    "host_header_injection": "CWE-644",
    "crlf_injection": "CWE-93", "header_injection": "CWE-113",
    "prototype_pollution": "CWE-1321",
    "deserialization": "CWE-502",
    "rce": "CWE-94",
}

_VULN_TYPE_DESCRIPTION: dict[str, str] = {
    "xss": "Cross-Site Scripting (XSS) allows injection of malicious scripts into web pages viewed by other users. An attacker can use this to steal session cookies, redirect users to malicious sites, or modify page content.",
    "reflected_xss": "Reflected XSS occurs when user input is immediately reflected in the page response without proper sanitization. An attacker can craft a malicious URL that executes JavaScript in the victim's browser when clicked.",
    "stored_xss": "Stored XSS occurs when malicious input is permanently stored on the server and served to other users. This is more dangerous than reflected XSS as it doesn't require the victim to click a crafted link.",
    "sqli": "SQL Injection allows an attacker to inject malicious SQL queries through user input. This can lead to unauthorized data access, data modification, or complete database compromise.",
    "blind_sqli": "Blind SQL Injection occurs when the application is vulnerable to SQL injection but doesn't display query results directly. The attacker infers data through timing delays or boolean responses.",
    "nosqli": "NoSQL Injection targets NoSQL databases (MongoDB, etc.) by injecting operators or queries through user input, potentially bypassing authentication or extracting data.",
    "cmdi": "Command Injection allows execution of arbitrary operating system commands on the host server through vulnerable application parameters.",
    "ssti": "Server-Side Template Injection occurs when user input is embedded directly into server-side templates, allowing execution of arbitrary code on the server.",
    "ssrf": "Server-Side Request Forgery allows an attacker to make the server send requests to internal services, cloud metadata endpoints, or other resources not normally accessible from outside.",
    "lfi": "Local File Inclusion allows reading arbitrary files from the server by manipulating file path parameters, potentially exposing source code, configuration files, or credentials.",
    "path_traversal": "Path Traversal allows accessing files outside the intended directory by using '../' sequences in file path parameters.",
    "idor": "Insecure Direct Object Reference allows accessing resources belonging to other users by manipulating identifiers (IDs, filenames) in API requests.",
    "csrf": "Cross-Site Request Forgery forces authenticated users to perform unintended actions by embedding requests in malicious web pages.",
    "xxe": "XML External Entity injection exploits XML parsers to read local files, perform SSRF, or cause denial of service.",
    "open_redirect": "Open Redirect allows attackers to redirect users to malicious external sites via trusted URL parameters, enabling phishing attacks.",
    "cors": "CORS Misconfiguration allows malicious websites to make authenticated cross-origin requests, potentially stealing sensitive data from the vulnerable application.",
    "auth_bypass": "Authentication Bypass allows accessing protected resources without proper credentials, potentially gaining unauthorized access to admin panels or user data.",
    "broken_access_control": "Broken Access Control allows users to access resources or perform actions beyond their intended permissions.",
    "info_disclosure": "Information Disclosure exposes sensitive technical details, configuration files, or internal data that can aid further attacks.",
    "file_upload": "Unrestricted File Upload allows uploading malicious files (web shells, scripts) that can lead to remote code execution.",
    "jwt": "JWT Misconfiguration allows forging or manipulating JSON Web Tokens to bypass authentication or elevate privileges.",
    "race_condition": "Race Condition allows exploiting timing windows in concurrent operations, potentially duplicating transactions or bypassing limits.",
    "host_header_injection": "Host Header Injection allows manipulating the Host header to poison caches, reset password links, or redirect users.",
    "crlf_injection": "CRLF Injection allows injecting HTTP headers by inserting carriage return/line feed characters into header values.",
    "rce": "Remote Code Execution allows running arbitrary code on the server, giving the attacker full control of the system.",
}


def _auto_enrich_finding(info: dict[str, Any]) -> None:
    """Auto-populate missing fields to produce quality reports.

    Called after validation passes, before DB push. Generates:
    - title: from vuln_type + endpoint
    - description: from vuln_type template + evidence context
    - poc_code: extracted from evidence payload data
    - method: from evidence or defaults
    - cwe_id: from vuln_type mapping
    - cvss_score: from CVSS calculator
    - steps_to_reproduce: auto-generated from evidence
    """
    vuln_type = (info.get("vuln_type") or "").lower().strip()
    endpoint = info.get("endpoint", "")
    parameter = info.get("parameter", "")
    evidence = str(info.get("evidence", ""))
    tool_used = info.get("tool_used", "")

    # ── Title ──
    if not info.get("title") or info["title"] == info.get("finding_key", "").replace("_", " ").title():
        vt_display = vuln_type.replace("_", " ").upper()
        if parameter:
            info["title"] = f"{vt_display} in '{parameter}' parameter on {_shorten_endpoint(endpoint)}"
        elif endpoint:
            info["title"] = f"{vt_display} on {_shorten_endpoint(endpoint)}"
        else:
            info["title"] = f"{vt_display} vulnerability"

    # ── Description ──
    if not info.get("description"):
        base_desc = _VULN_TYPE_DESCRIPTION.get(vuln_type, "")
        if base_desc:
            context_parts = []
            if endpoint:
                context_parts.append(f"The vulnerability was found at {endpoint}")
            if parameter:
                context_parts.append(f"in the '{parameter}' parameter")
            if tool_used:
                context_parts.append(f"using {tool_used}")
            context = " ".join(context_parts)
            if context:
                info["description"] = f"{base_desc}\n\n{context}."
            else:
                info["description"] = base_desc
        else:
            # Generate a generic description from evidence
            if len(evidence) > 20:
                info["description"] = (
                    f"A {vuln_type.replace('_', ' ')} vulnerability was detected"
                    + (f" at {endpoint}" if endpoint else "")
                    + (f" in the '{parameter}' parameter" if parameter else "")
                    + "."
                )

    # ── Method ──
    if not info.get("method"):
        # Try to extract from evidence or request_dump
        req_dump = info.get("request_dump", "")
        if req_dump:
            first_word = req_dump.split()[0] if req_dump.split() else ""
            if first_word in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                info["method"] = first_word
        if not info.get("method"):
            # Infer from evidence text
            ev_upper = evidence.upper()
            for m in ("POST", "PUT", "DELETE", "PATCH"):
                if m in ev_upper:
                    info["method"] = m
                    break
            if not info.get("method"):
                info["method"] = "GET"

    # ── CWE ──
    if not info.get("cwe_id"):
        cwe = _VULN_TYPE_CWE.get(vuln_type, "")
        if cwe:
            info["cwe_id"] = cwe

    # ── CVSS ──
    if not info.get("cvss_score"):
        try:
            from ai_brain.active.cvss_calculator import compute_cvss_vector
            score, vector = compute_cvss_vector(vuln_type, info)
            if score > 0:
                info["cvss_score"] = score
                info["cvss_vector"] = vector
        except Exception:
            # Fallback: severity-based estimate
            _SEV_CVSS = {"critical": 9.8, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}
            sev = (info.get("severity") or "medium").lower()
            info["cvss_score"] = _SEV_CVSS.get(sev, 5.0)

    # ── PoC code ──
    if not info.get("poc_code"):
        poc = _extract_poc_from_evidence(evidence, vuln_type, info)
        if poc:
            info["poc_code"] = poc

    # ── Steps to reproduce ──
    if not info.get("steps_to_reproduce"):
        steps = _generate_steps(info)
        if steps:
            info["steps_to_reproduce"] = steps


def _shorten_endpoint(endpoint: str) -> str:
    """Shorten an endpoint URL for display in titles."""
    if not endpoint:
        return "target"
    from urllib.parse import urlparse
    try:
        parsed = urlparse(endpoint)
        path = parsed.path or "/"
        if len(path) > 40:
            path = path[:37] + "..."
        host = parsed.hostname or ""
        if host:
            return f"{host}{path}"
        return path
    except Exception:
        return endpoint[:50]


def _extract_poc_from_evidence(evidence: str, vuln_type: str, info: dict) -> str:
    """Extract or construct PoC code from evidence and finding data."""
    import re as _re

    endpoint = info.get("endpoint", "")
    parameter = info.get("parameter", "")
    method = info.get("method", "GET")
    req_dump = info.get("request_dump", "")

    # If we have a request dump, build a curl command from it
    if req_dump and endpoint:
        return _build_curl_poc(req_dump, endpoint, method)

    # Try to extract payload from evidence
    vt = vuln_type.lower()

    # XSS payloads
    if "xss" in vt:
        for pat in [r'(<script[^>]*>.*?</script>)', r'(<img[^>]+onerror=[^>]+>)',
                     r"(on\w+=[\"\'][^\"\']+[\"\'])", r"(javascript:[^\s\"']+)"]:
            m = _re.search(pat, evidence, _re.IGNORECASE)
            if m:
                payload = m.group(1)
                if endpoint and parameter:
                    return f"curl -s '{endpoint}?{parameter}={payload}'"
                return payload

    # SQL injection
    if "sqli" in vt or "sql" in vt:
        for pat in [r"((?:' (?:OR|AND|UNION)\s).{5,50})", r"(\bUNION\s+SELECT\b.{5,80})",
                     r"((?:' OR '1'='1).*?)[\"\n]"]:
            m = _re.search(pat, evidence, _re.IGNORECASE)
            if m:
                payload = m.group(1).strip()
                if endpoint and parameter:
                    return f"curl -s '{endpoint}?{parameter}={payload}'"
                return payload

    # SSTI
    if "ssti" in vt or "template" in vt:
        for pat in [r'(\{\{7\*7\}\})', r'(\{\{[^}]+\}\})', r'(\$\{[^}]+\})', r'(<%= .+? %>)']:
            m = _re.search(pat, evidence)
            if m:
                payload = m.group(1)
                if endpoint and parameter:
                    return f"curl -s '{endpoint}?{parameter}={payload}'"
                return payload

    # Command injection
    if "cmdi" in vt or "command" in vt:
        for pat in [r'(;\s*(?:id|whoami|cat|ls)\b[^"\']*)', r'(\|\s*(?:id|whoami)\b[^"\']*)',
                     r'(`[^`]+`)']:
            m = _re.search(pat, evidence, _re.IGNORECASE)
            if m:
                payload = m.group(1).strip()
                if endpoint and parameter:
                    return f"curl -s '{endpoint}?{parameter}={payload}'"
                return payload

    # SSRF
    if "ssrf" in vt:
        for pat in [r'(https?://127\.0\.0\.1\S*)', r'(https?://169\.254\.169\.254\S*)',
                     r'(https?://localhost\S*)']:
            m = _re.search(pat, evidence)
            if m:
                payload = m.group(1)
                if endpoint and parameter:
                    return f"curl -s '{endpoint}?{parameter}={payload}'"
                return payload

    # CORS
    if "cors" in vt:
        if endpoint:
            return f"curl -s -H 'Origin: https://evil.com' -I '{endpoint}'"

    # Open redirect
    if "redirect" in vt:
        if endpoint and parameter:
            return f"curl -s -D - '{endpoint}?{parameter}=https://evil.com'"
        elif endpoint:
            return f"curl -s -D - '{endpoint}?url=https://evil.com'"

    # Info disclosure
    if "info" in vt or "disclosure" in vt:
        if endpoint:
            return f"curl -s '{endpoint}'"

    # Generic: if we have endpoint + parameter, build a simple test
    if endpoint and parameter:
        return f"curl -s '{endpoint}?{parameter}=test'"

    return ""


def _build_curl_poc(req_dump: str, endpoint: str, method: str) -> str:
    """Build a curl command from a request dump."""
    parts = [f"curl -s -X {method}"]

    lines = req_dump.strip().split("\n")
    for line in lines[1:]:  # Skip request line
        if ":" in line and not line.strip() == "":
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key.lower() not in ("host", "connection", "content-length"):
                parts.append(f"-H '{key}: {val}'")
        elif line.strip() == "":
            break

    # Check for body
    body_start = req_dump.find("\n\n")
    if body_start > 0:
        body = req_dump[body_start + 2:].strip()
        if body:
            parts.append(f"-d '{body[:500]}'")

    parts.append(f"'{endpoint}'")
    return " \\\n  ".join(parts)


def _generate_steps(info: dict) -> list[str]:
    """Generate steps to reproduce from finding data."""
    endpoint = info.get("endpoint", "")
    parameter = info.get("parameter", "")
    method = info.get("method", "GET")
    vuln_type = (info.get("vuln_type") or "").replace("_", " ")
    poc = info.get("poc_code", "")
    tool_used = info.get("tool_used", "")

    if not endpoint:
        return []

    steps = []
    steps.append(f"Navigate to or send a {method} request to: {endpoint}")

    if parameter and poc:
        steps.append(f"Inject the following payload into the '{parameter}' parameter: {poc[:200]}")
    elif parameter:
        steps.append(f"Inject a {vuln_type} test payload into the '{parameter}' parameter")
    elif poc:
        steps.append(f"Use the following payload: {poc[:200]}")

    steps.append(f"Observe the response for {vuln_type} indicators")

    if info.get("response_dump"):
        resp_preview = info["response_dump"][:100].replace("\n", " ")
        steps.append(f"The vulnerable response shows: {resp_preview}")

    if tool_used:
        steps.append(f"Originally detected using: {tool_used}")

    return steps


async def _validate_findings(
    findings: dict[str, Any],
    source: str = "brain",
    deps: ToolDeps | None = None,
) -> dict[str, Any]:
    """Validate findings at write-time with strict anti-fabrication gates.

    source="brain": findings submitted via update_knowledge (strict checks)
    source="tool_auto": findings auto-generated by tool code paths (relaxed)

    Hybrid validation (when deps provided):
    1. Deterministic score check (fast, free)
    2. Tool output auto-confirm (if tool says vulnerable=true with payloads)
    3. Claude Haiku validation (final arbiter, ~$0.001/call)

    Returns validated findings dict (only valid entries included).
    """
    # Cap findings per call from brain
    if source == "brain" and len(findings) > 5:
        logger.warning("finding_cap_exceeded", count=len(findings))
        return {}  # Reject ALL — too many at once

    validated: dict[str, Any] = {}

    for fid, info in findings.items():
        if not isinstance(info, dict):
            logger.warning("finding_invalid_type", finding_id=fid, type=type(info).__name__)
            continue

        # Check required fields
        missing = [f for f in _REQUIRED_FINDING_FIELDS if not info.get(f)]
        if missing:
            logger.warning("finding_missing_fields", finding_id=fid, missing=missing)
            continue

        # Validate severity
        severity = info.get("severity", "").lower()
        if severity not in _VALID_SEVERITIES:
            logger.warning("finding_invalid_severity", finding_id=fid, severity=severity)
            continue

        # Normalize severity
        info["severity"] = severity

        # ── Anti-fabrication gate 0: in-state dedup ──
        # Reject if same canonical vuln_type + normalized endpoint already in state or this batch
        vuln_type = info.get("vuln_type", "")
        canonical = _canonicalize_vuln_type(vuln_type)
        if canonical != "REJECT":
            endpoint_raw = info.get("endpoint", "")
            try:
                from urllib.parse import urlparse as _up
                _ep_path = _up(endpoint_raw).path.rstrip("/").lower() or "/"
            except Exception:
                _ep_path = endpoint_raw.lower().strip()
            _dedup_key = f"{canonical}|{_ep_path}"

            # Check existing findings in state
            _existing_findings = {}
            if deps and deps.current_state:
                _existing_findings = deps.current_state.get("findings", {})
            # Also check already-validated findings in this batch
            _all_existing = {**_existing_findings, **validated}
            _is_dup = False
            for _efid, _ef in _all_existing.items():
                _evt = _canonicalize_vuln_type(_ef.get("vuln_type", ""))
                _eep = _ef.get("endpoint", "")
                try:
                    _eep_path = _up(_eep).path.rstrip("/").lower() or "/"
                except Exception:
                    _eep_path = _eep.lower().strip()
                if f"{_evt}|{_eep_path}" == _dedup_key:
                    _is_dup = True
                    break
            if _is_dup:
                logger.warning("finding_rejected_in_state_dup", finding_id=fid,
                               vuln_type=vuln_type, endpoint=endpoint_raw[:100])
                continue

        # ── Anti-fabrication gate 0b: semantic dedup ──
        if deps and deps.deduplicator:
            try:
                _domain = ""
                if deps.current_state:
                    _domain = deps.current_state.get("domain", "") or ""
                if deps.deduplicator.is_duplicate(info, _domain):
                    logger.warning("finding_rejected_semantic_dup", finding_id=fid,
                                   vuln_type=vuln_type, endpoint=endpoint_raw[:100])
                    continue
            except Exception:
                pass  # Dedup is best-effort

        # ── Anti-fabrication gate 1: reject summary/meta vuln types ──
        if canonical == "REJECT":
            logger.warning("finding_rejected_summary_type", finding_id=fid, vuln_type=vuln_type)
            continue
        vt_words = set(vuln_type.lower().replace("-", "_").split("_"))
        if vt_words & _REJECT_VULN_TYPE_WORDS:
            logger.warning("finding_rejected_summary_type", finding_id=fid, vuln_type=vuln_type)
            continue

        if source == "brain":
            # ── Anti-fabrication gate 2: tool_used must be a real tool ──
            tool_used = info.get("tool_used", "")
            if not tool_used or tool_used == "?" or tool_used not in _REAL_TOOL_NAMES:
                logger.warning(
                    "finding_rejected_bad_tool",
                    finding_id=fid,
                    tool_used=tool_used,
                )
                continue

            # ── Anti-fabrication gate 3: evidence quality check ──
            evidence = str(info.get("evidence", ""))
            if len(evidence) < _MIN_EVIDENCE_LENGTH:
                logger.warning(
                    "finding_rejected_short_evidence",
                    finding_id=fid,
                    evidence_len=len(evidence),
                )
                continue

            if not _EVIDENCE_INDICATORS.search(evidence):
                logger.warning(
                    "finding_rejected_no_indicators",
                    finding_id=fid,
                    evidence_preview=evidence[:100],
                )
                continue

            # ── Anti-fabrication gate 3b: evidence quality score ──
            score, score_reason = _score_evidence(info)

            # ── Baseline fingerprint check ──
            # If the finding's endpoint has a stored baseline and the response
            # matches normal behavior, cap the score at 2 (needs more evidence).
            if score >= 3 and deps and deps.current_state:
                _baselines = deps.current_state.get("baselines", {})
                if _baselines:
                    _finding_endpoint = info.get("endpoint", "")
                    _finding_method = info.get("method", "GET").upper()
                    _baseline_fp = _baselines.get(f"{_finding_method} {_finding_endpoint}")
                    if _baseline_fp:
                        _resp_dump = str(info.get("response_dump", ""))
                        if _resp_dump and len(_resp_dump) > 20:
                            _st_match = re.search(r"HTTP/?\S*\s+(\d{3})", _resp_dump)
                            if _st_match:
                                _cand_status = int(_st_match.group(1))
                                # Check status + body length against baseline
                                _bl = _baseline_fp.get("body_length", 0)
                                _status_match = (_cand_status == _baseline_fp.get("status"))
                                _len_match = _bl > 0 and abs(len(_resp_dump) - _bl) / _bl <= 0.30
                                if _status_match and _len_match:
                                    score = min(score, 2)
                                    score_reason = (
                                        f"baseline_match: response matches normal baseline "
                                        f"(status={_cand_status}), capped at 2. "
                                        f"Original: {score_reason}"
                                    )

            info["evidence_score"] = score
            info["evidence_score_reason"] = score_reason
            min_score = 4 if severity in ("critical", "high") else 3

            # ── Hybrid validation: ALL findings go through 3-tier check ──
            # Tier 1: score >= 5 (definitive — OOB, root:x:0:0) → auto-pass
            # Tier 1b: score >= 4 with raw HTTP data → auto-pass (confirmed patterns)
            if score >= 5:
                info["validation_method"] = "score_definitive"
            elif score >= 4 and _has_raw_http_artifacts(evidence):
                info["validation_method"] = "score_confirmed_with_http"
                logger.info("finding_score4_auto_pass", finding_id=fid, score=score,
                            reason=score_reason)
            else:
                # Tier 2: check if deterministic tool output confirms
                tool_ok, tool_reason = _tool_output_confirms_vuln(info, deps)
                if tool_ok:
                    logger.info(
                        "finding_tool_auto_confirmed",
                        finding_id=fid, score=score, reason=tool_reason,
                    )
                    info["evidence_score"] = max(score, min_score)
                    info["evidence_score_reason"] = tool_reason
                    info["validation_method"] = "tool_auto_confirm"
                else:
                    # Tier 3: Claude Haiku as final arbiter for ALL findings
                    tool_result_str = _get_matching_tool_result(info, deps)
                    claude_ok, claude_reason = await _claude_validate_finding(
                        info, tool_result_str, deps,
                    )
                    if claude_ok:
                        # If Haiku was unavailable (429 etc), require minimum score
                        is_fallback = "claude_unavailable" in claude_reason
                        if is_fallback and score < min_score:
                            logger.warning(
                                "finding_rejected_fallback_low_score",
                                finding_id=fid, score=score, min_required=min_score,
                            )
                            continue
                        logger.info(
                            "finding_claude_confirmed",
                            finding_id=fid, score=score, reason=claude_reason,
                        )
                        info["evidence_score"] = max(score, min_score)
                        info["evidence_score_reason"] = claude_reason
                        info["validation_method"] = "claude_haiku" if not is_fallback else "score_fallback"
                    else:
                        logger.warning(
                            "finding_rejected_hybrid",
                            finding_id=fid, score=score, min_required=min_score,
                            score_reason=score_reason,
                            tool_reason=tool_reason,
                            claude_reason=claude_reason,
                        )
                        continue

            # ── Set confirmed=True ONLY after passing validation gates ──
            info["confirmed"] = True

        # Ensure confirmed field has a boolean
        if "confirmed" not in info:
            info["confirmed"] = False

        # ── Dynamic confidence scoring (replaces hardcoded 50) ──
        ev_score = info.get("evidence_score", 0)
        confidence = min(100, ev_score * 20)  # 0-5 → 0-100
        if info.get("request_dump") or info.get("response_dump"):
            confidence = min(100, confidence + 20)
        if info.get("validation_method", "").startswith("tool_"):
            confidence = min(100, confidence + 15)
        info["confidence"] = confidence

        # ── Auto-enrich missing fields for quality reports ──
        _auto_enrich_finding(info)

        validated[fid] = info

        # ── Register with semantic deduplicator ──
        if deps and deps.deduplicator:
            try:
                _domain = ""
                if deps.current_state:
                    _domain = deps.current_state.get("domain", "") or ""
                deps.deduplicator.register_finding(info, _domain, fid)
            except Exception:
                pass

    return validated


async def _try_solve_captcha(deps: ToolDeps, ctx_name: str) -> bool:
    """Try to detect and solve a CAPTCHA on the current page.

    Supports reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile (via 2captcha API),
    and simple image CAPTCHAs (via Claude Vision).
    """
    try:
        page = deps.browser._get_page(ctx_name)

        # Use universal solver if available
        if deps.captcha_solver:
            token = await deps.captcha_solver.solve(page)
            if token:
                return True

        # Fallback: legacy image CAPTCHA solving via Claude Vision
        captcha_selectors = [
            "img[src*='captcha']", "img.captcha", "#captcha-image",
            "img[alt*='captcha' i]", ".captcha img",
        ]
        for selector in captcha_selectors:
            exists = await deps.browser.check_element_exists(ctx_name, selector)
            if exists:
                try:
                    b64_img = await deps.browser.screenshot_element(ctx_name, selector)
                    if b64_img and deps.client:
                        result = await deps.client.call_vision(
                            image_base64=b64_img,
                            prompt=(
                                "This is a CAPTCHA image. Read the text/numbers shown in the image. "
                                "Return ONLY the characters you see, no explanation. "
                                "Remove any spaces between characters."
                            ),
                            media_type="image/jpeg",
                        )
                        captcha_text = result.strip().replace(" ", "")
                        if captcha_text:
                            captcha_inputs = [
                                "input[name*='captcha' i]",
                                "input#captcha",
                                "input[placeholder*='captcha' i]",
                            ]
                            for cap_sel in captcha_inputs:
                                try:
                                    await deps.browser.fill(ctx_name, cap_sel, captcha_text)
                                    return True
                                except Exception:
                                    continue
                except Exception as e:
                    logger.debug("captcha_solve_failed", selector=selector, error=str(e))
    except Exception:
        pass
    return False
