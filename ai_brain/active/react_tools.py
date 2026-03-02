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

logger = structlog.get_logger()

# Maximum tool output size to include inline (15KB).
# Larger outputs are written to temp files.
_MAX_INLINE_SIZE = 15_000


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
    captcha_solver: CaptchaSolver | None = None  # Universal CAPTCHA solver
    waf_engine: Any | None = None  # WafBypassEngine
    chain_engine: Any | None = None  # ChainDiscoveryEngine
    reasoning_engine: Any | None = None  # AdversarialReasoningEngine
    behavior_profiler: Any | None = None  # BehaviorProfiler
    goja_socks5_url: str | None = None  # Goja SOCKS5 proxy for Chrome TLS fingerprinting
    current_state: dict[str, Any] | None = None  # For tools that need state read access
    max_turns: int = 150  # 0 = indefinite mode
    default_headers: dict[str, str] = field(default_factory=dict)  # Custom headers for bug bounty programs
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


def _httpx_kwargs(deps: ToolDeps, **extra: Any) -> dict[str, Any]:
    """Build httpx.AsyncClient kwargs with Goja SOCKS5 proxy if available."""
    kwargs: dict[str, Any] = {"verify": False, "timeout": extra.pop("timeout", 15)}
    if deps.goja_socks5_url:
        kwargs["proxy"] = deps.goja_socks5_url
    # Merge default headers (bug bounty program headers)
    if deps.default_headers:
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


def _safe_json(obj: Any) -> str:
    """Convert obj to JSON string, handling non-serializable types.

    Uses ensure_ascii=True to escape control characters that would break
    json.loads() on the receiving end (e.g., binary data in proxy traffic).
    """
    try:
        return json.dumps(obj, default=str, ensure_ascii=True)
    except Exception:
        return json.dumps({"result": str(obj)}, ensure_ascii=True)


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

    # ── Attack Tools ─────────────────────────────────────────────

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

        # Test HTTP verb tampering
        for method in methods:
            try:
                import httpx
                async with httpx.AsyncClient(**_httpx_kwargs(deps, cf_inject_url=url)) as client:
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

        import httpx
        async with httpx.AsyncClient(**_httpx_kwargs(deps, cf_inject_url=url)) as client:
            for bh in bypass_headers:
                for test_method in test_methods:
                    try:
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

        import httpx
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
                async with httpx.AsyncClient(**_httpx_kwargs(deps, cf_inject_url=test_url)) as client:
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
        payloads = generate_upload_payloads(tech_stack=tech, max_payloads=max_payloads)

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
        import httpx
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

        # Route through Goja SOCKS5 proxy for Chrome TLS fingerprinting
        proxy_url = deps.goja_socks5_url
        client_kwargs: dict[str, Any] = {
            "verify": False,
            "timeout": 30,
            "follow_redirects": follow,
            "cookies": merged_cookies,
        }
        if proxy_url:
            client_kwargs["proxy"] = proxy_url

        async def _do_request(req_headers: dict, req_cookies: dict | None = None) -> dict:
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
            else:
                raise

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
        return await deps.tool_runner.run_jwt_tool(
            token=inp["token"],
            attacks=inp.get("attacks"),
        )

    if tool_name == "run_custom_exploit":
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

    if tool_name == "register_account":
        return await _register_account(deps, inp)

    if tool_name == "login_account":
        return await _login_account(deps, inp)

    if tool_name == "update_knowledge":
        # Special: returns state update directive
        # Validate findings at write-time (structured validation)
        validated_findings = {}
        if "findings" in inp:
            validated_findings = _validate_findings(inp["findings"])

        update: dict[str, Any] = {"_state_update": {}}
        if "endpoints" in inp:
            update["_state_update"]["endpoints"] = inp["endpoints"]
        if validated_findings:
            update["_state_update"]["findings"] = validated_findings
        elif "findings" in inp:
            # Validation returned nothing — return error
            return {
                "error": "Finding validation failed. Required fields: "
                "vuln_type, endpoint, severity (critical/high/medium/low/info). "
                "Provide at least these fields for each finding.",
                "_state_update": {},
            }
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
                    "severity": "critical", "confirmed": True, "tool_used": "blind_sqli_extract",
                }}}
                return {**result, "_state_update": state_update}
            return result
        finally:
            await extractor.close()

    if tool_name == "response_diff_analyze":
        from ai_brain.active.deterministic_tools import ResponseDiffAnalyzer
        analyzer = ResponseDiffAnalyzer(deps.scope_guard, socks_proxy=deps.goja_socks5_url)
        return await analyzer.analyze(**inp)

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

    return {"error": f"Unknown tool: {tool_name}"}


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

    # Auto-fill common field patterns
    field_map = {
        "username": username,
        "name": username,
        "user": username,
        "login": username,
        "email": email or f"{username}@example.com",
        "mail": email or f"{username}@example.com",
        "password": password,
        "pass": password,
        "password_confirmation": password,
        "confirm_password": password,
        "confirm": password,
    }

    filled_fields = []
    for form in forms:
        for field_info in form.get("fields", []):
            field_name = field_info.get("name", "")
            field_type = field_info.get("type", "text")

            # Skip unfillable types
            if field_type in {"hidden", "submit", "button", "image", "reset"}:
                continue

            # Match field name to our values
            for pattern, value in field_map.items():
                if pattern in field_name.lower():
                    try:
                        selector = f"[name='{field_name}']"
                        await deps.browser.fill(ctx_name, selector, value)
                        filled_fields.append(field_name)
                    except Exception:
                        pass
                    break

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

    # Fill login form
    forms = page_info.get("forms", [])
    login_fields = {
        "username": username, "user": username, "login": username,
        "email": username, "mail": username, "name": username,
        "password": password, "pass": password,
    }

    for form in forms:
        for field_info in form.get("fields", []):
            field_name = field_info.get("name", "")
            field_type = field_info.get("type", "text")
            if field_type in {"hidden", "submit", "button", "image", "reset"}:
                continue
            for pattern, value in login_fields.items():
                if pattern in field_name.lower():
                    try:
                        await deps.browser.fill(ctx_name, f"[name='{field_name}']", value)
                    except Exception:
                        pass
                    break

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


def _validate_findings(findings: dict[str, Any]) -> dict[str, Any]:
    """Validate findings at write-time, enforcing required fields.

    Required: vuln_type, endpoint, severity (must be in VALID_SEVERITIES).
    Optional but recommended: parameter, evidence, confirmed, tool_used,
    chained_from.

    Returns validated findings dict (only valid entries included).
    """
    validated: dict[str, Any] = {}

    for fid, info in findings.items():
        if not isinstance(info, dict):
            logger.warning("finding_invalid_type", finding_id=fid, type=type(info).__name__)
            continue

        # Check required fields
        missing = [f for f in _REQUIRED_FINDING_FIELDS if not info.get(f)]
        if missing:
            logger.warning(
                "finding_missing_fields",
                finding_id=fid,
                missing=missing,
            )
            continue

        # Validate severity
        severity = info.get("severity", "").lower()
        if severity not in _VALID_SEVERITIES:
            logger.warning(
                "finding_invalid_severity",
                finding_id=fid,
                severity=severity,
            )
            continue

        # Normalize severity to lowercase
        info["severity"] = severity

        # Ensure confirmed field has a boolean
        if "confirmed" not in info:
            info["confirmed"] = False

        validated[fid] = info

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
