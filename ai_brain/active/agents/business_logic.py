"""Business logic testing agent.

Maps application workflows, identifies state transition anomalies,
and tests for business logic vulnerabilities using multi-account
browser sessions and AI reasoning.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog

from ai_brain.active.agents.base import BaseActiveAgent
from ai_brain.active.http_attacker import (
    AuthzTester,
    TrafficAnalyzer,
    get_cookies_for_account,
)
from ai_brain.active_schemas import BusinessLogicTestResult, TestAccount
from ai_brain.prompts.active_business_logic import (
    ActiveBusinessExploitDesignPrompt,
    ActiveStateAnalysisPrompt,
    ActiveWorkflowMappingPrompt,
)

logger = structlog.get_logger()


def _safe_get(obj: Any, key: str, default: Any = None) -> Any:
    """Get attribute from either dict or Pydantic object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class BusinessLogicAgent(BaseActiveAgent):
    """Tests for business logic vulnerabilities using Opus-level reasoning."""

    @property
    def agent_type(self) -> str:
        return "business_logic"

    async def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        target_url = state["target_url"]
        recon = state.get("recon_result")
        accounts: list[TestAccount] = state.get("accounts", [])
        raw_findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # Get data for workflow mapping
        sitemap = []
        forms = []
        api_endpoints = []
        if recon:
            if isinstance(recon, dict):
                sitemap = recon.get("sitemap", [])
                forms = recon.get("forms", [])
                api_endpoints = recon.get("api_endpoints", [])
            else:
                sitemap = getattr(recon, "sitemap", [])
                forms = getattr(recon, "forms", [])
                api_endpoints = getattr(recon, "api_endpoints", [])
            # Ensure items are dicts (not Pydantic objects)
            sitemap = [s.model_dump() if hasattr(s, "model_dump") else s for s in sitemap]
            forms = [f.model_dump() if hasattr(f, "model_dump") else f for f in forms]
            api_endpoints = [a.model_dump() if hasattr(a, "model_dump") else a for a in api_endpoints]

        traffic = self.proxy.get_traffic(limit=50) if self.proxy.is_running else []
        traffic_json = json.dumps(
            [{"method": t.request.method, "url": t.request.url,
              "status": t.response.status, "tags": t.tags}
             for t in traffic],
            default=str,
        )[:8000]

        # Cascading intelligence: pass pipeline context
        pipeline_ctx = state.get("pipeline_context", [])
        pipeline_text = "\n".join(pipeline_ctx[-10:]) if pipeline_ctx else ""

        # Map workflows using Opus
        workflow_map = await self._call_claude(
            ActiveWorkflowMappingPrompt(),
            target=target_url,
            sitemap=json.dumps(sitemap, default=str)[:5000],
            forms=json.dumps(forms, default=str)[:5000],
            api_endpoints=json.dumps(api_endpoints, default=str)[:5000],
            traffic_summary=traffic_json,
            pipeline_context=pipeline_text,
        )

        # Analyze state transitions (handle both dict and Pydantic)
        hypotheses = _safe_get(workflow_map, "vulnerability_hypotheses", [])
        test_sequences = _safe_get(workflow_map, "test_sequences", [])

        state_analysis = await self._call_claude(
            ActiveStateAnalysisPrompt(),
            target=target_url,
            workflow=_safe_get(workflow_map, "workflow_name", "main"),
            transitions=json.dumps(
                _safe_get(workflow_map, "state_transitions", []), default=str
            )[:5000],
            timing_data=json.dumps(
                state.get("traffic_intelligence", {}).get("timing_anomalies", []),
                default=str,
            )[:3000],
            request_details=traffic_json[:3000],
        )

        # Design and execute exploits for promising hypotheses
        candidates = (
            _safe_get(state_analysis, "state_bypass_opportunities", [])
            + _safe_get(state_analysis, "race_condition_candidates", [])
        )

        for candidate in candidates[:8]:
            self._check_kill_switch()

            try:
                exploit = await self._call_claude(
                    ActiveBusinessExploitDesignPrompt(),
                    target=target_url,
                    anomaly=str(candidate),
                    workflow_map=json.dumps(
                        workflow_map.model_dump() if hasattr(workflow_map, "model_dump")
                        else workflow_map if isinstance(workflow_map, dict)
                        else {}, default=str
                    )[:5000],
                    accounts=json.dumps(
                        [a.model_dump() for a in accounts], default=str
                    )[:3000],
                    target_url=target_url,
                )

                # Execute exploit steps
                finding = await self._execute_exploit(
                    exploit=exploit,
                    accounts=accounts,
                    target_url=target_url,
                )
                if finding:
                    raw_findings.append(finding)

            except Exception as e:
                errors.append(f"Business logic test failed: {e}")

        # Test IDOR if we have 2+ accounts
        if len(accounts) >= 2:
            idor_findings = await self._test_idor(accounts, target_url, state)
            raw_findings.extend(idor_findings)

        # ── Authorization matrix testing ──
        # Replay auth-sensitive requests across privilege levels
        authz_findings = await self._test_authorization_matrix(
            accounts, target_url,
        )
        raw_findings.extend(authz_findings)

        # Test race conditions
        race_candidates = getattr(state_analysis, "race_condition_candidates", [])
        for rc in race_candidates[:8]:
            self._check_kill_switch()
            finding = await self._test_race_condition(rc, accounts, target_url)
            if finding:
                raw_findings.append(finding)

        self._log_step(
            "business_logic_testing",
            input_data={
                "hypotheses": len(hypotheses),
                "candidates": len(candidates),
                "accounts": len(accounts),
            },
            output_data={"findings": len(raw_findings)},
        )

        return {"raw_findings": raw_findings, "errors": errors}

    def _resolve_context(self, raw_context: str) -> str:
        """Map AI-generated context names to actual browser contexts."""
        raw = raw_context.lower().strip()
        available = list(self.browser._contexts.keys())
        # Direct match
        if raw_context in available:
            return raw_context
        # Common AI-generated names → actual contexts
        if any(kw in raw for kw in ("attacker", "unauth", "anon", "visitor")):
            return "user1"
        if any(kw in raw for kw in ("victim", "target", "user_a", "user a")):
            return "user2" if "user2" in available else "user1"
        if any(kw in raw for kw in ("admin", "privileged", "user_b", "user b")):
            return "user3" if "user3" in available else "user1"
        # Numbered references
        for ctx in available:
            if ctx in raw:
                return ctx
        # Default to user1
        return "user1"

    async def _execute_exploit(
        self,
        exploit: Any,
        accounts: list[TestAccount],
        target_url: str,
    ) -> dict[str, Any] | None:
        """Execute a designed exploit sequence."""
        steps = getattr(exploit, "steps", [])
        if not steps:
            return None

        evidence_parts = []
        for step in steps:
            self._check_kill_switch()

            action = step.get("action", "")
            url = step.get("url", "")
            context = self._resolve_context(step.get("context", "user1"))

            try:
                if action == "navigate" and url:
                    result = await self._safe_browser_action(
                        "navigate", context, url=url
                    )
                    evidence_parts.append(
                        f"Step: navigate {url} -> {result.page_url}"
                    )
                elif action == "click":
                    selector = step.get("selector", "")
                    result = await self._safe_browser_action(
                        "click", context, selector=selector
                    )
                    evidence_parts.append(f"Step: click {selector}")
                elif action == "fill":
                    selector = step.get("selector", "")
                    value = step.get("value", "")
                    await self._safe_browser_action(
                        "fill", context, selector=selector, value=value
                    )
                    evidence_parts.append(f"Step: fill {selector}")
                elif action == "submit":
                    await self._safe_browser_action("submit_form", context)
                    evidence_parts.append("Step: submit form")
            except Exception as e:
                evidence_parts.append(f"Step failed: {e}")

        if evidence_parts:
            return {
                "vuln_type": "business_logic",
                "endpoint": target_url,
                "parameter": "",
                "pattern_tested": getattr(exploit, "pattern", "unknown"),
                "evidence": "\n".join(evidence_parts),
                "tool_used": "browser",
                "confirmed": False,
                "impact": getattr(exploit, "expected_impact", ""),
            }
        return None

    async def _test_authorization_matrix(
        self,
        accounts: list[TestAccount],
        target_url: str,
    ) -> list[dict[str, Any]]:
        """Test authorization by replaying requests across privilege levels.

        Identifies auth-sensitive requests from proxy traffic, then replays
        each with different account cookies and anonymous (no cookies).
        Detects broken access control when lower-privilege users get
        the same response as higher-privilege ones.
        """
        findings: list[dict[str, Any]] = []

        if not self.proxy.is_running or len(accounts) < 2:
            return findings

        traffic = self.proxy.get_traffic(limit=500)
        if not traffic:
            return findings

        # Find auth-sensitive requests
        analyzer = TrafficAnalyzer(self.scope_guard)
        sensitive_requests = analyzer.find_auth_sensitive_requests(traffic)

        if not sensitive_requests:
            logger.info("authz_matrix_skip", reason="no_sensitive_requests")
            return findings

        logger.info("authz_matrix_start",
                     sensitive_requests=len(sensitive_requests),
                     accounts=len(accounts))

        # Build privilege levels: each account + anonymous
        privilege_levels: dict[str, dict[str, str]] = {}

        # Get cookies for each account
        for i, account in enumerate(accounts):
            try:
                cookies = await get_cookies_for_account(self.browser, account)
                if cookies:
                    level_name = f"user_{account.username}" if account.username else f"account_{i}"
                    privilege_levels[level_name] = cookies
            except Exception:
                pass

        # Always test anonymous access (no cookies)
        privilege_levels["anonymous"] = {}

        if len(privilege_levels) < 2:
            return findings

        # Test top auth-sensitive requests (limit to avoid excessive requests)
        authz_tester = AuthzTester(self.scope_guard)
        tested = 0
        max_authz_tests = 20

        # Deduplicate by URL+method
        seen_endpoints: set[str] = set()

        for entry in sensitive_requests:
            if tested >= max_authz_tests:
                break

            endpoint_key = f"{entry.request.method}:{entry.request.url}"
            if endpoint_key in seen_endpoints:
                continue
            seen_endpoints.add(endpoint_key)

            # Skip public endpoints (segment-level matching)
            from urllib.parse import urlparse
            path_lower = urlparse(entry.request.url).path.lower().rstrip("/")
            path_segments = [s for s in path_lower.split("/") if s]
            is_public = False
            # Check multi-segment prefixes
            for prefix in self._PUBLIC_PATH_PREFIXES:
                if path_lower == prefix.lower().rstrip("/"):
                    is_public = True
                    break
            # Check single-segment: only if last segment matches
            if not is_public and path_segments:
                if path_segments[-1] in self._PUBLIC_PATH_SEGMENTS:
                    is_public = True
            if is_public:
                continue

            self._check_kill_switch()

            try:
                authz_findings = await authz_tester.test_authorization(
                    entry, privilege_levels,
                )
                findings.extend(authz_findings)
                tested += 1
            except Exception as e:
                logger.debug("authz_test_error",
                             url=entry.request.url, error=str(e)[:200])

        logger.info("authz_matrix_done", tested=tested, findings=len(findings))
        return findings

    # Public path segments — endpoints whose FULL path segments match are
    # accessible by design (not suitable for IDOR/authz testing).
    _PUBLIC_PATH_SEGMENTS = frozenset({
        "login", "signin", "sign-in", "sign_in",
        "register", "signup", "sign-up", "sign_up",
        "forgot-password", "forget-password", "forgot_password",
        "reset-password", "reset_password", "password-reset",
        "oauth", "sso",
        "captcha", "health", "ping", "status",
    })

    _PUBLIC_PATH_PREFIXES = (
        "/auth/login", "/auth/register", "/auth/forgot",
    )

    async def _test_idor(
        self,
        accounts: list[TestAccount],
        target_url: str,
        state: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Test IDOR by accessing user A's resources from user B's session."""
        findings = []
        interaction_points = state.get("interaction_points", [])

        # Find endpoints with ID-like parameters, excluding public endpoints
        from urllib.parse import urlparse

        def _is_public_path(url: str) -> bool:
            """Segment-level public path check."""
            p = urlparse(url).path.lower().rstrip("/")
            segs = [s for s in p.split("/") if s]
            for prefix in self._PUBLIC_PATH_PREFIXES:
                if p == prefix.lower().rstrip("/"):
                    return True
            if segs and segs[-1] in self._PUBLIC_PATH_SEGMENTS:
                return True
            return False

        id_endpoints = [
            p for p in interaction_points
            if any(
                kw in param.lower()
                for param in p.params
                for kw in ("id", "uid", "user", "account", "profile")
            )
            and not _is_public_path(p.url)
        ]

        if len(accounts) < 2 or not id_endpoints:
            return findings

        user_a = accounts[0]
        user_b = accounts[1]

        for endpoint in id_endpoints[:15]:
            self._check_kill_switch()
            try:
                # Navigate as user A to get resource URL
                result_a = await self._safe_browser_action(
                    "navigate", user_a.context_name, url=endpoint.url
                )
                page_a = await self._safe_browser_action(
                    "extract_page_info", user_a.context_name
                )

                # Try accessing same URL as user B
                result_b = await self._safe_browser_action(
                    "navigate", user_b.context_name, url=result_a.page_url
                )
                page_b = await self._safe_browser_action(
                    "extract_page_info", user_b.context_name
                )

                # Compare — if user B can see user A's data, it's IDOR
                text_a = page_a.get("text_content", "")[:1000]
                text_b = page_b.get("text_content", "")[:1000]

                if text_a and text_b and text_a == text_b and result_b.success:
                    findings.append({
                        "vuln_type": "idor",
                        "endpoint": endpoint.url,
                        "parameter": ", ".join(endpoint.params),
                        "evidence": f"User B accessed User A's resource at {endpoint.url}",
                        "tool_used": "browser",
                        "confirmed": False,
                        "accounts_used": [user_a.username, user_b.username],
                    })

            except Exception as e:
                logger.debug("idor_test_error", endpoint=endpoint.url, error=str(e))

        return findings

    async def _test_race_condition(
        self,
        candidate: Any,
        accounts: list[TestAccount],
        target_url: str,
    ) -> dict[str, Any] | None:
        """Test a race condition by sending concurrent HTTP requests."""
        import re
        import httpx

        if not accounts:
            return None

        # Extract endpoint URL from candidate (may be a string or dict)
        candidate_str = str(candidate) if not isinstance(candidate, str) else candidate
        endpoint = _safe_get(candidate, "endpoint", "") if isinstance(candidate, dict) else ""

        # Try to find a URL in the candidate description
        if not endpoint:
            url_match = re.search(r"https?://[^\s,;\"'<>]+", candidate_str)
            if url_match:
                endpoint = url_match.group(0).rstrip(".,;:)")

        # Fall back to target_url only if no endpoint found
        if not endpoint:
            # Try to find a path reference like "/api/..." or "/auth/..."
            path_match = re.search(r'(/[\w/.-]+)', candidate_str)
            if path_match:
                from urllib.parse import urlparse, urljoin
                endpoint = urljoin(target_url, path_match.group(1))
            else:
                logger.debug("race_skip_no_endpoint", candidate=candidate_str[:200])
                return None

        # Get cookies from the first account's browser context for authenticated requests
        context = accounts[0].context_name
        cookies = {}
        try:
            browser_cookies = await self._safe_browser_action("get_cookies", context)
            if browser_cookies and isinstance(browser_cookies, list):
                for c in browser_cookies:
                    if isinstance(c, dict) and c.get("name"):
                        cookies[c["name"]] = c.get("value", "")
        except Exception:
            pass

        # Send concurrent HTTP requests (5-10 simultaneous)
        concurrency = 10
        try:
            async with httpx.AsyncClient(
                cookies=cookies,
                timeout=10.0,
                verify=False,
                follow_redirects=True,
            ) as client:
                tasks = [client.get(endpoint) for _ in range(concurrency)]
                results = await asyncio.gather(*tasks, return_exceptions=True)

            # Analyze responses for race condition indicators
            successful = [r for r in results if isinstance(r, httpx.Response)]
            if len(successful) < 2:
                return None

            status_codes = [r.status_code for r in successful]
            body_lengths = [len(r.content) for r in successful]

            # Race condition indicators:
            # 1. Mixed success/error status codes (some 200, some 4xx/5xx)
            unique_statuses = set(status_codes)
            status_mix = len(unique_statuses) > 1
            # 2. Significantly different response sizes (> 50% variance)
            avg_len = sum(body_lengths) / len(body_lengths) if body_lengths else 0
            size_variance = any(
                abs(bl - avg_len) > avg_len * 0.5 for bl in body_lengths
            ) if avg_len > 100 else False

            # 3. Content-based differences (word overlap similarity)
            content_diff = False
            content_evidence = ""
            response_texts = [r.text for r in successful]
            if len(response_texts) >= 2:
                # Compare word sets between first response and others
                ref_words = set(response_texts[0].split())
                if ref_words:
                    for idx, text in enumerate(response_texts[1:], 1):
                        other_words = set(text.split())
                        if not other_words:
                            continue
                        overlap = len(ref_words & other_words)
                        total = max(len(ref_words), len(other_words))
                        similarity = overlap / total if total > 0 else 1.0
                        if similarity < 0.85:  # Less than 85% word overlap
                            content_diff = True
                            content_evidence = (
                                f"Response {idx} differs from baseline "
                                f"(word similarity: {similarity:.1%})"
                            )
                            break

            # 4. Set-Cookie header differences (session state divergence)
            cookie_diff = False
            cookie_evidence = ""
            resp_cookies = []
            for r in successful:
                sc = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
                if not sc:
                    # fallback: single header
                    sc_val = r.headers.get("set-cookie", "")
                    sc = [sc_val] if sc_val else []
                resp_cookies.append(frozenset(sc))
            unique_cookie_sets = set(resp_cookies)
            if len(unique_cookie_sets) > 1:
                cookie_diff = True
                cookie_evidence = f"Set-Cookie divergence across {len(unique_cookie_sets)} variants"

            # 5. Response header differences (content-type, location, etc.)
            header_diff = False
            header_evidence = ""
            key_headers = ["content-type", "location", "x-redirect", "x-error"]
            for hdr in key_headers:
                hdr_vals = set()
                for r in successful:
                    val = r.headers.get(hdr, "")
                    if val:
                        hdr_vals.add(val)
                if len(hdr_vals) > 1:
                    header_diff = True
                    header_evidence = f"Header '{hdr}' varies: {hdr_vals}"
                    break

            if status_mix or size_variance or content_diff or cookie_diff or header_diff:
                evidence_parts = [
                    f"Race condition test on {endpoint} with {concurrency} concurrent requests:",
                    f"Status codes: {status_codes}",
                    f"Response sizes: {body_lengths}",
                ]
                if status_mix:
                    evidence_parts.append(f"Mixed status codes detected: {unique_statuses}")
                if size_variance:
                    evidence_parts.append(f"Significant response size variance (avg: {avg_len:.0f})")
                if content_diff:
                    evidence_parts.append(f"Content difference: {content_evidence}")
                if cookie_diff:
                    evidence_parts.append(f"Cookie difference: {cookie_evidence}")
                if header_diff:
                    evidence_parts.append(f"Header difference: {header_evidence}")
                return {
                    "vuln_type": "race_condition",
                    "endpoint": endpoint,
                    "parameter": "",
                    "evidence": "\n".join(evidence_parts),
                    "tool_used": "httpx_concurrent",
                    "confirmed": False,
                    "candidate_description": candidate_str[:500],
                }

        except Exception as e:
            logger.debug("race_test_error", endpoint=endpoint, error=str(e)[:200])

        return None
