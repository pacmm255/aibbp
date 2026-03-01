"""Injection testing agent.

Tests interaction points for SQL injection, XSS, command injection,
and other injection vulnerabilities using automated tools, HTTP-level
replay with differential analysis, and AI-guided manual payloads.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

import structlog

from ai_brain.active.agents.base import BaseActiveAgent
from ai_brain.active.errors import ToolExecutionError
from ai_brain.active.http_attacker import (
    HTTPRepeater,
    TrafficAnalyzer,
    get_cookies_for_account,
)
from ai_brain.active_schemas import InjectionTestResult, InteractionPoint
from ai_brain.prompts.active_injection import (
    ActiveInjectionAnalysisPrompt,
    ActivePayloadSelectionPrompt,
    ActiveSSRFTestingPrompt,
)

logger = structlog.get_logger()

# Pattern to extract a URL from a string that may contain notes/comments
_URL_PATTERN = re.compile(r"https?://[^\s,;\"'<>]+")


def _clean_endpoint(raw: str) -> str | None:
    """Extract a clean URL from an AI-generated endpoint string.

    Claude sometimes adds notes/comments to URLs in tool_recommendations,
    e.g. "http://example.com/api?id=1 - Obtain a valid captcha value first".
    This extracts just the URL portion and validates it.
    """
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip()

    # If the whole string is a valid URL, use it directly
    parsed = urlparse(raw)
    if parsed.scheme in ("http", "https") and parsed.netloc and " " not in raw:
        return raw

    # Otherwise, extract the first URL from the string
    match = _URL_PATTERN.search(raw)
    if match:
        url = match.group(0).rstrip(".,;:)")
        return url

    return None


class InjectionAgent(BaseActiveAgent):
    """Tests for injection vulnerabilities using tools and manual payloads."""

    @property
    def agent_type(self) -> str:
        return "injection"

    async def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        target_url = state["target_url"]
        interaction_points: list[InteractionPoint] = state.get("interaction_points", [])
        raw_findings: list[dict[str, Any]] = []
        errors: list[str] = []

        if not interaction_points:
            return {"raw_findings": [], "errors": ["No interaction points to test"]}

        # Get tech stack from recon
        tech_stack = []
        recon = state.get("recon_result")
        if recon:
            if isinstance(recon, dict):
                tech_stack = recon.get("technology_stack", [])
            else:
                tech_stack = getattr(recon, "technology_stack", [])

        # Get traffic intelligence (analyzed by TrafficIntelligence)
        intel = state.get("traffic_intelligence", {})
        intel_text = intel.get("prompt_text", "")
        waf_info = intel.get("waf_type", "")

        # Fall back to raw traffic sample if no intelligence
        if not intel_text:
            traffic = self.proxy.get_traffic(limit=50) if self.proxy.is_running else []
            traffic_json = json.dumps(
                [{"method": t.request.method, "url": t.request.url,
                  "status": t.response.status, "body": t.response.body[:500]}
                 for t in traffic],
                default=str,
            )[:5000]
        else:
            traffic_json = intel_text

        # Cascading intelligence: pass pipeline context to injection analysis
        pipeline_ctx = state.get("pipeline_context", [])
        pipeline_text = "\n".join(pipeline_ctx[-10:]) if pipeline_ctx else ""

        # Use Claude to analyze which points to test and how
        analysis = await self._call_claude(
            ActiveInjectionAnalysisPrompt(),
            target=target_url,
            interaction_points=json.dumps(
                [p.model_dump() for p in interaction_points[:100]], default=str
            )[:16000],
            observed_responses=traffic_json,
            tech_stack=json.dumps(tech_stack),
            pipeline_context=pipeline_text,
        )

        # Process candidates by tool recommendation
        candidates = getattr(analysis, "candidates", [])
        tool_recs = getattr(analysis, "tool_recommendations", {})

        # Test with sqlmap
        sqlmap_targets = tool_recs.get("sqlmap", [])
        for raw_endpoint in sqlmap_targets[:15]:
            endpoint = _clean_endpoint(raw_endpoint)
            if not endpoint:
                logger.debug("sqlmap_skip_bad_url", raw=str(raw_endpoint)[:200])
                continue
            self._check_kill_switch()
            try:
                result = await self._safe_tool_run(
                    "sqlmap",
                    url=endpoint,
                    params=self._get_params_for_endpoint(endpoint, interaction_points),
                )
                if result.get("findings"):
                    for finding_data in result["findings"]:
                        raw_findings.append({
                            "vuln_type": "sqli",
                            "endpoint": endpoint,
                            "parameter": str(finding_data.get("parameter", finding_data.get("param", ""))),
                            "evidence": json.dumps(finding_data)[:2000],
                            "tool_used": "sqlmap",
                            "confirmed": True,
                        })
            except ToolExecutionError as e:
                errors.append(f"sqlmap on {endpoint}: {e}")

        # Test with dalfox
        dalfox_targets = tool_recs.get("dalfox", [])
        for raw_endpoint in dalfox_targets[:15]:
            endpoint = _clean_endpoint(raw_endpoint)
            if not endpoint:
                logger.debug("dalfox_skip_bad_url", raw=str(raw_endpoint)[:200])
                continue
            self._check_kill_switch()
            try:
                result = await self._safe_tool_run(
                    "dalfox",
                    url=endpoint,
                    params=self._get_params_for_endpoint(endpoint, interaction_points),
                )
                if result.get("findings"):
                    for finding_data in result["findings"]:
                        # dalfox uses "param" key, not "parameter"
                        param = str(finding_data.get("param", finding_data.get("parameter", "")))
                        evidence = json.dumps(finding_data)[:2000]
                        # Skip truly empty findings (no useful data at all)
                        has_payload = (
                            finding_data.get("data")
                            or finding_data.get("poc")
                            or finding_data.get("payload")
                        )
                        has_context = (
                            finding_data.get("injection_point")
                            or finding_data.get("reflected_in")
                            or finding_data.get("type")
                            or finding_data.get("alert_type")
                        )
                        if not has_payload and not has_context:
                            logger.debug("dalfox_skip_empty_finding", finding=str(finding_data)[:200])
                            continue
                        raw_findings.append({
                            "vuln_type": "xss",
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload_used": str(finding_data.get("data", finding_data.get("payload", finding_data.get("poc", "")))),
                            "evidence": evidence,
                            "tool_used": "dalfox",
                            "confirmed": True,
                        })
            except ToolExecutionError as e:
                errors.append(f"dalfox on {endpoint}: {e}")

        # Test with commix
        commix_targets = tool_recs.get("commix", [])
        for raw_endpoint in commix_targets[:10]:
            endpoint = _clean_endpoint(raw_endpoint)
            if not endpoint:
                logger.debug("commix_skip_bad_url", raw=str(raw_endpoint)[:200])
                continue
            self._check_kill_switch()
            try:
                result = await self._safe_tool_run(
                    "commix",
                    url=endpoint,
                    params=self._get_params_for_endpoint(endpoint, interaction_points),
                )
                if result.get("findings"):
                    for finding_data in result["findings"]:
                        raw_findings.append({
                            "vuln_type": "command_injection",
                            "endpoint": endpoint,
                            "parameter": str(finding_data.get("parameter", finding_data.get("param", ""))),
                            "evidence": json.dumps(finding_data)[:2000],
                            "tool_used": "commix",
                            "confirmed": True,
                        })
            except ToolExecutionError as e:
                errors.append(f"commix on {endpoint}: {e}")

        # ── HTTP-level testing via traffic replay ──
        # Analyze captured proxy traffic and test insertion points directly
        http_findings = await self._test_http_level(state, tech_stack)
        raw_findings.extend(http_findings)

        # Manual testing via AI-selected payloads for remaining candidates
        manual_candidates = [
            c for c in candidates
            if getattr(c, "tool_used", "manual") == "manual"
        ][:20]

        # Always supplement with interaction points not already covered by tool targets
        tool_covered_urls = set()
        for raw_ep in (sqlmap_targets + dalfox_targets + commix_targets):
            ep = _clean_endpoint(raw_ep)
            if ep:
                tool_covered_urls.add(ep)
        manual_covered_urls = set()
        for c in manual_candidates:
            u = getattr(c, "endpoint", "") or getattr(c, "url", "")
            if isinstance(c, dict):
                u = c.get("endpoint", "") or c.get("url", "")
            if u:
                manual_covered_urls.add(u)

        # Add untested interaction points
        extra_points = [
            p for p in interaction_points
            if p.url not in tool_covered_urls and p.url not in manual_covered_urls
        ]
        if extra_points:
            logger.info("injection_adding_untested_points", count=len(extra_points))
            manual_candidates.extend(extra_points[:30])

        # Use best available auth context for deeper testing coverage
        test_context = "recon"
        for ctx_name in ["user1", "user2", "user3"]:
            try:
                self.browser._get_page(ctx_name)
                test_context = ctx_name
                break
            except (ValueError, KeyError):
                pass

        for i, candidate in enumerate(manual_candidates):
            self._check_kill_switch()
            try:
                # Handle both Pydantic objects and dicts
                if isinstance(candidate, dict):
                    endpoint = candidate.get("endpoint", "") or candidate.get("url", "")
                    parameter = candidate.get("parameter", "") or (
                        candidate.get("params", [""])[0]
                        if candidate.get("params", []) else "q"
                    )
                    vuln_type = candidate.get("vuln_type", "xss")
                else:
                    endpoint = getattr(candidate, "endpoint", "") or getattr(candidate, "url", "")
                    parameter = getattr(candidate, "parameter", "") or (
                        getattr(candidate, "params", [""])[0]
                        if getattr(candidate, "params", []) else "q"
                    )
                    vuln_type = getattr(candidate, "vuln_type", "xss")

                logger.debug("injection_candidate", index=i, endpoint=endpoint[:200],
                             parameter=parameter, vuln_type=vuln_type,
                             candidate_type=type(candidate).__name__)

                if not endpoint:
                    logger.debug("injection_candidate_skip", index=i, reason="no endpoint")
                    continue

                # Get a sample response for this endpoint from proxy
                sample_resp = ""
                if self.proxy.is_running:
                    endpoint_traffic = self.proxy.get_traffic(url_filter=endpoint, limit=1)
                    if endpoint_traffic:
                        sample_resp = endpoint_traffic[0].response.body[:2000]

                payload_result = await self._call_claude(
                    ActivePayloadSelectionPrompt(),
                    target=target_url,
                    parameter=parameter,
                    endpoint=endpoint,
                    injection_type=vuln_type,
                    tech_stack=json.dumps(tech_stack, default=str),
                    waf_info=waf_info or "None detected",
                    sample_response=sample_resp,
                )

                # Extract payloads from Claude result (handle both list and object)
                payloads = getattr(payload_result, "payloads", [])
                if not payloads:
                    payloads = getattr(payload_result, "payload_list", [])

                logger.debug("payload_extraction", count=len(payloads),
                             sample=str(payloads[:2])[:300])

                for payload_info in payloads[:10]:
                    # Handle both dict and object formats
                    if isinstance(payload_info, dict):
                        # Try common key names for payload value
                        payload = (
                            payload_info.get("payload", "")
                            or payload_info.get("value", "")
                            or payload_info.get("content", "")
                            or payload_info.get("string", "")
                        )
                        # Last resort: use first non-empty value
                        if not payload:
                            for v in payload_info.values():
                                if v and isinstance(v, str) and len(v) > 1:
                                    payload = v
                                    break
                    elif isinstance(payload_info, str):
                        payload = payload_info
                    else:
                        payload = getattr(payload_info, "payload", str(payload_info))

                    if not payload:
                        logger.debug("payload_empty", payload_info=str(payload_info)[:200])
                        continue

                    finding = await self._test_payload(
                        context_name=test_context,
                        endpoint=endpoint,
                        parameter=parameter,
                        payload=payload,
                        vuln_type=vuln_type,
                    )
                    if finding:
                        raw_findings.append(finding)
                        # Continue testing — may find more severe variants

            except Exception as e:
                errors.append(f"manual test on {getattr(candidate, 'endpoint', getattr(candidate, 'url', '?'))}: {e}")

        # SSRF testing — identify URL-accepting parameters and test
        ssrf_findings = await self._test_ssrf(state, interaction_points, tech_stack)
        raw_findings.extend(ssrf_findings)

        # File upload testing — check forms for file input fields
        file_upload_endpoints_tested: set[str] = set()
        for point in interaction_points[:50]:
            endpoint = point.url if hasattr(point, "url") else point.get("url", "")
            if not endpoint or endpoint in file_upload_endpoints_tested:
                continue
            self._check_kill_switch()
            try:
                await self.browser.create_context("file_upload_test")
            except Exception:
                pass
            try:
                result = await self._safe_browser_action(
                    "navigate", "file_upload_test", url=endpoint
                )
                if not result or not result.success:
                    continue
                page_info = await self._safe_browser_action(
                    "extract_page_info", "file_upload_test"
                )
                forms = page_info.get("forms", []) if page_info else []
                for form in forms:
                    for field in form.get("fields", []):
                        if field.get("type") == "file":
                            file_field_name = field.get("name", "file")
                            logger.info(
                                "file_upload_detected",
                                endpoint=endpoint,
                                field=file_field_name,
                            )
                            file_upload_endpoints_tested.add(endpoint)
                            file_findings = await self._test_file_upload(
                                context_name="file_upload_test",
                                endpoint=endpoint,
                                file_field_name=file_field_name,
                                tech_stack=tech_stack,
                                forms=forms,
                            )
                            raw_findings.extend(file_findings)
                            break  # One file field per form is enough
            except Exception as e:
                errors.append(f"file_upload test on {endpoint}: {e}")

        self._log_step(
            "injection_testing",
            input_data={
                "interaction_points": len(interaction_points),
                "tool_targets": {
                    "sqlmap": len(sqlmap_targets),
                    "dalfox": len(dalfox_targets),
                    "commix": len(commix_targets),
                    "manual": len(manual_candidates),
                    "ssrf": len(ssrf_findings),
                    "file_upload": len(file_upload_endpoints_tested),
                },
            },
            output_data={"findings": len(raw_findings)},
        )

        return {"raw_findings": raw_findings, "errors": errors}

    async def _test_payload(
        self,
        context_name: str,
        endpoint: str,
        parameter: str,
        payload: str,
        vuln_type: str,
    ) -> dict[str, Any] | None:
        """Test a single payload via browser and check for indicators."""
        try:
            logger.debug("payload_test_start", endpoint=endpoint, parameter=parameter,
                         vuln_type=vuln_type, payload=payload[:80], context=context_name)

            # First navigate to the endpoint
            result = await self._safe_browser_action(
                "navigate", context_name, url=endpoint
            )
            if not result.success:
                logger.debug("payload_navigate_failed", endpoint=endpoint, error=getattr(result, "error", ""))
                return None

            # Try to fill form fields with the payload
            page_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            forms = page_info.get("forms", [])

            form_tested = False
            # Skip hidden/CSRF fields — they can't be filled via browser
            unfillable_types = {"hidden", "submit", "button", "image", "reset"}
            if forms:
                # Try to fill the target parameter in a form field
                for form in forms:
                    for field in form.get("fields", []):
                        fname = field.get("name", "")
                        ftype = field.get("type", "text")
                        if ftype in unfillable_types:
                            continue
                        if fname == parameter or (not parameter and ftype in ("text", "search", "email")):
                            try:
                                selector = f"[name='{fname}']"
                                await self._safe_browser_action(
                                    "fill", context_name, selector=selector, value=payload
                                )
                                await self._safe_browser_action(
                                    "submit_form", context_name
                                )
                                form_tested = True
                                break
                            except Exception:
                                pass
                    if form_tested:
                        break

            if not form_tested:
                # Fall back to URL parameter injection
                test_url = endpoint
                if "?" in test_url:
                    test_url += f"&{parameter}={payload}"
                else:
                    test_url += f"?{parameter}={payload}"
                logger.debug("payload_url_injection", test_url=test_url[:200], parameter=parameter)
                result = await self._safe_browser_action(
                    "navigate", context_name, url=test_url
                )
                if not result.success:
                    logger.debug("payload_url_navigate_failed", test_url=test_url[:200],
                                 error=getattr(result, "error", ""))
                    return None

            # Check for injection indicators in the page
            page_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            text = page_info.get("text_content", "")
            page_url = page_info.get("url", "")

            # XSS: payload reflected in response
            if vuln_type == "xss" and payload in text:
                return {
                    "vuln_type": "xss",
                    "endpoint": endpoint,
                    "parameter": parameter,
                    "payload_used": payload,
                    "evidence": f"Payload reflected in response: {text[:500]}",
                    "tool_used": "manual_browser",
                    "confirmed": False,
                }

            # SQLi: error indicators
            sqli_indicators = [
                "sql syntax", "mysql", "syntax error", "unclosed quotation",
                "postgresql", "sqlite", "ora-", "sql server", "mariadb",
                "sqlstate", "database error", "query failed",
            ]
            if vuln_type == "sqli" and any(
                indicator in text.lower() for indicator in sqli_indicators
            ):
                return {
                    "vuln_type": "sqli",
                    "endpoint": endpoint,
                    "parameter": parameter,
                    "payload_used": payload,
                    "evidence": f"SQL error indicator in response: {text[:500]}",
                    "tool_used": "manual_browser",
                    "confirmed": False,
                }

            # Generic: check for error pages or stack traces
            error_indicators = [
                "traceback", "exception", "fatal error", "debug",
                "stack trace", "internal server error",
            ]
            if any(indicator in text.lower() for indicator in error_indicators):
                return {
                    "vuln_type": vuln_type,
                    "endpoint": endpoint,
                    "parameter": parameter,
                    "payload_used": payload,
                    "evidence": f"Error/debug info exposed: {text[:500]}",
                    "tool_used": "manual_browser",
                    "confirmed": False,
                }

        except Exception as e:
            logger.warning("payload_test_error", endpoint=endpoint, parameter=parameter,
                           error=str(e)[:300], context=context_name)
        return None

    async def _test_ssrf(
        self,
        state: dict[str, Any],
        interaction_points: list[InteractionPoint],
        tech_stack: list[str],
    ) -> list[dict[str, Any]]:
        """Test for SSRF by identifying URL-accepting parameters.

        Uses a cheap Haiku call to identify candidates, then tests each
        with SSRF payloads via httpx.
        """
        import httpx

        findings: list[dict[str, Any]] = []

        # Get traffic sample for context
        traffic_sample = ""
        if self.proxy.is_running:
            traffic = self.proxy.get_traffic(limit=30)
            if traffic:
                traffic_sample = json.dumps(
                    [{"method": t.request.method, "url": t.request.url,
                      "status": t.response.status}
                     for t in traffic],
                    default=str,
                )[:5000]

        try:
            result = await self._call_claude(
                ActiveSSRFTestingPrompt(),
                target=state["target_url"],
                interaction_points=json.dumps(
                    [p.model_dump() for p in interaction_points[:80]], default=str
                )[:12000],
                traffic_sample=traffic_sample,
            )
        except Exception as e:
            logger.warning("ssrf_analysis_failed", error=str(e)[:200])
            return findings

        candidates = getattr(result, "candidates", [])
        if not candidates:
            logger.info("ssrf_no_candidates")
            return findings

        logger.info("ssrf_testing_start", candidates=len(candidates))

        # Get cookies for authenticated testing
        accounts = state.get("accounts", [])
        cookies: dict[str, str] = {}
        if accounts:
            cookies = await get_cookies_for_account(self.browser, accounts[0])

        for candidate in candidates[:10]:
            self._check_kill_switch()
            endpoint = getattr(candidate, "endpoint", "")
            parameter = getattr(candidate, "parameter", "")
            payloads = getattr(candidate, "payloads", [])

            if not endpoint or not parameter or not payloads:
                continue

            # Scope check
            if not self.scope_guard.is_in_scope(endpoint):
                continue

            for payload in payloads[:8]:
                try:
                    # Build request with SSRF payload as parameter value
                    parsed = urlparse(endpoint)
                    if "?" in endpoint:
                        test_url = f"{endpoint}&{parameter}={payload}"
                    else:
                        test_url = f"{endpoint}?{parameter}={payload}"

                    async with httpx.AsyncClient(
                        cookies=cookies,
                        timeout=10,
                        verify=False,
                        follow_redirects=True,
                    ) as client:
                        response = await client.get(test_url)

                    body = response.text[:10_000]
                    status = response.status_code

                    # Check for SSRF indicators
                    ssrf_indicators = []

                    # Cloud metadata keywords
                    cloud_keywords = [
                        "ami-id", "instance-id", "iam", "security-credentials",
                        "meta-data", "computeMetadata", "instance/",
                        "availabilityZone", "accountId",
                    ]
                    if any(kw in body for kw in cloud_keywords):
                        ssrf_indicators.append("cloud_metadata_leak")

                    # Internal content indicators
                    internal_keywords = [
                        "root:x:", "/etc/passwd", "localhost", "127.0.0.1",
                        "internal server", "connection refused",
                    ]
                    if any(kw in body.lower() for kw in internal_keywords):
                        ssrf_indicators.append("internal_content")

                    # Metadata endpoint accessible
                    if "169.254.169.254" in payload and status == 200 and len(body) > 50:
                        ssrf_indicators.append("metadata_accessible")

                    if ssrf_indicators:
                        findings.append({
                            "vuln_type": "ssrf",
                            "endpoint": endpoint,
                            "parameter": parameter,
                            "payload_used": payload,
                            "evidence": (
                                f"SSRF indicators: {', '.join(ssrf_indicators)}. "
                                f"Status: {status}, Body: {body[:500]}"
                            ),
                            "tool_used": "http_repeater",
                            "confirmed": False,
                        })
                        logger.info("ssrf_finding", endpoint=endpoint,
                                    parameter=parameter, indicators=ssrf_indicators)
                        break  # One finding per candidate is enough

                except Exception as e:
                    logger.debug("ssrf_payload_error", endpoint=endpoint,
                                 payload=payload[:80], error=str(e)[:200])

        logger.info("ssrf_testing_done", candidates_tested=min(len(candidates), 10),
                     findings=len(findings))
        return findings

    async def _test_file_upload(
        self,
        context_name: str,
        endpoint: str,
        file_field_name: str,
        tech_stack: list[str],
        forms: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Test a file upload field for unrestricted upload vulnerabilities."""
        from ai_brain.active.file_payloads import generate_upload_payloads, write_payload_to_temp

        payloads = generate_upload_payloads(tech_stack)
        findings: list[dict[str, Any]] = []

        for payload in payloads[:10]:
            self._check_kill_switch()

            # Navigate to the page fresh for each payload
            result = await self._safe_browser_action(
                "navigate", context_name, url=endpoint
            )
            if not result or not result.success:
                continue

            # Write payload to temp file
            temp_path = write_payload_to_temp(payload)

            # Upload the file
            selector = f"input[name='{file_field_name}']"
            upload_result = await self._safe_browser_action(
                "upload_file", context_name, selector=selector, file_path=temp_path
            )
            if not upload_result or not upload_result.success:
                continue

            # Fill other required non-file form fields with dummy data
            page_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            current_forms = page_info.get("forms", []) if page_info else forms
            for form in current_forms:
                for field in form.get("fields", []):
                    ftype = field.get("type", "text")
                    fname = field.get("name", "")
                    if not fname or ftype in ("hidden", "submit", "button", "image", "reset", "file"):
                        continue
                    try:
                        await self._safe_browser_action(
                            "fill", context_name,
                            selector=f"[name='{fname}']",
                            value="test_upload",
                        )
                    except Exception:
                        pass

            # Submit the form
            await self._safe_browser_action("submit_form", context_name)

            # Check the response for success/rejection indicators
            post_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            response_text = post_info.get("text_content", "") if post_info else ""

            rejection_keywords = [
                "not allowed", "invalid file", "rejected", "forbidden",
                "unsupported", "blocked", "file type", "not permitted",
                "disallowed", "only accept",
            ]
            upload_rejected = any(
                kw in response_text.lower() for kw in rejection_keywords
            )

            if not upload_rejected:
                findings.append({
                    "endpoint": endpoint,
                    "parameter": file_field_name,
                    "vuln_type": "file_upload",
                    "payload_used": payload.filename,
                    "evidence": (
                        f"Upload of {payload.filename} ({payload.bypass_type}) "
                        f"accepted. {payload.description}. "
                        f"Response: {response_text[:500]}"
                    ),
                    "tool_used": "manual_browser",
                    "confirmed": False,
                    "description": payload.description,
                })
                logger.info(
                    "file_upload_finding",
                    filename=payload.filename,
                    bypass=payload.bypass_type,
                    endpoint=endpoint,
                )

        return findings

    async def _test_http_level(
        self,
        state: dict[str, Any],
        tech_stack: list[str],
    ) -> list[dict[str, Any]]:
        """Test insertion points at the HTTP level using traffic replay.

        Analyzes captured proxy traffic, extracts insertion points (URL params,
        POST body, JSON fields, path segments), and tests each with payloads
        via httpx — differential analysis detects blind vulnerabilities.
        """
        findings: list[dict[str, Any]] = []

        if not self.proxy.is_running:
            return findings

        traffic = self.proxy.get_traffic(limit=500)
        if not traffic:
            logger.info("http_level_skip", reason="no_traffic")
            return findings

        # Extract insertion points from traffic
        analyzer = TrafficAnalyzer(self.scope_guard)
        insertion_points = analyzer.extract_insertion_points(traffic)

        if not insertion_points:
            logger.info("http_level_skip", reason="no_insertion_points")
            return findings

        logger.info("http_level_testing_start",
                     insertion_points=len(insertion_points),
                     traffic_flows=len(traffic))

        # Get cookies from first available account for authenticated testing
        accounts = state.get("accounts", [])
        cookies: dict[str, str] = {}
        if accounts:
            cookies = await get_cookies_for_account(self.browser, accounts[0])

        repeater = HTTPRepeater(self.scope_guard)

        # Build payload sets for common vulnerability types
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1' AND SLEEP(5)--",
            "1; WAITFOR DELAY '0:0:5'--",
            "' UNION SELECT NULL--",
            "1 AND 1=1",
            "1 AND 1=2",
        ]
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
            "'-alert(1)-'",
            "<svg/onload=alert(1)>",
        ]
        ssti_payloads = [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
        ]
        path_traversal_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
        ]

        # Test top insertion points (limit to avoid excessive requests)
        tested = 0
        max_http_tests = 30

        for ip in insertion_points:
            if tested >= max_http_tests:
                break
            self._check_kill_switch()

            try:
                # Choose payloads based on parameter characteristics
                payloads: list[str] = []

                # ID-like params: test IDOR/SQLi
                if ip.priority <= 2 and ip.param_type in ("query", "body", "json", "path"):
                    payloads.extend(sqli_payloads[:3])
                    # Also test IDOR: try adjacent IDs
                    if ip.original_value.isdigit():
                        orig_id = int(ip.original_value)
                        payloads.extend([
                            str(orig_id + 1),
                            str(orig_id - 1),
                            str(orig_id + 1000),
                            "0",
                            "-1",
                        ])

                # Text input params: test XSS + SQLi + SSTI
                if ip.param_type in ("query", "body", "json"):
                    payloads.extend(xss_payloads[:3])
                    payloads.extend(sqli_payloads[:3])
                    payloads.extend(ssti_payloads[:2])

                # Path params: test path traversal + IDOR
                if ip.param_type == "path":
                    payloads.extend(path_traversal_payloads)

                if not payloads:
                    continue

                # Get baseline and test
                baseline = await repeater.get_baseline(ip, cookies)
                ip_findings = await repeater.test_payloads(
                    ip, payloads, cookies, baseline,
                )

                for f in ip_findings:
                    indicators = f.get("indicators", [])
                    if not indicators:
                        continue  # Only high-deviation without indicators = likely noise

                    # Map indicators to vulnerability types
                    vuln_type = "unknown"
                    if any("sqli" in i for i in indicators):
                        vuln_type = "sqli"
                    elif any("xss" in i for i in indicators):
                        vuln_type = "xss"
                    elif any("cmdi" in i for i in indicators):
                        vuln_type = "command_injection"
                    elif any("ssti" in i for i in indicators):
                        vuln_type = "ssti"
                    elif any("path_traversal" in i for i in indicators):
                        vuln_type = "path_traversal"
                    elif any("open_redirect" in i for i in indicators):
                        vuln_type = "open_redirect"
                    elif any("time_based" in i for i in indicators):
                        vuln_type = "blind_injection"

                    findings.append({
                        "vuln_type": vuln_type,
                        "endpoint": f["insertion_point"]["url"],
                        "parameter": f["insertion_point"]["param"],
                        "param_type": f["insertion_point"]["type"],
                        "payload_used": f["payload"],
                        "evidence": (
                            f"HTTP-level test: {', '.join(indicators)}. "
                            f"Status: {f['baseline_status']}→{f['response_status']}, "
                            f"Size: {f['baseline_length']}→{f['response_length']}B, "
                            f"Time: {f['elapsed_ms']}ms. "
                            f"{f.get('evidence', '')[:1000]}"
                        ),
                        "tool_used": "http_repeater",
                        "confirmed": False,
                    })

                tested += 1

            except Exception as e:
                logger.debug("http_level_test_error",
                             url=ip.url, param=ip.param_name,
                             error=str(e)[:200])

        logger.info("http_level_testing_done",
                     tested=tested, findings=len(findings))
        return findings

    @staticmethod
    def _get_params_for_endpoint(
        endpoint: str, points: list[InteractionPoint]
    ) -> dict[str, str] | None:
        """Find parameters for a given endpoint from interaction points.

        Uses relaxed matching: if exact URL match fails, falls back to
        path-based matching (ignoring query string and fragments).
        """
        # Exact match first
        for point in points:
            if point.url == endpoint and point.params:
                return {p: "test" for p in point.params}

        # Path-based match (AI may return URLs with different query strings)
        endpoint_path = urlparse(endpoint).path
        for point in points:
            if urlparse(point.url).path == endpoint_path and point.params:
                return {p: "test" for p in point.params}

        return None
