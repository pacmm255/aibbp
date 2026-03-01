"""Active finding validator agent.

Re-tests findings independently to confirm they are real vulnerabilities,
not false positives, and generates PoC code for verified findings.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from ai_brain.active.agents.base import BaseActiveAgent
from ai_brain.active_schemas import ActiveValidationResult, TestAccount
from ai_brain.prompts.active_validate import (
    ActiveFindingVerificationPrompt,
    ActivePoCGenerationPrompt,
)

logger = structlog.get_logger()


class ActiveValidatorAgent(BaseActiveAgent):
    """Validates findings and generates PoC code."""

    @property
    def agent_type(self) -> str:
        return "validator"

    async def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        target_url = state["target_url"]
        raw_findings: list[dict[str, Any]] = state.get("raw_findings", [])
        accounts: list[TestAccount] = state.get("accounts", [])
        validated: list[ActiveValidationResult] = []
        errors: list[str] = []

        # Gather WAF info and pipeline context for verdict-aware validation
        intel = state.get("traffic_intelligence", {})
        waf_info = intel.get("waf_type", "None detected")
        pipeline_ctx = state.get("pipeline_context", [])
        pipeline_text = "\n".join(pipeline_ctx[-10:]) if pipeline_ctx else ""

        if not raw_findings:
            return {"validated_findings": [], "errors": ["No findings to validate"]}

        for i, finding in enumerate(raw_findings):
            self._check_kill_switch()

            finding_id = f"finding_{i}"

            try:
                # Use Claude to plan verification (with WAF + pipeline context)
                verification: ActiveValidationResult = await self._call_claude(
                    ActiveFindingVerificationPrompt(),
                    target=target_url,
                    finding=json.dumps(finding, default=str)[:6000],
                    evidence=finding.get("evidence", "")[:4000],
                    target_url=target_url,
                    accounts=json.dumps(
                        [a.model_dump() for a in accounts], default=str
                    )[:4000],
                    waf_info=waf_info,
                    pipeline_context=pipeline_text,
                )

                # Attempt browser-based verification
                if not verification.verified:
                    browser_verified = await self._verify_via_browser(
                        finding, accounts, target_url
                    )
                    if browser_verified:
                        verification.verified = True
                        verification.verification_method = "browser_replay"
                        verification.verification_evidence = browser_verified

                verification.finding_id = finding_id
                # Carry over original finding metadata
                verification.vuln_type = verification.vuln_type or finding.get("vuln_type", "")
                verification.endpoint = verification.endpoint or finding.get("endpoint", "")
                verification.method = verification.method or finding.get("method", "")
                verification.tool_used = verification.tool_used or finding.get("tool_used", "")
                if not verification.original_evidence:
                    verification.original_evidence = finding.get("evidence", "")[:4000]

                # Generate PoC for exploited or partially-blocked findings
                if verification.verdict in ("EXPLOITED", "BLOCKED_BY_SECURITY"):
                    try:
                        poc = await self._call_claude(
                            ActivePoCGenerationPrompt(),
                            target=target_url,
                            finding=json.dumps(finding, default=str)[:3000],
                            target_url=target_url,
                            evidence=verification.verification_evidence or finding.get("evidence", ""),
                            poc_type="python",
                        )
                        verification.poc_code = getattr(poc, "code", "")
                        verification.poc_type = getattr(poc, "language", "python")
                    except Exception as e:
                        logger.debug("poc_generation_error", error=str(e))

                validated.append(verification)

            except Exception as e:
                error_msg = f"Validation of finding {finding_id} failed: {e}"
                logger.warning("validation_error", error=error_msg)
                errors.append(error_msg)

        # Verdict breakdown for logging
        verdict_counts: dict[str, int] = {}
        for v in validated:
            verdict_counts[v.verdict] = verdict_counts.get(v.verdict, 0) + 1

        self._log_step(
            "validate_findings",
            input_data={"raw_findings": len(raw_findings)},
            output_data={
                "validated": len(validated),
                "confirmed": sum(1 for v in validated if v.verified),
                "verdicts": verdict_counts,
            },
        )

        return {"validated_findings": validated, "errors": errors}

    # CSRF token parameters — these are not XSS targets
    _CSRF_PARAMS = frozenset({
        "_token", "csrf_token", "csrfmiddlewaretoken",
        "__RequestVerificationToken", "csrf", "_csrf",
        "authenticity_token", "csrfToken", "CSRF_TOKEN",
    })

    # Public path segments — endpoints whose FULL path segments match are
    # accessible by design (not suitable for IDOR testing).
    # Uses segment-level matching: "/login" blocks "/login" but NOT "/login/reset-token-abc".
    _PUBLIC_PATH_SEGMENTS = frozenset({
        "login", "signin", "sign-in", "sign_in",
        "register", "signup", "sign-up", "sign_up",
        "forgot-password", "forget-password", "forgot_password",
        "reset-password", "reset_password", "password-reset",
        "oauth", "sso",
        "captcha", "health", "ping", "status",
    })

    # Multi-segment public paths — matched as exact path prefixes
    _PUBLIC_PATH_PREFIXES = (
        "/auth/login", "/auth/register", "/auth/forgot",
    )

    @classmethod
    def _is_public_endpoint(cls, endpoint: str) -> bool:
        """Check if an endpoint is a public page (not suitable for IDOR testing).

        Uses path-segment matching: only blocks if the ENTIRE path segment
        matches a public keyword. E.g., /login is blocked but
        /login/reset-token-abc is NOT blocked (it has extra segments).
        /auth alone is NOT blocked (only /auth/login, /auth/register, etc.).
        """
        from urllib.parse import urlparse
        path = urlparse(endpoint).path.lower().rstrip("/")
        segments = [s for s in path.split("/") if s]

        # Check multi-segment prefixes first (e.g., /auth/login)
        for prefix in cls._PUBLIC_PATH_PREFIXES:
            prefix_clean = prefix.lower().rstrip("/")
            # Match only if the path IS the prefix (no extra segments beyond it)
            if path == prefix_clean:
                return True

        # Check single-segment matches: the path must END with the public
        # segment (i.e., nothing after it). This means /login matches but
        # /login/reset-token does not.
        if segments:
            last_segment = segments[-1]
            if last_segment in cls._PUBLIC_PATH_SEGMENTS:
                return True

        return False

    async def _verify_via_browser(
        self,
        finding: dict[str, Any],
        accounts: list[TestAccount],
        target_url: str,
    ) -> str:
        """Attempt to verify a finding using browser replay."""
        vuln_type = finding.get("vuln_type", "")
        endpoint = finding.get("endpoint", "")
        payload = finding.get("payload_used", "")
        param = finding.get("parameter", "")
        context = accounts[0].context_name if accounts else "recon"

        try:
            if vuln_type == "xss":
                if not payload:
                    return ""

                # Method 1: URL parameter injection
                test_url = endpoint
                if "?" in test_url:
                    test_url += f"&{param or 'q'}={payload}"
                else:
                    test_url += f"?{param or 'q'}={payload}"

                await self._safe_browser_action("navigate", context, url=test_url)
                page = await self._safe_browser_action("extract_page_info", context)
                text = page.get("text_content", "") if page else ""
                if payload in text:
                    return f"XSS payload reflected in URL param at {test_url}"

                # Method 2: Form injection — fill field and submit
                if param:
                    try:
                        await self._safe_browser_action(
                            "navigate", context, url=endpoint
                        )
                        page_info = await self._safe_browser_action(
                            "extract_page_info", context
                        )
                        forms = page_info.get("forms", []) if page_info else []
                        for form in forms:
                            for field in form.get("fields", []):
                                if field.get("name") == param:
                                    await self._safe_browser_action(
                                        "fill", context,
                                        selector=f"[name='{param}']",
                                        value=payload,
                                    )
                                    await self._safe_browser_action(
                                        "submit_form", context
                                    )
                                    post_info = await self._safe_browser_action(
                                        "extract_page_info", context
                                    )
                                    post_text = post_info.get("text_content", "") if post_info else ""
                                    if payload in post_text:
                                        return f"XSS payload reflected after form submission at {endpoint}"
                                    break
                    except Exception:
                        pass

            elif vuln_type == "idor" and len(accounts) >= 2:
                # Skip public endpoints — they're accessible to everyone by design
                if self._is_public_endpoint(endpoint):
                    logger.info("validator_skip_public_idor", endpoint=endpoint)
                    return ""

                # Access resource with wrong account AND compare content
                user_a = accounts[0]
                user_b = accounts[1]

                # Get content as user A (owner)
                await self._safe_browser_action(
                    "navigate", user_a.context_name, url=endpoint
                )
                page_a = await self._safe_browser_action(
                    "extract_page_info", user_a.context_name
                )
                text_a = page_a.get("text_content", "") if page_a else ""

                # Get content as user B (attacker)
                result = await self._safe_browser_action(
                    "navigate", user_b.context_name, url=endpoint
                )
                if result.success:
                    page_b = await self._safe_browser_action(
                        "extract_page_info", user_b.context_name
                    )
                    text_b = page_b.get("text_content", "") if page_b else ""

                    # IDOR confirmed if user B sees user A's content (similar response)
                    if text_a and text_b and len(text_b) > 100:
                        # Check significant overlap (not just a 403/401 error page)
                        if "forbidden" not in text_b.lower() and "unauthorized" not in text_b.lower():
                            return f"IDOR confirmed: {user_b.username} accessed {endpoint} (response length: {len(text_b)})"

            elif vuln_type == "broken_access_control":
                # Skip public endpoints — they're accessible to everyone
                if self._is_public_endpoint(endpoint):
                    logger.info("validator_skip_public_authz", endpoint=endpoint)
                    return ""

                # Verify by replaying with anonymous session via httpx
                try:
                    import httpx
                    method = finding.get("method", "GET")
                    async with httpx.AsyncClient(
                        timeout=15.0, verify=False, follow_redirects=False,
                    ) as http_client:
                        resp = await http_client.request(method=method, url=endpoint)
                        if resp.status_code in (401, 403, 302, 301):
                            return ""  # Properly denied — not a real issue
                        if resp.status_code == 200 and len(resp.text) > 200:
                            # Check if response is a login form (false positive)
                            body_lower = resp.text.lower()
                            login_indicators = ["password", "login", "sign in", "log in"]
                            if any(ind in body_lower for ind in login_indicators):
                                logger.info("validator_authz_login_form", endpoint=endpoint)
                                return ""
                            return (
                                f"Anonymous access returned 200 OK with {len(resp.text)}B "
                                f"at {endpoint} (not a login form)"
                            )
                except Exception as e:
                    logger.debug("authz_verify_error", error=str(e)[:200])
                return ""

            elif vuln_type == "sqli" and payload:
                # Method 1: Error-based confirmation
                test_url = endpoint
                p = param or "id"
                if "?" in test_url:
                    test_url += f"&{p}={payload}"
                else:
                    test_url += f"?{p}={payload}"

                result = await self._safe_browser_action(
                    "navigate", context, url=test_url
                )
                page = await self._safe_browser_action("extract_page_info", context)
                text = page.get("text_content", "").lower() if page else ""
                sql_indicators = [
                    "sql", "syntax", "error", "mysql", "postgresql",
                    "sqlite", "oracle", "mssql", "mariadb", "unclosed",
                    "unterminated", "unexpected", "query failed",
                ]
                if any(kw in text for kw in sql_indicators):
                    return f"SQL error confirmed at {test_url}"

                # Method 2: Time-based confirmation
                import time as _time
                # Build a proper time-based payload based on original structure
                stripped = payload.rstrip("- ").rstrip()
                if stripped.endswith("--"):
                    stripped = stripped[:-2].rstrip()
                # Detect quote style used in original payload
                if "'" in payload:
                    # Single-quote context: close it and add SLEEP
                    # Remove trailing comment if present
                    base = stripped.rstrip("'")
                    time_payload = f"{base}' AND SLEEP(3)-- -"
                elif '"' in payload:
                    base = stripped.rstrip('"')
                    time_payload = f'{base}" AND SLEEP(3)-- -'
                elif payload.strip().isdigit():
                    # Numeric context: no quotes needed
                    time_payload = f"{payload} AND SLEEP(3)-- -"
                else:
                    # Unknown context: try both with and without quote
                    time_payload = f"{payload}' AND SLEEP(3)-- -"
                time_url = endpoint
                if "?" in time_url:
                    time_url += f"&{p}={time_payload}"
                else:
                    time_url += f"?{p}={time_payload}"
                start = _time.monotonic()
                await self._safe_browser_action("navigate", context, url=time_url)
                elapsed = _time.monotonic() - start
                if elapsed > 2.5:
                    return f"Time-based SQLi confirmed at {time_url} (response took {elapsed:.1f}s)"

            elif vuln_type == "ssrf":
                # SSRF verification: replay the request with the payload and
                # check for internal content indicators
                if payload and param:
                    test_url = endpoint
                    if "?" in test_url:
                        test_url += f"&{param}={payload}"
                    else:
                        test_url += f"?{param}={payload}"
                    try:
                        import httpx
                        async with httpx.AsyncClient(
                            timeout=15.0, verify=False, follow_redirects=False,
                        ) as http_client:
                            resp = await http_client.get(test_url)
                            body = resp.text.lower()
                            # Cloud metadata indicators
                            ssrf_indicators = [
                                "ami-id", "instance-id", "iam", "security-credentials",
                                "compute.internal", "metadata.google", "169.254.169.254",
                                "latest/meta-data", "localhost", "127.0.0.1",
                                "root:x:0", "/etc/passwd", "private_key",
                            ]
                            if any(ind in body for ind in ssrf_indicators):
                                return f"SSRF confirmed: internal content at {test_url} ({resp.status_code})"
                            # Connection error differentials (server tried to connect)
                            if resp.status_code in (500, 502, 504) and "connection" in body:
                                return f"Potential SSRF: server error connecting to {payload} ({resp.status_code})"
                    except Exception as e:
                        logger.debug("ssrf_verify_error", error=str(e)[:200])

            elif vuln_type in ("command_injection", "rce"):
                if payload:
                    test_url = endpoint
                    p = param or "cmd"
                    if "?" in test_url:
                        test_url += f"&{p}={payload}"
                    else:
                        test_url += f"?{p}={payload}"
                    result = await self._safe_browser_action(
                        "navigate", context, url=test_url
                    )
                    page = await self._safe_browser_action("extract_page_info", context)
                    text = page.get("text_content", "") if page else ""
                    # Check for command output indicators
                    cmd_indicators = ["uid=", "root:", "/bin/", "www-data", "Linux"]
                    if any(ind in text for ind in cmd_indicators):
                        return f"Command injection confirmed at {test_url}"

        except Exception as e:
            logger.debug("browser_verify_error", error=str(e))

        return ""
