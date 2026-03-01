"""Authentication agent.

Analyzes auth flows, creates test accounts via browser automation,
handles CAPTCHA solving via Claude Vision, multi-step form wizards,
email verification, and tests session management.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import string
from typing import Any
from urllib.parse import urljoin, urlparse

import structlog

from ai_brain.active.agents.base import BaseActiveAgent
from ai_brain.active_schemas import AuthFlowResult, TestAccount
from ai_brain.prompts.active_auth import (
    ActiveAccountStrategyPrompt,
    ActiveAuthDiscoveryPrompt,
    ActiveAuthFlowAnalysisPrompt,
)

logger = structlog.get_logger()

# Fallback auth paths (used only if AI discovery finds nothing on homepage)
_FALLBACK_AUTH_PATHS = [
    "/login", "/register", "/signup",
    "/auth/login", "/auth/register",
    "/forget-password", "/forgot-password",
    "/panel/login",
]

# Fixed password used for our persistent test account
_FIXED_PASSWORD = "AibbpTest2024!#"

# Common CAPTCHA selectors
_CAPTCHA_IMG_SELECTORS = [
    "img[src*='captcha']",
    "img.captcha",
    ".captcha img",
    "#captcha img",
    "img[id*='captcha']",
    "img[alt*='captcha']",
    "img[src*='Captcha']",
    "img[src*='CAPTCHA']",
]

_CAPTCHA_INPUT_SELECTORS = [
    "input[name*='captcha']",
    "input[name*='Captcha']",
    "input[name*='CAPTCHA']",
    "input[id*='captcha']",
    "input[placeholder*='captcha']",
    "input[placeholder*='Captcha']",
    "input[placeholder*='کد امنیتی']",  # Persian: security code
    "input[placeholder*='کد تصویر']",   # Persian: image code
]


class AuthAgent(BaseActiveAgent):
    """Creates test accounts and analyzes authentication mechanisms."""

    @property
    def agent_type(self) -> str:
        return "auth"

    async def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        target_url = state["target_url"]
        recon = state.get("recon_result")
        accounts: list[TestAccount] = []
        errors: list[str] = []

        # Find auth endpoints from recon
        auth_endpoints = []
        if recon:
            if isinstance(recon, dict):
                auth_endpoints = recon.get("auth_endpoints", [])
            else:
                auth_endpoints = getattr(recon, "auth_endpoints", [])

        # Discover auth endpoints: recon first, then AI-based discovery
        login_url = ""
        register_url = ""
        reset_url = ""

        if auth_endpoints:
            for url in auth_endpoints:
                url_lower = url.lower()
                if any(k in url_lower for k in ("register", "signup", "create")):
                    register_url = url
                elif any(k in url_lower for k in ("login", "signin", "auth")):
                    login_url = url
                elif any(k in url_lower for k in ("reset", "forgot", "forget", "recover", "password")):
                    reset_url = url

        if not login_url or not register_url:
            logger.info("auth_ai_discovery_start", msg="Using AI to discover auth endpoints")
            ai_login, ai_register, ai_reset = await self._discover_auth_endpoints(target_url)
            if not login_url:
                login_url = ai_login
            if not register_url:
                register_url = ai_register
            if not reset_url:
                reset_url = ai_reset

        # Create analysis context and navigate to auth pages
        try:
            await self.browser.create_context("auth_analysis")
        except Exception:
            pass

        login_page_info = {}
        register_page_info = {}

        if login_url:
            try:
                result = await self._safe_browser_action(
                    "navigate", "auth_analysis", url=login_url
                )
                if result.success:
                    login_page_info = await self._safe_browser_action(
                        "extract_page_info", "auth_analysis"
                    )
            except Exception as e:
                logger.debug("auth_login_navigate_error", url=login_url, error=str(e))

        if register_url:
            try:
                result = await self._safe_browser_action(
                    "navigate", "auth_analysis", url=register_url
                )
                if result.success:
                    register_page_info = await self._safe_browser_action(
                        "extract_page_info", "auth_analysis"
                    )
            except Exception as e:
                logger.debug("auth_register_navigate_error", url=register_url, error=str(e))

        # Get auth-related traffic
        auth_traffic = self.proxy.get_traffic(tag_filter="auth", limit=20) if self.proxy.is_running else []
        auth_traffic_json = json.dumps(
            [{"method": t.request.method, "url": t.request.url,
              "status": t.response.status, "content_type": t.request.content_type}
             for t in auth_traffic],
            default=str,
        )[:5000]

        cookies = []
        try:
            cookies = await self.browser.get_cookies("auth_analysis")
        except Exception:
            pass

        # Use Claude to analyze the auth flow
        auth_result: AuthFlowResult = await self._call_claude(
            ActiveAuthFlowAnalysisPrompt(),
            target=target_url,
            login_page=json.dumps(login_page_info, default=str)[:5000],
            register_page=json.dumps(register_page_info, default=str)[:5000],
            auth_traffic=auth_traffic_json,
            cookies=json.dumps(cookies, default=str)[:2000],
        )

        # Override with discovered URLs if Claude didn't find them
        if not auth_result.login_url and login_url:
            auth_result.login_url = login_url
        if not auth_result.registration_url and register_url:
            auth_result.registration_url = register_url
        if not auth_result.password_reset_url and reset_url:
            auth_result.password_reset_url = reset_url

        # ── Single-account, login-first strategy ──
        # Always use hunter255@inbox.lt directly (no plus addressing)
        fixed_email = self._config.imap_user or "hunter255@inbox.lt"
        fixed_password = _FIXED_PASSWORD
        fixed_username = "hunter255"
        ctx_name = "user1"

        try:
            await self.browser.create_context(ctx_name)
        except Exception:
            pass

        credentials = {
            "email": fixed_email,
            "password": fixed_password,
            "username": fixed_username,
            "phone": "09123456789",
            "name": fixed_username,
        }

        # Step 1: Try logging in first (account may already exist)
        logged_in = False
        if login_url:
            logger.info("auth_login_attempt", email=fixed_email, login_url=login_url)
            logged_in = await self._login(
                context_name=ctx_name,
                login_url=login_url,
                credentials=credentials,
            )

        if logged_in:
            logger.info("auth_login_success_existing", email=fixed_email)
            session_cookies = {}
            try:
                raw_cookies = await self.browser.get_cookies(ctx_name)
                session_cookies = {c["name"]: c["value"] for c in raw_cookies}
            except Exception:
                pass
            accounts.append(TestAccount(
                username=fixed_username,
                email=fixed_email,
                password=fixed_password,
                role="user",
                cookies=session_cookies,
                auth_level="basic_user",
                context_name=ctx_name,
            ))

        # Step 2: Login failed — try password reset first (before registration)
        # Skip password reset before registration — it wastes 45s waiting
        # for an email that likely won't arrive (account may not exist yet).
        # Reset is only useful after a confirmed "already exists" + login fail.

        # Step 3: Login and reset failed — try registration
        if not logged_in and register_url:
            logger.info("auth_register_attempt", email=fixed_email)
            try:
                account = await self._create_account(
                    target_url=target_url,
                    context_name=ctx_name,
                    auth_result=auth_result,
                    register_url=register_url,
                    login_url=login_url,
                    reset_url=reset_url,
                )
                if account:
                    accounts.append(account)
                    logged_in = True
            except Exception as e:
                error_msg = f"Account creation failed: {e}"
                logger.warning("account_creation_failed", error=error_msg)
                errors.append(error_msg)

        # Step 4: Create a second account for IDOR testing (different username)
        if accounts and register_url:
            logger.info("auth_second_account_attempt", reason="idor_testing")
            try:
                second_username = "hunter255b"
                second_email_base = self._config.imap_user or "hunter255@inbox.lt"
                # Use plus addressing for second account: hunter255+b@inbox.lt
                local, domain = second_email_base.split("@", 1)
                second_email = f"{local}+b@{domain}"
                second_ctx = "user2"

                try:
                    await self.browser.create_context(second_ctx)
                except Exception:
                    pass

                second_credentials = {
                    "email": second_email,
                    "password": _FIXED_PASSWORD,
                    "username": second_username,
                    "phone": "09" + "".join(
                        secrets.choice(string.digits) for _ in range(9)
                    ),
                    "name": second_username,
                }

                # Try logging in first (account may already exist)
                second_logged_in = False
                if login_url:
                    second_logged_in = await self._login(
                        context_name=second_ctx,
                        login_url=login_url,
                        credentials=second_credentials,
                    )

                if second_logged_in:
                    logger.info("auth_second_login_success", email=second_email)
                    session_cookies = {}
                    try:
                        raw_cookies = await self.browser.get_cookies(second_ctx)
                        session_cookies = {c["name"]: c["value"] for c in raw_cookies}
                    except Exception:
                        pass
                    accounts.append(TestAccount(
                        username=second_username,
                        email=second_email,
                        password=_FIXED_PASSWORD,
                        role="user",
                        cookies=session_cookies,
                        auth_level="basic_user",
                        context_name=second_ctx,
                    ))
                elif register_url:
                    # Register second account with different credentials
                    second_account = await self._create_account_with_credentials(
                        target_url=target_url,
                        context_name=second_ctx,
                        auth_result=auth_result,
                        register_url=register_url,
                        login_url=login_url,
                        reset_url=reset_url,
                        credentials=second_credentials,
                    )
                    if second_account:
                        accounts.append(second_account)
                        logger.info("auth_second_account_created",
                                     username=second_username, email=second_email)
                    else:
                        logger.info("auth_second_account_failed",
                                     email=second_email)
            except Exception as e:
                logger.warning("auth_second_account_error", error=str(e)[:300])

        # Final status check
        if not accounts and not login_url and not register_url:
            errors.append("No auth endpoints found — testing unauthenticated only")
        elif not accounts:
            errors.append("Auth failed: login, reset, and registration all unsuccessful")

        auth_result.accounts_created = accounts

        self._log_step(
            "auth_setup",
            input_data={
                "target_url": target_url,
                "discovered_login": login_url,
                "discovered_register": register_url,
                "discovered_reset": reset_url,
                "auth_endpoints_from_recon": auth_endpoints,
            },
            output_data={
                "accounts_created": len(accounts),
                "login_method": auth_result.login_method,
                "session_mechanism": auth_result.session_mechanism,
            },
        )

        # Test for auth-related vulnerabilities
        auth_findings = await self._test_auth_vulnerabilities(
            target_url=target_url,
            login_url=login_url,
            register_url=register_url,
            accounts=accounts,
        )

        return {
            "accounts": accounts,
            "auth_flow_result": auth_result,
            "errors": errors,
            "raw_findings": auth_findings,
        }

    # ── Auth Endpoint Discovery (AI-based) ─────────────────────────

    async def _discover_auth_endpoints(
        self, target_url: str
    ) -> tuple[str, str, str]:
        """Discover auth endpoints using AI analysis of page content.

        Returns:
            (login_url, register_url, password_reset_url) — empty strings if not found.
        """
        login_url = ""
        register_url = ""
        reset_url = ""
        ctx = "auth_discovery"

        try:
            await self.browser.create_context(ctx)
        except Exception:
            pass

        parsed_target = urlparse(target_url)
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # Strategy 1: Navigate to homepage and ask AI to find auth links
        pages_to_check = [target_url]
        try:
            result = await self._safe_browser_action("navigate", ctx, url=target_url)
            if result.success:
                page_info = await self._safe_browser_action("extract_page_info", ctx)
                ai_result = await self._ai_discover_from_page(
                    page_info, target_url
                )
                login_url = ai_result.get("login_url", "")
                register_url = ai_result.get("register_url", "")
                reset_url = ai_result.get("password_reset_url", "")

                if login_url and register_url:
                    logger.info("auth_discovery_ai",
                                login=login_url, register=register_url,
                                reset=reset_url, source="homepage")
                    return login_url, register_url, reset_url
        except Exception as e:
            logger.debug("auth_discovery_homepage_failed", error=str(e))

        # Strategy 2: Probe a few fallback paths and ask AI on each
        for path in _FALLBACK_AUTH_PATHS:
            if login_url and register_url and reset_url:
                break

            url = urljoin(base_url, path)
            try:
                result = await self._safe_browser_action("navigate", ctx, url=url)
                if not result.success:
                    continue

                page_info = await self._safe_browser_action("extract_page_info", ctx)
                page_url = page_info.get("url", url)

                if "404" in page_info.get("title", "").lower():
                    continue

                # Check if this page has forms (likely auth page)
                forms = page_info.get("forms", [])
                has_password_field = any(
                    f.get("type") == "password"
                    for form in forms
                    for f in form.get("fields", [])
                )

                # Use path-based heuristic to identify this page (fast, free)
                path_lower = path.lower()
                is_reset_path = any(k in path_lower for k in ("reset", "forgot", "forget", "recover"))

                if has_password_field or is_reset_path or forms:
                    if any(k in path_lower for k in ("login", "signin")) and not login_url:
                        login_url = url
                        logger.info("auth_discovery_heuristic", url=url, type="login")
                    elif any(k in path_lower for k in ("register", "signup", "create")) and not register_url:
                        register_url = url
                        logger.info("auth_discovery_heuristic", url=url, type="register")
                    elif is_reset_path and not reset_url:
                        reset_url = url
                        logger.info("auth_discovery_heuristic", url=url, type="reset")

                    # Also ask AI to find links to OTHER auth pages from this page
                    ai_result = await self._ai_discover_from_page(
                        page_info, page_url
                    )
                    if ai_result.get("login_url") and not login_url:
                        login_url = ai_result["login_url"]
                    if ai_result.get("register_url") and not register_url:
                        register_url = ai_result["register_url"]
                    if ai_result.get("password_reset_url") and not reset_url:
                        reset_url = ai_result["password_reset_url"]

            except Exception:
                continue

        if login_url or register_url or reset_url:
            logger.info("auth_discovery_ai",
                        login=login_url, register=register_url,
                        reset=reset_url, source="fallback_probing")
        else:
            logger.info("auth_no_endpoints_found")

        return login_url, register_url, reset_url

    async def _ai_discover_from_page(
        self, page_info: dict[str, Any], page_url: str
    ) -> dict[str, str]:
        """Ask Claude to find auth endpoints from page content.

        Returns dict with login_url, register_url, password_reset_url keys.
        """
        links_json = json.dumps(page_info.get("links", []), default=str)[:4000]
        buttons_json = json.dumps(page_info.get("buttons", []), default=str)[:2000]
        forms_json = json.dumps(page_info.get("forms", []), default=str)[:2000]
        text_snippet = (page_info.get("text_content", "") or "")[:2000]

        try:
            result = await self._call_claude(
                ActiveAuthDiscoveryPrompt(),
                page_url=page_url,
                links=links_json,
                buttons=buttons_json,
                forms=forms_json,
                text_snippet=text_snippet,
            )
            # Result is an AuthDiscoveryResult pydantic model
            # Normalize relative URLs to absolute
            parsed = urlparse(page_url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            def _abs(u: str) -> str:
                u = u.strip()
                if not u:
                    return ""
                if u.startswith("/"):
                    return urljoin(base, u)
                if not u.startswith("http"):
                    return urljoin(base + "/", u)
                return u

            return {
                "login_url": _abs(getattr(result, "login_url", "") or ""),
                "register_url": _abs(getattr(result, "register_url", "") or ""),
                "password_reset_url": _abs(getattr(result, "password_reset_url", "") or ""),
            }
        except Exception as e:
            logger.debug("ai_auth_discovery_failed", error=str(e)[:200])
            return {"login_url": "", "register_url": "", "password_reset_url": ""}

    # ── CAPTCHA Solving ──────────────────────────────────────────────

    async def _solve_captcha(self, context_name: str) -> bool:
        """Find and solve a CAPTCHA on the current page.

        Screenshots the CAPTCHA image, sends to Claude Vision,
        and fills the CAPTCHA input field.

        Returns:
            True if CAPTCHA was found and solved (or no CAPTCHA present).
        """
        # Find CAPTCHA image (must be visible, not just in DOM)
        # Use wait_for_selector first to handle lazy-loaded/Livewire CAPTCHAs
        captcha_img_selector = ""
        page = self.browser._get_page(context_name)

        # First try: use wait_for_selector for the most common pattern
        for selector in _CAPTCHA_IMG_SELECTORS:
            try:
                await page.wait_for_selector(selector, state="visible", timeout=3000)
                captcha_img_selector = selector
                break
            except Exception:
                continue

        # Fallback: check all selectors with retries
        if not captcha_img_selector:
            for attempt in range(3):
                for selector in _CAPTCHA_IMG_SELECTORS:
                    try:
                        locator = page.locator(selector)
                        if await locator.count() > 0 and await locator.first.is_visible():
                            captcha_img_selector = selector
                            break
                    except Exception:
                        continue
                if captcha_img_selector:
                    break
                if attempt < 2:
                    await asyncio.sleep(1)

        if not captcha_img_selector:
            # Last resort: check for any visible img with captcha-like src
            try:
                all_imgs = page.locator("img[src*='/captcha'], img[src*='Captcha'], img[src*='CAPTCHA']")
                if await all_imgs.count() > 0 and await all_imgs.first.is_visible():
                    captcha_img_selector = "img[src*='/captcha'], img[src*='Captcha'], img[src*='CAPTCHA']"
                    logger.debug("captcha_found_by_fallback", context=context_name)
            except Exception:
                pass

        if not captcha_img_selector:
            # CAPTCHA img may exist in DOM but be hidden (e.g., multi-step form
            # where CAPTCHA is on a later step). Check if there's a hidden one.
            has_hidden_captcha = False
            try:
                hidden_captcha = page.locator(
                    "img[src*='captcha'], img[src*='Captcha'], img[src*='CAPTCHA']"
                )
                has_hidden_captcha = await hidden_captcha.count() > 0
            except Exception:
                pass

            if has_hidden_captcha:
                # CAPTCHA exists but is hidden — likely in a later form step.
                # Check if the CAPTCHA input is also hidden.
                captcha_input_hidden = False
                for sel in _CAPTCHA_INPUT_SELECTORS:
                    try:
                        loc = page.locator(sel)
                        if await loc.count() > 0 and not await loc.first.is_visible():
                            captcha_input_hidden = True
                            break
                    except Exception:
                        continue

                if captcha_input_hidden:
                    # Both CAPTCHA image and input are hidden — this is a later
                    # form step. Don't try to solve it now; it will become
                    # visible when the form advances.
                    logger.debug("captcha_hidden_for_later_step", context=context_name)
                    return True  # No CAPTCHA on current step

                # CAPTCHA image is hidden but input is visible (rare case) —
                # try to fetch the image via URL and solve it.
                try:
                    captcha_el = page.locator(
                        "img[src*='captcha'], img[src*='Captcha'], img[src*='CAPTCHA']"
                    ).first
                    captcha_img_selector = "img[src*='captcha'], img[src*='Captcha'], img[src*='CAPTCHA']"
                    logger.info("captcha_hidden_but_input_visible", context=context_name)
                except Exception:
                    return True
            else:
                # No CAPTCHA at all
                logger.debug("captcha_not_found", context=context_name)
                return True  # No CAPTCHA = success

        # Find CAPTCHA input field (visible or force-visible)
        captcha_input_selector = ""
        for selector in _CAPTCHA_INPUT_SELECTORS:
            try:
                locator = page.locator(selector)
                if await locator.count() > 0 and await locator.first.is_visible():
                    captcha_input_selector = selector
                    break
            except Exception:
                continue

        if not captcha_input_selector:
            logger.warning("captcha_input_not_found", context=context_name)
            return False

        # Screenshot the CAPTCHA image
        captcha_b64 = await self._safe_browser_action(
            "screenshot_element", context_name, selector=captcha_img_selector
        )
        captcha_media_type = "image/png"  # screenshot_element returns PNG

        if not captcha_b64:
            # Fallback: fetch the image directly via its URL (works for hidden elements)
            try:
                import base64 as b64mod
                captcha_el = page.locator(captcha_img_selector).first
                src = await captcha_el.get_attribute("src") or ""
                if src:
                    # Make src absolute if needed
                    if src.startswith("/"):
                        origin = await page.evaluate("() => window.location.origin")
                        src = origin + src
                    elif not src.startswith("http"):
                        base_url = await page.evaluate("() => window.location.href")
                        src = base_url.rsplit("/", 1)[0] + "/" + src
                    # Fetch image via page context (preserves cookies/session)
                    resp = await page.context.request.get(src)
                    if resp.ok:
                        raw = await resp.body()
                        captcha_b64 = b64mod.b64encode(raw).decode("utf-8")
                        # Detect media type from response headers or content
                        ct = resp.headers.get("content-type", "")
                        if "jpeg" in ct or "jpg" in ct:
                            captcha_media_type = "image/jpeg"
                        elif "gif" in ct:
                            captcha_media_type = "image/gif"
                        elif "webp" in ct:
                            captcha_media_type = "image/webp"
                        else:
                            captcha_media_type = "image/png"
                        logger.info(
                            "captcha_fetched_via_url",
                            src=src[:80], media_type=captcha_media_type,
                            size=len(raw), context=context_name,
                        )
            except Exception as e:
                logger.debug("captcha_url_fetch_failed", error=str(e))

        if not captcha_b64:
            logger.warning("captcha_screenshot_failed", context=context_name)
            return False

        # Send to Claude Vision for solving
        captcha_text = await self.client.call_vision(
            phase="active_testing",
            image_b64=captcha_b64,
            prompt=(
                "This is a CAPTCHA image. Read the text/numbers shown in the image "
                "and return ONLY the characters you see, nothing else. "
                "No explanation, no quotes, just the exact characters."
            ),
            target="captcha_solve",
            media_type=captcha_media_type,
        )

        if not captcha_text:
            logger.warning("captcha_vision_empty", context=context_name)
            return False

        # Clean up the response — remove ALL whitespace, quotes, etc.
        # Vision sometimes reads "629 676" instead of "629676"
        captcha_text = captcha_text.strip().strip("\"'`").strip()
        captcha_text = captcha_text.replace(" ", "").replace("\t", "").replace("\n", "")

        logger.info("captcha_solved", text=captcha_text, context=context_name)

        # Fill the CAPTCHA input
        try:
            await self._safe_browser_action(
                "fill", context_name,
                selector=captcha_input_selector,
                value=captcha_text,
            )
            return True
        except Exception as e:
            logger.warning("captcha_fill_failed", error=str(e))
            return False

    # ── Form Field Filling ───────────────────────────────────────────

    async def _fill_form_fields(
        self,
        context_name: str,
        fields: list[dict[str, Any]],
        credentials: dict[str, str],
    ) -> None:
        """Intelligently fill form fields based on name/type patterns.

        Only fills fields that are currently visible in the DOM (important
        for multi-step wizard forms where future-step fields don't exist yet).

        Args:
            context_name: Browser context.
            fields: List of field dicts from extract_page_info.
            credentials: Dict with 'email', 'password', 'username',
                         'phone', 'name' keys.
        """
        for field in fields:
            name = field.get("name", "")
            ftype = field.get("type", "text")
            tag = field.get("tag", "input")
            placeholder = field.get("placeholder", "").lower()

            if not name:
                continue

            # Skip non-fillable types
            if ftype in ("hidden", "submit", "button", "image", "reset", "file"):
                continue

            # Skip CAPTCHA fields — handled separately
            if "captcha" in name.lower() or "captcha" in placeholder:
                continue

            # Check if field actually exists and is visible in DOM before trying to fill
            # (critical for multi-step wizard forms where future-step fields are hidden)
            selector = f"[name='{name}']"
            try:
                page = self.browser._get_page(context_name)
                locator = page.locator(selector)
                if await locator.count() == 0:
                    continue
                if not await locator.first.is_visible():
                    continue
            except Exception:
                continue

            name_lower = name.lower()
            value = ""

            # Select dropdowns
            if tag == "select":
                await self._fill_select_field(context_name, name, name_lower, placeholder)
                continue

            # Checkbox fields
            if ftype == "checkbox":
                # Check any terms/agreement/accept checkbox
                if any(kw in name_lower for kw in ("terms", "agree", "accept", "tos", "rules", "قوانین")):
                    try:
                        await self._safe_browser_action(
                            "check_checkbox", context_name,
                            selector=f"input[name='{name}']",
                        )
                    except Exception:
                        pass
                continue

            # Text-like fields
            if "email" in name_lower or ftype == "email" or "ایمیل" in placeholder:
                value = credentials.get("email", "")
            elif "password" in name_lower or ftype == "password" or "رمز" in placeholder:
                value = credentials.get("password", "")
            elif "user" in name_lower or "نام کاربری" in placeholder:
                value = credentials.get("username", "")
            elif "mobile" in name_lower or "phone" in name_lower or "tel" in name_lower or ftype == "tel" or "موبایل" in placeholder or "تلفن" in placeholder:
                value = credentials.get("phone", "09" + "".join(
                    secrets.choice(string.digits) for _ in range(9)
                ))
            elif "name" in name_lower or "نام" in placeholder:
                # First name / display name
                value = credentials.get("name", "Test User")
            elif "first" in name_lower:
                value = "Test"
            elif "last" in name_lower:
                value = "User"

            if value:
                try:
                    await self._safe_browser_action(
                        "fill", context_name,
                        selector=selector,
                        value=value,
                    )
                except Exception:
                    pass

    async def _fill_select_field(
        self,
        context_name: str,
        name: str,
        name_lower: str,
        placeholder: str,
    ) -> None:
        """Fill a select/dropdown field with an appropriate value."""
        # For plan/type/role selects, pick the first non-empty option
        try:
            # Get available options via JS
            options = await self.browser._get_page(context_name).evaluate(
                f"""() => {{
                    const sel = document.querySelector("[name='{name}']");
                    if (!sel) return [];
                    return Array.from(sel.options).map(o => ({{
                        value: o.value, text: o.textContent.trim()
                    }}));
                }}"""
            )
            if options:
                # Pick first non-empty option
                for opt in options:
                    if opt.get("value"):
                        await self._safe_browser_action(
                            "select_option", context_name,
                            selector=f"[name='{name}']",
                            value=opt["value"],
                        )
                        break
        except Exception:
            pass

    # ── Account Creation ─────────────────────────────────────────────

    async def _create_account(
        self,
        target_url: str,
        context_name: str,
        auth_result: AuthFlowResult,
        register_url: str,
        login_url: str,
        reset_url: str = "",
    ) -> TestAccount | None:
        """Create a single test account via browser automation.

        Uses fixed credentials (hunter255@inbox.lt). If account already
        exists, tries login then password reset instead of regenerating.
        Handles multi-step forms, CAPTCHA solving, and email verification.
        """
        try:
            await self.browser.create_context(context_name)
        except Exception:
            pass

        # Use fixed credentials — always hunter255@inbox.lt directly
        email = self._config.imap_user or "hunter255@inbox.lt"
        password = _FIXED_PASSWORD
        username = "hunter255"  # Username matching the email
        phone = "09123456789"

        credentials = {
            "email": email,
            "password": password,
            "username": username,
            "phone": phone,
            "name": username,
        }

        # Navigate to registration page
        if not register_url:
            register_url = auth_result.registration_url or ""
        if not register_url:
            logger.info("auth_no_register_url")
            return None

        result = await self._safe_browser_action(
            "navigate", context_name, url=register_url
        )
        if not result.success:
            logger.warning("auth_register_navigate_failed", url=register_url)
            return None

        # Multi-step form loop (handle wizards up to 5 steps)
        max_steps = 5
        for step in range(max_steps):
            self._check_kill_switch()

            # Wait for page to settle (Livewire/AJAX updates)
            await self._safe_browser_action("wait_for_navigation", context_name, timeout=3000)

            # Extract current form state
            page_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            forms = page_info.get("forms", [])
            if not forms:
                logger.debug("auth_register_no_forms", step=step)
                break

            # Get all fields from all forms (both visible and hidden)
            all_fields = []
            for form in forms:
                all_fields.extend(form.get("fields", []))

            # Count visible fields only (hidden ones are for later steps)
            visible_fields = [f for f in all_fields if f.get("visible", True)
                              and f.get("type") != "hidden"]
            if not visible_fields:
                break

            # Screenshot CAPTCHA BEFORE filling fields (Livewire may hide it)
            captcha_solved = await self._solve_captcha(context_name)
            if not captcha_solved:
                logger.warning("auth_captcha_failed_pre_fill", step=step)

            # Fill fields for this step
            await self._fill_form_fields(context_name, all_fields, credentials)

            # Wait for Livewire/AJAX updates to settle after filling
            await asyncio.sleep(1.5)

            # If CAPTCHA wasn't solved pre-fill, try again post-fill
            if not captcha_solved:
                captcha_solved = await self._solve_captcha(context_name)
                if not captcha_solved:
                    # Try refreshing the CAPTCHA
                    try:
                        await self._safe_browser_action(
                            "click", context_name,
                            selector="img[src*='captcha'], .captcha-refresh, [onclick*='captcha']",
                        )
                        await asyncio.sleep(1)
                        captcha_solved = await self._solve_captcha(context_name)
                    except Exception:
                        pass

            # Find and click the submit/next button
            buttons = page_info.get("buttons", [])
            submitted = await self._click_form_button(context_name, buttons, step)

            if not submitted:
                # Try standard form submit as fallback
                try:
                    await self._safe_browser_action("submit_form", context_name)
                except Exception:
                    pass

            # Wait for response
            await asyncio.sleep(2)
            await self._safe_browser_action("wait_for_navigation", context_name, timeout=5000)

            # Check if we're still on the same page (wizard next step)
            new_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            new_url = new_info.get("url", "")
            new_text = new_info.get("text_content", "").lower()

            # Check for success indicators
            success_keywords = ["success", "welcome", "dashboard", "panel",
                                "verify", "email sent", "موفق", "خوش آمدید", "ایمیل"]
            if any(kw in new_text for kw in success_keywords):
                logger.info("auth_registration_success", step=step)
                break

            # Check for error indicators (registration failed)
            # Note: "قبلا ثبت نام کرده اید" is a static "Already registered?" link
            # — do NOT treat it as an error. Look for actual error messages instead.
            error_keywords = ["error", "invalid", "already exists", "taken", "نامعتبر"]
            # Farsi error patterns (more specific than just "قبلا"):
            farsi_error_patterns = [
                "خطا",                        # "error"
                "قبلا استفاده شده",           # "already used"
                "قبلا ثبت شده",              # "already registered" (as error)
                "این نام کاربری",             # "this username..." (validation)
                "این ایمیل",                  # "this email..." (validation)
                "تکراری",                     # "duplicate"
            ]
            page_errors = [kw for kw in error_keywords if kw in new_text]
            farsi_errors = [kw for kw in farsi_error_patterns if kw in new_text]
            all_errors = page_errors + farsi_errors
            if all_errors:
                logger.warning("auth_registration_error",
                               step=step, errors=all_errors[:3])
                # If "already exists"/"taken", try login then fresh email
                if any(kw in new_text for kw in ("already exists", "taken",
                       "قبلا استفاده شده", "قبلا ثبت شده", "تکراری")):
                    logger.info("auth_account_already_exists", email=email)

                    # Quick attempt: try logging in with our fixed password
                    actual_login = login_url or auth_result.login_url
                    if actual_login:
                        logged_in = await self._login(context_name, actual_login, credentials)
                        if logged_in:
                            logger.info("auth_login_after_exists", email=email)
                            break  # Success — proceed to cookie capture

                    # Account already exists — don't generate new emails.
                    # Just log and break; we'll try login or reset instead.
                    logger.info("auth_account_exists_skip_retry", email=email)
                    errors.append(f"Account {email} already exists, login failed")
                    break

            # Check if new VISIBLE form fields appeared (multi-step wizard)
            new_forms = new_info.get("forms", [])
            new_fields = []
            for form in new_forms:
                new_fields.extend(form.get("fields", []))

            # Compare visible fields only — hidden fields may exist in DOM
            # but become visible when form advances to next step
            old_visible = {f.get("name") for f in all_fields if f.get("visible", True)}
            new_visible = {f.get("name") for f in new_fields if f.get("visible", True)}
            truly_new = new_visible - old_visible

            if not truly_new:
                # No new visible fields → registration probably complete
                logger.info("auth_register_no_new_fields", step=step)
                break

            logger.info("auth_register_next_step",
                        step=step + 1, new_fields=list(truly_new)[:5])

        # Check for email verification
        try:
            email_msg = await self.email_mgr.wait_for_email(
                email, timeout=30, subject_filter="verif"
            )
            verify_link = self.email_mgr.extract_verification_link(
                email_msg.get("body", "")
            )
            if verify_link:
                await self._safe_browser_action(
                    "navigate", context_name, url=verify_link
                )
                logger.info("auth_email_verified", email=email)
        except Exception as e:
            logger.warning("auth_email_verification_failed",
                           email=email, error=str(e)[:200])

        # Try to log in
        logged_in = False
        if login_url or auth_result.login_url:
            actual_login_url = login_url or auth_result.login_url
            logged_in = await self._login(
                context_name=context_name,
                login_url=actual_login_url,
                credentials=credentials,
            )

        # Capture session cookies
        session_cookies = {}
        try:
            cookies = await self.browser.get_cookies(context_name)
            session_cookies = {c["name"]: c["value"] for c in cookies}
        except Exception:
            pass

        auth_level = "basic_user" if (logged_in or session_cookies) else "unauthenticated"

        logger.info("auth_account_created",
                     username=username, email=email,
                     logged_in=logged_in, cookies=len(session_cookies))

        return TestAccount(
            username=username,
            email=email,
            password=password,
            role="user",
            cookies=session_cookies,
            auth_level=auth_level,
            context_name=context_name,
        )

    async def _create_account_with_credentials(
        self,
        target_url: str,
        context_name: str,
        auth_result: AuthFlowResult,
        register_url: str,
        login_url: str,
        reset_url: str = "",
        credentials: dict[str, str] | None = None,
    ) -> TestAccount | None:
        """Create a test account with specific credentials.

        Like _create_account but accepts arbitrary credentials dict
        for creating additional accounts (e.g., for IDOR testing).
        """
        if not credentials:
            return None

        try:
            await self.browser.create_context(context_name)
        except Exception:
            pass

        email = credentials.get("email", "")
        password = credentials.get("password", _FIXED_PASSWORD)
        username = credentials.get("username", "")

        if not register_url:
            register_url = auth_result.registration_url or ""
        if not register_url:
            return None

        result = await self._safe_browser_action(
            "navigate", context_name, url=register_url
        )
        if not result.success:
            return None

        # Multi-step form loop (handle wizards up to 5 steps)
        max_steps = 5
        for step in range(max_steps):
            self._check_kill_switch()

            await self._safe_browser_action("wait_for_navigation", context_name, timeout=3000)

            page_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            forms = page_info.get("forms", [])
            if not forms:
                break

            all_fields = []
            for form in forms:
                all_fields.extend(form.get("fields", []))

            visible_fields = [f for f in all_fields if f.get("visible", True)
                              and f.get("type") != "hidden"]
            if not visible_fields:
                break

            captcha_solved = await self._solve_captcha(context_name)
            await self._fill_form_fields(context_name, all_fields, credentials)
            await asyncio.sleep(1.5)

            if not captcha_solved:
                captcha_solved = await self._solve_captcha(context_name)

            buttons = page_info.get("buttons", [])
            submitted = await self._click_form_button(context_name, buttons, step)
            if not submitted:
                try:
                    await self._safe_browser_action("submit_form", context_name)
                except Exception:
                    pass

            await asyncio.sleep(2)
            await self._safe_browser_action("wait_for_navigation", context_name, timeout=5000)

            new_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            new_text = new_info.get("text_content", "").lower()

            success_keywords = ["success", "welcome", "dashboard", "panel",
                                "verify", "email sent", "موفق", "خوش آمدید", "ایمیل"]
            if any(kw in new_text for kw in success_keywords):
                break

            error_keywords = ["already exists", "taken", "قبلا استفاده شده",
                              "قبلا ثبت شده", "تکراری"]
            if any(kw in new_text for kw in error_keywords):
                # Account exists — try login
                actual_login = login_url or auth_result.login_url
                if actual_login:
                    logged_in = await self._login(context_name, actual_login, credentials)
                    if logged_in:
                        break
                return None

            # Check for new visible fields (multi-step wizard)
            new_forms = new_info.get("forms", [])
            new_fields = []
            for form in new_forms:
                new_fields.extend(form.get("fields", []))
            old_visible = {f.get("name") for f in all_fields if f.get("visible", True)}
            new_visible = {f.get("name") for f in new_fields if f.get("visible", True)}
            if not (new_visible - old_visible):
                break

        # Check for email verification
        try:
            email_msg = await self.email_mgr.wait_for_email(
                email, timeout=30, subject_filter="verif"
            )
            verify_link = self.email_mgr.extract_verification_link(
                email_msg.get("body", "")
            )
            if verify_link:
                await self._safe_browser_action(
                    "navigate", context_name, url=verify_link
                )
        except Exception:
            pass

        # Try to log in
        logged_in = False
        if login_url or auth_result.login_url:
            actual_login_url = login_url or auth_result.login_url
            logged_in = await self._login(
                context_name=context_name,
                login_url=actual_login_url,
                credentials=credentials,
            )

        session_cookies = {}
        try:
            cookies = await self.browser.get_cookies(context_name)
            session_cookies = {c["name"]: c["value"] for c in cookies}
        except Exception:
            pass

        auth_level = "basic_user" if (logged_in or session_cookies) else "unauthenticated"

        return TestAccount(
            username=username,
            email=email,
            password=password,
            role="user",
            cookies=session_cookies,
            auth_level=auth_level,
            context_name=context_name,
        )

    async def _click_form_button(
        self,
        context_name: str,
        buttons: list[dict[str, Any]],
        step: int,
    ) -> bool:
        """Click the appropriate form button (submit/next/register).

        Returns True if a button was successfully clicked.
        """
        # Priority: submit button → register/signup button → next button → any button
        submit_keywords = ["submit", "register", "signup", "sign up", "create",
                           "login", "sign in", "log in", "send", "recover",
                           "ثبت", "ثبت نام", "ادامه", "next", "بعدی",
                           "ورود", "ارسال", "بازیابی"]

        for button in buttons:
            text = button.get("text", "").lower().strip()
            btype = button.get("type", "")
            bid = button.get("id", "")
            bname = button.get("name", "")

            if btype == "submit" or any(kw in text for kw in submit_keywords):
                selector = ""
                if bid:
                    selector = f"#{bid}"
                elif bname:
                    selector = f"button[name='{bname}'], input[name='{bname}']"
                else:
                    # Match by text content
                    selector = f"button:has-text('{button.get('text', '').strip()[:30]}')"

                try:
                    result = await self._safe_browser_action(
                        "click", context_name, selector=selector
                    )
                    if result.success:
                        return True
                except Exception:
                    continue

        # Fallback: click first button that isn't obviously a cancel/back
        cancel_keywords = {"cancel", "back", "reset", "بازگشت", "انصراف", "لغو"}
        for button in buttons:
            text = button.get("text", "").lower().strip()
            if any(kw in text for kw in cancel_keywords):
                continue
            bid = button.get("id", "")
            bname = button.get("name", "")
            selector = ""
            if bid:
                selector = f"#{bid}"
            elif bname:
                selector = f"button[name='{bname}']"
            else:
                continue

            try:
                result = await self._safe_browser_action(
                    "click", context_name, selector=selector
                )
                if result.success:
                    return True
            except Exception:
                continue

        return False

    # ── Login ────────────────────────────────────────────────────────

    async def _login(
        self,
        context_name: str,
        login_url: str,
        credentials: dict[str, str],
    ) -> bool:
        """Log in to the application with the given credentials.

        Handles CAPTCHA on login pages.

        Returns:
            True if login appears successful.
        """
        try:
            result = await self._safe_browser_action(
                "navigate", context_name, url=login_url
            )
            if not result.success:
                return False

            page_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )

            forms = page_info.get("forms", [])
            all_fields = []
            for form in forms:
                all_fields.extend(form.get("fields", []))

            # Fill login fields
            for field in all_fields:
                name = field.get("name", "")
                ftype = field.get("type", "text")
                if not name:
                    continue

                name_lower = name.lower()
                value = ""

                if "captcha" in name_lower:
                    continue  # Handled separately

                if ftype == "hidden":
                    continue

                if "email" in name_lower or ftype == "email":
                    value = credentials.get("email", "")
                elif "password" in name_lower or ftype == "password":
                    value = credentials.get("password", "")
                elif "user" in name_lower:
                    value = credentials.get("username", "")

                if value:
                    try:
                        await self._safe_browser_action(
                            "fill", context_name,
                            selector=f"[name='{name}']",
                            value=value,
                        )
                    except Exception:
                        pass

            # Solve CAPTCHA
            await self._solve_captcha(context_name)

            # Submit login form
            buttons = page_info.get("buttons", [])
            submitted = await self._click_form_button(context_name, buttons, 0)
            if not submitted:
                try:
                    await self._safe_browser_action("submit_form", context_name)
                except Exception:
                    pass

            # Wait for response
            await asyncio.sleep(2)
            await self._safe_browser_action("wait_for_navigation", context_name, timeout=5000)

            # Check if login succeeded
            post_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            post_url = post_info.get("url", "")
            post_text = post_info.get("text_content", "").lower()

            # Login success indicators — check URL path only (not domain)
            post_path = urlparse(post_url).path.lower()

            # Login still on login page = failed (check this FIRST)
            if any(kw in post_path for kw in ("login", "signin", "auth/login")):
                logger.info("auth_login_failed", url=post_url)
                return False

            if any(kw in post_path for kw in ("dashboard", "panel", "home", "account", "profile")):
                logger.info("auth_login_success", url=post_url)
                return True

            if any(kw in post_text for kw in ("dashboard", "logout", "sign out",
                                                "خروج", "پنل", "داشبورد")):
                logger.info("auth_login_success_text", url=post_url)
                return True

            # Check cookies as a signal
            cookies = await self.browser.get_cookies(context_name)
            session_cookies = [c for c in cookies if "session" in c.get("name", "").lower()
                               or "token" in c.get("name", "").lower()
                               or "auth" in c.get("name", "").lower()]
            if session_cookies:
                logger.info("auth_login_success_cookies",
                            cookies=[c["name"] for c in session_cookies])
                return True

            return False

        except Exception as e:
            logger.warning("auth_login_error", error=str(e))
            return False

    # ── Password Reset ─────────────────────────────────────────────

    async def _reset_password(
        self,
        context_name: str,
        reset_url: str,
        email: str,
    ) -> bool:
        """Reset account password via the password reset page.

        Navigates to reset URL, submits email, waits for reset email,
        follows the link, and sets a new password.

        Returns:
            True if password was successfully reset.
        """
        logger.info("auth_password_reset_start", email=email, reset_url=reset_url)

        try:
            # Step 1: Navigate to reset page
            result = await self._safe_browser_action(
                "navigate", context_name, url=reset_url
            )
            if not result.success:
                logger.warning("auth_reset_navigate_failed", url=reset_url)
                return False

            # Step 2: Extract form and fill email
            page_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            forms = page_info.get("forms", [])
            all_fields = []
            for form in forms:
                all_fields.extend(form.get("fields", []))

            # Find and fill email field
            email_filled = False
            for field in all_fields:
                name = field.get("name", "")
                ftype = field.get("type", "text")
                if not name or ftype == "hidden":
                    continue
                name_lower = name.lower()
                if "email" in name_lower or ftype == "email" or "user" in name_lower:
                    try:
                        await self._safe_browser_action(
                            "fill", context_name,
                            selector=f"[name='{name}']",
                            value=email,
                        )
                        email_filled = True
                    except Exception:
                        pass
                    break

            if not email_filled:
                logger.warning("auth_reset_no_email_field")
                return False

            # Step 3: Solve CAPTCHA if present
            await self._solve_captcha(context_name)

            # Step 4: Click submit
            buttons = page_info.get("buttons", [])
            submitted = await self._click_form_button(context_name, buttons, 0)
            if not submitted:
                try:
                    await self._safe_browser_action("submit_form", context_name)
                except Exception:
                    pass

            await asyncio.sleep(3)

            # Check if server showed an error (e.g., email not found)
            post_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            post_text = post_info.get("text_content", "").lower()
            error_indicators = ["not found", "does not exist", "no account", "invalid",
                                "خطا", "نامعتبر", "یافت نشد", "وجود ندارد"]
            if any(kw in post_text for kw in error_indicators):
                logger.warning("auth_reset_email_not_found", email=email)
                return False

            # Step 5: Wait for reset email
            try:
                email_msg = await self.email_mgr.wait_for_email(
                    email, timeout=45, subject_filter="reset|password|recover|بازیابی|رمز"
                )
            except Exception as e:
                logger.warning("auth_reset_email_timeout", error=str(e)[:200])
                return False

            # Step 6: Extract reset link
            reset_link = self.email_mgr.extract_verification_link(
                email_msg.get("body", "")
            )
            if not reset_link:
                logger.warning("auth_reset_no_link_in_email")
                return False

            logger.info("auth_reset_link_found", link=reset_link[:100])

            # Step 7: Navigate to reset link
            result = await self._safe_browser_action(
                "navigate", context_name, url=reset_link
            )
            if not result.success:
                return False

            await asyncio.sleep(2)

            # Step 8: Fill new password
            page_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            forms = page_info.get("forms", [])
            all_fields = []
            for form in forms:
                all_fields.extend(form.get("fields", []))

            password_filled = False
            for field in all_fields:
                name = field.get("name", "")
                ftype = field.get("type", "text")
                if not name or ftype == "hidden":
                    continue
                if ftype == "password" or "password" in name.lower():
                    try:
                        await self._safe_browser_action(
                            "fill", context_name,
                            selector=f"[name='{name}']",
                            value=_FIXED_PASSWORD,
                        )
                        password_filled = True
                    except Exception:
                        pass

            if not password_filled:
                logger.warning("auth_reset_no_password_field")
                return False

            # Step 9: Submit new password
            await self._solve_captcha(context_name)
            buttons = page_info.get("buttons", [])
            submitted = await self._click_form_button(context_name, buttons, 0)
            if not submitted:
                try:
                    await self._safe_browser_action("submit_form", context_name)
                except Exception:
                    pass

            await asyncio.sleep(2)
            await self._safe_browser_action("wait_for_navigation", context_name, timeout=5000)

            # Step 10: Check if reset succeeded
            post_info = await self._safe_browser_action(
                "extract_page_info", context_name
            )
            post_text = (post_info.get("text_content", "") or "").lower()

            success_indicators = ["success", "changed", "updated", "login",
                                  "موفق", "تغییر", "ورود"]
            if any(kw in post_text for kw in success_indicators):
                logger.info("auth_password_reset_success", email=email)
                return True

            # Also check if we got redirected to login page (common after reset)
            post_url = post_info.get("url", "").lower()
            if "login" in post_url:
                logger.info("auth_password_reset_redirected_to_login", email=email)
                return True

            logger.info("auth_password_reset_uncertain", email=email)
            return True  # Optimistic — try logging in anyway

        except Exception as e:
            logger.warning("auth_password_reset_error", error=str(e)[:200])
            return False

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _generate_password() -> str:
        """Generate a strong random password."""
        chars = string.ascii_letters + string.digits + "!@#$%"
        return "".join(secrets.choice(chars) for _ in range(16))

    # ── Auth Vulnerability Testing ────────────────────────────────────

    async def _test_auth_vulnerabilities(
        self,
        target_url: str,
        login_url: str,
        register_url: str,
        accounts: list[TestAccount],
    ) -> list[dict[str, Any]]:
        """Test for auth-related vulnerabilities.

        Tests: account enumeration, CAPTCHA bypass, session cookie flags,
        password reset probing.
        """
        findings: list[dict[str, Any]] = []

        # 1. Account enumeration — different error messages for valid/invalid emails
        if login_url:
            try:
                enum_result = await self._test_account_enumeration(login_url)
                if enum_result:
                    findings.append(enum_result)
            except Exception as e:
                logger.debug("auth_enum_test_error", error=str(e)[:200])

        # 2. CAPTCHA bypass — replay registration POST without CAPTCHA
        if register_url and self.proxy.is_running:
            try:
                captcha_result = await self._test_captcha_bypass(register_url)
                if captcha_result:
                    findings.append(captcha_result)
            except Exception as e:
                logger.debug("auth_captcha_bypass_error", error=str(e)[:200])

        # 3. Session cookie security analysis
        if accounts:
            try:
                cookie_findings = await self._test_session_cookies(accounts[0])
                findings.extend(cookie_findings)
            except Exception as e:
                logger.debug("auth_cookie_test_error", error=str(e)[:200])

        logger.info("auth_vuln_testing_done", findings=len(findings))
        return findings

    async def _test_account_enumeration(self, login_url: str) -> dict[str, Any] | None:
        """Test if login endpoint reveals whether an email/username exists."""
        import httpx

        known_email = f"test_{secrets.token_hex(4)}@example.com"
        unknown_email = f"nonexist_{secrets.token_hex(8)}@example.com"

        # Get the login page to find CSRF token
        try:
            async with httpx.AsyncClient(
                timeout=15.0, verify=False, follow_redirects=True,
            ) as client:
                # Get login page for CSRF
                get_resp = await client.get(login_url)
                csrf_token = ""
                csrf_field = ""
                for field_name in ("_token", "csrf_token", "csrfmiddlewaretoken", "_csrf"):
                    import re as _re
                    match = _re.search(
                        rf'name="{field_name}"\s+value="([^"]+)"', get_resp.text
                    )
                    if match:
                        csrf_token = match.group(1)
                        csrf_field = field_name
                        break

                # Submit with a likely-valid-format email + wrong password
                data1 = {"email": known_email, "password": "WrongPass123!"}
                if csrf_token:
                    data1[csrf_field] = csrf_token

                resp1 = await client.post(login_url, data=data1)

                # Get fresh CSRF for second request
                if csrf_token:
                    get_resp2 = await client.get(login_url)
                    match2 = _re.search(
                        rf'name="{csrf_field}"\s+value="([^"]+)"', get_resp2.text
                    )
                    if match2:
                        csrf_token = match2.group(1)

                # Submit with unknown email
                data2 = {"email": unknown_email, "password": "WrongPass123!"}
                if csrf_token:
                    data2[csrf_field] = csrf_token

                resp2 = await client.post(login_url, data=data2)

                # Compare responses — different = enumeration
                if resp1.text != resp2.text and resp1.status_code == resp2.status_code:
                    # Extract the error messages
                    msg1 = resp1.text[:500]
                    msg2 = resp2.text[:500]
                    if len(msg1) != len(msg2) or msg1 != msg2:
                        return {
                            "vuln_type": "account_enumeration",
                            "endpoint": login_url,
                            "method": "POST",
                            "evidence": (
                                f"Login responds differently for known vs unknown email. "
                                f"Response 1 length: {len(resp1.text)}, "
                                f"Response 2 length: {len(resp2.text)}"
                            ),
                            "tool_used": "manual_http",
                            "confirmed": False,
                        }
        except Exception as e:
            logger.debug("enumeration_test_error", error=str(e)[:200])

        return None

    async def _test_captcha_bypass(self, register_url: str) -> dict[str, Any] | None:
        """Test if CAPTCHA can be bypassed by replaying/removing the field."""
        from ai_brain.active.http_attacker import HTTPRepeater

        # Find a registration POST in captured traffic
        reg_traffic = self.proxy.get_traffic(url_filter=register_url, method_filter="POST", limit=5)
        if not reg_traffic:
            return None

        repeater = HTTPRepeater(self.scope_guard)
        for entry in reg_traffic:
            body = entry.request.body
            if not body:
                continue

            # Try replaying without CAPTCHA field
            from urllib.parse import parse_qs, urlencode
            try:
                params = parse_qs(body, keep_blank_values=True)
            except Exception:
                continue

            captcha_fields = [k for k in params if "captcha" in k.lower()]
            if not captcha_fields:
                continue

            # Remove CAPTCHA field and replay
            modified_params = {k: v[0] if v else "" for k, v in params.items() if k not in captcha_fields}
            modified_body = urlencode(modified_params)

            sig, resp_body = await repeater.send(
                method=entry.request.method,
                url=entry.request.url,
                headers=dict(entry.request.headers),
                body=modified_body,
            )

            # If we get 200 (not redirect to register or error page), CAPTCHA may be bypassed
            if sig.status_code == 200 and not sig.has_error:
                body_lower = resp_body.lower()
                error_indicators = ["captcha", "invalid", "error", "خطا"]
                if not any(ind in body_lower for ind in error_indicators):
                    return {
                        "vuln_type": "captcha_bypass",
                        "endpoint": register_url,
                        "method": "POST",
                        "evidence": (
                            f"Registration POST accepted without CAPTCHA field. "
                            f"Removed fields: {captcha_fields}. Status: {sig.status_code}"
                        ),
                        "tool_used": "http_repeater",
                        "confirmed": False,
                    }

        return None

    async def _test_session_cookies(self, account: TestAccount) -> list[dict[str, Any]]:
        """Check session cookies for missing security flags."""
        findings: list[dict[str, Any]] = []

        if not self.proxy.is_running:
            return findings

        # Check Set-Cookie headers from all traffic
        traffic = self.proxy.get_traffic(limit=100)
        seen_cookies: set[str] = set()

        for entry in traffic:
            for hdr_key, hdr_val in entry.response.headers.items():
                if hdr_key.lower() != "set-cookie":
                    continue

                cookie_name = hdr_val.split("=")[0].strip() if "=" in hdr_val else ""
                if not cookie_name or cookie_name in seen_cookies:
                    continue
                seen_cookies.add(cookie_name)

                # Only check session-like cookies
                session_indicators = ["session", "sess", "token", "auth", "jwt", "sid"]
                if not any(ind in cookie_name.lower() for ind in session_indicators):
                    continue

                val_lower = hdr_val.lower()
                missing: list[str] = []
                if "httponly" not in val_lower:
                    missing.append("HttpOnly")
                if "secure" not in val_lower:
                    missing.append("Secure")
                if "samesite" not in val_lower:
                    missing.append("SameSite")

                if missing:
                    findings.append({
                        "vuln_type": "insecure_cookie",
                        "endpoint": entry.request.url,
                        "method": "GET",
                        "parameter": cookie_name,
                        "evidence": (
                            f"Session cookie `{cookie_name}` missing security flags: "
                            f"{', '.join(missing)}. Full header: {hdr_val[:200]}"
                        ),
                        "tool_used": "traffic_analysis",
                        "confirmed": True,
                    })

        return findings
