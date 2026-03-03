"""Browser controller using Playwright for active web interaction.

Manages multiple isolated browser contexts (one per test account) and provides
methods for navigation, form interaction, screenshot capture, and DOM extraction.
Every action is validated through the ActiveScopeGuard before execution.
"""

from __future__ import annotations

import asyncio
import base64
import time
from typing import Any, Callable

import structlog
from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
)

from ai_brain.active.errors import ActiveScopeViolation, BrowserTimeout
from ai_brain.active.scope_guard import ActiveScopeGuard
from ai_brain.active_schemas import BrowserAction, BrowserActionResult
from ai_brain.config import ActiveTestingConfig

logger = structlog.get_logger()


class BrowserController:
    """Controls a Playwright browser with multiple isolated contexts.

    Each context represents a different user session (e.g., "user1", "admin",
    "unauthenticated"). Contexts have separate cookies, localStorage, and
    session state, enabling multi-account testing for IDOR/privilege escalation.
    """

    def __init__(
        self,
        scope_guard: ActiveScopeGuard,
        config: ActiveTestingConfig,
        kill_switch_checker: Callable[[], bool] | None = None,
    ) -> None:
        self._scope_guard = scope_guard
        self._config = config
        self._kill_check = kill_switch_checker or (lambda: False)
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._contexts: dict[str, BrowserContext] = {}
        self._pages: dict[str, Page] = {}
        self._started = False

    @property
    def is_started(self) -> bool:
        return self._started

    async def start(self) -> None:
        """Launch the browser. Must be called before any interactions."""
        if self._started:
            return

        if self._config.dry_run:
            logger.info("browser_dry_run", msg="Browser start skipped (dry run)")
            self._started = True
            return

        self._playwright = await async_playwright().start()

        launch_args = ["--disable-blink-features=AutomationControlled"]
        proxy_settings = None
        if self._config.proxy_port:
            proxy_settings = {
                "server": f"http://127.0.0.1:{self._config.proxy_port}"
            }

        # If upstream proxy is set, apply it at browser level so ALL contexts use it
        launch_proxy = None
        upstream = getattr(self._config, "upstream_proxy", "")
        if upstream:
            launch_proxy = {"server": upstream}

        self._browser = await self._playwright.chromium.launch(
            headless=self._config.browser_headless,
            args=launch_args,
            proxy=launch_proxy,
        )
        self._started = True
        logger.info(
            "browser_started",
            headless=self._config.browser_headless,
            proxy=proxy_settings,
            upstream_proxy=upstream or None,
        )

    async def stop(self) -> None:
        """Close all contexts and the browser."""
        for name in list(self._pages.keys()):
            try:
                await self._pages[name].close()
            except Exception:
                pass
        self._pages.clear()

        for name in list(self._contexts.keys()):
            try:
                await self._contexts[name].close()
            except Exception:
                pass
        self._contexts.clear()

        if self._browser:
            await self._browser.close()
            self._browser = None

        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

        self._started = False
        logger.info("browser_stopped")

    async def create_context(
        self,
        name: str,
        proxy: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Create an isolated browser context.

        Args:
            name: Context name (e.g., "user1", "admin", "unauthenticated").
            proxy: Optional proxy override for this context.
            user_agent: Optional custom user agent string.
        """
        if self._config.dry_run:
            logger.info("browser_dry_run", action="create_context", name=name)
            return

        if not self._browser:
            raise RuntimeError("Browser not started. Call start() first.")

        if name in self._contexts:
            return  # Already exists

        ctx_options: dict[str, Any] = {
            "ignore_https_errors": True,
            "viewport": {"width": 1280, "height": 720},
        }
        if proxy:
            ctx_options["proxy"] = proxy
        elif self._config.proxy_port:
            ctx_options["proxy"] = {
                "server": f"http://127.0.0.1:{self._config.proxy_port}"
            }
        if user_agent:
            ctx_options["user_agent"] = user_agent

        context = await self._browser.new_context(**ctx_options)
        self._contexts[name] = context

        page = await context.new_page()
        self._pages[name] = page

        logger.info("browser_context_created", name=name)

    def _get_page(self, context_name: str) -> Page:
        """Get the page for a context, raising if not found."""
        if context_name not in self._pages:
            raise ValueError(
                f"Browser context '{context_name}' not found. "
                f"Available: {list(self._pages.keys())}"
            )
        return self._pages[context_name]

    def _check_kill(self) -> None:
        """Check kill switch. Raises if active."""
        from ai_brain.active.errors import KillSwitchTriggered

        if self._kill_check():
            raise KillSwitchTriggered(reason="checked_in_browser")

    async def _delay(self) -> None:
        """Apply configured delay between actions."""
        if self._config.request_delay_ms > 0:
            await asyncio.sleep(self._config.request_delay_ms / 1000.0)

    async def navigate(
        self, context_name: str, url: str, wait_until: str = "networkidle"
    ) -> BrowserActionResult:
        """Navigate to a URL in the specified context.

        Args:
            context_name: Which browser context to use.
            url: URL to navigate to.
            wait_until: Playwright wait strategy (load, domcontentloaded, networkidle).

        Returns:
            BrowserActionResult with page URL, title, and optional screenshot.
        """
        self._check_kill()
        self._scope_guard.validate_url(url)

        if self._config.dry_run:
            logger.info("browser_dry_run", action="navigate", url=url)
            return BrowserActionResult(
                success=True, page_url=url, page_title="[dry run]"
            )

        page = self._get_page(context_name)
        start = time.monotonic()

        try:
            await page.goto(url, wait_until=wait_until, timeout=30000)
            # Extra wait for SPA/JS frameworks to finish rendering
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass
            await self._delay()

            result = BrowserActionResult(
                success=True,
                page_url=page.url,
                page_title=await page.title(),
                duration_ms=int((time.monotonic() - start) * 1000),
            )

            if self._config.screenshot_on_action:
                result.screenshot_b64 = await self._take_screenshot(page)

            return result

        except Exception as e:
            if "timeout" in str(e).lower():
                raise BrowserTimeout("navigate", url=url, timeout_ms=30000) from e
            return BrowserActionResult(
                success=False,
                page_url=url,
                error=str(e),
                duration_ms=int((time.monotonic() - start) * 1000),
            )

    async def click(
        self, context_name: str, selector: str
    ) -> BrowserActionResult:
        """Click an element in the specified context."""
        self._check_kill()

        if self._config.dry_run:
            logger.info("browser_dry_run", action="click", selector=selector)
            return BrowserActionResult(success=True)

        page = self._get_page(context_name)
        start = time.monotonic()

        try:
            await page.click(selector, timeout=10000)
            await page.wait_for_load_state("networkidle", timeout=15000)
            await self._delay()

            return BrowserActionResult(
                success=True,
                page_url=page.url,
                page_title=await page.title(),
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            return BrowserActionResult(
                success=False,
                error=str(e),
                duration_ms=int((time.monotonic() - start) * 1000),
            )

    async def fill(
        self, context_name: str, selector: str, value: str
    ) -> BrowserActionResult:
        """Fill a form field in the specified context."""
        self._check_kill()

        if self._config.dry_run:
            logger.info(
                "browser_dry_run", action="fill", selector=selector, value=value[:50]
            )
            return BrowserActionResult(success=True)

        page = self._get_page(context_name)
        start = time.monotonic()

        try:
            await page.fill(selector, value, timeout=10000)
            await self._delay()

            return BrowserActionResult(
                success=True,
                page_url=page.url,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            return BrowserActionResult(
                success=False,
                error=str(e),
                duration_ms=int((time.monotonic() - start) * 1000),
            )

    async def upload_file(
        self, context_name: str, selector: str, file_path: str
    ) -> BrowserActionResult:
        """Upload a file to a file input element using Playwright's set_input_files().

        Args:
            context_name: Browser context name.
            selector: CSS selector for the input[type=file] element.
            file_path: Path to the file to upload.
        """
        self._check_kill()

        if self._config.dry_run:
            logger.info(
                "browser_dry_run", action="upload_file",
                selector=selector, file=file_path,
            )
            return BrowserActionResult(success=True)

        page = self._get_page(context_name)
        start = time.monotonic()

        try:
            await page.set_input_files(selector, file_path, timeout=10000)
            await self._delay()

            return BrowserActionResult(
                success=True,
                page_url=page.url,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            return BrowserActionResult(
                success=False,
                error=str(e),
                duration_ms=int((time.monotonic() - start) * 1000),
            )

    async def submit_form(
        self, context_name: str, selector: str = "form"
    ) -> BrowserActionResult:
        """Submit a form by pressing Enter or clicking submit button."""
        self._check_kill()

        if self._config.dry_run:
            logger.info("browser_dry_run", action="submit", selector=selector)
            return BrowserActionResult(success=True)

        page = self._get_page(context_name)
        start = time.monotonic()

        try:
            # Try to find and click a submit button first
            submit_btn = page.locator(
                f"{selector} button[type=submit], "
                f"{selector} input[type=submit], "
                f"{selector} button:not([type])"
            )
            if await submit_btn.count() > 0:
                await submit_btn.first.click(timeout=10000)
            else:
                await page.press(selector, "Enter")

            await page.wait_for_load_state("networkidle", timeout=15000)
            await self._delay()

            return BrowserActionResult(
                success=True,
                page_url=page.url,
                page_title=await page.title(),
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            return BrowserActionResult(
                success=False,
                error=str(e),
                duration_ms=int((time.monotonic() - start) * 1000),
            )

    async def extract_page_info(self, context_name: str) -> dict[str, Any]:
        """Extract structured information from the current page.

        Returns a dict with: url, title, forms, links, buttons, text_content,
        meta_tags, and accessibility snapshot.
        """
        self._check_kill()

        if self._config.dry_run:
            return {"url": "", "title": "[dry run]", "forms": [], "links": []}

        page = self._get_page(context_name)

        info: dict[str, Any] = {
            "url": page.url,
            "title": await page.title(),
        }

        # Extract forms
        info["forms"] = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.action,
                method: f.method || 'GET',
                id: f.id,
                fields: Array.from(f.querySelectorAll('input, textarea, select')).map(el => ({
                    name: el.name,
                    type: el.type || 'text',
                    required: el.required,
                    value: el.type === 'password' ? '' : el.value,
                    placeholder: el.placeholder || '',
                    tag: el.tagName.toLowerCase(),
                    visible: el.offsetParent !== null && el.offsetWidth > 0,
                }))
            }));
        }""")

        # Extract links
        info["links"] = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('a[href]'))
                .map(a => ({ href: a.href, text: a.textContent.trim().substring(0, 100) }))
                .filter(l => l.href.startsWith('http'))
                .slice(0, 200);
        }""")

        # Extract buttons
        info["buttons"] = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('button, input[type=button], input[type=submit]'))
                .map(b => ({
                    text: b.textContent?.trim().substring(0, 100) || b.value || '',
                    type: b.type || 'button',
                    id: b.id,
                    name: b.name,
                }))
                .slice(0, 50);
        }""")

        # Extract text content (truncated)
        text = await page.evaluate(
            "() => document.body?.innerText?.substring(0, 5000) || ''"
        )
        info["text_content"] = text

        # Extract meta tags
        info["meta"] = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('meta')).map(m => ({
                name: m.name || m.getAttribute('property') || '',
                content: (m.content || '').substring(0, 200),
            })).filter(m => m.name);
        }""")

        return info

    async def screenshot(self, context_name: str) -> str:
        """Take a screenshot and return as base64 string."""
        self._check_kill()

        if self._config.dry_run:
            return ""

        page = self._get_page(context_name)
        return await self._take_screenshot(page)

    async def screenshot_element(
        self, context_name: str, selector: str
    ) -> str:
        """Screenshot a specific element and return as base64 PNG.

        Useful for capturing CAPTCHA images, specific form fields, etc.

        Args:
            context_name: Browser context name.
            selector: CSS selector for the element to screenshot.

        Returns:
            Base64-encoded PNG string, or empty string on failure.
        """
        self._check_kill()

        if self._config.dry_run:
            return ""

        page = self._get_page(context_name)
        try:
            element = page.locator(selector).first
            if await element.count() == 0:
                return ""
            # Try direct screenshot first (works if element is visible)
            raw = await element.screenshot(type="png", timeout=3000)
            return base64.b64encode(raw).decode("utf-8")
        except Exception as e:
            logger.debug("screenshot_element_failed", selector=selector, error=str(e))
            return ""

    async def wait_for_navigation(
        self, context_name: str, timeout: int = 10000
    ) -> None:
        """Wait for navigation/network activity to settle."""
        if self._config.dry_run:
            return
        page = self._get_page(context_name)
        try:
            await page.wait_for_load_state("networkidle", timeout=timeout)
        except Exception:
            pass

    async def check_element_exists(
        self, context_name: str, selector: str
    ) -> bool:
        """Check if an element exists on the current page."""
        if self._config.dry_run:
            return False
        page = self._get_page(context_name)
        try:
            return await page.locator(selector).count() > 0
        except Exception:
            return False

    async def select_option(
        self, context_name: str, selector: str, value: str
    ) -> BrowserActionResult:
        """Select an option from a dropdown/select element."""
        self._check_kill()

        if self._config.dry_run:
            return BrowserActionResult(success=True)

        page = self._get_page(context_name)
        start = time.monotonic()
        try:
            await page.select_option(selector, value, timeout=10000)
            await self._delay()
            return BrowserActionResult(
                success=True, page_url=page.url,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            return BrowserActionResult(
                success=False, error=str(e),
                duration_ms=int((time.monotonic() - start) * 1000),
            )

    async def check_checkbox(
        self, context_name: str, selector: str
    ) -> BrowserActionResult:
        """Check a checkbox if it's not already checked."""
        self._check_kill()

        if self._config.dry_run:
            return BrowserActionResult(success=True)

        page = self._get_page(context_name)
        start = time.monotonic()
        try:
            await page.locator(selector).first.check(timeout=10000)
            await self._delay()
            return BrowserActionResult(
                success=True, page_url=page.url,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            return BrowserActionResult(
                success=False, error=str(e),
                duration_ms=int((time.monotonic() - start) * 1000),
            )

    async def execute_js(
        self, context_name: str, script: str
    ) -> Any:
        """Execute JavaScript in the page context.

        The script is validated by the scope guard before execution.
        """
        self._check_kill()

        action = BrowserAction(action_type="execute_js", value=script)
        page = self._get_page(context_name)
        self._scope_guard.validate_browser_action(action, page.url)

        if self._config.dry_run:
            logger.info("browser_dry_run", action="execute_js", script=script[:100])
            return None

        return await page.evaluate(script)

    async def get_cookies(self, context_name: str) -> list[dict[str, Any]]:
        """Get all cookies for a browser context."""
        if self._config.dry_run:
            return []

        if context_name not in self._contexts:
            return []
        return await self._contexts[context_name].cookies()

    async def set_cookies(
        self, context_name: str, cookies: list[dict[str, Any]]
    ) -> None:
        """Set cookies on a browser context."""
        if self._config.dry_run:
            return

        if context_name not in self._contexts:
            raise ValueError(f"Context '{context_name}' not found")
        await self._contexts[context_name].add_cookies(cookies)

    async def intercept_requests(
        self,
        context_name: str,
        url_pattern: str,
        handler: Callable,
    ) -> None:
        """Set up request interception on a page.

        Args:
            context_name: Browser context to intercept on.
            url_pattern: URL glob pattern to match (e.g., "**/api/**").
            handler: Async function called with (route, request).
        """
        if self._config.dry_run:
            return

        page = self._get_page(context_name)
        await page.route(url_pattern, handler)

    async def _take_screenshot(self, page: Page) -> str:
        """Take a screenshot and return as base64."""
        try:
            raw = await page.screenshot(type="png", full_page=False)
            return base64.b64encode(raw).decode("utf-8")
        except Exception:
            return ""
