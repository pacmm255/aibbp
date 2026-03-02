"""Universal CAPTCHA solver supporting reCAPTCHA v2/v3, hCaptcha, Turnstile, and image CAPTCHAs.

Uses 2captcha-compatible API (works with 2captcha.com, rucaptcha.com, capsolver.com, anti-captcha via adapter).
Falls back to Claude Vision for simple image CAPTCHAs when no API key is configured.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

# Polling interval and timeout for captcha service
_POLL_INTERVAL = 5  # seconds
_SOLVE_TIMEOUT = 120  # seconds


class CaptchaType(Enum):
    RECAPTCHA_V2 = "recaptcha_v2"
    RECAPTCHA_V3 = "recaptcha_v3"
    HCAPTCHA = "hcaptcha"
    TURNSTILE = "turnstile"
    IMAGE = "image"


@dataclass
class CaptchaDetection:
    """Result of detecting a CAPTCHA on a page."""
    captcha_type: CaptchaType
    sitekey: str  # reCAPTCHA/hCaptcha/Turnstile site key
    page_url: str
    action: str = ""  # reCAPTCHA v3 action
    is_invisible: bool = False  # reCAPTCHA v2 invisible
    callback_name: str = ""  # JS callback function name


class CaptchaSolver:
    """Universal CAPTCHA solver using 2captcha-compatible API + Claude Vision fallback."""

    def __init__(
        self,
        api_key: str = "",
        api_url: str = "https://2captcha.com",
        vision_client: Any = None,  # ClaudeClient for image CAPTCHAs
    ):
        self.api_key = api_key
        self.api_url = api_url.rstrip("/")
        self.vision_client = vision_client
        self._balance_cache: float | None = None

    @property
    def has_service(self) -> bool:
        return bool(self.api_key)

    async def get_balance(self) -> float:
        """Check 2captcha account balance."""
        if not self.has_service:
            return 0.0
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{self.api_url}/res.php",
                params={"key": self.api_key, "action": "getbalance", "json": 1},
            )
            data = resp.json()
            if data.get("status") == 1:
                self._balance_cache = float(data["request"])
                return self._balance_cache
        return 0.0

    async def detect_captcha(self, page: Any) -> CaptchaDetection | None:
        """Detect what type of CAPTCHA is present on the page.

        Args:
            page: Playwright Page object.

        Returns:
            CaptchaDetection if found, None otherwise.
        """
        url = page.url

        # Check reCAPTCHA v2/v3 (Google)
        sitekey = await self._detect_recaptcha(page)
        if sitekey:
            # Distinguish v2 vs v3
            is_v3 = await page.evaluate("""() => {
                return !!(window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients &&
                    Object.values(window.___grecaptcha_cfg.clients).some(c =>
                        JSON.stringify(c).includes('"size":"invisible"')
                    ));
            }""")

            # Check for invisible v2 (badge-based)
            has_badge = await page.locator(".grecaptcha-badge").count() > 0
            has_checkbox = await page.locator(".g-recaptcha").count() > 0

            if is_v3 or (has_badge and not has_checkbox):
                action = await page.evaluate("""() => {
                    try {
                        const scripts = document.querySelectorAll('script');
                        for (const s of scripts) {
                            const m = s.textContent.match(/execute\\s*\\([^,]+,\\s*\\{\\s*action:\\s*['"]([^'"]+)/);
                            if (m) return m[1];
                        }
                    } catch {}
                    return 'verify';
                }""")
                return CaptchaDetection(
                    captcha_type=CaptchaType.RECAPTCHA_V3,
                    sitekey=sitekey,
                    page_url=url,
                    action=action,
                )

            # v2 — check invisible variant
            is_invisible = await page.evaluate("""() => {
                const el = document.querySelector('.g-recaptcha');
                return el ? el.getAttribute('data-size') === 'invisible' : false;
            }""")

            callback = await page.evaluate("""() => {
                const el = document.querySelector('.g-recaptcha');
                return el ? (el.getAttribute('data-callback') || '') : '';
            }""")

            return CaptchaDetection(
                captcha_type=CaptchaType.RECAPTCHA_V2,
                sitekey=sitekey,
                page_url=url,
                is_invisible=is_invisible,
                callback_name=callback,
            )

        # Check hCaptcha
        hcaptcha_key = await self._detect_hcaptcha(page)
        if hcaptcha_key:
            return CaptchaDetection(
                captcha_type=CaptchaType.HCAPTCHA,
                sitekey=hcaptcha_key,
                page_url=url,
            )

        # Check Cloudflare Turnstile
        turnstile_key = await self._detect_turnstile(page)
        if turnstile_key:
            return CaptchaDetection(
                captcha_type=CaptchaType.TURNSTILE,
                sitekey=turnstile_key,
                page_url=url,
            )

        # Check image CAPTCHA
        has_image = await self._detect_image_captcha(page)
        if has_image:
            return CaptchaDetection(
                captcha_type=CaptchaType.IMAGE,
                sitekey="",
                page_url=url,
            )

        return None

    async def solve(
        self, page: Any, detection: CaptchaDetection | None = None,
    ) -> str:
        """Detect and solve CAPTCHA on the page. Returns solved token or empty string."""
        if detection is None:
            detection = await self.detect_captcha(page)
        if detection is None:
            return ""

        logger.info(
            "captcha_solve_start",
            type=detection.captcha_type.value,
            sitekey=detection.sitekey[:20] if detection.sitekey else "",
            url=detection.page_url,
        )

        token = ""
        if detection.captcha_type == CaptchaType.IMAGE:
            token = await self._solve_image_captcha(page)
        elif not self.has_service:
            logger.warning(
                "captcha_no_service",
                type=detection.captcha_type.value,
                note="No 2captcha API key — cannot solve reCAPTCHA/hCaptcha/Turnstile",
            )
            return ""
        elif detection.captcha_type == CaptchaType.RECAPTCHA_V2:
            token = await self._solve_recaptcha_v2(detection)
        elif detection.captcha_type == CaptchaType.RECAPTCHA_V3:
            token = await self._solve_recaptcha_v3(detection)
        elif detection.captcha_type == CaptchaType.HCAPTCHA:
            token = await self._solve_hcaptcha(detection)
        elif detection.captcha_type == CaptchaType.TURNSTILE:
            token = await self._solve_turnstile(detection)

        if token:
            # Inject token into page
            injected = await self._inject_token(page, detection, token)
            logger.info(
                "captcha_solved",
                type=detection.captcha_type.value,
                token_length=len(token),
                injected=injected,
            )
        else:
            logger.warning("captcha_solve_failed", type=detection.captcha_type.value)

        return token

    # ── Detection helpers ────────────────────────────────────────

    async def _detect_recaptcha(self, page: Any) -> str:
        """Extract reCAPTCHA sitekey from the page."""
        return await page.evaluate("""() => {
            // Method 1: data-sitekey attribute
            const el = document.querySelector('[data-sitekey]');
            if (el) return el.getAttribute('data-sitekey') || '';

            // Method 2: grecaptcha.enterprise or grecaptcha config
            try {
                if (window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients) {
                    for (const client of Object.values(window.___grecaptcha_cfg.clients)) {
                        const str = JSON.stringify(client);
                        const m = str.match(/"sitekey"\\s*:\\s*"([^"]+)"/);
                        if (m) return m[1];
                    }
                }
            } catch {}

            // Method 3: script src
            const scripts = document.querySelectorAll('script[src*="recaptcha"], script[src*="grecaptcha"]');
            for (const s of scripts) {
                const m = s.src.match(/[?&]render=([^&]+)/);
                if (m && m[1] !== 'explicit') return m[1];
            }

            // Method 4: inline script with sitekey
            for (const s of document.querySelectorAll('script')) {
                if (s.textContent) {
                    const m = s.textContent.match(/['"]sitekey['"]\\s*:\\s*['"]([0-9A-Za-z_-]{20,})['"]/) ||
                              s.textContent.match(/grecaptcha\\.(?:enterprise\\.)?execute\\s*\\(\\s*['"]([^'"]+)/);
                    if (m) return m[1];
                }
            }

            return '';
        }""")

    async def _detect_hcaptcha(self, page: Any) -> str:
        """Extract hCaptcha sitekey from the page."""
        return await page.evaluate("""() => {
            const el = document.querySelector('[data-sitekey].h-captcha, .h-captcha[data-sitekey]');
            if (el) return el.getAttribute('data-sitekey') || '';

            const iframe = document.querySelector('iframe[src*="hcaptcha.com"]');
            if (iframe) {
                const m = iframe.src.match(/sitekey=([^&]+)/);
                if (m) return m[1];
            }

            for (const s of document.querySelectorAll('script')) {
                if (s.textContent) {
                    const m = s.textContent.match(/hcaptcha[^}]*sitekey['"]\\s*:\\s*['"]([^'"]+)/);
                    if (m) return m[1];
                }
            }

            return '';
        }""")

    async def _detect_turnstile(self, page: Any) -> str:
        """Extract Cloudflare Turnstile sitekey from the page."""
        return await page.evaluate("""() => {
            const el = document.querySelector('.cf-turnstile[data-sitekey]');
            if (el) return el.getAttribute('data-sitekey') || '';

            const iframe = document.querySelector('iframe[src*="challenges.cloudflare.com"]');
            if (iframe) {
                const m = iframe.src.match(/sitekey=([^&]+)/);
                if (m) return m[1];
            }

            for (const s of document.querySelectorAll('script')) {
                if (s.textContent) {
                    const m = s.textContent.match(/turnstile[^}]*sitekey['"]\\s*:\\s*['"]([^'"]+)/);
                    if (m) return m[1];
                }
            }

            return '';
        }""")

    async def _detect_image_captcha(self, page: Any) -> bool:
        """Check for image-based CAPTCHA."""
        selectors = [
            "img[src*='captcha']", "img.captcha", "#captcha-image",
            "img[alt*='captcha' i]", ".captcha img",
            "img[src*='Captcha']", "img[src*='CAPTCHA']",
        ]
        for sel in selectors:
            try:
                loc = page.locator(sel)
                if await loc.count() > 0 and await loc.first.is_visible():
                    return True
            except Exception:
                continue
        return False

    # ── Solving via 2captcha API ─────────────────────────────────

    async def _submit_task(self, params: dict) -> str:
        """Submit a CAPTCHA task to 2captcha and return task ID."""
        params["key"] = self.api_key
        params["json"] = 1
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(f"{self.api_url}/in.php", data=params)
            data = resp.json()
            if data.get("status") == 1:
                return data["request"]
            raise RuntimeError(f"2captcha submit failed: {data.get('request', data)}")

    async def _poll_result(self, task_id: str) -> str:
        """Poll 2captcha for the solved token."""
        start = time.monotonic()
        async with httpx.AsyncClient(timeout=30) as client:
            while time.monotonic() - start < _SOLVE_TIMEOUT:
                await asyncio.sleep(_POLL_INTERVAL)
                resp = await client.get(
                    f"{self.api_url}/res.php",
                    params={"key": self.api_key, "action": "get", "id": task_id, "json": 1},
                )
                data = resp.json()
                if data.get("status") == 1:
                    return data["request"]
                if data.get("request") == "CAPCHA_NOT_READY":
                    continue
                raise RuntimeError(f"2captcha solve failed: {data.get('request', data)}")
        raise RuntimeError("2captcha solve timeout")

    async def _solve_recaptcha_v2(self, det: CaptchaDetection) -> str:
        params = {
            "method": "userrecaptcha",
            "googlekey": det.sitekey,
            "pageurl": det.page_url,
        }
        if det.is_invisible:
            params["invisible"] = "1"
        try:
            task_id = await self._submit_task(params)
            return await self._poll_result(task_id)
        except Exception as e:
            logger.error("recaptcha_v2_error", error=str(e))
            return ""

    async def _solve_recaptcha_v3(self, det: CaptchaDetection) -> str:
        params = {
            "method": "userrecaptcha",
            "googlekey": det.sitekey,
            "pageurl": det.page_url,
            "version": "v3",
            "action": det.action or "verify",
            "min_score": "0.9",
        }
        try:
            task_id = await self._submit_task(params)
            return await self._poll_result(task_id)
        except Exception as e:
            logger.error("recaptcha_v3_error", error=str(e))
            return ""

    async def _solve_hcaptcha(self, det: CaptchaDetection) -> str:
        params = {
            "method": "hcaptcha",
            "sitekey": det.sitekey,
            "pageurl": det.page_url,
        }
        try:
            task_id = await self._submit_task(params)
            return await self._poll_result(task_id)
        except Exception as e:
            logger.error("hcaptcha_error", error=str(e))
            return ""

    async def _solve_turnstile(self, det: CaptchaDetection) -> str:
        params = {
            "method": "turnstile",
            "sitekey": det.sitekey,
            "pageurl": det.page_url,
        }
        try:
            task_id = await self._submit_task(params)
            return await self._poll_result(task_id)
        except Exception as e:
            logger.error("turnstile_error", error=str(e))
            return ""

    async def _solve_image_captcha(self, page: Any) -> str:
        """Solve image CAPTCHA using Claude Vision."""
        if not self.vision_client:
            return ""

        selectors = [
            "img[src*='captcha']", "img.captcha", "#captcha-image",
            "img[alt*='captcha' i]", ".captcha img",
            "img[src*='Captcha']", "img[src*='CAPTCHA']",
        ]
        for sel in selectors:
            try:
                loc = page.locator(sel)
                if await loc.count() > 0 and await loc.first.is_visible():
                    b64 = await loc.first.screenshot(type="jpeg")
                    import base64
                    b64_str = base64.b64encode(b64).decode()
                    result = await self.vision_client.call_vision(
                        image_base64=b64_str,
                        prompt=(
                            "This is a CAPTCHA image. Read the text/numbers shown in the image. "
                            "Return ONLY the characters you see, no explanation. "
                            "Remove any spaces between characters."
                        ),
                        media_type="image/jpeg",
                    )
                    text = result.strip().replace(" ", "")
                    if text:
                        # Fill CAPTCHA input
                        for inp_sel in [
                            "input[name*='captcha' i]", "input#captcha",
                            "input[placeholder*='captcha' i]",
                            "input[name*='code' i][type='text']",
                        ]:
                            try:
                                inp = page.locator(inp_sel)
                                if await inp.count() > 0:
                                    await inp.first.fill(text)
                                    return text
                            except Exception:
                                continue
                    return text
            except Exception as e:
                logger.debug("image_captcha_error", sel=sel, error=str(e))
        return ""

    # ── Token injection ──────────────────────────────────────────

    async def _inject_token(self, page: Any, det: CaptchaDetection, token: str) -> bool:
        """Inject solved token into the page so the form submission works."""
        try:
            if det.captcha_type in (CaptchaType.RECAPTCHA_V2, CaptchaType.RECAPTCHA_V3):
                await page.evaluate(f"""(token) => {{
                    // Set textarea (standard reCAPTCHA response field)
                    document.querySelectorAll('[name="g-recaptcha-response"]').forEach(el => {{
                        el.value = token;
                        el.innerHTML = token;
                    }});
                    document.querySelectorAll('textarea[id*="g-recaptcha-response"]').forEach(el => {{
                        el.value = token;
                        el.innerHTML = token;
                    }});
                    // Trigger callback if defined
                    const cb = '{det.callback_name}';
                    if (cb && typeof window[cb] === 'function') {{
                        window[cb](token);
                    }}
                    // Try grecaptcha callback
                    try {{
                        if (window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients) {{
                            for (const client of Object.values(window.___grecaptcha_cfg.clients)) {{
                                const str = JSON.stringify(client);
                                const m = str.match(/"callback"\\s*:\\s*"([^"]+)"/);
                                if (m && typeof window[m[1]] === 'function') {{
                                    window[m[1]](token);
                                }}
                            }}
                        }}
                    }} catch {{}}
                }}""", token)
                return True

            elif det.captcha_type == CaptchaType.HCAPTCHA:
                await page.evaluate("""(token) => {
                    document.querySelectorAll('[name="h-captcha-response"], [name="g-recaptcha-response"]')
                        .forEach(el => { el.value = token; el.innerHTML = token; });
                    // hCaptcha callback
                    try {
                        const iframe = document.querySelector('iframe[src*="hcaptcha"]');
                        if (iframe) {
                            const widgetId = iframe.getAttribute('data-hcaptcha-widget-id');
                            if (widgetId && window.hcaptcha) {
                                // Internal — set response
                            }
                        }
                    } catch {}
                }""", token)
                return True

            elif det.captcha_type == CaptchaType.TURNSTILE:
                await page.evaluate("""(token) => {
                    document.querySelectorAll('[name="cf-turnstile-response"]')
                        .forEach(el => { el.value = token; el.innerHTML = token; });
                    // Also set in any hidden input the turnstile widget created
                    document.querySelectorAll('input[name*="turnstile"]')
                        .forEach(el => { el.value = token; });
                    // Trigger turnstile callback
                    try {
                        if (window.turnstile && window.turnstile._callbacks) {
                            for (const cb of Object.values(window.turnstile._callbacks)) {
                                if (typeof cb === 'function') cb(token);
                            }
                        }
                    } catch {}
                }""", token)
                return True

        except Exception as e:
            logger.error("captcha_inject_error", type=det.captcha_type.value, error=str(e))

        return False
