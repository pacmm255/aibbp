"""Universal CAPTCHA solver supporting reCAPTCHA v2/v3, hCaptcha, Turnstile, and image CAPTCHAs.

Uses 2captcha-compatible API (works with 2captcha.com, rucaptcha.com, capsolver.com, anti-captcha via adapter).
Falls back to Claude Vision for simple image CAPTCHAs when no API key is configured.
"""

from __future__ import annotations

import asyncio
import re
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

# Retryable 2captcha errors (temporary capacity/rate issues)
_RETRYABLE_ERRORS = frozenset({
    "ERROR_NO_SLOT_AVAILABLE",
    "ERROR_TOO_MUCH_REQUESTS",
    "MAX_USER_TURN",
})
_MAX_SUBMIT_RETRIES = 3
_SUBMIT_RETRY_DELAY = 10  # seconds

# Image CAPTCHA selectors (shared across detect + solve)
_IMAGE_CAPTCHA_SELECTORS = (
    "img[src*='captcha']", "img.captcha", "#captcha-image",
    "img[alt*='captcha' i]", ".captcha img",
    "img[src*='Captcha']", "img[src*='CAPTCHA']",
)

# Safe JS callback name pattern
_SAFE_CALLBACK_RE = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$.]*$")

# JS helper to safely stringify objects with circular refs / DOM nodes
_SAFE_STRINGIFY_JS = """
const seen = new WeakSet();
const safeStringify = (obj) => {
    try {
        return JSON.stringify(obj, (key, value) => {
            if (typeof value === 'object' && value !== null) {
                if (value instanceof HTMLElement || value instanceof Node) return undefined;
                if (seen.has(value)) return undefined;
                seen.add(value);
            }
            return value;
        });
    } catch { return ''; }
};
"""


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
    is_enterprise: bool = False  # reCAPTCHA Enterprise
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
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self.api_url}/res.php",
                    params={"key": self.api_key, "action": "getbalance", "json": 1},
                )
                data = resp.json()
                if data.get("status") == 1:
                    self._balance_cache = float(data["request"])
                    return self._balance_cache
        except Exception as e:
            logger.debug("captcha_balance_error", error=str(e))
        return 0.0

    async def detect_captcha(self, page: Any) -> CaptchaDetection | None:
        """Detect what type of CAPTCHA is present on the page.

        Detection order: hCaptcha → Turnstile → reCAPTCHA → image
        (hCaptcha and Turnstile have unambiguous selectors; reCAPTCHA is most generic)
        """
        url = page.url

        # Check hCaptcha FIRST (hCaptcha shims window.grecaptcha, so must be before reCAPTCHA)
        hcaptcha_key = await self._detect_hcaptcha(page)
        if hcaptcha_key:
            return CaptchaDetection(
                captcha_type=CaptchaType.HCAPTCHA,
                sitekey=hcaptcha_key,
                page_url=url,
            )

        # Check Cloudflare Turnstile SECOND (uses data-sitekey like reCAPTCHA)
        turnstile_key = await self._detect_turnstile(page)
        if turnstile_key:
            callback = await page.evaluate("""() => {
                const el = document.querySelector('.cf-turnstile[data-callback]');
                return el ? (el.getAttribute('data-callback') || '') : '';
            }""")
            return CaptchaDetection(
                captcha_type=CaptchaType.TURNSTILE,
                sitekey=turnstile_key,
                page_url=url,
                callback_name=callback if _SAFE_CALLBACK_RE.match(callback or "") else "",
            )

        # Check reCAPTCHA v2/v3 (Google) LAST — most generic detection
        sitekey, is_enterprise = await self._detect_recaptcha(page)
        if sitekey:
            # Distinguish v2 vs v3
            # v3 is loaded via script?render=SITEKEY with NO .g-recaptcha element
            has_g_recaptcha_el = await page.locator(".g-recaptcha").count() > 0

            is_v3 = await page.evaluate("""() => {
                try {
                    // v3 is loaded via script src with ?render=SITEKEY (not 'explicit')
                    const scripts = document.querySelectorAll('script[src*="recaptcha"]');
                    for (const s of scripts) {
                        const m = s.src.match(/[?&]render=([^&]+)/);
                        if (m && m[1] !== 'explicit') return true;
                    }
                    // Also check for grecaptcha.execute calls in inline scripts (v3 pattern)
                    for (const s of document.querySelectorAll('script')) {
                        if (s.textContent && s.textContent.match(/grecaptcha\\.(?:enterprise\\.)?execute\\s*\\(/)) {
                            return true;
                        }
                    }
                } catch {}
                return false;
            }""")

            # v3: render-key loaded AND no .g-recaptcha widget element
            # If there IS a .g-recaptcha element, it's v2 (possibly invisible)
            if is_v3 and not has_g_recaptcha_el:
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
                    is_enterprise=is_enterprise,
                )

            # v2 — check invisible variant
            is_invisible = await page.evaluate("""() => {
                // Method 1: data-size attribute
                const el = document.querySelector('.g-recaptcha');
                if (el && el.getAttribute('data-size') === 'invisible') return true;

                // Method 2: grecaptcha badge present (invisible v2 uses badge, not checkbox)
                if (document.querySelectorAll('.grecaptcha-badge').length > 0) return true;

                // Method 3: check ___grecaptcha_cfg for invisible size
                try {
                    if (window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients) {
                        """ + _SAFE_STRINGIFY_JS + """
                        for (const client of Object.values(window.___grecaptcha_cfg.clients)) {
                            try {
                                const str = safeStringify(client);
                                if (str && str.includes('"size":"invisible"')) return true;
                            } catch {}
                        }
                    }
                } catch {}

                return false;
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
                is_enterprise=is_enterprise,
                callback_name=callback if _SAFE_CALLBACK_RE.match(callback or "") else "",
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
            enterprise=detection.is_enterprise,
        )

        # Store detection for callers that need it (e.g. dispatch handler)
        self._last_detection = detection

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
            # Inject token into page (skip for IMAGE — already filled by _solve_image_captcha)
            if detection.captcha_type != CaptchaType.IMAGE:
                injected = await self._inject_token(page, detection, token)
            else:
                injected = True  # Image solver fills the input directly
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

    async def _detect_recaptcha(self, page: Any) -> tuple[str, bool]:
        """Extract reCAPTCHA sitekey and enterprise flag from the page.

        Returns (sitekey, is_enterprise). Empty sitekey means not found.
        """
        result = await page.evaluate("""() => {
            let is_enterprise = false;

            // Check for enterprise script
            const scripts = document.querySelectorAll('script[src*="recaptcha"]');
            for (const s of scripts) {
                if (s.src.includes('/enterprise')) is_enterprise = true;
            }

            // Also check for grecaptcha.enterprise usage
            for (const s of document.querySelectorAll('script')) {
                if (s.textContent && s.textContent.includes('grecaptcha.enterprise')) {
                    is_enterprise = true;
                    break;
                }
            }

            // Method 1: .g-recaptcha element with data-sitekey
            const el = document.querySelector('.g-recaptcha[data-sitekey]');
            if (el) return { sitekey: el.getAttribute('data-sitekey') || '', enterprise: is_enterprise };

            // Method 1b: any [data-sitekey] that is NOT hCaptcha or Turnstile
            const allSitekey = document.querySelectorAll('[data-sitekey]');
            for (const candidate of allSitekey) {
                if (candidate.classList.contains('h-captcha') ||
                    candidate.classList.contains('cf-turnstile')) continue;
                return { sitekey: candidate.getAttribute('data-sitekey') || '', enterprise: is_enterprise };
            }

            // Method 2: grecaptcha config (safe stringify to avoid circular refs)
            try {
                if (window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients) {
                    """ + _SAFE_STRINGIFY_JS + """
                    for (const client of Object.values(window.___grecaptcha_cfg.clients)) {
                        try {
                            const str = safeStringify(client);
                            const m = str ? str.match(/"sitekey"\\s*:\\s*"([^"]+)"/) : null;
                            if (m) return { sitekey: m[1], enterprise: is_enterprise };
                        } catch {}
                    }
                }
            } catch {}

            // Method 3: script src with render=SITEKEY
            for (const s of scripts) {
                const m = s.src.match(/[?&]render=([^&]+)/);
                if (m && m[1] !== 'explicit') return { sitekey: m[1], enterprise: is_enterprise };
            }

            // Method 4: inline script with sitekey
            for (const s of document.querySelectorAll('script')) {
                if (s.textContent) {
                    const m = s.textContent.match(/['"]sitekey['"]\\s*:\\s*['"]([0-9A-Za-z_-]{20,})['"]/) ||
                              s.textContent.match(/grecaptcha\\.(?:enterprise\\.)?execute\\s*\\(\\s*['"]([^'"]+)/);
                    if (m) return { sitekey: m[1], enterprise: is_enterprise };
                }
            }

            return { sitekey: '', enterprise: false };
        }""")
        return (result.get("sitekey", ""), result.get("enterprise", False))

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
        for sel in _IMAGE_CAPTCHA_SELECTORS:
            try:
                loc = page.locator(sel)
                if await loc.count() > 0 and await loc.first.is_visible():
                    return True
            except Exception:
                continue
        return False

    # ── Solving via 2captcha API ─────────────────────────────────

    async def _submit_task(self, params: dict) -> str:
        """Submit a CAPTCHA task to 2captcha and return task ID.

        Retries on temporary capacity/rate-limit errors.
        """
        params["key"] = self.api_key
        params["json"] = 1
        last_error = ""
        for attempt in range(_MAX_SUBMIT_RETRIES):
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(f"{self.api_url}/in.php", data=params)
                data = resp.json()
                if data.get("status") == 1:
                    return data["request"]
                error_code = data.get("request", str(data))
                if error_code in _RETRYABLE_ERRORS and attempt < _MAX_SUBMIT_RETRIES - 1:
                    logger.info("captcha_submit_retry", error=error_code, attempt=attempt + 1)
                    await asyncio.sleep(_SUBMIT_RETRY_DELAY)
                    last_error = error_code
                    continue
                raise RuntimeError(f"2captcha submit failed: {error_code}")
        raise RuntimeError(f"2captcha submit failed after retries: {last_error}")

    async def _poll_result(self, task_id: str) -> str:
        """Poll 2captcha for the solved token."""
        deadline = time.monotonic() + _SOLVE_TIMEOUT
        async with httpx.AsyncClient(timeout=30) as client:
            while time.monotonic() < deadline:
                await asyncio.sleep(_POLL_INTERVAL)
                # Check deadline AFTER sleep to avoid exceeding timeout
                if time.monotonic() >= deadline:
                    break
                resp = await client.get(
                    f"{self.api_url}/res.php",
                    params={"key": self.api_key, "action": "get", "id": task_id, "json": 1},
                )
                data = resp.json()
                if data.get("status") == 1:
                    return data["request"]
                error_code = data.get("request", "")
                # Handle both spellings (2captcha typo + correct spelling)
                if error_code in ("CAPCHA_NOT_READY", "CAPTCHA_NOT_READY"):
                    continue
                raise RuntimeError(f"2captcha solve failed: {error_code or data}")
        raise RuntimeError("2captcha solve timeout")

    async def _solve_recaptcha_v2(self, det: CaptchaDetection) -> str:
        params: dict[str, str] = {
            "method": "userrecaptcha",
            "googlekey": det.sitekey,
            "pageurl": det.page_url,
        }
        if det.is_invisible:
            params["invisible"] = "1"
        if det.is_enterprise:
            params["enterprise"] = "1"
        try:
            task_id = await self._submit_task(params)
            return await self._poll_result(task_id)
        except Exception as e:
            logger.error("recaptcha_v2_error", error=str(e))
            return ""

    async def _solve_recaptcha_v3(self, det: CaptchaDetection) -> str:
        params: dict[str, str] = {
            "method": "userrecaptcha",
            "googlekey": det.sitekey,
            "pageurl": det.page_url,
            "version": "v3",
            "action": det.action or "verify",
            "min_score": "0.3",  # Low threshold — most sites accept 0.3-0.5
        }
        if det.is_enterprise:
            params["enterprise"] = "1"
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

        for sel in _IMAGE_CAPTCHA_SELECTORS:
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
                        # No matching input found — return empty (not "solved")
                        logger.warning("image_captcha_no_input", text=text[:10])
                        return ""
            except Exception as e:
                logger.debug("image_captcha_error", sel=sel, error=str(e))
        return ""

    # ── Token injection ──────────────────────────────────────────

    async def _inject_token(self, page: Any, det: CaptchaDetection, token: str) -> bool:
        """Inject solved token into the page so the form submission works."""
        try:
            if det.captcha_type in (CaptchaType.RECAPTCHA_V2, CaptchaType.RECAPTCHA_V3):
                # Pass callback_name as a safe argument (not interpolated into JS)
                callback_name = det.callback_name if _SAFE_CALLBACK_RE.match(det.callback_name or "") else ""
                await page.evaluate("""([token, cbName]) => {
                    // Set textarea value (standard reCAPTCHA response field)
                    document.querySelectorAll('[name="g-recaptcha-response"]').forEach(el => {
                        el.value = token;
                    });
                    document.querySelectorAll('textarea[id*="g-recaptcha-response"]').forEach(el => {
                        el.value = token;
                    });
                    // Trigger explicit callback if defined
                    if (cbName && typeof window[cbName] === 'function') {
                        window[cbName](token);
                    }
                    // Try grecaptcha internal callbacks
                    try {
                        if (window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients) {
                            const seen = new WeakSet();
                            const safeStringify = (obj) => {
                                try {
                                    return JSON.stringify(obj, (key, value) => {
                                        if (typeof value === 'object' && value !== null) {
                                            if (value instanceof HTMLElement || value instanceof Node) return undefined;
                                            if (seen.has(value)) return undefined;
                                            seen.add(value);
                                        }
                                        return value;
                                    });
                                } catch { return ''; }
                            };
                            for (const client of Object.values(window.___grecaptcha_cfg.clients)) {
                                try {
                                    const str = safeStringify(client);
                                    const m = str ? str.match(/"callback"\\s*:\\s*"([^"]+)"/) : null;
                                    if (m && typeof window[m[1]] === 'function') {
                                        window[m[1]](token);
                                    }
                                } catch {}
                            }
                        }
                    } catch {}
                }""", [token, callback_name])
                return True

            elif det.captcha_type == CaptchaType.HCAPTCHA:
                await page.evaluate("""(token) => {
                    // Set response fields
                    document.querySelectorAll('[name="h-captcha-response"], [name="g-recaptcha-response"]')
                        .forEach(el => { el.value = token; });
                    // Trigger hCaptcha callback via data-callback attribute
                    try {
                        const widget = document.querySelector('.h-captcha[data-callback]');
                        if (widget) {
                            const cbName = widget.getAttribute('data-callback');
                            if (cbName && typeof window[cbName] === 'function') {
                                window[cbName](token);
                            }
                        }
                    } catch {}
                }""", token)
                return True

            elif det.captcha_type == CaptchaType.TURNSTILE:
                # Pass callback_name as safe argument
                callback_name = det.callback_name if _SAFE_CALLBACK_RE.match(det.callback_name or "") else ""
                await page.evaluate("""([token, cbName]) => {
                    // Set response fields
                    document.querySelectorAll('[name="cf-turnstile-response"]')
                        .forEach(el => { el.value = token; });
                    document.querySelectorAll('input[name*="turnstile"]')
                        .forEach(el => { el.value = token; });
                    // Trigger callback via data-callback attribute
                    if (cbName && typeof window[cbName] === 'function') {
                        window[cbName](token);
                    }
                    // Also try widget's data-callback
                    try {
                        const widget = document.querySelector('.cf-turnstile[data-callback]');
                        if (widget) {
                            const wcb = widget.getAttribute('data-callback');
                            if (wcb && wcb !== cbName && typeof window[wcb] === 'function') {
                                window[wcb](token);
                            }
                        }
                    } catch {}
                }""", [token, callback_name])
                return True

        except Exception as e:
            logger.error("captcha_inject_error", type=det.captcha_type.value, error=str(e))

        return False
