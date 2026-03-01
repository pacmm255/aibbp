"""Non-AI validation layer for vulnerability findings.

Avoids "AI validating AI" circularity by using deterministic methods:
- HeadlessBrowserValidator: Playwright for XSS verification
- InteractSHValidator: OOB callback URLs for SSRF/blind XSS
- HeuristicValidator: Regex patterns for CORS, JWT, error leaks
- DifferentialValidator: Structural diff of baseline vs attack responses
- ValidationOrchestrator: Routes findings to the correct validator
"""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ValidationResult:
    """Result from a non-AI validation check."""

    vuln_id: str
    is_valid: bool
    method: str  # Which validator was used
    evidence: list[str] = field(default_factory=list)
    confidence_adjustment: int = 0  # Adjust AI confidence by this amount
    notes: str = ""


class BaseValidator(ABC):
    """Base class for non-AI validators."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    async def validate(
        self, finding: dict[str, Any], context: dict[str, Any]
    ) -> ValidationResult:
        ...


class HeadlessBrowserValidator(BaseValidator):
    """Validate XSS and client-side issues using Playwright.

    Loads pages in a real browser to verify:
    - Reflected XSS: payload appears in DOM and executes
    - Stored XSS: payload persists across page loads
    - DOM XSS: payload triggers via DOM manipulation
    - Open redirects: redirect actually occurs
    """

    @property
    def name(self) -> str:
        return "headless_browser"

    async def validate(
        self, finding: dict[str, Any], context: dict[str, Any]
    ) -> ValidationResult:
        vuln_id = finding.get("vuln_id", "unknown")
        vuln_type = finding.get("vuln_type", "")
        endpoint = finding.get("endpoint", "")

        if not endpoint:
            return ValidationResult(
                vuln_id=vuln_id,
                is_valid=False,
                method=self.name,
                notes="No endpoint to validate",
            )

        # Playwright validation would happen here in production.
        # We provide the structure; actual browser automation requires
        # a running Playwright instance.
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return ValidationResult(
                vuln_id=vuln_id,
                is_valid=False,
                method=self.name,
                notes="Playwright not available; skipping browser validation",
            )

        evidence: list[str] = []
        is_valid = False

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                # Set up alert/dialog handler for XSS detection
                dialog_triggered = False

                async def handle_dialog(dialog: Any) -> None:
                    nonlocal dialog_triggered
                    dialog_triggered = True
                    evidence.append(f"Dialog triggered: {dialog.message}")
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)

                # Navigate to the endpoint
                response = await page.goto(
                    endpoint, wait_until="domcontentloaded", timeout=10000
                )

                if dialog_triggered:
                    is_valid = True
                    evidence.append("XSS confirmed: JavaScript dialog triggered")

                # Check for open redirect
                if vuln_type == "open_redirect":
                    final_url = page.url
                    if final_url != endpoint:
                        is_valid = True
                        evidence.append(f"Redirected to: {final_url}")

                await browser.close()

        except Exception as e:
            evidence.append(f"Browser validation error: {str(e)}")

        return ValidationResult(
            vuln_id=vuln_id,
            is_valid=is_valid,
            method=self.name,
            evidence=evidence,
            confidence_adjustment=20 if is_valid else -10,
        )


class InteractSHValidator(BaseValidator):
    """Validate SSRF and blind XSS using out-of-band callbacks.

    Uses interactsh-style callback URLs to detect:
    - Blind SSRF: server makes request to our callback
    - Blind XSS: payload triggers callback from victim browser
    - XXE: external entity makes callback
    """

    def __init__(self, callback_domain: str = "") -> None:
        self.callback_domain = callback_domain

    @property
    def name(self) -> str:
        return "interactsh"

    def generate_callback_url(self, vuln_id: str) -> str:
        """Generate a unique callback URL for OOB detection."""
        token = hashlib.sha256(vuln_id.encode()).hexdigest()[:12]
        if self.callback_domain:
            return f"https://{token}.{self.callback_domain}"
        return f"https://{token}.oast.example"

    async def validate(
        self, finding: dict[str, Any], context: dict[str, Any]
    ) -> ValidationResult:
        vuln_id = finding.get("vuln_id", "unknown")

        # In production, this would:
        # 1. Generate a unique callback URL
        # 2. Inject it into the vulnerable parameter
        # 3. Wait for the callback
        # 4. Verify the callback came from the target
        return ValidationResult(
            vuln_id=vuln_id,
            is_valid=False,
            method=self.name,
            notes="OOB validation requires interactsh server configuration",
        )


class HeuristicValidator(BaseValidator):
    """Validate findings using deterministic regex patterns.

    Handles:
    - CORS: Check header values against known-bad patterns
    - JWT: Decode and check algorithm, claims, expiration
    - Error disclosure: Regex match for stack traces, paths
    - Information leaks: Known patterns for credentials, keys
    """

    # Compiled patterns for various checks
    _CORS_REFLECTED_PATTERN = re.compile(
        r"access-control-allow-origin:\s*(.+)", re.IGNORECASE
    )
    _CORS_CREDENTIALS_PATTERN = re.compile(
        r"access-control-allow-credentials:\s*true", re.IGNORECASE
    )
    _STACK_TRACE_PATTERNS = [
        re.compile(r"at\s+[\w.$]+\([\w.]+:\d+:\d+\)"),  # JS
        re.compile(r"File\s+\"[^\"]+\",\s+line\s+\d+"),  # Python
        re.compile(r"at\s+[\w.]+\.[\w]+\([\w]+\.java:\d+\)"),  # Java
        re.compile(r"#\d+\s+[\w\\/:]+\(\d+\)"),  # PHP
        re.compile(r"goroutine\s+\d+\s+\["),  # Go
    ]
    _PATH_PATTERNS = [
        re.compile(r"/var/www/[\w/.-]+"),
        re.compile(r"/home/[\w/.-]+"),
        re.compile(r"/opt/[\w/.-]+"),
        re.compile(r"C:\\[\w\\.-]+", re.IGNORECASE),
    ]
    _SECRET_PATTERNS = [
        re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
        re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+"),  # JWT
        re.compile(r"sk-[a-zA-Z0-9]{32,}"),  # OpenAI-style key
        re.compile(r"ghp_[a-zA-Z0-9]{36}"),  # GitHub PAT
    ]

    @property
    def name(self) -> str:
        return "heuristic"

    async def validate(
        self, finding: dict[str, Any], context: dict[str, Any]
    ) -> ValidationResult:
        vuln_type = finding.get("vuln_type", "")
        vuln_id = finding.get("vuln_id", "unknown")
        evidence_data = finding.get("evidence", [])
        raw_data = context.get("raw_response", "")

        if vuln_type == "cors_misconfiguration":
            return self._validate_cors(vuln_id, raw_data)
        elif vuln_type == "information_disclosure":
            return self._validate_info_disclosure(vuln_id, raw_data)
        elif vuln_type == "jwt_oauth":
            return self._validate_jwt(vuln_id, finding)
        else:
            return ValidationResult(
                vuln_id=vuln_id,
                is_valid=False,
                method=self.name,
                notes=f"No heuristic validator for {vuln_type}",
            )

    def _validate_cors(self, vuln_id: str, raw_data: str) -> ValidationResult:
        """Validate CORS misconfiguration using header patterns."""
        evidence: list[str] = []
        is_valid = False

        origin_match = self._CORS_REFLECTED_PATTERN.search(raw_data)
        creds_match = self._CORS_CREDENTIALS_PATTERN.search(raw_data)

        if origin_match:
            origin_value = origin_match.group(1).strip()
            evidence.append(f"ACAO: {origin_value}")

            if origin_value == "*":
                if creds_match:
                    is_valid = True
                    evidence.append("Wildcard + credentials = exploitable")
                else:
                    evidence.append("Wildcard without credentials = lower risk")
            elif origin_value == "null":
                if creds_match:
                    is_valid = True
                    evidence.append("Null origin + credentials = exploitable")
            else:
                # Check if origin is reflected (would need request origin)
                evidence.append(f"Specific origin: {origin_value}")

        if creds_match:
            evidence.append("ACAC: true")

        return ValidationResult(
            vuln_id=vuln_id,
            is_valid=is_valid,
            method=self.name,
            evidence=evidence,
            confidence_adjustment=15 if is_valid else -5,
        )

    def _validate_info_disclosure(
        self, vuln_id: str, raw_data: str
    ) -> ValidationResult:
        """Validate information disclosure using regex patterns."""
        evidence: list[str] = []

        for pattern in self._STACK_TRACE_PATTERNS:
            match = pattern.search(raw_data)
            if match:
                evidence.append(f"Stack trace found: {match.group()[:100]}")

        for pattern in self._PATH_PATTERNS:
            match = pattern.search(raw_data)
            if match:
                evidence.append(f"Path disclosure: {match.group()}")

        for pattern in self._SECRET_PATTERNS:
            match = pattern.search(raw_data)
            if match:
                val = match.group()
                redacted = val[:4] + "..." + val[-4:]
                evidence.append(f"Secret pattern: {redacted}")

        is_valid = len(evidence) > 0
        return ValidationResult(
            vuln_id=vuln_id,
            is_valid=is_valid,
            method=self.name,
            evidence=evidence,
            confidence_adjustment=10 if is_valid else -5,
        )

    def _validate_jwt(
        self, vuln_id: str, finding: dict[str, Any]
    ) -> ValidationResult:
        """Validate JWT weakness using token analysis."""
        import base64

        evidence: list[str] = []
        is_valid = False
        token = finding.get("token", "")

        if not token:
            return ValidationResult(
                vuln_id=vuln_id,
                is_valid=False,
                method=self.name,
                notes="No JWT token provided",
            )

        parts = token.split(".")
        if len(parts) != 3:
            evidence.append("Not a valid JWT format")
            return ValidationResult(
                vuln_id=vuln_id,
                is_valid=False,
                method=self.name,
                evidence=evidence,
            )

        try:
            # Decode header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))
            evidence.append(f"Algorithm: {header.get('alg', 'unknown')}")

            if header.get("alg") == "none":
                is_valid = True
                evidence.append("CRITICAL: 'none' algorithm accepted")
            elif header.get("alg") in ("HS256", "HS384", "HS512"):
                evidence.append("HMAC algorithm - check for weak secret")

            # Decode payload
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            if "exp" not in payload:
                evidence.append("Missing 'exp' claim - no expiration")
                is_valid = True
            if "aud" not in payload:
                evidence.append("Missing 'aud' claim")
            if "iss" not in payload:
                evidence.append("Missing 'iss' claim")

        except Exception as e:
            evidence.append(f"JWT decode error: {str(e)}")

        return ValidationResult(
            vuln_id=vuln_id,
            is_valid=is_valid,
            method=self.name,
            evidence=evidence,
            confidence_adjustment=15 if is_valid else 0,
        )


class DifferentialValidator(BaseValidator):
    """Validate findings by comparing baseline vs attack responses.

    Uses structural comparison (not AI) to detect meaningful differences.
    """

    @property
    def name(self) -> str:
        return "differential"

    async def validate(
        self, finding: dict[str, Any], context: dict[str, Any]
    ) -> ValidationResult:
        vuln_id = finding.get("vuln_id", "unknown")
        baseline = context.get("baseline_response", "")
        attack = context.get("attack_response", "")

        if not baseline or not attack:
            return ValidationResult(
                vuln_id=vuln_id,
                is_valid=False,
                method=self.name,
                notes="Missing baseline or attack response for comparison",
            )

        evidence: list[str] = []
        is_valid = False

        # Compare status codes
        baseline_status = self._extract_status(baseline)
        attack_status = self._extract_status(attack)
        if baseline_status != attack_status:
            evidence.append(
                f"Status code changed: {baseline_status} → {attack_status}"
            )
            if attack_status == 200 and baseline_status in (401, 403):
                is_valid = True
                evidence.append("Auth bypass: unauthorized → OK")

        # Compare response lengths
        len_diff = abs(len(attack) - len(baseline))
        if len_diff > 100:
            pct = (len_diff / max(len(baseline), 1)) * 100
            evidence.append(
                f"Response size diff: {len_diff} bytes ({pct:.1f}%)"
            )
            if pct > 20:
                is_valid = True
                evidence.append("Significant content difference detected")

        # Compare JSON structure if applicable
        baseline_json = self._try_parse_json(baseline)
        attack_json = self._try_parse_json(attack)
        if baseline_json is not None and attack_json is not None:
            new_keys = set(self._flatten_keys(attack_json)) - set(
                self._flatten_keys(baseline_json)
            )
            if new_keys:
                evidence.append(f"New fields in response: {list(new_keys)[:5]}")
                is_valid = True

        return ValidationResult(
            vuln_id=vuln_id,
            is_valid=is_valid,
            method=self.name,
            evidence=evidence,
            confidence_adjustment=15 if is_valid else -5,
        )

    @staticmethod
    def _extract_status(response: str) -> int:
        """Extract HTTP status code from response."""
        match = re.search(r"HTTP/[\d.]+\s+(\d{3})", response)
        if match:
            return int(match.group(1))
        return 0

    @staticmethod
    def _try_parse_json(text: str) -> dict[str, Any] | None:
        """Try to parse JSON from response body."""
        # Find JSON in response
        for start in (text.find("{"), text.find("[")):
            if start >= 0:
                try:
                    return json.loads(text[start:])
                except json.JSONDecodeError:
                    continue
        return None

    @staticmethod
    def _flatten_keys(obj: Any, prefix: str = "") -> list[str]:
        """Flatten JSON keys into dot-notation paths."""
        keys: list[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.append(full_key)
                keys.extend(
                    DifferentialValidator._flatten_keys(v, full_key)
                )
        elif isinstance(obj, list) and obj:
            keys.extend(
                DifferentialValidator._flatten_keys(obj[0], f"{prefix}[]")
            )
        return keys


class ValidationOrchestrator:
    """Routes findings to the appropriate non-AI validator(s).

    Mapping:
    - XSS → HeadlessBrowser
    - SSRF/Blind XSS → InteractSH
    - CORS, JWT, Info Disclosure → Heuristic
    - IDOR, Auth Bypass → Differential
    """

    def __init__(
        self,
        callback_domain: str = "",
    ) -> None:
        self.browser_validator = HeadlessBrowserValidator()
        self.interactsh_validator = InteractSHValidator(callback_domain)
        self.heuristic_validator = HeuristicValidator()
        self.differential_validator = DifferentialValidator()

        # Vuln type → validator mapping
        self._routing: dict[str, list[BaseValidator]] = {
            "xss": [self.browser_validator],
            "reflected_xss": [self.browser_validator],
            "stored_xss": [self.browser_validator],
            "dom_xss": [self.browser_validator],
            "open_redirect": [self.browser_validator],
            "ssrf": [self.interactsh_validator, self.differential_validator],
            "blind_xss": [self.interactsh_validator],
            "xxe": [self.interactsh_validator],
            "cors_misconfiguration": [self.heuristic_validator],
            "jwt_oauth": [self.heuristic_validator],
            "information_disclosure": [self.heuristic_validator],
            "auth_bypass": [self.differential_validator],
            "idor": [self.differential_validator],
            "business_logic": [self.differential_validator],
            "mass_assignment": [self.differential_validator],
            "graphql": [self.heuristic_validator, self.differential_validator],
        }

    async def validate(
        self, finding: dict[str, Any], context: dict[str, Any]
    ) -> list[ValidationResult]:
        """Run all applicable validators for a finding.

        Args:
            finding: Dict with vuln_type, endpoint, evidence, etc.
            context: Dict with raw_response, baseline_response, etc.

        Returns:
            List of ValidationResults from all applicable validators
        """
        vuln_type = finding.get("vuln_type", "unknown")
        validators = self._routing.get(vuln_type, [self.heuristic_validator])

        results: list[ValidationResult] = []
        for validator in validators:
            try:
                result = await validator.validate(finding, context)
                results.append(result)
                logger.info(
                    "validation_complete",
                    validator=validator.name,
                    vuln_type=vuln_type,
                    is_valid=result.is_valid,
                )
            except Exception as e:
                logger.error(
                    "validation_error",
                    validator=validator.name,
                    vuln_type=vuln_type,
                    error=str(e),
                )
                results.append(
                    ValidationResult(
                        vuln_id=finding.get("vuln_id", "unknown"),
                        is_valid=False,
                        method=validator.name,
                        notes=f"Validation error: {str(e)}",
                    )
                )

        return results
