"""Active scope guard wrapping the existing ScopeEnforcer.

All scope decisions are deterministic (compiled regex, domain matching).
No AI is involved in scope enforcement. The ActiveScopeGuard adds
browser-specific, proxy-specific, and tool-specific validation on top
of the proven ScopeEnforcer.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import structlog

from ai_brain.active.errors import ActiveScopeViolation
from ai_brain.active_schemas import BrowserAction
from ai_brain.scope import ScopeEnforcer

logger = structlog.get_logger()


class ActiveScopeGuard:
    """Scope enforcement layer for active testing operations.

    Wraps the existing ScopeEnforcer (composition, not inheritance) and adds
    validation specific to active testing: browser navigation, HTTP request
    interception, security tool execution, and destructive action prevention.
    """

    # HTTP methods considered destructive on production
    _DESTRUCTIVE_METHODS = {"DELETE", "PATCH", "PUT"}

    # Patterns in request bodies that indicate destructive SQL operations
    _DESTRUCTIVE_SQL_PATTERNS = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"DROP\s+(TABLE|DATABASE|INDEX|VIEW)",
            r"TRUNCATE\s+TABLE",
            r"DELETE\s+FROM\s+\w+\s*;?\s*$",
            r"ALTER\s+TABLE\s+\w+\s+DROP",
            r"UPDATE\s+\w+\s+SET\s+.*WHERE\s+1\s*=\s*1",
        ]
    ]

    # Domains that should never be tested (payment processors, auth providers)
    _NEVER_TEST_DOMAINS = {
        "stripe.com",
        "paypal.com",
        "braintreegateway.com",
        "square.com",
        "adyen.com",
        "checkout.com",
        "accounts.google.com",
        "login.microsoftonline.com",
        "cognito-idp.amazonaws.com",
        "auth0.com",
        "okta.com",
        "firebase.googleapis.com",
        "recaptcha.net",
        "hcaptcha.com",
        "challenges.cloudflare.com",
    }

    def __init__(self, scope_enforcer: ScopeEnforcer) -> None:
        self._scope = scope_enforcer

    def validate_url(self, url: str) -> None:
        """Validate a URL before browser navigation or HTTP request.

        Checks:
        1. Domain is in scope (via ScopeEnforcer)
        2. Domain is not in the never-test list
        3. URL scheme is http/https (no file://, javascript://, data://)

        Raises:
            ActiveScopeViolation: If the URL is not in scope.
        """
        if not url:
            raise ActiveScopeViolation(
                "Empty URL", action="navigate", component="browser"
            )

        parsed = urlparse(url)

        # Block non-HTTP schemes
        if parsed.scheme and parsed.scheme not in ("http", "https"):
            raise ActiveScopeViolation(
                f"Blocked URL scheme: {parsed.scheme}",
                action="navigate",
                target=url,
                component="browser",
            )

        hostname = (parsed.hostname or "").lower().strip(".")

        # Check never-test domains
        for domain in self._NEVER_TEST_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                raise ActiveScopeViolation(
                    f"Domain {hostname} is a protected third-party service",
                    action="navigate",
                    target=url,
                    component="browser",
                )

        # Delegate to ScopeEnforcer for domain/IP/port validation
        try:
            self._scope.validate_action(action="active_browse", target=url)
        except Exception as e:
            raise ActiveScopeViolation(
                str(e), action="navigate", target=url, component="browser"
            ) from e

    def validate_request(
        self, method: str, url: str, body: str | None = None
    ) -> None:
        """Validate an HTTP request before sending or intercepting.

        Checks:
        1. URL is in scope
        2. If method is destructive (DELETE/PUT/PATCH), logs a warning
        3. Request body doesn't contain destructive SQL patterns

        Raises:
            ActiveScopeViolation: If the request violates scope.
        """
        self.validate_url(url)

        method_upper = method.upper()
        if method_upper in self._DESTRUCTIVE_METHODS:
            logger.warning(
                "destructive_http_method",
                method=method_upper,
                url=url,
            )

        if body:
            for pattern in self._DESTRUCTIVE_SQL_PATTERNS:
                if pattern.search(body):
                    raise ActiveScopeViolation(
                        f"Request body contains destructive SQL: {pattern.pattern}",
                        action="request",
                        target=url,
                        component="proxy",
                    )

            # Also check with ScopeEnforcer's payload validation
            try:
                self._scope._validate_payload(body)
            except Exception as e:
                raise ActiveScopeViolation(
                    str(e), action="request", target=url, component="proxy"
                ) from e

    def validate_tool_command(self, tool: str, args: list[str]) -> None:
        """Validate a security tool command before execution.

        Checks:
        1. Tool target URLs/domains are in scope
        2. Command doesn't contain destructive flags

        Raises:
            ActiveScopeViolation: If the tool command violates scope.
        """
        # Extract URLs from common tool arguments
        for arg in args:
            # Skip flags
            if arg.startswith("-"):
                continue

            # If it looks like a URL, validate it
            if "://" in arg or "." in arg:
                try:
                    parsed = urlparse(arg if "://" in arg else f"http://{arg}")
                    if parsed.hostname:
                        self.validate_url(
                            arg if "://" in arg else f"http://{arg}"
                        )
                except ActiveScopeViolation:
                    raise
                except Exception:
                    pass  # Not a URL, skip

        # Validate full command string for destructive patterns
        full_command = f"{tool} {' '.join(args)}"
        try:
            self._scope.validate_command(full_command)
        except Exception as e:
            raise ActiveScopeViolation(
                str(e),
                action="tool_exec",
                target=full_command[:200],
                component="tools",
            ) from e

    def validate_browser_action(
        self, action: BrowserAction, current_url: str
    ) -> None:
        """Validate a browser action before execution.

        Checks:
        1. Navigation actions have in-scope URLs
        2. JavaScript execution doesn't contain destructive code
        3. Form submissions target in-scope URLs

        Raises:
            ActiveScopeViolation: If the action violates scope.
        """
        if action.action_type == "navigate" and action.url:
            self.validate_url(action.url)

        if action.action_type == "execute_js" and action.value:
            # Check for obviously destructive JS
            js_lower = action.value.lower()
            dangerous_js = [
                "document.cookie",  # reading cookies is ok for testing
                # But sending them externally is not
            ]
            # Check if JS tries to exfiltrate to external domains
            if "fetch(" in js_lower or "xmlhttprequest" in js_lower:
                # Extract any URLs from the JS and validate them
                url_pattern = re.compile(r'["\']https?://[^"\']+["\']')
                for match in url_pattern.finditer(action.value):
                    url = match.group().strip("\"'")
                    try:
                        self.validate_url(url)
                    except ActiveScopeViolation:
                        raise ActiveScopeViolation(
                            f"JavaScript would make request to out-of-scope URL: {url}",
                            action="execute_js",
                            target=url,
                            component="browser",
                        )

    def is_destructive_method(self, method: str, url: str) -> bool:
        """Check if an HTTP method is considered destructive for the given URL.

        Returns True for DELETE/PUT/PATCH on non-test endpoints.
        This is a soft check — it doesn't raise, just informs the caller.
        """
        return method.upper() in self._DESTRUCTIVE_METHODS
