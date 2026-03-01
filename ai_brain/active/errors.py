"""Exception classes for the active testing engine."""

from __future__ import annotations

from ai_brain.errors import BudgetExhausted
from ai_brain.scope import ScopeViolation


class ActiveScopeViolation(ScopeViolation):
    """Raised when an active testing action would violate scope.

    Extends the base ScopeViolation with active-testing-specific context
    such as the browser context name or tool that triggered it.
    """

    def __init__(
        self,
        message: str,
        action: str = "",
        target: str = "",
        component: str = "",
    ):
        self.component = component  # browser, proxy, tool, email
        super().__init__(message, action=action, target=target)


class KillSwitchTriggered(Exception):
    """Raised when the kill switch is active.

    The kill switch is a Redis-backed mechanism that any process can trigger
    to immediately halt all active testing.
    """

    def __init__(self, reason: str = "manual", session_id: str = ""):
        self.reason = reason
        self.session_id = session_id
        super().__init__(f"Kill switch triggered: {reason}")


class BrowserTimeout(Exception):
    """Raised when a Playwright browser operation times out."""

    def __init__(self, action: str, url: str = "", timeout_ms: int = 0):
        self.action = action
        self.url = url
        self.timeout_ms = timeout_ms
        super().__init__(f"Browser timeout on {action} at {url} ({timeout_ms}ms)")


class ToolExecutionError(Exception):
    """Raised when a security tool (sqlmap, dalfox, etc.) fails."""

    def __init__(self, tool: str, message: str, exit_code: int = -1):
        self.tool = tool
        self.exit_code = exit_code
        super().__init__(f"{tool} error (exit {exit_code}): {message}")


class AccountCreationFailed(Exception):
    """Raised when account registration or email verification fails."""

    def __init__(self, message: str, step: str = ""):
        self.step = step  # registration, email_verify, login, etc.
        super().__init__(f"Account creation failed at {step}: {message}")


class ActiveTestBudgetExhausted(BudgetExhausted):
    """Raised when the active testing budget is exhausted."""

    def __init__(self, spent: float, limit: float):
        super().__init__(phase="active_testing", spent=spent, limit=limit)
