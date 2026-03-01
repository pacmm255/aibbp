"""Circuit breaker, idempotency tracking, and error handling."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum


class BudgetExhausted(Exception):
    """Raised when the token budget is exhausted."""

    def __init__(self, phase: str, spent: float, limit: float):
        self.phase = phase
        self.spent = spent
        self.limit = limit
        super().__init__(f"Budget exhausted for {phase}: ${spent:.4f} / ${limit:.4f}")


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is open."""

    def __init__(self, failures: int, reset_time: float):
        self.failures = failures
        self.reset_time = reset_time
        super().__init__(
            f"Circuit breaker open after {failures} failures. "
            f"Reset in {reset_time:.0f}s"
        )


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """Circuit breaker for Anthropic API calls.

    States:
    - CLOSED: Normal operation, requests go through
    - OPEN: Too many failures, requests blocked
    - HALF_OPEN: Testing if service recovered
    """

    failure_threshold: int = 5
    recovery_timeout: float = 60.0  # seconds
    half_open_max_calls: int = 1
    _state: CircuitState = field(init=False, default=CircuitState.CLOSED)
    _failure_count: int = field(init=False, default=0)
    _success_count: int = field(init=False, default=0)
    _last_failure_time: float = field(init=False, default=0.0)
    _half_open_calls: int = field(init=False, default=0)

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
        return self._state

    def can_execute(self) -> bool:
        """Check if a request is allowed."""
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            return self._half_open_calls < self.half_open_max_calls
        return False

    def before_call(self) -> None:
        """Called before making an API request.

        Raises:
            CircuitBreakerOpen: If the circuit is open.
        """
        if not self.can_execute():
            remaining = self.recovery_timeout - (
                time.monotonic() - self._last_failure_time
            )
            raise CircuitBreakerOpen(self._failure_count, max(0, remaining))

        if self._state == CircuitState.HALF_OPEN:
            self._half_open_calls += 1

    def record_success(self) -> None:
        """Record a successful API call."""
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.half_open_max_calls:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._success_count = 0
        else:
            self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed API call."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
        elif self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN


@dataclass
class IdempotencyTracker:
    """Tracks completed actions to prevent duplicate work after crash recovery.

    Uses SHA256 of action parameters as the dedup key.
    Action keys are stored in the LangGraph state for persistence.
    """

    completed_keys: set[str] = field(default_factory=set)

    @staticmethod
    def make_key(action: str, target: str, params: str = "") -> str:
        """Generate a deterministic key for an action."""
        raw = f"{action}:{target}:{params}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def is_completed(self, key: str) -> bool:
        """Check if an action has already been completed."""
        return key in self.completed_keys

    def mark_completed(self, key: str) -> None:
        """Mark an action as completed."""
        self.completed_keys.add(key)

    def check_and_mark(self, action: str, target: str, params: str = "") -> bool:
        """Check if action is new; if so, mark it. Returns True if new (should execute)."""
        key = self.make_key(action, target, params)
        if self.is_completed(key):
            return False
        self.mark_completed(key)
        return True
