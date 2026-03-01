"""Dual rate limiter: target-side RPS + Anthropic API RPM/ITPM."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class TokenBucket:
    """In-memory token bucket rate limiter."""

    rate: float  # tokens per second
    burst: int  # max bucket capacity
    _tokens: float = field(init=False)
    _last_time: float = field(init=False)
    _lock: asyncio.Lock = field(init=False, default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        self._tokens = float(self.burst)
        self._last_time = time.monotonic()

    async def acquire(self) -> None:
        """Wait until a token is available."""
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_time
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                self._last_time = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

                # Calculate wait time for next token
                wait = (1.0 - self._tokens) / self.rate
                await asyncio.sleep(wait)

    def try_acquire(self) -> bool:
        """Try to acquire a token without waiting. Returns True if successful."""
        now = time.monotonic()
        elapsed = now - self._last_time
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_time = now

        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


@dataclass
class DualRateLimiter:
    """Combines target-side RPS limiting with Anthropic API RPM/ITPM limiting.

    - target_rps: Limits requests to the scanning target (2-5 RPS)
    - api_rpm: Limits Anthropic API requests per minute
    - api_itpm: Limits Anthropic API input tokens per minute
    """

    target_rps: float = 3.0
    target_burst: int = 5
    api_rpm: int = 50
    api_itpm: int = 100_000
    _target_bucket: TokenBucket = field(init=False)
    _api_bucket: TokenBucket = field(init=False)
    _token_counter: int = field(init=False, default=0)
    _token_window_start: float = field(init=False)
    _lock: asyncio.Lock = field(init=False, default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        self._target_bucket = TokenBucket(rate=self.target_rps, burst=self.target_burst)
        # API RPM as tokens per second
        self._api_bucket = TokenBucket(
            rate=self.api_rpm / 60.0, burst=min(self.api_rpm, 10)
        )
        self._token_window_start = time.monotonic()

    async def acquire_target(self) -> None:
        """Wait for target-side rate limit."""
        await self._target_bucket.acquire()

    async def acquire_api(self, estimated_tokens: int = 0) -> None:
        """Wait for Anthropic API rate limit."""
        # Check token budget within current minute
        async with self._lock:
            now = time.monotonic()
            if now - self._token_window_start >= 60.0:
                self._token_counter = 0
                self._token_window_start = now

            if self._token_counter + estimated_tokens > self.api_itpm:
                wait = 60.0 - (now - self._token_window_start)
                if wait > 0:
                    await asyncio.sleep(wait)
                self._token_counter = 0
                self._token_window_start = time.monotonic()

            self._token_counter += estimated_tokens

        await self._api_bucket.acquire()

    def record_tokens(self, tokens: int) -> None:
        """Record actual token usage for ITPM tracking."""
        self._token_counter += tokens
