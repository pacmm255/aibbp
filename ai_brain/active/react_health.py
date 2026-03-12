"""Pre-flight health checks and circuit breakers for tool infrastructure.

Runs before the first brain turn to verify that all infrastructure components
are healthy (SOCKS proxy, mitmproxy, Docker sandbox, scanners, browser).

Circuit breaker wraps tool dispatch: after N consecutive failures, a tool
is disabled and removed from the schema list presented to the brain.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Any

import structlog

logger = structlog.get_logger()

# ── Health Check Status ─────────────────────────────────────────────────

HEALTHY = "healthy"
DEGRADED = "degraded"
UNAVAILABLE = "unavailable"


async def run_preflight_checks(config: dict[str, Any]) -> dict[str, str]:
    """Run pre-flight health checks on all infrastructure components.

    Returns a dict mapping tool/component name to status string:
    "healthy", "degraded", or "unavailable".

    This runs before the first brain turn.
    """
    results: dict[str, str] = {}
    c = config.get("configurable", config)

    # ── 1. SOCKS proxy connectivity ─────────────────────────────
    goja_url = c.get("goja_socks5_url", "")
    if goja_url:
        results["socks_proxy"] = await _check_socks_proxy(goja_url)
    else:
        results["socks_proxy"] = UNAVAILABLE

    # ── 2. mitmproxy is listening ────────────────────────────────
    proxy = c.get("proxy")
    if proxy:
        results["mitmproxy"] = await _check_mitmproxy(proxy)
    else:
        results["mitmproxy"] = UNAVAILABLE

    # ── 3. Docker sandbox responsive ─────────────────────────────
    docker_executor = c.get("docker_executor")
    if docker_executor:
        results["docker_sandbox"] = await _check_docker(docker_executor)
    else:
        results["docker_sandbox"] = UNAVAILABLE

    # ── 4. HexStrike (nuclei/ffuf/gobuster) ──────────────────────
    hexstrike = c.get("hexstrike_client")
    if hexstrike:
        results["hexstrike"] = await _check_hexstrike(hexstrike)
    else:
        results["hexstrike"] = UNAVAILABLE

    # ── 5. Browser launch ────────────────────────────────────────
    browser = c.get("browser")
    if browser:
        results["browser"] = await _check_browser(browser)
    else:
        results["browser"] = UNAVAILABLE

    # ── 6. Tool runner (sqlmap/dalfox/commix/etc.) ───────────────
    tool_runner = c.get("tool_runner")
    if tool_runner:
        results["tool_runner"] = HEALTHY  # Assume healthy if present
    else:
        results["tool_runner"] = UNAVAILABLE

    # ── 7. Email manager ─────────────────────────────────────────
    email_mgr = c.get("email_mgr")
    if email_mgr and getattr(email_mgr, "is_configured", False):
        results["email"] = HEALTHY
    else:
        results["email"] = UNAVAILABLE

    logger.info(
        "preflight_checks_complete",
        results=results,
        healthy=sum(1 for v in results.values() if v == HEALTHY),
        unavailable=sum(1 for v in results.values() if v == UNAVAILABLE),
    )

    return results


async def _check_socks_proxy(socks_url: str) -> str:
    """Check SOCKS5 proxy by connecting to its port."""
    try:
        # Parse socks5://host:port
        parts = socks_url.replace("socks5://", "").replace("socks5h://", "")
        host, port_str = parts.rsplit(":", 1)
        port = int(port_str)

        loop = asyncio.get_running_loop()
        # Test TCP connection to proxy port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            await loop.run_in_executor(None, sock.connect, (host, port))
            return HEALTHY
        finally:
            sock.close()
    except Exception as e:
        logger.warning("socks_proxy_check_failed", error=str(e)[:100])
        return UNAVAILABLE


async def _check_mitmproxy(proxy: Any) -> str:
    """Check mitmproxy by querying its status."""
    try:
        if hasattr(proxy, "is_running") and proxy.is_running:
            return HEALTHY
        # Try to connect to proxy port
        if hasattr(proxy, "port"):
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            try:
                await loop.run_in_executor(
                    None, sock.connect, ("127.0.0.1", proxy.port)
                )
                return HEALTHY
            finally:
                sock.close()
        return UNAVAILABLE
    except Exception as e:
        logger.warning("mitmproxy_check_failed", error=str(e)[:100])
        return UNAVAILABLE


async def _check_docker(executor: Any) -> str:
    """Check Docker by running a trivial command."""
    try:
        if hasattr(executor, "run"):
            result = await asyncio.wait_for(
                executor.run("echo healthcheck", timeout=5),
                timeout=10,
            )
            if result and "healthcheck" in str(result):
                return HEALTHY
            return DEGRADED
        return UNAVAILABLE
    except Exception as e:
        logger.warning("docker_check_failed", error=str(e)[:100])
        return UNAVAILABLE


async def _check_hexstrike(client: Any) -> str:
    """Check HexStrike by pinging its health endpoint."""
    try:
        if hasattr(client, "health_check"):
            result = await asyncio.wait_for(client.health_check(), timeout=5)
            if result:
                return HEALTHY
        # Fallback: check if base_url is reachable
        if hasattr(client, "base_url"):
            import httpx
            async with httpx.AsyncClient(timeout=5) as hc:
                resp = await hc.get(f"{client.base_url}/health")
                if resp.status_code < 500:
                    return HEALTHY
        return UNAVAILABLE
    except Exception as e:
        logger.warning("hexstrike_check_failed", error=str(e)[:100])
        return UNAVAILABLE


async def _check_browser(browser: Any) -> str:
    """Check browser by verifying Playwright is available."""
    try:
        if hasattr(browser, "playwright") and browser.playwright:
            return HEALTHY
        if hasattr(browser, "_browser") and browser._browser:
            return HEALTHY
        # Browser may not be launched yet but is launchable
        if hasattr(browser, "launch"):
            return HEALTHY
        return DEGRADED
    except Exception as e:
        logger.warning("browser_check_failed", error=str(e)[:100])
        return UNAVAILABLE


# ── Circuit Breaker ──────────────────────────────────────────────────────

class ToolCircuitBreaker:
    """Simple circuit breaker for tool dispatch.

    After FAIL_THRESHOLD consecutive failures, a tool is disabled.
    Disabled tools are removed from the schema list presented to the brain.

    The breaker resets after RESET_TIMEOUT_SECONDS, allowing the tool
    to be tried again (half-open state).
    """

    FAIL_THRESHOLD = 3
    RESET_TIMEOUT_SECONDS = 300  # 5 minutes

    def __init__(self) -> None:
        # tool_name -> consecutive failure count
        self._failures: dict[str, int] = {}
        # tool_name -> timestamp when it was disabled
        self._disabled: dict[str, float] = {}

    def record_success(self, tool_name: str) -> None:
        """Record a successful tool execution, resetting failure count."""
        self._failures.pop(tool_name, None)
        self._disabled.pop(tool_name, None)

    def record_failure(self, tool_name: str) -> None:
        """Record a tool failure. Disables tool after FAIL_THRESHOLD."""
        count = self._failures.get(tool_name, 0) + 1
        self._failures[tool_name] = count

        if count >= self.FAIL_THRESHOLD and tool_name not in self._disabled:
            self._disabled[tool_name] = time.monotonic()
            logger.warning(
                "circuit_breaker_open",
                tool=tool_name,
                failures=count,
                msg=f"CIRCUIT OPEN: {tool_name} disabled after {count} failures",
            )

    def is_disabled(self, tool_name: str) -> bool:
        """Check if a tool is currently disabled.

        Returns False if the tool has been disabled long enough to
        try again (half-open state).
        """
        if tool_name not in self._disabled:
            return False

        # Check if reset timeout has elapsed (half-open)
        elapsed = time.monotonic() - self._disabled[tool_name]
        if elapsed >= self.RESET_TIMEOUT_SECONDS:
            # Allow retry (half-open state)
            logger.info(
                "circuit_breaker_half_open",
                tool=tool_name,
                elapsed_s=int(elapsed),
            )
            self._disabled.pop(tool_name, None)
            self._failures[tool_name] = self.FAIL_THRESHOLD - 1  # One more failure re-opens
            return False

        return True

    def get_disabled_tools(self) -> set[str]:
        """Return the set of currently disabled tool names."""
        now = time.monotonic()
        # Clean up expired entries
        expired = [
            name for name, ts in self._disabled.items()
            if now - ts >= self.RESET_TIMEOUT_SECONDS
        ]
        for name in expired:
            self._disabled.pop(name, None)
            self._failures[name] = self.FAIL_THRESHOLD - 1

        return set(self._disabled.keys())

    def get_failure_counts(self) -> dict[str, int]:
        """Return current failure counts for all tracked tools."""
        return dict(self._failures)

    def filter_tool_schemas(
        self, schemas: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Remove disabled tools from the schema list."""
        disabled = self.get_disabled_tools()
        if not disabled:
            return schemas

        filtered = [s for s in schemas if s.get("name") not in disabled]
        removed = len(schemas) - len(filtered)
        if removed > 0:
            logger.info(
                "circuit_breaker_filtered_tools",
                removed=removed,
                disabled=sorted(disabled),
            )
        return filtered


def build_health_prompt_section(
    tool_health: dict[str, str],
    circuit_breaker: ToolCircuitBreaker,
) -> str:
    """Build the tool health section for injection into the dynamic prompt.

    Shows component health status and circuit breaker state.
    """
    if not tool_health and not circuit_breaker.get_failure_counts():
        return ""

    lines = ["### TOOL STATUS"]

    # Health check results
    if tool_health:
        health_parts = []
        for name, status in sorted(tool_health.items()):
            if status == HEALTHY:
                health_parts.append(f"{name}=OK")
            elif status == DEGRADED:
                health_parts.append(f"{name}=DEGRADED")
            else:
                health_parts.append(f"{name}=UNAVAILABLE")
        lines.append(f"  Infrastructure: {', '.join(health_parts)}")

    # Circuit breaker state
    disabled = circuit_breaker.get_disabled_tools()
    failures = circuit_breaker.get_failure_counts()
    degraded = {
        name: count for name, count in failures.items()
        if count > 0 and name not in disabled
    }

    if disabled:
        lines.append(
            f"  DISABLED tools (circuit open): {', '.join(sorted(disabled))}"
        )
        lines.append(
            "  >> These tools have failed repeatedly. Use alternatives."
        )

    if degraded:
        parts = [f"{name}({count} failures)" for name, count in sorted(degraded.items())]
        lines.append(f"  Degraded: {', '.join(parts)}")

    # Guidance for unavailable components
    unavailable = [
        name for name, status in tool_health.items()
        if status == UNAVAILABLE
    ]
    if unavailable:
        lines.append(
            f"  >> Unavailable: {', '.join(unavailable)}. "
            "Adapt your strategy to use working tools."
        )

    return "\n".join(lines)
