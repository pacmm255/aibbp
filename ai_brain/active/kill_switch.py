"""Redis-backed global kill switch for active testing.

Any process can trigger the kill switch (CLI, web UI, monitoring).
Checked before every single browser action, tool execution, and graph node.
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger()


class KillSwitch:
    """Redis-backed kill switch for active testing sessions.

    Keys:
    - ``aibbp:kill_switch:global`` — stops ALL active testing
    - ``aibbp:kill_switch:{session_id}`` — stops a specific session
    """

    def __init__(self, redis_client: Any | None = None) -> None:
        self._redis = redis_client

    async def is_active(self, session_id: str | None = None) -> bool:
        """Check if the kill switch has been triggered.

        Args:
            session_id: Optional session to check in addition to global.

        Returns:
            True if kill switch is active (testing should stop).
        """
        if self._redis is None:
            return False

        try:
            # Check global kill switch
            global_val = await self._async_get("aibbp:kill_switch:global")
            if global_val:
                logger.warning("kill_switch_active", scope="global", reason=global_val)
                return True

            # Check session-specific kill switch
            if session_id:
                session_val = await self._async_get(
                    f"aibbp:kill_switch:{session_id}"
                )
                if session_val:
                    logger.warning(
                        "kill_switch_active",
                        scope="session",
                        session_id=session_id,
                        reason=session_val,
                    )
                    return True

        except Exception as e:
            logger.debug("kill_switch_check_error", error=str(e))

        return False

    async def activate(
        self, session_id: str | None = None, reason: str = "manual"
    ) -> None:
        """Activate the kill switch.

        Args:
            session_id: If provided, only kills that session. Otherwise global.
            reason: Human-readable reason for the kill.
        """
        if self._redis is None:
            return

        key = (
            f"aibbp:kill_switch:{session_id}"
            if session_id
            else "aibbp:kill_switch:global"
        )

        try:
            await self._async_set(key, reason)
            logger.info(
                "kill_switch_activated",
                key=key,
                reason=reason,
            )
        except Exception as e:
            logger.error("kill_switch_activate_error", error=str(e))

    async def deactivate(self, session_id: str | None = None) -> None:
        """Deactivate the kill switch.

        Args:
            session_id: If provided, clears that session. Otherwise clears global.
        """
        if self._redis is None:
            return

        key = (
            f"aibbp:kill_switch:{session_id}"
            if session_id
            else "aibbp:kill_switch:global"
        )

        try:
            await self._async_delete(key)
            logger.info("kill_switch_deactivated", key=key)
        except Exception as e:
            logger.error("kill_switch_deactivate_error", error=str(e))

    def is_active_sync(self, session_id: str | None = None) -> bool:
        """Synchronous check for use as a callable in graph nodes.

        Returns True if kill switch is active.
        """
        if self._redis is None:
            return False

        try:
            global_val = self._redis.get("aibbp:kill_switch:global")
            if global_val:
                return True

            if session_id:
                session_val = self._redis.get(f"aibbp:kill_switch:{session_id}")
                if session_val:
                    return True
        except Exception:
            pass

        return False

    # ── Redis helpers (handle both sync and async clients) ────────

    async def _async_get(self, key: str) -> str | None:
        """Get value from Redis, handling both sync and async clients."""
        result = self._redis.get(key)
        if hasattr(result, "__await__"):
            result = await result
        if result is None:
            return None
        return result.decode() if isinstance(result, bytes) else str(result)

    async def _async_set(self, key: str, value: str) -> None:
        """Set value in Redis, handling both sync and async clients."""
        result = self._redis.set(key, value)
        if hasattr(result, "__await__"):
            await result

    async def _async_delete(self, key: str) -> None:
        """Delete key from Redis, handling both sync and async clients."""
        result = self._redis.delete(key)
        if hasattr(result, "__await__"):
            await result
