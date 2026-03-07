"""Watch Agent A's memory.json for state updates via inotify.

Uses asyncinotify CLOSE_WRITE events for ~1-10ms latency
with zero polling overhead. Agent A is never modified.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, AsyncIterator

import structlog

logger = structlog.get_logger()


class AgentAStateWatcher:
    """Watch Agent A's memory.json and yield state updates."""

    def __init__(self, memory_path: str | Path):
        self.memory_path = Path(memory_path)
        self._last_state: dict | None = None

    def read_current(self) -> dict | None:
        """Read Agent A's current state (one-shot)."""
        if not self.memory_path.exists():
            return None
        try:
            with open(self.memory_path) as f:
                state = json.load(f)
            self._last_state = state
            return state
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning("state_read_failed", path=str(self.memory_path), error=str(e))
            return self._last_state

    async def watch(self) -> AsyncIterator[dict]:
        """Yield state dicts whenever Agent A updates memory.json.

        Uses inotify CLOSE_WRITE for instant notification.
        Falls back to polling if inotify is unavailable.
        """
        try:
            async for state in self._watch_inotify():
                yield state
        except ImportError:
            logger.warning("asyncinotify_unavailable_falling_back_to_polling")
            async for state in self._watch_polling():
                yield state

    async def _watch_inotify(self) -> AsyncIterator[dict]:
        """Watch via inotify CLOSE_WRITE events."""
        from asyncinotify import Inotify, Mask

        # Wait for the file to exist
        while not self.memory_path.exists():
            logger.info("waiting_for_agent_a_memory", path=str(self.memory_path))
            await asyncio.sleep(5)

        # Yield initial state
        initial = self.read_current()
        if initial:
            yield initial

        with Inotify() as inotify:
            inotify.add_watch(self.memory_path, Mask.CLOSE_WRITE | Mask.MOVED_TO)
            logger.info("inotify_watching", path=str(self.memory_path))

            async for event in inotify:
                # Retry on partial reads
                for attempt in range(3):
                    try:
                        with open(self.memory_path) as f:
                            state = json.load(f)
                        self._last_state = state
                        yield state
                        break
                    except (json.JSONDecodeError, FileNotFoundError):
                        await asyncio.sleep(0.01 * (attempt + 1))

    async def _watch_polling(self, interval: float = 2.0) -> AsyncIterator[dict]:
        """Fallback polling watcher."""
        last_mtime = 0.0

        while True:
            if self.memory_path.exists():
                mtime = self.memory_path.stat().st_mtime
                if mtime > last_mtime:
                    last_mtime = mtime
                    state = self.read_current()
                    if state:
                        yield state
            await asyncio.sleep(interval)

    def extract_key_fields(self, state: dict) -> dict[str, Any]:
        """Extract the fields Agent B cares about from Agent A's state."""
        return {
            "target_url": state.get("target_url", ""),
            "tech_stack": state.get("tech_stack", []),
            "endpoints": state.get("endpoints", {}),
            "findings": state.get("findings", {}),
            "tested_techniques": state.get("tested_techniques", {}),
            "failed_approaches": state.get("failed_approaches", {}),
            "accounts": state.get("accounts", {}),
            "working_memory": state.get("working_memory", {}),
            "total_sessions": state.get("total_sessions", 0),
            "total_turns": state.get("total_turns", 0),
        }
