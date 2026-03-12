"""WebSocket connection manager with Redis pub/sub bridge.

Handles client connections, channel subscriptions, and bridges
Redis pub/sub events to WebSocket clients.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import structlog
from fastapi import WebSocket, WebSocketDisconnect

from ai_brain.active.auth import decode_jwt

logger = structlog.get_logger()


class ConnectionManager:
    """Manages WebSocket connections and channel subscriptions."""

    def __init__(self):
        # ws → set of subscribed channels
        self._connections: dict[WebSocket, set[str]] = {}
        self._last_ping: dict[WebSocket, float] = {}
        self._ping_task: asyncio.Task | None = None
        self._redis_task: asyncio.Task | None = None
        self._redis = None

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, ws: WebSocket, token: str) -> dict | None:
        """Validate JWT and accept WebSocket connection.
        Returns user dict or None if auth fails.
        """
        payload = decode_jwt(token)
        if not payload:
            await ws.close(code=4001, reason="Invalid token")
            return None
        await ws.accept()
        self._connections[ws] = set()
        self._last_ping[ws] = time.time()
        logger.info("ws_connected", user=payload.get("email"), total=len(self._connections))
        return {
            "user_id": payload.get("sub"),
            "email": payload.get("email"),
            "role": payload.get("role"),
        }

    async def disconnect(self, ws: WebSocket):
        """Remove connection and clean up subscriptions."""
        self._connections.pop(ws, None)
        self._last_ping.pop(ws, None)
        logger.info("ws_disconnected", total=len(self._connections))

    def subscribe(self, ws: WebSocket, channels: list[str]):
        """Subscribe a connection to channels."""
        if ws in self._connections:
            self._connections[ws].update(channels)

    def unsubscribe(self, ws: WebSocket, channels: list[str]):
        """Unsubscribe a connection from channels."""
        if ws in self._connections:
            self._connections[ws].difference_update(channels)

    async def broadcast(self, channel: str, data: Any):
        """Send data to all subscribers of a channel."""
        message = json.dumps({"type": "event", "channel": channel, "data": data})
        stale = []
        for ws, channels in self._connections.items():
            if channel in channels or "*" in channels:
                try:
                    await ws.send_text(message)
                except Exception:
                    stale.append(ws)
        for ws in stale:
            await self.disconnect(ws)

    async def send_to(self, ws: WebSocket, data: Any):
        """Send data to a specific client."""
        try:
            if isinstance(data, str):
                await ws.send_text(data)
            else:
                await ws.send_text(json.dumps(data))
        except Exception:
            await self.disconnect(ws)

    async def handle_message(self, ws: WebSocket, message: str):
        """Process incoming WebSocket message."""
        try:
            msg = json.loads(message)
        except json.JSONDecodeError:
            await self.send_to(ws, {"type": "error", "data": {"message": "Invalid JSON"}})
            return

        msg_type = msg.get("type")
        if msg_type == "subscribe":
            channels = msg.get("channels", [])
            if isinstance(channels, str):
                channels = [channels]
            self.subscribe(ws, channels)
            await self.send_to(ws, {"type": "subscribed", "channels": list(self._connections.get(ws, set()))})
        elif msg_type == "unsubscribe":
            channels = msg.get("channels", [])
            if isinstance(channels, str):
                channels = [channels]
            self.unsubscribe(ws, channels)
            await self.send_to(ws, {"type": "unsubscribed", "channels": list(self._connections.get(ws, set()))})
        elif msg_type == "ping":
            self._last_ping[ws] = time.time()
            await self.send_to(ws, {"type": "pong"})
        else:
            await self.send_to(ws, {"type": "error", "data": {"message": f"Unknown type: {msg_type}"}})

    async def start_ping_loop(self):
        """Background task: ping clients every 30s, disconnect stale ones."""
        while True:
            await asyncio.sleep(30)
            now = time.time()
            stale = []
            for ws, last in self._last_ping.items():
                if now - last > 90:  # No activity for 90s
                    stale.append(ws)
                else:
                    try:
                        await ws.send_text(json.dumps({"type": "ping"}))
                    except Exception:
                        stale.append(ws)
            for ws in stale:
                try:
                    await ws.close(code=4002, reason="Stale connection")
                except Exception:
                    pass
                await self.disconnect(ws)

    async def start_redis_bridge(self, redis_client):
        """Bridge Redis pub/sub to WebSocket clients.

        Subscribes to patterns:
        - aibbp:findings
        - aibbp:scan_progress:*
        - aibbp:proxy_traffic:*
        - aibbp:revalidation:*
        - aibbp:agents

        Automatically reconnects with exponential backoff on failure.
        """
        self._redis = redis_client
        if not redis_client:
            logger.warning("ws_redis_bridge_skipped", reason="No Redis client")
            return

        backoff = 5
        max_backoff = 60

        while True:
            pubsub = redis_client.pubsub()
            try:
                await pubsub.subscribe("aibbp:findings", "aibbp:agents")
                await pubsub.psubscribe(
                    "aibbp:scan_progress:*",
                    "aibbp:proxy_traffic:*",
                    "aibbp:revalidation:*",
                )
                logger.info("ws_redis_bridge_started")
                backoff = 5  # Reset backoff on successful connection

                while True:
                    msg = await pubsub.get_message(
                        ignore_subscribe_messages=True, timeout=1.0,
                    )
                    if msg and msg.get("type") in ("message", "pmessage"):
                        channel = msg.get("channel", "")
                        # Map Redis channel to WS channel
                        ws_channel = self._redis_to_ws_channel(channel)
                        try:
                            data = json.loads(msg["data"])
                        except (json.JSONDecodeError, TypeError):
                            data = {"raw": str(msg.get("data", ""))}
                        await self.broadcast(ws_channel, data)
                    else:
                        await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                # Clean shutdown — do not retry
                try:
                    await pubsub.unsubscribe()
                    await pubsub.punsubscribe()
                    await pubsub.aclose()
                except Exception:
                    pass
                return
            except Exception as e:
                logger.error("ws_redis_bridge_error", error=str(e)[:200], retry_in=backoff)
            finally:
                try:
                    await pubsub.unsubscribe()
                    await pubsub.punsubscribe()
                    await pubsub.aclose()
                except Exception:
                    pass

            # Wait before reconnecting with exponential backoff
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

    @staticmethod
    def _redis_to_ws_channel(redis_channel: str) -> str:
        """Map Redis channel name to WebSocket channel name.

        aibbp:findings → findings
        aibbp:scan_progress:session123 → scan_progress:session123
        aibbp:proxy_traffic:session123 → proxy_traffic:session123
        aibbp:revalidation:finding_id → revalidation:finding_id
        """
        if redis_channel.startswith("aibbp:"):
            return redis_channel[6:]  # Strip "aibbp:" prefix
        return redis_channel

    async def start(self, redis_client=None):
        """Start background tasks (ping loop + Redis bridge)."""
        self._ping_task = asyncio.create_task(self.start_ping_loop())
        if redis_client:
            self._redis_task = asyncio.create_task(self.start_redis_bridge(redis_client))

    async def stop(self):
        """Stop background tasks and close all connections."""
        if self._ping_task:
            self._ping_task.cancel()
        if self._redis_task:
            self._redis_task.cancel()
        for ws in list(self._connections.keys()):
            try:
                await ws.close(code=1001, reason="Server shutdown")
            except Exception:
                pass
        self._connections.clear()
        self._last_ping.clear()
