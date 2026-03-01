"""HexStrike-AI server lifecycle manager.

Manages the hexstrike Flask API server as a subprocess:
- start(): launches the server, polls /health until ready
- stop(): SIGTERM -> wait -> SIGKILL
- Detects externally running instances before launching
"""

from __future__ import annotations

import asyncio
import signal
import time

import structlog

logger = structlog.get_logger()

_HEXSTRIKE_SCRIPT = "/tmp/hexstrike-ai/hexstrike_server.py"
_DEFAULT_PORT = 8877  # 8888 often occupied by other services


class HexstrikeServerManager:
    """Start/stop the hexstrike-ai Flask server as a subprocess."""

    def __init__(self, port: int = _DEFAULT_PORT) -> None:
        self._port = port
        self._process: asyncio.subprocess.Process | None = None
        self._base_url = f"http://localhost:{port}"

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def is_running(self) -> bool:
        if self._process is not None and self._process.returncode is None:
            return True
        return False

    async def _health_ok(self) -> bool:
        """Check if the server is responding to /health."""
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._base_url}/health", timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("status") == "healthy"
        except Exception:
            pass
        return False

    async def start(self, timeout: int = 30) -> None:
        """Start the hexstrike server (or detect an already-running instance).

        Args:
            timeout: Max seconds to wait for the server to become healthy.

        Raises:
            RuntimeError: If the server fails to start within the timeout.
        """
        # Check if already running externally
        if await self._health_ok():
            logger.info("hexstrike_already_running", url=self._base_url)
            return

        logger.info("hexstrike_starting", script=_HEXSTRIKE_SCRIPT, port=self._port)

        self._process = await asyncio.create_subprocess_exec(
            "python3", _HEXSTRIKE_SCRIPT, "--port", str(self._port),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        # Give Flask a few seconds to initialize before polling health
        await asyncio.sleep(3)

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._process.returncode is not None:
                stderr_bytes = await self._process.stderr.read(2000) if self._process.stderr else b""
                stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    f"hexstrike exited with code {self._process.returncode}: {stderr_text}"
                )
            if await self._health_ok():
                logger.info("hexstrike_ready", url=self._base_url)
                return
            await asyncio.sleep(1)

        # Timed out — kill and raise
        await self.stop()
        raise RuntimeError(f"hexstrike failed to become healthy within {timeout}s")

    async def stop(self) -> None:
        """Stop the hexstrike server (SIGTERM -> 5s wait -> SIGKILL)."""
        if self._process is None or self._process.returncode is not None:
            return

        logger.info("hexstrike_stopping", pid=self._process.pid)
        try:
            self._process.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        except ProcessLookupError:
            pass
        finally:
            self._process = None
            logger.info("hexstrike_stopped")
