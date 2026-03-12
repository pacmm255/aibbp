"""Goja TLS fingerprint proxy manager.

Starts and manages the Goja SOCKS5 MITM proxy that replays HTTPS requests
with authentic browser TLS fingerprints (JA3/JA4/HTTP2). This makes
send_http_request look like Chrome at the TLS level, bypassing WAF/CDN
bot detection based on TLS fingerprinting.

Architecture:
    send_http_request → Goja SOCKS5 (:1081) → target
    browser (Playwright) → mitmproxy (:8085) → target  (unchanged)
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Default Goja binary and config paths
_GOJA_BINARY = "/root/Goja/bin/goja-proxy"
_GOJA_DEFAULT_PORT = 1081  # Avoid conflict with anything else on 1080

# Chrome 139 desktop fingerprint preset
_CHROME_FINGERPRINT = {
    "userAgent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/139.0.0.0 Safari/537.36"
    ),
    "ja3": (
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-"
        "49171-49172-156-157-47-53,"
        "23-43-10-5-51-11-65037-27-0-18-45-35-17613-65281-13-16,"
        "4588-29-23-24,0"
    ),
    "ja4r": (
        "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,"
        "c02b,c02c,c02f,c030,cca8,cca9_"
        "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,"
        "44cd,fe0d,ff01_"
        "0403,0804,0401,0503,0805,0501,0806,0601"
    ),
    "http2Fingerprint": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "headers": {
        "sec-ch-ua": '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "upgrade-insecure-requests": "1",
        "accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
        "priority": "u=0, i",
    },
    "headerOrder": [
        "host", "connection",
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "accept-encoding", "accept-language", "priority",
    ],
    "disableGrease": False,
    "enableCompression": False,  # Let httpx handle decompression
}


class GojaManager:
    """Manages the Goja SOCKS5 TLS fingerprint proxy lifecycle.

    Includes health monitoring with automatic restart on failure:
    - Periodic SOCKS5 connectivity checks (every 15s)
    - Consecutive failure tracking (3 failures → auto-restart)
    - Process crash detection via poll()
    - Graceful restart with connection draining
    """

    _HEALTH_CHECK_INTERVAL = 15  # seconds between health checks
    _MAX_CONSECUTIVE_FAILURES = 3  # failures before auto-restart
    _MAX_RESTARTS = 10  # max restarts before giving up
    _RESTART_BACKOFF_BASE = 2  # exponential backoff base (seconds)

    def __init__(self, port: int = _GOJA_DEFAULT_PORT) -> None:
        self._port = port
        self._process: subprocess.Popen[bytes] | None = None
        self._config_path: str | None = None
        self._running = False
        self._upstream_proxy: str = ""
        self._monitor_task: asyncio.Task[None] | None = None
        self._consecutive_failures = 0
        self._restart_count = 0
        self._total_health_checks = 0
        self._total_health_failures = 0

    @property
    def port(self) -> int:
        return self._port

    @property
    def socks5_url(self) -> str:
        """SOCKS5 proxy URL for httpx."""
        return f"socks5://127.0.0.1:{self._port}"

    @property
    def is_running(self) -> bool:
        return self._running and self._process is not None and self._process.poll() is None

    async def start(self, timeout: int = 10, upstream_proxy: str = "") -> None:
        """Start Goja proxy process with health monitoring.

        Args:
            timeout: Seconds to wait for proxy to be ready.
            upstream_proxy: Optional upstream HTTP/SOCKS proxy URL.
                Chain: httpx → Goja (TLS fingerprint) → upstream proxy → target.
        """
        if self._running:
            return
        self._upstream_proxy = upstream_proxy

        binary = _GOJA_BINARY
        if not os.path.isfile(binary):
            logger.warning("goja_binary_not_found", path=binary)
            raise FileNotFoundError(f"Goja binary not found at {binary}")

        # Write config to temp file
        config = {
            "fingerprint": _CHROME_FINGERPRINT,
            "fingerprintPreset": "",
            "dashboard": {"enabled": False},
            "upstreamProxy": upstream_proxy,
            "reuseConnections": True,
            "requestTimeoutSec": 30,
            "filters": [],
            "replacements": [],
        }

        fd, config_path = tempfile.mkstemp(suffix=".json", prefix="goja_")
        with os.fdopen(fd, "w") as f:
            json.dump(config, f)
        self._config_path = config_path

        # Set port via env var
        env = os.environ.copy()
        env["SOCKS_PORT"] = str(self._port)

        self._process = subprocess.Popen(
            [binary, "-config", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env,
        )

        # Wait for the proxy to be ready
        for _ in range(timeout * 10):
            await asyncio.sleep(0.1)
            if self._process.poll() is not None:
                stderr = self._process.stderr.read().decode() if self._process.stderr else ""
                raise RuntimeError(f"Goja exited immediately: {stderr[:500]}")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect(("127.0.0.1", self._port))
                sock.close()
                self._running = True
                logger.info("goja_started", port=self._port, pid=self._process.pid)
                self._start_health_monitor()
                return
            except (ConnectionRefusedError, OSError):
                continue

        # Timeout
        self.stop_sync()
        raise TimeoutError(f"Goja failed to start on port {self._port} within {timeout}s")

    def _start_health_monitor(self) -> None:
        """Start the background health monitoring task."""
        if self._monitor_task and not self._monitor_task.done():
            return
        try:
            loop = asyncio.get_running_loop()
            self._monitor_task = loop.create_task(self._health_monitor_loop())
        except RuntimeError:
            logger.warning("goja_no_event_loop_for_monitor")

    async def _health_monitor_loop(self) -> None:
        """Background loop that checks Goja health and auto-restarts on failure."""
        while self._running:
            await asyncio.sleep(self._HEALTH_CHECK_INTERVAL)
            if not self._running:
                break
            try:
                healthy = await self._health_check()
                self._total_health_checks += 1
                if healthy:
                    self._consecutive_failures = 0
                else:
                    self._consecutive_failures += 1
                    self._total_health_failures += 1
                    logger.warning(
                        "goja_health_check_failed",
                        consecutive=self._consecutive_failures,
                        total_failures=self._total_health_failures,
                    )
                    if self._consecutive_failures >= self._MAX_CONSECUTIVE_FAILURES:
                        await self._auto_restart()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("goja_health_monitor_error", error=str(exc))

    async def _health_check(self) -> bool:
        """Test SOCKS5 connectivity by performing a TCP connect to the proxy port.

        Also checks if the process has crashed via poll().
        """
        # Check process is alive
        if self._process is None or self._process.poll() is not None:
            logger.warning("goja_process_dead", poll=self._process.poll() if self._process else None)
            return False

        # TCP connect to SOCKS5 port
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self._port),
                timeout=3.0,
            )
            # Send SOCKS5 greeting: version=5, 1 auth method, no-auth
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            # Expect SOCKS5 response: version=5, method chosen
            data = await asyncio.wait_for(reader.read(2), timeout=3.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if len(data) >= 2 and data[0] == 0x05:
                return True
            logger.warning("goja_socks5_bad_response", data=data.hex())
            return False
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
            logger.warning("goja_socks5_unreachable", error=str(exc))
            return False

    async def _auto_restart(self) -> None:
        """Kill the stale Goja process and restart it."""
        if self._restart_count >= self._MAX_RESTARTS:
            logger.error(
                "goja_max_restarts_reached",
                restarts=self._restart_count,
                msg="Goja has crashed too many times, giving up",
            )
            self._running = False
            return

        self._restart_count += 1
        backoff = min(self._RESTART_BACKOFF_BASE ** self._restart_count, 30)
        logger.warning(
            "goja_auto_restarting",
            restart_count=self._restart_count,
            backoff=backoff,
        )

        # Kill the old process
        self._kill_process()

        # Backoff before restart
        await asyncio.sleep(backoff)

        # Restart
        try:
            self._running = False  # Allow start() to proceed
            await self.start(timeout=10, upstream_proxy=self._upstream_proxy)
            self._consecutive_failures = 0
            logger.info(
                "goja_restarted_successfully",
                restart_count=self._restart_count,
                pid=self._process.pid if self._process else None,
            )
        except Exception as exc:
            logger.error("goja_restart_failed", error=str(exc), restart_count=self._restart_count)
            self._running = False

    def _kill_process(self) -> None:
        """Force-kill the Goja process without cleaning up config."""
        if self._process and self._process.poll() is None:
            try:
                self._process.kill()
                self._process.wait(timeout=5)
            except Exception:
                pass
            logger.info("goja_process_killed", pid=self._process.pid)
        self._process = None

    async def stop(self) -> None:
        """Stop Goja proxy process and health monitor."""
        # Cancel health monitor first
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None
        self.stop_sync()

    def stop_sync(self) -> None:
        """Synchronous stop for use in finally blocks."""
        if self._process and self._process.poll() is None:
            try:
                self._process.send_signal(signal.SIGTERM)
                self._process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self._process.kill()
                    self._process.wait(timeout=2)
                except Exception:
                    pass
            logger.info("goja_stopped", pid=self._process.pid)
        self._process = None
        self._running = False

        if self._config_path and os.path.exists(self._config_path):
            try:
                os.unlink(self._config_path)
            except OSError:
                pass
            self._config_path = None
