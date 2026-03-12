"""Docker-based sandbox executor for security tool isolation.

Provides per-agent Kali containers for running untrusted security tools
(custom exploits, shell commands) without host contamination.

Usage:
    executor = DockerExecutor()
    await executor.start()
    result = await executor.execute("nmap -sV target.com")
    await executor.stop()
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class DockerExecutor:
    """Per-agent Kali container for sandboxed tool execution.

    Uses asyncio.create_subprocess_exec for docker CLI (no SDK dependency).
    Container runs with network_mode=host for target access.
    Memory limited to 2GB per container.
    Files exchanged via mounted /tmp/aibbp_sandbox_{pid} directory.
    """

    def __init__(
        self,
        image: str = "kalilinux/kali-rolling",
        memory_limit: str = "2g",
        network_mode: str = "host",
        isolated_network: bool = False,
    ):
        self._image = image
        self._memory_limit = memory_limit
        self._network_mode = network_mode
        self._isolated_network = isolated_network
        self._network_name = ""
        self._container_name = f"aibbp_sandbox_{os.getpid()}"
        self._exchange_dir = Path(tempfile.mkdtemp(prefix="aibbp_sandbox_"))
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def exchange_dir(self) -> Path:
        return self._exchange_dir

    async def start(self) -> None:
        """Create and start the sandbox container."""
        # Check if docker is available
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "version", "--format", "{{.Server.Version}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"Docker not available: {stderr.decode()}")
        except FileNotFoundError:
            raise RuntimeError("Docker CLI not found on PATH")

        # Remove any stale container with same name
        await self._remove_container()

        # Create isolated network if requested
        if self._isolated_network:
            self._network_name = f"aibbp-sandbox-{os.getpid()}"
            # Create isolated network
            create_net = await asyncio.create_subprocess_exec(
                "docker", "network", "create", "--internal", self._network_name,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await create_net.communicate()
            # Override network_mode for container
            self._network_mode = self._network_name

        # Start container in detached mode with sleep infinity
        cmd = [
            "docker", "run", "-d",
            "--name", self._container_name,
            "--memory", self._memory_limit,
            f"--network={self._network_mode}",
            "-v", f"{self._exchange_dir}:/exchange",
            self._image,
            "sleep", "infinity",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to start container: {stderr.decode()}")

        self._running = True
        logger.info("docker_sandbox_started", container=self._container_name, image=self._image)

    async def execute(self, command: str, timeout: int = 120) -> dict[str, Any]:
        """Execute a shell command inside the container.

        Returns dict with keys: stdout, stderr, exit_code, timed_out
        """
        if not self._running:
            return {"error": "Container not running", "stdout": "", "stderr": "", "exit_code": -1, "timed_out": False}

        cmd = [
            "docker", "exec", self._container_name,
            "bash", "-c", command,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return {
                    "stdout": stdout.decode(errors="replace")[:50000],
                    "stderr": stderr.decode(errors="replace")[:10000],
                    "exit_code": proc.returncode,
                    "timed_out": False,
                }
            except asyncio.TimeoutError:
                proc.kill()
                return {
                    "stdout": "",
                    "stderr": f"Command timed out after {timeout}s",
                    "exit_code": -1,
                    "timed_out": True,
                }
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1, "timed_out": False}

    async def execute_python(self, code: str, timeout: int = 120) -> dict[str, Any]:
        """Execute Python code inside the container.

        Writes code to exchange dir, executes via python3.
        """
        if not self._running:
            return {"error": "Container not running", "stdout": "", "stderr": "", "exit_code": -1, "timed_out": False}

        # Write code to exchange dir
        script_path = self._exchange_dir / "script.py"
        script_path.write_text(code)

        return await self.execute(f"python3 /exchange/script.py", timeout=timeout)

    async def stop(self) -> None:
        """Stop and remove the container, clean up exchange dir."""
        await self._remove_container()
        self._running = False

        # Clean up isolated network if created
        if self._network_name:
            try:
                cleanup_net = await asyncio.create_subprocess_exec(
                    "docker", "network", "rm", self._network_name,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await cleanup_net.communicate()
            except Exception:
                pass

        # Clean up exchange directory
        try:
            if self._exchange_dir.exists():
                shutil.rmtree(self._exchange_dir, ignore_errors=True)
        except Exception:
            pass

        logger.info("docker_sandbox_stopped", container=self._container_name)

    async def _remove_container(self) -> None:
        """Remove container if it exists."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", self._container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
        except Exception:
            pass
