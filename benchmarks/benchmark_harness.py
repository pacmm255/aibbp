"""Benchmark harness for continuous regression testing.

Defines BenchmarkTarget protocol and suite implementations for XBOW,
Juice Shop, and crAPI.

Usage:
    suite = XBOWBenchmark()
    await suite.setup()
    results = await suite.run(max_challenges=5, budget=2.0)
    await suite.teardown()
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from benchmarks.metrics import BenchmarkMetrics

logger = logging.getLogger("benchmark_harness")


# ── Protocol ────────────────────────────────────────────────────────────

class BenchmarkTarget(Protocol):
    """Protocol for benchmark suite implementations."""

    async def setup(self) -> None:
        """Set up the benchmark environment."""
        ...

    def get_challenges(self) -> list[dict[str, Any]]:
        """Get list of challenge definitions."""
        ...

    async def verify(self, challenge: dict[str, Any], output: dict[str, Any]) -> bool:
        """Verify if a challenge was solved."""
        ...

    async def teardown(self) -> None:
        """Clean up the benchmark environment."""
        ...


# ── Benchmark Result ────────────────────────────────────────────────────

@dataclass
class BenchmarkResult:
    """Result from a single benchmark challenge."""

    challenge_id: str = ""
    challenge_name: str = ""
    passed: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)
    cost: float = 0.0
    turns: int = 0
    duration_seconds: float = 0.0
    error: str = ""


@dataclass
class SuiteResult:
    """Result from a full benchmark suite run."""

    suite_name: str = ""
    results: list[BenchmarkResult] = field(default_factory=list)
    total_duration: float = 0.0
    metrics: BenchmarkMetrics | None = None

    @property
    def pass_rate(self) -> float:
        if not self.results:
            return 0.0
        return sum(1 for r in self.results if r.passed) / len(self.results)

    @property
    def total_cost(self) -> float:
        return sum(r.cost for r in self.results)

    def summary(self) -> str:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        return (
            f"{self.suite_name}: {passed}/{total} passed ({self.pass_rate:.1%}), "
            f"cost=${self.total_cost:.2f}, time={self.total_duration:.0f}s"
        )


# ── XBOW Benchmark ─────────────────────────────────────────────────────

class XBOWBenchmark:
    """XBOW CTF-style benchmark (refactored from xbow_runner.py)."""

    def __init__(self, xbow_dir: str = "benchmarks/xbow") -> None:
        self._xbow_dir = Path(xbow_dir)
        self._challenges: list[dict[str, Any]] = []

    async def setup(self) -> None:
        """Load XBOW challenge definitions."""
        challenges_dir = self._xbow_dir / "challenges"
        if not challenges_dir.exists():
            logger.warning("xbow_challenges_not_found", path=str(challenges_dir))
            return

        for challenge_dir in sorted(challenges_dir.iterdir()):
            if not challenge_dir.is_dir():
                continue
            meta_file = challenge_dir / "metadata.json"
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text())
                    meta["challenge_dir"] = str(challenge_dir)
                    self._challenges.append(meta)
                except Exception:
                    continue

    def get_challenges(self) -> list[dict[str, Any]]:
        return self._challenges

    async def verify(self, challenge: dict[str, Any], output: dict[str, Any]) -> bool:
        """Verify XBOW challenge solution."""
        expected_flag = challenge.get("flag", "")
        if not expected_flag:
            return False

        # Check if any finding contains the flag
        for finding in output.get("findings", {}).values():
            if isinstance(finding, dict):
                evidence = str(finding.get("evidence", ""))
                poc = str(finding.get("poc_code", ""))
                if expected_flag in evidence or expected_flag in poc:
                    return True

        return False

    async def teardown(self) -> None:
        """Clean up XBOW containers."""
        pass

    async def run(
        self,
        max_challenges: int = 0,
        budget: float = 2.0,
        brain: str = "claude",
    ) -> SuiteResult:
        """Run XBOW benchmark suite."""
        await self.setup()
        challenges = self._challenges[:max_challenges] if max_challenges else self._challenges
        results: list[BenchmarkResult] = []
        start = time.time()

        for challenge in challenges:
            result = BenchmarkResult(
                challenge_id=challenge.get("id", ""),
                challenge_name=challenge.get("name", ""),
            )
            try:
                # Run agent against challenge
                cmd = [
                    "python", "-m", "ai_brain.active.react_main",
                    "--target", challenge.get("target_url", "http://localhost:8080"),
                    "--budget", str(budget),
                    "--max-turns", "150",
                    "--output", f"/tmp/xbow_{challenge.get('id', 'unknown')}.json",
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

                # Read output
                output_path = Path(f"/tmp/xbow_{challenge.get('id', 'unknown')}.json")
                if output_path.exists():
                    output = json.loads(output_path.read_text())
                    result.findings = list(output.get("findings", {}).values())
                    result.cost = output.get("budget_spent", 0.0)
                    result.turns = output.get("turn_count", 0)
                    result.passed = await self.verify(challenge, output)

            except asyncio.TimeoutError:
                result.error = "timeout"
            except Exception as e:
                result.error = str(e)[:200]

            result.duration_seconds = time.time() - start
            results.append(result)

        suite = SuiteResult(
            suite_name="XBOW",
            results=results,
            total_duration=time.time() - start,
        )
        return suite


# ── Juice Shop Benchmark ───────────────────────────────────────────────

class JuiceShopBenchmark:
    """OWASP Juice Shop benchmark (Docker-based)."""

    def __init__(self, port: int = 3000) -> None:
        self._port = port
        self._container_id: str = ""
        self._challenges: list[dict[str, Any]] = []

    async def setup(self) -> None:
        """Start Juice Shop Docker container."""
        try:
            result = subprocess.run(
                ["docker", "run", "-d", "-p", f"{self._port}:3000",
                 "bkimminich/juice-shop"],
                capture_output=True, text=True, timeout=60,
            )
            self._container_id = result.stdout.strip()
            # Wait for startup
            await asyncio.sleep(10)

            # Fetch challenges from API
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(f"http://localhost:{self._port}/api/Challenges/")
                if resp.status_code == 200:
                    data = resp.json()
                    self._challenges = data.get("data", [])
        except Exception as e:
            logger.error("juiceshop_setup_failed", error=str(e)[:200])

    def get_challenges(self) -> list[dict[str, Any]]:
        return self._challenges

    async def verify(self, challenge: dict[str, Any], output: dict[str, Any]) -> bool:
        """Verify via Juice Shop challenge API."""
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(f"http://localhost:{self._port}/api/Challenges/")
                if resp.status_code == 200:
                    data = resp.json()
                    for c in data.get("data", []):
                        if c.get("name") == challenge.get("name") and c.get("solved"):
                            return True
        except Exception:
            pass
        return False

    async def teardown(self) -> None:
        """Stop and remove container."""
        if self._container_id:
            subprocess.run(["docker", "rm", "-f", self._container_id],
                           capture_output=True, timeout=30)


# ── crAPI Benchmark ────────────────────────────────────────────────────

class CrAPIBenchmark:
    """crAPI (Completely Ridiculous API) benchmark."""

    def __init__(self, port: int = 8025) -> None:
        self._port = port
        self._container_id: str = ""
        self._challenges: list[dict[str, Any]] = [
            {"id": "crapi-01", "name": "Access details of another user's vehicle",
             "vuln_type": "bola", "severity": "high"},
            {"id": "crapi-02", "name": "Access mechanic reports of other users",
             "vuln_type": "bola", "severity": "high"},
            {"id": "crapi-03", "name": "Reset password of another user",
             "vuln_type": "broken_auth", "severity": "critical"},
            {"id": "crapi-04", "name": "Find an API endpoint that leaks other users' info",
             "vuln_type": "excessive_data_exposure", "severity": "high"},
            {"id": "crapi-05", "name": "Find an API endpoint that doesn't perform rate limiting",
             "vuln_type": "rate_limiting", "severity": "medium"},
            {"id": "crapi-06", "name": "Perform a layer 7 DoS via resource-intensive query",
             "vuln_type": "resource_consumption", "severity": "high"},
            {"id": "crapi-07", "name": "Delete a video of another user",
             "vuln_type": "bfla", "severity": "high"},
            {"id": "crapi-08", "name": "Buy item for free using mass assignment",
             "vuln_type": "mass_assignment", "severity": "high"},
            {"id": "crapi-09", "name": "Gain admin access via JWT manipulation",
             "vuln_type": "jwt", "severity": "critical"},
            {"id": "crapi-10", "name": "Find a way to forge valid coupons",
             "vuln_type": "business_logic", "severity": "high"},
        ]

    async def setup(self) -> None:
        """Start crAPI Docker container."""
        try:
            result = subprocess.run(
                ["docker", "run", "-d", "-p", f"{self._port}:8025",
                 "crapi/crapi:latest"],
                capture_output=True, text=True, timeout=120,
            )
            self._container_id = result.stdout.strip()
            await asyncio.sleep(30)  # crAPI takes a while to start
        except Exception as e:
            logger.error("crapi_setup_failed", error=str(e)[:200])

    def get_challenges(self) -> list[dict[str, Any]]:
        return self._challenges

    async def verify(self, challenge: dict[str, Any], output: dict[str, Any]) -> bool:
        """Verify crAPI challenge by checking for matching finding types."""
        expected_type = challenge.get("vuln_type", "")
        for finding in output.get("findings", {}).values():
            if isinstance(finding, dict):
                found_type = finding.get("vuln_type", "").lower()
                if expected_type in found_type or found_type in expected_type:
                    return True
        return False

    async def teardown(self) -> None:
        if self._container_id:
            subprocess.run(["docker", "rm", "-f", self._container_id],
                           capture_output=True, timeout=30)
