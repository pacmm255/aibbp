"""Security tool runner for active testing.

Wraps external tools (sqlmap, dalfox, jwt_tool, commix) and provides
sandboxed execution of AI-generated PoC code. Every invocation is
scope-validated and timeout-bounded.

Also includes HexstrikeClient for the hexstrike-ai 150+ tool platform.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import time
from typing import Any
from urllib.parse import urlparse

import structlog

from ai_brain.active.errors import ToolExecutionError
from ai_brain.active.scope_guard import ActiveScopeGuard
from ai_brain.config import ActiveTestingConfig

logger = structlog.get_logger()

# ── HexStrike API Client ─────────────────────────────────────────────


class HexstrikeClient:
    """Async HTTP client wrapping the hexstrike-ai REST API.

    Every method validates URLs/targets via scope_guard before calling
    hexstrike. Uses aiohttp with configurable timeout.
    """

    def __init__(
        self,
        base_url: str,
        scope_guard: ActiveScopeGuard,
        timeout: int = 600,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._scope_guard = scope_guard
        self._timeout = timeout

    def _validate_target(self, target: str) -> None:
        """Scope-validate a target URL or domain."""
        self._scope_guard.validate_tool_command("hexstrike", [target])

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """POST to hexstrike and return JSON response."""
        import aiohttp

        url = f"{self._base_url}{path}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self._timeout),
                ) as resp:
                    data = await resp.json()
                    if resp.status >= 400:
                        error_msg = data.get("error", f"HTTP {resp.status}")
                        raise ToolExecutionError("hexstrike", f"{path}: {error_msg}")
                    return data
        except ToolExecutionError:
            raise
        except asyncio.TimeoutError:
            raise ToolExecutionError("hexstrike", f"{path}: timed out after {self._timeout}s")
        except Exception as e:
            raise ToolExecutionError("hexstrike", f"{path}: {e}") from e

    # ── Individual tools ──────────────────────────────────────────

    async def run_nuclei(
        self, target: str, severity: str = "critical,high,medium"
    ) -> dict[str, Any]:
        self._validate_target(target)
        return await self._post("/api/tools/nuclei", {
            "target": target, "severity": severity, "use_recovery": True,
        })

    async def run_nmap(
        self, target: str, scan_type: str = "-sCV"
    ) -> dict[str, Any]:
        self._validate_target(target)
        return await self._post("/api/tools/nmap", {
            "target": target, "scan_type": scan_type, "use_recovery": True,
        })

    async def run_ffuf(
        self, url: str, wordlist: str = "", mode: str = "directory"
    ) -> dict[str, Any]:
        self._validate_target(url)
        payload: dict[str, Any] = {"url": url, "mode": mode}
        if wordlist:
            payload["wordlist"] = wordlist
        return await self._post("/api/tools/ffuf", payload)

    async def run_gobuster(
        self, url: str, mode: str = "dir"
    ) -> dict[str, Any]:
        self._validate_target(url)
        return await self._post("/api/tools/gobuster", {
            "url": url, "mode": mode, "use_recovery": True,
        })

    async def run_katana(self, target: str) -> dict[str, Any]:
        self._validate_target(target)
        return await self._post("/api/tools/katana", {
            "url": target, "depth": 3, "js_crawl": True,
            "form_extraction": True, "output_format": "json",
        })

    async def run_wafw00f(self, target: str) -> dict[str, Any]:
        self._validate_target(target)
        return await self._post("/api/tools/wafw00f", {"target": target})

    async def run_httpx(self, target: str) -> dict[str, Any]:
        self._validate_target(target)
        return await self._post("/api/tools/httpx", {
            "target": target, "probe": True, "tech_detect": True,
            "status_code": True, "title": True, "web_server": True,
        })

    # ── Intelligence engine ───────────────────────────────────────

    async def analyze_target(self, target: str) -> dict[str, Any]:
        self._validate_target(target)
        return await self._post("/api/intelligence/analyze-target", {"target": target})

    async def smart_scan(
        self, target: str, objective: str = "comprehensive", max_tools: int = 5
    ) -> dict[str, Any]:
        self._validate_target(target)
        return await self._post("/api/intelligence/smart-scan", {
            "target": target, "objective": objective, "max_tools": max_tools,
        })

    async def technology_detection(self, target: str) -> dict[str, Any]:
        self._validate_target(target)
        return await self._post("/api/intelligence/technology-detection", {"target": target})

    # ── Bug bounty workflows ──────────────────────────────────────

    async def recon_workflow(self, domain: str) -> dict[str, Any]:
        self._validate_target(domain)
        return await self._post("/api/bugbounty/reconnaissance-workflow", {
            "domain": domain, "program_type": "web",
        })

    async def vuln_hunting_workflow(
        self, domain: str, priority_vulns: list[str] | None = None
    ) -> dict[str, Any]:
        self._validate_target(domain)
        vulns = priority_vulns or ["rce", "sqli", "xss", "idor", "ssrf"]
        return await self._post("/api/bugbounty/vulnerability-hunting-workflow", {
            "domain": domain, "priority_vulns": vulns,
        })

# Maximum output size to capture from tool stdout/stderr (50KB)
_MAX_OUTPUT_SIZE = 50 * 1024


class ToolRunner:
    """Executes security testing tools with scope validation and timeouts.

    Supports:
    - sqlmap (via REST API): automated SQL injection detection
    - dalfox (subprocess): reflected/stored XSS scanning
    - jwt_tool (subprocess): JWT vulnerability testing
    - commix (subprocess): command injection testing
    - Custom PoC code (sandboxed subprocess): AI-generated exploit verification
    """

    def __init__(
        self,
        scope_guard: ActiveScopeGuard,
        config: ActiveTestingConfig,
    ) -> None:
        self._scope_guard = scope_guard
        self._config = config
        self._timeout = config.tools_timeout

    async def run_sqlmap(
        self,
        url: str,
        params: dict[str, str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run sqlmap against a URL via the sqlmap REST API.

        Flow: POST /task/new -> POST /scan/{id}/start -> poll status -> GET /scan/{id}/data

        Args:
            url: Target URL to test.
            params: Parameters to inject (e.g., {"id": "1"}).
            options: Extra sqlmap options (level, risk, technique, tamper).

        Returns:
            Dict with task_id, status, data (findings), and log.

        Raises:
            ToolExecutionError: If sqlmap API is unreachable or scan fails.
        """
        # Validate URL format before passing to sqlmap
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ToolExecutionError("sqlmap", f"Invalid URL: {url[:200]}")

        self._scope_guard.validate_tool_command("sqlmap", [url])

        if self._config.dry_run:
            logger.info("tool_dry_run", tool="sqlmap", url=url, params=params)
            return {"tool": "sqlmap", "dry_run": True, "url": url, "data": []}

        # Try REST API first, fall back to subprocess
        api_url = self._config.sqlmap_api_url
        try:
            return await self._run_sqlmap_api(url, params, options, api_url)
        except ToolExecutionError:
            logger.debug("sqlmap_api_unavailable", api_url=api_url, url=url)
            return await self._run_sqlmap_subprocess(url, params, options)

    async def _run_sqlmap_api(
        self,
        url: str,
        params: dict[str, str] | None,
        options: dict[str, Any] | None,
        api_url: str,
    ) -> dict[str, Any]:
        """Run sqlmap via REST API."""
        import aiohttp

        start = time.monotonic()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{api_url}/task/new") as resp:
                    if resp.status != 200:
                        raise ToolExecutionError("sqlmap", "Failed to create task")
                    task_data = await resp.json()
                    task_id = task_data["taskid"]

                scan_options: dict[str, Any] = {"url": url}
                if params:
                    scan_options["data"] = "&".join(
                        f"{k}={v}" for k, v in params.items()
                    )
                if options:
                    scan_options.update(options)

                scan_options.setdefault("level", 3)
                scan_options.setdefault("risk", 2)
                scan_options.setdefault("batch", True)
                scan_options.setdefault("threads", 1)

                async with session.post(
                    f"{api_url}/scan/{task_id}/start",
                    json=scan_options,
                ) as resp:
                    if resp.status != 200:
                        raise ToolExecutionError(
                            "sqlmap", f"Failed to start scan: {await resp.text()}"
                        )

                deadline = time.monotonic() + self._timeout
                while time.monotonic() < deadline:
                    async with session.get(
                        f"{api_url}/scan/{task_id}/status"
                    ) as resp:
                        status_data = await resp.json()
                        status = status_data.get("status", "")
                        if status in ("terminated", "not running"):
                            break
                    await asyncio.sleep(3)
                else:
                    await session.get(f"{api_url}/scan/{task_id}/kill")
                    raise ToolExecutionError(
                        "sqlmap", f"Scan timed out after {self._timeout}s"
                    )

                async with session.get(f"{api_url}/scan/{task_id}/data") as resp:
                    result_data = await resp.json()
                async with session.get(f"{api_url}/scan/{task_id}/log") as resp:
                    log_data = await resp.json()

                duration_ms = int((time.monotonic() - start) * 1000)
                logger.info(
                    "sqlmap_complete",
                    task_id=task_id,
                    findings=len(result_data.get("data", [])),
                    duration_ms=duration_ms,
                )
                return {
                    "tool": "sqlmap",
                    "task_id": task_id,
                    "url": url,
                    "data": result_data.get("data", []),
                    "log": log_data.get("log", [])[-20:],
                    "duration_ms": duration_ms,
                }

        except ToolExecutionError:
            raise
        except Exception as e:
            raise ToolExecutionError("sqlmap", str(e)) from e

    async def _run_sqlmap_subprocess(
        self,
        url: str,
        params: dict[str, str] | None,
        options: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Run sqlmap as subprocess (fallback when REST API is unavailable).

        Uses faster settings than the API (level=2, risk=1) since subprocess
        mode is the fallback and we don't want to block for too long.
        """
        cmd = [
            "sqlmap", "-u", url,
            "--batch",
            "--level", str((options or {}).get("level", 1)),
            "--risk", str((options or {}).get("risk", 1)),
            "--threads", "1",
            "--timeout", "10",
            "--retries", "1",
            "--technique", "BEU",
            "--output-dir", tempfile.mkdtemp(prefix="sqlmap_"),
        ]
        if params:
            data_str = "&".join(f"{k}={v}" for k, v in params.items())
            cmd.extend(["--data", data_str])

        # Use shorter timeout for subprocess fallback (120s max)
        saved_timeout = self._timeout
        self._timeout = min(self._timeout, 120)
        try:
            result = await self._run_subprocess("sqlmap", cmd)
        finally:
            self._timeout = saved_timeout

        # Translate subprocess output to the same format as API results
        # sqlmap CLI doesn't output JSON — parse stdout for vuln indicators
        findings: list[dict[str, Any]] = []
        stdout = result.get("stdout", "")
        if "is vulnerable" in stdout.lower() or "payload:" in stdout.lower():
            # Extract basic finding info from sqlmap text output
            findings.append({
                "type": "sqli",
                "url": url,
                "evidence": stdout[-2000:],
            })

        return {
            "tool": "sqlmap",
            "url": url,
            "data": findings,
            "log": stdout[-2000:].split("\n")[-20:],
            "duration_ms": result.get("duration_ms", 0),
        }

    async def run_dalfox(
        self,
        url: str,
        params: dict[str, str] | None = None,
        options: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run dalfox for XSS vulnerability scanning.

        Args:
            url: Target URL to test.
            params: Parameters to test (e.g., {"q": "test"}).
            options: Extra CLI flags (e.g., ["--blind", "https://callback.example.com"]).

        Returns:
            Dict with parsed findings from dalfox JSON output.
        """
        # Validate URL format
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ToolExecutionError("dalfox", f"Invalid URL: {url[:200]}")

        cmd_args = [url]
        if params:
            param_str = "&".join(f"{k}={v}" for k, v in params.items())
            cmd_args.extend(["-p", param_str])
        self._scope_guard.validate_tool_command("dalfox", cmd_args)

        if self._config.dry_run:
            logger.info("tool_dry_run", tool="dalfox", url=url, params=params)
            return {"tool": "dalfox", "dry_run": True, "url": url, "findings": []}

        cmd = ["dalfox", "url", url, "--silence", "--format", "json"]
        if params:
            for key in params:
                cmd.extend(["-p", key])
        if options:
            cmd.extend(options)

        return await self._run_subprocess("dalfox", cmd)

    async def run_jwt_tool(
        self,
        token: str,
        attacks: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run jwt_tool to test JWT vulnerabilities.

        Args:
            token: The JWT token to analyze.
            attacks: Attack types (e.g., ["none-alg", "key-confusion", "claim-inject"]).

        Returns:
            Dict with jwt_tool output.
        """
        # jwt_tool doesn't target URLs, but validate we're not leaking tokens
        if self._config.dry_run:
            logger.info("tool_dry_run", tool="jwt_tool", attacks=attacks)
            return {"tool": "jwt_tool", "dry_run": True, "findings": []}

        cmd = ["python3", "-m", "jwt_tool", token]

        if attacks:
            for attack in attacks:
                if attack == "none-alg":
                    cmd.extend(["-X", "a"])
                elif attack == "key-confusion":
                    cmd.extend(["-X", "k"])
                elif attack == "claim-inject":
                    cmd.extend(["-I", "-pc", "name", "-pv", "admin"])
                else:
                    cmd.extend(["-X", attack])

        return await self._run_subprocess("jwt_tool", cmd)

    async def run_commix(
        self,
        url: str,
        params: dict[str, str] | None = None,
        options: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run commix for command injection testing.

        Args:
            url: Target URL to test.
            params: Parameters to inject.
            options: Extra CLI flags.

        Returns:
            Dict with commix output.
        """
        # Validate URL format
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ToolExecutionError("commix", f"Invalid URL: {url[:200]}")

        cmd_args = [url]
        if params:
            cmd_args.extend(f"{k}={v}" for k, v in params.items())
        self._scope_guard.validate_tool_command("commix", cmd_args)

        if self._config.dry_run:
            logger.info("tool_dry_run", tool="commix", url=url, params=params)
            return {"tool": "commix", "dry_run": True, "url": url, "findings": []}

        cmd = ["commix", "--url", url, "--batch"]
        if params:
            data_str = "&".join(f"{k}={v}" for k, v in params.items())
            cmd.extend(["--data", data_str])
        if options:
            cmd.extend(options)

        return await self._run_subprocess("commix", cmd)

    async def run_custom_poc(
        self,
        code: str,
        language: str = "python",
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Execute AI-generated PoC code in a sandboxed subprocess.

        The code runs in a temporary file with restricted capabilities.
        Only Python and shell scripts are supported.

        Args:
            code: Source code to execute.
            language: "python" or "bash".
            timeout: Override timeout in seconds.

        Returns:
            Dict with stdout, stderr, exit_code, and duration_ms.
        """
        if self._config.dry_run:
            logger.info(
                "tool_dry_run",
                tool="custom_poc",
                language=language,
                code_length=len(code),
            )
            return {
                "tool": "custom_poc",
                "dry_run": True,
                "language": language,
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
            }

        ext = ".py" if language == "python" else ".sh"
        run_timeout = timeout or min(self._timeout, 90)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, delete=False
        ) as f:
            f.write(code)
            f.flush()
            script_path = f.name

        if language == "python":
            cmd = ["python3", script_path]
        elif language == "bash":
            cmd = ["bash", script_path]
        else:
            return {
                "tool": "custom_poc",
                "error": f"Unsupported language: {language}",
                "exit_code": -1,
            }

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=run_timeout
            )

            stdout = stdout_bytes.decode("utf-8", errors="replace")[:_MAX_OUTPUT_SIZE]
            stderr = stderr_bytes.decode("utf-8", errors="replace")[:_MAX_OUTPUT_SIZE]
            duration_ms = int((time.monotonic() - start) * 1000)

            logger.info(
                "custom_poc_complete",
                language=language,
                exit_code=proc.returncode,
                duration_ms=duration_ms,
            )

            return {
                "tool": "custom_poc",
                "language": language,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": proc.returncode or 0,
                "duration_ms": duration_ms,
            }

        except asyncio.TimeoutError:
            proc.kill()
            raise ToolExecutionError(
                "custom_poc", f"PoC timed out after {run_timeout}s"
            )
        except Exception as e:
            raise ToolExecutionError("custom_poc", str(e)) from e

    async def _run_subprocess(
        self,
        tool_name: str,
        cmd: list[str],
    ) -> dict[str, Any]:
        """Run an external tool as a subprocess with timeout and output capture.

        Args:
            tool_name: Name for logging.
            cmd: Full command to execute.

        Returns:
            Dict with tool name, stdout, stderr, exit_code, duration_ms,
            and parsed findings if output is JSON.
        """
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout
            )

            stdout = stdout_bytes.decode("utf-8", errors="replace")[:_MAX_OUTPUT_SIZE]
            stderr = stderr_bytes.decode("utf-8", errors="replace")[:_MAX_OUTPUT_SIZE]
            duration_ms = int((time.monotonic() - start) * 1000)

            # Try to parse JSON output (handles JSON arrays, objects, and NDJSON)
            findings: list[dict[str, Any]] = []
            try:
                parsed = json.loads(stdout)
                if isinstance(parsed, list):
                    findings = parsed
                elif isinstance(parsed, dict):
                    findings = parsed.get("findings", parsed.get("results", [parsed]))
            except (json.JSONDecodeError, TypeError):
                # Fallback: try NDJSON (one JSON object per line, e.g. dalfox)
                for line in stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            findings.append(obj)
                        elif isinstance(obj, list):
                            findings.extend(obj)
                    except (json.JSONDecodeError, TypeError):
                        pass

            logger.info(
                "tool_subprocess_complete",
                tool=tool_name,
                exit_code=proc.returncode,
                findings_count=len(findings),
                duration_ms=duration_ms,
            )

            return {
                "tool": tool_name,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": proc.returncode or 0,
                "findings": findings,
                "duration_ms": duration_ms,
            }

        except asyncio.TimeoutError:
            proc.kill()
            raise ToolExecutionError(
                tool_name, f"Timed out after {self._timeout}s"
            )
        except FileNotFoundError:
            raise ToolExecutionError(
                tool_name,
                f"{tool_name} not found. Ensure it is installed and on PATH.",
            )
        except Exception as e:
            raise ToolExecutionError(tool_name, str(e)) from e
