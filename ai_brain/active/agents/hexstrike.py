"""HexStrike agent — orchestrates hexstrike-ai's 150+ security tools.

Runs target analysis, smart scan, nuclei vuln scanning, WAF detection,
content discovery, and web crawling. Maps hexstrike tool output into
AIBBP's standard finding format.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import structlog

from ai_brain.active.agents.base import BaseActiveAgent
from ai_brain.active.errors import ToolExecutionError
from ai_brain.active.tools import HexstrikeClient

logger = structlog.get_logger()


def _parse_nuclei_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse nuclei JSON output into AIBBP finding dicts.

    Nuclei outputs NDJSON lines with keys:
      template-id, info.severity, info.name, matched-at, matcher-name,
      extracted-results, curl-command, type
    """
    findings: list[dict[str, Any]] = []
    stdout = result.get("stdout", "")

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            # Try pattern matching for non-JSON nuclei output
            # e.g. "[critical] [cve-2021-1234] https://example.com/path"
            m = re.match(
                r"\[(\w+)\]\s+\[([^\]]+)\]\s+(https?://\S+)", line
            )
            if m:
                findings.append({
                    "vuln_type": m.group(2),
                    "endpoint": m.group(3),
                    "parameter": "",
                    "evidence": line,
                    "tool_used": "nuclei",
                    "confirmed": False,
                })
            continue

        if not isinstance(obj, dict):
            continue

        info = obj.get("info", {})
        severity = info.get("severity", "unknown")
        # Skip info-level noise
        if severity == "info":
            continue

        findings.append({
            "vuln_type": info.get("name", obj.get("template-id", "unknown")),
            "endpoint": obj.get("matched-at", obj.get("host", "")),
            "parameter": obj.get("matcher-name", ""),
            "evidence": (
                obj.get("extracted-results", "")
                or obj.get("curl-command", "")
                or json.dumps(obj, default=str)[:500]
            ),
            "tool_used": f"nuclei/{obj.get('template-id', '')}",
            "confirmed": False,
        })

    return findings


def _parse_text_findings(
    tool_name: str, result: dict[str, Any], target: str
) -> list[dict[str, Any]]:
    """Parse text-based tool output (gobuster, katana, etc.) into findings.

    Most tools output discovered paths or vulnerabilities as text lines.
    We only create findings for things that look security-relevant.
    """
    findings: list[dict[str, Any]] = []
    stdout = result.get("stdout", "")
    if not stdout:
        return findings

    # For WAF detection results
    if tool_name == "wafw00f":
        if "is behind" in stdout.lower():
            findings.append({
                "vuln_type": "waf_detection",
                "endpoint": target,
                "parameter": "",
                "evidence": stdout[:1000],
                "tool_used": "wafw00f",
                "confirmed": True,
            })
        return findings

    # For gobuster/ffuf — interesting status codes on discovered paths
    interesting_patterns = [
        r"(Status:\s*(?:200|301|302|403))\s+.*?(https?://\S+|\S+)",
        r"(https?://\S+)\s+\[Status:\s*(?:200|301|302|403)",
    ]
    for pattern in interesting_patterns:
        for match in re.finditer(pattern, stdout, re.IGNORECASE):
            findings.append({
                "vuln_type": f"discovered_path",
                "endpoint": match.group(0)[:300],
                "parameter": "",
                "evidence": match.group(0)[:500],
                "tool_used": tool_name,
                "confirmed": False,
            })

    return findings


class HexstrikeAgent(BaseActiveAgent):
    """Orchestrates hexstrike-ai tools for broad automated scanning."""

    def __init__(self, hexstrike_client: HexstrikeClient, **deps: Any) -> None:
        super().__init__(**deps)
        self._hex = hexstrike_client

    @property
    def agent_type(self) -> str:
        return "hexstrike"

    async def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        """Run hexstrike scanning pipeline.

        1. Target analysis via Intelligence Engine
        2. Smart scan (parallel multi-tool, max 8 tools)
        3. Nuclei vuln scan (critical+high+medium)
        4. WAF detection (wafw00f)
        5. Content discovery (gobuster)
        6. Web crawling (katana)
        """
        target_url = state["target_url"]
        all_findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # 1. Target analysis
        target_profile: dict[str, Any] = {}
        try:
            analysis = await self._hex.analyze_target(target_url)
            target_profile = analysis.get("target_profile", {})
            logger.info(
                "hexstrike_target_analyzed",
                target=target_url,
                risk=target_profile.get("risk_level", "unknown"),
                techs=target_profile.get("technologies", []),
            )
        except ToolExecutionError as e:
            errors.append(f"hexstrike_analyze: {e}")
            logger.warning("hexstrike_analyze_failed", error=str(e))

        # 2. Smart scan — parallel multi-tool orchestration
        try:
            smart = await self._hex.smart_scan(target_url, objective="comprehensive", max_tools=8)
            total_vulns = smart.get("total_vulnerabilities", 0)
            tools_used = smart.get("tools_executed", [])
            logger.info(
                "hexstrike_smart_scan_done",
                tools=tools_used,
                total_vulns=total_vulns,
            )
            # Parse combined output for findings
            combined = smart.get("combined_output", "")
            if combined:
                for line in combined.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict) and obj.get("info", {}).get("severity"):
                            parsed = _parse_nuclei_findings({"stdout": line})
                            all_findings.extend(parsed)
                    except (json.JSONDecodeError, TypeError):
                        pass
        except ToolExecutionError as e:
            errors.append(f"hexstrike_smart_scan: {e}")
            logger.warning("hexstrike_smart_scan_failed", error=str(e))

        # 3. Nuclei vulnerability scan
        try:
            nuclei_result = await self._hex.run_nuclei(target_url, severity="critical,high,medium")
            nuclei_findings = _parse_nuclei_findings(nuclei_result)
            all_findings.extend(nuclei_findings)
            logger.info("hexstrike_nuclei_done", findings=len(nuclei_findings))
        except ToolExecutionError as e:
            errors.append(f"hexstrike_nuclei: {e}")
            logger.warning("hexstrike_nuclei_failed", error=str(e))

        # 4-6: Run WAF detection, gobuster, katana in parallel
        waf_task = self._safe_run(self._hex.run_wafw00f, target_url)
        gobuster_task = self._safe_run(self._hex.run_gobuster, target_url)
        katana_task = self._safe_run(self._hex.run_katana, target_url)

        results = await asyncio.gather(waf_task, gobuster_task, katana_task, return_exceptions=True)

        tool_names = ["wafw00f", "gobuster", "katana"]
        for i, res in enumerate(results):
            tool = tool_names[i]
            if isinstance(res, Exception):
                errors.append(f"hexstrike_{tool}: {res}")
                logger.warning(f"hexstrike_{tool}_failed", error=str(res))
            elif isinstance(res, dict):
                parsed = _parse_text_findings(tool, res, target_url)
                all_findings.extend(parsed)
                logger.info(f"hexstrike_{tool}_done", findings=len(parsed))

        logger.info(
            "hexstrike_execute_complete",
            total_findings=len(all_findings),
            errors=len(errors),
        )

        return {
            "raw_findings": all_findings,
            "errors": errors,
        }

    async def _safe_run(self, coro_fn: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Run a hexstrike client method with error wrapping."""
        try:
            return await coro_fn(*args, **kwargs)
        except ToolExecutionError:
            raise
        except Exception as e:
            raise ToolExecutionError("hexstrike", str(e)) from e
