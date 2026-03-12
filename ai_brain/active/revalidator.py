"""Opus-powered active finding revalidator.

Uses Claude Opus as a ReAct agent with full HTTP tools to actively verify
findings. Opus sees the complete finding report and can send any requests
it needs — no permissions, no restrictions.

Streams terminal-style output via callback for live WebSocket display.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import subprocess
from typing import Any, Callable, Awaitable
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger()

# Type for the output callback
OutputCallback = Callable[[str, str], Awaitable[None]]  # (text, color)

# Max turns Opus gets per finding
_MAX_TURNS = 15

# Tools available to Opus during revalidation
_REVAL_TOOLS = [
    {
        "name": "send_http_request",
        "description": "Send an HTTP request to any URL. Use this to replay attacks, send baselines, test payloads, check headers, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]},
                "url": {"type": "string", "description": "Full URL to request"},
                "headers": {"type": "object", "description": "Request headers as key-value pairs", "additionalProperties": {"type": "string"}},
                "body": {"type": "string", "description": "Request body (for POST/PUT/PATCH)"},
                "follow_redirects": {"type": "boolean", "description": "Follow HTTP redirects (default: false)"},
                "timeout": {"type": "number", "description": "Timeout in seconds (default: 15)"},
            },
            "required": ["method", "url"],
        },
    },
    {
        "name": "curl",
        "description": "Run a curl command directly. Use for complex requests, certificate handling, or when you need specific curl features. Return raw output.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Full curl command (without 'curl' prefix). Example: -v -X POST https://example.com/api -d '{\"key\":\"value\"}'"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "render_verdict",
        "description": "Submit your final verdict on this finding. Call this when you have enough evidence to decide.",
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["confirmed", "false_positive", "inconclusive"]},
                "confidence": {"type": "integer", "description": "Confidence 0-100 in your verdict"},
                "reasoning": {"type": "string", "description": "Detailed explanation of why you reached this verdict, including what you tested and what you observed"},
            },
            "required": ["verdict", "confidence", "reasoning"],
        },
    },
]


def _build_system_prompt() -> str:
    return """You are an expert security researcher performing active revalidation of a vulnerability finding.

Your job: Determine if this finding is REAL (confirmed), FAKE (false_positive), or UNCLEAR (inconclusive).

## Rules
- You have FULL access to send any HTTP requests needed. No restrictions.
- ACTIVELY TEST the vulnerability. Don't just look at the report — reproduce it.
- Send baseline requests first, then attack requests, then compare.
- For injection vulns (XSS, SQLi, SSTI, etc.): inject actual payloads and check if they execute/reflect.
- For access control issues (IDOR, BAC): test with different auth contexts.
- For info disclosure: check if the endpoint still leaks sensitive data.
- For CORS: send request with evil Origin header and check ACAO response header.
- For open redirect: test if Location header reflects external URLs.
- For SSRF: check if internal URLs are fetchable via the parameter.
- For DoS/rate-limiting: these are hard to verify — lean toward inconclusive unless you see clear evidence.

## How to decide
- CONFIRMED: You reproduced the vulnerability. You have concrete evidence (reflected payload, SQL error, leaked data, etc.)
- FALSE_POSITIVE: You tested thoroughly and the vulnerability does NOT exist. The original evidence was fabricated or misinterpreted.
- INCONCLUSIVE: You couldn't reach the endpoint, or the test was ambiguous, or the vuln type can't be tested this way.

## Important
- Don't be afraid to mark things as false_positive. Most automated findings ARE false positives.
- But also don't dismiss real vulns. If you see actual evidence, confirm it.
- Always call render_verdict when done. Never leave without a verdict.
- Be thorough but efficient — you have limited turns."""


def _build_finding_prompt(finding: dict) -> str:
    """Build the user message with full finding details."""
    parts = ["# Finding to Revalidate\n"]

    fields = [
        ("ID", str(finding.get("id", ""))[:12]),
        ("Domain", finding.get("domain", "")),
        ("Target URL", finding.get("target_url", "")),
        ("Vulnerability Type", finding.get("vuln_type", "")),
        ("Severity", finding.get("severity", "")),
        ("Title", finding.get("title", "")),
        ("Endpoint", finding.get("endpoint", "")),
        ("Method", finding.get("method", "GET")),
        ("Parameter", finding.get("parameter", "")),
        ("Tool Used", finding.get("tool_used", "")),
        ("CWE", finding.get("cwe_id", "")),
        ("CVSS", str(finding.get("cvss_score", "")) if finding.get("cvss_score") else ""),
    ]
    for label, value in fields:
        if value:
            parts.append(f"**{label}**: {value}")

    desc = finding.get("description", "")
    if desc:
        parts.append(f"\n## Description\n{desc[:3000]}")

    evidence = finding.get("evidence")
    if evidence:
        if isinstance(evidence, dict):
            parts.append(f"\n## Evidence\n```json\n{json.dumps(evidence, indent=2)[:3000]}\n```")
        elif isinstance(evidence, str):
            parts.append(f"\n## Evidence\n{evidence[:3000]}")

    poc = finding.get("poc_code", "")
    if poc:
        parts.append(f"\n## PoC Code\n```\n{poc[:2000]}\n```")

    steps = finding.get("steps_to_reproduce")
    if steps:
        parts.append("\n## Steps to Reproduce")
        if isinstance(steps, list):
            for i, step in enumerate(steps, 1):
                parts.append(f"{i}. {step}")
        else:
            parts.append(str(steps)[:2000])

    req_dump = finding.get("request_dump", "")
    if req_dump:
        parts.append(f"\n## Original Request\n```http\n{req_dump[:2000]}\n```")

    resp_dump = finding.get("response_dump", "")
    if resp_dump:
        parts.append(f"\n## Original Response\n```http\n{resp_dump[:2000]}\n```")

    parts.append("\n---\nNow actively test this finding. Send HTTP requests to verify it. Call render_verdict when done.")
    return "\n".join(parts)


async def _execute_tool(tool_name: str, tool_input: dict, callback: OutputCallback) -> str:
    """Execute a revalidation tool and return the result as JSON string."""

    if tool_name == "send_http_request":
        method = tool_input.get("method", "GET")
        url = tool_input.get("url", "")
        headers = tool_input.get("headers") or {}
        body = tool_input.get("body")
        follow = tool_input.get("follow_redirects", False)
        timeout = tool_input.get("timeout", 15)

        await callback(f"    [{method}] {url}", "cyan")

        try:
            async with httpx.AsyncClient(
                timeout=min(timeout, 30),
                verify=False,
                follow_redirects=follow,
            ) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers or None,
                    content=body.encode() if body else None,
                )
                resp_headers = dict(resp.headers)
                resp_body = resp.text[:10000]
                elapsed = int(resp.elapsed.total_seconds() * 1000)

                color = "green" if 200 <= resp.status_code < 300 else "yellow" if 300 <= resp.status_code < 400 else "red"
                await callback(f"    => HTTP {resp.status_code} ({elapsed}ms, {len(resp_body)} bytes)", color)

                return json.dumps({
                    "status_code": resp.status_code,
                    "headers": resp_headers,
                    "body": resp_body,
                    "url": str(resp.url),
                    "elapsed_ms": elapsed,
                })
        except Exception as e:
            await callback(f"    => Error: {e}", "red")
            return json.dumps({"error": str(e)})

    elif tool_name == "curl":
        command = tool_input.get("command", "")
        await callback(f"    $ curl {command[:120]}", "cyan")

        try:
            result = subprocess.run(
                ["curl", "-s", "-S", "--max-time", "15", "-k"] + _split_curl_args(command),
                capture_output=True,
                text=True,
                timeout=20,
            )
            output = result.stdout[:10000]
            stderr = result.stderr[:2000]
            await callback(f"    => {len(output)} bytes output", "white")
            return json.dumps({
                "stdout": output,
                "stderr": stderr,
                "returncode": result.returncode,
            })
        except subprocess.TimeoutExpired:
            await callback("    => curl timed out", "yellow")
            return json.dumps({"error": "timeout", "stdout": "", "stderr": ""})
        except Exception as e:
            await callback(f"    => Error: {e}", "red")
            return json.dumps({"error": str(e)})

    elif tool_name == "render_verdict":
        # Just return it — handled by the caller
        return json.dumps(tool_input)

    return json.dumps({"error": f"Unknown tool: {tool_name}"})


def _split_curl_args(command: str) -> list[str]:
    """Split curl command string into args, handling quoted strings."""
    import shlex
    try:
        # Remove leading 'curl' if present
        cmd = command.strip()
        if cmd.startswith("curl "):
            cmd = cmd[5:]
        return shlex.split(cmd)
    except ValueError:
        return command.split()


class Revalidator:
    """Opus-powered active finding revalidator.

    Uses Claude Opus as a ReAct agent with HTTP tools to actively
    verify each finding. No dumb replays — real AI-driven testing.
    """

    def __init__(self, findings_db, redis_client=None, claude_client=None):
        self._db = findings_db
        self._redis = redis_client
        self._claude_client = claude_client

    async def _get_claude_client(self):
        """Get or create a raw Anthropic client for Opus calls."""
        if self._claude_client:
            return self._claude_client

        import anthropic

        # Try OAuth first, then API key
        client_kwargs = {}
        try:
            from ai_brain.models import _read_claude_credentials
            auth_token = _read_claude_credentials()
            if auth_token:
                client_kwargs["auth_token"] = auth_token
                client_kwargs["default_headers"] = {
                    "anthropic-beta": "oauth-2025-04-20",
                }
        except Exception:
            pass

        if not client_kwargs:
            import os
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if api_key:
                client_kwargs["api_key"] = api_key

        self._claude_client = anthropic.AsyncAnthropic(**client_kwargs)
        return self._claude_client

    async def revalidate(self, finding_id: str, callback: OutputCallback) -> str:
        """Revalidate a finding using Opus as an active agent.

        Returns: 'confirmed', 'false_positive', or 'inconclusive'
        """
        await callback(f"[*] Starting Opus-powered revalidation for {finding_id[:8]}...", "cyan")

        # Load finding from DB
        try:
            rows, _ = await self._db.get_findings_paginated(
                offset=0, limit=1, finding_id=finding_id,
            )
            if not rows:
                await callback("[!] Finding not found in database", "red")
                return "inconclusive"
            finding = rows[0]
        except Exception as e:
            await callback(f"[!] DB error: {e}", "red")
            return "inconclusive"

        vuln_type = finding.get("vuln_type", "")
        endpoint = finding.get("endpoint", "")
        severity = finding.get("severity", "")

        await callback(f"  Target:    {endpoint}", "white")
        await callback(f"  Type:      {vuln_type}", "white")
        await callback(f"  Severity:  {severity}", "white")
        await callback("", "white")

        # Get Claude client
        try:
            client = await self._get_claude_client()
        except Exception as e:
            await callback(f"[!] Failed to initialize Claude client: {e}", "red")
            return "inconclusive"

        # Build messages
        system = _build_system_prompt()
        user_msg = _build_finding_prompt(finding)

        messages = [{"role": "user", "content": user_msg}]
        verdict = None

        # ReAct loop — let Opus investigate
        for turn in range(_MAX_TURNS):
            await callback(f"\n[Turn {turn + 1}/{_MAX_TURNS}]", "cyan")

            try:
                raw_client = client
                # If it's our ClaudeClient wrapper (has .budget attr), get the Anthropic client
                if hasattr(raw_client, 'budget') and hasattr(raw_client, '_client'):
                    raw_client = raw_client._client

                kwargs = {
                    "model": "claude-opus-4-6",
                    "max_tokens": 16384,
                    "system": system,
                    "messages": messages,
                    "tools": _REVAL_TOOLS,
                    "thinking": {"type": "adaptive"},
                }

                # Stream to avoid timeout on long Opus calls
                text_parts: list[str] = []
                tool_uses: list[dict] = []
                resp = None

                async with raw_client.messages.stream(**kwargs) as stream:
                    async for event in stream:
                        if hasattr(event, "type") and event.type == "content_block_delta":
                            delta = getattr(event, "delta", None)
                            if delta and hasattr(delta, "text"):
                                text_parts.append(delta.text)
                    resp = await stream.get_final_message()

                # Extract text and tool_use blocks from response
                assistant_text = ""
                tool_use_blocks = []

                for block in resp.content:
                    if getattr(block, "type", "") == "text":
                        assistant_text += block.text
                    elif getattr(block, "type", "") == "tool_use":
                        tool_use_blocks.append(block)

                # Show Opus's reasoning
                if assistant_text.strip():
                    # Show first 500 chars of reasoning
                    display_text = assistant_text.strip()[:500]
                    await callback(f"  Opus: {display_text}", "white")

                # No tool calls and stop_reason is end_turn — Opus is done thinking
                if not tool_use_blocks and resp.stop_reason == "end_turn":
                    await callback("  Opus stopped without verdict — marking inconclusive", "yellow")
                    verdict = {"verdict": "inconclusive", "confidence": 30,
                               "reasoning": f"Opus ended without calling render_verdict. Last text: {assistant_text[:500]}"}
                    break

                # Process tool calls
                # Append assistant message as-is for conversation continuity
                messages.append({"role": "assistant", "content": resp.content})

                tool_results = []
                for tool_block in tool_use_blocks:
                    tool_name = tool_block.name
                    tool_input = tool_block.input
                    tool_id = tool_block.id

                    await callback(f"  Tool: {tool_name}", "cyan")

                    result_str = await _execute_tool(tool_name, tool_input, callback)

                    if tool_name == "render_verdict":
                        verdict = tool_input
                        await callback(f"  Verdict: {verdict.get('verdict', '').upper()} (confidence: {verdict.get('confidence', 0)}%)", "green" if verdict.get("verdict") == "confirmed" else "red" if verdict.get("verdict") == "false_positive" else "yellow")
                        await callback(f"  Reasoning: {verdict.get('reasoning', '')[:300]}", "white")
                        # Still need to send tool_result back but we'll break after
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_id,
                            "content": result_str,
                        })
                        break
                    else:
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_id,
                            "content": result_str,
                        })

                messages.append({"role": "user", "content": tool_results})

                if verdict:
                    break

            except Exception as e:
                err_str = str(e)
                await callback(f"  [!] Opus error: {err_str[:200]}", "red")
                logger.error("revalidation_opus_error", error=err_str[:500], turn=turn)
                # Don't retry on non-transient errors (400, auth, etc.)
                if "400" in err_str or "401" in err_str or "invalid_request" in err_str:
                    verdict = {"verdict": "inconclusive", "confidence": 10,
                               "reasoning": f"API error (non-retryable): {err_str[:300]}"}
                    break
                # Continue to next turn for transient errors
                if turn >= _MAX_TURNS - 1:
                    verdict = {"verdict": "inconclusive", "confidence": 20,
                               "reasoning": f"Opus errored: {err_str[:200]}"}
                continue

        # If no verdict after all turns
        if not verdict:
            verdict = {"verdict": "inconclusive", "confidence": 10,
                       "reasoning": "Max turns reached without verdict"}

        result = verdict.get("verdict", "inconclusive")

        # Display final verdict
        await self._display_verdict(callback, result, verdict)

        # Update DB
        await self._update_finding(finding_id, result, verdict, callback)

        return result

    async def _display_verdict(self, callback: OutputCallback, result: str, verdict: dict):
        """Display the verdict in terminal format."""
        await callback("", "white")
        if result == "confirmed":
            await callback("=" * 60, "green")
            await callback(f"  CONFIRMED (confidence: {verdict.get('confidence', 0)}%)", "green")
            await callback(f"  {verdict.get('reasoning', '')[:200]}", "green")
            await callback("=" * 60, "green")
        elif result == "false_positive":
            await callback("=" * 60, "red")
            await callback(f"  FALSE POSITIVE (confidence: {verdict.get('confidence', 0)}%)", "red")
            await callback(f"  {verdict.get('reasoning', '')[:200]}", "red")
            await callback("=" * 60, "red")
        else:
            await callback("=" * 60, "yellow")
            await callback(f"  INCONCLUSIVE (confidence: {verdict.get('confidence', 0)}%)", "yellow")
            await callback(f"  {verdict.get('reasoning', '')[:200]}", "yellow")
            await callback("=" * 60, "yellow")

    async def _update_finding(self, finding_id: str, result: str, verdict: dict, callback: OutputCallback):
        """Update finding status in DB and publish via Redis."""
        try:
            if result == "confirmed":
                confidence = verdict.get("confidence", 80)
                await self._db.mark_confirmed(finding_id, confidence=confidence)
            elif result == "false_positive":
                reason = verdict.get("reasoning", "Opus revalidation: not reproduced")[:500]
                await self._db.mark_false_positive(finding_id, reason)
            await callback(f"[*] Finding status updated: {result}", "cyan")
        except Exception as e:
            await callback(f"[!] DB update failed: {e}", "red")

        if self._redis:
            try:
                await self._redis.publish(
                    f"aibbp:revalidation:{finding_id}",
                    json.dumps({
                        "status": result,
                        "finding_id": finding_id,
                        "confidence": verdict.get("confidence", 0),
                        "reasoning": verdict.get("reasoning", "")[:500],
                    }),
                )
            except Exception:
                pass

    async def revalidate_batch(
        self,
        finding_ids: list[str] | None = None,
        domain: str | None = None,
        callback: OutputCallback | None = None,
        max_findings: int = 50,
    ) -> dict[str, str]:
        """Revalidate multiple findings. Returns {finding_id: verdict}."""
        if callback is None:
            async def callback(text, color):
                print(text)

        # Load findings
        if finding_ids:
            findings = []
            for fid in finding_ids[:max_findings]:
                rows, _ = await self._db.get_findings_paginated(
                    offset=0, limit=1, finding_id=fid,
                )
                if rows:
                    findings.append(rows[0])
        else:
            findings, _ = await self._db.get_findings_paginated(
                offset=0, limit=max_findings, domain=domain,
                is_fp=False,
            )

        await callback(f"[*] Revalidating {len(findings)} findings with Opus...", "cyan")
        results = {}
        for i, finding in enumerate(findings):
            fid = str(finding["id"])
            await callback(f"\n{'='*60}", "white")
            await callback(f"[{i+1}/{len(findings)}] Finding {fid[:8]} — {finding.get('vuln_type', '?')} on {finding.get('endpoint', '?')}", "cyan")
            await callback(f"{'='*60}", "white")
            verdict = await self.revalidate(fid, callback)
            results[fid] = verdict

        # Summary
        await callback(f"\n{'='*60}", "cyan")
        await callback("REVALIDATION SUMMARY", "cyan")
        await callback(f"{'='*60}", "cyan")
        confirmed = sum(1 for v in results.values() if v == "confirmed")
        fp = sum(1 for v in results.values() if v == "false_positive")
        inc = sum(1 for v in results.values() if v == "inconclusive")
        await callback(f"  Confirmed:    {confirmed}", "green")
        await callback(f"  False Pos:    {fp}", "red")
        await callback(f"  Inconclusive: {inc}", "yellow")
        await callback(f"  Total:        {len(results)}", "white")

        return results


# ── CLI entry point ──────────────────────────────────────────────

async def _cli_main():
    import argparse

    parser = argparse.ArgumentParser(description="Opus-powered finding revalidator")
    parser.add_argument("--finding", type=str, help="Single finding ID to revalidate")
    parser.add_argument("--domain", type=str, help="Revalidate all findings for domain")
    parser.add_argument("--limit", type=int, default=20, help="Max findings to revalidate (default: 20)")
    parser.add_argument("--unconfirmed", action="store_true", help="Only revalidate unconfirmed findings")
    args = parser.parse_args()

    # Color output callback for terminal
    _COLORS = {
        "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
        "cyan": "\033[96m", "white": "\033[0m",
    }

    async def print_callback(text: str, color: str):
        c = _COLORS.get(color, "")
        reset = "\033[0m" if c else ""
        print(f"{c}{text}{reset}")

    # Connect to DB
    from ai_brain.active.findings_db import FindingsDB
    db = FindingsDB("postgresql://aibbp:aibbp_dev@localhost:5433/aibbp")
    await db.connect()

    reval = Revalidator(findings_db=db)

    try:
        if args.finding:
            await reval.revalidate(args.finding, print_callback)
        else:
            finding_ids = None
            if args.unconfirmed:
                # Get unconfirmed, non-FP findings
                rows, total = await db.get_findings_paginated(
                    offset=0, limit=args.limit,
                    domain=args.domain,
                    confirmed=False, is_fp=False,
                )
                finding_ids = [str(r["id"]) for r in rows]
                await print_callback(f"Found {len(finding_ids)} unconfirmed findings (of {total} total)", "cyan")
            await reval.revalidate_batch(
                finding_ids=finding_ids,
                domain=args.domain,
                callback=print_callback,
                max_findings=args.limit,
            )
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(_cli_main())
