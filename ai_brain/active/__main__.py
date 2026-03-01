"""Standalone CLI entry point for active testing.

Usage:
    python -m ai_brain.active --target https://example.com \
        --allowed-domains "*.example.com" \
        --dry-run \
        --email-domain testmail.example.com
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from typing import Any

import structlog

from ai_brain.active.browser import BrowserController
from ai_brain.active.email import EmailManager
from ai_brain.active.graph import build_active_subgraph
from ai_brain.active.hexstrike_server import HexstrikeServerManager
from ai_brain.active.proxy import TrafficInterceptor
from ai_brain.active.scope_guard import ActiveScopeGuard
from ai_brain.active.tools import HexstrikeClient, ToolRunner
from ai_brain.budget import BudgetManager
from ai_brain.config import AIBrainConfig, ActiveTestingConfig, BudgetConfig
from ai_brain.models import ClaudeClient
from ai_brain.rate_limiter import DualRateLimiter
from ai_brain.errors import CircuitBreaker
from ai_brain.scope import ScopeEnforcer

logger = structlog.get_logger()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AIBBP Active Testing Engine - Autonomous web app security testing"
    )
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target URL to test (e.g., https://example.com)",
    )
    parser.add_argument(
        "--allowed-domains",
        type=str,
        nargs="*",
        default=[],
        help="In-scope domains (e.g., *.example.com)",
    )
    parser.add_argument(
        "--out-of-scope",
        type=str,
        nargs="*",
        default=[],
        help="Out-of-scope domains",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Dry run mode (AI reasons but no browser/network actions)",
    )
    parser.add_argument(
        "--email-domain",
        type=str,
        default=None,
        help="Catch-all domain for account registration (default: inbox.lt)",
    )
    parser.add_argument(
        "--email-mode",
        type=str,
        default=None,
        choices=["local", "imap"],
        help="Email mode: 'local' (aiosmtpd) or 'imap' (default: imap)",
    )
    parser.add_argument(
        "--imap-host",
        type=str,
        default=None,
        help="IMAP server hostname (default: mail.inbox.lt)",
    )
    parser.add_argument(
        "--imap-user",
        type=str,
        default=None,
        help="IMAP login email (default: hunter255@inbox.lt)",
    )
    parser.add_argument(
        "--imap-password",
        type=str,
        default=None,
        help="IMAP login password",
    )
    parser.add_argument(
        "--email-plus-addressing",
        action="store_true",
        default=None,
        help="Use plus addressing (user+tag@domain) instead of catch-all",
    )
    parser.add_argument(
        "--budget",
        type=float,
        default=15.0,
        help="Budget in dollars for this active test (default: $15.00)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="",
        help="Output JSON file path for findings (default: /tmp/aibbp_findings_<timestamp>.json)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=True,
        help="Run browser in headless mode (default: True)",
    )
    parser.add_argument(
        "--no-headless",
        action="store_true",
        default=False,
        help="Run browser with visible UI",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        default=False,
        help="Demo mode: mock AI responses (no API key needed)",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    config = AIBrainConfig()

    if args.demo:
        config.demo_mode = True
    elif not config.anthropic_api_key and not config.anthropic_auth_token:
        # ClaudeClient will auto-read from ~/.claude/.credentials.json
        # but check here to give a clear error if that also fails
        from ai_brain.models import _read_claude_credentials

        if not _read_claude_credentials():
            logger.error(
                "No credentials found. Set ANTHROPIC_API_KEY, "
                "ANTHROPIC_AUTH_TOKEN, or install Claude Code (credentials "
                "are read from ~/.claude/.credentials.json)"
            )
            sys.exit(1)

    # Configure active testing — only override defaults if CLI args are explicitly set
    active_overrides: dict[str, Any] = {
        "enabled": True,
        "dry_run": args.dry_run,
        "browser_headless": not args.no_headless,
    }
    if args.email_domain is not None:
        active_overrides["email_domain"] = args.email_domain
    if args.email_mode is not None:
        active_overrides["email_mode"] = args.email_mode
    if args.imap_host is not None:
        active_overrides["imap_host"] = args.imap_host
    if args.imap_user is not None:
        active_overrides["imap_user"] = args.imap_user
    if args.imap_password is not None:
        active_overrides["imap_password"] = args.imap_password
    if args.email_plus_addressing is not None:
        active_overrides["email_plus_addressing"] = args.email_plus_addressing
    active_cfg = ActiveTestingConfig(**active_overrides)

    # Set up budget (active-only, all goes to active_testing phase)
    budget_cfg = BudgetConfig(total_dollars=args.budget)
    budget = BudgetManager(budget_cfg, active_testing=True)

    # Initialize Claude client
    rate_limiter = DualRateLimiter(
        target_rps=3.0,
        api_rpm=config.rate_limits.requests_per_minute,
        api_itpm=config.rate_limits.input_tokens_per_minute,
    )
    circuit_breaker = CircuitBreaker()
    client = ClaudeClient(
        config=config,
        budget=budget,
        rate_limiter=rate_limiter,
        circuit_breaker=circuit_breaker,
    )

    # Set up scope
    scope = ScopeEnforcer(
        allowed_domains=args.allowed_domains,
        out_of_scope_domains=args.out_of_scope,
    )
    scope_guard = ActiveScopeGuard(scope)

    # Initialize infrastructure
    browser = BrowserController(scope_guard, active_cfg)
    proxy = TrafficInterceptor(scope_guard, active_cfg)
    email_mgr = EmailManager(active_cfg)
    tool_runner = ToolRunner(scope_guard, active_cfg)

    hexstrike_mgr = HexstrikeServerManager()
    hexstrike_client: HexstrikeClient | None = None

    target = args.target
    print(f"\n{'='*60}")
    print(f"Active Testing: {target}")
    print(f"Budget: ${args.budget:.2f}")
    print(f"Dry run: {args.dry_run}")
    print(f"{'='*60}\n")

    try:
        if not active_cfg.dry_run:
            await browser.start()
            await proxy.start(port=active_cfg.proxy_port)
            if email_mgr.is_configured:
                await email_mgr.start()

            # Start hexstrike server (non-fatal if unavailable)
            try:
                await hexstrike_mgr.start(timeout=30)
                hexstrike_client = HexstrikeClient(
                    hexstrike_mgr.base_url, scope_guard, active_cfg.tools_timeout,
                )
                print(f"HexStrike: ready ({hexstrike_mgr.base_url})")
            except Exception as e:
                logger.warning("hexstrike_start_failed", error=str(e))
                print(f"HexStrike: unavailable ({e})")

        # Build and run active testing subgraph
        active_subgraph = build_active_subgraph()

        active_budget = budget.phases.get("active_testing")
        budget_limit = active_budget.remaining if active_budget else args.budget

        subgraph_config = {
            "recursion_limit": 200,
            "configurable": {
                "client": client,
                "scope_guard": scope_guard,
                "browser": browser,
                "proxy": proxy,
                "email_mgr": email_mgr,
                "tool_runner": tool_runner,
                "budget": budget,
                "kill_switch_checker": None,
                "hexstrike_client": hexstrike_client,
                "thread_id": f"standalone_{target}",
            }
        }

        output_path = args.output or ""
        initial_state = {
            "target_url": target,
            "session_id": f"standalone_{target}",
            "passive_recon": {},
            "config": {"output_path": output_path},
            "budget_spent": 0,
            "budget_limit": budget_limit,
            "kill_switch_active": False,
            "phase": "planning",
        }

        start_time = time.time()
        result = {}
        graph_error = None
        try:
            result = await active_subgraph.ainvoke(initial_state, config=subgraph_config)
        except Exception as e:
            graph_error = str(e)
            logger.error("graph_crashed", error=graph_error)
            print(f"\n[!] Graph crashed: {graph_error}")
            print("[!] Attempting to recover partial findings...")

            # Recover partial findings from incremental save file
            import json as _recover_json
            _incremental_path = "/tmp/aibbp_incremental_findings.json"
            try:
                with open(_incremental_path) as _f:
                    partial = _recover_json.load(_f)
                result = partial
                print(f"[+] Recovered partial findings from {_incremental_path}")
                print(f"    Raw: {len(partial.get('raw_findings', []))}, "
                      f"Validated: {len(partial.get('validated_findings', []))}, "
                      f"Reports: {len(partial.get('reports', []))}")
            except FileNotFoundError:
                print("[!] No incremental findings file found")
            except Exception as re:
                print(f"[!] Recovery failed: {re}")

        elapsed = time.time() - start_time

        # Print results
        raw_findings = result.get("raw_findings", [])
        findings = result.get("validated_findings", [])
        reports = result.get("reports", [])
        errors = result.get("errors", [])
        if graph_error:
            errors = list(errors) + [f"Graph crashed: {graph_error}"]

        def _getf(obj: object, key: str, default: str = "N/A") -> str:
            """Get field from Pydantic model or dict."""
            if hasattr(obj, key):
                val = getattr(obj, key)
                return str(val) if val else default
            if isinstance(obj, dict):
                val = obj.get(key)
                return str(val) if val else default
            return default

        def _serialize_item(obj: object) -> dict:
            """Serialize Pydantic model or dict to dict."""
            if hasattr(obj, "model_dump"):
                return obj.model_dump()
            if isinstance(obj, dict):
                return obj
            return {"raw": str(obj)}

        print(f"\n{'='*60}")
        print(f"Active Test Complete{'  (PARTIAL - graph crashed)' if graph_error else ''}")
        print(f"{'='*60}")
        print(f"Target: {target}")
        print(f"Elapsed: {elapsed / 60:.1f} minutes")
        print(f"Raw findings: {len(raw_findings)}")
        print(f"Validated findings: {len(findings)}")
        confirmed = sum(
            1 for v in findings
            if (v.verified if hasattr(v, "verified") else v.get("verified", False) if isinstance(v, dict) else False)
        )
        print(f"Confirmed findings: {confirmed}")
        print(f"Reports: {len(reports)}")
        print(f"Errors: {len(errors)}")
        print(f"Budget spent: ${budget.total_spent:.4f}")

        # Show raw findings summary
        if raw_findings:
            print(f"\n--- Raw Findings ({len(raw_findings)}) ---")
            for i, rf in enumerate(raw_findings, 1):
                vuln = _getf(rf, "vuln_type")
                endpoint = _getf(rf, "endpoint")
                param = _getf(rf, "parameter", "")
                tool = _getf(rf, "tool_used", "")
                evidence = _getf(rf, "evidence", "")[:200]
                print(f"  [{i}] {vuln} at {endpoint}")
                if param and param != "N/A":
                    print(f"      Param: {param}")
                if tool and tool != "N/A":
                    print(f"      Tool: {tool}")
                if evidence and evidence != "N/A":
                    print(f"      Evidence: {evidence}")

        # Show validated findings
        if findings:
            print(f"\n--- Validated Findings ({len(findings)}) ---")
            for i, vf in enumerate(findings, 1):
                fid = _getf(vf, "finding_id")
                verified = _getf(vf, "verified", "False")
                method = _getf(vf, "verification_method", "")
                v_evidence = _getf(vf, "verification_evidence", "")[:200]
                print(f"  [{i}] {fid}: verified={verified}")
                if method and method != "N/A":
                    print(f"      Method: {method}")
                if v_evidence and v_evidence != "N/A":
                    print(f"      Evidence: {v_evidence}")

        # Show reports
        for i, report in enumerate(reports, 1):
            print(f"\n--- Report {i} ---")
            print(f"Title: {_getf(report, 'title')}")
            print(f"Severity: {_getf(report, 'severity')}")
            print(f"Type: {_getf(report, 'vuln_type')}")
            desc = _getf(report, "description", "")[:500]
            if desc and desc != "N/A":
                print(f"Description: {desc}")
            impact = _getf(report, "impact", "")[:300]
            if impact and impact != "N/A":
                print(f"Impact: {impact}")
            steps = getattr(report, "steps_to_reproduce", None) or (report.get("steps_to_reproduce") if isinstance(report, dict) else None)
            if steps:
                print(f"Steps to reproduce:")
                for s in steps[:10]:
                    print(f"    - {s}")

        if errors:
            print(f"\n--- Errors ({len(errors)}) ---")
            for err in errors[-10:]:
                print(f"  - {err}")

        # Always persist findings to JSON (even partial results)
        import json as _json
        _output_path = output_path or f"/tmp/aibbp_findings_{time.strftime('%Y%m%d_%H%M%S')}.json"
        try:
            output_data = {
                "target_url": target,
                "elapsed_seconds": int(elapsed),
                "budget_spent": budget.total_spent,
                "budget_limit": args.budget,
                "graph_error": graph_error,
                "raw_findings": [_serialize_item(f) for f in raw_findings],
                "validated_findings": [_serialize_item(f) for f in findings],
                "reports": [_serialize_item(r) for r in reports],
                "errors": list(errors)[-50:],
                "summary": {
                    "total_raw_findings": len(raw_findings),
                    "total_validated": len(findings),
                    "confirmed": confirmed,
                    "reports_generated": len(reports),
                },
            }
            with open(_output_path, "w") as f:
                _json.dump(output_data, f, indent=2, default=str)
            print(f"\nFindings saved to: {_output_path}")
        except Exception as e:
            print(f"\n[!] Failed to save findings: {e}")

        # Save individual report markdown files
        if reports:
            import os as _os
            _reports_dir = f"/tmp/aibbp_reports_{time.strftime('%Y%m%d_%H%M%S')}"
            _os.makedirs(_reports_dir, exist_ok=True)
            for _i, _report in enumerate(reports, 1):
                _r = _serialize_item(_report)
                _title = _r.get("title", f"Finding {_i}")
                _severity = _r.get("severity", "unknown")
                _md = [
                    f"# {_title}", "",
                    f"**Severity:** {_severity.upper()}",
                    f"**Type:** {_r.get('vuln_type', '')}",
                ]
                _cwe = _r.get("weakness_cwe", "")
                if _cwe:
                    _md.append(f"**CWE:** {_cwe}")
                _cvss = _r.get("cvss_score", 0)
                if _cvss:
                    _md.append(f"**CVSS:** {_cvss}")
                _md += ["", "## Description", "", _r.get("description", ""), ""]
                _impact = _r.get("impact", "")
                if _impact:
                    _md += ["## Impact", "", _impact, ""]
                _steps = _r.get("steps_to_reproduce", [])
                if _steps:
                    _md.append("## Steps to Reproduce")
                    _md.append("")
                    for _j, _s in enumerate(_steps, 1):
                        _md.append(f"{_j}. {_s}")
                    _md.append("")
                _poc = _r.get("poc_code", "")
                if _poc:
                    _md += ["## PoC", "", f"```{_r.get('poc_type', 'python')}", _poc, "```", ""]
                _remed = _r.get("remediation", "")
                if _remed:
                    _md += ["## Remediation", "", _remed, ""]
                _safe = "".join(c if c.isalnum() or c in " -_" else "" for c in _title)[:60].strip().replace(" ", "_")
                _fname = f"{_i:02d}_{_severity}_{_safe}.md"
                try:
                    with open(_os.path.join(_reports_dir, _fname), "w") as _f:
                        _f.write("\n".join(_md))
                except Exception:
                    pass
            print(f"Reports saved to: {_reports_dir}")

    finally:
        try:
            await hexstrike_mgr.stop()
        except Exception:
            pass
        try:
            await browser.stop()
        except Exception:
            pass
        try:
            await proxy.stop()
        except Exception:
            pass
        try:
            await email_mgr.stop()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
