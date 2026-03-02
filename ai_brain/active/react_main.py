"""CLI entry point for the single-brain ReAct pentesting agent.

Usage:
    python -m ai_brain.active.react_main --target https://example.com \
        --allowed-domains "*.example.com" \
        --budget 15.0

    # Indefinite mode (run until budget/timeout/Ctrl-C)
    python -m ai_brain.active.react_main --target https://example.com \
        --max-turns 0 --budget 50.0 --timeout 7200

    # Resume with target memory from prior sessions
    python -m ai_brain.active.react_main --target https://example.com \
        --max-turns 0 --budget 10.0

    # Fresh start (ignore saved memory)
    python -m ai_brain.active.react_main --target https://example.com \
        --no-memory --budget 5.0
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
import time
from typing import Any

import structlog

from ai_brain.active.browser import BrowserController
from ai_brain.active.captcha_solver import CaptchaSolver
from ai_brain.active.email import EmailManager
from ai_brain.active.goja_manager import GojaManager
from ai_brain.active.hexstrike_server import HexstrikeServerManager
from ai_brain.active.http_attacker import (
    AuthzTester,
    HTTPRepeater,
    TrafficAnalyzer,
    TrafficIntelligence,
)
from ai_brain.active.proxy import TrafficInterceptor
from ai_brain.active.react_graph import build_react_graph
from ai_brain.active.react_memory import TargetMemory
from ai_brain.active.react_transcript import TranscriptLogger
from ai_brain.active.scope_guard import ActiveScopeGuard
from ai_brain.active.tools import HexstrikeClient, ToolRunner
from ai_brain.budget import BudgetManager
from ai_brain.config import AIBrainConfig, ActiveTestingConfig, BudgetConfig
from ai_brain.errors import CircuitBreaker
from ai_brain.models import ClaudeClient
from ai_brain.rate_limiter import DualRateLimiter
from ai_brain.scope import ScopeEnforcer

logger = structlog.get_logger()


def _detect_external_goja(port: int) -> str | None:
    """Check if Goja is already running externally on the given port."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            logger.info("external_goja_detected", port=port)
            return f"socks5://127.0.0.1:{port}"
    except (ConnectionRefusedError, OSError):
        return None


# Global shutdown flag (set by SIGINT handler)
_shutdown_requested = False


def _handle_sigint(signum, frame):
    """Graceful shutdown: set flag so graph saves state and exits."""
    global _shutdown_requested
    if _shutdown_requested:
        # Second Ctrl-C = force exit
        print("\n[!] Forced exit.")
        sys.exit(1)
    _shutdown_requested = True
    logger.info("sigint_received", msg="Saving state and shutting down...")
    print("\n[*] Shutdown requested — finishing current turn and saving state...")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AIBBP ReAct Agent — Single-brain autonomous pentester",
    )
    parser.add_argument(
        "--target", type=str, required=True,
        help="Target URL to test",
    )
    parser.add_argument(
        "--allowed-domains", type=str, nargs="*", default=[],
        help="In-scope domains",
    )
    parser.add_argument(
        "--out-of-scope", type=str, nargs="*", default=[],
        help="Out-of-scope domains",
    )
    parser.add_argument(
        "--dry-run", action="store_true", default=False,
        help="AI reasons but no browser/network actions",
    )
    parser.add_argument(
        "--budget", type=float, default=15.0,
        help="Budget in dollars (default: $15.00)",
    )
    parser.add_argument(
        "--max-turns", type=int, default=150,
        help="Maximum brain turns (0 = indefinite, default: 150)",
    )
    parser.add_argument(
        "--timeout", type=int, default=0,
        help="Time limit in seconds (0 = no limit, default: 0)",
    )
    parser.add_argument(
        "--output", type=str, default="",
        help="Output JSON file path",
    )
    parser.add_argument(
        "--headless", action="store_true", default=True,
        help="Run browser in headless mode (default)",
    )
    parser.add_argument(
        "--no-headless", action="store_true", default=False,
        help="Run browser with visible UI",
    )
    parser.add_argument(
        "--demo", action="store_true", default=False,
        help="Demo mode (no API key needed)",
    )
    # Memory options
    parser.add_argument(
        "--no-memory", action="store_true", default=False,
        help="Start fresh — ignore saved target memory",
    )
    parser.add_argument(
        "--memory-dir", type=str, default="~/.aibbp/targets",
        help="Custom memory directory (default: ~/.aibbp/targets)",
    )
    # Email options
    parser.add_argument("--email-domain", type=str, default=None)
    parser.add_argument("--email-mode", type=str, default=None, choices=["local", "imap"])
    parser.add_argument("--imap-host", type=str, default=None)
    parser.add_argument("--imap-user", type=str, default=None)
    parser.add_argument("--imap-password", type=str, default=None)
    parser.add_argument("--email-plus-addressing", action="store_true", default=None)
    # Custom headers for bug bounty programs
    parser.add_argument(
        "--header", type=str, nargs="*", default=[],
        help='Custom headers as "Name: Value" pairs (e.g., --header "X-Bug-Bounty: test")',
    )
    # CAPTCHA solver options
    parser.add_argument(
        "--captcha-api-key", type=str, default="",
        help="2captcha/rucaptcha/capsolver API key for reCAPTCHA/hCaptcha/Turnstile solving",
    )
    parser.add_argument(
        "--captcha-api-url", type=str, default="https://2captcha.com",
        help="CAPTCHA service API URL (default: https://2captcha.com)",
    )
    return parser.parse_args()


async def main() -> None:
    global _shutdown_requested

    args = parse_args()
    config = AIBrainConfig()

    # Install SIGINT handler for graceful shutdown
    signal.signal(signal.SIGINT, _handle_sigint)

    if args.demo:
        config.demo_mode = True
    elif not config.anthropic_api_key and not config.anthropic_auth_token:
        from ai_brain.models import _read_claude_credentials
        if not _read_claude_credentials():
            logger.error(
                "No credentials found. Set ANTHROPIC_API_KEY, "
                "ANTHROPIC_AUTH_TOKEN, or install Claude Code."
            )
            sys.exit(1)

    # Active testing config
    active_overrides: dict[str, Any] = {
        "enabled": True,
        "dry_run": args.dry_run,
        "browser_headless": not args.no_headless,
    }
    for attr in ("email_domain", "email_mode", "imap_host", "imap_user",
                 "imap_password", "email_plus_addressing"):
        val = getattr(args, attr, None)
        if val is not None:
            active_overrides[attr] = val
    active_cfg = ActiveTestingConfig(**active_overrides)

    # Budget — set per_target_max_dollars to match total so it doesn't cap early
    budget_cfg = BudgetConfig(total_dollars=args.budget, per_target_max_dollars=args.budget)
    budget = BudgetManager(budget_cfg, active_testing=True)

    # Claude client
    rate_limiter = DualRateLimiter(
        target_rps=3.0,
        api_rpm=config.rate_limits.requests_per_minute,
        api_itpm=config.rate_limits.input_tokens_per_minute,
    )
    circuit_breaker = CircuitBreaker()
    client = ClaudeClient(
        config=config, budget=budget,
        rate_limiter=rate_limiter, circuit_breaker=circuit_breaker,
    )

    # Scope
    scope = ScopeEnforcer(
        allowed_domains=args.allowed_domains,
        out_of_scope_domains=args.out_of_scope,
    )
    scope_guard = ActiveScopeGuard(scope)

    # Infrastructure
    browser = BrowserController(scope_guard, active_cfg)
    proxy = TrafficInterceptor(scope_guard, active_cfg)
    email_mgr = EmailManager(active_cfg)
    tool_runner = ToolRunner(scope_guard, active_cfg)
    hexstrike_mgr = HexstrikeServerManager()
    hexstrike_client: HexstrikeClient | None = None
    goja_mgr = GojaManager()

    # HTTP-level testing infrastructure
    http_repeater = HTTPRepeater(scope_guard)
    authz_tester = AuthzTester(scope_guard)
    traffic_intelligence = TrafficIntelligence(scope_guard)
    traffic_analyzer = TrafficAnalyzer(scope_guard)

    # CAPTCHA solver
    captcha_api_key = args.captcha_api_key or active_cfg.captcha_api_key
    captcha_api_url = args.captcha_api_url or active_cfg.captcha_api_url
    captcha_solver = CaptchaSolver(
        api_key=captcha_api_key,
        api_url=captcha_api_url,
        vision_client=client,
    ) if captcha_api_key else CaptchaSolver(vision_client=client)

    # Target memory
    memory = TargetMemory(args.target, args.memory_dir)
    saved_memory: dict[str, Any] | None = None
    if not args.no_memory:
        saved_memory = memory.load()

    # Parse custom headers
    default_headers: dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            name, _, value = h.partition(":")
            default_headers[name.strip()] = value.strip()

    # Transcript logger
    transcript = TranscriptLogger(
        target_url=args.target,
        memory_dir=args.memory_dir,
    )

    target = args.target
    mode_str = "indefinite" if args.max_turns == 0 else f"{args.max_turns} turns"
    timeout_str = f"{args.timeout}s" if args.timeout > 0 else "none"

    print(f"\n{'='*60}")
    print(f"  AIBBP ReAct Agent — Single-Brain Pentester")
    print(f"{'='*60}")
    print(f"  Target:     {target}")
    print(f"  Budget:     ${args.budget:.2f}")
    print(f"  Mode:       {mode_str}")
    print(f"  Timeout:    {timeout_str}")
    print(f"  Dry run:    {args.dry_run}")
    if captcha_solver.has_service:
        print(f"  CAPTCHA:    2captcha API ({captcha_api_url})")
    else:
        print(f"  CAPTCHA:    image-only (Claude Vision) — add --captcha-api-key for reCAPTCHA/hCaptcha/Turnstile")
    if saved_memory:
        print(f"  Memory:     loaded ({saved_memory.get('total_sessions', 0)} prior sessions, "
              f"{len(saved_memory.get('tested_techniques', {}))} techniques)")
        if memory.is_stale(saved_memory):
            print(f"  Memory age: STALE (last: {saved_memory.get('last_session', '?')[:19]})")
    elif args.no_memory:
        print(f"  Memory:     disabled (--no-memory)")
    else:
        print(f"  Memory:     fresh start (no prior data)")
    print(f"{'='*60}\n")

    try:
        # Start infrastructure
        if not active_cfg.dry_run:
            await browser.start()
            await proxy.start(port=active_cfg.proxy_port)
            if email_mgr.is_configured:
                await email_mgr.start()

            try:
                await hexstrike_mgr.start(timeout=30)
                hexstrike_client = HexstrikeClient(
                    hexstrike_mgr.base_url, scope_guard, active_cfg.tools_timeout,
                )
                print(f"  HexStrike: ready ({hexstrike_mgr.base_url})")
            except Exception as e:
                logger.warning("hexstrike_start_failed", error=str(e))
                print(f"  HexStrike: unavailable ({e})")

            try:
                await goja_mgr.start(timeout=10)
                print(f"  Goja TLS proxy: ready ({goja_mgr.socks5_url})")
            except Exception as e:
                logger.warning("goja_start_failed", error=str(e))
                print(f"  Goja TLS proxy: unavailable ({e})")

        # Build the ReAct graph
        graph = build_react_graph()

        graph_config = {
            "recursion_limit": 10000,  # ~3333 turns (3 graph steps per turn)
            "configurable": {
                "client": client,
                "scope_guard": scope_guard,
                "browser": browser,
                "proxy": proxy,
                "email_mgr": email_mgr,
                "tool_runner": tool_runner,
                "budget": budget,
                "hexstrike_client": hexstrike_client,
                "goja_socks5_url": goja_mgr.socks5_url if goja_mgr.is_running else _detect_external_goja(goja_mgr.port),
                "http_repeater": http_repeater,
                "authz_tester": authz_tester,
                "traffic_intelligence": traffic_intelligence,
                "traffic_analyzer": traffic_analyzer,
                "captcha_solver": captcha_solver,
                "config": active_cfg,
                "max_turns": args.max_turns,
                "budget_limit": args.budget,
                "transcript": transcript,
                "default_headers": default_headers,
            },
        }

        initial_state = {
            "target_url": target,
            "session_id": f"react_{target}",
            "allowed_domains": args.allowed_domains,
            "endpoints": {},
            "findings": {},
            "hypotheses": {},
            "accounts": {},
            "tech_stack": [],
            "messages": [],
            "compressed_summary": "",
            "tool_output_files": {},
            "endpoints_snapshot": "{}",
            "findings_snapshot": "{}",
            "traffic_intelligence": {},
            "tested_techniques": {},
            "failed_approaches": {},
            "no_progress_count": 0,
            "last_result_hashes": [],
            "consecutive_failures": 0,
            "working_memory": {
                "attack_surface": {},
                "vuln_findings": {},
                "credentials": {},
                "attack_chain": {},
                "lessons": {},
                "response_signatures": {},
                "waf_profiles": {},
                "chain_evidence": {},
                "parameter_map": {},
            },
            "phase_budgets": {
                "recon": {"allocated_pct": 0.20, "spent": 0.0, "max_turns": 6, "turns_used": 0},
                "auth": {"allocated_pct": 0.10, "spent": 0.0, "max_turns": 4, "turns_used": 0},
                "exploitation": {"allocated_pct": 0.60, "spent": 0.0, "max_turns": 30, "turns_used": 0},
                "post_exploit": {"allocated_pct": 0.10, "spent": 0.0, "max_turns": 4, "turns_used": 0},
            },
            "hypothesis_budgets": {},
            "info_gain_history": [],
            "phase": "running",
            "budget_spent": 0.0,
            "budget_limit": args.budget,
            "turn_count": 0,
            "max_turns": args.max_turns,
            "done": False,
            "done_reason": "",
            "confidence": 0.5,
            "memory_path": str(memory.memory_path) if not args.no_memory else "",
            "_pending_tool_calls": [],
            "start_time": time.time(),
            "errors": [],
        }

        # Merge saved memory into initial state
        if saved_memory:
            initial_state = memory.merge_into_state(initial_state, saved_memory)

            # If very stale (>30 days), clear volatile data but keep techniques
            if memory.is_very_stale(saved_memory):
                initial_state["endpoints"] = {}
                initial_state["endpoints_snapshot"] = "{}"
                initial_state["tech_stack"] = []
                logger.info("memory_very_stale_cleared",
                            msg="Cleared endpoints/tech_stack (>30 days old)")

            # Add stale warning as user message
            if memory.is_stale(saved_memory):
                initial_state["messages"] = [{
                    "role": "user",
                    "content": (
                        f"NOTE: Previous session data is from "
                        f"{saved_memory.get('last_session', '?')[:19]}. "
                        f"Target may have changed. Re-verify key endpoints "
                        f"before deep testing."
                    ),
                }]

        # Start transcript logging
        transcript.start()
        print(f"  Transcript: {transcript.path}")
        if default_headers:
            print(f"  Headers:    {default_headers}")

        # Store timeout and start_time for checking in brain_node
        timeout = args.timeout
        start_time = time.time()
        result: dict[str, Any] = {}
        graph_error = None

        # Wrap graph invocation with shutdown and timeout checking
        # We use astream to check shutdown flag between iterations
        try:
            # Use ainvoke — the shutdown flag is checked via a custom
            # wrapper that sets done=True in state
            if _shutdown_requested:
                raise KeyboardInterrupt("Shutdown before start")

            # For timeout and SIGINT, we run the graph in a task
            # and monitor the flags
            async def _run_with_checks():
                """Run graph, periodically checking shutdown/timeout."""
                global _shutdown_requested
                # We can't interrupt ainvoke mid-way, but the brain_node
                # checks _shutdown_requested at the top of each turn.
                # For timeout, we use asyncio.wait_for.
                r = await graph.ainvoke(initial_state, config=graph_config)
                return r

            if timeout > 0:
                try:
                    result = await asyncio.wait_for(
                        _run_with_checks(),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    graph_error = f"Timeout after {timeout}s"
                    logger.warning("react_timeout", timeout=timeout)
                    print(f"\n[*] Timeout reached ({timeout}s)")
            else:
                result = await _run_with_checks()

        except KeyboardInterrupt:
            graph_error = "Shutdown requested (SIGINT)"
            logger.info("react_sigint_shutdown")
            print("\n[*] Graceful shutdown complete")
        except Exception as e:
            graph_error = str(e)
            logger.error("react_graph_crashed", error=graph_error)
            print(f"\n[!] Graph crashed: {graph_error}")

        elapsed = time.time() - start_time

        # On crash with empty result, load latest state from target memory
        if not result and not args.no_memory:
            try:
                saved = memory.load()
                if saved:
                    result = {
                        "findings": saved.get("findings", {}),
                        "endpoints": saved.get("endpoints", {}),
                        "hypotheses": saved.get("hypotheses", {}),
                        "accounts": saved.get("accounts", {}),
                        "tech_stack": saved.get("tech_stack", []),
                        "tested_techniques": saved.get("tested_techniques", {}),
                        "turn_count": saved.get("total_turns", 0),
                        "done_reason": graph_error or "unknown",
                        "errors": [graph_error] if graph_error else [],
                    }
                    print(f"  [*] Recovered state from target memory (findings={len(result['findings'])})")
            except Exception as mem_err:
                logger.warning("memory_recovery_failed", error=str(mem_err))

        # Save target memory (always, unless --no-memory)
        if not args.no_memory and result:
            try:
                memory.save(result)
                print(f"  Memory saved: {memory.memory_path}")
            except Exception as e:
                logger.warning("memory_save_failed", error=str(e))
                print(f"  [!] Memory save failed: {e}")

        # Print results
        findings = result.get("findings", {})
        hypotheses = result.get("hypotheses", {})
        endpoints = result.get("endpoints", {})
        accounts = result.get("accounts", {})
        errors = result.get("errors", [])
        done_reason = result.get("done_reason", "")
        turns = result.get("turn_count", 0)

        if graph_error:
            errors = list(errors) + [f"Graph error: {graph_error}"]
            if not done_reason:
                done_reason = graph_error

        confirmed_findings = {
            fid: f for fid, f in findings.items()
            if f.get("confirmed")
        }

        print(f"\n{'='*60}")
        print(f"  ReAct Test Complete{'  (INTERRUPTED)' if graph_error else ''}")
        print(f"{'='*60}")
        print(f"  Target:              {target}")
        print(f"  Elapsed:             {elapsed / 60:.1f} minutes")
        print(f"  Turns:               {turns}")
        print(f"  Done reason:         {done_reason}")
        print(f"  Endpoints found:     {len(endpoints)}")
        print(f"  Total findings:      {len(findings)}")
        print(f"  Confirmed findings:  {len(confirmed_findings)}")
        print(f"  Hypotheses:          {len(hypotheses)}")
        print(f"  Accounts created:    {len(accounts)}")
        print(f"  Budget spent:        ${budget.total_spent:.4f}")
        print(f"  Errors:              {len(errors)}")

        if findings:
            print(f"\n--- Findings ({len(findings)}) ---")
            for fid, f in findings.items():
                sev = f.get("severity", "?")
                vtype = f.get("vuln_type", "?")
                ep = f.get("endpoint", "?")
                confirmed = "CONFIRMED" if f.get("confirmed") else "unconfirmed"
                print(f"  [{sev}] {vtype} at {ep} ({confirmed})")
                evidence = f.get("evidence", "")
                if evidence:
                    print(f"        Evidence: {str(evidence)[:200]}")

        if hypotheses:
            print(f"\n--- Hypotheses ({len(hypotheses)}) ---")
            for hid, h in hypotheses.items():
                status = h.get("status", "?")
                desc = h.get("description", "?")
                print(f"  [{status}] {desc}")

        if errors:
            print(f"\n--- Errors ({len(errors)}) ---")
            for err in errors[-10:]:
                print(f"  - {err}")

        # Save findings to JSON
        output_path = args.output or f"/tmp/aibbp_react_{time.strftime('%Y%m%d_%H%M%S')}.json"
        try:
            output_data = {
                "target_url": target,
                "elapsed_seconds": int(elapsed),
                "turns": turns,
                "done_reason": done_reason,
                "budget_spent": budget.total_spent,
                "budget_limit": args.budget,
                "graph_error": graph_error,
                "endpoints": endpoints,
                "findings": findings,
                "confirmed_findings": confirmed_findings,
                "hypotheses": hypotheses,
                "accounts": {u: {k: v for k, v in a.items() if k != "cookies"} for u, a in accounts.items()},
                "tech_stack": result.get("tech_stack", []),
                "errors": list(errors)[-50:],
            }
            with open(output_path, "w") as f:
                json.dump(output_data, f, indent=2, default=str)
            print(f"\nResults saved to: {output_path}")
        except Exception as e:
            print(f"\n[!] Failed to save results: {e}")

    finally:
        # Stop transcript logging
        try:
            transcript.stop()
        except Exception:
            pass

        for name, service in [
            ("goja", goja_mgr),
            ("hexstrike", hexstrike_mgr),
            ("browser", browser),
            ("proxy", proxy),
            ("email", email_mgr),
        ]:
            try:
                await service.stop()
            except Exception:
                pass


if __name__ == "__main__":
    asyncio.run(main())
