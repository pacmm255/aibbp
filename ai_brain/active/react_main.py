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
import fcntl
import json
import os
import resource
import signal
import sys
import time
from pathlib import Path
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

# Global RSS limit in bytes (set by --max-rss)
_max_rss_bytes: int = 700 * 1024 * 1024


def _check_rss_limit() -> bool:
    """Return True if current RSS exceeds the configured limit."""
    try:
        return get_rss_mb() * 1024 * 1024 >= _max_rss_bytes
    except Exception:
        return False


def get_rss_mb() -> int:
    """Return current RSS in MB (actual, not peak)."""
    try:
        # /proc/self/status VmRSS is current RSS (not peak like ru_maxrss)
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024  # kB → MB
    except Exception:
        pass
    try:
        # Fallback to peak RSS
        rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return rss_kb // 1024
    except Exception:
        return 0


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
        "--report-format", type=str, default="md", choices=["md", "html", "json"],
        help="Report format: md, html, or json (default: md)",
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
    parser.add_argument(
        "--upstream-proxy", type=str, default="",
        help="External SOCKS5/HTTP proxy URL (e.g. socks5://127.0.0.1:9054)",
    )
    parser.add_argument(
        "--proxy-port", type=int, default=0,
        help="Override mitmproxy port (default: 8085). Use different ports for parallel agents.",
    )
    # Z.ai (free GLM-5) mode
    parser.add_argument(
        "--zai", action="store_true", default=False,
        help="Use Z.ai GLM-5 (free) instead of Claude for the brain. Enables thinking.",
    )
    parser.add_argument(
        "--zai-model", type=str, default="glm-5",
        help="Z.ai model to use (default: glm-5). Options: glm-5, glm-4.7, glm-4.6v",
    )
    # Proxy pool for Z.ai rate limit bypass
    parser.add_argument(
        "--enable-proxylist", action="store_true", default=False,
        help="Use rotating proxy pool for Z.ai calls (bypass rate limits)",
    )
    parser.add_argument(
        "--proxy-ratelimit", type=float, default=3.0,
        help="Seconds between Z.ai calls per proxy IP (default: 3.0)",
    )
    parser.add_argument(
        "--min-proxies", type=int, default=10,
        help="Minimum healthy proxies before starting (default: 10)",
    )
    parser.add_argument(
        "--max-proxies", type=int, default=100,
        help="Maximum proxies to validate (default: 100)",
    )
    parser.add_argument(
        "--max-rss", type=int, default=700,
        help="Max RSS memory in MB per agent (default: 700). Agent exits gracefully when exceeded.",
    )
    parser.add_argument(
        "--no-app-gate", action="store_true", default=False,
        help="Disable app comprehension gate (allow exploitation without build_app_model)",
    )
    parser.add_argument(
        "--force-opus", action="store_true", default=False,
        help="Force Opus model for ALL turns (not just strategy/validation)",
    )
    parser.add_argument(
        "--force-sonnet", action="store_true", default=False,
        help="Force Sonnet model for ALL turns (no Opus escalation)",
    )
    # Agent C deep research
    parser.add_argument(
        "--zai-research", action="store_true", default=False,
        help="Enable Agent C deep research tool (uses Z.ai with web search + thinking). Requires --zai.",
    )
    # Docker sandbox
    parser.add_argument(
        "--docker-sandbox", action="store_true", default=False,
        help="Run security tools in Docker containers for isolation",
    )
    parser.add_argument(
        "--docker-image", type=str, default="kalilinux/kali-rolling",
        help="Docker image for sandbox containers (default: kalilinux/kali-rolling)",
    )
    # External tools
    parser.add_argument(
        "--external-tools", type=str, default="",
        help="Path or URL to JSON file with external tool definitions",
    )
    # Neo4j Knowledge Graph
    parser.add_argument(
        "--neo4j-uri", type=str, default="",
        help="Neo4j bolt URI (e.g., bolt://localhost:7687). Empty = disabled.",
    )

    # ChatGPT (free GPT-5.3) mode
    parser.add_argument(
        "--chatgpt", action="store_true", default=False,
        help="Use ChatGPT anonymous GPT-5.3 (free) instead of Claude for the brain.",
    )
    parser.add_argument(
        "--chatgpt-model", type=str, default="gpt-5-3",
        help="ChatGPT model slug (default: gpt-5-3). Options: gpt-5-3, gpt-5-2, gpt-5-1, gpt-5, gpt-5-mini, auto",
    )

    # Policy (Sprint 2)
    parser.add_argument(
        "--policy", type=str, default="",
        help="Path to policy YAML file for scope/rules/rate-limit enforcement",
    )
    parser.add_argument(
        "--mode", type=str, default="", choices=["", "public_bounty", "ctf", "cooperative"],
        help="Testing mode (default: auto-detect from budget)",
    )
    parser.add_argument(
        "--prohibited-tests", type=str, nargs="*", default=[],
        help="Prohibited test techniques (e.g., dos brute_force)",
    )

    # Dependency isolation (Sprint 5)
    parser.add_argument(
        "--experimental", action="store_true", default=False,
        help="Required gate for --zai, --chatgpt, --enable-proxylist",
    )
    parser.add_argument(
        "--stealth", action="store_true", default=False,
        help="Required gate for Goja TLS fingerprinting",
    )
    parser.add_argument(
        "--network-mode", type=str, default="host", choices=["host", "isolated"],
        help="Docker sandbox network mode (default: host)",
    )

    return parser.parse_args()


def _acquire_target_lock(target: str, memory_dir: str = "") -> int | None:
    """Acquire an exclusive file lock for a target URL.

    Returns the lock fd on success, None if another agent already holds it.
    Prevents duplicate agents on the same target from consuming memory.
    The memory_dir is included in the lock name so Agent A and Agent B
    (which use different memory dirs) can run the same target concurrently.
    """
    lock_dir = Path.home() / ".aibbp" / "agent_locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    # Sanitize target URL to filename
    safe = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    # Include memory dir suffix so different agents (A vs B) get separate locks
    if memory_dir and "targets_b" in memory_dir:
        safe += "_agent_b"
    lock_path = lock_dir / f"{safe}.lock"
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, f"{os.getpid()}\n".encode())
        os.fsync(fd)
        return fd
    except OSError:
        os.close(fd)
        # Read existing PID
        try:
            existing_pid = lock_path.read_text().strip()
        except Exception:
            existing_pid = "?"
        return None


async def main() -> None:
    global _shutdown_requested

    args = parse_args()
    config = AIBrainConfig()

    # Install SIGINT handler for graceful shutdown
    signal.signal(signal.SIGINT, _handle_sigint)

    # Prevent duplicate agents on the same target (OOM prevention)
    lock_fd = _acquire_target_lock(args.target, getattr(args, "memory_dir", ""))
    if lock_fd is None:
        print(f"[!] Another agent is already running for {args.target} — exiting to prevent OOM")
        sys.exit(1)

    # Set RSS memory limit for OOM prevention
    global _max_rss_bytes
    _max_rss_bytes = args.max_rss * 1024 * 1024
    logger.info("memory_limit_set", max_rss_mb=args.max_rss)

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
    if args.upstream_proxy:
        active_overrides["upstream_proxy"] = args.upstream_proxy
    if args.proxy_port:
        active_overrides["proxy_port"] = args.proxy_port
    active_cfg = ActiveTestingConfig(**active_overrides)

    # Budget — set per_target_max_dollars to match total so it doesn't cap early
    budget_cfg = BudgetConfig(total_dollars=args.budget, per_target_max_dollars=args.budget)
    budget = BudgetManager(budget_cfg, active_testing=True)

    # Dependency isolation (Sprint 5)
    if (args.zai or args.chatgpt or args.enable_proxylist) and not getattr(args, 'experimental', False):
        logger.warning("experimental_flag_required",
                        msg="--zai/--chatgpt/--enable-proxylist require --experimental flag. Proceeding anyway.")

    # Brain client — ChatGPT (free GPT-5.3), Z.ai (free GLM-5), or Claude
    proxy_pool = None
    if args.chatgpt:
        from ai_brain.active.chatgpt_client import ChatGPTClient

        client = ChatGPTClient(
            budget=budget,
            config=config,
            model=args.chatgpt_model,
            use_goja=False,  # Direct httpx — Cloudflare blocks public proxies & detects Goja
        )
        logger.info("using_chatgpt_brain", model=args.chatgpt_model)
        print(f"[*] Brain: ChatGPT {args.chatgpt_model} (free, anonymous, direct)")

        agent_c_research = None

        # Still need a Claude client for compression (Haiku)
        rate_limiter = DualRateLimiter(
            target_rps=3.0,
            api_rpm=config.rate_limits.requests_per_minute,
            api_itpm=config.rate_limits.input_tokens_per_minute,
        )
        circuit_breaker = CircuitBreaker()
        claude_client = ClaudeClient(
            config=config, budget=budget,
            rate_limiter=rate_limiter, circuit_breaker=circuit_breaker,
        )
    elif args.zai:
        from ai_brain.active.zai_client import ZaiClient

        if args.enable_proxylist:
            from ai_brain.active.proxy_pool import ProxyPool
            proxy_pool = ProxyPool(
                rate_limit_seconds=args.proxy_ratelimit,
                min_proxies=args.min_proxies,
                max_proxies=args.max_proxies,
            )
            print(f"[*] Warming proxy pool (min={args.min_proxies})...")
            await proxy_pool.warm()
            stats = proxy_pool.stats()
            print(f"[*] Proxy pool ready: {stats['healthy']}/{stats['total']} proxies, {args.proxy_ratelimit}s rate limit")

        client = ZaiClient(
            budget=budget,
            config=config,
            model=args.zai_model,
            enable_thinking=True,
            proxy_pool=proxy_pool,
        )
        logger.info("using_zai_brain", model=args.zai_model, proxy_pool=args.enable_proxylist)
        print(f"[*] Brain: Z.ai {args.zai_model} (free, with thinking)")

        # Agent C deep research tool
        agent_c_research = None
        if args.zai_research:
            from ai_brain.active.agent_c_research import AgentCResearch
            agent_c_research = AgentCResearch(zai_client=client, proxy_pool=proxy_pool)
            print(f"[*] Agent C: deep research enabled (Z.ai web search + thinking)")

        # Still need a Claude client for compression (Haiku)
        rate_limiter = DualRateLimiter(
            target_rps=3.0,
            api_rpm=config.rate_limits.requests_per_minute,
            api_itpm=config.rate_limits.input_tokens_per_minute,
        )
        circuit_breaker = CircuitBreaker()
        claude_client = ClaudeClient(
            config=config, budget=budget,
            rate_limiter=rate_limiter, circuit_breaker=circuit_breaker,
        )
    else:
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
        claude_client = client
        agent_c_research = None

    # Scope — flatten comma-separated values (supports both --allowed-domains "a,b" and --allowed-domains a b)
    _flat_allowed = [d.strip() for raw in args.allowed_domains for d in raw.split(",") if d.strip()]
    _flat_oos = [d.strip() for raw in args.out_of_scope for d in raw.split(",") if d.strip()]
    scope = ScopeEnforcer(
        allowed_domains=_flat_allowed,
        out_of_scope_domains=_flat_oos,
    )
    # Policy manifest (Sprint 2)
    from ai_brain.active.policy import PolicyCompiler
    policy_manifest = PolicyCompiler.from_cli_args(args)
    scope_guard = ActiveScopeGuard(scope, policy_manifest=policy_manifest)

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

    # Verifier (Sprint 2)
    from ai_brain.active.verifier import Verifier
    verifier = Verifier(scope_guard, claude_client=claude_client)

    # Target memory
    memory = TargetMemory(args.target, args.memory_dir)
    saved_memory: dict[str, Any] | None = None
    if not args.no_memory:
        saved_memory = memory.load()

    # Findings DB
    findings_db = None
    try:
        from ai_brain.active.findings_db import FindingsDB
        findings_db = FindingsDB()
        await findings_db.connect()
        print(f"[*] Findings DB: connected (PostgreSQL)")
    except Exception as _fdb_init_err:
        print(f"[*] Findings DB: unavailable ({_fdb_init_err}) — using JSON only")
        findings_db = None

    # Docker sandbox
    docker_executor = None
    if args.docker_sandbox:
        try:
            from ai_brain.active.docker_executor import DockerExecutor
            docker_executor = DockerExecutor(image=args.docker_image)
            await docker_executor.start()
            print(f"  Docker sandbox: ready ({args.docker_image})")
        except Exception as _docker_err:
            print(f"  Docker sandbox: unavailable ({_docker_err})")
            docker_executor = None

    # External tools
    if args.external_tools:
        try:
            from ai_brain.active.react_prompt import load_external_tools
            count = load_external_tools(args.external_tools)
            print(f"  External tools: {count} loaded from {args.external_tools}")
        except Exception as _ext_err:
            print(f"  External tools: failed to load ({_ext_err})")

    # Neo4j Knowledge Graph
    neo4j_kg = None
    if args.neo4j_uri:
        try:
            from ai_brain.active.neo4j_knowledge_graph import Neo4jKnowledgeGraph
            neo4j_kg = Neo4jKnowledgeGraph(uri=args.neo4j_uri)
            if await neo4j_kg.connect():
                print(f"  Neo4j: connected ({args.neo4j_uri})")
            else:
                print(f"  Neo4j: connection failed — using NetworkX fallback")
                neo4j_kg = None
        except Exception as _neo4j_err:
            print(f"  Neo4j: unavailable ({_neo4j_err}) — using NetworkX fallback")
            neo4j_kg = None

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
    if proxy_pool:
        stats = proxy_pool.stats()
        print(f"  Proxy pool: {stats['healthy']}/{stats['total']} proxies, {args.proxy_ratelimit}s rate limit")
    if active_cfg.upstream_proxy:
        print(f"  Proxy:      {active_cfg.upstream_proxy}")
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
        # Set upstream proxy env vars for subprocess tools (run_custom_exploit, etc.)
        if active_cfg.upstream_proxy:
            import os
            os.environ["ALL_PROXY"] = active_cfg.upstream_proxy
            os.environ["HTTPS_PROXY"] = active_cfg.upstream_proxy
            os.environ["HTTP_PROXY"] = active_cfg.upstream_proxy

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
                "claude_client": claude_client,  # Always Claude — for compression/vision
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
                "findings_db": findings_db,
                "agent_c_research": agent_c_research,
                "docker_executor": docker_executor,
                "verifier": verifier,
                "policy_manifest": policy_manifest,
                "deduplicator": None,  # Set below after session_learning
                "_neo4j_kg": neo4j_kg,
                "check_rss_limit": _check_rss_limit,
                "get_rss_mb": get_rss_mb,
                "max_rss_mb": args.max_rss,
                "force_opus": args.force_opus,
                "force_sonnet": args.force_sonnet,
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
            "app_model": {},
            "bandit_state": {},
            "_no_app_gate": args.no_app_gate,
            "phase": "running",
            # Hard phase gates: deterministic phase progression
            "current_phase": "recon",
            "phase_turn_count": 0,
            "phase_history": [],
            "consecutive_bookkeeping": 0,
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
            "sonnet_app_model_done": False,
            "sonnet_exploit_calls": 0,
            "opus_chain_reasoning_done": False,
            "reflector_retries": 0,
            "repeat_detector_state": {},
            "subtask_plan": [],
            "coverage_queue": {},
            "coverage_ratio": 0.0,
            "tool_health": {},
        }

        # ── Cross-session learning (warm start from Redis) ──
        session_learning = None
        try:
            from ai_brain.active.session_learning import SessionLearning
            from urllib.parse import urlparse
            _domain = urlparse(target).hostname or target
            session_learning = SessionLearning()
            if await session_learning.connect():
                warm_data = await session_learning.warm_start(_domain)
                if warm_data.get("bandit_state"):
                    initial_state["bandit_state"] = warm_data["bandit_state"]
                if warm_data.get("tech_stack"):
                    initial_state["tech_stack"] = warm_data["tech_stack"]
                if warm_data.get("waf_profile"):
                    initial_state["working_memory"]["waf_profiles"] = warm_data["waf_profile"]
                graph_config["configurable"]["session_learning"] = session_learning
        except Exception as _sl_err:
            logger.warning("session_learning_init_failed", error=str(_sl_err)[:200])

        # ── Semantic Finding Deduplicator ──
        try:
            from ai_brain.active.finding_dedup import FindingDeduplicator
            _redis_client = session_learning._redis if session_learning and hasattr(session_learning, "_redis") else None
            deduplicator = FindingDeduplicator(redis_client=_redis_client)
            graph_config["configurable"]["deduplicator"] = deduplicator
            logger.info("finding_deduplicator_initialized")
        except Exception as _dd_err:
            logger.warning("finding_deduplicator_init_failed", error=str(_dd_err)[:200])

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

        # ── Pre-flight health checks ─────────────────────────────
        try:
            from ai_brain.active.react_health import run_preflight_checks, ToolCircuitBreaker
            tool_health = await run_preflight_checks(graph_config)
            initial_state["tool_health"] = tool_health
            # Create circuit breaker and store in config for graph access
            circuit_breaker = ToolCircuitBreaker()
            graph_config["configurable"]["circuit_breaker"] = circuit_breaker
            _healthy = sum(1 for v in tool_health.values() if v == "healthy")
            _total = len(tool_health)
            print(f"  Pre-flight: {_healthy}/{_total} components healthy")
            for name, status in sorted(tool_health.items()):
                if status != "healthy":
                    print(f"    {name}: {status}")
        except Exception as _pf_err:
            logger.warning("preflight_checks_failed", error=str(_pf_err)[:200])
            graph_config["configurable"]["circuit_breaker"] = ToolCircuitBreaker()

        # Store timeout and start_time for checking in brain_node
        timeout = args.timeout
        start_time = time.time()
        result: dict[str, Any] = {}
        graph_error = None

        # Register scan in findings DB
        if findings_db:
            try:
                from urllib.parse import urlparse as _urlparse_scan
                _scan_domain = _urlparse_scan(target).hostname or target
                _brain_mode = "chatgpt" if args.chatgpt else "zai" if args.zai else "claude"
                await findings_db.upsert_scan(
                    session_id=initial_state["session_id"],
                    target_url=target,
                    domain=_scan_domain,
                    status="running",
                    budget_limit=args.budget,
                    brain_mode=_brain_mode,
                    transcript_path=str(transcript.path) if transcript.path else "",
                )
            except Exception as _scan_reg_err:
                logger.warning("scan_register_failed", error=str(_scan_reg_err)[:200])

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

        # Update scan record in findings DB
        if findings_db:
            try:
                _scan_status = "failed" if graph_error else "completed"
                _findings_count = len(result.get("findings", {})) if result else 0
                _confirmed_count = sum(1 for f in (result.get("findings", {}) or {}).values() if f.get("confirmed")) if result else 0
                _endpoints_count = len(result.get("endpoints", {})) if result else 0
                await findings_db.update_scan_stats(
                    session_id=initial_state["session_id"],
                    status=_scan_status,
                    turns=result.get("turn_count") if result else 0,
                    budget_spent=budget.total_spent,
                    findings_count=_findings_count,
                    confirmed_count=_confirmed_count,
                    endpoints_count=_endpoints_count,
                    tech_stack=result.get("tech_stack", []) if result else [],
                    error=graph_error,
                )
            except Exception as _scan_upd_err:
                logger.warning("scan_update_failed", error=str(_scan_upd_err)[:200])

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
            cost_bd = budget.cost_breakdown()
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
                "cost_breakdown": cost_bd,
            }
            with open(output_path, "w") as f:
                json.dump(output_data, f, indent=2, default=str)
            print(f"\nResults saved to: {output_path}")

            # Print cost breakdown
            if cost_bd.get("per_model"):
                print(f"\n--- Cost Breakdown ---")
                print(f"  Total: ${cost_bd['total']:.4f} ({cost_bd['call_count']} calls, avg ${cost_bd['avg_cost_per_call']:.6f})")
                for model, cost in list(cost_bd["per_model"].items())[:5]:
                    print(f"  {model}: ${cost:.4f}")
        except Exception as e:
            print(f"\n[!] Failed to save results: {e}")

        # Generate professional report
        if confirmed_findings:
            try:
                from ai_brain.active.report_generator import ReportGenerator
                rg = ReportGenerator()
                report = rg.generate(
                    findings=confirmed_findings,
                    target_url=target,
                    tech_stack=result.get("tech_stack", []),
                    attack_chains=result.get("attack_chains"),
                    format=args.report_format,
                    metadata={"elapsed_seconds": int(elapsed), "turns": turns},
                )
                ext = {"md": "md", "html": "html", "json": "report.json"}[args.report_format]
                report_path = output_path.rsplit(".", 1)[0] + f".{ext}"
                with open(report_path, "w") as f:
                    f.write(report)
                print(f"  Report saved to: {report_path}")
            except Exception as e:
                print(f"  [!] Report generation failed: {e}")

        # Final sync to findings DB
        if findings_db and findings:
            try:
                count = await findings_db.bulk_upsert(
                    findings,
                    domain=result.get("domain", ""),
                    target_url=target,
                    session_id=result.get("session_id", ""),
                )
                print(f"  Findings DB: {count} findings synced")
            except Exception as e:
                print(f"  [!] Findings DB final sync failed: {e}")

        # Save cross-session learning data
        if session_learning:
            try:
                from urllib.parse import urlparse
                _domain = urlparse(target).hostname or target
                await session_learning.save_bandit_state(_domain, result.get("bandit_state", {}))
                await session_learning.save_tech_stack(_domain, result.get("tech_stack", []))
                if findings:
                    await session_learning.record_findings_for_tech(
                        result.get("tech_stack", []), findings,
                    )
                await session_learning.close()
                print(f"  Cross-session learning saved")
            except Exception as e:
                print(f"  [!] Session learning save failed: {e}")

    finally:
        # Stop transcript logging
        try:
            transcript.stop()
        except Exception:
            pass

        if findings_db:
            try:
                await findings_db.close()
            except Exception:
                pass

        if proxy_pool:
            try:
                await proxy_pool.close()
            except Exception:
                pass

        if docker_executor:
            try:
                await docker_executor.stop()
            except Exception:
                pass

        if neo4j_kg:
            try:
                await neo4j_kg.close()
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
