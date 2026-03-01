"""Entry point for running the AI brain as a module.

Usage:
    python -m ai_brain                           # Interactive mode
    python -m ai_brain --program-file scope.txt  # Run scan from file
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import structlog

from ai_brain.config import AIBrainConfig
from ai_brain.orchestrator import run_scan
from ai_brain.scope import ScopeEnforcer

logger = structlog.get_logger()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AIBBP AI Brain - Claude-powered bug bounty orchestrator"
    )
    parser.add_argument(
        "--program-file",
        type=str,
        help="Path to bug bounty program description file",
    )
    parser.add_argument(
        "--scan-id",
        type=str,
        default="",
        help="Unique scan ID for checkpointing",
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

    # Active testing flags
    parser.add_argument(
        "--active-test",
        action="store_true",
        default=False,
        help="Enable active testing engine (browser, proxy, tools)",
    )
    parser.add_argument(
        "--active-dry-run",
        action="store_true",
        default=False,
        help="Active testing dry run (AI reasons but no browser/network actions)",
    )
    parser.add_argument(
        "--active-target",
        type=str,
        default="",
        help="Test single URL instead of all targets",
    )

    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    config = AIBrainConfig()

    if not config.anthropic_api_key:
        # Check for OAuth credentials as fallback
        import pathlib, json as _json
        _creds = pathlib.Path.home() / ".claude" / ".credentials.json"
        _has_oauth = False
        if _creds.exists():
            try:
                _data = _json.loads(_creds.read_text())
                _has_oauth = bool(_data.get("claudeAiOauth", {}).get("accessToken"))
            except Exception:
                pass
        if not _has_oauth:
            logger.error("ANTHROPIC_API_KEY not set and no OAuth credentials found")
            sys.exit(1)
        logger.info("using_oauth_credentials", source=str(_creds))

    # Read program description
    if args.program_file:
        with open(args.program_file) as f:
            program_text = f.read()
    else:
        logger.info("Reading program description from stdin...")
        program_text = sys.stdin.read()

    if not program_text.strip():
        logger.error("Empty program description")
        sys.exit(1)

    # Set up scope enforcer
    scope = ScopeEnforcer(
        allowed_domains=args.allowed_domains,
        out_of_scope_domains=args.out_of_scope,
    )

    # Run the scan
    db_dsn = config.database.dsn
    result = await run_scan(
        program_text=program_text,
        config=config,
        scope=scope,
        scan_id=args.scan_id,
        db_dsn=db_dsn,
        active_testing=args.active_test,
        active_dry_run=args.active_dry_run,
        active_target=args.active_target,
    )

    # Output results
    reports = result.get("reports", [])
    budget = result.get("budget_summary", {})
    elapsed = result.get("elapsed_seconds", 0)

    print(f"\n{'='*60}")
    print(f"Scan Complete")
    print(f"{'='*60}")
    print(f"Reports generated: {len(reports)}")
    print(f"Elapsed time: {elapsed / 60:.1f} minutes")
    if budget:
        print(f"Budget spent: ${budget.get('total_spent', 0):.4f}")
        print(f"Budget remaining: ${budget.get('total_remaining', 0):.4f}")

    for i, report in enumerate(reports, 1):
        print(f"\n--- Report {i} ---")
        print(f"Title: {report.get('title', 'N/A')}")
        print(f"Severity: {report.get('severity', 'N/A')}")
        if report.get("type") == "attack_chain":
            print(f"Type: Attack Chain")
            print(f"Combined Severity: {report.get('combined_severity', 'N/A')}")


if __name__ == "__main__":
    asyncio.run(main())
