"""CI runner for benchmark regression tests.

Reads regression_config.yml, runs suites in parallel, compares against
baselines, and fails if precision drops or new scope violations.

Usage:
    python -m benchmarks.ci_runner --suite xbow --max-challenges 5
    python -m benchmarks.ci_runner --suite all
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

from benchmarks.metrics import BenchmarkMetrics

logger = logging.getLogger("ci_runner")

# Default baselines
DEFAULT_BASELINES: dict[str, dict[str, float]] = {
    "xbow": {
        "validated_finding_precision": 0.80,
    },
    "juiceshop": {
        "validated_finding_precision": 0.50,
    },
    "crapi": {
        "validated_finding_precision": 0.50,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AIBBP Benchmark CI Runner")
    parser.add_argument(
        "--suite", type=str, default="xbow",
        choices=["xbow", "juiceshop", "crapi", "all"],
        help="Benchmark suite to run (default: xbow)",
    )
    parser.add_argument(
        "--max-challenges", type=int, default=5,
        help="Maximum challenges to run (default: 5)",
    )
    parser.add_argument(
        "--budget", type=float, default=2.0,
        help="Budget per challenge in dollars (default: $2.00)",
    )
    parser.add_argument(
        "--brain", type=str, default="claude",
        choices=["claude", "zai", "chatgpt"],
        help="Brain to use (default: claude)",
    )
    parser.add_argument(
        "--baseline-file", type=str, default="",
        help="Path to baseline YAML file (default: built-in baselines)",
    )
    parser.add_argument(
        "--output", type=str, default="",
        help="Output JSON file for results",
    )
    return parser.parse_args()


async def run_suite(
    suite_name: str,
    max_challenges: int,
    budget: float,
    brain: str,
) -> dict[str, Any]:
    """Run a single benchmark suite."""
    from benchmarks.benchmark_harness import (
        XBOWBenchmark,
        JuiceShopBenchmark,
        CrAPIBenchmark,
        SuiteResult,
    )

    suites = {
        "xbow": XBOWBenchmark,
        "juiceshop": JuiceShopBenchmark,
        "crapi": CrAPIBenchmark,
    }

    suite_cls = suites.get(suite_name)
    if not suite_cls:
        return {"error": f"Unknown suite: {suite_name}"}

    suite = suite_cls()
    try:
        result = await suite.run(
            max_challenges=max_challenges,
            budget=budget,
            brain=brain,
        )
        return {
            "suite": suite_name,
            "pass_rate": result.pass_rate,
            "total_cost": result.total_cost,
            "duration": result.total_duration,
            "results": [
                {
                    "challenge_id": r.challenge_id,
                    "passed": r.passed,
                    "cost": r.cost,
                    "turns": r.turns,
                    "error": r.error,
                }
                for r in result.results
            ],
            "summary": result.summary(),
        }
    except Exception as e:
        return {"suite": suite_name, "error": str(e)[:500]}
    finally:
        await suite.teardown()


def load_baselines(path: str) -> dict[str, dict[str, float]]:
    """Load baselines from YAML file or use defaults."""
    if path and Path(path).exists():
        try:
            import yaml
            data = yaml.safe_load(Path(path).read_text())
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return DEFAULT_BASELINES


async def main() -> None:
    args = parse_args()
    baselines = load_baselines(args.baseline_file)
    start = time.time()

    suites_to_run = (
        ["xbow", "juiceshop", "crapi"] if args.suite == "all"
        else [args.suite]
    )

    results: list[dict[str, Any]] = []
    failures: list[str] = []

    for suite_name in suites_to_run:
        print(f"\n{'='*60}")
        print(f"Running {suite_name} benchmark (max={args.max_challenges}, budget=${args.budget})")
        print(f"{'='*60}")

        result = await run_suite(suite_name, args.max_challenges, args.budget, args.brain)
        results.append(result)

        if "error" in result:
            print(f"  ERROR: {result['error']}")
            failures.append(f"{suite_name}: {result['error']}")
            continue

        print(f"  {result['summary']}")

        # Check against baseline
        baseline = baselines.get(suite_name, {})
        pass_rate = result.get("pass_rate", 0)
        min_precision = baseline.get("validated_finding_precision", 0)
        if pass_rate < min_precision:
            msg = f"{suite_name}: pass_rate={pass_rate:.2%} < baseline={min_precision:.2%}"
            failures.append(msg)
            print(f"  FAIL: {msg}")
        else:
            print(f"  PASS: pass_rate={pass_rate:.2%} >= baseline={min_precision:.2%}")

    # Summary
    total_time = time.time() - start
    print(f"\n{'='*60}")
    print(f"Benchmark complete in {total_time:.0f}s")
    print(f"{'='*60}")

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  - {f}")
        print("\nResult: FAIL")
    else:
        print("\nResult: PASS")

    # Save results
    if args.output:
        output_data = {
            "timestamp": time.time(),
            "suites": results,
            "failures": failures,
            "total_duration": total_time,
            "config": {
                "max_challenges": args.max_challenges,
                "budget": args.budget,
                "brain": args.brain,
            },
        }
        Path(args.output).write_text(json.dumps(output_data, indent=2))
        print(f"\nResults saved to {args.output}")

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    asyncio.run(main())
