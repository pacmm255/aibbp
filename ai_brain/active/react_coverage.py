"""UCB1 Coverage Work Queue for comprehensive endpoint testing.

Ensures the agent tests a broad set of endpoints rather than fixating on
a small subset. Uses UCB1 (Upper Confidence Bound) scoring to prioritize
untested (endpoint, technique) pairs.

Key features:
- Untested pairs get infinity priority (guaranteed first visit)
- Tested pairs scored by: exploitation_score + sqrt(2 * ln(total_tests) / times_tested) * estimated_value
- Value heuristics weight API/auth/admin/payment endpoints higher
- Minimum coverage gate: blocks deep exploitation until >= 60% coverage
"""

from __future__ import annotations

import math
import re
from typing import Any
from urllib.parse import urlparse

import structlog

from ai_brain.active.react_prompt import STANDARD_TECHNIQUES, _TOOL_TO_TECHNIQUE

logger = structlog.get_logger()

# ── Value heuristics for endpoint scoring ─────────────────────────────

# Substrings that indicate high-value endpoints (3x multiplier)
_HIGH_VALUE_PATTERNS = re.compile(
    r'(api|auth|admin|pay|checkout|transfer|billing|account|token|secret|'
    r'internal|graphql|webhook|oauth|password|session|upload|download)',
    re.IGNORECASE,
)

# Substrings that indicate dev/staging endpoints (2x multiplier)
_DEV_PATTERNS = re.compile(
    r'(dev|staging|test|debug|sandbox|beta|canary|preview)',
    re.IGNORECASE,
)

# Substrings that indicate low-value endpoints (0.5x multiplier)
_LOW_VALUE_PATTERNS = re.compile(
    r'(static|cdn|assets|images|fonts|favicon|robots\.txt|sitemap|\.css|\.png|\.jpg|\.svg|\.ico)',
    re.IGNORECASE,
)


def _endpoint_value(endpoint: str) -> float:
    """Estimate the value multiplier of an endpoint based on its path."""
    if _HIGH_VALUE_PATTERNS.search(endpoint):
        return 3.0
    if _DEV_PATTERNS.search(endpoint):
        return 2.0
    if _LOW_VALUE_PATTERNS.search(endpoint):
        return 0.5
    return 1.0


# ── Technique impact weights (shared with Thompson Sampling) ──────────

_TECHNIQUE_IMPACT: dict[str, float] = {
    "sqli": 3.0, "ssrf": 2.5, "cmdi": 2.5, "ssti": 2.5,
    "xss": 1.5, "idor": 2.0, "authz": 2.0, "lfi": 2.0,
    "upload": 1.5, "jwt": 2.0, "race": 1.5, "info_disc": 1.0,
    "diff": 1.0, "js_scan": 1.0, "graphql": 1.5, "fuzz": 1.0,
    "nosqli": 2.5, "xxe": 3.0, "deser": 3.0, "dos": 1.0, "jwt_deep": 2.5,
    "csrf": 1.5, "error_disc": 0.8, "crlf": 2.0, "header_injection": 1.5,
}

# Core techniques to track (subset of STANDARD_TECHNIQUES for efficiency)
# Only include techniques that are actionable via tools
_CORE_TECHNIQUES = [
    "sqli", "xss", "ssrf", "cmdi", "ssti", "idor", "authz",
    "lfi", "upload", "jwt", "fuzz", "info_disc", "diff",
]


class CoverageQueue:
    """Priority queue of (endpoint, technique) pairs using UCB1 scoring.

    Untested pairs always have the highest priority (infinity score).
    Tested pairs are scored using the UCB1 formula with value heuristics.
    """

    def __init__(self) -> None:
        # endpoint -> technique -> {tested: bool, score: float, times: int, last_turn: int}
        self._queue: dict[str, dict[str, dict[str, Any]]] = {}
        self._total_tests: int = 0
        self._total_endpoints: int = 0
        self._tested_endpoints: set[str] = set()

    def rebuild_from_state(
        self,
        endpoints: dict[str, Any],
        tested_techniques: dict[str, bool],
    ) -> None:
        """Rebuild the queue from current state.

        Called at the start of each brain turn to ensure the queue reflects
        the latest endpoint and tested_technique data.
        """
        self._queue.clear()
        self._tested_endpoints.clear()
        self._total_tests = 0

        # Build reverse map: technique -> tool names
        technique_to_tools: dict[str, list[str]] = {}
        for tool, tech in _TOOL_TO_TECHNIQUE.items():
            technique_to_tools.setdefault(tech, []).append(tool)

        for ep_url in endpoints:
            try:
                path = urlparse(ep_url).path or ep_url
            except Exception:
                path = ep_url

            # Normalize path for matching
            norm_path = path.rstrip("/").lower() or "/"

            self._queue[norm_path] = {}
            endpoint_has_test = False

            for tech in _CORE_TECHNIQUES:
                # Check if any tool for this technique was tested on this endpoint
                tool_names = technique_to_tools.get(tech, [tech])
                tested = any(
                    f"{norm_path}::{tn}" in tested_techniques
                    or f"{ep_url}::{tn}" in tested_techniques
                    or f"{path}::{tn}" in tested_techniques
                    for tn in tool_names
                )

                times = 1 if tested else 0
                self._queue[norm_path][tech] = {
                    "tested": tested,
                    "score": 0.0,
                    "times": times,
                }

                if tested:
                    self._total_tests += 1
                    endpoint_has_test = True

            if endpoint_has_test:
                self._tested_endpoints.add(norm_path)

        self._total_endpoints = len(self._queue)

    def get_coverage_ratio(self) -> float:
        """Return the ratio of endpoints that have at least one test."""
        if self._total_endpoints == 0:
            return 0.0
        return len(self._tested_endpoints) / self._total_endpoints

    def get_coverage_stats(self) -> dict[str, Any]:
        """Return coverage statistics."""
        total_pairs = sum(
            len(techs) for techs in self._queue.values()
        )
        tested_pairs = sum(
            1
            for techs in self._queue.values()
            for info in techs.values()
            if info["tested"]
        )
        return {
            "total_endpoints": self._total_endpoints,
            "tested_endpoints": len(self._tested_endpoints),
            "coverage_ratio": self.get_coverage_ratio(),
            "total_pairs": total_pairs,
            "tested_pairs": tested_pairs,
            "pair_coverage": tested_pairs / max(total_pairs, 1),
        }

    def mark_tested(self, endpoint: str, technique: str) -> None:
        """Mark an (endpoint, technique) pair as tested."""
        try:
            norm = urlparse(endpoint).path.rstrip("/").lower() or "/"
        except Exception:
            norm = endpoint.rstrip("/").lower() or "/"

        if norm in self._queue and technique in self._queue[norm]:
            entry = self._queue[norm][technique]
            if not entry["tested"]:
                entry["tested"] = True
                self._total_tests += 1
                self._tested_endpoints.add(norm)
            entry["times"] += 1

    def get_top_recommendations(self, n: int = 5) -> list[dict[str, Any]]:
        """Return top-N (endpoint, technique) pairs by UCB1 score.

        Untested pairs get infinity priority. Tested pairs are scored
        using UCB1: exploitation_score + exploration_bonus * endpoint_value.
        """
        candidates: list[tuple[float, str, str]] = []

        for endpoint, techs in self._queue.items():
            ep_value = _endpoint_value(endpoint)

            for tech, info in techs.items():
                tech_impact = _TECHNIQUE_IMPACT.get(tech, 1.0)

                if not info["tested"]:
                    # Untested: infinity priority (adjusted by value heuristics)
                    score = float("inf") * ep_value * tech_impact
                    # Use a large finite number for sorting instead of inf
                    sort_score = 1_000_000.0 * ep_value * tech_impact
                    candidates.append((sort_score, endpoint, tech))
                else:
                    # UCB1: exploitation + exploration bonus
                    times = max(info["times"], 1)
                    exploitation = info["score"]

                    if self._total_tests > 0:
                        exploration = math.sqrt(
                            2.0 * math.log(self._total_tests) / times
                        )
                    else:
                        exploration = 0.0

                    ucb1 = exploitation + exploration * ep_value * tech_impact
                    candidates.append((ucb1, endpoint, tech))

        # Sort by score descending
        candidates.sort(key=lambda x: x[0], reverse=True)

        results = []
        seen = set()
        for score, ep, tech in candidates:
            if len(results) >= n:
                break
            key = (ep, tech)
            if key in seen:
                continue
            seen.add(key)

            is_untested = not self._queue.get(ep, {}).get(tech, {}).get("tested", False)
            results.append({
                "endpoint": ep,
                "technique": tech,
                "score": round(min(score, 999999.0), 2),
                "untested": is_untested,
                "value": round(_endpoint_value(ep), 1),
            })

        return results

    def should_block_deep_exploitation(self) -> bool:
        """Return True if coverage is too low for deep exploitation.

        Coverage gate: at least 60% of endpoints must have >= 1 test
        before entering deep exploitation phase.
        """
        if self._total_endpoints <= 3:
            return False  # Too few endpoints to enforce coverage gate
        return self.get_coverage_ratio() < 0.60


def build_coverage_prompt_section(queue: CoverageQueue) -> str:
    """Build the coverage queue section for injection into the dynamic prompt.

    Returns a string like:
    COVERAGE QUEUE -- HIGHEST PRIORITY TARGETS:
    Coverage: 12/51 endpoints tested (23.5%) -- BELOW 60% GATE
    #1. [UNTESTED] /api/v1/users :: sqli (value=3.0)
    #2. [UNTESTED] /admin/settings :: authz (value=3.0)
    ...
    """
    stats = queue.get_coverage_stats()
    recs = queue.get_top_recommendations(n=5)

    if not recs and stats["total_endpoints"] == 0:
        return ""

    lines = [
        "### COVERAGE QUEUE -- HIGHEST PRIORITY TARGETS",
        f"  Coverage: {stats['tested_endpoints']}/{stats['total_endpoints']} "
        f"endpoints tested ({stats['coverage_ratio']*100:.1f}%)"
        f" | {stats['tested_pairs']}/{stats['total_pairs']} pairs tested "
        f"({stats['pair_coverage']*100:.1f}%)",
    ]

    if queue.should_block_deep_exploitation():
        lines.append(
            "  ** COVERAGE GATE: Below 60% endpoint coverage. "
            "You MUST test MORE endpoints before going deeper on known ones. **"
        )

    if recs:
        lines.append("")
        for i, rec in enumerate(recs, 1):
            tag = "[UNTESTED]" if rec["untested"] else f"[score={rec['score']:.1f}]"
            lines.append(
                f"  #{i}. {tag} {rec['endpoint']} :: {rec['technique']} "
                f"(value={rec['value']}x)"
            )

    lines.append(
        "  >> Test the UNTESTED pairs above before repeating tests on already-tested endpoints."
    )

    return "\n".join(lines)


def update_coverage_from_tool_call(
    queue: CoverageQueue,
    tool_name: str,
    tool_input: dict[str, Any],
) -> None:
    """Update the coverage queue after a tool call completes.

    Extracts the endpoint and technique from the tool call and marks it tested.
    """
    # Map tool name to technique
    technique = _TOOL_TO_TECHNIQUE.get(tool_name)
    if not technique:
        return

    # Extract endpoint from tool input
    endpoint = (
        tool_input.get("url")
        or tool_input.get("target")
        or tool_input.get("start_url")
        or tool_input.get("endpoint")
        or ""
    )
    if not endpoint:
        return

    queue.mark_tested(endpoint, technique)
