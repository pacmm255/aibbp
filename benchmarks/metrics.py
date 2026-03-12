"""Benchmark metrics for regression testing.

Tracks precision, false positive rate, replay success, time to first high,
cost per validated finding, duplicate reduction, scope violations, and
coverage ratio.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BenchmarkMetrics:
    """Comprehensive benchmark metrics."""

    # Core quality metrics
    validated_finding_precision: float = 0.0  # confirmed_true / total_reported
    false_positive_rate: float = 0.0  # false_positive / total_reported
    replay_success_rate: float = 0.0  # successful_replays / total_replays
    time_to_first_high: float = 0.0  # seconds to first high/critical
    cost_per_validated_finding: float = 0.0  # total_cost / confirmed_true
    duplicate_reduction_rate: float = 0.0  # 1 - (dupes / total_raw)
    scope_violations: int = 0  # MUST be 0
    coverage_ratio: float = 0.0  # tested_endpoints / total_endpoints

    # Raw counts
    total_reported: int = 0
    confirmed_true: int = 0
    false_positives: int = 0
    total_replays: int = 0
    successful_replays: int = 0
    total_raw: int = 0
    duplicates: int = 0
    total_endpoints: int = 0
    tested_endpoints: int = 0
    total_cost: float = 0.0

    def compute(self) -> None:
        """Compute derived metrics from raw counts."""
        if self.total_reported > 0:
            self.validated_finding_precision = self.confirmed_true / self.total_reported
            self.false_positive_rate = self.false_positives / self.total_reported
        if self.total_replays > 0:
            self.replay_success_rate = self.successful_replays / self.total_replays
        if self.confirmed_true > 0:
            self.cost_per_validated_finding = self.total_cost / self.confirmed_true
        if self.total_raw > 0:
            self.duplicate_reduction_rate = 1.0 - (self.duplicates / self.total_raw)
        if self.total_endpoints > 0:
            self.coverage_ratio = self.tested_endpoints / self.total_endpoints

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        return {
            "validated_finding_precision": round(self.validated_finding_precision, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "replay_success_rate": round(self.replay_success_rate, 4),
            "time_to_first_high": round(self.time_to_first_high, 1),
            "cost_per_validated_finding": round(self.cost_per_validated_finding, 4),
            "duplicate_reduction_rate": round(self.duplicate_reduction_rate, 4),
            "scope_violations": self.scope_violations,
            "coverage_ratio": round(self.coverage_ratio, 4),
            "total_reported": self.total_reported,
            "confirmed_true": self.confirmed_true,
            "false_positives": self.false_positives,
            "total_cost": round(self.total_cost, 4),
        }

    def passes_baseline(self, baseline: dict[str, Any]) -> tuple[bool, list[str]]:
        """Check if metrics pass baseline requirements.

        Args:
            baseline: Dict of metric_name → minimum_value.

        Returns:
            (passes, list of failure reasons)
        """
        failures: list[str] = []

        # Scope violations MUST be 0
        if self.scope_violations > 0:
            failures.append(f"scope_violations={self.scope_violations} (must be 0)")

        # Check configurable baselines
        for metric, min_val in baseline.items():
            actual = getattr(self, metric, None)
            if actual is not None and isinstance(actual, (int, float)):
                if actual < min_val:
                    failures.append(f"{metric}={actual:.4f} < {min_val}")

        return len(failures) == 0, failures

    @staticmethod
    def from_results(results: list[dict[str, Any]]) -> BenchmarkMetrics:
        """Build metrics from a list of benchmark results."""
        m = BenchmarkMetrics()
        for r in results:
            m.total_reported += r.get("findings_count", 0)
            m.confirmed_true += r.get("confirmed_count", 0)
            m.false_positives += r.get("fp_count", 0)
            m.total_cost += r.get("cost", 0.0)
            if r.get("time_to_first_high"):
                if m.time_to_first_high == 0 or r["time_to_first_high"] < m.time_to_first_high:
                    m.time_to_first_high = r["time_to_first_high"]
        m.compute()
        return m
