"""Adaptive work queue with scored hypothesis prioritization.

Replaces rigid phase gates with a priority-scored queue of work items.
Each item has a priority computed from impact, novelty, uncertainty,
program value, and policy compliance.

Usage:
    queue = AdaptiveWorkQueue(manifest)
    queue.seed_from_endpoints(endpoints, tested, tech_stack)
    top = queue.get_top_n(5)
    queue.mark_done(item_id, found_something=True)
"""

from __future__ import annotations

import math
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Literal


# ── Impact weights per technique ────────────────────────────────────────

_TECHNIQUE_IMPACT: dict[str, float] = {
    "sqli": 3.0,
    "rce": 3.5,
    "cmdi": 3.5,
    "ssti": 3.0,
    "ssrf": 2.5,
    "auth_bypass": 2.5,
    "idor": 2.0,
    "bac": 2.5,
    "xss": 1.5,
    "lfi": 2.0,
    "file_upload": 2.0,
    "jwt": 2.0,
    "xxe": 2.0,
    "nosqli": 2.5,
    "race_condition": 1.5,
    "csrf": 1.0,
    "redirect": 0.8,
    "cors": 0.5,
    "info_disc": 0.5,
    "graphql": 1.0,
    "deserialization": 3.0,
    "mass_assignment": 1.5,
    "http_smuggling": 2.0,
    "cache_poisoning": 1.5,
    "subdomain_takeover": 1.5,
    # AuthZ-specific
    "authz_role_pair": 2.5,
    "workflow_invariant": 2.0,
    "step_skip": 1.5,
    "tenant_isolation": 3.0,
    # Discovery
    "crawl": 0.3,
    "content_discovery": 0.5,
    "js_analysis": 0.7,
    "tech_detection": 0.3,
    "subdomain_enum": 0.4,
    # Scanning
    "nuclei_scan": 1.0,
    "info_disclosure_scan": 0.6,
    "auth_bypass_scan": 1.5,
    "csrf_scan": 0.8,
}


# ── Side-effect risk per technique ──────────────────────────────────────

_SIDE_EFFECT_RISK: dict[str, float] = {
    "sqli": 0.3,
    "cmdi": 0.6,
    "rce": 0.8,
    "file_upload": 0.5,
    "race_condition": 0.4,
    "mass_assignment": 0.3,
    "xss": 0.1,
    "ssrf": 0.2,
    "lfi": 0.1,
    "idor": 0.1,
    "crawl": 0.0,
    "content_discovery": 0.05,
    "js_analysis": 0.0,
}


# ── Work Item ───────────────────────────────────────────────────────────

@dataclass
class WorkItem:
    """A unit of testing work in the priority queue."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    category: Literal["discovery", "scan", "exploit", "validate", "report"] = "exploit"
    endpoint: str = ""
    technique: str = ""
    hypothesis: str = ""
    priority_score: float = 0.0
    expected_impact: float = 1.0
    novelty: float = 1.0
    verifier_uncertainty: float = 1.0
    program_value: float = 0.5
    policy_allowance: float = 1.0
    estimated_cost: float = 0.01
    side_effect_risk: float = 0.1
    status: Literal["pending", "active", "done", "blocked"] = "pending"
    depends_on: list[str] = field(default_factory=list)
    auth_context: str = ""
    created_at_turn: int = 0
    test_count: int = 0  # How many times this endpoint::technique has been tested

    def compute_priority(self) -> float:
        """Compute priority score from component values.

        Formula: (impact × novelty × uncertainty × program_value × policy_allowance)
                 / (cost × side_effect_risk)
        """
        numerator = (
            self.expected_impact
            * self.novelty
            * self.verifier_uncertainty
            * self.program_value
            * self.policy_allowance
        )
        denominator = max(self.estimated_cost, 0.001) * max(self.side_effect_risk, 0.01)
        self.priority_score = numerator / denominator
        return self.priority_score

    def to_dict(self) -> dict[str, Any]:
        """Serialize for LangGraph state storage."""
        return {
            "id": self.id,
            "category": self.category,
            "endpoint": self.endpoint,
            "technique": self.technique,
            "hypothesis": self.hypothesis,
            "priority_score": self.priority_score,
            "status": self.status,
            "auth_context": self.auth_context,
            "test_count": self.test_count,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> WorkItem:
        """Deserialize from LangGraph state."""
        item = WorkItem(
            id=d.get("id", str(uuid.uuid4())[:8]),
            category=d.get("category", "exploit"),
            endpoint=d.get("endpoint", ""),
            technique=d.get("technique", ""),
            hypothesis=d.get("hypothesis", ""),
            priority_score=d.get("priority_score", 0.0),
            status=d.get("status", "pending"),
            auth_context=d.get("auth_context", ""),
            test_count=d.get("test_count", 0),
        )
        return item


# ── Adaptive Work Queue ─────────────────────────────────────────────────

class AdaptiveWorkQueue:
    """Priority-scored queue replacing rigid phase gates.

    Items are scored by:
    - impact: vulnerability type severity weight
    - novelty: 1/(1+test_count) — high for untested pairs
    - uncertainty: 1.0 if no findings for this technique, 0.3 if found something
    - program_value: asset criticality from policy manifest
    - policy_allowance: 0.0 if prohibited, 1.0 if allowed
    - cost: estimated dollar cost of the test
    - side_effect_risk: risk of side effects (data mutation, etc.)
    """

    def __init__(self, manifest: Any | None = None) -> None:
        self._items: dict[str, WorkItem] = {}
        self._manifest = manifest
        self._found_techniques: set[str] = set()  # Techniques that found something
        self._discovery_done: dict[str, bool] = {}  # endpoint → has_discovery_scan

    def seed_from_endpoints(
        self,
        endpoints: dict[str, dict[str, Any]],
        tested_techniques: dict[str, bool],
        tech_stack: list[str] | None = None,
    ) -> None:
        """Populate queue from current state."""
        # Standard techniques to test per endpoint
        standard = [
            "sqli", "xss", "ssrf", "cmdi", "ssti", "idor", "lfi",
            "file_upload", "jwt", "race_condition", "info_disc",
        ]

        # Tech-stack-specific additions
        if tech_stack:
            ts_lower = " ".join(tech_stack).lower()
            if "graphql" in ts_lower:
                standard.append("graphql")
            if "java" in ts_lower or "spring" in ts_lower:
                standard.append("deserialization")
            if "node" in ts_lower or "express" in ts_lower:
                standard.append("mass_assignment")

        for ep_url, ep_info in endpoints.items():
            for technique in standard:
                key = f"{ep_url}::{technique}"
                if key in tested_techniques:
                    continue

                # Skip if already in queue
                existing = self._find_item(ep_url, technique)
                if existing:
                    continue

                impact = _TECHNIQUE_IMPACT.get(technique, 1.0)
                side_risk = _SIDE_EFFECT_RISK.get(technique, 0.1)

                # Compute program value from manifest
                program_value = 0.5
                policy_allowance = 1.0
                if self._manifest:
                    program_value = self._manifest.get_asset_criticality(ep_url)
                    if not self._manifest.is_test_allowed(technique, ep_url):
                        policy_allowance = 0.0

                # Determine category
                category: str = "exploit"
                if technique in ("crawl", "content_discovery", "js_analysis", "tech_detection", "subdomain_enum"):
                    category = "discovery"
                elif technique in ("nuclei_scan", "info_disclosure_scan", "auth_bypass_scan", "csrf_scan"):
                    category = "scan"

                # Auth-required endpoints get higher priority
                if ep_info.get("auth_required"):
                    impact *= 1.3

                item = WorkItem(
                    category=category,
                    endpoint=ep_url,
                    technique=technique,
                    expected_impact=impact,
                    novelty=1.0,
                    verifier_uncertainty=1.0,
                    program_value=program_value,
                    policy_allowance=policy_allowance,
                    side_effect_risk=side_risk,
                )
                item.compute_priority()
                self._items[item.id] = item

    def add_work_item(self, item: WorkItem) -> None:
        """Add a single work item."""
        item.compute_priority()
        self._items[item.id] = item

    def inject_discovery_items(self, new_endpoints: list[str]) -> None:
        """Re-enter discovery when new attack surface is found."""
        for ep_url in new_endpoints:
            if ep_url in self._discovery_done:
                continue
            for technique in ("crawl", "js_analysis", "content_discovery"):
                item = WorkItem(
                    category="discovery",
                    endpoint=ep_url,
                    technique=technique,
                    expected_impact=_TECHNIQUE_IMPACT.get(technique, 0.5),
                    novelty=1.0,
                )
                item.compute_priority()
                self._items[item.id] = item

    def get_top_n(self, n: int = 5, auth_context: str = "") -> list[WorkItem]:
        """Get top-N priority items with dependencies met."""
        done_ids = {
            item.id for item in self._items.values()
            if item.status == "done"
        }

        candidates = []
        for item in self._items.values():
            if item.status != "pending":
                continue
            if item.policy_allowance <= 0:
                continue
            # Check dependencies
            if item.depends_on and not all(dep in done_ids for dep in item.depends_on):
                continue
            # Auth context filter
            if auth_context and item.auth_context and item.auth_context != auth_context:
                continue
            candidates.append(item)

        # Sort by priority (descending)
        candidates.sort(key=lambda x: x.priority_score, reverse=True)
        return candidates[:n]

    def mark_done(self, item_id: str, found_something: bool = False) -> None:
        """Mark an item as done and update scores."""
        item = self._items.get(item_id)
        if not item:
            return
        item.status = "done"
        item.test_count += 1

        # Track discovery
        if item.category == "discovery":
            self._discovery_done[item.endpoint] = True

        # Update related items' novelty
        if found_something:
            self._found_techniques.add(item.technique)

        # Anti-fixation: reduce novelty for over-tested pairs
        for other in self._items.values():
            if other.status != "pending":
                continue
            if other.technique == item.technique and other.endpoint == item.endpoint:
                other.test_count = item.test_count
                other.novelty = 1.0 / (1.0 + other.test_count)
                other.compute_priority()

            # Reduce uncertainty for same technique on other endpoints
            if other.technique == item.technique:
                if found_something:
                    other.verifier_uncertainty = max(0.3, other.verifier_uncertainty * 0.8)
                other.compute_priority()

    def mark_done_by_key(self, endpoint: str, technique: str, found: bool = False) -> None:
        """Mark done by endpoint+technique key."""
        item = self._find_item(endpoint, technique)
        if item:
            self.mark_done(item.id, found)

    def should_block_exploitation(self) -> bool:
        """Soft gate: True if <40% of endpoints have any scan."""
        if not self._items:
            return False
        endpoints = {item.endpoint for item in self._items.values()}
        scanned = {
            item.endpoint for item in self._items.values()
            if item.status == "done" and item.category in ("discovery", "scan")
        }
        if not endpoints:
            return False
        ratio = len(scanned) / len(endpoints)
        return ratio < 0.4

    def build_prompt_section(self) -> str:
        """Build prompt section showing queue status."""
        top = self.get_top_n(10)
        if not top:
            return "Work queue: empty (all techniques tested)"

        lines = ["## Work Queue (top 10 by priority)"]
        for i, item in enumerate(top, 1):
            lines.append(
                f"{i}. [{item.category}] {item.technique} on {item.endpoint[:60]} "
                f"(priority={item.priority_score:.1f}, impact={item.expected_impact:.1f})"
            )

        # Stats
        total = len(self._items)
        done = sum(1 for it in self._items.values() if it.status == "done")
        pending = sum(1 for it in self._items.values() if it.status == "pending")
        lines.append(f"\nQueue: {pending} pending, {done} done, {total} total")

        return "\n".join(lines)

    def get_effective_phase(self) -> str:
        """Compute dominant category from top items → maps to phase."""
        top = self.get_top_n(5)
        if not top:
            return "reporting"

        cats = Counter(item.category for item in top)
        dominant = cats.most_common(1)[0][0]
        return {
            "discovery": "recon",
            "scan": "vuln_scan",
            "exploit": "exploitation",
            "validate": "exploitation",
            "report": "reporting",
        }.get(dominant, "exploitation")

    def get_stats(self) -> dict[str, Any]:
        """Get queue statistics."""
        total = len(self._items)
        by_status = Counter(item.status for item in self._items.values())
        by_category = Counter(item.category for item in self._items.values() if item.status == "pending")
        return {
            "total": total,
            "pending": by_status.get("pending", 0),
            "done": by_status.get("done", 0),
            "blocked": by_status.get("blocked", 0),
            "by_category": dict(by_category),
            "effective_phase": self.get_effective_phase(),
            "found_techniques": list(self._found_techniques),
        }

    def to_state_dict(self) -> dict[str, dict[str, Any]]:
        """Serialize queue for LangGraph state."""
        return {item.id: item.to_dict() for item in self._items.values()}

    def from_state_dict(self, state_dict: dict[str, dict[str, Any]]) -> None:
        """Restore queue from LangGraph state."""
        for item_id, item_data in state_dict.items():
            self._items[item_id] = WorkItem.from_dict(item_data)

    def _find_item(self, endpoint: str, technique: str) -> WorkItem | None:
        """Find an existing item by endpoint+technique."""
        for item in self._items.values():
            if item.endpoint == endpoint and item.technique == technique:
                return item
        return None
