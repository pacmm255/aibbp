"""Capability graph for vulnerability chaining with prerequisite/effect rules.

Replaces template-only chain_discovery.py with a graph-based approach.
Each finding grants capabilities, each test requires prerequisites.
BFS from current capabilities toward goal states suggests next tests.

Usage:
    graph = CapabilityGraph()
    graph.register_finding(finding_dict)
    chains = graph.find_reachable_goals(current_caps)
    suggestions = graph.suggest_next_tests(current_caps)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


# ── Capability ──────────────────────────────────────────────────────────

@dataclass
class Capability:
    """A capability gained or required in the attack graph."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    cap_type: Literal["read", "write", "execute", "escalate", "exfiltrate"] = "read"
    subject: str = ""  # e.g., "database", "session_token", "filesystem"
    scope: Literal["cross_role", "cross_tenant", "same_user", "unauthenticated"] = "same_user"
    verified: bool = False
    proof_id: str = ""  # Link to ProofPack/finding


# ── Vulnerability Effects ───────────────────────────────────────────────

@dataclass
class VulnEffect:
    """What a vulnerability type grants and requires."""

    vuln_type: str
    prerequisites: list[str] = field(default_factory=list)  # Capability IDs like "read:session_token"
    grants: list[str] = field(default_factory=list)  # Capability strings like "read:database"


# ~30 effect rules (replacing 15 templates)
VULN_EFFECTS: list[VulnEffect] = [
    VulnEffect("xss", [], ["read:session_token", "write:dom", "execute:client_js"]),
    VulnEffect("stored_xss", [], ["read:session_token", "write:dom", "execute:client_js", "escalate:account_takeover"]),
    VulnEffect("sqli", [], ["read:database", "write:database", "escalate:auth_bypass"]),
    VulnEffect("blind_sqli", [], ["read:database"]),
    VulnEffect("nosqli", [], ["read:database", "write:database"]),
    VulnEffect("ssrf", [], ["read:internal_network", "read:cloud_metadata"]),
    VulnEffect("rce", [], ["execute:os_command", "read:filesystem", "write:filesystem"]),
    VulnEffect("cmdi", [], ["execute:os_command", "read:filesystem", "write:filesystem"]),
    VulnEffect("ssti", [], ["execute:os_command", "read:filesystem"]),
    VulnEffect("lfi", [], ["read:filesystem", "read:source_code"]),
    VulnEffect("path_traversal", [], ["read:filesystem", "read:source_code"]),
    VulnEffect("file_upload", [], ["write:filesystem", "execute:webshell"]),
    VulnEffect("xxe", [], ["read:filesystem", "read:internal_network"]),
    VulnEffect("idor", [], ["read:cross_tenant_data", "write:cross_tenant_data"]),
    VulnEffect("bac", [], ["read:cross_role_data", "write:cross_role_data", "escalate:privilege"]),
    VulnEffect("auth_bypass", [], ["escalate:admin", "read:auth_data"]),
    VulnEffect("jwt", [], ["escalate:impersonation", "read:auth_data"]),
    VulnEffect("csrf", [], ["write:victim_action"]),
    VulnEffect("redirect", [], ["read:oauth_token", "escalate:phishing"]),
    VulnEffect("cors", ["read:session_token"], ["read:cross_origin_data"]),
    VulnEffect("race_condition", [], ["write:double_spend", "escalate:business_logic"]),
    VulnEffect("mass_assignment", [], ["write:privilege_field", "escalate:privilege"]),
    VulnEffect("deserialization", [], ["execute:os_command", "read:filesystem"]),
    VulnEffect("information_disclosure", [], ["read:config", "read:credentials"]),
    VulnEffect("user_enumeration", [], ["read:user_list"]),
    VulnEffect("subdomain_takeover", [], ["write:dns", "escalate:phishing"]),
    VulnEffect("http_smuggling", [], ["escalate:cache_poison", "read:internal_requests"]),
    VulnEffect("cache_poisoning", [], ["write:cached_response", "execute:client_js"]),
    VulnEffect("graphql", [], ["read:schema", "read:database"]),
    VulnEffect("ato", ["read:session_token"], ["escalate:account_takeover", "read:victim_data"]),
]

# Build lookup
_VULN_EFFECT_MAP: dict[str, VulnEffect] = {ve.vuln_type: ve for ve in VULN_EFFECTS}

# Goal states (what we're trying to reach)
GOAL_STATES: list[str] = [
    "execute:os_command",
    "exfiltrate:pii",
    "escalate:admin",
    "read:cloud_credentials",
    "escalate:account_takeover",
    "read:database",
    "write:filesystem",
]


# ── Chain ───────────────────────────────────────────────────────────────

@dataclass
class Chain:
    """A chain of vulnerabilities reaching a goal state."""

    chain_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    goal: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    current_capabilities: list[str] = field(default_factory=list)
    missing_capabilities: list[str] = field(default_factory=list)
    confidence: float = 0.0
    impact: str = "high"

    def describe(self) -> str:
        """Human-readable chain description."""
        step_descs = [f"  {i+1}. {s.get('vuln_type', '?')} → {', '.join(s.get('grants', []))}"
                      for i, s in enumerate(self.steps)]
        status = "COMPLETE" if not self.missing_capabilities else f"NEEDS: {', '.join(self.missing_capabilities)}"
        return f"Chain → {self.goal} [{status}]\n" + "\n".join(step_descs)


# ── Capability Graph ────────────────────────────────────────────────────

class CapabilityGraph:
    """Graph-based vulnerability chaining engine.

    Nodes are capabilities. Edges represent vulnerability effects.
    Findings add capabilities; BFS finds paths to goals.
    """

    def __init__(self) -> None:
        self._capabilities: dict[str, Capability] = {}
        self._findings: list[dict[str, Any]] = []
        self._granted: set[str] = set()  # Set of granted capability strings

        # Internal graph (networkx if available, otherwise dict-based)
        if HAS_NETWORKX:
            self._graph: Any = nx.DiGraph()
        else:
            self._adj: dict[str, set[str]] = {}  # Simple adjacency list fallback

    def register_finding(self, finding: dict[str, Any]) -> list[str]:
        """Register a finding and return newly granted capabilities."""
        vuln_type = finding.get("vuln_type", "").lower().strip()
        self._findings.append(finding)

        effect = _VULN_EFFECT_MAP.get(vuln_type)
        if not effect:
            # Try aliases
            aliases = {
                "reflected_xss": "xss", "cross_site_scripting": "xss",
                "sql_injection": "sqli", "command_injection": "cmdi",
                "server_side_request_forgery": "ssrf",
                "local_file_inclusion": "lfi", "directory_traversal": "path_traversal",
                "broken_access_control": "bac", "authentication_bypass": "auth_bypass",
                "account_takeover": "ato",
            }
            aliased = aliases.get(vuln_type, vuln_type)
            effect = _VULN_EFFECT_MAP.get(aliased)

        if not effect:
            return []

        new_caps: list[str] = []
        for cap_str in effect.grants:
            if cap_str not in self._granted:
                self._granted.add(cap_str)
                new_caps.append(cap_str)

                # Add to graph
                parts = cap_str.split(":", 1)
                cap = Capability(
                    cap_type=parts[0] if len(parts) > 1 else "read",
                    subject=parts[1] if len(parts) > 1 else cap_str,
                    verified=bool(finding.get("confirmed")),
                    proof_id=finding.get("finding_id", ""),
                )
                self._capabilities[cap_str] = cap

                # Add edges
                self._add_edge(vuln_type, cap_str)

        return new_caps

    def bootstrap_from_tech_stack(self, tech_stack: list[str]) -> None:
        """Seed potential capabilities from known tech vulnerabilities."""
        ts_lower = " ".join(tech_stack).lower()

        # Common tech → potential capabilities
        if "java" in ts_lower or "spring" in ts_lower:
            self._add_potential("deserialization", ["execute:os_command"])
        if "php" in ts_lower:
            self._add_potential("file_upload", ["write:filesystem", "execute:webshell"])
            self._add_potential("lfi", ["read:filesystem"])
        if "graphql" in ts_lower:
            self._add_potential("graphql", ["read:schema", "read:database"])
        if any(db in ts_lower for db in ("mysql", "postgres", "mssql", "sqlite")):
            self._add_potential("sqli", ["read:database", "write:database"])
        if any(cloud in ts_lower for cloud in ("aws", "gcp", "azure")):
            self._add_potential("ssrf", ["read:cloud_metadata", "read:cloud_credentials"])

    def find_reachable_goals(self, current_caps: set[str] | None = None) -> list[Chain]:
        """Find goal states reachable from current capabilities via BFS."""
        if current_caps is None:
            current_caps = self._granted

        chains: list[Chain] = []

        for goal in GOAL_STATES:
            if goal in current_caps:
                # Already reached this goal
                chains.append(Chain(
                    goal=goal,
                    steps=[{"vuln_type": "achieved", "grants": [goal]}],
                    current_capabilities=list(current_caps),
                    confidence=1.0,
                    impact="critical" if "execute" in goal or "admin" in goal else "high",
                ))
                continue

            # BFS from each granted capability toward goal
            path = self._find_path_to_goal(current_caps, goal)
            if path:
                missing = [step.get("requires", "") for step in path
                           if step.get("requires") and step["requires"] not in current_caps]
                chains.append(Chain(
                    goal=goal,
                    steps=path,
                    current_capabilities=list(current_caps),
                    missing_capabilities=missing,
                    confidence=0.3 if missing else 0.8,
                    impact="critical" if "execute" in goal or "admin" in goal else "high",
                ))

        # Sort by confidence descending, impact
        chains.sort(key=lambda c: (c.confidence, 1 if c.impact == "critical" else 0), reverse=True)
        return chains

    def suggest_next_tests(self, current_caps: set[str] | None = None) -> list[str]:
        """Identify missing capabilities to complete promising chains."""
        if current_caps is None:
            current_caps = self._granted

        suggestions: set[str] = set()

        for effect in VULN_EFFECTS:
            # Find effects whose grants include goal-adjacent capabilities
            for cap in effect.grants:
                if cap in GOAL_STATES and cap not in current_caps:
                    # This vuln type can reach a goal
                    if effect.prerequisites:
                        # Check if we have prerequisites
                        if all(p in current_caps for p in effect.prerequisites):
                            suggestions.add(f"Test {effect.vuln_type} (can reach {cap})")
                    else:
                        suggestions.add(f"Test {effect.vuln_type} (can reach {cap})")

        return sorted(suggestions)[:10]

    def get_chain_suggestions(self) -> str:
        """Build prompt section with chain analysis."""
        chains = self.find_reachable_goals()
        suggestions = self.suggest_next_tests()

        if not chains and not suggestions:
            return ""

        lines = ["## Vulnerability Chains"]

        if chains:
            for chain in chains[:5]:
                lines.append(chain.describe())

        if suggestions:
            lines.append("\n### Suggested Next Tests (chain-informed)")
            for s in suggestions[:7]:
                lines.append(f"- {s}")

        return "\n".join(lines)

    def _add_edge(self, from_node: str, to_node: str) -> None:
        """Add edge to internal graph."""
        if HAS_NETWORKX:
            self._graph.add_edge(from_node, to_node)
        else:
            if from_node not in self._adj:
                self._adj[from_node] = set()
            self._adj[from_node].add(to_node)

    def _add_potential(self, vuln_type: str, caps: list[str]) -> None:
        """Mark potential capabilities from tech stack."""
        for cap in caps:
            self._add_edge(f"potential:{vuln_type}", cap)

    def _find_path_to_goal(
        self,
        current_caps: set[str],
        goal: str,
    ) -> list[dict[str, Any]]:
        """BFS from any granted capability toward a goal."""
        # Simple approach: check which vuln effects can reach the goal
        for effect in VULN_EFFECTS:
            if goal in effect.grants:
                # Check if prerequisites are met
                prereqs_met = all(p in current_caps for p in effect.prerequisites)
                step = {
                    "vuln_type": effect.vuln_type,
                    "grants": effect.grants,
                    "requires": effect.prerequisites[0] if effect.prerequisites else "",
                    "prereqs_met": prereqs_met,
                }
                return [step]

        # Multi-hop: find effects that grant prerequisites of goal-reaching effects
        for goal_effect in VULN_EFFECTS:
            if goal not in goal_effect.grants:
                continue
            if not goal_effect.prerequisites:
                continue
            for prereq in goal_effect.prerequisites:
                if prereq in current_caps:
                    continue
                # Find effect that grants this prereq
                for bridge_effect in VULN_EFFECTS:
                    if prereq in bridge_effect.grants:
                        prereqs_met = all(p in current_caps for p in bridge_effect.prerequisites)
                        return [
                            {
                                "vuln_type": bridge_effect.vuln_type,
                                "grants": bridge_effect.grants,
                                "requires": "",
                                "prereqs_met": prereqs_met,
                            },
                            {
                                "vuln_type": goal_effect.vuln_type,
                                "grants": goal_effect.grants,
                                "requires": prereq,
                                "prereqs_met": False,
                            },
                        ]

        return []
