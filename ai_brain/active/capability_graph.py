"""Capability graph for vulnerability chaining with prerequisite/effect rules.

Replaces template-only chain_discovery.py with a graph-based approach.
Each finding grants capabilities, each test requires prerequisites.
BFS from current capabilities toward goal states suggests next tests.

Dynamic chain builder (`build_chains_from_state`) analyzes actual findings,
credentials, and tech stack to propose novel attack chains, replacing the
static 15-template system.

Usage:
    graph = CapabilityGraph()
    graph.register_finding(finding_dict)
    chains = graph.find_reachable_goals(current_caps)
    suggestions = graph.suggest_next_tests(current_caps)

    # Dynamic chains from full agent state:
    dynamic_chains = build_chains_from_state(state_dict)
    ranked = rank_chains(dynamic_chains)
"""

from __future__ import annotations

import hashlib
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


# ── Impact Scoring ─────────────────────────────────────────────────────

_IMPACT_SCORES: dict[str, int] = {
    "execute:os_command": 10,
    "escalate:admin": 10,
    "escalate:account_takeover": 9,
    "read:cloud_credentials": 9,
    "exfiltrate:pii": 8,
    "read:database": 8,
    "write:filesystem": 7,
    "read:victim_data": 7,
    "escalate:impersonation": 7,
    "write:database": 7,
    "escalate:auth_bypass": 7,
    "read:internal_network": 6,
    "read:cloud_metadata": 6,
    "execute:webshell": 9,
    "write:cross_tenant_data": 8,
    "read:cross_tenant_data": 7,
    "write:cross_role_data": 8,
    "read:cross_role_data": 6,
    "escalate:privilege": 8,
    "read:source_code": 5,
    "read:filesystem": 5,
    "read:auth_data": 5,
    "read:credentials": 6,
    "read:config": 4,
    "write:privilege_field": 7,
    "write:victim_action": 4,
    "write:double_spend": 6,
    "escalate:business_logic": 5,
    "read:user_list": 3,
    "read:session_token": 4,
    "write:dom": 3,
    "execute:client_js": 3,
    "read:oauth_token": 5,
    "escalate:phishing": 3,
    "read:cross_origin_data": 4,
    "write:dns": 4,
    "escalate:cache_poison": 4,
    "read:internal_requests": 5,
    "write:cached_response": 4,
    "read:schema": 3,
}


# ── Credential / Token Types ──────────────────────────────────────────

_CREDENTIAL_PATTERNS: dict[str, list[str]] = {
    # credential type -> list of capabilities it unlocks
    "jwt": ["escalate:impersonation", "read:auth_data"],
    "api_key": ["read:internal_network", "escalate:auth_bypass"],
    "session_cookie": ["read:session_token", "escalate:account_takeover"],
    "oauth_token": ["read:oauth_token", "escalate:impersonation"],
    "database_password": ["read:database", "write:database"],
    "admin_password": ["escalate:admin"],
    "aws_key": ["read:cloud_credentials", "read:cloud_metadata"],
    "secret_key": ["escalate:impersonation", "read:auth_data"],
}

# Tech -> attack patterns that become viable
_TECH_ATTACK_PATTERNS: dict[str, list[tuple[str, str]]] = {
    # tech -> [(vuln_type, description), ...]
    "php": [("lfi", "PHP filter wrappers for source code read"), ("file_upload", "PHP webshell upload")],
    "laravel": [("information_disclosure", ".env exposure"), ("mass_assignment", "is_admin field injection")],
    "django": [("ssti", "Django template injection"), ("information_disclosure", "DEBUG page secrets")],
    "spring": [("deserialization", "Java deserialization RCE"), ("ssrf", "Actuator endpoint SSRF")],
    "express": [("nosqli", "MongoDB NoSQL injection"), ("ssti", "Prototype pollution to RCE")],
    "node": [("nosqli", "MongoDB NoSQL injection"), ("ssti", "Prototype pollution to RCE")],
    "graphql": [("graphql", "Introspection + unprotected mutations"), ("idor", "Object-level auth bypass")],
    "jwt": [("jwt", "Algorithm confusion / weak secret"), ("auth_bypass", "Token forgery")],
    "aws": [("ssrf", "IMDSv1 metadata theft -> IAM keys"), ("information_disclosure", "S3 bucket enumeration")],
    "wordpress": [("file_upload", "Plugin upload RCE"), ("sqli", "Plugin SQL injection")],
    "nginx": [("path_traversal", "Off-by-slash alias traversal"), ("ssrf", "Proxy misconfiguration")],
    "apache": [("file_upload", ".htaccess upload"), ("path_traversal", "mod_proxy SSRF")],
}


# ── Dynamic Chain ──────────────────────────────────────────────────────

@dataclass
class DynamicChain:
    """An attack chain discovered from actual findings and observations."""

    chain_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    steps: list[str] = field(default_factory=list)
    source_findings: list[str] = field(default_factory=list)  # finding IDs
    impact_score: float = 0.0       # 0-10
    feasibility: float = 0.0        # 0-1 (1 = all prereqs met)
    novelty: float = 0.0            # 0-1 (1 = not a standard vuln type)
    overall_score: float = 0.0      # composite
    action: str = ""                # what the brain should do next

    def prompt_line(self) -> str:
        """One-line prompt representation for injection into dynamic state."""
        steps_str = " -> ".join(self.steps)
        return (
            f"[{self.overall_score:.1f}] {self.title}: {steps_str}\n"
            f"      Action: {self.action}"
        )


def _title_hash(title: str) -> str:
    """Hash a chain title for dedup."""
    return hashlib.md5(title.encode()).hexdigest()


def _dedup_append(chain: DynamicChain, chains: list[DynamicChain], seen: set[str]) -> None:
    """Append chain if its title hasn't been seen."""
    h = _title_hash(chain.title)
    if h not in seen:
        seen.add(h)
        chains.append(chain)


def build_chains_from_state(state: dict[str, Any]) -> list[DynamicChain]:
    """Analyze current state to propose novel attack chains.

    Examines findings, credentials/tokens, tech stack, and endpoints to
    build chains from ACTUAL observations, not predefined templates.
    Returns a list of DynamicChain objects (unsorted).
    """
    findings = state.get("findings", {})
    tech_stack = state.get("tech_stack", [])
    endpoints = state.get("endpoints", {})
    working_memory = state.get("working_memory", {})

    chains: list[DynamicChain] = []
    seen_hashes: set[str] = set()

    # Build capability graph once, reuse across sub-builders
    graph = CapabilityGraph()
    finding_caps: dict[str, list[str]] = {}
    for fid, fdata in findings.items():
        if isinstance(fdata, dict):
            finding_caps[fid] = graph.register_finding(fdata)

    # 1. Finding-to-finding chains: A's output is B's input
    _build_finding_chains(findings, finding_caps, chains, seen_hashes)

    # 2. Credential/token chains: found creds unlock endpoints
    _build_credential_chains(findings, working_memory, endpoints, chains, seen_hashes)

    # 3. Tech-stack chains: detected tech enables specific attacks
    _build_tech_chains(tech_stack, findings, endpoints, chains, seen_hashes)

    # 4. Cross-reference chains: findings + endpoints that haven't been combined
    _build_cross_reference_chains(findings, endpoints, graph._granted, chains, seen_hashes)

    return chains


def _build_finding_chains(
    findings: dict[str, dict[str, Any]],
    finding_caps: dict[str, list[str]],
    chains: list[DynamicChain],
    seen: set[str],
) -> None:
    """Build chains where one finding's output enables another's escalation.

    Also adds direct goal-path chains for single findings.
    Uses pre-built finding_caps from build_chains_from_state.
    """
    # Single findings that directly reach a goal
    for fid, caps in finding_caps.items():
        fdata = findings.get(fid)
        if not isinstance(fdata, dict):
            continue
        for cap in caps:
            if cap in GOAL_STATES:
                vtype = fdata.get("vuln_type", "")
                ep = fdata.get("endpoint", "")
                _dedup_append(DynamicChain(
                    title=f"{vtype} at {ep} -> {cap}",
                    description=f"Direct path: {vtype} already grants {cap}",
                    steps=[f"Exploit {vtype} at {ep}"],
                    source_findings=[fid],
                    impact_score=_IMPACT_SCORES.get(cap, 5),
                    feasibility=1.0,
                    novelty=0.2,
                    action=f"Verify and demonstrate {cap} via {vtype} at {ep}",
                ), chains, seen)

    # Pairwise chains: A's grants satisfy B's prerequisites
    fids = list(finding_caps.keys())
    for i, fid_a in enumerate(fids):
        caps_a = set(finding_caps.get(fid_a, []))
        if not caps_a:
            continue
        fdata_a = findings[fid_a]
        if not isinstance(fdata_a, dict):
            continue
        vtype_a = fdata_a.get("vuln_type", "")
        ep_a = fdata_a.get("endpoint", "")

        for fid_b in fids[i + 1:]:
            fdata_b = findings.get(fid_b)
            if not isinstance(fdata_b, dict):
                continue
            vtype_b = fdata_b.get("vuln_type", "")
            ep_b = fdata_b.get("endpoint", "")
            caps_b = set(finding_caps.get(fid_b, []))

            # Check both directions
            for chain in (
                _try_chain_pair(vtype_a, ep_a, caps_a, fid_a, vtype_b, ep_b, caps_b, fid_b),
                _try_chain_pair(vtype_b, ep_b, caps_b, fid_b, vtype_a, ep_a, caps_a, fid_a),
            ):
                if chain:
                    _dedup_append(chain, chains, seen)


def _try_chain_pair(
    vtype_a: str, ep_a: str, caps_a: set[str], fid_a: str,
    vtype_b: str, ep_b: str, caps_b: set[str], fid_b: str,
) -> DynamicChain | None:
    """Check if finding A enables escalation through finding B."""
    effect_b = _VULN_EFFECT_MAP.get(vtype_b)
    if not effect_b or not effect_b.prerequisites:
        return None

    # Do A's granted caps satisfy B's prerequisites?
    satisfied = [p for p in effect_b.prerequisites if p in caps_a]
    if not satisfied:
        return None

    # A enables B -- build a chain
    # What's the best goal reachable through B?
    best_goal = ""
    best_score = 0
    for cap in effect_b.grants:
        score = _IMPACT_SCORES.get(cap, 3)
        if score > best_score:
            best_score = score
            best_goal = cap

    if not best_goal:
        return None

    title = f"{vtype_a} + {vtype_b} -> {best_goal}"
    return DynamicChain(
        title=title,
        description=(
            f"Use {vtype_a} at {ep_a} to obtain {', '.join(satisfied)}, "
            f"then leverage {vtype_b} at {ep_b} to reach {best_goal}"
        ),
        steps=[
            f"Exploit {vtype_a} at {ep_a} (grants {', '.join(sorted(caps_a)[:3])})",
            f"Use {', '.join(satisfied)} to exploit {vtype_b} at {ep_b}",
            f"Achieve {best_goal}",
        ],
        source_findings=[fid_a, fid_b],
        impact_score=best_score,
        feasibility=1.0,  # all prereqs met by existing findings
        novelty=0.7,      # cross-finding chain is non-trivial
        action=f"Chain {vtype_a} output into {vtype_b} to demonstrate {best_goal}",
    )


def _build_credential_chains(
    findings: dict[str, dict[str, Any]],
    working_memory: dict[str, Any],
    endpoints: dict[str, dict[str, Any]],
    chains: list[DynamicChain],
    seen: set[str],
) -> None:
    """Build chains from credentials/tokens found in findings or working memory."""
    # Collect credentials from findings evidence
    cred_types: list[tuple[str, str, str]] = []  # (cred_type, source_fid, context)

    for fid, fdata in findings.items():
        if not isinstance(fdata, dict):
            continue
        evidence = str(fdata.get("evidence", "")).lower()
        vtype = fdata.get("vuln_type", "").lower()

        for cred_type in _CREDENTIAL_PATTERNS:
            if cred_type.replace("_", " ") in evidence or cred_type in evidence:
                cred_types.append((cred_type, fid, f"found in {vtype} finding"))
            elif cred_type in vtype:
                cred_types.append((cred_type, fid, f"finding type is {vtype}"))

    # Also check working memory for credentials
    for section_name, section_data in working_memory.items():
        if not isinstance(section_data, dict):
            continue
        section_str = str(section_data).lower()
        for cred_type in _CREDENTIAL_PATTERNS:
            if cred_type.replace("_", " ") in section_str or cred_type in section_str:
                cred_types.append((cred_type, f"wm:{section_name}", "from working memory"))

    # For each credential found, propose chains to endpoints it could unlock
    auth_endpoints = [
        url for url, info in endpoints.items()
        if info.get("auth_required")
    ]

    for cred_type, source, context in cred_types:
        unlocked_caps = _CREDENTIAL_PATTERNS.get(cred_type, [])
        if not unlocked_caps:
            continue

        best_cap = max(unlocked_caps, key=lambda c: _IMPACT_SCORES.get(c, 0))
        best_score = _IMPACT_SCORES.get(best_cap, 5)

        # Generic chain: credential -> escalation
        action_parts = [f"Use {cred_type} to access protected resources"]
        if auth_endpoints:
            action_parts.append(
                f"Try against: {', '.join(auth_endpoints[:3])}"
            )

        _dedup_append(DynamicChain(
            title=f"{cred_type} ({context}) -> {best_cap}",
            description=f"Credential '{cred_type}' {context} unlocks {', '.join(unlocked_caps)}",
            steps=[
                f"Extract {cred_type} ({context})",
                f"Use {cred_type} on protected endpoints",
                f"Achieve {best_cap}",
            ],
            source_findings=[source] if not source.startswith("wm:") else [],
            impact_score=best_score,
            feasibility=0.8,
            novelty=0.5,
            action=" | ".join(action_parts),
        ), chains, seen)


def _build_tech_chains(
    tech_stack: list[str],
    findings: dict[str, dict[str, Any]],
    endpoints: dict[str, dict[str, Any]],
    chains: list[DynamicChain],
    seen: set[str],
) -> None:
    """Build chains based on detected technology enabling specific attacks."""
    ts_lower = " ".join(tech_stack).lower()
    existing_vtypes = {
        f.get("vuln_type", "").lower() for f in findings.values() if isinstance(f, dict)
    }

    for tech, patterns in _TECH_ATTACK_PATTERNS.items():
        if tech not in ts_lower:
            continue
        for vtype, desc in patterns:
            if vtype in existing_vtypes:
                # Already found this vuln type -- propose escalation instead
                for fid, fdata in findings.items():
                    if not isinstance(fdata, dict):
                        continue
                    if fdata.get("vuln_type", "").lower() == vtype:
                        effect = _VULN_EFFECT_MAP.get(vtype)
                        if effect:
                            for cap in effect.grants:
                                if cap in GOAL_STATES:
                                    _dedup_append(DynamicChain(
                                        title=f"{tech}-aware: escalate {vtype} -> {cap}",
                                        description=f"Existing {vtype} on {tech} stack can reach {cap}",
                                        steps=[
                                            f"Leverage {vtype} finding ({tech}-specific techniques)",
                                            f"Escalate to {cap}",
                                        ],
                                        source_findings=[fid],
                                        impact_score=_IMPACT_SCORES.get(cap, 5),
                                        feasibility=0.9,
                                        novelty=0.4,
                                        action=f"Use {tech}-specific {desc} to escalate {vtype}",
                                    ), chains, seen)
                        break
            else:
                # New attack vector enabled by tech
                effect = _VULN_EFFECT_MAP.get(vtype)
                best_cap = ""
                best_score = 0
                if effect:
                    for cap in effect.grants:
                        s = _IMPACT_SCORES.get(cap, 3)
                        if s > best_score:
                            best_score = s
                            best_cap = cap

                if best_score < 5:
                    continue  # only propose high-impact chains

                _dedup_append(DynamicChain(
                    title=f"{tech} enables {vtype} -> {best_cap}",
                    description=f"{tech} detected: {desc}",
                    steps=[
                        f"Test {vtype} ({tech}-specific: {desc})",
                        f"If successful, achieve {best_cap}",
                    ],
                    source_findings=[],
                    impact_score=best_score,
                    feasibility=0.5,  # not yet confirmed
                    novelty=0.6,
                    action=f"Test for {vtype} using {tech}-specific payloads: {desc}",
                ), chains, seen)


def _build_cross_reference_chains(
    findings: dict[str, dict[str, Any]],
    endpoints: dict[str, dict[str, Any]],
    granted: set[str],
    chains: list[DynamicChain],
    seen: set[str],
) -> None:
    """Cross-reference findings with untested endpoints for combination attacks.

    Uses pre-built `granted` capability set from build_chains_from_state.
    """
    if not findings or not endpoints:
        return

    # Find auth-required endpoints we haven't found vulns on
    finding_endpoints = {
        f.get("endpoint", "") for f in findings.values() if isinstance(f, dict)
    }

    untested_auth = [
        url for url, info in endpoints.items()
        if info.get("auth_required") and url not in finding_endpoints
    ]

    # If we have session_token capability and untested auth endpoints, propose IDOR/BAC chains
    if "read:session_token" in granted and untested_auth:
        _dedup_append(DynamicChain(
            title="Session token + auth endpoints -> IDOR/BAC",
            description=(
                f"Session tokens available. {len(untested_auth)} auth endpoints "
                f"untested for IDOR/BAC"
            ),
            steps=[
                "Use captured session tokens",
                f"Test IDOR/BAC on: {', '.join(untested_auth[:3])}",
                "Achieve cross-tenant/cross-role data access",
            ],
            source_findings=[],
            impact_score=8,
            feasibility=0.7,
            novelty=0.5,
            action=f"Test IDOR on {', '.join(untested_auth[:3])} with captured session",
        ), chains, seen)

    # If we have database read capability, propose credential extraction
    if "read:database" in granted:
        _dedup_append(DynamicChain(
            title="DB access -> credential extraction -> admin",
            description="Database read access can extract admin credentials",
            steps=[
                "Extract user table via existing DB access",
                "Crack or use admin credentials",
                "Achieve escalate:admin",
            ],
            source_findings=[],
            impact_score=10,
            feasibility=0.8,
            novelty=0.3,
            action="Extract credentials from database and attempt admin login",
        ), chains, seen)

    # If we can read filesystem, propose config/source code theft
    if "read:filesystem" in granted:
        _dedup_append(DynamicChain(
            title="Filesystem read -> config theft -> further exploitation",
            description="Filesystem access enables config files with secrets",
            steps=[
                "Read config files (.env, database.yml, web.config)",
                "Extract database credentials, API keys, secrets",
                "Use extracted creds for lateral movement",
            ],
            source_findings=[],
            impact_score=8,
            feasibility=0.9,
            novelty=0.3,
            action="Read config files to extract credentials and secrets",
        ), chains, seen)


def rank_chains(chains: list[DynamicChain]) -> list[DynamicChain]:
    """Score and rank chains by impact, feasibility, and novelty.

    Score formula: impact * 0.5 + feasibility * 10 * 0.3 + novelty * 10 * 0.2
    Returns sorted list (highest score first).
    """
    for chain in chains:
        chain.overall_score = (
            chain.impact_score * 0.5
            + chain.feasibility * 10 * 0.3
            + chain.novelty * 10 * 0.2
        )

    chains.sort(key=lambda c: c.overall_score, reverse=True)
    return chains


def build_dynamic_chain_prompt(state: dict[str, Any], max_chains: int = 3) -> str:
    """Build the prompt section for dynamic attack chains.

    Called from react_graph.context_compressor.
    Returns empty string if no meaningful chains found.
    Keeps output under 500 chars per the codebase convention.
    """
    chains = build_chains_from_state(state)
    if not chains:
        return ""

    ranked = rank_chains(chains)
    top = ranked[:max_chains]

    lines = ["## Active Attack Chains -- PURSUE THESE"]
    for chain in top:
        lines.append(chain.prompt_line())

    result = "\n".join(lines)
    # Cap at 500 chars as per convention
    if len(result) > 500:
        result = result[:497] + "..."
    return result
