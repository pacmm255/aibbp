"""Knowledge graph for the ReAct pentesting agent.

Builds a NetworkX directed graph from the brain's accumulated knowledge
(endpoints, findings, hypotheses, accounts). Generates strategic insights
by analyzing graph structure — attack paths, high-value targets, unexplored
areas, and vulnerability chains.

Inspired by PentestAgent's ShadowGraph pattern.
"""

from __future__ import annotations

import json
from typing import Any

import networkx as nx
import structlog

logger = structlog.get_logger()

# Node types
HOST = "host"
ENDPOINT = "endpoint"
FINDING = "finding"
HYPOTHESIS = "hypothesis"
ACCOUNT = "account"
TECH = "technology"
PARAM = "parameter"


class KnowledgeGraph:
    """Auto-maintained knowledge graph derived from pentest state."""

    def __init__(self) -> None:
        self.G = nx.DiGraph()
        self._last_state_hash = ""

    def rebuild(self, state: dict[str, Any]) -> None:
        """Rebuild the graph from current state dicts.

        Called before generating insights. Only rebuilds if state changed.
        """
        state_hash = self._compute_hash(state)
        if state_hash == self._last_state_hash:
            return
        self._last_state_hash = state_hash

        self.G.clear()
        target = state.get("target_url", "")

        # Extract host from target
        if target:
            from urllib.parse import urlparse

            parsed = urlparse(target)
            host = parsed.netloc or parsed.hostname or target
            self.G.add_node(host, type=HOST, url=target)

        # Add technologies
        for tech in state.get("tech_stack", []):
            self.G.add_node(f"tech:{tech}", type=TECH, name=tech)
            if target:
                self.G.add_edge(host, f"tech:{tech}", relation="runs")

        # Add endpoints
        for url, info in state.get("endpoints", {}).items():
            ep_id = f"ep:{url}"
            self.G.add_node(ep_id, type=ENDPOINT, url=url, **info)
            if target:
                self.G.add_edge(host, ep_id, relation="exposes")

            # Extract parameters as nodes
            params = info.get("params", {})
            if isinstance(params, dict):
                for pname, pval in params.items():
                    param_id = f"param:{url}:{pname}"
                    self.G.add_node(
                        param_id, type=PARAM, name=pname, value=str(pval),
                        endpoint=url,
                    )
                    self.G.add_edge(ep_id, param_id, relation="accepts")

        # Add findings
        for fid, info in state.get("findings", {}).items():
            finding_id = f"finding:{fid}"
            self.G.add_node(finding_id, type=FINDING, **info)
            ep = info.get("endpoint", "")
            if ep:
                ep_id = f"ep:{ep}"
                self.G.add_edge(finding_id, ep_id, relation="affects")
            param = info.get("parameter", "")
            if param and ep:
                param_id = f"param:{ep}:{param}"
                if self.G.has_node(param_id):
                    self.G.add_edge(finding_id, param_id, relation="exploits")
            # Chain relationships
            chained_from = info.get("chained_from", "")
            if chained_from:
                self.G.add_edge(
                    f"finding:{chained_from}", finding_id, relation="chains_to",
                )

        # Add hypotheses
        for hid, info in state.get("hypotheses", {}).items():
            hyp_id = f"hyp:{hid}"
            self.G.add_node(hyp_id, type=HYPOTHESIS, **info)
            for ep in info.get("related_endpoints", []):
                ep_id = f"ep:{ep}"
                if self.G.has_node(ep_id):
                    self.G.add_edge(hyp_id, ep_id, relation="targets")

        # Add accounts
        for username, info in state.get("accounts", {}).items():
            acct_id = f"acct:{username}"
            self.G.add_node(acct_id, type=ACCOUNT, username=username, **info)
            if target:
                self.G.add_edge(acct_id, host, relation="authenticates_to")

    def generate_insights(self, state: dict[str, Any]) -> str:
        """Generate strategic insights from the knowledge graph.

        Returns a compact text block to inject into the system prompt.
        """
        self.rebuild(state)

        if self.G.number_of_nodes() < 2:
            return ""

        insights: list[str] = []

        # 1. Attack surface summary
        ep_count = sum(
            1 for _, d in self.G.nodes(data=True) if d.get("type") == ENDPOINT
        )
        finding_count = sum(
            1 for _, d in self.G.nodes(data=True) if d.get("type") == FINDING
        )
        param_count = sum(
            1 for _, d in self.G.nodes(data=True) if d.get("type") == PARAM
        )
        hyp_count = sum(
            1 for _, d in self.G.nodes(data=True) if d.get("type") == HYPOTHESIS
        )

        insights.append(
            f"Graph: {ep_count} endpoints, {param_count} params, "
            f"{finding_count} findings, {hyp_count} hypotheses"
        )

        # 2. High-value targets (endpoints with most parameters)
        ep_params: dict[str, int] = {}
        for node, data in self.G.nodes(data=True):
            if data.get("type") == ENDPOINT:
                param_edges = [
                    t for _, t, d in self.G.edges(node, data=True)
                    if d.get("relation") == "accepts"
                ]
                if param_edges:
                    ep_params[data.get("url", node)] = len(param_edges)
        if ep_params:
            top = sorted(ep_params.items(), key=lambda x: -x[1])[:5]
            insights.append(
                "High-value targets (most params): "
                + ", ".join(f"{url} ({n} params)" for url, n in top)
            )

        # 3. Untested endpoints (endpoints with no findings pointing to them)
        tested_eps = set()
        for node, data in self.G.nodes(data=True):
            if data.get("type") == FINDING:
                for _, target, edata in self.G.edges(node, data=True):
                    if edata.get("relation") == "affects":
                        tested_eps.add(target)
        all_eps = {
            node for node, data in self.G.nodes(data=True)
            if data.get("type") == ENDPOINT
        }
        untested = all_eps - tested_eps
        if untested and len(untested) <= 15:
            urls = [self.G.nodes[n].get("url", n) for n in list(untested)[:10]]
            insights.append(f"Untested endpoints ({len(untested)}): " + ", ".join(urls))
        elif untested:
            insights.append(f"Untested endpoints: {len(untested)} remaining")

        # 4. Auth-required endpoints without accounts
        auth_eps = [
            n for n, d in self.G.nodes(data=True)
            if d.get("type") == ENDPOINT and d.get("auth_required")
        ]
        acct_count = sum(
            1 for _, d in self.G.nodes(data=True) if d.get("type") == ACCOUNT
        )
        if auth_eps and acct_count == 0:
            insights.append(
                f"PRIORITY: {len(auth_eps)} auth-required endpoints found but "
                "NO accounts created. Register accounts to test authenticated surface."
            )

        # 5. Vulnerability chains
        chain_paths = self._find_vuln_chains()
        if chain_paths:
            for chain in chain_paths[:3]:
                insights.append(f"Vuln chain: {' -> '.join(chain)}")

        # 6. Pending hypotheses that target high-param endpoints
        pending_hyps = [
            (n, d) for n, d in self.G.nodes(data=True)
            if d.get("type") == HYPOTHESIS and d.get("status") == "pending"
        ]
        if pending_hyps:
            insights.append(
                f"Pending hypotheses: {len(pending_hyps)} — "
                "test these before forming new ones"
            )

        # 7. Technology-specific attack suggestions
        tech_attacks = self._suggest_tech_attacks(state)
        if tech_attacks:
            insights.append("Tech-specific attacks: " + "; ".join(tech_attacks[:3]))

        if not insights:
            return ""

        return "\n".join(f"  * {i}" for i in insights)

    def _find_vuln_chains(self) -> list[list[str]]:
        """Find vulnerability chain paths (finding → chains_to → finding)."""
        chains: list[list[str]] = []
        finding_nodes = [
            n for n, d in self.G.nodes(data=True) if d.get("type") == FINDING
        ]

        for fn in finding_nodes:
            # Follow chains_to edges
            chain = [self.G.nodes[fn].get("vuln_type", fn)]
            current = fn
            visited = {current}
            while True:
                next_findings = [
                    t for _, t, d in self.G.edges(current, data=True)
                    if d.get("relation") == "chains_to" and t not in visited
                ]
                if not next_findings:
                    break
                current = next_findings[0]
                visited.add(current)
                chain.append(self.G.nodes[current].get("vuln_type", current))

            if len(chain) > 1:
                chains.append(chain)

        return chains

    def _suggest_tech_attacks(self, state: dict[str, Any]) -> list[str]:
        """Suggest attacks based on detected technologies."""
        tech_stack = [t.lower() for t in state.get("tech_stack", [])]
        suggestions = []

        tech_attack_map = {
            "laravel": "Test Laravel debug mode (/_ignition), mass assignment, .env exposure",
            "php": "Test PHP type juggling, LFI via include params, deserialization",
            "wordpress": "Test wp-admin, xmlrpc.php, plugin vulns, user enumeration",
            "django": "Test Django debug mode, SSTI in templates, admin panel",
            "node": "Test prototype pollution, SSTI in Express/Pug, npm package vulns",
            "react": "Check for exposed source maps, API keys in JS bundles",
            "angular": "Test template injection in Angular expressions",
            "spring": "Test Spring Actuator endpoints, SpEL injection",
            "nginx": "Test path traversal via off-by-slash, alias misconfiguration",
            "apache": "Test .htaccess bypass, mod_status, server-info",
            "graphql": "Test GraphQL introspection, batch queries, injection in variables",
            "jwt": "Test JWT none algorithm, key confusion, weak secrets",
        }

        for tech in tech_stack:
            for key, attack in tech_attack_map.items():
                if key in tech:
                    suggestions.append(attack)

        return suggestions

    def _compute_hash(self, state: dict[str, Any]) -> str:
        """Compute a quick hash of state knowledge dicts."""
        parts = [
            str(len(state.get("endpoints", {}))),
            str(len(state.get("findings", {}))),
            str(len(state.get("hypotheses", {}))),
            str(len(state.get("accounts", {}))),
            str(len(state.get("tech_stack", []))),
        ]
        # Include a sample of keys for change detection
        for key in ("endpoints", "findings", "hypotheses"):
            d = state.get(key, {})
            if d:
                parts.append(",".join(sorted(d.keys())[:20]))
        return "|".join(parts)
