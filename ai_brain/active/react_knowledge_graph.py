"""Knowledge graph for the ReAct pentesting agent.

Builds a NetworkX directed graph from the brain's accumulated knowledge
(endpoints, findings, hypotheses, accounts). Generates strategic insights
by analyzing graph structure -- attack paths, high-value targets, unexplored
areas, and vulnerability chains.

Cross-Endpoint Context Engine: surfaces relevant context when testing any
endpoint by finding structurally similar endpoints, shared parameters with
known findings, common auth middleware, and discovered tokens/credentials.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse

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
CREDENTIAL = "credential"
TOKEN = "token"

# Edge types (constants for consistency)
EDGE_EXPOSES = "exposes"
EDGE_USES_TECH = "uses_tech"
EDGE_SHARES_AUTH = "shares_auth"
EDGE_SIMILAR_RESPONSE = "similar_response"
EDGE_ACCEPTS = "accepts"
EDGE_AFFECTS = "affects"
EDGE_EXPLOITS = "exploits"
EDGE_CHAINS_TO = "chains_to"
EDGE_TARGETS = "targets"
EDGE_AUTHENTICATES = "authenticates_to"
EDGE_RUNS = "runs"

# Auth-related vuln types used to detect access control issues
_AUTH_VULN_TYPES = frozenset({
    "idor", "bac", "broken_access_control",
    "auth_bypass", "privilege_escalation", "bola",
})

# Max context chars per endpoint to avoid prompt bloat
MAX_CONTEXT_CHARS = 500

# Token-related keywords for extraction
_TOKEN_KEYWORDS = ("token", "jwt", "api_key", "secret", "bearer")
_COOKIE_TOKEN_KEYWORDS = ("token", "session", "jwt", "auth")


def _path_pattern(url: str) -> str:
    """Convert a URL path to a structural pattern by replacing IDs with {id}.

    /api/users/123/orders -> /api/users/{id}/orders
    /api/v2/items/abc-def -> /api/v2/items/{id}
    """
    try:
        path = urlparse(url).path or "/"
    except Exception:
        path = url
    segments = [s for s in path.split("/") if s]
    pattern_parts = []
    for seg in segments:
        # Numeric IDs, UUIDs, hex strings
        if re.match(r'^(\d+|[0-9a-f]{8,}|[0-9a-f-]{36})$', seg, re.IGNORECASE):
            pattern_parts.append("{id}")
        else:
            pattern_parts.append(seg)
    return "/" + "/".join(pattern_parts)


def _safe_node_attrs(info: dict[str, Any]) -> dict[str, Any]:
    """Filter dict to only hashable values safe for NetworkX node attributes."""
    return {
        k: v for k, v in info.items()
        if isinstance(v, (str, int, float, bool, type(None)))
    }


class KnowledgeGraph:
    """Auto-maintained knowledge graph with cross-endpoint intelligence."""

    def __init__(self) -> None:
        self.G = nx.DiGraph()
        self._last_state_hash = ""
        # Caches for cross-endpoint queries (rebuilt with graph)
        self._param_to_endpoints: dict[str, set[str]] = {}
        self._endpoint_params: dict[str, set[str]] = {}
        self._pattern_to_endpoints: dict[str, set[str]] = {}
        self._auth_groups: dict[str, set[str]] = {}
        self._param_findings: dict[str, list[dict[str, Any]]] = {}
        self._endpoint_findings: dict[str, list[dict[str, Any]]] = {}

    # ── Core rebuild (backward-compatible) ────────────────────────────

    def rebuild(self, state: dict[str, Any]) -> None:
        """Rebuild the graph from current state dicts.

        Called before generating insights. Only rebuilds if state changed.
        """
        state_hash = self._compute_hash(state)
        if state_hash == self._last_state_hash:
            return
        self._last_state_hash = state_hash
        self.G.clear()
        self._param_to_endpoints.clear()
        self._endpoint_params.clear()
        self._pattern_to_endpoints.clear()
        self._auth_groups.clear()
        self._param_findings.clear()
        self._endpoint_findings.clear()

        target = state.get("target_url", "")
        host = ""

        # Extract host from target
        if target:
            parsed = urlparse(target)
            host = parsed.netloc or parsed.hostname or target
            self.G.add_node(host, type=HOST, url=target)

        # Add technologies and collect their node IDs for endpoint linking
        tech_node_ids: list[tuple[str, str]] = []
        for tech in state.get("tech_stack", []):
            tech_id = f"tech:{tech}"
            self.G.add_node(tech_id, type=TECH, name=tech)
            tech_node_ids.append((tech_id, tech.lower()))
            if host:
                self.G.add_edge(host, tech_id, relation=EDGE_RUNS)

        # Add endpoints with cross-referencing
        endpoints = state.get("endpoints", {})
        for url, info in endpoints.items():
            self._add_endpoint(url, info, host, tech_node_ids)

        # Build auth sharing edges after all endpoints are added
        self._build_auth_edges(endpoints)

        # Build structural similarity edges
        self._build_similarity_edges()

        # Add findings and link to params
        for fid, info in state.get("findings", {}).items():
            self._add_finding(fid, info)

        # Add hypotheses
        for hid, info in state.get("hypotheses", {}).items():
            hyp_id = f"hyp:{hid}"
            self.G.add_node(hyp_id, type=HYPOTHESIS, **info)
            for ep in info.get("related_endpoints", []):
                ep_id = f"ep:{ep}"
                if self.G.has_node(ep_id):
                    self.G.add_edge(hyp_id, ep_id, relation=EDGE_TARGETS)

        # Add accounts
        for username, info in state.get("accounts", {}).items():
            acct_id = f"acct:{username}"
            self.G.add_node(acct_id, type=ACCOUNT, username=username, **info)
            if host:
                self.G.add_edge(acct_id, host, relation=EDGE_AUTHENTICATES)

        # Extract credentials and tokens from working memory
        working_memory = state.get("working_memory", {})
        self._extract_credentials(working_memory)
        self._extract_tokens(working_memory, state)

    def update_graph(self, state: dict[str, Any]) -> None:
        """Incremental update -- same as rebuild but with hash-based skip.

        Intended to be called from context_compressor node every turn.
        Delegates to rebuild which already handles change detection.
        """
        self.rebuild(state)

    # ── Cross-Endpoint Intelligence ───────────────────────────────────

    def get_context_for_endpoint(self, url: str) -> str:
        """Return cross-endpoint context relevant when testing a specific URL.

        Surfaces:
        - Similar parameters at other endpoints that had findings
        - Shared auth middleware patterns
        - Discovered tokens/credentials applicable here
        - Structurally similar endpoints and their test results

        Returns a compact string (max MAX_CONTEXT_CHARS).
        """
        if self.G.number_of_nodes() < 2:
            return ""

        lines: list[str] = []
        pattern = _path_pattern(url)

        # 1. Find params at this endpoint that share names with vulnerable params
        ep_params = self._endpoint_params.get(url, set())
        for pname in ep_params:
            findings_for_param = self._param_findings.get(pname, [])
            for f in findings_for_param:
                f_ep = f.get("endpoint", "")
                if f_ep and f_ep != url:
                    vtype = f.get("vuln_type", "?")
                    lines.append(
                        f"Param '{pname}' was {vtype} at {f_ep} -- test here too"
                    )
                    if len(lines) >= 3:
                        break
            if len(lines) >= 3:
                break

        # 2. Structurally similar endpoints (same pattern)
        similar_eps = self._pattern_to_endpoints.get(pattern, set())
        sibling_urls = [u for u in similar_eps if u != url]
        if sibling_urls:
            siblings_with_findings = []
            for sib_url in sibling_urls[:5]:
                sib_findings = self._endpoint_findings.get(sib_url, [])
                if sib_findings:
                    vtypes = [f.get("vuln_type", "?") for f in sib_findings[:3]]
                    siblings_with_findings.append(f"{sib_url} ({', '.join(vtypes)})")
            if siblings_with_findings:
                lines.append(
                    f"Similar endpoints with vulns: {'; '.join(siblings_with_findings[:2])}"
                )
            elif sibling_urls:
                lines.append(
                    f"{len(sibling_urls)} similar endpoints (pattern: {pattern})"
                )

        # 3. Shared auth middleware
        auth_key = self._get_auth_key_for_endpoint(url)
        if auth_key:
            auth_peers = self._auth_groups.get(auth_key, set())
            for peer_url in auth_peers:
                if peer_url == url:
                    continue
                peer_findings = self._endpoint_findings.get(peer_url, [])
                if any(f.get("vuln_type", "") in _AUTH_VULN_TYPES for f in peer_findings):
                    lines.append(
                        f"Same auth as {peer_url} which had auth bypass -- check here"
                    )
                    break

        # 4. Relevant tokens/credentials
        token_nodes = [
            (n, d) for n, d in self.G.nodes(data=True)
            if d.get("type") == TOKEN
        ]
        for _, tdata in token_nodes[:2]:
            scope = tdata.get("scope", "")
            if scope and (scope in url or scope == "*"):
                ttype = tdata.get("token_type", "token")
                lines.append(f"Discovered {ttype} may apply here (scope: {scope})")

        # 5. Credential nodes
        if not lines:
            cred_count = sum(
                1 for _, d in self.G.nodes(data=True) if d.get("type") == CREDENTIAL
            )
            if cred_count:
                lines.append(
                    f"{cred_count} credential(s) discovered -- try authenticated access"
                )

        if not lines:
            return ""

        result = "; ".join(lines)
        if len(result) > MAX_CONTEXT_CHARS:
            result = result[:MAX_CONTEXT_CHARS - 3] + "..."
        return result

    def get_similar_endpoints(self, url: str) -> list[dict[str, Any]]:
        """Find structurally similar endpoints.

        Similarity criteria:
        - Same URL path pattern (IDs replaced with {id})
        - Shared parameter names
        - Same response characteristics

        Returns list of {url, similarity_reason, findings} dicts.
        """
        if self.G.number_of_nodes() < 2:
            return []

        results: list[dict[str, Any]] = []
        ep_params = self._endpoint_params.get(url, set())
        pattern = _path_pattern(url)
        seen_urls: set[str] = {url}

        def _finding_summary(ep_url: str) -> list[dict[str, str | None]]:
            return [
                {"vuln_type": f.get("vuln_type"), "severity": f.get("severity")}
                for f in self._endpoint_findings.get(ep_url, [])[:3]
            ]

        # 1. Same path pattern
        for candidate_url in self._pattern_to_endpoints.get(pattern, set()):
            if candidate_url in seen_urls:
                continue
            seen_urls.add(candidate_url)
            results.append({
                "url": candidate_url,
                "similarity_reason": f"same pattern ({pattern})",
                "findings": _finding_summary(candidate_url),
            })

        # 2. Shared parameters (at least 2 params in common)
        for pname in ep_params:
            for candidate_url in self._param_to_endpoints.get(pname, set()):
                if candidate_url in seen_urls:
                    continue
                candidate_params = self._endpoint_params.get(candidate_url, set())
                shared = ep_params & candidate_params
                if len(shared) >= 2:
                    seen_urls.add(candidate_url)
                    results.append({
                        "url": candidate_url,
                        "similarity_reason": f"shared params: {', '.join(list(shared)[:5])}",
                        "findings": _finding_summary(candidate_url),
                    })

        # 3. Same auth group
        auth_key = self._get_auth_key_for_endpoint(url)
        if auth_key:
            for candidate_url in self._auth_groups.get(auth_key, set()):
                if candidate_url in seen_urls:
                    continue
                seen_urls.add(candidate_url)
                candidate_findings = _finding_summary(candidate_url)
                if candidate_findings:
                    results.append({
                        "url": candidate_url,
                        "similarity_reason": f"same auth ({auth_key})",
                        "findings": candidate_findings,
                    })

        # Sort: endpoints with findings first
        results.sort(key=lambda r: len(r.get("findings", [])), reverse=True)
        return results[:10]

    def get_cross_endpoint_intelligence(self) -> str:
        """Generate a compact cross-endpoint intelligence summary.

        Meant for injection into the dynamic system prompt. Surfaces
        the most actionable cross-endpoint patterns:
        - Parameter names that are vulnerable at one endpoint (test them everywhere)
        - Endpoint clusters sharing auth (if one has BAC, all likely do)
        - Structural patterns with known vulns (IDOR at /api/users/1 -> try /api/orders/1)

        Returns max ~500 chars.
        """
        if self.G.number_of_nodes() < 3:
            return ""

        lines: list[str] = []

        # 1. Vulnerable parameter names (param found vuln at one EP -> test elsewhere)
        for pname, findings in self._param_findings.items():
            if not findings:
                continue
            vtypes = list({f.get("vuln_type", "?") for f in findings})
            tested_eps = {f.get("endpoint", "") for f in findings}
            untested_eps = self._param_to_endpoints.get(pname, set()) - tested_eps
            if untested_eps:
                ep_str = ", ".join(list(untested_eps)[:2])
                lines.append(
                    f"'{pname}' was {'/'.join(vtypes[:2])} -- also at: {ep_str}"
                )
            if len(lines) >= 3:
                break

        # 2. Auth clusters with findings (BAC at one -> test siblings)
        for auth_key, eps in self._auth_groups.items():
            if len(eps) < 2:
                continue
            eps_with_auth_vuln = []
            eps_without = []
            for ep_url in eps:
                ep_findings = self._endpoint_findings.get(ep_url, [])
                if any(f.get("vuln_type", "") in _AUTH_VULN_TYPES for f in ep_findings):
                    eps_with_auth_vuln.append(ep_url)
                else:
                    eps_without.append(ep_url)
            if eps_with_auth_vuln and eps_without:
                lines.append(
                    f"Auth bypass at {eps_with_auth_vuln[0]} -- "
                    f"test {len(eps_without)} siblings with same auth"
                )
                break  # One auth cluster hint is enough

        # 3. Structural patterns with vulns
        for pattern, eps in self._pattern_to_endpoints.items():
            if len(eps) < 2:
                continue
            eps_with_finding = []
            eps_without_finding = []
            for ep_url in eps:
                if self._endpoint_findings.get(ep_url):
                    eps_with_finding.append(ep_url)
                else:
                    eps_without_finding.append(ep_url)
            if eps_with_finding and eps_without_finding:
                lines.append(
                    f"Pattern {pattern}: vuln at {eps_with_finding[0]} -- "
                    f"{len(eps_without_finding)} untested siblings"
                )
                if len(lines) >= 5:
                    break

        if not lines:
            return ""

        result = "\n".join(f"  * {line}" for line in lines[:5])
        if len(result) > MAX_CONTEXT_CHARS:
            result = result[:MAX_CONTEXT_CHARS - 3] + "..."
        return result

    # ── Existing generate_insights (backward-compatible) ──────────────

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
        ep_params_count: dict[str, int] = {}
        for node, data in self.G.nodes(data=True):
            if data.get("type") == ENDPOINT:
                param_edges = [
                    t for _, t, d in self.G.edges(node, data=True)
                    if d.get("relation") == EDGE_ACCEPTS
                ]
                if param_edges:
                    ep_params_count[data.get("url", node)] = len(param_edges)
        if ep_params_count:
            top = sorted(ep_params_count.items(), key=lambda x: -x[1])[:5]
            insights.append(
                "High-value targets (most params): "
                + ", ".join(f"{url} ({n} params)" for url, n in top)
            )

        # 3. Untested endpoints (endpoints with no findings pointing to them)
        tested_eps = set()
        for node, data in self.G.nodes(data=True):
            if data.get("type") == FINDING:
                for _, target, edata in self.G.edges(node, data=True):
                    if edata.get("relation") == EDGE_AFFECTS:
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
                f"Pending hypotheses: {len(pending_hyps)} -- "
                "test these before forming new ones"
            )

        # 7. Technology-specific attack suggestions
        tech_attacks = self._suggest_tech_attacks(state)
        if tech_attacks:
            insights.append("Tech-specific attacks: " + "; ".join(tech_attacks[:3]))

        if not insights:
            return ""

        return "\n".join(f"  * {i}" for i in insights)

    # ── Internal helpers ──────────────────────────────────────────────

    def _add_endpoint(
        self, url: str, info: dict[str, Any], host: str,
        tech_node_ids: list[tuple[str, str]],
    ) -> None:
        """Add an endpoint node with parameter and pattern indexing."""
        ep_id = f"ep:{url}"
        self.G.add_node(ep_id, type=ENDPOINT, url=url, **_safe_node_attrs(info))
        if host:
            self.G.add_edge(host, ep_id, relation=EDGE_EXPOSES)

        # Extract and index parameters
        params_dict = info.get("params", {})
        ep_param_names: set[str] = set()
        if isinstance(params_dict, dict):
            for pname, pval in params_dict.items():
                param_id = f"param:{url}:{pname}"
                self.G.add_node(
                    param_id, type=PARAM, name=pname,
                    value=str(pval)[:200], endpoint=url,
                )
                self.G.add_edge(ep_id, param_id, relation=EDGE_ACCEPTS)
                self._param_to_endpoints.setdefault(pname, set()).add(url)
                ep_param_names.add(pname)
        elif isinstance(params_dict, list):
            for p in params_dict:
                ep_param_names.add(str(p))
        self._endpoint_params[url] = ep_param_names

        # Index: path_pattern -> set of endpoint URLs
        pattern = _path_pattern(url)
        self._pattern_to_endpoints.setdefault(pattern, set()).add(url)

        # Link endpoint to technologies if tech keywords appear in notes
        notes = str(info.get("notes", "")).lower()
        if notes:
            for tech_node_id, tech_name in tech_node_ids:
                if tech_name in notes:
                    self.G.add_edge(ep_id, tech_node_id, relation=EDGE_USES_TECH)

    def _add_finding(self, fid: str, info: dict[str, Any]) -> None:
        """Add a finding node and link to endpoint/param."""
        finding_id = f"finding:{fid}"
        self.G.add_node(finding_id, type=FINDING, **_safe_node_attrs(info))

        ep = info.get("endpoint", "")
        if ep:
            ep_id = f"ep:{ep}"
            self.G.add_edge(finding_id, ep_id, relation=EDGE_AFFECTS)
            # Cache for O(1) lookup
            self._endpoint_findings.setdefault(ep, []).append(info)

        param = info.get("parameter", "")
        if param:
            self._param_findings.setdefault(param, []).append(info)
            if ep:
                param_id = f"param:{ep}:{param}"
                if self.G.has_node(param_id):
                    self.G.add_edge(finding_id, param_id, relation=EDGE_EXPLOITS)

        # Chain relationships
        chained_from = info.get("chained_from", "")
        if chained_from:
            self.G.add_edge(
                f"finding:{chained_from}", finding_id, relation=EDGE_CHAINS_TO,
            )

    def _build_auth_edges(self, endpoints: dict[str, dict[str, Any]]) -> None:
        """Link endpoints that share authentication middleware."""
        for url, info in endpoints.items():
            auth_key = self._compute_auth_key(info)
            if auth_key:
                self._auth_groups.setdefault(auth_key, set()).add(url)

        # Create edges between endpoints in the same auth group
        for auth_key, eps in self._auth_groups.items():
            if len(eps) < 2:
                continue
            ep_list = list(eps)
            # Connect first to all others (star topology to avoid O(n^2))
            anchor = f"ep:{ep_list[0]}"
            for other_url in ep_list[1:]:
                other_id = f"ep:{other_url}"
                if self.G.has_node(anchor) and self.G.has_node(other_id):
                    self.G.add_edge(
                        anchor, other_id,
                        relation=EDGE_SHARES_AUTH, auth_type=auth_key,
                    )

    def _build_similarity_edges(self) -> None:
        """Connect endpoints with the same structural pattern."""
        for pattern, eps in self._pattern_to_endpoints.items():
            if len(eps) < 2:
                continue
            ep_list = list(eps)
            anchor = f"ep:{ep_list[0]}"
            for other_url in ep_list[1:]:
                other_id = f"ep:{other_url}"
                if self.G.has_node(anchor) and self.G.has_node(other_id):
                    self.G.add_edge(
                        anchor, other_id,
                        relation=EDGE_SIMILAR_RESPONSE, pattern=pattern,
                    )

    def _extract_credentials(self, working_memory: dict[str, Any]) -> None:
        """Extract credential nodes from working memory."""
        creds = working_memory.get("credentials", {})
        if not isinstance(creds, dict):
            return
        for key, value in creds.items():
            cred_id = f"cred:{hashlib.md5(str(key).encode()).hexdigest()[:8]}"
            self.G.add_node(
                cred_id, type=CREDENTIAL,
                label=str(key)[:100], value_hint=str(value)[:50],
            )

    def _extract_tokens(
        self, working_memory: dict[str, Any], state: dict[str, Any],
    ) -> None:
        """Extract token/secret nodes from working memory and accounts."""
        # From working memory
        for _section_name, section in working_memory.items():
            if not isinstance(section, dict):
                continue
            for key, value in section.items():
                key_lower = key.lower()
                if any(kw in key_lower for kw in _TOKEN_KEYWORDS):
                    token_id = f"token:{hashlib.md5(str(key).encode()).hexdigest()[:8]}"
                    self.G.add_node(
                        token_id, type=TOKEN,
                        token_type=key_lower, scope="*",
                        value_hint=str(value)[:30] + "...",
                    )

        # From accounts (cookies/tokens)
        for username, acct_info in state.get("accounts", {}).items():
            cookies = acct_info.get("cookies", {})
            if isinstance(cookies, dict):
                for cname, cval in cookies.items():
                    if any(kw in cname.lower() for kw in _COOKIE_TOKEN_KEYWORDS):
                        token_id = f"token:acct:{username}:{cname}"
                        self.G.add_node(
                            token_id, type=TOKEN,
                            token_type=cname, scope="*",
                            value_hint=str(cval)[:30] + "...",
                            account=username,
                        )

    def _compute_auth_key(self, info: dict[str, Any]) -> str:
        """Compute a key representing the auth mechanism for an endpoint."""
        parts = []
        if info.get("auth_required"):
            parts.append("auth_required")
        # Look for auth-related hints in notes
        notes = str(info.get("notes", "")).lower()
        for auth_type in ("bearer", "cookie", "session", "jwt", "oauth", "basic", "api_key"):
            if auth_type in notes:
                parts.append(auth_type)
        if info.get("method"):
            parts.append(info["method"])
        return "|".join(sorted(parts)) if parts else ""

    def _get_auth_key_for_endpoint(self, url: str) -> str:
        """Find which auth group an endpoint belongs to."""
        for auth_key, eps in self._auth_groups.items():
            if url in eps:
                return auth_key
        return ""

    def _find_vuln_chains(self) -> list[list[str]]:
        """Find vulnerability chain paths (finding -> chains_to -> finding)."""
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
                    if d.get("relation") == EDGE_CHAINS_TO and t not in visited
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
        # Also include working_memory size for token/credential extraction
        wm = state.get("working_memory", {})
        parts.append(str(sum(len(v) for v in wm.values() if isinstance(v, dict))))
        return "|".join(parts)
