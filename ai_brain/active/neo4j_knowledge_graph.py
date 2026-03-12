"""Neo4j-backed knowledge graph for pentesting agent with Graphiti-inspired search."""

from __future__ import annotations

import time
from typing import Any

import structlog

log = structlog.get_logger(__name__)

try:
    from neo4j import AsyncGraphDatabase  # type: ignore[import-untyped]

    _NEO4J_AVAILABLE = True
except ImportError:
    _NEO4J_AVAILABLE = False
    AsyncGraphDatabase = None  # type: ignore[assignment,misc]


class Neo4jKnowledgeGraph:
    """Async Neo4j-backed knowledge graph with Graphiti-inspired search."""

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "aibbp_dev",
    ):
        self._uri = uri
        self._user = user
        self._password = password
        self._driver: Any = None
        self._connected = False
        self._last_episode_id: str | None = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        """Try to connect. Returns False if unavailable (graceful)."""
        if not _NEO4J_AVAILABLE:
            log.warning("neo4j_kg.package_missing", hint="pip install neo4j")
            return False
        try:
            self._driver = AsyncGraphDatabase.driver(
                self._uri, auth=(self._user, self._password)
            )
            await self._driver.verify_connectivity()
            self._connected = True
            log.info("neo4j_kg.connected", uri=self._uri)
            return True
        except Exception as exc:
            log.warning("neo4j_kg.connect_failed", err=str(exc))
            self._driver = None
            self._connected = False
            return False

    async def close(self) -> None:
        if self._driver:
            try:
                await self._driver.close()
            except Exception:
                pass
            self._driver = None
            self._connected = False

    # ------------------------------------------------------------------
    # State synchronisation (MERGE-based upsert)
    # ------------------------------------------------------------------

    async def sync_state(self, state: dict) -> None:
        """MERGE-based upsert from PentestState into Neo4j.

        Syncs: target, endpoints, findings, hypotheses, accounts,
        tech_stack, tested_techniques.  Uses MERGE to avoid duplicates.
        """
        if not self._connected:
            return
        try:
            async with self._driver.session() as session:
                await session.execute_write(self._sync_tx, state)
        except Exception as exc:
            log.warning("neo4j_kg.sync_state_error", err=str(exc))

    @staticmethod
    async def _sync_tx(tx: Any, state: dict) -> None:
        target_url = state.get("target_url") or state.get("target") or ""
        domain = state.get("domain") or target_url
        if not domain:
            return

        # -- Target node ---------------------------------------------------
        await tx.run(
            "MERGE (t:Target {url: $url}) SET t.domain = $domain, t.updated = timestamp()",
            url=target_url, domain=domain,
        )

        # -- Endpoints -----------------------------------------------------
        for ep in state.get("endpoints_discovered", []):
            url = ep if isinstance(ep, str) else ep.get("url", str(ep))
            method = "GET" if isinstance(ep, str) else ep.get("method", "GET")
            await tx.run(
                """MERGE (e:Endpoint {url: $url})
                   SET e.method = $method, e.updated = timestamp()
                   WITH e
                   MATCH (t:Target {url: $target})
                   MERGE (t)-[:HAS_ENDPOINT]->(e)""",
                url=url, method=method, target=target_url,
            )

        # -- Findings ------------------------------------------------------
        for i, f in enumerate(state.get("confirmed_findings", [])):
            fid = f.get("id") or f.get("title", f"finding-{i}")
            await tx.run(
                """MERGE (f:Finding {fid: $fid})
                   SET f.title = $title, f.severity = $severity,
                       f.evidence = $evidence, f.vuln_type = $vuln_type,
                       f.endpoint = $endpoint, f.updated = timestamp()
                   WITH f
                   MATCH (t:Target {url: $target})
                   MERGE (f)-[:FOUND_ON]->(t)""",
                fid=fid,
                title=f.get("title", ""),
                severity=f.get("severity", "info"),
                evidence=str(f.get("evidence", ""))[:2000],
                vuln_type=f.get("vuln_type", ""),
                endpoint=f.get("endpoint", ""),
                target=target_url,
            )
            ep_url = f.get("endpoint", "")
            if ep_url:
                await tx.run(
                    """MATCH (f:Finding {fid: $fid}), (e:Endpoint {url: $ep})
                       MERGE (f)-[:FOUND_ON]->(e)""",
                    fid=fid, ep=ep_url,
                )
            param = f.get("parameter", "")
            if param:
                await tx.run(
                    """MERGE (p:Parameter {name: $name, endpoint: $ep})
                       WITH p
                       MATCH (f:Finding {fid: $fid})
                       MERGE (f)-[:EXPLOITS_PARAM]->(p)""",
                    name=param, ep=ep_url, fid=fid,
                )

        # -- Hypotheses ----------------------------------------------------
        for h in state.get("hypotheses", []):
            hid = h if isinstance(h, str) else h.get("id", str(h))
            text = h if isinstance(h, str) else h.get("text", str(h))
            await tx.run(
                """MERGE (h:Hypothesis {hid: $hid})
                   SET h.text = $text, h.updated = timestamp()
                   WITH h
                   MATCH (t:Target {url: $target})
                   MERGE (h)-[:TARGETS]->(t)""",
                hid=hid, text=str(text)[:1000], target=target_url,
            )

        # -- Accounts ------------------------------------------------------
        for acc in state.get("accounts", []):
            username = acc if isinstance(acc, str) else acc.get("username", str(acc))
            await tx.run(
                """MERGE (a:Account {username: $username})
                   SET a.updated = timestamp()
                   WITH a
                   MATCH (t:Target {url: $target})
                   MERGE (a)-[:TARGETS]->(t)""",
                username=username, target=target_url,
            )

        # -- Technology stack ----------------------------------------------
        techs = state.get("tech_stack") or state.get("technology_stack") or []
        if isinstance(techs, str):
            techs = [techs]
        for tech in techs:
            name = tech if isinstance(tech, str) else str(tech)
            await tx.run(
                """MERGE (tc:Technology {name: $name})
                   WITH tc
                   MATCH (t:Target {url: $target})
                   MERGE (t)-[:USES_TECH]->(tc)""",
                name=name, target=target_url,
            )

        # -- Tested techniques ---------------------------------------------
        for tt in state.get("tested_techniques", []):
            ep_url = tt.get("endpoint", "") if isinstance(tt, dict) else ""
            technique = tt.get("technique", str(tt)) if isinstance(tt, dict) else str(tt)
            tool = tt.get("tool", "") if isinstance(tt, dict) else ""
            await tx.run(
                """MERGE (tt:TestedTechnique {technique: $technique, endpoint: $ep})
                   SET tt.tool = $tool, tt.updated = timestamp()""",
                technique=technique, ep=ep_url, tool=tool,
            )
            if ep_url:
                await tx.run(
                    """MATCH (e:Endpoint {url: $ep}), (tt:TestedTechnique {technique: $technique, endpoint: $ep})
                       MERGE (e)-[:TESTED_BY]->(tt)""",
                    ep=ep_url, technique=technique,
                )

    # ------------------------------------------------------------------
    # Episode recording
    # ------------------------------------------------------------------

    async def record_episode(
        self,
        turn: int,
        phase: str,
        tools_used: list[str],
        summary: str,
        findings_count: int,
        endpoints_count: int,
    ) -> None:
        """Record an episode (one brain turn) with FOLLOWS relationship to previous."""
        if not self._connected:
            return
        try:
            eid = f"episode-{turn}"
            async with self._driver.session() as session:
                await session.run(
                    """MERGE (ep:Episode {eid: $eid})
                       SET ep.turn = $turn, ep.phase = $phase,
                           ep.tools_used = $tools, ep.summary = $summary,
                           ep.findings_count = $fc, ep.endpoints_count = $ec,
                           ep.ts = timestamp()""",
                    eid=eid, turn=turn, phase=phase,
                    tools=tools_used, summary=summary[:500],
                    fc=findings_count, ec=endpoints_count,
                )
                if self._last_episode_id:
                    await session.run(
                        """MATCH (prev:Episode {eid: $prev}), (cur:Episode {eid: $cur})
                           MERGE (cur)-[:FOLLOWS]->(prev)""",
                        prev=self._last_episode_id, cur=eid,
                    )
            self._last_episode_id = eid
        except Exception as exc:
            log.warning("neo4j_kg.record_episode_error", err=str(exc))

    # ------------------------------------------------------------------
    # Graphiti-inspired search methods
    # ------------------------------------------------------------------

    async def search_temporal_window(self, last_n_turns: int = 10) -> list[dict]:
        """Get episodes from last N turns with their connected entities."""
        if not self._connected:
            return []
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """MATCH (ep:Episode)
                       WITH ep ORDER BY ep.turn DESC LIMIT $n
                       RETURN ep {.eid, .turn, .phase, .tools_used, .summary,
                                  .findings_count, .endpoints_count} AS episode""",
                    n=last_n_turns,
                )
                return [dict(r["episode"]) async for r in result]
        except Exception as exc:
            log.warning("neo4j_kg.search_temporal_error", err=str(exc))
            return []

    async def search_entity_relationships(self, entity_id: str) -> dict:
        """Get all relationships for a specific entity (endpoint, finding, etc.)."""
        if not self._connected:
            return {}
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """MATCH (n) WHERE n.url = $id OR n.fid = $id OR n.eid = $id
                            OR n.hid = $id OR n.name = $id OR n.username = $id
                       OPTIONAL MATCH (n)-[r]-(m)
                       RETURN labels(n) AS labels, properties(n) AS props,
                              collect({type: type(r), dir: CASE WHEN startNode(r) = n
                                       THEN 'out' ELSE 'in' END,
                                       other_labels: labels(m),
                                       other_props: properties(m)}) AS rels
                       LIMIT 1""",
                    id=entity_id,
                )
                rec = await result.single()
                if not rec:
                    return {}
                return {
                    "labels": rec["labels"],
                    "properties": dict(rec["props"]),
                    "relationships": [dict(r) for r in rec["rels"]],
                }
        except Exception as exc:
            log.warning("neo4j_kg.search_entity_rels_error", err=str(exc))
            return {}

    async def search_diverse_results(self, limit: int = 10) -> list[dict]:
        """Get diverse set of entities across different labels."""
        if not self._connected:
            return []
        try:
            labels = [
                "Target", "Endpoint", "Finding", "Hypothesis",
                "Technology", "Account", "AttackChain",
            ]
            per_label = max(1, limit // len(labels))
            results: list[dict] = []
            async with self._driver.session() as session:
                for label in labels:
                    res = await session.run(
                        f"MATCH (n:{label}) RETURN labels(n) AS labels, "
                        f"properties(n) AS props ORDER BY n.updated DESC LIMIT $lim",
                        lim=per_label,
                    )
                    async for r in res:
                        results.append({"labels": r["labels"], "properties": dict(r["props"])})
            return results[:limit]
        except Exception as exc:
            log.warning("neo4j_kg.search_diverse_error", err=str(exc))
            return []

    async def search_episode_context(self, turn: int) -> dict:
        """Get full context for a specific episode/turn."""
        if not self._connected:
            return {}
        try:
            eid = f"episode-{turn}"
            async with self._driver.session() as session:
                result = await session.run(
                    """MATCH (ep:Episode {eid: $eid})
                       OPTIONAL MATCH (ep)-[:FOLLOWS]->(prev:Episode)
                       RETURN ep {.eid, .turn, .phase, .tools_used, .summary,
                                  .findings_count, .endpoints_count} AS episode,
                              prev {.eid, .turn, .phase} AS previous""",
                    eid=eid,
                )
                rec = await result.single()
                if not rec:
                    return {}
                return {
                    "episode": dict(rec["episode"]) if rec["episode"] else {},
                    "previous": dict(rec["previous"]) if rec["previous"] else {},
                }
        except Exception as exc:
            log.warning("neo4j_kg.search_episode_ctx_error", err=str(exc))
            return {}

    async def search_successful_tools(self, limit: int = 5) -> list[dict]:
        """Find tools that produced findings (successful attacks)."""
        if not self._connected:
            return []
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """MATCH (ep:Episode)
                       WHERE ep.findings_count > 0
                       UNWIND ep.tools_used AS tool
                       RETURN tool, count(*) AS successes, sum(ep.findings_count) AS total_findings
                       ORDER BY total_findings DESC LIMIT $lim""",
                    lim=limit,
                )
                return [
                    {"tool": r["tool"], "successes": r["successes"],
                     "total_findings": r["total_findings"]}
                    async for r in result
                ]
        except Exception as exc:
            log.warning("neo4j_kg.search_successful_tools_error", err=str(exc))
            return []

    async def search_recent_context(self, limit: int = 20) -> list[dict]:
        """Get most recent entities modified."""
        if not self._connected:
            return []
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """MATCH (n) WHERE n.updated IS NOT NULL
                       RETURN labels(n) AS labels, properties(n) AS props
                       ORDER BY n.updated DESC LIMIT $lim""",
                    lim=limit,
                )
                return [
                    {"labels": r["labels"], "properties": dict(r["props"])}
                    async for r in result
                ]
        except Exception as exc:
            log.warning("neo4j_kg.search_recent_error", err=str(exc))
            return []

    async def search_entity_by_label(
        self, label: str, filters: dict | None = None
    ) -> list[dict]:
        """Search entities by label with optional property filters."""
        if not self._connected:
            return []
        try:
            where_clauses: list[str] = []
            params: dict[str, Any] = {"lim": 50}
            for key, val in (filters or {}).items():
                safe_key = key.replace(" ", "_").replace("-", "_")
                where_clauses.append(f"n.{safe_key} = ${safe_key}")
                params[safe_key] = val
            where = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            async with self._driver.session() as session:
                result = await session.run(
                    f"MATCH (n:{label}){where} RETURN properties(n) AS props "
                    f"ORDER BY n.updated DESC LIMIT $lim",
                    **params,
                )
                return [dict(r["props"]) async for r in result]
        except Exception as exc:
            log.warning("neo4j_kg.search_by_label_error", err=str(exc))
            return []

    # ------------------------------------------------------------------
    # Strategic methods
    # ------------------------------------------------------------------

    async def generate_strategic_insights(self, state: dict) -> str:
        """Generate text insights from graph structure for prompt injection.

        - Attack paths: multi-hop relationships from findings
        - Untested surface: endpoints without TESTED_BY relationships
        - Coverage gaps: high-value endpoints with few tests
        """
        if not self._connected:
            return ""
        try:
            parts: list[str] = []

            # Untested surface
            untested = await self.get_untested_surface()
            if untested.get("untested_endpoints"):
                eps = untested["untested_endpoints"][:10]
                parts.append(
                    f"UNTESTED ENDPOINTS ({len(untested['untested_endpoints'])} total): "
                    + ", ".join(eps)
                )

            # Coverage matrix summary
            coverage = await self.get_coverage_matrix()
            if coverage:
                low_coverage = [
                    ep for ep, techs in coverage.items() if len(techs) < 3
                ]
                if low_coverage:
                    parts.append(
                        f"LOW COVERAGE ({len(low_coverage)} endpoints with <3 techniques): "
                        + ", ".join(low_coverage[:8])
                    )

            # Attack paths from existing findings
            paths = await self.find_attack_paths(max_depth=3)
            if paths:
                path_strs = []
                for p in paths[:5]:
                    path_strs.append(" -> ".join(p.get("nodes", [])))
                parts.append("ATTACK PATHS: " + " | ".join(path_strs))

            # Successful tools
            tools = await self.search_successful_tools(limit=3)
            if tools:
                tool_strs = [
                    f"{t['tool']}({t['total_findings']} findings)" for t in tools
                ]
                parts.append("SUCCESSFUL TOOLS: " + ", ".join(tool_strs))

            if not parts:
                return ""
            return "\n[KG INSIGHTS]\n" + "\n".join(f"- {p}" for p in parts) + "\n"
        except Exception as exc:
            log.warning("neo4j_kg.strategic_insights_error", err=str(exc))
            return ""

    async def find_attack_paths(
        self, from_finding_id: str | None = None, max_depth: int = 5
    ) -> list[dict]:
        """Find multi-hop attack paths through the graph."""
        if not self._connected:
            return []
        try:
            async with self._driver.session() as session:
                if from_finding_id:
                    result = await session.run(
                        """MATCH path = (f:Finding {fid: $fid})-[*1..$depth]-(other)
                           WHERE other:Finding OR other:Endpoint OR other:Parameter
                           RETURN [n IN nodes(path) |
                                   COALESCE(n.fid, n.url, n.name)] AS nodes,
                                  [r IN relationships(path) | type(r)] AS rels
                           LIMIT 20""",
                        fid=from_finding_id, depth=max_depth,
                    )
                else:
                    result = await session.run(
                        """MATCH path = (f:Finding)-[*2..$depth]-(f2:Finding)
                           WHERE f <> f2
                           RETURN [n IN nodes(path) |
                                   COALESCE(n.fid, n.url, n.name)] AS nodes,
                                  [r IN relationships(path) | type(r)] AS rels
                           LIMIT 20""",
                        depth=max_depth,
                    )
                return [
                    {"nodes": r["nodes"], "relationships": r["rels"]}
                    async for r in result
                ]
        except Exception as exc:
            log.warning("neo4j_kg.find_attack_paths_error", err=str(exc))
            return []

    async def get_untested_surface(self) -> dict:
        """Return endpoints that have no TESTED_BY relationships."""
        if not self._connected:
            return {}
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """MATCH (e:Endpoint)
                       WHERE NOT (e)-[:TESTED_BY]->()
                       RETURN e.url AS url ORDER BY e.updated DESC LIMIT 100"""
                )
                urls = [r["url"] async for r in result]
                return {"untested_endpoints": urls, "count": len(urls)}
        except Exception as exc:
            log.warning("neo4j_kg.untested_surface_error", err=str(exc))
            return {}

    async def get_coverage_matrix(self) -> dict:
        """Return endpoint -> list of techniques tested mapping."""
        if not self._connected:
            return {}
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """MATCH (e:Endpoint)-[:TESTED_BY]->(tt:TestedTechnique)
                       RETURN e.url AS endpoint,
                              collect(DISTINCT tt.technique) AS techniques
                       ORDER BY size(collect(DISTINCT tt.technique)) ASC
                       LIMIT 200"""
                )
                matrix: dict[str, list[str]] = {}
                async for r in result:
                    matrix[r["endpoint"]] = r["techniques"]
                return matrix
        except Exception as exc:
            log.warning("neo4j_kg.coverage_matrix_error", err=str(exc))
            return {}
