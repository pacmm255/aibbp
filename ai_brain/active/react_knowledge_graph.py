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
        """Suggest attacks based on detected technologies.

        Delegates to the module-level TECH_ATTACK_MAP, returning the first
        attack per matched technology for a compact insights summary.
        """
        recs = get_tech_recommendations(state.get("tech_stack", []))
        # Return just the first recommendation per match for the compact insight line
        return recs[:5]

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


# ── Tech-Stack Attack Map ────────────────────────────────────────────────
# Maps technology keywords (lowercase) to ordered lists of specific attack
# vectors.  Used by KnowledgeGraph._suggest_tech_attacks() (via delegation)
# and by the module-level helper get_tech_recommendations().

TECH_ATTACK_MAP: dict[str, list[str]] = {
    "laravel": [
        "Mass assignment via $fillable — POST extra fields (is_admin, role, balance)",
        "Debug mode /_ignition — RCE via Ignition solution gadgets",
        ".env exposure — GET /.env for APP_KEY, DB creds, mail secrets",
        "Blade SSTI — inject {{ }} and {!! !!} in user-controlled template vars",
        "Session cookie deserialization — tamper laravel_session with known APP_KEY",
        "_debugbar — GET /_debugbar/open for queries, requests, vars",
    ],
    "express": [
        "Prototype pollution — __proto__, constructor.prototype in JSON body",
        "NoSQL injection — $gt, $ne, $regex operators in JSON params",
        "SSRF via url/href/path params — internal service access",
        "SSTI in Pug/EJS/Handlebars — #{} / <%= %> / {{}} in template inputs",
        "Path traversal via ../ in Express static middleware",
    ],
    "node": [
        "Prototype pollution — __proto__, constructor.prototype in JSON body",
        "NoSQL injection — $gt, $ne, $regex operators in MongoDB queries",
        "SSRF via url/href/path params — internal service access",
        "npm package vulns — check package.json exposure, outdated deps",
    ],
    "django": [
        "Debug page info leak — trigger 500 with DEBUG=True for settings, paths",
        "ORM injection — extra(), raw(), annotate() with user input",
        "Template injection — {% %} and {{ }} in user-controlled strings",
        "Admin panel brute force — /admin/ with common creds",
        "ALLOWED_HOSTS bypass — Host header manipulation for password reset poisoning",
    ],
    "spring": [
        "Actuator endpoints — /actuator/env, /actuator/heapdump, /actuator/mappings",
        "SpEL injection — ${} in error messages, input fields, headers",
        "Deserialization RCE — ysoserial gadgets in serialized Java objects",
        "Path traversal via ; — /admin;/..;/actuator/env bypasses path filters",
        "Spring4Shell — class.module.classLoader.* parameter manipulation",
    ],
    "java": [
        "Deserialization RCE — ysoserial gadgets in cookies, params, file uploads",
        "JNDI injection — ${jndi:ldap://} in Log4j-vulnerable inputs",
        "Path traversal via ; — /admin;/resource bypasses security filters",
        "JSP webshell upload — .jsp extension in file upload features",
    ],
    "php": [
        "Type juggling — 0e hash comparison bypass (0e123 == 0 in loose compare)",
        "LFI/RFI — include/require params with ../../etc/passwd, php://filter",
        "php:// wrappers — php://input for RCE, php://filter/convert.base64-encode",
        ".php~ and .php.bak backup files — source code disclosure",
        "Deserialization — unserialize() on user-controlled POP chain data",
        "open_basedir bypass — symlink/glob:// for restricted file reads",
    ],
    "wordpress": [
        "xmlrpc.php — system.multicall brute force, pingback SSRF",
        "wp-json API — /wp-json/wp/v2/users for user enumeration",
        "Plugin enumeration — /wp-content/plugins/[name]/ probing",
        "User enumeration via ?author=1 — redirect leaks usernames",
        "wp-config.php.bak — backup config with DB creds",
        "wpscan — automated vuln scanning of plugins/themes/core",
    ],
    "asp.net": [
        "ViewState deserialization — tamper __VIEWSTATE with known machineKey",
        "IIS shortnames ~1 — /ABCDEF~1 brute force for hidden files/dirs",
        "web.config disclosure — GET /web.config for connection strings, keys",
        "Padding oracle — valid ciphertext manipulation on encrypted cookies",
        "Trace.axd — /trace.axd for request/response history",
    ],
    "iis": [
        "IIS shortnames ~1 — /ABCDEF~1 brute force for hidden files/dirs",
        "web.config disclosure — path traversal to read web.config",
        "Trace.axd — /trace.axd for request/response history",
        ".aspx source via ::$DATA — /page.aspx::$DATA alternate data stream",
    ],
    "rails": [
        "Mass assignment — unpermitted params (role, admin, is_superuser) in POST/PATCH",
        "YAML deserialization — Psych/Syck gadgets in YAML-accepting endpoints",
        "Debug console — /rails/info/routes, /_debug_console (dev mode)",
        "secret_key_base leak — ENV exposure for cookie forgery/RCE",
        "Render file — path traversal in render file: params",
    ],
    "ruby": [
        "YAML deserialization — Psych/Syck gadgets in YAML-accepting endpoints",
        "ERB template injection — <%= %> in user-controlled strings",
        "Mass assignment — unpermitted params in strong parameters bypass",
    ],
    "nginx": [
        "Off-by-slash path traversal — /static../etc/passwd (alias misconfiguration)",
        "Alias misconfiguration — location /i { alias /data/; } leaks parent dir",
        "Merge_slashes off — //admin bypasses location blocks",
        "Raw backend response — X-Accel-Redirect header injection",
    ],
    "apache": [
        ".htaccess upload — override server config for PHP execution",
        "mod_status — /server-status for live request monitoring",
        "mod_info — /server-info for full Apache configuration",
        "Path traversal via %2e — /cgi-bin/.%2e/%2e%2e/etc/passwd (CVE-2021-41773)",
        "AddHandler bypass — .php.jpg for PHP execution",
    ],
    "graphql": [
        "Introspection query — full schema dump via __schema",
        "Batch query — alias-based brute force (100+ login attempts in 1 request)",
        "Injection in variables — SQLi/NoSQLi through variable values",
        "Nested query DoS — deeply nested relationships for resource exhaustion",
        "Field suggestion enumeration — typo-based field name discovery",
    ],
    "jwt": [
        "None algorithm — set alg:none to bypass signature verification",
        "Key confusion — RS256 to HS256 with public key as HMAC secret",
        "Weak secret brute force — hashcat/jwt_tool on HS256 tokens",
        "Kid injection — kid header for SQLi/LFI/command injection",
        "JKU/X5U spoofing — point to attacker-controlled key server",
    ],
    "flask": [
        "SSTI in Jinja2 — {{ config }} {{ ''.__class__.__mro__[1].__subclasses__() }}",
        "Debug PIN — /console with Werkzeug debugger PIN calculation",
        "Secret key brute force — flask-unsign for session cookie forgery",
        "Blueprint enumeration — route discovery via debug mode or error pages",
    ],
    "fastapi": [
        "OpenAPI schema — /docs, /redoc, /openapi.json for full API docs",
        "Pydantic validation bypass — type coercion edge cases",
        "Dependency injection — parameter pollution in query/body params",
    ],
    "nextjs": [
        "API route SSRF — /api/* routes may proxy internal services",
        "Source map exposure — /_next/static/ for source code",
        "_next/data leaks — /__nextjs_original-stack-frame for debug info",
        "Middleware bypass — direct fetch to API skipping auth middleware",
    ],
    "react": [
        "Source maps — .map files expose original source code",
        "API keys in JS bundles — search for hardcoded tokens, secrets",
        "dangerouslySetInnerHTML — XSS via React-rendered user content",
    ],
    "angular": [
        "Template injection — {{constructor.constructor('return this')()}}",
        "Source maps — .map files expose TypeScript source",
        "Bypassable sanitization — [innerHTML] with crafted payloads",
    ],
    "mongodb": [
        "NoSQL injection — $gt, $ne, $regex, $where in query params",
        "BSON injection — type confusion in ObjectId fields",
        "Server-side JS — $where with JavaScript code injection",
    ],
    "redis": [
        "Unauthenticated access — default port 6379, no password",
        "SSRF to Redis — gopher:// or dict:// for command execution",
        "Lua injection — EVAL command with user-controlled scripts",
    ],
    "docker": [
        "Docker socket exposure — /var/run/docker.sock via SSRF",
        "Container escape — privileged mode, mounted host dirs",
        "Registry access — /v2/_catalog for image enumeration",
    ],
    "kubernetes": [
        "API server access — /api/v1/pods, /api/v1/secrets via SSRF",
        "Service account token — /var/run/secrets/kubernetes.io/serviceaccount/token",
        "etcd access — unauthenticated etcd on port 2379",
    ],
    "aws": [
        "SSRF to metadata — http://169.254.169.254/latest/meta-data/ for IAM creds",
        "S3 bucket misconfiguration — public listing, unauthenticated upload",
        "Cognito pool enumeration — user pools with self-registration enabled",
    ],
    "firebase": [
        "Insecure Firestore rules — read/write without authentication",
        "Cloud Functions — unauthenticated invocation of admin functions",
        "Storage bucket — public listing of uploaded files",
    ],
}


def get_tech_recommendations(
    detected_techs: list[str],
    app_model: dict[str, Any] | None = None,
) -> list[str]:
    """Return prioritized attack recommendations for detected technologies.

    Args:
        detected_techs: List of technology strings from state['tech_stack'].
        app_model: Optional app_model dict for additional tech signals.

    Returns:
        Deduplicated list of actionable attack strings.
    """
    all_techs: list[str] = [t.lower().strip() for t in detected_techs]
    if app_model:
        for t in app_model.get("tech_signals", []):
            if isinstance(t, str):
                all_techs.append(t.lower().strip())

    if not all_techs:
        return []

    seen: set[str] = set()
    recommendations: list[str] = []
    for tech_keyword, attacks in TECH_ATTACK_MAP.items():
        matched = False
        for det in all_techs:
            if tech_keyword in det:
                matched = True
                break
        if matched:
            for atk in attacks:
                if atk not in seen:
                    seen.add(atk)
                    recommendations.append(atk)

    return recommendations
