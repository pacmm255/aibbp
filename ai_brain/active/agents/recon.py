"""Active reconnaissance agent.

Navigates to target URL, crawls pages (BFS, max depth 3), extracts forms,
links, and API endpoints. Also checks robots.txt, sitemap.xml, probes
common API paths, and extracts endpoints from JavaScript files.
Uses Claude to categorize the attack surface.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import structlog

from ai_brain.active.agents.base import BaseActiveAgent
from ai_brain.active_schemas import ActiveReconResult, BrowserActionResult
from ai_brain.prompts.active_recon import (
    ActiveInteractionPointDiscoveryPrompt,
    ActiveSurfaceMappingPrompt,
)

logger = structlog.get_logger()

# Common API/admin paths to probe
_COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql",
    "/rest", "/rest/v1",
    "/swagger", "/swagger.json", "/swagger-ui",
    "/openapi.json", "/api-docs",
    "/admin", "/administrator", "/admin/login",
    "/wp-admin", "/wp-login.php",
    "/.env", "/config.js", "/config.json",
    "/debug", "/status", "/health", "/info",
    "/phpinfo.php", "/server-status",
]

# Regex patterns for extracting endpoints from JavaScript
_JS_ENDPOINT_PATTERNS = [
    r"""['"](/api/[^'"?#\s]{2,60})['"]""",
    r"""['"](/rest/[^'"?#\s]{2,60})['"]""",
    r"""['"](/v[123]/[^'"?#\s]{2,60})['"]""",
    r"""['"](/graphql[^'"?#\s]{0,30})['"]""",
    r"""fetch\s*\(\s*['"]([^'"?#\s]{5,100})['"]""",
    r"""axios\.\w+\s*\(\s*['"]([^'"?#\s]{5,100})['"]""",
    r"""\$\.\w+\s*\(\s*['"]([^'"?#\s]{5,100})['"]""",
    r"""url\s*[:=]\s*['"]([^'"?#\s]{5,100})['"]""",
    r"""endpoint\s*[:=]\s*['"]([^'"?#\s]{5,100})['"]""",
    r"""route\s*[:=]\s*['"]([^'"?#\s]{5,100})['"]""",
]


class ActiveReconAgent(BaseActiveAgent):
    """Maps the application attack surface through browser crawling."""

    @property
    def agent_type(self) -> str:
        return "recon"

    async def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        target_url = state["target_url"]
        context_name = "recon"
        max_depth = 5
        max_pages = 200

        # Ensure browser context exists
        await self.browser.create_context(context_name)

        # ── Phase 1: Pre-crawl discovery (robots.txt, sitemap, common paths) ──

        parsed_target = urlparse(target_url)
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"

        extra_urls: list[str] = []
        robots_info = ""
        sitemap_urls: list[str] = []

        # Check robots.txt
        try:
            result = await self._safe_browser_action(
                "navigate", context_name, url=urljoin(base_url, "/robots.txt")
            )
            if result.success:
                page_info = await self._safe_browser_action(
                    "extract_page_info", context_name
                )
                text = page_info.get("text_content", "")
                if "user-agent" in text.lower() or "disallow" in text.lower():
                    robots_info = text[:3000]
                    # Extract Disallowed and Sitemap paths
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/" and not path.startswith("#"):
                                extra_urls.append(urljoin(base_url, path))
                        elif line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            if sitemap_url.startswith("http"):
                                sitemap_urls.append(sitemap_url)
                    logger.info("recon_robots_found",
                                disallow_paths=len(extra_urls),
                                sitemaps=len(sitemap_urls))
        except Exception:
            pass

        # Check sitemap.xml (use first sitemap from robots.txt or default)
        sitemap_check_urls = sitemap_urls or [urljoin(base_url, "/sitemap.xml")]
        for sitemap_url in sitemap_check_urls[:5]:  # Check sitemaps
            try:
                result = await self._safe_browser_action(
                    "navigate", context_name, url=sitemap_url
                )
                if result.success:
                    page_info = await self._safe_browser_action(
                        "extract_page_info", context_name
                    )
                    text = page_info.get("text_content", "")
                    # Extract URLs from sitemap XML
                    urls_found = re.findall(r"<loc>\s*(https?://[^<]+)\s*</loc>", text)
                    same_origin = [
                        u for u in urls_found
                        if self._is_same_origin(u, target_url)
                    ]
                    extra_urls.extend(same_origin[:100])
                    if same_origin:
                        logger.info("recon_sitemap_found", urls=len(same_origin))
            except Exception:
                pass

        # Probe common API/admin paths
        interesting_paths: list[dict[str, Any]] = []
        for path in _COMMON_PATHS:
            if path in ("/robots.txt", "/sitemap.xml"):
                continue  # Already checked
            try:
                probe_url = urljoin(base_url, path)
                result = await self._safe_browser_action(
                    "navigate", context_name, url=probe_url
                )
                if result.success:
                    page_info = await self._safe_browser_action(
                        "extract_page_info", context_name
                    )
                    page_url = page_info.get("url", probe_url)
                    title = page_info.get("title", "")
                    text = page_info.get("text_content", "")[:500]

                    # Check it's not a 404 page
                    if "404" in title.lower() or "not found" in title.lower():
                        continue
                    if page_url.rstrip("/") != probe_url.rstrip("/"):
                        # Redirected — might be 404 redirect
                        if "login" in page_url.lower():
                            interesting_paths.append({
                                "url": probe_url, "redirected_to": page_url,
                                "note": "requires_auth",
                            })
                        continue

                    interesting_paths.append({
                        "url": page_url, "title": title,
                        "text_preview": text[:200],
                    })
                    # Add to crawl queue
                    extra_urls.append(page_url)
                    logger.info("recon_path_found", path=path, url=page_url)
            except Exception:
                continue

        # ── Phase 2: BFS crawl ──

        visited: set[str] = set()
        pages_data: list[dict[str, Any]] = []
        queue: list[tuple[str, int]] = [(target_url, 0)]

        # Add extra discovered URLs to queue at depth 1
        for url in extra_urls[:50]:
            normalized = self._normalize_url(url)
            if normalized not in visited:
                queue.append((url, 1))

        js_files: list[str] = []  # Track JS file URLs for endpoint extraction

        while queue and len(visited) < max_pages:
            self._check_kill_switch()

            url, depth = queue.pop(0)
            normalized = self._normalize_url(url)
            if normalized in visited:
                continue
            visited.add(normalized)

            # Navigate
            try:
                result = await self._safe_browser_action(
                    "navigate", context_name, url=url
                )
            except Exception as e:
                logger.debug("recon_navigate_error", url=url, error=str(e))
                continue

            if not result.success:
                continue

            # Extract page info
            try:
                page_info = await self._safe_browser_action(
                    "extract_page_info", context_name
                )
            except Exception:
                page_info = {"url": url, "title": "", "forms": [], "links": []}

            pages_data.append({
                "url": page_info.get("url", url),
                "title": page_info.get("title", ""),
                "depth": depth,
                "forms": page_info.get("forms", []),
                "links_count": len(page_info.get("links", [])),
                "forms_count": len(page_info.get("forms", [])),
                "buttons": page_info.get("buttons", []),
                "meta": page_info.get("meta", []),
                "text_content": page_info.get("text_content", "")[:2000],
            })

            # Collect JS file URLs from the page
            try:
                js_srcs = await self.browser._get_page(context_name).evaluate("""() => {
                    return Array.from(document.querySelectorAll('script[src]'))
                        .map(s => s.src)
                        .filter(s => s.startsWith('http') && s.endsWith('.js'))
                        .slice(0, 20);
                }""")
                for js_src in js_srcs:
                    if self._is_same_origin(js_src, target_url) and js_src not in js_files:
                        js_files.append(js_src)
            except Exception:
                pass

            # Queue discovered links (if not at max depth)
            if depth < max_depth:
                for link in page_info.get("links", []):
                    href = link.get("href", "")
                    if self._is_same_origin(href, target_url) and href not in visited:
                        queue.append((href, depth + 1))

        # ── Phase 3: JavaScript endpoint extraction ──

        js_endpoints: list[str] = []
        for js_url in js_files[:30]:  # Analyze JS files for endpoints
            try:
                result = await self._safe_browser_action(
                    "navigate", context_name, url=js_url
                )
                if result.success:
                    page_info = await self._safe_browser_action(
                        "extract_page_info", context_name
                    )
                    js_content = page_info.get("text_content", "")
                    if js_content:
                        for pattern in _JS_ENDPOINT_PATTERNS:
                            matches = re.findall(pattern, js_content)
                            for match in matches:
                                if match.startswith("/") or match.startswith("http"):
                                    endpoint = match if match.startswith("http") else urljoin(base_url, match)
                                    if self._is_same_origin(endpoint, target_url):
                                        js_endpoints.append(endpoint)
            except Exception:
                continue

        # Deduplicate JS endpoints
        js_endpoints = list(set(js_endpoints))
        if js_endpoints:
            logger.info("recon_js_endpoints", count=len(js_endpoints),
                        sample=js_endpoints[:5])

        # ── Phase 4: Claude analysis ──

        # Get API map from traffic interceptor
        api_map = self.proxy.get_api_map() if self.proxy.is_running else {}

        # Build enhanced context for Claude
        extra_context = {
            "robots_txt": robots_info[:1000] if robots_info else "",
            "interesting_paths": interesting_paths[:10],
            "js_endpoints": js_endpoints[:30],
        }

        # Use Claude to categorize the surface
        recon_result: ActiveReconResult | None = await self._call_claude(
            ActiveSurfaceMappingPrompt(),
            target=target_url,
            pages=json.dumps(pages_data, default=str)[:10000],
            links=json.dumps(
                [l for p in pages_data for l in p.get("links", [])], default=str
            )[:5000],
            forms=json.dumps(
                [f for p in pages_data for f in p.get("forms", [])], default=str
            )[:5000],
            api_map=json.dumps({**api_map, "js_endpoints": js_endpoints[:20],
                                "probed_paths": interesting_paths[:10]},
                               default=str)[:5000],
            headers="{}",
        )
        if recon_result is None:
            recon_result = ActiveReconResult(reasoning="fallback_empty")

        # Discover interaction points
        traffic = self.proxy.get_traffic(limit=50) if self.proxy.is_running else []
        traffic_json = json.dumps(
            [{"method": t.request.method, "url": t.request.url, "status": t.response.status}
             for t in traffic],
            default=str,
        )[:8000]

        ip_result = await self._call_claude(
            ActiveInteractionPointDiscoveryPrompt(),
            target=target_url,
            dom_snapshot=json.dumps(
                pages_data[-1] if pages_data else {}, default=str
            )[:5000],
            api_map=json.dumps({**api_map, "js_endpoints": js_endpoints[:20]},
                               default=str)[:5000],
            traffic_entries=traffic_json,
        )

        # Merge interaction points (safely handle malformed data from model_construct)
        def _safe_points(data: Any) -> list:
            """Extract InteractionPoint objects, skipping non-objects."""
            if not data:
                return []
            if isinstance(data, dict):
                # Haiku sometimes returns a dict instead of list — skip it
                return []
            if not isinstance(data, (list, tuple)):
                return []
            return [
                p for p in data
                if hasattr(p, "method") and hasattr(p, "url")
            ]

        all_points = _safe_points(recon_result.forms) + _safe_points(recon_result.api_endpoints)
        if hasattr(ip_result, "points"):
            all_points.extend(_safe_points(ip_result.points))

        # Deduplicate by URL+method
        seen_keys: set[str] = set()
        unique_points = []
        for p in all_points:
            key = f"{p.method}:{p.url}"
            if key not in seen_keys:
                seen_keys.add(key)
                unique_points.append(p)

        recon_result.total_pages_crawled = len(visited)

        self._log_step(
            "active_recon",
            input_data={"target_url": target_url, "max_depth": max_depth},
            output_data={
                "pages_crawled": len(visited),
                "forms_found": len(recon_result.forms),
                "api_endpoints": len(recon_result.api_endpoints),
                "interaction_points": len(unique_points),
                "js_endpoints_found": len(js_endpoints),
                "interesting_paths": len(interesting_paths),
                "robots_found": bool(robots_info),
            },
        )

        return {
            "recon_result": recon_result,
            "interaction_points": unique_points,
        }

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Strip fragment and trailing slash for dedup."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    @staticmethod
    def _is_same_origin(url: str, base_url: str) -> bool:
        """Check if URL has same origin as base."""
        try:
            parsed = urlparse(url)
            base = urlparse(base_url)
            return parsed.netloc == base.netloc
        except Exception:
            return False
