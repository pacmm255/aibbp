"""HTTP traffic interceptor using mitmproxy for request/response capture.

Runs an embedded mitmproxy instance that captures all browser traffic,
auto-tags requests (auth, api, form, etc.), builds API maps, and detects
interesting patterns in responses (stack traces, secrets, internal paths).

Includes dynamic deduplication of similar requests and WebSocket message
suppression to prevent log/memory spam from real-time feeds.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import structlog

from ai_brain.active.errors import ActiveScopeViolation
from ai_brain.active.scope_guard import ActiveScopeGuard
from ai_brain.active_schemas import HTTPRequest, HTTPResponse, HTTPTrafficEntry
from ai_brain.config import ActiveTestingConfig

logger = structlog.get_logger()

# Maximum body size to store (100KB)
_MAX_BODY_SIZE = 100 * 1024

# Static asset extensions to skip entirely (never useful for pentesting)
_STATIC_EXTS = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".webp",
})


def _is_static_asset(url: str) -> bool:
    """Check if URL is a static asset (JS/CSS/images/fonts)."""
    path = urlparse(url).path.lower()
    # Check extension
    for ext in _STATIC_EXTS:
        if path.endswith(ext):
            return True
    # Common asset path patterns
    if any(seg in path for seg in ("/assets/", "/static/", "/dist/", "/bundles/", "/_next/static/")):
        return True
    return False


def _dedup_key(method: str, url: str, status: int) -> str:
    """Build a dedup key: METHOD + normalized_path + status.

    Strips query params and normalizes IDs so that e.g.
    GET /api/v1/quote/bucketed?symbol=XBTUSD&binSize=1h&count=1000
    and the same URL with different time params share one key.
    """
    parsed = urlparse(url)
    path = _normalize_path(parsed.path)
    # Include a short hash of query params to distinguish truly different endpoints
    # but group identical paths with only varying timestamps/nonces
    query = parsed.query
    # Strip volatile params (timestamps, nonces, cache busters)
    stable_params = []
    for part in query.split("&"):
        if "=" in part:
            k, _ = part.split("=", 1)
            k_lower = k.lower()
            # Skip volatile params
            if any(v in k_lower for v in (
                "time", "stamp", "from", "to", "nonce", "cb", "cache",
                "_", "t", "ts", "start", "end", "since", "until",
            )):
                continue
            stable_params.append(k)
    params_sig = ",".join(sorted(stable_params))
    return f"{method}:{path}:{status}:{params_sig}"


def _normalize_path(path: str) -> str:
    """Normalize a URL path by replacing numeric/UUID segments with {id}."""
    parts = path.strip("/").split("/")
    normalized = []
    for part in parts:
        if re.match(r"^\d+$", part):
            normalized.append("{id}")
        elif re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            part,
            re.IGNORECASE,
        ):
            normalized.append("{uuid}")
        elif re.match(r"^[0-9a-f]{24}$", part, re.IGNORECASE):
            normalized.append("{objectid}")
        # Hash-like segments (bundle filenames, cache busters)
        elif re.match(r"^[a-f0-9]{16,}$", part, re.IGNORECASE):
            normalized.append("{hash}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized)


class TrafficInterceptor:
    """Captures and analyzes HTTP traffic flowing through the proxy.

    Uses mitmproxy's DumpMaster API embedded in a background thread.
    All captured traffic is stored in-memory and can be queried/filtered
    by the AI agents.

    Features:
    - WebSocket message suppression (only first message per connection logged)
    - Dynamic request deduplication (same method+path+status stored once,
      with a hit counter)
    - Static asset filtering (JS/CSS/images/fonts skipped)
    """

    def __init__(
        self,
        scope_guard: ActiveScopeGuard,
        config: ActiveTestingConfig,
    ) -> None:
        self._scope_guard = scope_guard
        self._config = config
        self._traffic: list[HTTPTrafficEntry] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None
        self._master: Any = None

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self, port: int | None = None) -> None:
        """Start the mitmproxy instance on a background thread."""
        if self._running:
            return

        if self._config.dry_run:
            logger.info("proxy_dry_run", msg="Proxy start skipped (dry run)")
            self._running = True
            return

        listen_port = port or self._config.proxy_port

        try:
            from mitmproxy import options
            from mitmproxy.tools.dump import DumpMaster

            opts = options.Options(
                listen_host="127.0.0.1",
                listen_port=listen_port,
                ssl_insecure=True,
            )

            # Suppress noisy mitmproxy logs (TLS handshakes, WebSocket frames)
            import logging
            for noisy_logger in (
                "mitmproxy.proxy", "mitmproxy.connection",
                "mitmproxy.proxy.layers.websocket",
            ):
                logging.getLogger(noisy_logger).setLevel(logging.ERROR)

            master = DumpMaster(opts)

            # Disable the default dumper addon that prints every flow to stdout
            # (this is what causes the WebSocket spam in terminal)
            to_remove = [
                a for a in master.addons.chain
                if type(a).__name__ in ("Dumper", "TermLog")
            ]
            for addon_obj in to_remove:
                master.addons.remove(addon_obj)

            addon = _TrafficCaptureAddon(self._scope_guard, self._traffic, self._lock)
            master.addons.add(addon)

            self._master = master
            self._thread = threading.Thread(
                target=self._run_proxy, args=(master,), daemon=True
            )
            self._thread.start()

            # Wait for proxy to actually start listening
            import socket
            proxy_ready = False
            for _ in range(20):  # Try for 2 seconds
                time.sleep(0.1)
                try:
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=0.5):
                        proxy_ready = True
                        break
                except (ConnectionRefusedError, OSError):
                    continue

            if proxy_ready:
                self._running = True
                logger.info("proxy_started", port=listen_port)
            else:
                logger.warning("proxy_start_failed",
                               msg="Proxy thread started but port not listening. Disabling proxy.")
                self._config.proxy_port = 0
                self._running = True  # Continue without proxy

        except ImportError:
            logger.warning(
                "mitmproxy_not_available",
                msg="mitmproxy not installed. Traffic capture disabled.",
            )
            self._config.proxy_port = 0
            self._running = True  # Continue without proxy

    def _run_proxy(self, master: Any) -> None:
        """Run mitmproxy event loop in a background thread."""
        import asyncio
        import inspect

        try:
            run_result = master.run()
            if inspect.isawaitable(run_result):
                asyncio.run(run_result)
        except Exception as e:
            logger.error("proxy_error", error=str(e))

    async def stop(self) -> None:
        """Stop the mitmproxy instance."""
        if self._master:
            try:
                self._master.shutdown()
            except Exception:
                pass
            self._master = None

        # Wait for the proxy thread to fully exit (releases the port)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

        self._running = False
        logger.info("proxy_stopped", captured_entries=len(self._traffic))

    def get_traffic(
        self,
        url_filter: str | None = None,
        method_filter: str | None = None,
        tag_filter: str | None = None,
        status_filter: int | None = None,
        limit: int = 1000,
    ) -> list[HTTPTrafficEntry]:
        """Query captured traffic with optional filters."""
        with self._lock:
            results = list(self._traffic)

        if url_filter:
            results = [e for e in results if url_filter in e.request.url]
        if method_filter:
            results = [e for e in results if e.request.method == method_filter.upper()]
        if tag_filter:
            results = [e for e in results if tag_filter in e.tags]
        if status_filter:
            results = [e for e in results if e.response.status == status_filter]

        return results[-limit:]

    def get_api_map(self) -> dict[str, list[dict[str, Any]]]:
        """Build an API map from observed traffic."""
        api_map: dict[str, list[dict[str, Any]]] = defaultdict(list)

        with self._lock:
            entries = list(self._traffic)

        for entry in entries:
            parsed = urlparse(entry.request.url)
            path = _normalize_path(parsed.path)

            api_map[path].append({
                "method": entry.request.method,
                "content_type": entry.request.content_type,
                "response_status": entry.response.status,
                "response_type": entry.response.content_type,
                "has_body": bool(entry.request.body),
                "tags": entry.tags,
            })

        # Deduplicate
        result: dict[str, list[dict[str, Any]]] = {}
        for path, entries_list in api_map.items():
            seen_methods: set[str] = set()
            unique: list[dict[str, Any]] = []
            for e in entries_list:
                key = f"{e['method']}:{e.get('response_status', 0)}"
                if key not in seen_methods:
                    seen_methods.add(key)
                    unique.append(e)
            result[path] = unique

        return result

    def find_auth_tokens(self) -> list[dict[str, str]]:
        """Identify cookies/headers that look like authentication tokens."""
        tokens: list[dict[str, str]] = []
        seen: set[str] = set()

        auth_patterns = [
            re.compile(r"(bearer|token|jwt|session|auth|csrf|xsrf)", re.IGNORECASE),
        ]

        with self._lock:
            entries = list(self._traffic)

        for entry in entries:
            for header, value in entry.request.headers.items():
                header_lower = header.lower()
                if header_lower in ("authorization", "x-csrf-token", "x-xsrf-token"):
                    key = f"header:{header}:{value[:20]}"
                    if key not in seen:
                        seen.add(key)
                        tokens.append({
                            "type": "header",
                            "name": header,
                            "value_preview": value[:50] + ("..." if len(value) > 50 else ""),
                            "url": entry.request.url,
                        })

                if header_lower == "cookie":
                    for cookie_part in value.split(";"):
                        cookie_part = cookie_part.strip()
                        if "=" in cookie_part:
                            cname, cval = cookie_part.split("=", 1)
                            for p in auth_patterns:
                                if p.search(cname):
                                    key = f"cookie:{cname}:{cval[:20]}"
                                    if key not in seen:
                                        seen.add(key)
                                        tokens.append({
                                            "type": "cookie",
                                            "name": cname.strip(),
                                            "value_preview": cval[:50].strip(),
                                            "url": entry.request.url,
                                        })

        return tokens

    def find_interesting_responses(self) -> list[HTTPTrafficEntry]:
        """Find responses containing potentially interesting information."""
        interesting_patterns = [
            re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
            re.compile(r"at \w+\.\w+\(.*:\d+\)"),
            re.compile(r"/(etc/passwd|proc/self|var/log)", re.IGNORECASE),
            re.compile(r"(mysql|postgres|sqlite|mongodb).*error", re.IGNORECASE),
            re.compile(r"(api[_-]?key|secret[_-]?key|password)\s*[=:]\s*\S+", re.IGNORECASE),
            re.compile(r"X-Powered-By:", re.IGNORECASE),
            re.compile(r"Server:\s*(Apache|nginx|IIS|Tomcat)", re.IGNORECASE),
            re.compile(r'"debug"\s*:\s*true', re.IGNORECASE),
            re.compile(r"(internal server error|500|exception)", re.IGNORECASE),
        ]

        results: list[HTTPTrafficEntry] = []

        with self._lock:
            entries = list(self._traffic)

        for entry in entries:
            body = entry.response.body
            if not body:
                continue

            for pattern in interesting_patterns:
                if pattern.search(body):
                    if entry not in results:
                        results.append(entry)
                    break

        return results

    def clear(self) -> None:
        """Clear all captured traffic."""
        with self._lock:
            self._traffic.clear()


class _TrafficCaptureAddon:
    """mitmproxy addon that captures request/response pairs.

    Includes:
    - Out-of-scope domain blocking (log once per domain)
    - WebSocket message suppression (log first per connection, count rest)
    - Static asset filtering (skip JS/CSS/images/fonts)
    - Dynamic dedup of similar requests (same method+path+status → store once)
    """

    # Tags to auto-apply based on URL/content patterns
    _TAG_RULES = [
        (re.compile(r"/api/|/v\d+/|/graphql", re.IGNORECASE), "api"),
        (re.compile(r"(login|signin|auth|oauth|token)", re.IGNORECASE), "auth"),
        (re.compile(r"(register|signup|create.account)", re.IGNORECASE), "registration"),
        (re.compile(r"(upload|file|attachment|media)", re.IGNORECASE), "file_upload"),
        (re.compile(r"(payment|checkout|cart|billing|stripe|paypal)", re.IGNORECASE), "payment"),
        (re.compile(r"(admin|dashboard|manage|settings)", re.IGNORECASE), "admin"),
        (re.compile(r"\.(json|xml)(\?|$)", re.IGNORECASE), "data"),
        (re.compile(r"graphql", re.IGNORECASE), "graphql"),
    ]

    def __init__(
        self,
        scope_guard: ActiveScopeGuard,
        traffic: list[HTTPTrafficEntry],
        lock: threading.Lock,
    ) -> None:
        self._scope_guard = scope_guard
        self._traffic = traffic
        self._lock = lock
        # Dedup state
        self._blocked_domains_warned: set[str] = set()
        self._ws_connections_seen: set[str] = set()  # WebSocket URLs already logged
        self._ws_message_counts: dict[str, int] = defaultdict(int)
        self._seen_requests: dict[str, int] = {}  # dedup_key → count

    def request(self, flow: Any) -> None:
        """Called when a request is about to be sent."""
        try:
            self._scope_guard.validate_request(
                method=flow.request.method,
                url=flow.request.url,
                body=flow.request.get_text() if flow.request.content else None,
            )
        except ActiveScopeViolation:
            domain = urlparse(flow.request.url).hostname or ""
            if domain not in self._blocked_domains_warned:
                self._blocked_domains_warned.add(domain)
                logger.info("proxy_blocked_domain", domain=domain)
            flow.kill()

    def websocket_message(self, flow: Any) -> None:
        """Called for each WebSocket message — suppress spam.

        Only store the first message per WebSocket connection URL.
        Count subsequent messages silently.
        """
        ws_url = flow.request.url
        self._ws_message_counts[ws_url] += 1

        # Already seen this connection — suppress silently
        if ws_url in self._ws_connections_seen:
            return

        # First message for this connection — log once and store
        self._ws_connections_seen.add(ws_url)
        logger.info("websocket_connection", url=ws_url[:120])

        # Store a single synthetic traffic entry for this WebSocket
        try:
            msg = flow.websocket.messages[-1] if flow.websocket and flow.websocket.messages else None
            msg_preview = ""
            if msg:
                try:
                    msg_preview = msg.text[:500] if hasattr(msg, "text") and msg.text else "[binary]"
                except Exception:
                    msg_preview = "[binary]"

            entry = HTTPTrafficEntry(
                request=HTTPRequest(
                    method="WS",
                    url=ws_url,
                    headers=dict(flow.request.headers),
                    body="",
                    content_type="websocket",
                ),
                response=HTTPResponse(
                    status=101,
                    headers={},
                    body=msg_preview,
                    content_type="websocket",
                ),
                duration_ms=0,
                tags=["websocket"] + self._auto_tag(flow),
            )
            with self._lock:
                self._traffic.append(entry)
        except Exception:
            pass

    def response(self, flow: Any) -> None:
        """Called when a response is received."""
        try:
            url = flow.request.url

            # Skip static assets entirely — they waste memory and add no value
            if _is_static_asset(url):
                return

            method = flow.request.method
            status = flow.response.status_code if flow.response else 0

            # Build dedup key
            dk = _dedup_key(method, url, status)
            prev_count = self._seen_requests.get(dk, 0)
            self._seen_requests[dk] = prev_count + 1

            # For duplicate requests, only store every Nth occurrence to save memory
            # but always store the first one and any with interesting status codes
            if prev_count > 0:
                interesting_status = status >= 400 or status in (301, 302, 307)
                # Store 1st, 2nd, then every 10th duplicate
                if prev_count > 2 and not interesting_status and prev_count % 10 != 0:
                    return

            req_body = ""
            if flow.request.content:
                try:
                    req_body = flow.request.get_text()[:_MAX_BODY_SIZE]
                    req_body = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', req_body)
                except Exception:
                    req_body = "[binary]"

            resp_body = ""
            if flow.response and flow.response.content:
                try:
                    resp_body = flow.response.get_text()[:_MAX_BODY_SIZE]
                    resp_body = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', resp_body)
                except Exception:
                    resp_body = "[binary]"

            req_headers = dict(flow.request.headers)
            resp_headers = dict(flow.response.headers) if flow.response else {}

            entry = HTTPTrafficEntry(
                request=HTTPRequest(
                    method=method,
                    url=url,
                    headers=req_headers,
                    body=req_body,
                    content_type=flow.request.headers.get("content-type", ""),
                ),
                response=HTTPResponse(
                    status=status,
                    headers=resp_headers,
                    body=resp_body,
                    content_type=resp_headers.get("content-type", ""),
                ),
                duration_ms=int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
                if flow.response
                else 0,
                tags=self._auto_tag(flow),
            )

            with self._lock:
                self._traffic.append(entry)

        except Exception as e:
            logger.debug("proxy_capture_error", error=str(e))

    def _auto_tag(self, flow: Any) -> list[str]:
        """Auto-tag a flow based on URL and content patterns."""
        tags: list[str] = []
        url = flow.request.url

        for pattern, tag in self._TAG_RULES:
            if pattern.search(url):
                tags.append(tag)

        if flow.response:
            status = flow.response.status_code
            if status >= 400:
                tags.append("error")
            if status in (301, 302, 303, 307, 308):
                tags.append("redirect")

        ct = flow.request.headers.get("content-type", "")
        if "json" in ct:
            tags.append("json")
        elif "form" in ct:
            tags.append("form")
        elif "multipart" in ct:
            tags.append("multipart")

        return tags
