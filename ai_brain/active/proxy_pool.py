"""Rotating proxy pool for Z.ai rate limit bypass.

Fetches public HTTP proxies from 28+ free proxy list APIs and GitHub repos
(same mechanism as MHDDoS — HTTP GET only, NO port scanning), validates via
three-phase pipeline (CONNECT check → HTTPS check → lazy Z.ai session),
then rotates API calls across the pool.

Each proxy IP calls Z.ai at most once per N seconds (default 3s). With 500+
healthy proxies at 3s = ~10000 calls/min throughput.

Auto-replacement: background tasks continuously validate new proxies and
replace dead ones so the pool stays healthy during long runs.

Usage:
    pool = ProxyPool(rate_limit_seconds=3.0)
    await pool.warm(min_proxies=50)
    proxy = await pool.acquire()  # blocks until rate limit OK
    try:
        client = pool.get_http_client(proxy)
        await pool.ensure_proxy_session(proxy)
        # ... make Z.ai call through proxy ...
        pool.release(proxy, success=True)
    except Exception:
        pool.release(proxy, success=False)
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import structlog

logger = structlog.get_logger("proxy_pool")

# ── Shared proxy cache (cross-process) ──────────────────────────────
_PROXY_CACHE_DIR = Path.home() / ".aibbp" / "proxy_cache"
_PROXY_CACHE_FILE = _PROXY_CACHE_DIR / "validated_proxies.json"
_PROXY_CACHE_LOCK = _PROXY_CACHE_DIR / ".lock"
_PROXY_CACHE_MAX_AGE = 300  # 5 minutes — proxies older than this are re-validated

# ── Proxy sources (HTTP GET only — NO port scanning) ─────────────────

_PROXY_SOURCES: list[dict[str, str]] = [
    # ── HTTP proxy APIs ──
    {"url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all", "protocol": "http", "format": "plain"},
    {"url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=5000&country=all&ssl=all&anonymity=all", "protocol": "http", "format": "plain"},

    # ── GitHub: TheSpeedX (updated daily, 2000+ HTTP) ──
    {"url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "protocol": "http", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: monosans (updated hourly) ──
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: ErcinDedeoglu (updated hourly) ──
    {"url": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt", "protocol": "http", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: clarketm (updated daily) ──
    {"url": "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: ShiftyTR (updated hourly) ──
    {"url": "https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: roosterkid (updated frequently) ──
    {"url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: proxifly (updated every 5 min) ──
    {"url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt", "protocol": "http", "format": "plain"},
    {"url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/https/data.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: vakhov (updated every 5-20 min) ──
    {"url": "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt", "protocol": "http", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: ALIILAPRO (updated hourly) ──
    {"url": "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: officialputuid/KangProxy ──
    {"url": "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: sunny9577/proxy-scraper ──
    {"url": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: MuRongPIG/Proxy-Master ──
    {"url": "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: Zaeem20/FREE_PROXY_LIST ──
    {"url": "https://raw.githubusercontent.com/Zaeem20/FREE_PROXY_LIST/master/http.txt", "protocol": "http", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/Zaeem20/FREE_PROXY_LIST/master/https.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: prxchk/proxy-list ──
    {"url": "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: zloi-user/hideip.me ──
    {"url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt", "protocol": "http", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: ObcbO/getproxy ──
    {"url": "https://raw.githubusercontent.com/ObcbO/getproxy/master/http.txt", "protocol": "http", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/ObcbO/getproxy/master/https.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: rdavydov/proxy-list ──
    {"url": "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt", "protocol": "http", "format": "plain"},

    # ── GitHub: Anonym0usWork1221/Free-Proxies ──
    {"url": "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt", "protocol": "http", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt", "protocol": "http", "format": "plain"},

    # ── Geonode API (HTTP) ──
    {"url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps", "protocol": "http", "format": "geonode"},

    # ── SOCKS5 proxies (lower priority — used as fallback) ──
    {"url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all&ssl=all&anonymity=all", "protocol": "socks5", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "protocol": "socks5", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "protocol": "socks5", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt", "protocol": "socks5", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "protocol": "socks5", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "protocol": "socks5", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt", "protocol": "socks5", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt", "protocol": "socks5", "format": "plain"},
    {"url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5", "protocol": "socks5", "format": "geonode"},

    # ── SOCKS4 proxies (lowest priority) ──
    {"url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=5000&country=all&ssl=all&anonymity=all", "protocol": "socks4", "format": "plain"},
    {"url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "protocol": "socks4", "format": "plain"},
]

_PROTOCOL_PRIORITY = {"http": 0, "https": 0, "socks5": 1, "socks4": 2}

# Target host for CONNECT check — we test if proxy can tunnel to Z.ai
_CONNECT_TARGET = "chat.z.ai:443"


@dataclass
class ProxyEntry:
    """A single proxy with health tracking and Z.ai session state."""

    url: str                      # http://host:port or socks5://host:port
    protocol: str                 # http, socks5, socks4
    last_call_time: float = 0.0
    consecutive_failures: int = 0
    total_calls: int = 0
    is_healthy: bool = True
    # Per-proxy Z.ai session (guest tokens are IP-bound)
    zai_token: str | None = None
    zai_user_id: str | None = None
    zai_cookies: dict = field(default_factory=dict)


class ProxyPool:
    """Rotating proxy pool with per-proxy rate limiting, Z.ai sessions,
    and automatic dead proxy replacement.

    Three-phase validation for maximum speed:
    - Phase 1: Raw TCP CONNECT check (1000 concurrent, 2s timeout) ~5% pass
    - Phase 2: Full HTTPS request through proxy (500 concurrent, 3s timeout) ~50% of P1
    - Phase 3: Z.ai session obtained lazily on first use

    Background tasks continuously grow and maintain the pool.
    """

    ZAI_BASE_URL = "https://chat.z.ai"
    _MAX_CONSECUTIVE_FAILURES = 3

    # Phase 1: raw CONNECT check (extremely fast)
    _P1_TIMEOUT = 1.5
    _P1_CONCURRENCY = 2000

    # Phase 2: full HTTPS through proxy
    _P2_TIMEOUT = 5.0
    _P2_CONCURRENCY = 300

    def __init__(
        self,
        rate_limit_seconds: float = 3.0,
        min_proxies: int = 10,
        max_proxies: int = 2000,
    ):
        self.rate_limit_seconds = rate_limit_seconds
        self.min_proxies = min_proxies
        self.max_proxies = max_proxies

        self._proxies: list[ProxyEntry] = []
        self._lock = asyncio.Lock()
        self._robin_index = 0
        self._http_clients: dict[str, httpx.AsyncClient] = {}
        self._refresh_task: asyncio.Task | None = None
        self._health_task: asyncio.Task | None = None
        self._growth_task: asyncio.Task | None = None
        self._fetch_client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=10.0),
            follow_redirects=True,
        )
        self._tried_urls: set[str] = set()
        # Phase 1 survivors awaiting Phase 2
        self._p1_passed_queue: list[ProxyEntry] = []
        # Raw untested candidates
        self._candidate_queue: list[ProxyEntry] = []
        self._closed = False

    # ── Shared proxy cache (cross-process) ────────────────────────

    def _load_cached_proxies(self) -> list[ProxyEntry]:
        """Load validated proxies from shared disk cache.

        Returns proxies that were validated less than _PROXY_CACHE_MAX_AGE ago.
        Uses file locking for safe concurrent access from multiple agents.
        """
        try:
            _PROXY_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            if not _PROXY_CACHE_FILE.exists():
                return []
            with open(_PROXY_CACHE_LOCK, "w") as lock_f:
                fcntl.flock(lock_f, fcntl.LOCK_SH)
                try:
                    data = json.loads(_PROXY_CACHE_FILE.read_text())
                finally:
                    fcntl.flock(lock_f, fcntl.LOCK_UN)

            now = time.time()
            cached_at = data.get("cached_at", 0)
            if now - cached_at > _PROXY_CACHE_MAX_AGE:
                return []  # Cache too old

            entries = []
            for p in data.get("proxies", []):
                entry = ProxyEntry(url=p["url"], protocol=p["protocol"])
                entry.zai_token = p.get("zai_token")
                entry.zai_user_id = p.get("zai_user_id")
                entry.zai_cookies = p.get("zai_cookies", {})
                entries.append(entry)
            logger.info("proxy_cache_loaded", count=len(entries),
                         age_s=int(now - cached_at))
            return entries
        except Exception as e:
            logger.debug("proxy_cache_load_failed", error=str(e))
            return []

    def _save_cached_proxies(self) -> None:
        """Save current validated proxies to shared disk cache.

        Other agents starting up can immediately use these instead of
        re-validating 100K+ proxies against Z.ai.
        """
        try:
            _PROXY_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            healthy = [p for p in self._proxies if p.is_healthy]
            data = {
                "cached_at": time.time(),
                "count": len(healthy),
                "proxies": [
                    {
                        "url": p.url,
                        "protocol": p.protocol,
                        "zai_token": p.zai_token,
                        "zai_user_id": p.zai_user_id,
                        "zai_cookies": p.zai_cookies,
                    }
                    for p in healthy
                ],
            }
            with open(_PROXY_CACHE_LOCK, "w") as lock_f:
                fcntl.flock(lock_f, fcntl.LOCK_EX)
                try:
                    _PROXY_CACHE_FILE.write_text(json.dumps(data))
                finally:
                    fcntl.flock(lock_f, fcntl.LOCK_UN)
            logger.info("proxy_cache_saved", count=len(healthy))
        except Exception as e:
            logger.debug("proxy_cache_save_failed", error=str(e))

    # ── Proxy fetching ─────────────────────────────────────────────

    async def _fetch_from_source(self, source: dict[str, str]) -> list[tuple[str, str]]:
        """Fetch proxy list from a single source via HTTP GET."""
        url = source["url"]
        protocol = source["protocol"]
        fmt = source["format"]
        results: list[tuple[str, str]] = []

        try:
            resp = await self._fetch_client.get(url)
            if resp.status_code != 200:
                return results

            if fmt == "geonode":
                data = resp.json()
                for entry in data.get("data", []):
                    ip = entry.get("ip", "")
                    port = entry.get("port", "")
                    if ip and port:
                        results.append((f"{ip}:{port}", protocol))
            else:
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if line and ":" in line and not line.startswith("#"):
                        parts = line.split(":")
                        if len(parts) >= 2:
                            try:
                                int(parts[1])
                                results.append((f"{parts[0]}:{parts[1]}", protocol))
                            except ValueError:
                                continue

            logger.debug("proxy_source_ok", url=url[:60], count=len(results))
        except Exception:
            pass

        return results

    async def _fetch_all(self) -> list[ProxyEntry]:
        """Fetch proxies from all sources, deduplicate, shuffle."""
        tasks = [self._fetch_from_source(src) for src in _PROXY_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen: dict[str, str] = {}
        for result in results:
            if isinstance(result, Exception):
                continue
            for host_port, protocol in result:
                existing = seen.get(host_port)
                if existing is None or _PROTOCOL_PRIORITY.get(protocol, 9) < _PROTOCOL_PRIORITY.get(existing, 9):
                    seen[host_port] = protocol

        grouped: dict[str, list[ProxyEntry]] = {}
        for host_port, protocol in seen.items():
            proxy_url = f"{protocol}://{host_port}"
            entry = ProxyEntry(url=proxy_url, protocol=protocol)
            grouped.setdefault(protocol, []).append(entry)

        shuffled: list[ProxyEntry] = []
        for proto in ["http", "https", "socks5", "socks4"]:
            group = grouped.get(proto, [])
            random.shuffle(group)
            shuffled.extend(group)

        counts = {proto: len(lst) for proto, lst in grouped.items()}
        logger.info("proxies_fetched", total=len(shuffled), **counts)
        return shuffled

    # ── Three-phase validation ──────────────────────────────────────

    async def _check_connect(self, proxy: ProxyEntry) -> bool:
        """Phase 1: Raw TCP CONNECT check — test if proxy supports HTTPS tunneling.

        Opens TCP to proxy, sends HTTP CONNECT request, checks for 200 response.
        This is extremely fast (no TLS, no full HTTP) and filters out proxies
        that can't tunnel HTTPS at all.

        NOT port scanning — sends a standard HTTP CONNECT to a publicly
        advertised proxy server.
        """
        try:
            # Parse proxy host:port
            addr = proxy.url.split("://", 1)[1]
            host, port_str = addr.rsplit(":", 1)
            port = int(port_str)

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self._P1_TIMEOUT,
            )
            try:
                # Send CONNECT request
                connect_req = (
                    f"CONNECT {_CONNECT_TARGET} HTTP/1.1\r\n"
                    f"Host: {_CONNECT_TARGET}\r\n"
                    f"\r\n"
                ).encode()
                writer.write(connect_req)
                await writer.drain()

                # Read response line
                response_line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=self._P1_TIMEOUT,
                )
                return b"200" in response_line
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            return False

    async def _check_https(self, proxy: ProxyEntry) -> bool:
        """Phase 2: Full HTTPS request through proxy to verify working HTTPS tunnel.

        Validates the proxy can actually complete a TLS handshake and transfer data.
        Uses Z.ai auth endpoint directly so a successful check also pre-populates
        the Z.ai session.
        """
        try:
            async with httpx.AsyncClient(
                proxy=proxy.url,
                timeout=httpx.Timeout(self._P2_TIMEOUT, connect=3.0),
            ) as client:
                resp = await client.get(
                    f"{self.ZAI_BASE_URL}/api/v1/auths/",
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    token = data.get("token", "")
                    if token:
                        proxy.zai_token = token
                        proxy.zai_user_id = data.get("id", "")
                        for name, value in resp.cookies.items():
                            proxy.zai_cookies[name] = value
                        return True
                return False
        except Exception:
            return False

    # ── Warm / refresh ─────────────────────────────────────────────

    async def warm(self, min_proxies: int | None = None, max_proxies: int | None = None) -> None:
        """Fetch and validate proxies using interleaved pipeline.

        1. Try shared disk cache first (instant startup if another agent validated recently)
        2. Stagger Phase 2 validation with random delay to avoid thundering herd
        3. Retry up to 3 times with exponential backoff instead of hard crash
        4. Save validated proxies to cache for other agents

        Runs Phase 1 (CONNECT) in waves of ~10K, then immediately runs
        Phase 2 (HTTPS+Z.ai) on survivors. Stops as soon as min_proxies
        are validated. Remaining candidates go to background growth.
        """
        if min_proxies is not None:
            self.min_proxies = min_proxies
        if max_proxies is not None:
            self.max_proxies = max_proxies

        # ── Step 0: Try shared proxy cache first ──
        cached = self._load_cached_proxies()
        if len(cached) >= self.min_proxies:
            async with self._lock:
                existing_urls = {p.url for p in self._proxies}
                for p in cached:
                    if p.url not in existing_urls:
                        self._proxies.append(p)
                if len(self._proxies) > self.max_proxies:
                    self._proxies = self._proxies[:self.max_proxies]
            logger.info("proxy_pool_warmed_from_cache", **self.stats())
            self._ensure_background_tasks()
            return

        # ── Step 1: Stagger Phase 2 to avoid thundering herd ──
        # Random delay 0-10s prevents 29 agents from all hitting Z.ai at once
        stagger_delay = random.uniform(0.5, 10.0)
        logger.info("warm_stagger_delay", delay_s=round(stagger_delay, 1))
        await asyncio.sleep(stagger_delay)

        # ── Step 2: Validate with retries ──
        max_retries = 3
        for attempt in range(max_retries):
            validated_total = await self._do_validate_proxies()

            if validated_total or self._proxies:
                break  # Got some proxies

            if attempt < max_retries - 1:
                # Before retrying, check cache again (another agent may have finished)
                cached = self._load_cached_proxies()
                if len(cached) >= self.min_proxies:
                    async with self._lock:
                        existing_urls = {p.url for p in self._proxies}
                        for p in cached:
                            if p.url not in existing_urls:
                                self._proxies.append(p)
                    logger.info("proxy_pool_warmed_from_cache_retry", **self.stats())
                    self._ensure_background_tasks()
                    return

                backoff = (2 ** attempt) * 5 + random.uniform(0, 5)
                logger.warning("warm_retry", attempt=attempt + 1, backoff_s=round(backoff, 1))
                await asyncio.sleep(backoff)
                self._tried_urls.clear()  # Reset tried URLs for retry

        if not self._proxies:
            raise RuntimeError(
                "No proxies passed validation after 3 attempts. "
                "Check network connectivity or try again later."
            )

        # Accept partial results — start with what we have, background growth will find more
        if len(self._proxies) < self.min_proxies:
            logger.warning("warm_partial_result",
                           validated=len(self._proxies), target=self.min_proxies,
                           msg="Starting with fewer proxies; background growth will find more")

        logger.info("proxy_pool_warmed", **self.stats())

        # ── Step 3: Save to cache for other agents ──
        self._save_cached_proxies()
        self._ensure_background_tasks()

    async def _do_validate_proxies(self) -> list[ProxyEntry]:
        """Core validation logic — extracted from warm() for retry support."""
        raw = await self._fetch_all()
        if not raw:
            return []

        # Skip already-in-pool and already-tried
        existing_urls = {p.url for p in self._proxies}
        new_candidates = [p for p in raw if p.url not in existing_urls and p.url not in self._tried_urls]
        if not new_candidates:
            self._tried_urls.clear()
            new_candidates = [p for p in raw if p.url not in existing_urls]

        target = self.min_proxies
        validated_total: list[ProxyEntry] = []
        p1_wave_size = 10000  # Phase 1 wave size
        sem1 = asyncio.Semaphore(self._P1_CONCURRENCY)
        sem2 = asyncio.Semaphore(self._P2_CONCURRENCY)
        total_p1_tested = 0

        async def p1_check(p: ProxyEntry) -> bool:
            async with sem1:
                return await self._check_connect(p)

        async def p2_check(p: ProxyEntry) -> bool:
            async with sem2:
                try:
                    return await asyncio.wait_for(
                        self._check_https(p), timeout=self._P2_TIMEOUT + 5.0,
                    )
                except (asyncio.TimeoutError, Exception):
                    return False

        for wave_start in range(0, len(new_candidates), p1_wave_size):
            if len(validated_total) >= target:
                # Queue remaining for background
                self._candidate_queue.extend(new_candidates[wave_start:])
                break

            wave = new_candidates[wave_start:wave_start + p1_wave_size]

            # Phase 1 on wave
            p1_tasks = [p1_check(p) for p in wave]
            p1_results = await asyncio.gather(*p1_tasks, return_exceptions=True)
            p1_survivors = []
            for proxy, result in zip(wave, p1_results):
                self._tried_urls.add(proxy.url)
                if result is True:
                    p1_survivors.append(proxy)

            total_p1_tested += len(wave)
            logger.info("phase1_wave", tested=total_p1_tested, survivors=len(p1_survivors),
                         total_validated=len(validated_total), target=target)

            if not p1_survivors:
                continue

            # Phase 2 on this wave's survivors
            p2_tasks = [p2_check(p) for p in p1_survivors]
            p2_results = await asyncio.gather(*p2_tasks, return_exceptions=True)
            wave_validated = [p for p, r in zip(p1_survivors, p2_results) if r is True]

            validated_total.extend(wave_validated)
            logger.info("phase2_wave", p1_survivors=len(p1_survivors),
                         validated=len(wave_validated), total_validated=len(validated_total),
                         target=target)

        if validated_total:
            async with self._lock:
                existing_urls = {p.url for p in self._proxies}
                for proxy in validated_total:
                    if proxy.url not in existing_urls:
                        self._proxies.append(proxy)
                self._proxies = [p for p in self._proxies if p.is_healthy]
                if len(self._proxies) > self.max_proxies:
                    self._proxies = self._proxies[:self.max_proxies]

        return validated_total

    def _ensure_background_tasks(self) -> None:
        """Start background tasks if not already running."""
        if self._closed:
            return
        if self._refresh_task is None or self._refresh_task.done():
            self._refresh_task = asyncio.create_task(self._background_refresh())
        if self._health_task is None or self._health_task.done():
            self._health_task = asyncio.create_task(self._background_health_check())
        if self._growth_task is None or self._growth_task.done():
            self._growth_task = asyncio.create_task(self._background_growth())

    async def _background_refresh(self) -> None:
        """Re-fetch proxy lists every 10 minutes and update shared cache."""
        while not self._closed:
            await asyncio.sleep(10 * 60)
            try:
                logger.info("proxy_pool_refreshing")
                raw = await self._fetch_all()
                existing = {p.url for p in self._proxies}
                new = [p for p in raw if p.url not in existing and p.url not in self._tried_urls]
                random.shuffle(new)
                self._candidate_queue.extend(new)
                logger.info("candidates_refreshed", new_candidates=len(new))
                # Update shared cache
                self._save_cached_proxies()
            except Exception as e:
                logger.warning("proxy_refresh_failed", error=str(e))

    async def _background_health_check(self) -> None:
        """Every 20 seconds: remove dead proxies."""
        while not self._closed:
            await asyncio.sleep(20)
            try:
                async with self._lock:
                    dead = [p for p in self._proxies if not p.is_healthy]
                    if dead:
                        dead_urls = {p.url for p in dead}
                        self._proxies = [p for p in self._proxies if p.is_healthy]
                        for url in dead_urls:
                            client = self._http_clients.pop(url, None)
                            if client:
                                try:
                                    await client.aclose()
                                except Exception:
                                    pass
                        logger.info("dead_proxies_removed", count=len(dead),
                                    pool_size=len(self._proxies))
            except Exception as e:
                logger.warning("health_check_error", error=str(e))

    async def _background_growth(self) -> None:
        """Continuously grow the pool by validating queued candidates.

        Processes P1-passed candidates first (only need Phase 2),
        then raw candidates (need both phases).
        Runs every 10 seconds.
        """
        while not self._closed:
            await asyncio.sleep(10)
            try:
                current_size = sum(1 for p in self._proxies if p.is_healthy)
                if current_size >= self.max_proxies:
                    continue

                added = 0

                # First: Phase-1-passed candidates (only need HTTPS/Z.ai check)
                if self._p1_passed_queue:
                    batch_size = min(200, len(self._p1_passed_queue))
                    batch = self._p1_passed_queue[:batch_size]
                    self._p1_passed_queue = self._p1_passed_queue[batch_size:]

                    sem = asyncio.Semaphore(100)

                    async def check(p: ProxyEntry) -> bool:
                        async with sem:
                            return await self._check_https(p)

                    tasks = [check(p) for p in batch]
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    new_valid = [p for p, r in zip(batch, results) if r is True]
                    if new_valid:
                        async with self._lock:
                            existing = {p.url for p in self._proxies}
                            for p in new_valid:
                                if p.url not in existing and len(self._proxies) < self.max_proxies:
                                    self._proxies.append(p)
                                    added += 1

                    if added or new_valid:
                        logger.info("bg_growth_p1queue", added=added, tested=len(batch),
                                    passed=len(new_valid), pool=len(self._proxies),
                                    p1_queue=len(self._p1_passed_queue))

                # Second: raw candidates (need both phases)
                if self._candidate_queue and added == 0:
                    batch_size = min(1000, len(self._candidate_queue))
                    batch = self._candidate_queue[:batch_size]
                    self._candidate_queue = self._candidate_queue[batch_size:]

                    # Phase 1 on batch
                    sem1 = asyncio.Semaphore(500)

                    async def p1_check(p: ProxyEntry) -> bool:
                        async with sem1:
                            return await self._check_connect(p)

                    p1_tasks = [p1_check(p) for p in batch]
                    p1_results = await asyncio.gather(*p1_tasks, return_exceptions=True)
                    p1_ok = [p for p, r in zip(batch, p1_results) if r is True]

                    if p1_ok:
                        # Phase 2 on survivors
                        sem2 = asyncio.Semaphore(100)

                        async def p2_check(p: ProxyEntry) -> bool:
                            async with sem2:
                                try:
                                    return await asyncio.wait_for(
                                        self._check_https(p), timeout=self._P2_TIMEOUT + 5.0,
                                    )
                                except (asyncio.TimeoutError, Exception):
                                    return False

                        p2_tasks = [p2_check(p) for p in p1_ok]
                        p2_results = await asyncio.gather(*p2_tasks, return_exceptions=True)
                        p2_ok = [p for p, r in zip(p1_ok, p2_results) if r is True]

                        if p2_ok:
                            async with self._lock:
                                existing = {p.url for p in self._proxies}
                                for p in p2_ok:
                                    if p.url not in existing and len(self._proxies) < self.max_proxies:
                                        self._proxies.append(p)
                                        added += 1

                        logger.info("bg_growth_raw", p1_tested=len(batch), p1_ok=len(p1_ok),
                                    p2_ok=len(p2_ok) if p1_ok else 0, added=added,
                                    pool=len(self._proxies), cand_queue=len(self._candidate_queue))

                # If queues are empty and pool is small, refill
                if (not self._p1_passed_queue and not self._candidate_queue
                        and current_size + added < self.min_proxies):
                    try:
                        raw = await self._fetch_all()
                        existing = {p.url for p in self._proxies}
                        new = [p for p in raw if p.url not in existing and p.url not in self._tried_urls]
                        random.shuffle(new)
                        self._candidate_queue = new
                        logger.info("candidate_queue_refilled", count=len(new))
                    except Exception:
                        pass

                # Save to shared cache periodically (every ~60s of bg growth)
                if added > 0:
                    self._save_cached_proxies()

            except Exception as e:
                logger.warning("bg_growth_error", error=str(e))

    async def refresh(self) -> None:
        """Manual refresh trigger."""
        await self.warm()

    # ── Acquire / release ──────────────────────────────────────────

    async def acquire(self) -> ProxyEntry:
        """Select next healthy proxy past its rate limit cooldown.

        Round-robin. Blocks briefly if all proxies are rate-limited.
        """
        max_wait = 60.0
        waited = 0.0

        while waited < max_wait:
            async with self._lock:
                healthy = [p for p in self._proxies if p.is_healthy]
                if not healthy:
                    raise RuntimeError("No healthy proxies available")

                now = time.time()
                best: ProxyEntry | None = None
                best_wait = float("inf")

                for i in range(len(healthy)):
                    idx = (self._robin_index + i) % len(healthy)
                    proxy = healthy[idx]
                    elapsed = now - proxy.last_call_time
                    if elapsed >= self.rate_limit_seconds:
                        best = proxy
                        self._robin_index = (idx + 1) % len(healthy)
                        break
                    else:
                        remaining = self.rate_limit_seconds - elapsed
                        if remaining < best_wait:
                            best_wait = remaining

                if best is not None:
                    best.last_call_time = now
                    best.total_calls += 1
                    return best

            sleep_time = min(best_wait + 0.05, 0.5)
            await asyncio.sleep(sleep_time)
            waited += sleep_time

        raise RuntimeError(f"Could not acquire proxy within {max_wait}s")

    def release(self, proxy: ProxyEntry, success: bool) -> None:
        """Update proxy health after a call."""
        if success:
            proxy.consecutive_failures = 0
        else:
            proxy.consecutive_failures += 1
            if proxy.consecutive_failures >= self._MAX_CONSECUTIVE_FAILURES:
                proxy.is_healthy = False
                proxy.zai_token = None
                proxy.zai_user_id = None
                proxy.zai_cookies = {}
                logger.warning("proxy_marked_unhealthy", url=proxy.url,
                               total_calls=proxy.total_calls)

    # ── Per-proxy Z.ai sessions ────────────────────────────────────

    async def ensure_proxy_session(self, proxy: ProxyEntry) -> None:
        """Get Z.ai guest token through this proxy's IP."""
        if proxy.zai_token:
            return

        client = self.get_http_client(proxy)
        resp = await client.get(
            f"{self.ZAI_BASE_URL}/api/v1/auths/",
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Z.ai auth via proxy failed: {resp.status_code}")
        data = resp.json()
        proxy.zai_token = data.get("token", "")
        proxy.zai_user_id = data.get("id", "")
        for name, value in resp.cookies.items():
            proxy.zai_cookies[name] = value
        logger.info("proxy_zai_session", proxy=proxy.url[:30],
                     user_id=proxy.zai_user_id[:8] if proxy.zai_user_id else "?")

    def invalidate_proxy_session(self, proxy: ProxyEntry) -> None:
        """Clear Z.ai session for a proxy."""
        proxy.zai_token = None
        proxy.zai_user_id = None
        proxy.zai_cookies = {}

    # ── HTTP client management ─────────────────────────────────────

    def get_http_client(self, proxy: ProxyEntry) -> httpx.AsyncClient:
        """Get or create a cached httpx client for this proxy."""
        if proxy.url not in self._http_clients:
            self._http_clients[proxy.url] = httpx.AsyncClient(
                proxy=proxy.url,
                timeout=httpx.Timeout(90.0, connect=15.0),
                follow_redirects=True,
            )
        return self._http_clients[proxy.url]

    # ── Stats ──────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Return pool statistics."""
        healthy = sum(1 for p in self._proxies if p.is_healthy)
        total_calls = sum(p.total_calls for p in self._proxies)
        with_session = sum(1 for p in self._proxies if p.zai_token)
        return {
            "healthy": healthy,
            "total": len(self._proxies),
            "total_calls": total_calls,
            "with_session": with_session,
            "rate_limit_seconds": self.rate_limit_seconds,
            "p1_queue": len(self._p1_passed_queue),
            "candidate_queue": len(self._candidate_queue),
        }

    # ── Cleanup ────────────────────────────────────────────────────

    async def close(self) -> None:
        """Close all HTTP clients and stop background tasks."""
        self._closed = True
        for task in [self._refresh_task, self._health_task, self._growth_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        for client in self._http_clients.values():
            try:
                await client.aclose()
            except Exception:
                pass
        self._http_clients.clear()

        try:
            await self._fetch_client.aclose()
        except Exception:
            pass
