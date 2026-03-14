"""Memory corruption attack engine — stub for import compatibility."""
from __future__ import annotations
from typing import Any

class MemCorruptionAttackEngine:
    def __init__(self, client=None, rate_delay=0.3, scope_domains=None, scope_guard=None, socks_proxy=None):
        self._client = client
        self._rate_delay = rate_delay
        self._scope_domains = scope_domains
        self._scope_guard = scope_guard
        self._socks_proxy = socks_proxy
        self._request_count = 0

    async def full_scan(self, url: str, tech_stack: list[str] | None = None, skip_protocol_probes: bool = False) -> list[dict[str, Any]]:
        return []
