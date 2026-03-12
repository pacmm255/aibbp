"""Cross-session learning via Redis — persists bandit state, WAF profiles,
tech stack, and technique priorities across agent runs.

All Redis operations are non-fatal: if Redis is unavailable, methods return
None/False and the agent continues without cross-session data.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import structlog

logger = structlog.get_logger()


class SessionLearning:
    """Redis-backed cross-session learning for AIBBP agents."""

    def __init__(self, redis_url: str = "redis://localhost:6382", ttl: int = 7 * 24 * 3600):
        self._redis_url = redis_url
        self._ttl = ttl
        self._long_ttl = 30 * 24 * 3600  # 30 days for aggregated data
        self._redis = None

    async def connect(self) -> bool:
        """Connect to Redis. Returns False on failure (non-fatal)."""
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                self._redis_url, decode_responses=True, socket_timeout=5,
            )
            await self._redis.ping()
            logger.info("session_learning_connected", redis_url=self._redis_url)
            return True
        except Exception as e:
            logger.warning("session_learning_connect_failed", error=str(e)[:200])
            self._redis = None
            return False

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            try:
                await self._redis.aclose()
            except Exception:
                pass
            self._redis = None

    # ── Bandit State ──────────────────────────────────────────────────

    async def save_bandit_state(self, domain: str, bandit_state: dict[str, list[float]]) -> None:
        if not self._redis or not bandit_state:
            return
        try:
            key = f"bandit:{domain}"
            await self._redis.set(key, json.dumps(bandit_state), ex=self._ttl)
            logger.debug("bandit_state_saved", domain=domain, keys=len(bandit_state))
        except Exception as e:
            logger.warning("bandit_state_save_failed", error=str(e)[:200])

    async def load_bandit_state(self, domain: str) -> dict[str, list[float]] | None:
        if not self._redis:
            return None
        try:
            data = await self._redis.get(f"bandit:{domain}")
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning("bandit_state_load_failed", error=str(e)[:200])
        return None

    # ── WAF Profile ──────────────────────────────────────────────────

    async def save_waf_profile(self, domain: str, waf_data: dict[str, Any]) -> None:
        if not self._redis or not waf_data:
            return
        try:
            await self._redis.set(f"waf:{domain}", json.dumps(waf_data), ex=self._ttl)
        except Exception as e:
            logger.warning("waf_profile_save_failed", error=str(e)[:200])

    async def load_waf_profile(self, domain: str) -> dict[str, Any] | None:
        if not self._redis:
            return None
        try:
            data = await self._redis.get(f"waf:{domain}")
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning("waf_profile_load_failed", error=str(e)[:200])
        return None

    # ── Tech Stack ───────────────────────────────────────────────────

    async def save_tech_stack(self, domain: str, tech_stack: list[str]) -> None:
        if not self._redis or not tech_stack:
            return
        try:
            await self._redis.set(f"tech:{domain}", json.dumps(tech_stack), ex=self._ttl)
        except Exception as e:
            logger.warning("tech_stack_save_failed", error=str(e)[:200])

    async def load_tech_stack(self, domain: str) -> list[str] | None:
        if not self._redis:
            return None
        try:
            data = await self._redis.get(f"tech:{domain}")
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning("tech_stack_load_failed", error=str(e)[:200])
        return None

    # ── Tech-Based Finding Aggregation ───────────────────────────────

    async def record_findings_for_tech(
        self, tech_stack: list[str], findings: dict[str, dict[str, Any]],
    ) -> None:
        """Aggregate vuln_type counts for this tech stack combination."""
        if not self._redis or not tech_stack or not findings:
            return
        try:
            key = f"tech_findings:{self._tech_hash(tech_stack)}"
            existing_raw = await self._redis.get(key)
            existing: dict[str, int] = json.loads(existing_raw) if existing_raw else {}

            for _fid, info in findings.items():
                vt = info.get("vuln_type", "unknown")
                existing[vt] = existing.get(vt, 0) + 1

            await self._redis.set(key, json.dumps(existing), ex=self._long_ttl)
        except Exception as e:
            logger.warning("record_findings_for_tech_failed", error=str(e)[:200])

    async def get_technique_priorities_for_tech(
        self, tech_stack: list[str],
    ) -> dict[str, list[float]] | None:
        """Build bandit priors from historical findings for similar tech stacks."""
        if not self._redis or not tech_stack:
            return None
        try:
            key = f"tech_findings:{self._tech_hash(tech_stack)}"
            data = await self._redis.get(key)
            if not data:
                return None

            vuln_counts: dict[str, int] = json.loads(data)
            # Build bandit priors: higher alpha for vuln types found before
            priors: dict[str, list[float]] = {}
            for vt, count in vuln_counts.items():
                # Use count as alpha boost (more findings → stronger prior)
                alpha = 1.0 + min(count, 10)
                beta = 1.0
                priors[vt] = [alpha, beta]
            return priors
        except Exception as e:
            logger.warning("get_technique_priorities_failed", error=str(e)[:200])
        return None

    # ── Warm Start ───────────────────────────────────────────────────

    async def warm_start(
        self, domain: str, tech_stack: list[str] | None = None,
    ) -> dict[str, Any]:
        """Load all available cross-session data for a domain."""
        result: dict[str, Any] = {}

        bandit = await self.load_bandit_state(domain)
        if bandit:
            result["bandit_state"] = bandit

        waf = await self.load_waf_profile(domain)
        if waf:
            result["waf_profile"] = waf

        tech = await self.load_tech_stack(domain)
        if tech:
            result["tech_stack"] = tech

        # Also try tech-based priors
        stack = tech_stack or tech
        if stack:
            priors = await self.get_technique_priorities_for_tech(stack)
            if priors:
                result["tech_priors"] = priors

        if result:
            logger.info("warm_start_loaded", domain=domain, keys=list(result.keys()))

        return result

    # ── Agent Heartbeat ──────────────────────────────────────────────

    async def set_heartbeat(self, session_id: str, data: dict[str, Any]) -> None:
        """Set agent heartbeat (for dashboard live status)."""
        if not self._redis:
            return
        try:
            key = f"aibbp:agent:{session_id}"
            await self._redis.set(key, json.dumps(data), ex=120)
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _tech_hash(tech_stack: list[str]) -> str:
        """MD5 of sorted, lowered tech list."""
        normalized = sorted(t.lower().strip() for t in tech_stack if t)
        return hashlib.md5("|".join(normalized).encode()).hexdigest()[:12]
