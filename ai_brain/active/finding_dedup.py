"""Semantic finding deduplication via sentence embeddings.

Uses sentence-transformers/all-MiniLM-L6-v2 for cosine similarity.
Falls back gracefully if model is not installed — uses exact string
matching as a simple alternative.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import structlog

logger = structlog.get_logger()


class FindingDeduplicator:
    """Deduplicate findings using embedding similarity or exact matching."""

    _COSINE_THRESHOLD = 0.85
    _model = None
    _model_loaded = False

    def __init__(self, redis_client: Any | None = None):
        self._redis = redis_client
        # domain → list of (dedup_key, embedding_or_text)
        self._registered: dict[str, list[tuple[str, Any]]] = {}

    def _load_model(self) -> bool:
        """Lazy-load sentence-transformers model. Returns True if available."""
        if self._model_loaded:
            return self._model is not None
        self._model_loaded = True
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            logger.info("dedup_model_loaded", model="all-MiniLM-L6-v2")
            return True
        except Exception as e:
            logger.info("dedup_model_unavailable", error=str(e)[:100],
                        fallback="exact_match")
            self._model = None
            return False

    def _embed(self, text: str) -> Any:
        """Compute normalized embedding. Returns None if model unavailable."""
        if not self._load_model():
            return None
        try:
            import numpy as np
            vec = self._model.encode(text, normalize_embeddings=True)
            return vec
        except Exception:
            return None

    @staticmethod
    def _finding_text(finding: dict[str, Any]) -> str:
        """Build text representation of a finding for embedding."""
        vuln_type = finding.get("vuln_type", "")
        endpoint = finding.get("endpoint", "")
        evidence = str(finding.get("evidence", ""))[:200]
        parameter = finding.get("parameter", "")
        return f"{vuln_type} {endpoint} {parameter} {evidence}"

    @staticmethod
    def _dedup_key(finding: dict[str, Any]) -> str:
        """Generate a deterministic dedup key for exact matching."""
        text = f"{finding.get('vuln_type', '')}|{finding.get('endpoint', '')}|{finding.get('parameter', '')}"
        return hashlib.md5(text.encode()).hexdigest()[:16]

    def is_duplicate(self, finding: dict[str, Any], domain: str) -> bool:
        """Check if finding is a duplicate of any registered finding."""
        if domain not in self._registered or not self._registered[domain]:
            return False

        text = self._finding_text(finding)
        embedding = self._embed(text)

        for _key, stored in self._registered[domain]:
            if embedding is not None and stored is not None:
                try:
                    import numpy as np
                    sim = float(np.dot(embedding, stored))
                    if sim > self._COSINE_THRESHOLD:
                        logger.debug("finding_duplicate_detected",
                                     similarity=round(sim, 3), domain=domain)
                        return True
                except Exception:
                    pass
            else:
                # Fallback: exact dedup key match
                new_key = self._dedup_key(finding)
                if _key == new_key:
                    return True

        return False

    def register_finding(
        self, finding: dict[str, Any], domain: str, dedup_key: str | None = None,
    ) -> None:
        """Register a finding for future duplicate checks."""
        if domain not in self._registered:
            self._registered[domain] = []

        key = dedup_key or self._dedup_key(finding)
        text = self._finding_text(finding)
        embedding = self._embed(text)

        self._registered[domain].append((key, embedding if embedding is not None else text))

    def cluster_findings(
        self, findings: dict[str, dict[str, Any]], domain: str,
    ) -> list[list[str]]:
        """Group similar findings into clusters."""
        if not findings:
            return []

        fids = list(findings.keys())
        texts = [self._finding_text(findings[fid]) for fid in fids]
        embeddings = [self._embed(t) for t in texts]

        # If model unavailable, cluster by vuln_type+endpoint
        if all(e is None for e in embeddings):
            groups: dict[str, list[str]] = {}
            for fid, info in findings.items():
                key = f"{info.get('vuln_type', '')}|{info.get('endpoint', '')}"
                groups.setdefault(key, []).append(fid)
            return list(groups.values())

        # Cosine similarity clustering
        import numpy as np
        clusters: list[list[str]] = []
        assigned: set[int] = set()

        for i in range(len(fids)):
            if i in assigned:
                continue
            cluster = [fids[i]]
            assigned.add(i)
            for j in range(i + 1, len(fids)):
                if j in assigned:
                    continue
                if embeddings[i] is not None and embeddings[j] is not None:
                    sim = float(np.dot(embeddings[i], embeddings[j]))
                    if sim > self._COSINE_THRESHOLD:
                        cluster.append(fids[j])
                        assigned.add(j)
            clusters.append(cluster)

        return clusters

    async def load_from_redis(self, domain: str) -> None:
        """Load registered embeddings from Redis for cross-session dedup."""
        if not self._redis:
            return
        try:
            key = f"dedup_embeddings:{domain}"
            data = await self._redis.get(key)
            if data:
                entries = json.loads(data)
                self._registered[domain] = [
                    (e["key"], e.get("text", "")) for e in entries
                ]
                logger.info("dedup_loaded_from_redis", domain=domain,
                            count=len(entries))
        except Exception as e:
            logger.warning("dedup_load_failed", error=str(e)[:200])

    async def save_to_redis(self, domain: str) -> None:
        """Save registered entries to Redis for cross-session persistence."""
        if not self._redis or domain not in self._registered:
            return
        try:
            key = f"dedup_embeddings:{domain}"
            # Store keys and texts (not numpy arrays — those can't be JSON-serialized)
            entries = []
            for dedup_key, stored in self._registered[domain]:
                text = stored if isinstance(stored, str) else ""
                entries.append({"key": dedup_key, "text": text})
            await self._redis.set(key, json.dumps(entries), ex=7 * 24 * 3600)
        except Exception as e:
            logger.warning("dedup_save_failed", error=str(e)[:200])
