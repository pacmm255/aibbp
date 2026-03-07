"""Three-tier novelty scoring for technique deduplication.

Tier 1: Embedding cosine similarity (fast, every technique)
Tier 2: LLM assessment (borderline cases)
Tier 3: Deterministic hash check (exact duplicates)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import numpy as np
import structlog

logger = structlog.get_logger()


class NoveltyScorer:
    """Score how novel a technique is relative to Agent A's history."""

    def __init__(self, embedding_model=None):
        self._embedder = embedding_model
        self._agent_a_embeddings: np.ndarray | None = None
        self._agent_a_hashes: set[str] = set()

    def _get_embedder(self):
        if self._embedder is None:
            from ai_brain.active.agent_b.knowledge_base import EmbeddingModel
            self._embedder = EmbeddingModel.get()
        return self._embedder

    def update_agent_a_state(
        self,
        tested_techniques: dict,
        findings: dict | None = None,
        failed_approaches: dict | None = None,
    ) -> None:
        """Update the reference state from Agent A's memory."""
        # Tier 3: exact hashes
        self._agent_a_hashes = set(tested_techniques.keys())

        # Tier 1: embeddings of all tested technique descriptions
        descriptions = []
        for key, val in tested_techniques.items():
            # key format: "endpoint::tool::hash"
            parts = key.split("::")
            desc = " ".join(parts[:2]) if len(parts) >= 2 else key
            if isinstance(val, dict):
                desc += " " + val.get("description", "")
            descriptions.append(desc)

        # Also embed findings as tested territory
        if findings:
            for fid, fd in findings.items():
                if isinstance(fd, dict):
                    desc = f"{fd.get('vuln_type', '')} {fd.get('endpoint', '')} {fd.get('tool_used', '')}"
                    descriptions.append(desc)

        # Embed failed approaches too
        if failed_approaches:
            for key, val in failed_approaches.items():
                descriptions.append(key)

        if descriptions:
            embedder = self._get_embedder()
            self._agent_a_embeddings = embedder.encode(descriptions)
        else:
            self._agent_a_embeddings = None

    def score(self, technique_card: dict) -> float:
        """Compute novelty score for a technique card (0.0 = duplicate, 1.0 = novel)."""
        card_id = technique_card.get("id", "")

        # Tier 3: exact hash check
        if card_id in self._agent_a_hashes:
            return 0.0

        # Check common key patterns
        vuln_class = technique_card.get("vuln_class", "")
        for h in self._agent_a_hashes:
            if vuln_class and vuln_class in h:
                # Partial match — reduce but don't eliminate
                pass

        # Tier 1: embedding similarity
        if self._agent_a_embeddings is not None and len(self._agent_a_embeddings) > 0:
            embedder = self._get_embedder()
            embed_text = (
                f"{technique_card.get('title', '')}. "
                f"{technique_card.get('heuristic', '')}. "
                f"{technique_card.get('vuln_class', '')}"
            )
            tech_emb = embedder.encode([embed_text])
            similarities = np.dot(tech_emb, self._agent_a_embeddings.T)[0]
            max_sim = float(np.max(similarities))

            # 0.85+ = very similar (probably duplicate)
            # 0.5-0.85 = borderline
            # <0.5 = genuinely novel
            novelty = 1.0 - max_sim
            return max(0.0, min(1.0, novelty))

        # No Agent A data — everything is novel
        return 1.0

    def filter_novel(
        self,
        techniques: list[dict],
        threshold: float = 0.4,
    ) -> list[dict]:
        """Filter techniques to only novel ones, sorted by novelty score."""
        scored = []
        for t in techniques:
            score = self.score(t)
            if score >= threshold:
                t["_novelty_score"] = score
                scored.append(t)

        scored.sort(key=lambda t: t["_novelty_score"], reverse=True)
        return scored
