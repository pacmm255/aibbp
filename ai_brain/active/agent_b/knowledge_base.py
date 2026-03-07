"""LanceDB-backed knowledge base for security technique cards.

Stores technique cards extracted from H1 reports and security writeups.
Supports hybrid search (vector + metadata filtering) for retrieval.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import lancedb
import numpy as np
import structlog

logger = structlog.get_logger()

# Default DB path
DEFAULT_DB_PATH = os.path.expanduser("~/.aibbp/knowledge_base")

# Embedding dimensions (nomic-embed-text-v1.5 at 256 dims for memory efficiency)
EMBED_DIM = 384  # all-MiniLM-L6-v2 default, lightweight


class EmbeddingModel:
    """Lazy-loaded sentence-transformers embedding model."""

    _instance: EmbeddingModel | None = None
    _model: Any = None

    @classmethod
    def get(cls) -> EmbeddingModel:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load(self) -> None:
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer
        # all-MiniLM-L6-v2: 80MB, 384 dims, fast, good quality
        self._model = SentenceTransformer("all-MiniLM-L6-v2")
        logger.info("embedding_model_loaded", model="all-MiniLM-L6-v2", dim=EMBED_DIM)

    def encode(self, texts: list[str]) -> np.ndarray:
        self.load()
        return self._model.encode(texts, normalize_embeddings=True)

    def encode_one(self, text: str) -> list[float]:
        return self.encode([text])[0].tolist()


class KnowledgeBase:
    """LanceDB-backed knowledge store for technique cards."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        Path(db_path).mkdir(parents=True, exist_ok=True)
        self.db = lancedb.connect(db_path)
        self.embedder = EmbeddingModel.get()
        self._tables: dict[str, Any] = {}

    def _get_table(self, name: str):
        if name not in self._tables:
            try:
                self._tables[name] = self.db.open_table(name)
            except Exception:
                return None
        return self._tables[name]

    # ── Technique Cards ──────────────────────────────────────────

    def init_techniques_table(self) -> None:
        """Create the techniques table if it doesn't exist."""
        if "techniques" in self.db.table_names():
            return
        import pyarrow as pa
        schema = pa.schema([
            pa.field("id", pa.string()),
            pa.field("title", pa.string()),
            pa.field("vuln_class", pa.string()),      # comma-separated
            pa.field("target_tech", pa.string()),      # comma-separated
            pa.field("preconditions", pa.string()),    # JSON list
            pa.field("heuristic", pa.string()),        # core reasoning
            pa.field("reasoning_chain", pa.string()),  # WHY this works
            pa.field("attack_steps", pa.string()),     # JSON list
            pa.field("variations", pa.string()),       # JSON list
            pa.field("cwe_ids", pa.string()),          # comma-separated
            pa.field("difficulty", pa.string()),       # low/medium/high
            pa.field("severity", pa.string()),         # info/low/medium/high/critical
            pa.field("source_id", pa.string()),        # H1 report ID or writeup file
            pa.field("source_url", pa.string()),
            pa.field("bounty_amount", pa.float64()),
            pa.field("confidence", pa.float64()),
            pa.field("vector", pa.list_(pa.float32(), EMBED_DIM)),
        ])
        self.db.create_table("techniques", schema=schema)
        logger.info("techniques_table_created")

    def add_technique(self, card: dict) -> bool:
        """Add a technique card. Returns False if duplicate."""
        table = self._get_table("techniques")
        if table is None:
            self.init_techniques_table()
            table = self._get_table("techniques")

        # Check for duplicate by ID
        card_id = card.get("id", "")
        if card_id:
            try:
                existing = table.search().where(f"id = '{card_id}'").limit(1).to_list()
                if existing:
                    return False
            except Exception:
                pass

        # Generate embedding from title + heuristic + reasoning
        embed_text = f"{card.get('title', '')}. {card.get('heuristic', '')}. {card.get('reasoning_chain', '')}"
        vector = self.embedder.encode_one(embed_text)

        row = {
            "id": card_id,
            "title": card.get("title", ""),
            "vuln_class": card.get("vuln_class", ""),
            "target_tech": card.get("target_tech", ""),
            "preconditions": json.dumps(card.get("preconditions", [])),
            "heuristic": card.get("heuristic", ""),
            "reasoning_chain": card.get("reasoning_chain", ""),
            "attack_steps": json.dumps(card.get("attack_steps", [])),
            "variations": json.dumps(card.get("variations", [])),
            "cwe_ids": card.get("cwe_ids", ""),
            "difficulty": card.get("difficulty", "medium"),
            "severity": card.get("severity", "medium"),
            "source_id": card.get("source_id", ""),
            "source_url": card.get("source_url", ""),
            "bounty_amount": float(card.get("bounty_amount", 0)),
            "confidence": float(card.get("confidence", 0.5)),
            "vector": vector,
        }
        table.add([row])
        return True

    def add_techniques_batch(self, cards: list[dict]) -> int:
        """Add multiple technique cards. Returns count added."""
        table = self._get_table("techniques")
        if table is None:
            self.init_techniques_table()
            table = self._get_table("techniques")

        rows = []
        for card in cards:
            embed_text = f"{card.get('title', '')}. {card.get('heuristic', '')}. {card.get('reasoning_chain', '')}"
            vector = self.embedder.encode_one(embed_text)
            rows.append({
                "id": card.get("id", ""),
                "title": card.get("title", ""),
                "vuln_class": card.get("vuln_class", ""),
                "target_tech": card.get("target_tech", ""),
                "preconditions": json.dumps(card.get("preconditions", [])),
                "heuristic": card.get("heuristic", ""),
                "reasoning_chain": card.get("reasoning_chain", ""),
                "attack_steps": json.dumps(card.get("attack_steps", [])),
                "variations": json.dumps(card.get("variations", [])),
                "cwe_ids": card.get("cwe_ids", ""),
                "difficulty": card.get("difficulty", "medium"),
                "severity": card.get("severity", "medium"),
                "source_id": card.get("source_id", ""),
                "source_url": card.get("source_url", ""),
                "bounty_amount": float(card.get("bounty_amount", 0)),
                "confidence": float(card.get("confidence", 0.5)),
                "vector": vector,
            })

        if rows:
            table.add(rows)
        return len(rows)

    def search_techniques(
        self,
        query: str,
        technology: str | None = None,
        vuln_class: str | None = None,
        limit: int = 10,
    ) -> list[dict]:
        """Semantic search over technique cards with optional filtering."""
        table = self._get_table("techniques")
        if table is None:
            return []

        query_vec = self.embedder.encode_one(query)
        search = table.search(query_vec)

        if technology:
            search = search.where(f"target_tech LIKE '%{technology}%'")
        if vuln_class:
            search = search.where(f"vuln_class LIKE '%{vuln_class}%'")

        results = search.limit(limit).to_list()

        # Parse JSON fields back
        for r in results:
            for field in ("preconditions", "attack_steps", "variations"):
                if isinstance(r.get(field), str):
                    try:
                        r[field] = json.loads(r[field])
                    except json.JSONDecodeError:
                        r[field] = []
            r.pop("vector", None)
            r.pop("_distance", None)

        return results

    def search_for_target(
        self,
        tech_stack: list[str],
        endpoints: dict,
        tested_techniques: dict,
        limit: int = 15,
    ) -> list[dict]:
        """Retrieve techniques relevant to a target's tech stack and attack surface.

        Combines tech-stack queries, filters out already-tested techniques,
        and returns ranked results.
        """
        table = self._get_table("techniques")
        if table is None:
            return []

        all_results = []
        seen_ids = set()

        # Query per technology
        for tech in tech_stack[:5]:
            query = f"attack techniques for {tech}"
            results = self.search_techniques(query, technology=tech, limit=5)
            for r in results:
                if r["id"] not in seen_ids:
                    seen_ids.add(r["id"])
                    all_results.append(r)

        # Query for compound patterns
        if len(tech_stack) >= 2:
            compound_query = f"compound vulnerabilities {' '.join(tech_stack[:3])}"
            results = self.search_techniques(compound_query, limit=5)
            for r in results:
                if r["id"] not in seen_ids:
                    seen_ids.add(r["id"])
                    all_results.append(r)

        # General query based on endpoints
        if endpoints:
            endpoint_types = set()
            for ep_data in endpoints.values():
                if isinstance(ep_data, dict):
                    for k in ("method", "type", "params"):
                        if k in ep_data:
                            endpoint_types.add(str(ep_data[k]))
            if endpoint_types:
                ep_query = f"web application testing {' '.join(list(endpoint_types)[:5])}"
                results = self.search_techniques(ep_query, limit=5)
                for r in results:
                    if r["id"] not in seen_ids:
                        seen_ids.add(r["id"])
                        all_results.append(r)

        # Sort by confidence descending
        all_results.sort(key=lambda r: r.get("confidence", 0), reverse=True)
        return all_results[:limit]

    def count(self) -> int:
        table = self._get_table("techniques")
        if table is None:
            return 0
        return table.count_rows()

    def stats(self) -> dict:
        table = self._get_table("techniques")
        if table is None:
            return {"total": 0}
        try:
            count = table.count_rows()
            return {"total": count}
        except Exception:
            return {"total": 0}
