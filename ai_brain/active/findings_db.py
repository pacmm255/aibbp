"""
Centralized findings database using PostgreSQL + asyncpg.

Stores all vulnerability findings with full details, deduplication,
and auto-push from running React agents.

Usage:
    from ai_brain.active.findings_db import FindingsDB

    db = FindingsDB()
    await db.connect()
    await db.upsert_finding(finding_dict, domain, target_url, session_id)
    await db.close()

CLI import:
    python -m ai_brain.active.findings_db
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from glob import glob
from pathlib import Path
from typing import Any

import asyncpg

logger = logging.getLogger("findings_db")

DSN = "postgresql://aibbp:aibbp_dev@localhost:5433/aibbp"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Identity
    finding_key     TEXT NOT NULL,
    domain          TEXT NOT NULL,
    target_url      TEXT NOT NULL,
    session_id      TEXT,

    -- Classification
    vuln_type       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT,
    description     TEXT,

    -- Location
    endpoint        TEXT,
    parameter       TEXT,
    method          TEXT,

    -- Evidence
    evidence        JSONB,
    poc_code        TEXT,
    poc_type        TEXT,
    steps_to_reproduce TEXT[],
    request_dump    TEXT,
    response_dump   TEXT,
    screenshot_b64  TEXT,

    -- Validation
    confirmed       BOOLEAN DEFAULT FALSE,
    is_false_positive BOOLEAN DEFAULT FALSE,
    fp_reason       TEXT,
    confidence      INT DEFAULT 50,
    validated_at    TIMESTAMPTZ,

    -- Metadata
    tool_used       TEXT,
    source          TEXT DEFAULT 'react_agent',
    cvss_score      NUMERIC(3,1),
    cvss_vector     TEXT,
    cwe_id          TEXT,

    -- Chain info
    chained_from    TEXT,
    attack_chain    TEXT,

    -- Bounty tracking
    bounty_program  TEXT,
    bounty_status   TEXT DEFAULT 'new',
    bounty_amount   NUMERIC(10,2),
    reported_at     TIMESTAMPTZ,

    -- Timestamps
    discovered_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    -- Deduplication
    dedup_hash      TEXT UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_findings_confirmed ON findings(confirmed);
CREATE INDEX IF NOT EXISTS idx_findings_is_fp ON findings(is_false_positive);
CREATE INDEX IF NOT EXISTS idx_findings_discovered ON findings(discovered_at);
CREATE INDEX IF NOT EXISTS idx_findings_bounty_status ON findings(bounty_status);
CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(dedup_hash);

CREATE TABLE IF NOT EXISTS finding_updates (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID REFERENCES findings(id) ON DELETE CASCADE,
    field       TEXT NOT NULL,
    old_value   TEXT,
    new_value   TEXT,
    source      TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fupdates_finding ON finding_updates(finding_id);
"""


def _dedup_hash(domain: str, vuln_type: str, endpoint: str, parameter: str = "") -> str:
    raw = f"{domain}|{vuln_type}|{endpoint}|{parameter}".lower().strip()
    return hashlib.md5(raw.encode()).hexdigest()


def _extract_field(finding: dict, *keys: str, default: Any = None) -> Any:
    """Extract a field from finding dict, trying multiple key names."""
    for k in keys:
        if k in finding and finding[k] is not None:
            return finding[k]
    return default


def _finding_to_row(finding_key: str, finding: dict, domain: str, target_url: str, session_id: str) -> dict:
    """Convert a finding dict (from memory.json format) to DB row dict."""
    vuln_type = _extract_field(finding, "vuln_type", "type", "vulnerability_type", default="unknown")
    severity = _extract_field(finding, "severity", default="info")
    endpoint = _extract_field(finding, "endpoint", "url", "affected_url", default="")
    parameter = _extract_field(finding, "parameter", "param", "vulnerable_parameter", default="")

    # Evidence — keep as JSONB
    evidence = _extract_field(finding, "evidence", "details", "raw_evidence")
    if evidence and not isinstance(evidence, (dict, list)):
        evidence = {"raw": str(evidence)}
    if isinstance(evidence, list):
        evidence = {"items": evidence}

    # Steps to reproduce
    steps = _extract_field(finding, "steps_to_reproduce", "steps", "reproduction_steps")
    if steps and isinstance(steps, str):
        steps = [s.strip() for s in steps.split("\n") if s.strip()]
    if steps and not isinstance(steps, list):
        steps = None

    # PoC
    poc_code = _extract_field(finding, "poc_code", "poc", "proof_of_concept", "payload_used", "payload")
    if poc_code and not isinstance(poc_code, str):
        poc_code = json.dumps(poc_code)

    return {
        "finding_key": finding_key,
        "domain": domain,
        "target_url": target_url,
        "session_id": session_id or "",
        "vuln_type": vuln_type,
        "severity": severity.lower() if severity else "info",
        "title": _extract_field(finding, "title", "name", default=finding_key.replace("_", " ").title()),
        "description": _extract_field(finding, "description", "desc", "summary"),
        "endpoint": endpoint,
        "parameter": parameter,
        "method": _extract_field(finding, "method", "http_method"),
        "evidence": json.dumps(evidence) if evidence else None,
        "poc_code": poc_code,
        "poc_type": _extract_field(finding, "poc_type"),
        "steps_to_reproduce": steps,
        "request_dump": _extract_field(finding, "request_dump", "request"),
        "response_dump": _extract_field(finding, "response_dump", "response"),
        "screenshot_b64": _extract_field(finding, "screenshot_b64", "screenshot"),
        "confirmed": bool(_extract_field(finding, "confirmed", default=False)),
        "is_false_positive": bool(_extract_field(finding, "is_false_positive", "false_positive", default=False)),
        "fp_reason": _extract_field(finding, "fp_reason"),
        "confidence": int(_extract_field(finding, "confidence", default=50)),
        "tool_used": _extract_field(finding, "tool_used", "tool"),
        "source": _extract_field(finding, "source", default="react_agent"),
        "cvss_score": _extract_field(finding, "cvss_score"),
        "cvss_vector": _extract_field(finding, "cvss_vector"),
        "cwe_id": _extract_field(finding, "cwe_id", "cwe"),
        "chained_from": _extract_field(finding, "chained_from"),
        "attack_chain": _ac if isinstance((_ac := _extract_field(finding, "attack_chain")), str) or _ac is None else json.dumps(_ac),
        "bounty_program": _extract_field(finding, "bounty_program"),
        "bounty_status": _extract_field(finding, "bounty_status", default="new"),
        "dedup_hash": _dedup_hash(domain, vuln_type, endpoint, parameter),
    }


class FindingsDB:
    """Async PostgreSQL client for centralized findings storage."""

    def __init__(self, dsn: str = DSN):
        self.dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def connect(self):
        """Connect to PostgreSQL and create tables if needed."""
        self._pool = await asyncpg.create_pool(self.dsn, min_size=1, max_size=5)
        async with self._pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)
        logger.info("findings_db connected")

    async def close(self):
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None

    async def upsert_finding(
        self,
        finding_key: str,
        finding: dict,
        domain: str,
        target_url: str,
        session_id: str = "",
    ) -> str | None:
        """Insert or update a single finding. Returns the finding UUID."""
        row = _finding_to_row(finding_key, finding, domain, target_url, session_id)
        async with self._pool.acquire() as conn:
            result = await conn.fetchrow(
                """
                INSERT INTO findings (
                    finding_key, domain, target_url, session_id,
                    vuln_type, severity, title, description,
                    endpoint, parameter, method,
                    evidence, poc_code, poc_type, steps_to_reproduce,
                    request_dump, response_dump, screenshot_b64,
                    confirmed, is_false_positive, fp_reason, confidence,
                    tool_used, source, cvss_score, cvss_vector, cwe_id,
                    chained_from, attack_chain,
                    bounty_program, bounty_status, dedup_hash
                ) VALUES (
                    $1, $2, $3, $4,
                    $5, $6, $7, $8,
                    $9, $10, $11,
                    $12::jsonb, $13, $14, $15,
                    $16, $17, $18,
                    $19, $20, $21, $22,
                    $23, $24, $25, $26, $27,
                    $28, $29,
                    $30, $31, $32
                )
                ON CONFLICT (dedup_hash) DO UPDATE SET
                    evidence = COALESCE(EXCLUDED.evidence, findings.evidence),
                    poc_code = COALESCE(EXCLUDED.poc_code, findings.poc_code),
                    confirmed = EXCLUDED.confirmed OR findings.confirmed,
                    is_false_positive = EXCLUDED.is_false_positive,
                    fp_reason = COALESCE(EXCLUDED.fp_reason, findings.fp_reason),
                    confidence = GREATEST(EXCLUDED.confidence, findings.confidence),
                    session_id = EXCLUDED.session_id,
                    updated_at = NOW()
                RETURNING id
                """,
                row["finding_key"], row["domain"], row["target_url"], row["session_id"],
                row["vuln_type"], row["severity"], row["title"], row["description"],
                row["endpoint"], row["parameter"], row["method"],
                row["evidence"], row["poc_code"], row["poc_type"], row["steps_to_reproduce"],
                row["request_dump"], row["response_dump"], row["screenshot_b64"],
                row["confirmed"], row["is_false_positive"], row["fp_reason"], row["confidence"],
                row["tool_used"], row["source"], row["cvss_score"], row["cvss_vector"], row["cwe_id"],
                row["chained_from"], row["attack_chain"],
                row["bounty_program"], row["bounty_status"], row["dedup_hash"],
            )
            return str(result["id"]) if result else None

    async def bulk_upsert(
        self,
        findings: dict[str, dict],
        domain: str,
        target_url: str,
        session_id: str = "",
    ) -> int:
        """Upsert multiple findings. Returns count of upserted rows."""
        if not findings:
            return 0
        count = 0
        for fkey, fdata in findings.items():
            try:
                await self.upsert_finding(fkey, fdata, domain, target_url, session_id)
                count += 1
            except Exception as e:
                logger.warning("upsert_failed key=%s: %s", fkey, e)
        return count

    async def mark_false_positive(self, finding_id: str, reason: str):
        """Mark a finding as false positive with reason."""
        async with self._pool.acquire() as conn:
            old = await conn.fetchval("SELECT is_false_positive FROM findings WHERE id = $1", finding_id)
            await conn.execute(
                "UPDATE findings SET is_false_positive = TRUE, fp_reason = $2, validated_at = NOW(), updated_at = NOW() WHERE id = $1",
                finding_id, reason,
            )
            await conn.execute(
                "INSERT INTO finding_updates (finding_id, field, old_value, new_value, source) VALUES ($1, 'is_false_positive', $2, 'true', 'manual')",
                finding_id, str(old),
            )

    async def mark_confirmed(self, finding_id: str, confidence: int = 95):
        """Mark a finding as confirmed."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE findings SET confirmed = TRUE, confidence = $2, validated_at = NOW(), updated_at = NOW() WHERE id = $1",
                finding_id, confidence,
            )
            await conn.execute(
                "INSERT INTO finding_updates (finding_id, field, old_value, new_value, source) VALUES ($1, 'confirmed', 'false', 'true', 'manual')",
                finding_id,
            )

    async def update_bounty_status(self, finding_id: str, status: str, amount: float | None = None):
        """Update bounty tracking fields."""
        async with self._pool.acquire() as conn:
            old = await conn.fetchval("SELECT bounty_status FROM findings WHERE id = $1", finding_id)
            if amount is not None:
                await conn.execute(
                    "UPDATE findings SET bounty_status = $2, bounty_amount = $3, updated_at = NOW() WHERE id = $1",
                    finding_id, status, amount,
                )
            else:
                await conn.execute(
                    "UPDATE findings SET bounty_status = $2, updated_at = NOW() WHERE id = $1",
                    finding_id, status,
                )
            await conn.execute(
                "INSERT INTO finding_updates (finding_id, field, old_value, new_value, source) VALUES ($1, 'bounty_status', $2, $3, 'manual')",
                finding_id, old, status,
            )

    async def get_findings(
        self,
        domain: str | None = None,
        severity: str | None = None,
        confirmed: bool | None = None,
        is_fp: bool | None = None,
        vuln_type: str | None = None,
        bounty_status: str | None = None,
        limit: int = 500,
    ) -> list[dict]:
        """Query findings with optional filters."""
        conditions = []
        params = []
        idx = 1

        if domain:
            conditions.append(f"domain = ${idx}")
            params.append(domain)
            idx += 1
        if severity:
            conditions.append(f"severity = ${idx}")
            params.append(severity.lower())
            idx += 1
        if confirmed is not None:
            conditions.append(f"confirmed = ${idx}")
            params.append(confirmed)
            idx += 1
        if is_fp is not None:
            conditions.append(f"is_false_positive = ${idx}")
            params.append(is_fp)
            idx += 1
        if vuln_type:
            conditions.append(f"vuln_type = ${idx}")
            params.append(vuln_type)
            idx += 1
        if bounty_status:
            conditions.append(f"bounty_status = ${idx}")
            params.append(bounty_status)
            idx += 1

        where = " AND ".join(conditions) if conditions else "TRUE"
        query = f"SELECT * FROM findings WHERE {where} ORDER BY discovered_at DESC LIMIT ${idx}"
        params.append(limit)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(r) for r in rows]

    async def get_stats(self) -> dict:
        """Get summary statistics."""
        async with self._pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM findings")
            by_severity = await conn.fetch(
                "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity ORDER BY cnt DESC"
            )
            by_domain = await conn.fetch(
                "SELECT domain, COUNT(*) as cnt FROM findings GROUP BY domain ORDER BY cnt DESC"
            )
            confirmed = await conn.fetchval("SELECT COUNT(*) FROM findings WHERE confirmed = TRUE")
            fp = await conn.fetchval("SELECT COUNT(*) FROM findings WHERE is_false_positive = TRUE")
            by_vuln = await conn.fetch(
                "SELECT vuln_type, COUNT(*) as cnt FROM findings GROUP BY vuln_type ORDER BY cnt DESC LIMIT 20"
            )
            return {
                "total": total,
                "confirmed": confirmed,
                "false_positives": fp,
                "by_severity": {r["severity"]: r["cnt"] for r in by_severity},
                "by_domain": {r["domain"]: r["cnt"] for r in by_domain},
                "by_vuln_type": {r["vuln_type"]: r["cnt"] for r in by_vuln},
            }

    async def search(self, query: str, limit: int = 50) -> list[dict]:
        """Full-text search across description, evidence, poc_code, endpoint."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM findings
                WHERE description ILIKE $1
                   OR endpoint ILIKE $1
                   OR poc_code ILIKE $1
                   OR finding_key ILIKE $1
                   OR title ILIKE $1
                   OR evidence::text ILIKE $1
                ORDER BY discovered_at DESC
                LIMIT $2
                """,
                f"%{query}%", limit,
            )
            return [dict(r) for r in rows]


# Singleton
_DB: FindingsDB | None = None


async def get_findings_db() -> FindingsDB:
    """Get or create the singleton FindingsDB instance."""
    global _DB
    if _DB is None:
        _DB = FindingsDB()
        await _DB.connect()
    return _DB


async def import_from_memory():
    """Import all existing findings from ~/.aibbp/targets/*/memory.json into DB."""
    db = FindingsDB()
    await db.connect()

    target_dir = Path.home() / ".aibbp" / "targets"
    files = list(target_dir.glob("*/memory.json"))
    total = 0

    for f in files:
        try:
            data = json.loads(f.read_text())
            domain = data.get("domain", "")
            target_url = data.get("target_url", "")
            findings = data.get("findings", {})

            if not findings or not isinstance(findings, dict):
                continue

            count = await db.bulk_upsert(findings, domain, target_url, session_id="import")
            total += count
            print(f"  {domain}: {count} findings imported")
        except Exception as e:
            print(f"  ERROR {f}: {e}")

    stats = await db.get_stats()
    print(f"\nImport complete: {total} findings imported")
    print(f"  Total in DB: {stats['total']}")
    print(f"  By severity: {stats['by_severity']}")
    print(f"  By domain: {stats['by_domain']}")

    await db.close()


if __name__ == "__main__":
    asyncio.run(import_from_memory())
