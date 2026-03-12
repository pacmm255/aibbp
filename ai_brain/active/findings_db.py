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
import re
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
    dedup_hash      TEXT UNIQUE,

    -- Observation/ProofPack extensions (Sprint 1)
    auth_context    TEXT DEFAULT '',
    workflow_step   TEXT DEFAULT '',
    role            TEXT DEFAULT '',
    evidence_score  INT,
    verifier_confidence NUMERIC(4,3),
    exploit_maturity TEXT DEFAULT 'none',
    composite_score NUMERIC(5,3),
    proof_pack      JSONB,
    dedup_hash_v2   TEXT
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

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    display_name    TEXT,
    role            TEXT DEFAULT 'viewer',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    last_login      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      TEXT UNIQUE NOT NULL,
    target_url      TEXT NOT NULL,
    domain          TEXT,
    status          TEXT DEFAULT 'running',
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    turns           INT DEFAULT 0,
    budget_spent    NUMERIC(10,4) DEFAULT 0,
    budget_limit    NUMERIC(10,4),
    findings_count  INT DEFAULT 0,
    confirmed_count INT DEFAULT 0,
    endpoints_count INT DEFAULT 0,
    models_used     TEXT[],
    tech_stack      TEXT[],
    brain_mode      TEXT,
    transcript_path TEXT,
    error           TEXT,
    config          JSONB
);

CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);

CREATE TABLE IF NOT EXISTS proxy_traffic (
    id              BIGSERIAL PRIMARY KEY,
    session_id      TEXT,
    method          TEXT,
    url             TEXT,
    status          INT,
    content_type    TEXT,
    request_headers JSONB,
    request_body    TEXT,
    response_headers JSONB,
    response_body   TEXT,
    duration_ms     INT,
    tags            TEXT[],
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_proxy_session ON proxy_traffic(session_id);
CREATE INDEX IF NOT EXISTS idx_proxy_timestamp ON proxy_traffic(timestamp);

CREATE TABLE IF NOT EXISTS observations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      TEXT,
    type            TEXT,
    subject         TEXT,
    auth_context    TEXT,
    workflow_step   TEXT,
    tool_name       TEXT,
    turn            INT,
    confidence      NUMERIC(4,3),
    canonical_fingerprint TEXT,
    replay_recipe   JSONB,
    raw_result      JSONB,
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_obs_session ON observations(session_id);
CREATE INDEX IF NOT EXISTS idx_obs_tool ON observations(tool_name);

CREATE TABLE IF NOT EXISTS artifacts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    observation_id  UUID REFERENCES observations(id) ON DELETE CASCADE,
    finding_id      UUID REFERENCES findings(id) ON DELETE SET NULL,
    type            TEXT,
    content_hash    TEXT,
    content         TEXT,
    metadata        JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_art_obs ON artifacts(observation_id);
CREATE INDEX IF NOT EXISTS idx_art_finding ON artifacts(finding_id);
CREATE INDEX IF NOT EXISTS idx_art_hash ON artifacts(content_hash);
"""

# Migration SQL for existing databases (run separately if tables already exist)
MIGRATION_SQL = """
ALTER TABLE findings ADD COLUMN IF NOT EXISTS auth_context TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS workflow_step TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS role TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_score INT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verifier_confidence NUMERIC(4,3);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS exploit_maturity TEXT DEFAULT 'none';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS composite_score NUMERIC(5,3);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS proof_pack JSONB;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dedup_hash_v2 TEXT;
"""


def _normalize_endpoint_for_dedup(ep: str) -> str:
    """Normalize endpoint to path-only for dedup."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(ep)
        return (parsed.path.rstrip("/").lower()) or "/"
    except Exception:
        return ep.lower().strip()


# Canonical vuln type mapping (mirrors react_tools._VULN_TYPE_CANONICAL)
_DB_VULN_TYPE_CANONICAL: dict[str, str] = {
    "reflected_xss": "xss", "stored_xss": "xss", "cross_site_scripting": "xss",
    "sql_injection": "sqli", "blind_sqli": "sqli", "union_sqli": "sqli",
    "command_injection": "cmdi", "os_command_injection": "cmdi",
    "server_side_request_forgery": "ssrf", "open_redirect": "redirect",
    "url_redirect": "redirect", "cors_misconfiguration": "cors",
    "account_takeover": "ato", "path_traversal": "lfi",
    "directory_traversal": "lfi", "local_file_inclusion": "lfi",
    "nosql_injection": "nosqli",
}


def _extract_domain_from_url(url: str) -> str:
    """Extract domain from a URL (endpoint or target_url)."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower() or ""
    except Exception:
        return ""


def _normalize_parameter_for_dedup(param: str) -> str:
    """Normalize parameter for dedup — take first simple param name only."""
    if not param:
        return ""
    # Strip descriptions like "ReturnUrl (also: returnUrl, RETURNURL, ...)"
    param = re.sub(r"\s*\(.*\)", "", param)
    # Take only the first parameter name if comma/space separated
    first = re.split(r"[,\s]+", param.strip())[0]
    return first.lower().strip()


def _dedup_hash_v2(
    domain: str, vuln_type: str, endpoint: str, parameter: str = "",
    auth_context: str = "", workflow_step: str = "", role: str = "",
) -> str:
    """Enhanced dedup hash including auth/workflow/role context.

    Empty auth/workflow/role produces the same hash as v1 (backward compat).
    """
    vt = _DB_VULN_TYPE_CANONICAL.get(vuln_type.lower().strip(), vuln_type.lower().strip())
    ep = _normalize_endpoint_for_dedup(endpoint)
    param = _normalize_parameter_for_dedup(parameter)
    if not domain:
        domain = _extract_domain_from_url(endpoint)
    parts = [domain, vt, ep, param]
    # Only add extra parts if non-empty (backward compat with v1)
    extras = [auth_context.lower().strip(), workflow_step.lower().strip(), role.lower().strip()]
    if any(extras):
        parts.extend(extras)
    raw = "|".join(parts).lower().strip()
    return hashlib.md5(raw.encode()).hexdigest()


def _dedup_hash(domain: str, vuln_type: str, endpoint: str, parameter: str = "") -> str:
    # Canonicalize vuln_type and normalize endpoint for stronger dedup
    vt = _DB_VULN_TYPE_CANONICAL.get(vuln_type.lower().strip(), vuln_type.lower().strip())
    ep = _normalize_endpoint_for_dedup(endpoint)
    param = _normalize_parameter_for_dedup(parameter)
    # If domain is empty, try to extract from endpoint URL
    if not domain:
        domain = _extract_domain_from_url(endpoint)
    raw = f"{domain}|{vt}|{ep}|{param}".lower().strip()
    return hashlib.md5(raw.encode()).hexdigest()


def _extract_field(finding: dict, *keys: str, default: Any = None) -> Any:
    """Extract a field from finding dict, trying multiple key names."""
    for k in keys:
        if k in finding and finding[k] is not None:
            return finding[k]
    return default


def _finding_to_row(finding_key: str, finding: dict, domain: str, target_url: str, session_id: str) -> dict:
    """Convert a finding dict (from memory.json format) to DB row dict."""
    # Fix empty domain — extract from target_url or endpoint
    if not domain:
        domain = _extract_domain_from_url(target_url) or _extract_domain_from_url(
            _extract_field(finding, "endpoint", "url", "affected_url", default="")
        )
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
        # Sprint 1 extensions
        "auth_context": _extract_field(finding, "auth_context", default=""),
        "workflow_step": _extract_field(finding, "workflow_step", default=""),
        "role": _extract_field(finding, "role", default=""),
        "evidence_score": _extract_field(finding, "evidence_score"),
        "verifier_confidence": _extract_field(finding, "verifier_confidence"),
        "exploit_maturity": _extract_field(finding, "exploit_maturity", default="none"),
        "composite_score": _extract_field(finding, "composite_score"),
        "proof_pack": json.dumps(_extract_field(finding, "proof_pack")) if _extract_field(finding, "proof_pack") else None,
        "dedup_hash_v2": _dedup_hash_v2(
            domain, vuln_type, endpoint, parameter,
            _extract_field(finding, "auth_context", default=""),
            _extract_field(finding, "workflow_step", default=""),
            _extract_field(finding, "role", default=""),
        ),
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
            # Run migrations for existing databases (idempotent)
            try:
                await conn.execute(MIGRATION_SQL)
            except Exception:
                pass  # Columns already exist or table doesn't exist yet
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
                    bounty_program, bounty_status, dedup_hash,
                    auth_context, workflow_step, role,
                    evidence_score, verifier_confidence, exploit_maturity,
                    composite_score, proof_pack, dedup_hash_v2
                ) VALUES (
                    $1, $2, $3, $4,
                    $5, $6, $7, $8,
                    $9, $10, $11,
                    $12::jsonb, $13, $14, $15,
                    $16, $17, $18,
                    $19, $20, $21, $22,
                    $23, $24, $25, $26, $27,
                    $28, $29,
                    $30, $31, $32,
                    $33, $34, $35,
                    $36, $37, $38,
                    $39, $40::jsonb, $41
                )
                ON CONFLICT (dedup_hash) DO UPDATE SET
                    evidence = COALESCE(EXCLUDED.evidence, findings.evidence),
                    poc_code = COALESCE(EXCLUDED.poc_code, findings.poc_code),
                    confirmed = EXCLUDED.confirmed,
                    is_false_positive = EXCLUDED.is_false_positive,
                    fp_reason = COALESCE(EXCLUDED.fp_reason, findings.fp_reason),
                    confidence = GREATEST(EXCLUDED.confidence, findings.confidence),
                    session_id = EXCLUDED.session_id,
                    proof_pack = COALESCE(EXCLUDED.proof_pack, findings.proof_pack),
                    verifier_confidence = COALESCE(EXCLUDED.verifier_confidence, findings.verifier_confidence),
                    composite_score = COALESCE(EXCLUDED.composite_score, findings.composite_score),
                    exploit_maturity = COALESCE(EXCLUDED.exploit_maturity, findings.exploit_maturity),
                    dedup_hash_v2 = COALESCE(EXCLUDED.dedup_hash_v2, findings.dedup_hash_v2),
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
                row["auth_context"], row["workflow_step"], row["role"],
                row["evidence_score"], row["verifier_confidence"], row["exploit_maturity"],
                row["composite_score"], row["proof_pack"], row["dedup_hash_v2"],
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

    async def get_findings_paginated(
        self,
        offset: int = 0,
        limit: int = 50,
        finding_id: str | None = None,
        domain: str | None = None,
        severity: str | None = None,
        confirmed: bool | None = None,
        is_fp: bool | None = None,
        vuln_type: str | None = None,
    ) -> tuple[list[dict], int]:
        """Paginated findings query. Returns (rows, total_count)."""
        conditions = []
        params: list[Any] = []
        idx = 1

        if finding_id:
            conditions.append(f"id::text = ${idx}")
            params.append(finding_id)
            idx += 1
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

        where = " AND ".join(conditions) if conditions else "TRUE"

        async with self._pool.acquire() as conn:
            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM findings WHERE {where}", *params,
            )
            query = (
                f"SELECT * FROM findings WHERE {where} "
                f"ORDER BY discovered_at DESC LIMIT ${idx} OFFSET ${idx+1}"
            )
            params.extend([limit, offset])
            rows = await conn.fetch(query, *params)
            return [dict(r) for r in rows], total

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

    # ── User Management ─────────────────────────────────────────────

    async def create_user(self, email: str, password_hash: str, display_name: str = "", role: str = "viewer") -> dict:
        """Create a new user."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO users (email, password_hash, display_name, role) VALUES ($1, $2, $3, $4) RETURNING *",
                email, password_hash, display_name, role,
            )
            return dict(row)

    async def get_user_by_email(self, email: str) -> dict | None:
        """Get user by email."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
            return dict(row) if row else None

    async def update_last_login(self, user_id: str):
        """Update user's last login timestamp."""
        async with self._pool.acquire() as conn:
            await conn.execute("UPDATE users SET last_login = NOW() WHERE id = $1", user_id)

    # ── Scan Management ──────────────────────────────────────────────

    async def upsert_scan(self, session_id: str, target_url: str, domain: str = "",
                          status: str = "running", budget_limit: float = 0,
                          brain_mode: str = "", transcript_path: str = "",
                          config: dict | None = None) -> dict:
        """Insert or update a scan record."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO scans (session_id, target_url, domain, status, budget_limit,
                    brain_mode, transcript_path, config)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
                   ON CONFLICT (session_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    budget_limit = EXCLUDED.budget_limit,
                    brain_mode = COALESCE(EXCLUDED.brain_mode, scans.brain_mode),
                    transcript_path = COALESCE(EXCLUDED.transcript_path, scans.transcript_path),
                    config = COALESCE(EXCLUDED.config, scans.config)
                   RETURNING *""",
                session_id, target_url, domain, status, budget_limit,
                brain_mode, transcript_path,
                json.dumps(config) if config else None,
            )
            return dict(row)

    async def update_scan_stats(self, session_id: str, status: str | None = None,
                                turns: int | None = None, budget_spent: float | None = None,
                                findings_count: int | None = None, confirmed_count: int | None = None,
                                endpoints_count: int | None = None, models_used: list[str] | None = None,
                                tech_stack: list[str] | None = None, error: str | None = None):
        """Update scan statistics."""
        sets = []
        params = []
        idx = 1
        if status is not None:
            sets.append(f"status = ${idx}")
            params.append(status)
            idx += 1
            if status in ("completed", "failed", "stopped"):
                sets.append("finished_at = NOW()")
        if turns is not None:
            sets.append(f"turns = ${idx}")
            params.append(turns)
            idx += 1
        if budget_spent is not None:
            sets.append(f"budget_spent = ${idx}")
            params.append(budget_spent)
            idx += 1
        if findings_count is not None:
            sets.append(f"findings_count = ${idx}")
            params.append(findings_count)
            idx += 1
        if confirmed_count is not None:
            sets.append(f"confirmed_count = ${idx}")
            params.append(confirmed_count)
            idx += 1
        if endpoints_count is not None:
            sets.append(f"endpoints_count = ${idx}")
            params.append(endpoints_count)
            idx += 1
        if models_used is not None:
            sets.append(f"models_used = ${idx}")
            params.append(models_used)
            idx += 1
        if tech_stack is not None:
            sets.append(f"tech_stack = ${idx}")
            params.append(tech_stack)
            idx += 1
        if error is not None:
            sets.append(f"error = ${idx}")
            params.append(error)
            idx += 1
        if not sets:
            return
        sets_sql = ", ".join(sets)
        params.append(session_id)
        async with self._pool.acquire() as conn:
            await conn.execute(
                f"UPDATE scans SET {sets_sql} WHERE session_id = ${idx}",
                *params,
            )

    async def get_scans_paginated(self, offset: int = 0, limit: int = 50,
                                   status: str | None = None, domain: str | None = None) -> tuple[list[dict], int]:
        """Paginated scan list."""
        conditions = []
        params: list[Any] = []
        idx = 1
        if status:
            conditions.append(f"status = ${idx}")
            params.append(status)
            idx += 1
        if domain:
            conditions.append(f"domain = ${idx}")
            params.append(domain)
            idx += 1
        where = " AND ".join(conditions) if conditions else "TRUE"
        async with self._pool.acquire() as conn:
            total = await conn.fetchval(f"SELECT COUNT(*) FROM scans WHERE {where}", *params)
            query = f"SELECT * FROM scans WHERE {where} ORDER BY started_at DESC LIMIT ${idx} OFFSET ${idx+1}"
            params.extend([limit, offset])
            rows = await conn.fetch(query, *params)
            return [dict(r) for r in rows], total

    async def get_scan_by_session(self, session_id: str) -> dict | None:
        """Get scan by session_id."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM scans WHERE session_id = $1", session_id)
            return dict(row) if row else None

    # ── Proxy Traffic ────────────────────────────────────────────────

    async def insert_proxy_traffic_batch(self, entries: list[dict]) -> None:
        """Bulk insert proxy traffic entries."""
        if not entries:
            return
        async with self._pool.acquire() as conn:
            await conn.executemany(
                """INSERT INTO proxy_traffic (session_id, method, url, status, content_type,
                    request_headers, request_body, response_headers, response_body,
                    duration_ms, tags)
                   VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::jsonb, $9, $10, $11)""",
                [(
                    e.get("session_id", ""),
                    e.get("method", ""),
                    e.get("url", ""),
                    e.get("status", 0),
                    e.get("content_type", ""),
                    json.dumps(e.get("request_headers")) if e.get("request_headers") else None,
                    e.get("request_body"),
                    json.dumps(e.get("response_headers")) if e.get("response_headers") else None,
                    e.get("response_body"),
                    e.get("duration_ms", 0),
                    e.get("tags", []),
                ) for e in entries],
            )

    async def get_proxy_traffic(self, session_id: str | None = None, method: str | None = None,
                                status_min: int | None = None, status_max: int | None = None,
                                url_pattern: str | None = None, tag: str | None = None,
                                content_type: str | None = None, body_search: str | None = None,
                                offset: int = 0, limit: int = 100) -> tuple[list[dict], int]:
        """Paginated, filtered proxy traffic (excludes bodies for list view)."""
        conditions = []
        params: list[Any] = []
        idx = 1
        if session_id:
            conditions.append(f"session_id = ${idx}")
            params.append(session_id)
            idx += 1
        if method:
            conditions.append(f"method = ${idx}")
            params.append(method.upper())
            idx += 1
        if status_min is not None:
            conditions.append(f"status >= ${idx}")
            params.append(status_min)
            idx += 1
        if status_max is not None:
            conditions.append(f"status <= ${idx}")
            params.append(status_max)
            idx += 1
        if url_pattern:
            conditions.append(f"url ~ ${idx}")
            params.append(url_pattern)
            idx += 1
        if tag:
            conditions.append(f"${idx} = ANY(tags)")
            params.append(tag)
            idx += 1
        if content_type:
            conditions.append(f"content_type ILIKE ${idx}")
            params.append(f"%{content_type}%")
            idx += 1
        if body_search:
            conditions.append(f"(request_body ILIKE ${idx} OR response_body ILIKE ${idx})")
            params.append(f"%{body_search}%")
            idx += 1
        where = " AND ".join(conditions) if conditions else "TRUE"
        async with self._pool.acquire() as conn:
            total = await conn.fetchval(f"SELECT COUNT(*) FROM proxy_traffic WHERE {where}", *params)
            # Exclude bodies from list query for performance
            query = (
                f"SELECT id, session_id, method, url, status, content_type, "
                f"duration_ms, tags, timestamp "
                f"FROM proxy_traffic WHERE {where} "
                f"ORDER BY timestamp DESC LIMIT ${idx} OFFSET ${idx+1}"
            )
            params.extend([limit, offset])
            rows = await conn.fetch(query, *params)
            return [dict(r) for r in rows], total

    async def get_proxy_traffic_entry(self, entry_id: int) -> dict | None:
        """Get full proxy traffic entry including bodies."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM proxy_traffic WHERE id = $1", entry_id)
            return dict(row) if row else None

    # ── Analytics ────────────────────────────────────────────────────

    async def get_domains(self) -> list[str]:
        """Get distinct domains from findings."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT DISTINCT domain FROM findings WHERE domain != '' ORDER BY domain"
            )
            return [r["domain"] for r in rows]

    async def get_findings_timeline(self, days: int = 30) -> list[dict]:
        """Findings count by day for the last N days, broken down by severity."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT DATE(discovered_at) as date, severity, COUNT(*) as count
                   FROM findings
                   WHERE discovered_at >= NOW() - INTERVAL '1 day' * $1
                   GROUP BY DATE(discovered_at), severity
                   ORDER BY date""",
                days,
            )
            # Group by date
            by_date: dict[str, dict] = {}
            for r in rows:
                d = str(r["date"])
                if d not in by_date:
                    by_date[d] = {"date": d, "count": 0, "by_severity": {}}
                by_date[d]["count"] += r["count"]
                by_date[d]["by_severity"][r["severity"]] = r["count"]
            return list(by_date.values())

    async def get_proxy_domains(self) -> list[dict]:
        """Get domain tree data from proxy traffic."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT
                    split_part(split_part(url, '://', 2), '/', 1) as host,
                    split_part(url, split_part(split_part(url, '://', 2), '/', 1), 2) as path,
                    COUNT(*) as count
                   FROM proxy_traffic
                   WHERE url IS NOT NULL AND url != ''
                   GROUP BY host, path
                   ORDER BY host, count DESC"""
            )
            # Build tree structure
            tree: dict[str, dict] = {}
            for r in rows:
                host = r["host"] or "unknown"
                path = (r["path"] or "/").split("?")[0]
                # Truncate to first 2 path segments
                parts = [p for p in path.split("/") if p][:2]
                path_key = "/" + "/".join(parts) if parts else "/"
                if host not in tree:
                    tree[host] = {"host": host, "count": 0, "paths": {}}
                tree[host]["count"] += r["count"]
                if path_key not in tree[host]["paths"]:
                    tree[host]["paths"][path_key] = 0
                tree[host]["paths"][path_key] += r["count"]
            return [
                {
                    "host": v["host"],
                    "count": v["count"],
                    "paths": [{"path": p, "count": c} for p, c in sorted(v["paths"].items(), key=lambda x: -x[1])],
                }
                for v in sorted(tree.values(), key=lambda x: -x["count"])
            ]

    async def get_proxy_sessions(self) -> list[dict]:
        """Get session IDs that have proxy traffic, with request counts and scan info."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT pt.session_id, COUNT(*) as traffic_count,
                          s.target_url, s.status, s.started_at
                   FROM proxy_traffic pt
                   LEFT JOIN scans s ON s.session_id = pt.session_id
                   WHERE pt.session_id IS NOT NULL AND pt.session_id != ''
                   GROUP BY pt.session_id, s.target_url, s.status, s.started_at
                   ORDER BY s.started_at DESC NULLS LAST"""
            )
            return [dict(r) for r in rows]

    async def get_scan_transcript(self, transcript_path: str, turn_start: int = 0,
                                   turn_end: int = 0) -> list[dict]:
        """Parse JSONL transcript file and return events."""
        from pathlib import Path
        events = []
        try:
            p = Path(transcript_path)
            if not p.exists():
                return []
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        turn = event.get("turn", 0)
                        if turn_start and turn < turn_start:
                            continue
                        if turn_end and turn > turn_end:
                            break
                        events.append(event)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.warning("transcript_read_failed", path=transcript_path, error=str(e)[:200])
        return events

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
