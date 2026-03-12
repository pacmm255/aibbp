#!/usr/bin/env python3
"""Backfill missing title, description, poc_code, method, CWE, CVSS, steps for existing findings.

Usage: python backfill_finding_details.py [--dry-run] [--limit N]
"""

import asyncio
import json
import re
import sys
from datetime import datetime, timezone

import asyncpg

DB_DSN = "postgresql://aibbp:aibbp_dev@localhost:5433/aibbp"

# Import the enrichment logic
sys.path.insert(0, ".")
from ai_brain.active.react_tools import (
    _auto_enrich_finding,
    _VULN_TYPE_CWE,
    _VULN_TYPE_DESCRIPTION,
)


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Backfill finding details")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    pool = await asyncpg.create_pool(DB_DSN, min_size=2, max_size=5)

    # Get findings missing key fields
    query = """
        SELECT id, finding_key, vuln_type, severity, endpoint, parameter,
               method, title, description, poc_code, steps_to_reproduce,
               evidence, request_dump, response_dump, tool_used,
               cwe_id, cvss_score, cvss_vector
        FROM findings
        WHERE description IS NULL OR description = ''
           OR cwe_id IS NULL OR cwe_id = ''
           OR method IS NULL OR method = ''
        ORDER BY discovered_at DESC
    """
    rows = await pool.fetch(query)
    findings = [dict(r) for r in rows]
    if args.limit > 0:
        findings = findings[:args.limit]

    print(f"Found {len(findings)} findings to enrich")

    updated = 0
    for f in findings:
        # Build info dict matching what _auto_enrich_finding expects
        evidence_raw = ""
        if f["evidence"]:
            if isinstance(f["evidence"], dict):
                evidence_raw = json.dumps(f["evidence"])
            elif isinstance(f["evidence"], str):
                evidence_raw = f["evidence"]

        info = {
            "vuln_type": f["vuln_type"] or "",
            "severity": f["severity"] or "medium",
            "endpoint": f["endpoint"] or "",
            "parameter": f["parameter"] or "",
            "method": f["method"] or "",
            "title": f["title"] or "",
            "description": f["description"] or "",
            "poc_code": f["poc_code"] or "",
            "steps_to_reproduce": f["steps_to_reproduce"],
            "evidence": evidence_raw,
            "request_dump": f["request_dump"] or "",
            "response_dump": f["response_dump"] or "",
            "tool_used": f["tool_used"] or "",
            "cwe_id": f["cwe_id"] or "",
            "cvss_score": float(f["cvss_score"]) if f["cvss_score"] else None,
            "cvss_vector": f["cvss_vector"] or "",
        }

        _auto_enrich_finding(info)

        # Check what changed
        changes = {}
        field_map = {
            "title": "title",
            "description": "description",
            "method": "method",
            "cwe_id": "cwe_id",
            "cvss_score": "cvss_score",
            "cvss_vector": "cvss_vector",
            "poc_code": "poc_code",
        }

        for info_key, db_key in field_map.items():
            old_val = f[db_key]
            new_val = info.get(info_key)
            if new_val and (not old_val or old_val == ""):
                changes[db_key] = new_val

        # Handle steps_to_reproduce (array)
        if info.get("steps_to_reproduce") and not f["steps_to_reproduce"]:
            changes["steps_to_reproduce"] = info["steps_to_reproduce"]

        if not changes:
            continue

        vt = (f["vuln_type"] or "?")[:25]
        ep = (f["endpoint"] or "?")[:40]
        fields = ", ".join(changes.keys())
        print(f"  [{vt:25s}] {ep:40s} + {fields}")

        if not args.dry_run:
            # Build UPDATE query
            set_parts = []
            params = [f["id"]]
            idx = 2
            for col, val in changes.items():
                if col == "steps_to_reproduce":
                    set_parts.append(f"{col} = ${idx}")
                    params.append(val)
                elif col == "cvss_score":
                    set_parts.append(f"{col} = ${idx}")
                    params.append(float(val) if val else None)
                else:
                    set_parts.append(f"{col} = ${idx}")
                    params.append(str(val) if val is not None else None)
                idx += 1

            set_parts.append(f"updated_at = ${idx}")
            params.append(datetime.now(timezone.utc))

            sql = f"UPDATE findings SET {', '.join(set_parts)} WHERE id = $1"
            await pool.execute(sql, *params)
            updated += 1

    print(f"\nDone: {updated} findings enriched" + (" (dry run)" if args.dry_run else ""))
    await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
