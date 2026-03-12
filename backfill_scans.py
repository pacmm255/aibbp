#!/usr/bin/env python3
"""Backfill scans table from transcript JSONL files with proper session_ids."""
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import asyncpg

TARGETS_DIR = Path("/root/.aibbp/targets")
DB_DSN = "postgresql://aibbp:aibbp_dev@localhost:5433/aibbp"


def parse_scan_info(path: Path) -> dict | None:
    """Extract scan metadata from a transcript file."""
    session_id = None
    target_url = None
    started_at = None
    finished_at = None
    max_turn = 0
    tools_used = set()
    findings_count = 0
    error_msg = None

    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event = obj.get("event")
                data = obj.get("data", {})
                ts = obj.get("ts", 0)
                turn = obj.get("turn", 0)

                if turn > max_turn:
                    max_turn = turn

                if event == "session_start":
                    session_id = data.get("session_id", "")
                    target_url = data.get("target_url", "")
                    if ts:
                        started_at = datetime.fromtimestamp(ts, tz=timezone.utc)

                elif event == "tool_call":
                    tools_used.add(data.get("tool_name", ""))

                elif event == "tool_result" and data.get("tool_name") == "submit_finding":
                    findings_count += 1

                elif event == "error":
                    error_msg = str(data)[:500]

                # Track last timestamp
                if ts:
                    finished_at = datetime.fromtimestamp(ts, tz=timezone.utc)

    except Exception as e:
        print(f"  Error reading {path}: {e}", file=sys.stderr)
        return None

    if not session_id or not target_url:
        return None

    # Extract domain
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    domain = parsed.hostname or ""

    return {
        "session_id": session_id,
        "target_url": target_url,
        "domain": domain,
        "status": "completed",
        "started_at": started_at,
        "finished_at": finished_at,
        "turns": max_turn,
        "findings_count": findings_count,
        "transcript_path": str(path),
        "error": error_msg,
    }


async def backfill():
    conn = await asyncpg.connect(DB_DSN)

    # Clear old fake scan records
    deleted = await conn.execute("DELETE FROM scans WHERE session_id LIKE 'react_%'")
    print(f"Deleted old fake scan records: {deleted}")

    transcript_files = sorted(TARGETS_DIR.glob("*/transcript_*.jsonl"))
    print(f"Found {len(transcript_files)} transcript files")

    inserted = 0
    skipped = 0

    for i, tf in enumerate(transcript_files):
        if (i + 1) % 200 == 0:
            print(f"  Processing {i+1}/{len(transcript_files)}... ({inserted} inserted)")

        info = parse_scan_info(tf)
        if not info:
            skipped += 1
            continue

        try:
            await conn.execute("""
                INSERT INTO scans (session_id, target_url, domain, status,
                    started_at, finished_at, turns, findings_count, transcript_path, error)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (session_id) DO UPDATE SET
                    transcript_path = COALESCE(EXCLUDED.transcript_path, scans.transcript_path),
                    turns = GREATEST(scans.turns, EXCLUDED.turns),
                    findings_count = GREATEST(scans.findings_count, EXCLUDED.findings_count),
                    finished_at = COALESCE(EXCLUDED.finished_at, scans.finished_at)
            """,
                info["session_id"], info["target_url"], info["domain"], info["status"],
                info["started_at"], info["finished_at"], info["turns"], info["findings_count"],
                info["transcript_path"], info["error"],
            )
            inserted += 1
        except Exception as e:
            print(f"  Error inserting scan {info['session_id']}: {e}", file=sys.stderr)

    # Also update findings_count from the findings table
    await conn.execute("""
        UPDATE scans SET findings_count = sub.cnt
        FROM (
            SELECT domain, COUNT(*) as cnt FROM findings GROUP BY domain
        ) sub
        WHERE scans.domain = sub.domain AND sub.cnt > scans.findings_count
    """)

    # Update confirmed_count
    await conn.execute("""
        UPDATE scans SET confirmed_count = sub.cnt
        FROM (
            SELECT domain, COUNT(*) as cnt FROM findings WHERE confirmed = true GROUP BY domain
        ) sub
        WHERE scans.domain = sub.domain
    """)

    total = await conn.fetchval("SELECT COUNT(*) FROM scans")
    with_traffic = await conn.fetchval("""
        SELECT COUNT(DISTINCT s.session_id) FROM scans s
        JOIN proxy_traffic pt ON s.session_id = pt.session_id
    """)

    print(f"\nDone! Inserted/updated {inserted} scans (skipped {skipped})")
    print(f"Total scans: {total}")
    print(f"Scans with proxy traffic: {with_traffic}")

    await conn.close()


if __name__ == "__main__":
    asyncio.run(backfill())
