#!/usr/bin/env python3
"""Backfill proxy_traffic table from transcript JSONL files.

Extracts send_http_request tool_call/tool_result pairs and inserts them
into the proxy_traffic PostgreSQL table.
"""
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import asyncpg

TARGETS_DIR = Path("/root/.aibbp/targets")
DB_DSN = "postgresql://aibbp:aibbp_dev@localhost:5433/aibbp"
BATCH_SIZE = 200


def parse_transcript(path: Path) -> list[dict]:
    """Parse a transcript JSONL file and extract HTTP traffic entries."""
    entries = []
    session_id = None

    # First pass: collect tool_call inputs keyed by tool_id
    tool_calls = {}  # tool_id -> {method, url, headers, body}
    tool_results = []  # list of (timestamp, turn, tool_name, result_str, tool_id_hint)

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

                if event == "session_start":
                    session_id = data.get("session_id", "")

                elif event == "tool_call" and data.get("tool_name") == "send_http_request":
                    tool_id = data.get("tool_id", "")
                    try:
                        inp = json.loads(data.get("input", "{}"))
                    except (json.JSONDecodeError, TypeError):
                        inp = {}
                    tool_calls[tool_id] = {
                        "method": inp.get("method", "GET"),
                        "url": inp.get("url", ""),
                        "headers": inp.get("headers", {}),
                        "body": inp.get("body", inp.get("data", "")),
                        "ts": ts,
                        "turn": turn,
                    }

                elif event == "tool_result" and data.get("tool_name") == "send_http_request":
                    tool_results.append({
                        "ts": ts,
                        "turn": turn,
                        "result_str": data.get("result", ""),
                        "elapsed_ms": data.get("elapsed_ms", 0),
                        "is_error": data.get("is_error", False),
                    })
    except Exception as e:
        print(f"  Error reading {path}: {e}", file=sys.stderr)
        return []

    if not session_id:
        return []

    # Match tool_results to tool_calls by order (they appear in sequence)
    call_list = sorted(tool_calls.values(), key=lambda x: x["ts"])

    for i, tr in enumerate(tool_results):
        # Parse response
        result_str = tr["result_str"]
        try:
            result = json.loads(result_str)
        except (json.JSONDecodeError, TypeError):
            # Try extracting JSON from string
            if isinstance(result_str, str):
                idx = result_str.find("{")
                if idx >= 0:
                    try:
                        result = json.loads(result_str[idx:])
                    except json.JSONDecodeError:
                        continue
                else:
                    continue
            else:
                continue

        if tr["is_error"] or "error" in result:
            continue

        status_code = result.get("status_code", result.get("status", 0))
        try:
            status_code = int(status_code)
        except (ValueError, TypeError):
            status_code = 0

        resp_headers = result.get("headers", {})
        resp_body = result.get("body", "")
        if isinstance(resp_body, dict):
            resp_body = json.dumps(resp_body)

        # Get matching request info
        if i < len(call_list):
            call = call_list[i]
            method = call["method"]
            url = call["url"]
            req_headers = call["headers"]
            req_body = call["body"]
        else:
            method = "GET"
            url = ""
            req_headers = {}
            req_body = ""

        if not url:
            continue

        # Parse URL for content_type
        content_type = ""
        if isinstance(resp_headers, dict):
            content_type = resp_headers.get("content-type", resp_headers.get("Content-Type", ""))

        # Calculate elapsed
        elapsed = tr.get("elapsed_ms", 0)
        if isinstance(elapsed, str):
            try:
                elapsed = int(float(elapsed))
            except (ValueError, TypeError):
                elapsed = 0

        timestamp = datetime.fromtimestamp(tr["ts"], tz=timezone.utc) if tr["ts"] else datetime.now(tz=timezone.utc)

        if isinstance(req_body, dict):
            req_body = json.dumps(req_body)

        entries.append({
            "session_id": session_id,
            "method": method.upper(),
            "url": url,
            "status": status_code,
            "content_type": content_type[:200] if content_type else "",
            "request_headers": json.dumps(req_headers) if isinstance(req_headers, dict) else str(req_headers),
            "request_body": str(req_body or "")[:50000],
            "response_headers": json.dumps(resp_headers) if isinstance(resp_headers, dict) else str(resp_headers),
            "response_body": str(resp_body or "")[:100000],
            "duration_ms": elapsed,
            "tags": [],
            "timestamp": timestamp,
        })

    return entries


async def backfill():
    conn = await asyncpg.connect(DB_DSN)

    # Get all transcript files
    transcript_files = sorted(TARGETS_DIR.glob("*/transcript_*.jsonl"))
    print(f"Found {len(transcript_files)} transcript files")

    total_inserted = 0
    batch = []

    for i, tf in enumerate(transcript_files):
        if (i + 1) % 100 == 0:
            print(f"  Processing {i+1}/{len(transcript_files)}... ({total_inserted} inserted so far)")

        entries = parse_transcript(tf)
        batch.extend(entries)

        if len(batch) >= BATCH_SIZE:
            inserted = await insert_batch(conn, batch)
            total_inserted += inserted
            batch = []

    # Final batch
    if batch:
        inserted = await insert_batch(conn, batch)
        total_inserted += inserted

    print(f"\nDone! Inserted {total_inserted} proxy traffic entries")

    # Also update scans table with transcript_path
    updated = await update_scan_transcript_paths(conn)
    print(f"Updated {updated} scan records with transcript_path")

    await conn.close()


async def insert_batch(conn, batch):
    if not batch:
        return 0

    count = 0
    for entry in batch:
        try:
            await conn.execute("""
                INSERT INTO proxy_traffic
                    (session_id, method, url, status, content_type,
                     request_headers, request_body, response_headers, response_body,
                     duration_ms, tags, timestamp)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            """,
                entry["session_id"],
                entry["method"],
                entry["url"],
                entry["status"],
                entry["content_type"],
                json.dumps(json.loads(entry["request_headers"])) if entry["request_headers"].startswith("{") else "{}",
                entry["request_body"],
                json.dumps(json.loads(entry["response_headers"])) if entry["response_headers"].startswith("{") else "{}",
                entry["response_body"],
                entry["duration_ms"],
                entry["tags"],
                entry["timestamp"],
            )
            count += 1
        except Exception as e:
            # Skip duplicates or invalid entries
            if "duplicate" not in str(e).lower():
                pass  # silently skip

    return count


async def update_scan_transcript_paths(conn):
    """Update scans table with transcript_path for scans that don't have one."""
    rows = await conn.fetch("SELECT session_id FROM scans WHERE transcript_path IS NULL OR transcript_path = ''")
    updated = 0

    for row in rows:
        sid = row["session_id"]
        # Find transcript file for this session
        matches = list(TARGETS_DIR.glob(f"*/transcript_{sid}.jsonl"))
        if matches:
            await conn.execute(
                "UPDATE scans SET transcript_path = $1 WHERE session_id = $2",
                str(matches[0]), sid
            )
            updated += 1

    return updated


if __name__ == "__main__":
    asyncio.run(backfill())
