"""FastAPI dashboard server for AIBBP.

Serves the SPA dashboard, REST API, and WebSocket connections.
Includes JWT auth, findings/scans/proxy endpoints, and revalidation.

Usage:
    python -m ai_brain.active.api_server --port 8080
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
import uuid as _uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

import structlog
import uvicorn
from fastapi import FastAPI, Query, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, Response
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ai_brain.active.auth import (
    authenticate_user, check_rate_limit, create_default_admin,
    create_jwt, require_auth, decode_jwt,
)
from ai_brain.active.ws_manager import ConnectionManager

logger = structlog.get_logger()

# Dashboard static files directory
DASHBOARD_DIR = Path(__file__).parent / "dashboard"

# Globals
_findings_db = None
_redis = None
_ws_manager = ConnectionManager()
_revalidator = None
_running_tasks: set = set()
_scan_processes: dict[str, subprocess.Popen] = {}


def _validate_uuid(value: str) -> str:
    """Validate that a string is a valid UUID."""
    try:
        _uuid.UUID(value)
        return value
    except (ValueError, AttributeError):
        raise HTTPException(400, "Invalid finding ID format")


# ── Request/Response Models ──────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str

class FPRequest(BaseModel):
    reason: str = ""


class NewScanRequest(BaseModel):
    """Request body for launching a new scan via the API.

    All fields mirror the CLI arguments from react_main.py.
    Only ``target`` is required; everything else is optional.
    """

    # Required
    target: str

    # Scope
    allowed_domains: list[str] | None = None
    out_of_scope: list[str] | None = None

    # Execution
    dry_run: bool = False
    budget: float = 15.0
    max_turns: int = 150
    timeout: int = 0
    output: str | None = None
    report_format: Literal["md", "html", "json"] = "md"
    headless: bool = True
    no_memory: bool = False
    memory_dir: str | None = None

    # Email
    email_domain: str | None = None
    email_mode: Literal["local", "imap"] | None = None
    imap_host: str | None = None
    imap_user: str | None = None
    imap_password: str | None = None
    email_plus_addressing: bool = False

    # Custom headers
    header: list[str] | None = None

    # CAPTCHA
    captcha_api_key: str | None = None
    captcha_api_url: str | None = None

    # Proxy
    upstream_proxy: str | None = None
    proxy_port: int | None = None

    # Z.ai
    zai: bool = False
    zai_model: str = "glm-5"
    enable_proxylist: bool = False
    proxy_ratelimit: float = 3.0
    min_proxies: int = 10
    max_proxies: int = 100

    # Agent tuning
    max_rss: int = 700
    no_app_gate: bool = False
    force_opus: bool = False
    force_sonnet: bool = False

    # Agent C research
    zai_research: bool = False

    # Docker sandbox
    docker_sandbox: bool = False
    docker_image: str | None = None

    # External tools
    external_tools: str | None = None

    # Neo4j
    neo4j_uri: str | None = None

    # ChatGPT
    chatgpt: bool = False
    chatgpt_model: str = "gpt-5-3"


# ── Security Headers Middleware ──────────────────────────────────

async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# ── Lifespan ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _findings_db, _redis, _revalidator

    db_dsn = app.state.db_dsn
    redis_url = app.state.redis_url

    # Connect FindingsDB
    try:
        from ai_brain.active.findings_db import FindingsDB
        _findings_db = FindingsDB(db_dsn)
        await _findings_db.connect()
        logger.info("api_findings_db_connected")
    except Exception as e:
        logger.warning("api_findings_db_failed", error=str(e)[:200])
        _findings_db = None

    # Connect Redis
    try:
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(redis_url, decode_responses=True, socket_timeout=5)
        await _redis.ping()
        logger.info("api_redis_connected")
    except Exception as e:
        logger.warning("api_redis_failed", error=str(e)[:200])
        _redis = None

    # Create default admin
    if _findings_db:
        try:
            await create_default_admin(_findings_db)
            logger.info("default_admin_ensured")
        except Exception as e:
            logger.warning("default_admin_failed", error=str(e)[:200])

    # Initialize revalidator
    if _findings_db and _redis:
        try:
            from ai_brain.active.revalidator import Revalidator
            _revalidator = Revalidator(_findings_db, _redis)
        except Exception as e:
            logger.warning("revalidator_init_failed", error=str(e)[:200])

    # Start WebSocket manager
    await _ws_manager.start(redis_client=_redis)
    logger.info("ws_manager_started")

    yield

    # Shutdown
    await _ws_manager.stop()
    if _findings_db:
        await _findings_db.close()
    if _redis:
        await _redis.aclose()


app = FastAPI(title="AIBBP Security Dashboard", lifespan=lifespan)
app.state.db_dsn = "postgresql://aibbp:aibbp_dev@localhost:5433/aibbp"
app.state.redis_url = "redis://localhost:6382/0"
app.add_middleware(GZipMiddleware, minimum_size=500)
app.middleware("http")(security_headers_middleware)


# ── Static Files ─────────────────────────────────────────────────

if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")


# ── Dashboard SPA ────────────────────────────────────────────────

@app.get("/")
async def serve_dashboard():
    index = DASHBOARD_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index), headers={"Cache-Control": "no-cache"})
    raise HTTPException(404, "Dashboard not found")


# ── Auth Endpoints ───────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")

    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(429, "Too many login attempts. Try again later.")

    user = await authenticate_user(_findings_db, req.email, req.password)
    if not user:
        raise HTTPException(401, "Invalid email or password")

    token = create_jwt(str(user["id"]), user["email"], user["role"])
    try:
        await _findings_db.update_last_login(str(user["id"]))
    except Exception:
        pass

    return {
        "token": token,
        "user": {
            "id": str(user["id"]),
            "email": user["email"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
    }


@app.get("/api/auth/me")
async def get_me(user: dict = Depends(require_auth)):
    return user


# ── Findings Endpoints ───────────────────────────────────────────

@app.get("/api/findings")
async def get_findings(
    domain: str | None = None,
    severity: str | None = None,
    vuln_type: str | None = None,
    confirmed: bool | None = None,
    is_fp: bool | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: dict = Depends(require_auth),
):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")

    if search:
        results = await _findings_db.search(search, limit=per_page)
        return {"findings": _serialize_rows(results), "total": len(results), "page": 1, "per_page": per_page, "pages": 1}

    offset = (page - 1) * per_page
    rows, total = await _findings_db.get_findings_paginated(
        offset=offset, limit=per_page,
        domain=domain, severity=severity, vuln_type=vuln_type,
        confirmed=confirmed, is_fp=is_fp,
    )
    return {
        "findings": _serialize_rows(rows),
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if per_page else 1,
    }


@app.get("/api/findings/timeline")
async def get_findings_timeline(
    days: int = Query(30, ge=1, le=365),
    user: dict = Depends(require_auth),
):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    return await _findings_db.get_findings_timeline(days)


@app.get("/api/findings/{finding_id}")
async def get_finding(finding_id: str, user: dict = Depends(require_auth)):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    rows, _ = await _findings_db.get_findings_paginated(offset=0, limit=1, finding_id=finding_id)
    if not rows:
        raise HTTPException(404, "Finding not found")
    return _serialize_row(rows[0])


@app.post("/api/findings/{finding_id}/false-positive")
async def mark_false_positive(finding_id: str, req: FPRequest, user: dict = Depends(require_auth)):
    _validate_uuid(finding_id)
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    await _findings_db.mark_false_positive(finding_id, req.reason)
    if _redis:
        await _redis.publish("aibbp:findings", json.dumps({"action": "updated", "finding_id": finding_id}))
    return {"status": "ok", "finding_id": finding_id, "is_fp": True}


@app.post("/api/findings/{finding_id}/confirm")
async def confirm_finding(finding_id: str, user: dict = Depends(require_auth)):
    _validate_uuid(finding_id)
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    await _findings_db.mark_confirmed(finding_id)
    if _redis:
        await _redis.publish("aibbp:findings", json.dumps({"action": "updated", "finding_id": finding_id}))
    return {"status": "ok", "finding_id": finding_id, "confirmed": True}


@app.post("/api/findings/{finding_id}/revalidate")
async def revalidate_finding(finding_id: str, user: dict = Depends(require_auth)):
    _validate_uuid(finding_id)
    if not _revalidator:
        raise HTTPException(503, "Revalidator not available")

    async def _stream_callback(text: str, color: str):
        if _redis:
            await _redis.publish(
                f"aibbp:revalidation:{finding_id}",
                json.dumps({"type": "output", "text": text, "color": color}),
            )

    # Run revalidation in background
    task = asyncio.create_task(_run_revalidation(finding_id, _stream_callback))
    _running_tasks.add(task)
    task.add_done_callback(_running_tasks.discard)
    return {"status": "started", "finding_id": finding_id}


async def _run_revalidation(finding_id: str, callback):
    try:
        result = await _revalidator.revalidate(finding_id, callback)
        if _redis:
            await _redis.publish(
                f"aibbp:revalidation:{finding_id}",
                json.dumps({"type": "complete", "result": result}),
            )
    except Exception as e:
        logger.error("revalidation_failed", finding_id=finding_id, error=str(e)[:200])
        if _redis:
            await _redis.publish(
                f"aibbp:revalidation:{finding_id}",
                json.dumps({"type": "error", "error": str(e)[:200]}),
            )


# ── Stats ────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats(user: dict = Depends(require_auth)):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    stats = await _findings_db.get_stats()
    return stats


# ── Scans ────────────────────────────────────────────────────────

@app.get("/api/scans")
async def get_scans(
    status: str | None = None,
    domain: str | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: dict = Depends(require_auth),
):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    offset = (page - 1) * per_page
    rows, total = await _findings_db.get_scans_paginated(offset=offset, limit=per_page, status=status, domain=domain)
    return {
        "scans": _serialize_rows(rows),
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if per_page else 1,
    }


# NOTE: /api/scans/new and /api/scans/running MUST come before /api/scans/{session_id}
# to avoid being captured by the {session_id} path parameter.

@app.post("/api/scans/new")
async def launch_scan(req: NewScanRequest, user: dict = Depends(require_auth)):
    """Launch a new scan as a background subprocess."""
    import secrets as _secrets
    launch_id = _secrets.token_hex(6)
    cli_args = _build_scan_cli_args(req)
    log_path = f"/tmp/aibbp_scan_{launch_id}.log"

    cmd = [sys.executable, "-m", "ai_brain.active.react_main"] + cli_args
    logger.info("scan_launching", launch_id=launch_id, target=req.target, cmd=" ".join(cmd[:6]) + "...")
    try:
        log_fh = open(log_path, "w")
        proc = subprocess.Popen(
            cmd, stdout=log_fh, stderr=subprocess.STDOUT, start_new_session=True,
        )
    except Exception as e:
        logger.error("scan_launch_failed", error=str(e)[:300])
        raise HTTPException(500, f"Failed to launch scan: {e}")

    _scan_processes[launch_id] = proc
    logger.info("scan_launched", launch_id=launch_id, target=req.target, pid=proc.pid)
    return {"status": "started", "launch_id": launch_id, "target": req.target, "pid": proc.pid, "log_path": log_path}


@app.get("/api/scans/running")
async def get_running_scans(user: dict = Depends(require_auth)):
    """Return all tracked scan processes and whether they are still alive."""
    scans = []
    for lid, proc in list(_scan_processes.items()):
        returncode = proc.poll()
        scans.append({
            "launch_id": lid, "pid": proc.pid,
            "running": returncode is None, "returncode": returncode,
            "log_path": f"/tmp/aibbp_scan_{lid}.log",
        })
    return {"scans": scans, "count": len(scans)}


@app.post("/api/scans/{launch_id}/stop")
async def stop_scan(launch_id: str, user: dict = Depends(require_auth)):
    """Stop a running scan process."""
    proc = _scan_processes.get(launch_id)
    if not proc:
        raise HTTPException(404, "Unknown launch ID")
    if proc.poll() is not None:
        return {"status": "already_finished", "launch_id": launch_id, "returncode": proc.returncode}
    import signal
    try:
        proc.send_signal(signal.SIGTERM)
        return {"status": "stopped", "launch_id": launch_id, "pid": proc.pid}
    except Exception as e:
        raise HTTPException(500, f"Failed to stop scan: {e}")


@app.get("/api/scans/detail")
async def get_scan(session_id: str = Query(...), user: dict = Depends(require_auth)):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    scan = await _findings_db.get_scan_by_session(session_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _serialize_row(scan)


@app.get("/api/scans/transcript")
async def get_scan_transcript(
    session_id: str = Query(...),
    turn_start: int = Query(0, ge=0),
    turn_end: int = Query(0, ge=0),
    user: dict = Depends(require_auth),
):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    scan = await _findings_db.get_scan_by_session(session_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    path = scan.get("transcript_path", "")
    if not path:
        return {"events": [], "total": 0}
    events = await _findings_db.get_scan_transcript(path, turn_start, turn_end)
    return {"events": events, "total": len(events)}


# ── Scan Management (launch / monitor / stop) ────────────────────


def _build_scan_cli_args(req: NewScanRequest) -> list[str]:
    """Convert a *NewScanRequest* into CLI arguments for ``react_main``."""
    args: list[str] = ["--target", req.target]

    # Lists
    if req.allowed_domains:
        args += ["--allowed-domains"] + req.allowed_domains
    if req.out_of_scope:
        args += ["--out-of-scope"] + req.out_of_scope
    if req.header:
        args += ["--header"] + req.header

    # Boolean flags (only when True)
    if req.dry_run:
        args.append("--dry-run")
    if req.no_memory:
        args.append("--no-memory")
    if req.email_plus_addressing:
        args.append("--email-plus-addressing")
    if req.zai:
        args.append("--zai")
    if req.enable_proxylist:
        args.append("--enable-proxylist")
    if req.no_app_gate:
        args.append("--no-app-gate")
    if req.force_opus:
        args.append("--force-opus")
    if req.force_sonnet:
        args.append("--force-sonnet")
    if req.zai_research:
        args.append("--zai-research")
    if req.docker_sandbox:
        args.append("--docker-sandbox")
    if req.chatgpt:
        args.append("--chatgpt")
    if not req.headless:
        args.append("--no-headless")

    # Scalar options (only when not default / not None)
    if req.budget != 15.0:
        args += ["--budget", str(req.budget)]
    if req.max_turns != 150:
        args += ["--max-turns", str(req.max_turns)]
    if req.timeout != 0:
        args += ["--timeout", str(req.timeout)]
    if req.output:
        args += ["--output", req.output]
    if req.report_format != "md":
        args += ["--report-format", req.report_format]
    if req.memory_dir:
        args += ["--memory-dir", req.memory_dir]
    if req.email_domain:
        args += ["--email-domain", req.email_domain]
    if req.email_mode:
        args += ["--email-mode", req.email_mode]
    if req.imap_host:
        args += ["--imap-host", req.imap_host]
    if req.imap_user:
        args += ["--imap-user", req.imap_user]
    if req.imap_password:
        args += ["--imap-password", req.imap_password]
    if req.captcha_api_key:
        args += ["--captcha-api-key", req.captcha_api_key]
    if req.captcha_api_url:
        args += ["--captcha-api-url", req.captcha_api_url]
    if req.upstream_proxy:
        args += ["--upstream-proxy", req.upstream_proxy]
    if req.proxy_port is not None and req.proxy_port != 0:
        args += ["--proxy-port", str(req.proxy_port)]
    if req.zai_model != "glm-5":
        args += ["--zai-model", req.zai_model]
    if req.proxy_ratelimit != 3.0:
        args += ["--proxy-ratelimit", str(req.proxy_ratelimit)]
    if req.min_proxies != 10:
        args += ["--min-proxies", str(req.min_proxies)]
    if req.max_proxies != 100:
        args += ["--max-proxies", str(req.max_proxies)]
    if req.max_rss != 700:
        args += ["--max-rss", str(req.max_rss)]
    if req.docker_image:
        args += ["--docker-image", req.docker_image]
    if req.external_tools:
        args += ["--external-tools", req.external_tools]
    if req.neo4j_uri:
        args += ["--neo4j-uri", req.neo4j_uri]
    if req.chatgpt_model != "gpt-5-3":
        args += ["--chatgpt-model", req.chatgpt_model]

    return args


# ── Proxy ────────────────────────────────────────────────────────

@app.get("/api/proxy/traffic")
async def get_proxy_traffic(
    session_id: str | None = None,
    method: str | None = None,
    status_min: int | None = None,
    status_max: int | None = None,
    url_pattern: str | None = None,
    content_type: str | None = None,
    tag: str | None = None,
    body_search: str | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    user: dict = Depends(require_auth),
):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    offset = (page - 1) * per_page
    try:
        rows, total = await _findings_db.get_proxy_traffic(
            session_id=session_id, method=method,
            status_min=status_min, status_max=status_max,
            url_pattern=url_pattern, tag=tag,
            content_type=content_type, body_search=body_search,
            offset=offset, limit=per_page,
        )
    except Exception as e:
        if "regular expression" in str(e).lower():
            raise HTTPException(400, "Invalid URL pattern regex")
        raise
    return {
        "traffic": _serialize_rows(rows),
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if per_page else 1,
    }


@app.get("/api/proxy/traffic/{entry_id}")
async def get_proxy_traffic_entry(entry_id: int, user: dict = Depends(require_auth)):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    entry = await _findings_db.get_proxy_traffic_entry(entry_id)
    if not entry:
        raise HTTPException(404, "Traffic entry not found")
    return _serialize_row(entry)


@app.get("/api/proxy/sessions")
async def get_proxy_sessions(user: dict = Depends(require_auth)):
    """Get sessions that have proxy traffic (for session dropdown)."""
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    sessions = await _findings_db.get_proxy_sessions()
    return {"sessions": _serialize_rows(sessions)}


@app.get("/api/proxy/domains")
async def get_proxy_domains(user: dict = Depends(require_auth)):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    return await _findings_db.get_proxy_domains()


# ── Agents ───────────────────────────────────────────────────────

@app.get("/api/agents")
async def get_agents(user: dict = Depends(require_auth)):
    if not _redis:
        return {"agents": [], "note": "Redis not connected"}
    try:
        keys = []
        async for key in _redis.scan_iter("aibbp:agent:*", count=100):
            keys.append(key)

        agents = []
        for key in keys[:50]:
            data = await _redis.get(key)
            if data:
                try:
                    agent_info = json.loads(data)
                    agent_info["session_id"] = key.split(":")[-1]
                    ttl = await _redis.ttl(key)
                    agent_info["ttl_seconds"] = ttl
                    agents.append(agent_info)
                except json.JSONDecodeError:
                    pass

        return {"agents": agents, "count": len(agents)}
    except Exception as e:
        return {"agents": [], "error": str(e)[:200]}


# ── Domains ──────────────────────────────────────────────────────

@app.get("/api/domains")
async def get_domains(user: dict = Depends(require_auth)):
    if not _findings_db:
        raise HTTPException(503, "Database not connected")
    domains = await _findings_db.get_domains()
    return {"domains": domains}


# ── WebSocket ────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str = Query("")):
    user = await _ws_manager.connect(ws, token)
    if not user:
        return
    try:
        while True:
            data = await ws.receive_text()
            await _ws_manager.handle_message(ws, data)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await _ws_manager.disconnect(ws)


# ── Helpers ──────────────────────────────────────────────────────

_JSONB_FIELDS = {"request_headers", "response_headers", "config", "tags"}


def _serialize_row(row: dict) -> dict:
    """Convert a DB row dict to JSON-serializable format.

    Only parses known JSONB field names to avoid accidentally mangling
    string fields that happen to start with '{' or '['.
    """
    result = {}
    for k, v in row.items():
        if hasattr(v, 'isoformat'):
            result[k] = v.isoformat()
        elif isinstance(v, bytes):
            result[k] = v.decode('utf-8', errors='replace')
        elif isinstance(v, str) and k in _JSONB_FIELDS:
            try:
                result[k] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                result[k] = v
        else:
            result[k] = v
    return result


def _serialize_rows(rows: list[dict]) -> list[dict]:
    return [_serialize_row(r) for r in rows]


# ── CLI ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AIBBP Security Dashboard")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--db-dsn", default="postgresql://aibbp:aibbp_dev@localhost:5433/aibbp")
    parser.add_argument("--redis-url", default="redis://localhost:6382")
    args = parser.parse_args()

    app.state.db_dsn = args.db_dsn
    app.state.redis_url = args.redis_url

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
