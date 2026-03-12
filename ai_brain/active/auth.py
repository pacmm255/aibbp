"""JWT + bcrypt authentication for the AIBBP dashboard."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
import jwt
from fastapi import Request, HTTPException

# JWT config
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

_JWT_SECRET_FILE = Path.home() / ".aibbp" / ".jwt_secret"


def _load_jwt_secret() -> str:
    """Load JWT secret from env var, file, or generate and persist a new one."""
    # 1. Env var takes priority
    env_secret = os.environ.get("AIBBP_JWT_SECRET", "")
    if env_secret:
        return env_secret

    # 2. Read from persisted file
    if _JWT_SECRET_FILE.is_file():
        secret = _JWT_SECRET_FILE.read_text().strip()
        if secret:
            return secret

    # 3. Generate new secret and persist it
    secret = os.urandom(32).hex()
    _JWT_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    _JWT_SECRET_FILE.write_text(secret)
    _JWT_SECRET_FILE.chmod(0o600)
    return secret


JWT_SECRET = _load_jwt_secret()


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except Exception:
        return False


def create_jwt(user_id: str, email: str, role: str) -> str:
    """Create a JWT token with 24h expiry."""
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict | None:
    """Decode and validate a JWT token. Returns payload dict or None."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


async def create_default_admin(db) -> None:
    """Create default admin user if no users exist."""
    existing = await db.get_user_by_email("admin@aibbp.local")
    if existing:
        return
    await db.create_user(
        email="admin@aibbp.local",
        password_hash=hash_password("admin"),
        display_name="Admin",
        role="admin",
    )


async def authenticate_user(db, email: str, password: str) -> dict | None:
    """Authenticate user by email and password. Returns user dict or None."""
    user = await db.get_user_by_email(email)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


async def require_auth(request: Request) -> dict:
    """FastAPI dependency: validate JWT from Authorization header or query param. Returns user dict or raises 401."""
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    if not token:
        token = request.query_params.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication token")

    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return {
        "user_id": payload.get("sub"),
        "email": payload.get("email"),
        "role": payload.get("role"),
    }


# Rate limiting for auth endpoints (in-memory)
_auth_attempts: dict[str, list[float]] = {}
_AUTH_WINDOW = 60  # seconds
_AUTH_MAX_ATTEMPTS = 5

def check_rate_limit(identifier: str) -> bool:
    """Check if identifier (IP) has exceeded auth rate limit. Returns True if allowed."""
    import time
    now = time.time()
    attempts = _auth_attempts.get(identifier, [])
    # Clean old attempts
    attempts = [t for t in attempts if now - t < _AUTH_WINDOW]
    _auth_attempts[identifier] = attempts
    if len(attempts) >= _AUTH_MAX_ATTEMPTS:
        return False
    attempts.append(now)
    _auth_attempts[identifier] = attempts
    return True
