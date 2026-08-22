"""
AegisGuard — Auth Routes
Register, login, profile endpoints + get_current_user dependency.
"""

import logging
from fastapi import APIRouter, HTTPException, Header
from typing import Optional

from database import get_db
from auth.models import RegisterRequest, LoginRequest, TokenResponse, UserProfile
from auth.utils import hash_password, verify_password, create_token, verify_token

logger = logging.getLogger("AegisGuard.Auth")
router = APIRouter(prefix="/auth", tags=["Authentication"])


def get_current_user(authorization: Optional[str] = Header(None)) -> dict | None:
    """Extract and verify user from Authorization header. Returns None if no/invalid token."""
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "").strip()
    if not token:
        return None
    payload = verify_token(token)
    return payload  # {"uid": ..., "usr": ..., "exp": ..., "iat": ...} or None


def require_user(authorization: Optional[str] = Header(None)) -> dict:
    """Same as get_current_user but raises 401 if not authenticated."""
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated. Please login.")
    return user


@router.post("/register", response_model=TokenResponse)
def register(req: RegisterRequest):
    """Register a new user account."""
    db = get_db()
    try:
        # Check existing
        existing = db.execute(
            "SELECT id FROM users WHERE username=? OR email=?",
            (req.username, req.email)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Username or email already exists")

        hashed = hash_password(req.password)
        cursor = db.execute(
            "INSERT INTO users (username, email, password, full_name, org_name) VALUES (?, ?, ?, ?, ?)",
            (req.username, req.email, hashed, req.full_name, req.org_name)
        )
        db.commit()
        user_id = cursor.lastrowid
        token = create_token(user_id, req.username)
        logger.info(f"[AUTH] New user registered: {req.username}")
        return TokenResponse(access_token=token, username=req.username, user_id=user_id)
    finally:
        db.close()


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest):
    """Login with username and password."""
    db = get_db()
    try:
        user = db.execute(
            "SELECT id, username, password FROM users WHERE username=?",
            (req.username.strip().lower(),)
        ).fetchone()
        if not user or not verify_password(req.password, user["password"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")

        db.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
        db.commit()

        token = create_token(user["id"], user["username"])
        logger.info(f"[AUTH] User logged in: {user['username']}")
        return TokenResponse(access_token=token, username=user["username"], user_id=user["id"])
    finally:
        db.close()


@router.get("/me", response_model=UserProfile)
def get_profile(authorization: Optional[str] = Header(None)):
    """Get current user's profile."""
    user = require_user(authorization)
    db = get_db()
    try:
        row = db.execute(
            "SELECT id, username, email, full_name, org_name, created_at FROM users WHERE id=?",
            (user["uid"],)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        scan_count = db.execute(
            "SELECT COUNT(*) as cnt FROM scan_history WHERE user_id=?",
            (user["uid"],)
        ).fetchone()["cnt"]

        return UserProfile(
            id=row["id"], username=row["username"], email=row["email"],
            full_name=row["full_name"] or "", org_name=row["org_name"] or "",
            created_at=row["created_at"] or "", scan_count=scan_count,
        )
    finally:
        db.close()
