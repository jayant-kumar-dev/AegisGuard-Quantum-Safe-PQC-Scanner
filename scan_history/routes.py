"""
AegisGuard — Scan History
Endpoints to save, retrieve, and manage per-user scan history.
"""

import json
import logging
from typing import Optional
from fastapi import APIRouter, Header, HTTPException

from database import get_db
from auth.routes import get_current_user

logger = logging.getLogger("AegisGuard.History")
router = APIRouter(prefix="/history", tags=["Scan History"])


def save_scan(user_id: int, scan_result: dict):
    """Save a scan result to the user's history."""
    try:
        db = get_db()
        raw_tls = scan_result.get("raw_tls") or {}
        db.execute(
            """INSERT INTO scan_history
               (user_id, target, port, mode, score, grade, pqc_safe, tls_version, cipher, scan_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                raw_tls.get("host") or scan_result.get("target", ""),
                raw_tls.get("port", 443),
                "full",
                scan_result.get("score", 0),
                scan_result.get("grade", ""),
                1 if scan_result.get("quantum_safe") else 0,
                raw_tls.get("tls_version", ""),
                raw_tls.get("cipher_suite", ""),
                json.dumps(scan_result, default=str),
            )
        )
        db.commit()
        db.close()
        logger.info(f"[HISTORY] Saved scan for user {user_id}: {raw_tls.get('host')}")
    except Exception as e:
        logger.warning(f"[HISTORY] Failed to save scan: {e}")


@router.get("/")
def get_scan_history(
    limit: int = 20,
    offset: int = 0,
    authorization: Optional[str] = Header(None),
):
    """Get the current user's scan history (most recent first)."""
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = get_db()
    try:
        rows = db.execute(
            """SELECT id, target, port, mode, score, grade, pqc_safe, tls_version, cipher, created_at
               FROM scan_history WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?""",
            (user["uid"], limit, offset)
        ).fetchall()

        total = db.execute(
            "SELECT COUNT(*) as cnt FROM scan_history WHERE user_id=?",
            (user["uid"],)
        ).fetchone()["cnt"]

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "scans": [
                {
                    "id": r["id"], "target": r["target"], "port": r["port"],
                    "score": r["score"], "grade": r["grade"],
                    "pqc_safe": bool(r["pqc_safe"]),
                    "tls_version": r["tls_version"], "cipher": r["cipher"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ],
        }
    finally:
        db.close()


@router.get("/{scan_id}")
def get_scan_detail(scan_id: int, authorization: Optional[str] = Header(None)):
    """Get full details of a specific scan from history."""
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = get_db()
    try:
        row = db.execute(
            "SELECT * FROM scan_history WHERE id=? AND user_id=?",
            (scan_id, user["uid"])
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan_data = json.loads(row["scan_data"]) if row["scan_data"] else {}
        return {
            "id": row["id"], "target": row["target"], "port": row["port"],
            "score": row["score"], "grade": row["grade"],
            "pqc_safe": bool(row["pqc_safe"]),
            "tls_version": row["tls_version"], "cipher": row["cipher"],
            "created_at": row["created_at"],
            "scan_data": scan_data,
        }
    finally:
        db.close()


@router.delete("/{scan_id}")
def delete_scan(scan_id: int, authorization: Optional[str] = Header(None)):
    """Delete a specific scan from history."""
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = get_db()
    try:
        result = db.execute(
            "DELETE FROM scan_history WHERE id=? AND user_id=?",
            (scan_id, user["uid"])
        )
        db.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"status": "deleted", "scan_id": scan_id}
    finally:
        db.close()


@router.delete("/")
def clear_history(authorization: Optional[str] = Header(None)):
    """Clear all scan history for the current user."""
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = get_db()
    try:
        db.execute("DELETE FROM scan_history WHERE user_id=?", (user["uid"],))
        db.commit()
        return {"status": "cleared"}
    finally:
        db.close()
