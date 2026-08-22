"""
AegisGuard — Scheduler Service
Persists schedules and executes scheduled report generation.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Any, Dict, List

from fastapi import HTTPException

from database import get_db, init_db
from services.report_service import generate_executive_report

logger = logging.getLogger("AegisGuard.Scheduler")

try:
    from apscheduler.schedulers.background import BackgroundScheduler  # type: ignore
    from apscheduler.triggers.interval import IntervalTrigger  # type: ignore
except Exception:
    BackgroundScheduler = None
    IntervalTrigger = None

_scheduler = None


def _utc_now() -> datetime.datetime:
    return datetime.datetime.utcnow().replace(microsecond=0)


def _compute_next_run(frequency: str, from_time: datetime.datetime | None = None) -> datetime.datetime:
    ref = from_time or _utc_now()
    if frequency == "daily":
        return ref + datetime.timedelta(days=1)
    if frequency == "weekly":
        return ref + datetime.timedelta(weeks=1)
    if frequency == "monthly":
        return ref + datetime.timedelta(days=30)
    if frequency == "hourly":
        return ref + datetime.timedelta(hours=1)
    raise HTTPException(status_code=400, detail=f"Unsupported frequency: {frequency}")


def _to_iso(dt: datetime.datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat() + "Z"


def init_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        return

    if BackgroundScheduler is None:
        logger.warning("[SCHEDULER] APScheduler not installed; scheduled reports disabled")
        return

    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.start()
    logger.info("[SCHEDULER] Background scheduler started")

    schedules = list_schedules(active_only=True)
    for item in schedules:
        try:
            _register_job(item)
        except Exception as exc:
            logger.warning("[SCHEDULER] Could not restore schedule %s: %s", item.get("id"), exc)


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("[SCHEDULER] Background scheduler stopped")


def _register_job(schedule: Dict[str, Any]) -> None:
    if _scheduler is None or IntervalTrigger is None:
        return

    sid = schedule["id"]
    freq = schedule["frequency"]
    job_id = f"report_schedule_{sid}"

    if freq == "hourly":
        trigger = IntervalTrigger(hours=1)
    elif freq == "daily":
        trigger = IntervalTrigger(days=1)
    elif freq == "weekly":
        trigger = IntervalTrigger(weeks=1)
    elif freq == "monthly":
        trigger = IntervalTrigger(days=30)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported frequency: {freq}")

    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)

    _scheduler.add_job(
        run_scheduled_scan,
        trigger=trigger,
        args=[sid],
        id=job_id,
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )


def create_schedule(report_type: str, frequency: str, targets: List[str], email: str = "", timezone: str = "UTC") -> Dict[str, Any]:
    init_db()
    if report_type != "executive":
        raise HTTPException(status_code=400, detail="Currently only executive scheduled reports are supported")

    if frequency not in {"hourly", "daily", "weekly", "monthly"}:
        raise HTTPException(status_code=400, detail="Invalid frequency. Use hourly/daily/weekly/monthly")

    if not targets:
        raise HTTPException(status_code=400, detail="Targets are required")

    next_run = _compute_next_run(frequency)

    conn = get_db()
    try:
        cur = conn.execute(
            """
            INSERT INTO schedules (report_type, frequency, targets_json, email, timezone, status, next_run_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'active', ?, datetime('now'))
            """,
            (report_type, frequency, json.dumps(targets), email or "", timezone or "UTC", _to_iso(next_run)),
        )
        conn.commit()
        schedule_id = int(cur.lastrowid)
    finally:
        conn.close()

    schedule = get_schedule(schedule_id)
    _register_job(schedule)
    return schedule


def list_schedules(active_only: bool = False) -> List[Dict[str, Any]]:
    init_db()
    conn = get_db()
    try:
        if active_only:
            rows = conn.execute("SELECT * FROM schedules WHERE status='active' ORDER BY created_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()

        return [
            {
                "id": r["id"],
                "report_type": r["report_type"],
                "frequency": r["frequency"],
                "targets": json.loads(r["targets_json"] or "[]"),
                "email": r["email"],
                "timezone": r["timezone"],
                "status": r["status"],
                "next_run_at": r["next_run_at"],
                "last_run_at": r["last_run_at"],
                "last_report_id": r["last_report_id"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]
    finally:
        conn.close()


def get_schedule(schedule_id: int) -> Dict[str, Any]:
    init_db()
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Schedule not found")
        return {
            "id": row["id"],
            "report_type": row["report_type"],
            "frequency": row["frequency"],
            "targets": json.loads(row["targets_json"] or "[]"),
            "email": row["email"],
            "timezone": row["timezone"],
            "status": row["status"],
            "next_run_at": row["next_run_at"],
            "last_run_at": row["last_run_at"],
            "last_report_id": row["last_report_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    finally:
        conn.close()


def _update_schedule_run(schedule_id: int, report_id: int) -> None:
    schedule = get_schedule(schedule_id)
    next_run = _compute_next_run(schedule["frequency"])

    conn = get_db()
    try:
        conn.execute(
            """
            UPDATE schedules
            SET last_run_at=?, next_run_at=?, last_report_id=?, updated_at=datetime('now')
            WHERE id=?
            """,
            (_to_iso(_utc_now()), _to_iso(next_run), report_id, schedule_id),
        )
        conn.commit()
    finally:
        conn.close()


def send_report_email(email: str, report: Dict[str, Any]) -> Dict[str, Any]:
    if not email:
        return {"sent": False, "reason": "no email configured"}

    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    smtp_from = os.getenv("SMTP_FROM", smtp_user or "noreply@aegisguard.local")

    if not smtp_host or not smtp_user or not smtp_pass:
        logger.info("[SCHEDULER] SMTP not configured; skipping email to %s", email)
        return {"sent": False, "reason": "smtp not configured"}

    message = EmailMessage()
    message["Subject"] = "AegisGuard Scheduled Executive Report"
    message["From"] = smtp_from
    message["To"] = email

    final_score = (report.get("final_score") or {}).get("final_score", 0)
    grade = (report.get("final_score") or {}).get("grade", "F")
    summary = (report.get("ai_summary") or {}).get("summary", "")
    message.set_content(
        f"Scheduled report generated successfully.\n"
        f"Report ID: {report.get('report_id')}\n"
        f"Score: {final_score}/1000 ({grade})\n"
        f"Summary: {summary}\n"
    )

    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(message)

    return {"sent": True, "to": email}


def run_scheduled_scan(schedule_id: int) -> Dict[str, Any]:
    schedule = get_schedule(schedule_id)
    if schedule["status"] != "active":
        return {"status": "skipped", "reason": "schedule inactive", "schedule_id": schedule_id}

    report = generate_executive_report(schedule["targets"], generated_by="scheduler")
    _update_schedule_run(schedule_id, int(report.get("report_id")))

    email_status = send_report_email(schedule.get("email", ""), report)
    return {
        "status": "ok",
        "schedule_id": schedule_id,
        "report_id": report.get("report_id"),
        "email": email_status,
    }
