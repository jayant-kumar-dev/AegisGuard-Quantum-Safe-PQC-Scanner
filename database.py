"""
AegisGuard — Database Layer (SQLite)
Handles user accounts and scan history persistence.
"""

import sqlite3
import os
import logging
from config import DB_PATH

logger = logging.getLogger("AegisGuard.DB")


def get_db():
    """Get a new SQLite connection (use per-request)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            email       TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,
            full_name   TEXT    DEFAULT '',
            org_name    TEXT    DEFAULT '',
            created_at  TEXT    DEFAULT (datetime('now')),
            last_login  TEXT    DEFAULT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            target      TEXT    NOT NULL,
            port        INTEGER DEFAULT 443,
            mode        TEXT    DEFAULT 'full',
            score       INTEGER DEFAULT 0,
            grade       TEXT    DEFAULT '',
            pqc_safe    INTEGER DEFAULT 0,
            tls_version TEXT    DEFAULT '',
            cipher      TEXT    DEFAULT '',
            scan_data   TEXT    DEFAULT '{}',
            created_at  TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_history_user 
        ON scan_history(user_id, created_at DESC)
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            target              TEXT    NOT NULL,
            port                INTEGER DEFAULT 443,
            mode                TEXT    DEFAULT 'full',
            score               INTEGER DEFAULT 0,
            grade               TEXT    DEFAULT '',
            pqc_safe            INTEGER DEFAULT 0,
            vulnerability_pct   INTEGER DEFAULT 0,
            pqc_readiness_pct   INTEGER DEFAULT 0,
            confidence          REAL    DEFAULT 0.0,
            scan_data           TEXT    DEFAULT '{}',
            created_at          TEXT    DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_target_created
        ON scans(target, created_at DESC)
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            report_type     TEXT    NOT NULL,
            generated_by    TEXT    DEFAULT 'system',
            domains_json    TEXT    DEFAULT '[]',
            final_score     INTEGER DEFAULT 0,
            grade           TEXT    DEFAULT 'F',
            report_data     TEXT    DEFAULT '{}',
            created_at      TEXT    DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_reports_type_created
        ON reports(report_type, created_at DESC)
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schedules (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            report_type     TEXT    NOT NULL,
            frequency       TEXT    NOT NULL,
            targets_json    TEXT    DEFAULT '[]',
            email           TEXT    DEFAULT '',
            timezone        TEXT    DEFAULT 'UTC',
            status          TEXT    DEFAULT 'active',
            next_run_at     TEXT    DEFAULT NULL,
            last_run_at     TEXT    DEFAULT NULL,
            last_report_id  INTEGER DEFAULT NULL,
            created_at      TEXT    DEFAULT (datetime('now')),
            updated_at      TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (last_report_id) REFERENCES reports(id) ON DELETE SET NULL
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_schedules_status_next
        ON schedules(status, next_run_at)
    """)

    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")
