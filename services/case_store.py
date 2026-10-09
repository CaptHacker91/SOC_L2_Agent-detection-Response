"""Small SQLite-backed case and audit store for analyst workflow persistence."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config import PROJECT_ROOT

DB_PATH = PROJECT_ROOT / ".soc_state" / "soc_cases.db"
DB_VERSION = "1.1"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                assigned_analyst TEXT,
                decision TEXT,
                note TEXT,
                note_type TEXT DEFAULT 'Analyst Note',
                ai_recommendation TEXT,
                ai_confidence REAL,
                ai_latency_ms REAL,
                source TEXT,
                severity TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS case_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                at TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT,
                FOREIGN KEY(case_id) REFERENCES cases(case_id)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                incident_id TEXT,
                case_id TEXT,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_log(incident_id);
            CREATE INDEX IF NOT EXISTS idx_history_case ON case_history(case_id);
            """
        )
        # Lightweight forward migration for databases created by earlier builds.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
        migrations = {
            "note_type": "ALTER TABLE cases ADD COLUMN note_type TEXT DEFAULT 'Analyst Note'",
            "ai_recommendation": "ALTER TABLE cases ADD COLUMN ai_recommendation TEXT",
            "ai_confidence": "ALTER TABLE cases ADD COLUMN ai_confidence REAL",
            "ai_latency_ms": "ALTER TABLE cases ADD COLUMN ai_latency_ms REAL",
        }
        for name, sql in migrations.items():
            if name not in columns:
                conn.execute(sql)


def _next_case_id(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT COUNT(*) AS n FROM cases").fetchone()
    return f"CASE-SOC-{int(row['n']) + 1:05d}"


def get_case(incident_id: str) -> dict[str, Any] | None:
    init_db()
    with _conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE incident_id=?", (str(incident_id),)).fetchone()
    return dict(row) if row else None


def get_or_create_case(incident_id: str, *, source: str = "", severity: str = "", default_priority: str = "P3") -> dict[str, Any]:
    init_db()
    incident_id = str(incident_id)
    existing = get_case(incident_id)
    if existing:
        return existing
    now = _now()
    with _conn() as conn:
        case_id = _next_case_id(conn)
        conn.execute(
            "INSERT INTO cases(case_id,incident_id,status,priority,assigned_analyst,decision,note,note_type,ai_recommendation,ai_confidence,ai_latency_ms,source,severity,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, incident_id, "NEW", default_priority, "Unassigned", None, "", "Analyst Note", None, None, None, source, severity, now, now),
        )
        conn.execute(
            "INSERT INTO case_history(case_id,at,actor,action,detail) VALUES(?,?,?,?,?)",
            (case_id, now, "system", "CASE_CREATED", "Case created from selected telemetry."),
        )
    return get_case(incident_id) or {}


def allowed_next_statuses(current: str) -> list[str]:
    """Return conservative forward case transitions used by the analyst UI."""
    transitions = {
        "NEW": ["NEW", "INVESTIGATING"],
        "INVESTIGATING": ["INVESTIGATING", "REVIEWED", "CLOSED"],
        "REVIEWED": ["REVIEWED", "CLOSED", "INVESTIGATING"],
        "CLOSED": ["CLOSED", "INVESTIGATING"],
    }
    return transitions.get(str(current), ["NEW", "INVESTIGATING", "REVIEWED", "CLOSED"])


def update_case(case_id: str, **fields: Any) -> dict[str, Any]:
    init_db()
    allowed = {"status", "priority", "assigned_analyst", "decision", "note", "note_type", "ai_recommendation", "ai_confidence", "ai_latency_ms", "source", "severity"}
    patch = {key: value for key, value in fields.items() if key in allowed}
    if not patch:
        row = get_case_by_id(case_id)
        return row or {}
    now = _now()
    with _conn() as conn:
        before = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not before:
            raise ValueError(f"Unknown case: {case_id}")
        sets = ", ".join(f"{key}=?" for key in patch)
        conn.execute(f"UPDATE cases SET {sets}, updated_at=? WHERE case_id=?", (*patch.values(), now, case_id))
        for key, value in patch.items():
            old = before[key]
            if old != value:
                conn.execute(
                    "INSERT INTO case_history(case_id,at,actor,action,detail) VALUES(?,?,?,?,?)",
                    (case_id, now, "analyst", f"UPDATE_{key.upper()}", f"{old or 'None'} -> {value}"),
                )
    return get_case_by_id(case_id) or {}


def get_case_by_id(case_id: str) -> dict[str, Any] | None:
    init_db()
    with _conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    return dict(row) if row else None


def list_cases(limit: int = 200) -> list[dict[str, Any]]:
    init_db()
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?", (max(1, int(limit)),)).fetchall()
    return [dict(row) for row in rows]


def record_audit(action: str, *, incident_id: str = "", case_id: str = "", detail: str = "", actor: str = "analyst") -> None:
    init_db()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO audit_log(at,actor,action,incident_id,case_id,detail) VALUES(?,?,?,?,?,?)",
            (_now(), actor, str(action), str(incident_id), str(case_id), str(detail)),
        )


def audit_events(limit: int = 300, incident_id: str | None = None) -> list[dict[str, Any]]:
    init_db()
    with _conn() as conn:
        if incident_id:
            rows = conn.execute("SELECT * FROM audit_log WHERE incident_id=? ORDER BY id DESC LIMIT ?", (str(incident_id), max(1, int(limit)))).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (max(1, int(limit)),)).fetchall()
    return [dict(row) for row in rows]


def case_history(case_id: str, limit: int = 200) -> list[dict[str, Any]]:
    init_db()
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM case_history WHERE case_id=? ORDER BY id DESC LIMIT ?", (case_id, max(1, int(limit)))).fetchall()
    return [dict(row) for row in rows]


def case_metrics() -> dict[str, int]:
    init_db()
    with _conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS n FROM cases").fetchone()["n"]
        closed = conn.execute("SELECT COUNT(*) AS n FROM cases WHERE status='CLOSED'").fetchone()["n"]
        reviewed = conn.execute("SELECT COUNT(*) AS n FROM cases WHERE status='REVIEWED'").fetchone()["n"]
        assigned = conn.execute("SELECT COUNT(*) AS n FROM cases WHERE assigned_analyst IS NOT NULL AND assigned_analyst!='Unassigned'").fetchone()["n"]
        true_positive = conn.execute("SELECT COUNT(*) AS n FROM cases WHERE decision='True Positive'").fetchone()["n"]
        false_positive = conn.execute("SELECT COUNT(*) AS n FROM cases WHERE decision='False Positive'").fetchone()["n"]
        needs_investigation = conn.execute("SELECT COUNT(*) AS n FROM cases WHERE decision='Needs Investigation'").fetchone()["n"]
        benign = conn.execute("SELECT COUNT(*) AS n FROM cases WHERE decision='Benign'").fetchone()["n"]
    return {"total": int(total), "closed": int(closed), "reviewed": int(reviewed), "assigned": int(assigned), "true_positive": int(true_positive), "false_positive": int(false_positive), "needs_investigation": int(needs_investigation), "benign": int(benign)}


def serialize_case(case: dict[str, Any]) -> str:
    return json.dumps(case or {}, sort_keys=True, indent=2, default=str)
