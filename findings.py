#!/usr/bin/env python3
"""
findings.py — SQLite findings store for the AI Security POC.
Import this in any test script to record findings to the central DB.
"""
import sqlite3, json, os, time, uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "findings.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    run_id      TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    completed_at TEXT,
    label       TEXT,
    total_tests INTEGER DEFAULT 0,
    passed      INTEGER DEFAULT 0,
    failed      INTEGER DEFAULT 0,
    skipped     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS test_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    test_num    TEXT NOT NULL,
    test_name   TEXT NOT NULL,
    status      TEXT NOT NULL,
    duration_ms INTEGER,
    notes       TEXT,
    timestamp   TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT NOT NULL,
    test_num         TEXT,
    finding_name     TEXT NOT NULL,
    category         TEXT,
    owasp_id         TEXT,
    severity         TEXT,
    status           TEXT,
    detail           TEXT,
    payload          TEXT,
    response_preview TEXT,
    framework        TEXT,
    remediation      TEXT,
    timestamp        TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);

CREATE TABLE IF NOT EXISTS service_checks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    service_name TEXT NOT NULL,
    url          TEXT,
    status       TEXT,
    http_code    INTEGER,
    timestamp    TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);
"""

def _conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con

def now():
    return datetime.now(timezone.utc).isoformat()

# ── Run management ────────────────────────────────────────────────────────────

def new_run(label: str = "POC Test Run") -> str:
    run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    with _conn() as con:
        con.execute(
            "INSERT INTO scan_runs (run_id, started_at, label) VALUES (?,?,?)",
            (run_id, now(), label)
        )
    return run_id

def close_run(run_id: str, passed: int, failed: int, skipped: int):
    total = passed + failed + skipped
    with _conn() as con:
        con.execute("""
            UPDATE scan_runs SET completed_at=?, total_tests=?, passed=?, failed=?, skipped=?
            WHERE run_id=?
        """, (now(), total, passed, failed, skipped, run_id))

def latest_run_id() -> str | None:
    with _conn() as con:
        row = con.execute(
            "SELECT run_id FROM scan_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
    return row["run_id"] if row else None

# ── Test result recording ─────────────────────────────────────────────────────

def record_test(run_id: str, num: str, name: str, status: str,
                duration_ms: int = 0, notes: str = ""):
    with _conn() as con:
        con.execute("""
            INSERT INTO test_results (run_id, test_num, test_name, status, duration_ms, notes, timestamp)
            VALUES (?,?,?,?,?,?,?)
        """, (run_id, num, name, status, duration_ms, notes, now()))

# ── Finding recording ─────────────────────────────────────────────────────────

def record_finding(run_id: str, *, test_num: str = "", finding_name: str,
                   category: str = "", owasp_id: str = "", severity: str = "Medium",
                   status: str = "", detail: str = "", payload: str = "",
                   response_preview: str = "", framework: str = "", remediation: str = ""):
    with _conn() as con:
        con.execute("""
            INSERT INTO findings
            (run_id, test_num, finding_name, category, owasp_id, severity, status,
             detail, payload, response_preview, framework, remediation, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (run_id, test_num, finding_name, category, owasp_id, severity, status,
              detail, payload, response_preview[:500], framework, remediation, now()))

# ── Service check recording ───────────────────────────────────────────────────

def record_service(run_id: str, name: str, url: str, status: str, code: int):
    with _conn() as con:
        con.execute("""
            INSERT INTO service_checks (run_id, service_name, url, status, http_code, timestamp)
            VALUES (?,?,?,?,?,?)
        """, (run_id, name, url, status, code, now()))

# ── Read helpers for dashboard ────────────────────────────────────────────────

def get_all_runs():
    with _conn() as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT 20"
        ).fetchall()]

def get_findings(run_id: str = None):
    with _conn() as con:
        if run_id:
            rows = con.execute(
                "SELECT * FROM findings WHERE run_id=? ORDER BY timestamp DESC", (run_id,)
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM findings ORDER BY timestamp DESC LIMIT 200"
            ).fetchall()
    return [dict(r) for r in rows]

def get_test_results(run_id: str = None):
    with _conn() as con:
        if run_id:
            rows = con.execute(
                "SELECT * FROM test_results WHERE run_id=? ORDER BY test_num", (run_id,)
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM test_results ORDER BY timestamp DESC LIMIT 100"
            ).fetchall()
    return [dict(r) for r in rows]

def get_service_checks(run_id: str = None):
    with _conn() as con:
        if run_id:
            rows = con.execute(
                "SELECT * FROM service_checks WHERE run_id=? ORDER BY service_name", (run_id,)
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM service_checks ORDER BY timestamp DESC LIMIT 50"
            ).fetchall()
    return [dict(r) for r in rows]

def get_summary(run_id: str = None):
    with _conn() as con:
        q = "WHERE run_id=?" if run_id else ""
        p = (run_id,) if run_id else ()
        total    = con.execute(f"SELECT COUNT(*) FROM findings {q}", p).fetchone()[0]
        critical = con.execute(f"SELECT COUNT(*) FROM findings {q} {'AND' if run_id else 'WHERE'} severity='Critical'", p).fetchone()[0]
        high     = con.execute(f"SELECT COUNT(*) FROM findings {q} {'AND' if run_id else 'WHERE'} severity='High'", p).fetchone()[0]
        medium   = con.execute(f"SELECT COUNT(*) FROM findings {q} {'AND' if run_id else 'WHERE'} severity='Medium'", p).fetchone()[0]
        vuln     = con.execute(f"SELECT COUNT(*) FROM findings {q} {'AND' if run_id else 'WHERE'} status='VULNERABLE'", p).fetchone()[0]
    return {"total": total, "critical": critical, "high": high, "medium": medium, "vulnerable": vuln}
